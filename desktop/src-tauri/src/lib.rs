//! Tauri command surface for Crypt Wallet's desktop app.
//!
//! ## Secret-handling rules this module follows
//!
//! - A generated mnemonic crosses the IPC bridge exactly **once** (on
//!   [`generate_new_mnemonic`], for display on the backup screen). The
//!   confirm step sends back only the *slot numbers* the user clicked, not
//!   the words: this process holds the confirmation display order, so the
//!   clicks can be checked without the phrase ever making a return trip.
//! - The pending mnemonic lives in Tauri managed state, not in the webview,
//!   and is cleared once it has been sealed.
//! - No error message, log line, or `Debug` output in this module ever
//!   contains a mnemonic, seed, or password. Error strings are static.
//! - Passphrases arriving over IPC are wrapped in `Zeroizing` on entry.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::primitives::{Address as AlloyAddress, Bytes as AlloyBytes, PrimitiveSignature, TxKind, U256};
use alloy::eips::eip2930::AccessList;
use alloy::sol_types::SolCall;
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use cryptwallet_crypto::{BitcoinAccountKey, EvmAccountKey, SecretMnemonic, SolanaAccountKey, WordCount};
use cryptwallet_vault::{KdfParams, SealedVault, VaultError};
use ed25519_dalek::Signer as _;
use ed25519_dalek::Signature as Ed25519Signature;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use solana_hash::Hash as SolanaHash;
use solana_pubkey::Pubkey as SolanaPubkey;
use solana_sdk::message::legacy::Message as SolanaMessage;
use solana_sdk::signature::Signature as SolanaSignature;
use solana_sdk::transaction::Transaction as SolanaTransaction;
use tauri::{AppHandle, Manager, State, WindowEvent};
use zeroize::Zeroizing;

alloy::sol! {
    /// Just the one ERC-20 function this app calls. `sol!` compiles this
    /// signature to a real ABI encoder/decoder (`IERC20::transferCall`,
    /// used by `encode_erc20_transfer`) — the calldata layout and the
    /// `0xa9059cbb` selector both come from this macro, not hand-written.
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
    }
}

/// Chain IDs for every network this app recognizes at all, for the network
/// switcher. Each has a short doc comment recording exactly how its chain
/// ID was verified (matches `desktop/src/networks.ts`'s own verification
/// notes, which is the frontend's copy of this same source-of-truth list —
/// kept in sync by hand, since Rust and TypeScript can't literally share a
/// constant).
///
/// Deliberately NOT the same list as "chains we can sign for" — see
/// `SENDABLE_CHAIN_IDS`, below, which is a separate list (currently equal
/// in membership, not in meaning — see its own doc comment for the
/// 2026-08-22 policy reversal that made them agree). Adding a network to
/// `SUPPORTED_CHAIN_IDS` enables read-only balance/history viewing for it
/// and nothing else; enabling it to actually SIGN is a separate,
/// deliberate addition to `SENDABLE_CHAIN_IDS`, never a side effect of
/// this list growing. That split is what let this app add Ethereum
/// mainnet as view-only first, then later, separately and deliberately,
/// enable mainnet sending once that was the explicit decision.
const SEPOLIA_CHAIN_ID: u64 = 11155111;
const MAINNET_CHAIN_ID: u64 = 1;
/// Verified 2026-08-27 against https://chainlist.org/chain/56 directly.
const BSC_CHAIN_ID: u64 = 56;
/// Confirmed by the user directly (not independently re-verified in this
/// pass, per their explicit note when requesting this network).
const BSC_TESTNET_CHAIN_ID: u64 = 97;
/// Verified 2026-08-27 against https://chainlist.org/chain/42161 directly.
const ARBITRUM_CHAIN_ID: u64 = 42161;
/// Verified 2026-08-27 against https://chainlist.org/chain/421614 directly.
const ARBITRUM_SEPOLIA_CHAIN_ID: u64 = 421614;
/// Verified 2026-08-27 against https://chainlist.org/chain/8453 directly.
const BASE_CHAIN_ID: u64 = 8453;
/// Verified 2026-08-27 against https://chainlist.org/chain/84532 directly.
const BASE_SEPOLIA_CHAIN_ID: u64 = 84532;
/// Verified 2026-08-20 against https://chainlist.org/chain/137 directly
/// (page displays "Polygon Mainnet", chain ID 137 / 0x89), and independently
/// against a direct eth_chainId call to this app's RPC default, which
/// echoed back the same 0x89.
const POLYGON_CHAIN_ID: u64 = 137;
/// Verified 2026-08-20 against https://chainlist.org/chain/10 directly
/// (page displays "OP Mainnet", chain ID 10 / 0xa), and independently
/// against a direct eth_chainId call to this app's RPC default, which
/// echoed back the same 0xa.
const OPTIMISM_CHAIN_ID: u64 = 10;
/// Verified 2026-08-21 against https://chainlist.org/chain/80002 directly
/// (page displays "Amoy", chain ID 80002 / 0x13882 — Polygon's current
/// testnet; Mumbai, the previous one, was deprecated in 2024), and
/// independently against a direct eth_chainId call to this app's RPC
/// default, which echoed back the same 0x13882.
const POLYGON_AMOY_CHAIN_ID: u64 = 80002;
/// Verified 2026-08-21 against https://chainlist.org/chain/11155420
/// directly (page displays "OP Sepolia Testnet", chain ID 11155420 /
/// 0xaa37dc), and independently against a direct eth_chainId call to this
/// app's RPC default, which echoed back the same 0xaa37dc.
const OPTIMISM_SEPOLIA_CHAIN_ID: u64 = 11155420;

const SUPPORTED_CHAIN_IDS: [u64; 12] = [
    SEPOLIA_CHAIN_ID,
    MAINNET_CHAIN_ID,
    BSC_CHAIN_ID,
    BSC_TESTNET_CHAIN_ID,
    ARBITRUM_CHAIN_ID,
    ARBITRUM_SEPOLIA_CHAIN_ID,
    BASE_CHAIN_ID,
    BASE_SEPOLIA_CHAIN_ID,
    POLYGON_CHAIN_ID,
    OPTIMISM_CHAIN_ID,
    POLYGON_AMOY_CHAIN_ID,
    OPTIMISM_SEPOLIA_CHAIN_ID,
];

/// Chain IDs this app will actually sign a transaction for. This is the
/// real enforcement behind whether a network is sendable (see
/// `sign_transaction_impl`'s and `sign_token_transfer_impl`'s own chain-id
/// checks, which are what actually consult this list); `networks.ts`'s
/// `sendSupported` flag is only the frontend's copy of the same decision,
/// there to give a good experience (block the send flow before a form is
/// filled out) rather than to be the boundary itself.
///
/// POLICY HISTORY — read before changing this list again: from this app's
/// EVM mainnet support being added through 2026-08-22, this list held ONLY
/// testnets — every mainnet was architecturally, deliberately excluded
/// pending an external security audit, "no chain is exempt just because
/// its signer works" (see the Solana equivalent block added and then
/// reversed the same night, `SOLANA_SENDABLE_NETWORKS` below). On
/// 2026-08-22, the wallet owner made an explicit, deliberate decision to
/// reverse that restriction and enable mainnet sending for every chain
/// this app supports — not an audit having occurred, not a per-chain
/// evaluation, a direct policy reversal recorded here so a future reader
/// does not mistake the absence of the old restriction for an oversight.
/// All 6 mainnets (`MAINNET_CHAIN_ID`, `BSC_CHAIN_ID`, `ARBITRUM_CHAIN_ID`,
/// `BASE_CHAIN_ID`, `POLYGON_CHAIN_ID`, `OPTIMISM_CHAIN_ID`) now sit
/// alongside every testnet — this list is currently identical to
/// `SUPPORTED_CHAIN_IDS`, kept as its own separate, explicitly-enumerated
/// list rather than collapsed into an alias, since the two lists represent
/// genuinely different decisions (read-only support vs. sign-for) that
/// happen to currently agree, not the same decision twice — a future
/// restriction (e.g. a custom network, or re-tightening this policy) would
/// need to diverge them again. See `desktop/src/main.ts`'s
/// `EVM_MAINNET_WARNING_ACKNOWLEDGED`-style one-time warning gate for the
/// compensating control this reversal shipped with: informed consent
/// before a user's first real-fund send this session, since removing the
/// architectural block does not mean removing the "this hasn't been
/// audited" disclosure.
const SENDABLE_CHAIN_IDS: [u64; 12] = [
    SEPOLIA_CHAIN_ID,
    MAINNET_CHAIN_ID,
    BSC_CHAIN_ID,
    BSC_TESTNET_CHAIN_ID,
    ARBITRUM_CHAIN_ID,
    ARBITRUM_SEPOLIA_CHAIN_ID,
    BASE_CHAIN_ID,
    BASE_SEPOLIA_CHAIN_ID,
    POLYGON_CHAIN_ID,
    OPTIMISM_CHAIN_ID,
    POLYGON_AMOY_CHAIN_ID,
    OPTIMISM_SEPOLIA_CHAIN_ID,
];

/// `Err` if `chain_id` isn't one of `SUPPORTED_CHAIN_IDS` at all. Shared by
/// both signing commands so the allowlist has exactly one implementation —
/// see each call site for the additional, narrower "must actually be
/// sendable" check (`require_sendable_chain_id`) layered on top of this
/// one.
fn require_supported_chain_id(chain_id: u64) -> Result<(), String> {
    if !SUPPORTED_CHAIN_IDS.contains(&chain_id) {
        return Err(format!(
            "unsupported chain ID {chain_id} — this app currently recognizes: {SUPPORTED_CHAIN_IDS:?}"
        ));
    }
    Ok(())
}

/// `Err` if `chain_id` is a recognized network (already passed
/// `require_supported_chain_id`) but isn't one this app will sign for.
/// Since the 2026-08-22 policy reversal (see `SENDABLE_CHAIN_IDS`'s own
/// doc comment) `SENDABLE_CHAIN_IDS` now equals `SUPPORTED_CHAIN_IDS`
/// exactly, so this currently never rejects anything that
/// `require_supported_chain_id` already let through — kept as its own
/// separate check anyway, not deleted, because the two lists represent
/// genuinely different decisions that happen to agree today, not
/// permanently the same list (see that doc comment). Deliberately a fixed,
/// generic message rather than naming a specific chain, for whenever this
/// check is next load-bearing again.
fn require_sendable_chain_id(chain_id: u64) -> Result<(), String> {
    if !SENDABLE_CHAIN_IDS.contains(&chain_id) {
        return Err("Sending is not yet supported on this network".to_string());
    }
    Ok(())
}

/// Solana's own cluster identifiers -- "mainnet-beta", "devnet", "testnet"
/// -- Solana's real, protocol-level equivalent of EVM's numeric chain ID,
/// even though this app does not yet expose a Solana network selector in
/// the UI (`desktop/src/solana.ts` hardcodes the mainnet-beta RPC endpoint
/// today; see that module's own doc comment).
///
/// POLICY HISTORY -- read before changing this again: from this being
/// added through 2026-08-22, "mainnet-beta" was deliberately excluded here,
/// mirroring `SENDABLE_CHAIN_IDS`'s then-current EVM mainnet exclusion --
/// "no chain is exempt just because its signer works," even though
/// Solana's signer was proven against real mainnet via a verified
/// checkpoint send before this check existed (see `sign_solana_transaction`'s
/// own doc comment). On 2026-08-22, the wallet owner made an explicit,
/// deliberate decision to reverse that restriction across every chain this
/// app supports, EVM and Solana together -- not an audit having occurred,
/// a direct policy reversal. "mainnet-beta" now sits alongside
/// "devnet"/"testnet" here. See `desktop/src/main.ts`'s one-time mainnet
/// warning gate for the compensating control this reversal shipped with:
/// informed consent before a user's first real Solana send this session.
const SOLANA_SENDABLE_NETWORKS: [&str; 3] = ["mainnet-beta", "devnet", "testnet"];

/// `Err` unless `network` is one of `SOLANA_SENDABLE_NETWORKS` -- the
/// Solana-side equivalent of `require_sendable_chain_id`, called by
/// [`sign_solana_transaction_impl`] before it will produce a signature.
/// Deliberately the same fixed, generic message as that check: the useful
/// information for a user is "not this network," not an internal allowlist.
fn require_sendable_solana_network(network: &str) -> Result<(), String> {
    if !SOLANA_SENDABLE_NETWORKS.contains(&network) {
        return Err("Sending is not yet supported on this network".to_string());
    }
    Ok(())
}

/// Filename of the sealed vault inside the app data directory.
const VAULT_FILENAME: &str = "wallet.vault";

/// Filename of the persisted consecutive-failed-unlock counter, kept next to
/// the vault in app data. Survives process restart on purpose: an in-memory
/// counter is reset simply by killing and relaunching the app, which is
/// exactly the scripted-attack case the rate limit is meant to slow.
const UNLOCK_FAILURES_FILENAME: &str = "unlock-failures";

/// Filename of the persisted Solana account count, kept next to the vault
/// in app data. Not secret (it's an integer, not key material) -- same
/// sensitivity class as `UNLOCK_FAILURES_FILENAME` above, which is why this
/// lives as its own plain sidecar file rather than inside the encrypted
/// vault: adding a field to the vault's encrypted plaintext would mean a
/// vault format/version migration, a materially bigger and riskier change
/// than a wallet-account-count feature calls for. See `read_solana_account_count`/
/// `add_solana_account` for how this is used.
const SOLANA_ACCOUNTS_FILENAME: &str = "solana-accounts";

/// How long an unlocked wallet may sit before its mnemonic is cleared from
/// memory. See [`UnlockedWallet`] for the reasoning behind this value.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How often the background sweeper checks the idle timeout. Only bounds how
/// long past the timeout a session can linger, so coarse is fine.
const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Minimum accepted unlock-password length.
///
/// This password is the only thing standing between an attacker who has
/// copied the vault file and the recovery phrase inside it. Argon2id at
/// `KdfParams::DESKTOP_DEFAULT` (256 MiB, 3 iterations) makes each guess
/// expensive, which buys a great deal — but the KDF cost multiplies the
/// search space, it doesn't create one, so the password's own entropy is
/// still the binding constraint.
///
/// 12 is a floor, not a target. Length dominates character variety here:
/// against an offline attacker running a wordlist-and-mangling-rules attack
/// (which is what real cracking looks like, not brute force over the
/// alphabet), a short string with substitutions is weaker than a longer
/// multi-word passphrase. The UI recommends the latter accordingly.
const MIN_PASSWORD_LEN: usize = 12;

/// A newly generated phrase, plus the display order its confirmation step
/// will use.
#[derive(Serialize)]
struct NewMnemonic {
    /// The phrase in order, for the backup screen. This is the only time
    /// the words cross the bridge.
    words: Vec<String>,
    /// Confirmation display order: slot `i` shows `words[bank[i]]`.
    bank: Vec<usize>,
}

/// A wallet-creation flow that hasn't been confirmed and sealed yet.
struct PendingCreation {
    mnemonic: SecretMnemonic,
    /// `bank[slot]` is the position in the phrase of the word shown in
    /// confirmation slot `slot`.
    ///
    /// Keeping this here is what lets the confirm step work on slot numbers
    /// alone: the frontend reports which slots were clicked, and only this
    /// process can map those back to phrase positions. Without it, the
    /// frontend would have to send the words themselves — i.e. the phrase,
    /// a second time.
    bank: Vec<usize>,
}

/// The pending wallet creation, held in the Rust process rather than the
/// webview.
#[derive(Default)]
struct PendingMnemonic(Mutex<Option<PendingCreation>>);

/// Fisher–Yates shuffle of `0..len`, seeded from the OS CSPRNG.
///
/// This ordering is **not** a security control — it only decides where each
/// word appears on screen, and the user is looking at all of them anyway.
/// It uses `OsRng` regardless, because the alternative (`Math.random` in the
/// webview, as this previously did) leaves a reader auditing the app unsure
/// which randomness here is load-bearing. Modulo bias is irrelevant at these
/// sizes and for this purpose.
fn shuffled_indices(len: usize) -> Vec<usize> {
    let mut out: Vec<usize> = (0..len).collect();
    let mut rng = OsRng;
    for i in (1..len).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        out.swap(i, j);
    }
    out
}

/// An unlocked wallet: the mnemonic plus when the session began.
struct UnlockedSession {
    // Read by get_account_address and sign_transaction to re-derive
    // account keys on demand, and held (rather than a derived key) for the
    // not-yet-built authenticated reveal/export flow (spec §D.5) too. The
    // idle timeout and window-event clears exist so that neither use finds
    // this sitting in memory indefinitely, reachable without re-auth.
    mnemonic: SecretMnemonic,
    /// When this session was unlocked. The idle timeout is measured from
    /// here. A future reveal/export command should refresh this on use so
    /// the timeout tracks *inactivity* rather than raw session age — today
    /// nothing reads the session, so the two are the same thing.
    unlocked_at: Instant,
}

/// The currently-unlocked wallet, held for the lifetime of the session.
///
/// Storing the mnemonic (rather than a derived key) is what lets a later
/// authenticated reveal/export flow work without asking for the passphrase
/// again. `SecretMnemonic` is `ZeroizeOnDrop`, so both replacing and
/// clearing this scrub the previous value.
///
/// The session is cleared on four triggers: [`lock_wallet`], an idle timeout
/// ([`SESSION_IDLE_TIMEOUT`], swept by a background thread), and window
/// blur/close. The idle default is **10 minutes**: this holds a raw mnemonic
/// in process memory, so the window wants to be short, but there is no
/// activity signal to extend it yet (no command reads the session), so it is
/// really "time since unlock" — 10 minutes is long enough not to evict a
/// user mid-task and short enough to bound how long the mnemonic lingers if
/// they walk away with the window focused. Blur/close cover the commoner
/// "switched away" case immediately; the timer is the backstop for "left it
/// focused and left."
///
/// `Arc` so the background sweeper thread can hold its own handle.
#[derive(Default, Clone)]
struct UnlockedWallet(Arc<Mutex<Option<UnlockedSession>>>);

impl UnlockedWallet {
    /// Unconditionally clear the session (drop zeroizes the mnemonic).
    fn clear(&self) {
        if let Ok(mut guard) = self.0.lock() {
            *guard = None;
        }
    }

    /// Clear the session if it has been idle at least `timeout` as of `now`.
    /// Split out from the sweeper loop so the expiry rule is unit-testable
    /// without waiting on wall-clock time.
    fn clear_if_expired(&self, now: Instant, timeout: Duration) {
        if let Ok(mut guard) = self.0.lock() {
            let expired = guard
                .as_ref()
                .is_some_and(|s| now.duration_since(s.unlocked_at) >= timeout);
            if expired {
                *guard = None;
            }
        }
    }
}

/// Consecutive failed unlock attempts to enforce a delay before, capped so a
/// user who eventually remembers their passphrase isn't locked out forever.
///
/// The first few misses cost nothing (ordinary fat-fingering); past that the
/// wait doubles each time. On top of the ~10s Argon2id already pays per
/// attempt, this throttles a script hard while barely touching a human.
///
/// | consecutive failures | delay before next attempt |
/// |---|---|
/// | 0–2 | none |
/// | 3 | 1s |
/// | 4 | 2s |
/// | 5 | 4s |
/// | … | doubling |
/// | 12+ | 300s (capped) |
fn unlock_delay(failures: u32) -> Duration {
    const FREE_ATTEMPTS: u32 = 3;
    const CAP: Duration = Duration::from_secs(300);
    if failures < FREE_ATTEMPTS {
        return Duration::ZERO;
    }
    // `1u64 << n` for n up to ~40 stays well inside u64; the `.min` against
    // the cap (300) means the shift exponent never grows large enough to
    // overflow in practice, but saturate anyway to be safe.
    let shift = failures - FREE_ATTEMPTS;
    let seconds = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    Duration::from_secs(seconds).min(CAP)
}

/// Read the persisted consecutive-failure count. A missing or unparseable
/// file reads as 0 — the counter is a throttle, not an integrity control, so
/// failing open here is acceptable (see the honesty note in `unlock_impl`).
fn read_unlock_failures(path: &Path) -> u32 {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Persist the consecutive-failure count (best effort).
fn write_unlock_failures(path: &Path, failures: u32) {
    if let Some(parent) = path.parent() {
        let _ = create_private_dir_all(parent);
    }
    // Not atomic and not private-mode-forced: this file holds no secret (an
    // integer), and a torn write at worst under- or over-counts by one,
    // which the throttle tolerates.
    let _ = fs::write(path, failures.to_string());
}

/// Create a file readable only by the owning user.
///
/// On Unix the mode is applied at creation time (alongside `O_CREAT|O_EXCL`),
/// so there is no window in which the file exists with the default
/// `0644` — which would have made the vault world-readable and available
/// for offline cracking by any local user.
///
/// On Windows nothing extra is applied: files here inherit the user-profile
/// ACL of the app data directory, which grants only SYSTEM, Administrators
/// and the owning user. That was verified against a real vault file rather
/// than assumed.
fn create_new_private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Create a directory tree traversable only by the owning user (Unix).
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Write the vault so the target file is either absent or complete, never
/// truncated: contents go to a temp file that is fsynced, then renamed over
/// the target.
///
/// The failure this prevents is not an attack. Previously a mid-write error
/// left a partial file that `create_new` had already claimed, so the user
/// could neither unlock it nor create a new wallet — locked out with no
/// attacker involved.
fn write_vault_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("invalid wallet file path")?;
    create_private_dir_all(parent)
        .map_err(|_| "could not create the application data directory".to_string())?;

    let temp_path = path.with_extension("tmp");
    // A leftover temp file means a previous attempt died mid-write. It holds
    // no usable wallet, so clearing it is safe; `create_new` below still
    // provides the `O_EXCL` semantics that defeat a symlink swap.
    if temp_path.exists() {
        let _ = fs::remove_file(&temp_path);
    }

    let mut file = create_new_private_file(&temp_path)
        .map_err(|_| "could not create the wallet file".to_string())?;
    file.write_all(bytes)
        .map_err(|_| "could not write the wallet file".to_string())?;
    // Without this the rename can become visible before the contents reach
    // disk, so a crash leaves a present-but-empty vault.
    file.sync_all()
        .map_err(|_| "could not flush the wallet file to disk".to_string())?;
    drop(file);

    // Re-checked here rather than relying on `create_new` against the final
    // path, because atomic replacement rules that out (POSIX `rename` always
    // replaces). The remaining TOCTOU window is accepted: exploiting it
    // requires an attacker already running as this user, who could overwrite
    // the vault directly anyway — whereas the lockout this replaces was
    // hurting ordinary users with no attacker present.
    if path.exists() {
        let _ = fs::remove_file(&temp_path);
        return Err("a wallet already exists on this device".to_string());
    }

    fs::rename(&temp_path, path)
        .map_err(|_| "could not finalize the wallet file".to_string())?;

    // On Unix the rename itself is only durable once the directory entry is
    // synced; on Windows `MoveFileEx` ordering already covers this.
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Write `bytes` to `path` atomically (temp file, fsync, rename over the
/// target) -- the same crash-safety technique as `write_vault_atomically`,
/// but deliberately a separate function, not a shared one: that function's
/// whole point includes refusing to ever overwrite an existing vault, which
/// is wrong for a file like the Solana account count that is *meant* to be
/// legitimately rewritten every time an account is added. What this DOES
/// share with it is the actual crash-safety property -- no reader of this
/// file ever observes a partially-written value, torn mid-write by a power
/// loss or crash between open and close.
fn write_file_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("invalid file path")?;
    create_private_dir_all(parent)
        .map_err(|_| "could not create the application data directory".to_string())?;

    let temp_path = path.with_extension("tmp");
    if temp_path.exists() {
        let _ = fs::remove_file(&temp_path);
    }

    let mut file = create_new_private_file(&temp_path).map_err(|_| "could not create a temporary file".to_string())?;
    file.write_all(bytes).map_err(|_| "could not write the file".to_string())?;
    file.sync_all().map_err(|_| "could not flush the file to disk".to_string())?;
    drop(file);

    fs::rename(&temp_path, path).map_err(|_| "could not finalize the file".to_string())?;

    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Read the persisted Solana account count. Defaults to `1` (just account
/// 0) when the file is missing or unparseable -- the same "fail open"
/// reasoning as `read_unlock_failures`, and the correct default for a
/// wallet that predates this feature or has never added a second Solana
/// account: account 0 always exists, so `1` is the honest floor, not `0`.
fn read_solana_account_count(path: &Path) -> u32 {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .filter(|&n: &u32| n >= 1)
        .unwrap_or(1)
}

/// Persist the Solana account count, atomically (see `write_file_atomically`).
fn write_solana_account_count(path: &Path, count: u32) -> Result<(), String> {
    write_file_atomically(path, count.to_string().as_bytes())
}

/// Path the persisted Solana account count lives at, alongside the vault.
fn solana_accounts_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(SOLANA_ACCOUNTS_FILENAME))
}

/// Path the sealed vault lives at, inside Tauri's resolved app data
/// directory (never a hardcoded path — that varies per user and per OS).
fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(VAULT_FILENAME))
}

/// Path of the persisted failed-unlock counter, alongside the vault.
fn failures_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(UNLOCK_FAILURES_FILENAME))
}

fn app_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|_| "could not resolve the application data directory".to_string())
}

/// Generate a new BIP-39 mnemonic and return its words for display.
///
/// This is the one and only time the phrase crosses the bridge. The
/// mnemonic itself stays in [`PendingMnemonic`] for the confirm step.
#[tauri::command]
fn generate_new_mnemonic(
    word_count: u32,
    pending: State<'_, PendingMnemonic>,
) -> Result<NewMnemonic, String> {
    let word_count = match word_count {
        12 => WordCount::Twelve,
        24 => WordCount::TwentyFour,
        _ => return Err("word count must be 12 or 24".to_string()),
    };

    let mnemonic =
        SecretMnemonic::generate(word_count).map_err(|_| "failed to generate a recovery phrase")?;

    // The words are returned for display, so they necessarily become plain
    // `String`s at this boundary — that copy is the residual exposure
    // `expose_secret`'s docs warn about, and it's unavoidable for a phrase
    // the user has to be shown. It must not outlive the backup screen.
    let words: Vec<String> = mnemonic.expose_secret(|phrase| {
        phrase.split_whitespace().map(str::to_string).collect()
    });

    let bank = shuffled_indices(words.len());

    let mut guard = pending
        .0
        .lock()
        .map_err(|_| "wallet creation state is unavailable")?;
    *guard = Some(PendingCreation {
        mnemonic,
        bank: bank.clone(),
    });

    Ok(NewMnemonic { words, bank })
}

/// Whether a sealed vault already exists in app data.
#[tauri::command]
fn wallet_exists(app: AppHandle) -> bool {
    vault_path(&app).map(|p| p.exists()).unwrap_or(false)
}

/// Open the sealed vault with `password` and unlock the wallet for this
/// session. Returns the derived account-0 address (public data).
#[tauri::command]
fn unlock_wallet(
    password: String,
    app: AppHandle,
    unlocked: State<'_, UnlockedWallet>,
) -> Result<String, String> {
    // Wrapped the moment it arrives, so it is scrubbed on every exit path
    // including the error ones.
    //
    // What this deliberately does NOT claim to reach: Tauri's IPC layer and
    // serde have already materialized their own copies of this string
    // before this function is entered, and both are dropped without
    // scrubbing. This removes our copy, not every copy — the remaining ones
    // are outside this crate's control and are why M8 (locking pages out of
    // swap) is the real ceiling here.
    let password = Zeroizing::new(password);
    let path = vault_path(&app)?;
    let failures = failures_path(&app)?;
    unlock_impl(&unlocked, &password, &path, &failures, sleep_for)
}

/// Clear the unlocked wallet from memory, ending the session.
#[tauri::command]
fn lock_wallet(unlocked: State<'_, UnlockedWallet>) -> Result<(), String> {
    // Dropping the `SecretMnemonic` zeroizes it.
    unlocked.clear();
    Ok(())
}

/// Real delay enforcer, injected into [`unlock_impl`] so tests can pass a
/// no-op instead of sleeping for real.
fn sleep_for(d: Duration) {
    if !d.is_zero() {
        std::thread::sleep(d);
    }
}

/// The testable core of [`unlock_wallet`].
///
/// `delay` is injected so tests exercise the counter without real sleeps.
fn unlock_impl(
    unlocked: &UnlockedWallet,
    password: &str,
    vault_path: &Path,
    failures_path: &Path,
    delay: impl Fn(Duration),
) -> Result<String, String> {
    let mnemonic = open_vault_with_password(password, vault_path, failures_path, delay)?;

    // Seed is re-derived from the phrase rather than stored — deterministic,
    // so nothing is lost by not persisting it.
    let address = EvmAccountKey::derive(&mnemonic.to_seed(""), 0)
        .map_err(|_| "failed to derive an account from the recovery phrase".to_string())?
        .address()
        .to_checksummed_hex();

    let mut guard = unlocked
        .0
        .lock()
        .map_err(|_| "wallet session state is unavailable")?;
    *guard = Some(UnlockedSession {
        mnemonic,
        unlocked_at: Instant::now(),
    });

    Ok(address)
}

/// Open the sealed vault fresh, right now, given `password` — the shared
/// core of both [`unlock_impl`] (which additionally starts a session) and
/// every reveal/export command below (which use this as a re-authentication
/// gate: proof the caller knows the passphrase *at this moment*, independent
/// of whether a session happens to be unlocked already). Deliberately one
/// implementation, not a copy per caller — the rate-limiting behavior below
/// is the actual brute-force defense, and a second, slightly-different copy
/// would be exactly the kind of drift that quietly weakens it for whichever
/// caller has the weaker copy.
fn open_vault_with_password(
    password: &str,
    vault_path: &Path,
    failures_path: &Path,
    delay: impl Fn(Duration),
) -> Result<SecretMnemonic, String> {
    let bytes = fs::read(vault_path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => "no wallet exists on this device yet".to_string(),
        _ => "could not read the wallet file".to_string(),
    })?;

    // Version is checked before the passphrase is even used, so an
    // out-of-date vault reports the real problem instead of spending ~10s in
    // the KDF and then surfacing as a decryption failure. This also isn't a
    // password oracle — it tells the user nothing about their passphrase.
    let vault = SealedVault::from_bytes(&bytes).map_err(|e| match e {
        VaultError::UnsupportedVersion => {
            "this wallet file was created by an earlier version of Crypt Wallet \
             and cannot be opened by this build. Restore from your recovery \
             phrase instead."
                .to_string()
        }
        _ => "the wallet file is damaged or not a Crypt Wallet vault".to_string(),
    })?;

    // Rate limit: wait out the penalty earned by prior consecutive failures
    // *before* attempting the KDF, so the delay can't be skipped by killing
    // the process mid-wait — on restart the count is still on disk and the
    // same delay applies. Only wrong-passphrase failures (the `vault.open`
    // path below) increment it; a missing/corrupt/old-format file is not a
    // guess and is handled above without touching the counter.
    //
    // Honest limit: an attacker who can read the vault for offline cracking
    // can also delete this counter file to reset the throttle. It is not
    // claimed to stop that attacker — it stops the in-app "kill and relaunch
    // to reset an in-memory counter" loop the review described, which a
    // memory-only counter would not. Shared across unlock AND every
    // reveal/export command: a reveal/export command is just as much a
    // passphrase-guessing surface as unlock itself, and must never have
    // weaker throttling.
    let failures = read_unlock_failures(failures_path);
    delay(unlock_delay(failures));

    // Deliberately one message for wrong-passphrase AND tampered/corrupt
    // ciphertext. AEAD tag verification cannot tell them apart anyway, and
    // reporting which occurred would hand an attacker a free oracle.
    let decrypted = match vault.open(password) {
        Ok(decrypted) => decrypted,
        Err(_) => {
            write_unlock_failures(failures_path, failures.saturating_add(1));
            return Err("could not unlock the wallet: check your passphrase".to_string());
        }
    };

    // Defense in depth behind the version check: a v2 vault whose plaintext
    // somehow isn't a valid phrase is corrupt in a way the AEAD tag couldn't
    // catch (i.e. it was sealed wrong), not a passphrase problem — so it does
    // not count against the passphrase throttle.
    let phrase = std::str::from_utf8(decrypted.as_bytes())
        .map_err(|_| "the wallet file's contents are not a valid recovery phrase".to_string())?;
    let mnemonic = SecretMnemonic::import(phrase)
        .map_err(|_| "the wallet file's contents are not a valid recovery phrase".to_string())?;

    // Success resets the throttle.
    let _ = fs::remove_file(failures_path);

    Ok(mnemonic)
}

/// Reveal the wallet's recovery phrase. Requires a session to already be
/// unlocked (this is reached from inside the unlocked-wallet UI, never from
/// the lock screen) AND a fresh, successful re-entry of the passphrase via
/// [`open_vault_with_password`] — an already-unlocked session is NOT by
/// itself sufficient to reveal the phrase, since the whole point is
/// confirming the person at the keyboard right now knows it, not that they
/// (or anyone else) unlocked the app at some earlier point.
///
/// The phrase crosses the IPC bridge exactly once per reveal, the same rule
/// [`generate_new_mnemonic`] follows for the initial backup screen — nothing
/// about this command's exposure is looser than that one.
#[tauri::command]
fn reveal_mnemonic(
    password: String,
    app: AppHandle,
    unlocked: State<'_, UnlockedWallet>,
) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let path = vault_path(&app)?;
    let failures = failures_path(&app)?;
    reveal_mnemonic_impl(&unlocked, &password, &path, &failures, sleep_for)
}

/// The testable core of [`reveal_mnemonic`].
fn reveal_mnemonic_impl(
    unlocked: &UnlockedWallet,
    password: &str,
    vault_path: &Path,
    failures_path: &Path,
    delay: impl Fn(Duration),
) -> Result<String, String> {
    {
        let guard = unlocked.0.lock().map_err(|_| "wallet session state is unavailable")?;
        guard.as_ref().ok_or("wallet is locked")?;
    }

    let mnemonic = open_vault_with_password(password, vault_path, failures_path, delay)?;
    Ok(mnemonic.expose_secret(|phrase| phrase.to_string()))
}

/// Export EVM account `index`'s raw secp256k1 private key, as a
/// `0x`-prefixed 32-byte hex string — the format MetaMask and every other
/// EVM wallet's "import account" expects. Deliberately one key per account
/// *index*, not one per chain: this app's whole EVM model (see
/// `crypto/src/derivation.rs`) is one address/key per index shared across
/// every EVM-compatible network, so there is nothing chain-specific to
/// export here even in principle. The frontend must label this
/// accordingly — see index.html's export panel.
///
/// Same re-authentication requirement as [`reveal_mnemonic`]: a session
/// must already be unlocked, AND the passphrase must be freshly re-entered
/// for this specific export.
#[tauri::command]
fn export_evm_private_key(
    password: String,
    index: u32,
    app: AppHandle,
    unlocked: State<'_, UnlockedWallet>,
) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let path = vault_path(&app)?;
    let failures = failures_path(&app)?;
    export_evm_private_key_impl(&unlocked, &password, index, &path, &failures, sleep_for)
}

/// The testable core of [`export_evm_private_key`].
fn export_evm_private_key_impl(
    unlocked: &UnlockedWallet,
    password: &str,
    index: u32,
    vault_path: &Path,
    failures_path: &Path,
    delay: impl Fn(Duration),
) -> Result<String, String> {
    {
        let guard = unlocked.0.lock().map_err(|_| "wallet session state is unavailable")?;
        guard.as_ref().ok_or("wallet is locked")?;
    }

    let mnemonic = open_vault_with_password(password, vault_path, failures_path, delay)?;
    let seed = mnemonic.to_seed("");
    let account =
        EvmAccountKey::derive(&seed, index).map_err(|_| "failed to derive the requested account".to_string())?;

    Ok(account.expose_secret(|signing_key| format!("0x{}", hex_encode(&signing_key.to_bytes()))))
}

/// Export Solana account `index`'s ed25519 keypair bytes, Base58-encoded —
/// the 64-byte `secret(32) || public(32)` layout Phantom, Solflare, and the
/// Solana CLI all use for "import private key" (matches
/// `ed25519_dalek::SigningKey::to_keypair_bytes`'s own documented layout,
/// which Solana's ecosystem adopted directly). One key per account index,
/// entirely separate key material from the EVM export above — see
/// `crypto/src/solana.rs`'s module doc comment for why Solana derivation
/// shares nothing with EVM's. The frontend must label this accordingly.
///
/// Same re-authentication requirement as [`reveal_mnemonic`].
#[tauri::command]
fn export_solana_private_key(
    password: String,
    index: u32,
    app: AppHandle,
    unlocked: State<'_, UnlockedWallet>,
) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let path = vault_path(&app)?;
    let failures = failures_path(&app)?;
    export_solana_private_key_impl(&unlocked, &password, index, &path, &failures, sleep_for)
}

/// The testable core of [`export_solana_private_key`].
fn export_solana_private_key_impl(
    unlocked: &UnlockedWallet,
    password: &str,
    index: u32,
    vault_path: &Path,
    failures_path: &Path,
    delay: impl Fn(Duration),
) -> Result<String, String> {
    {
        let guard = unlocked.0.lock().map_err(|_| "wallet session state is unavailable")?;
        guard.as_ref().ok_or("wallet is locked")?;
    }

    let mnemonic = open_vault_with_password(password, vault_path, failures_path, delay)?;
    let seed = mnemonic.to_seed("");
    let account =
        SolanaAccountKey::derive(&seed, index).map_err(|_| "failed to derive the requested account".to_string())?;

    Ok(account.expose_secret(|signing_key| bs58::encode(signing_key.to_keypair_bytes()).into_string()))
}

/// Verify the user's word ordering against the pending mnemonic, then seal
/// the derived seed to disk under `password`.
///
/// Returns the derived account-0 address (public data) on success.
#[tauri::command]
fn confirm_and_seal_wallet(
    selected_order: Vec<usize>,
    password: String,
    app: AppHandle,
    pending: State<'_, PendingMnemonic>,
) -> Result<String, String> {
    // See `unlock_wallet` for what this does and does not scrub.
    let password = Zeroizing::new(password);
    let path = vault_path(&app)?;
    confirm_and_seal_impl(&pending, &selected_order, &password, &path)
}

/// The testable core of [`confirm_and_seal_wallet`], separated from the
/// Tauri plumbing so it can be exercised against a temp directory without
/// standing up an app runtime.
fn confirm_and_seal_impl(
    pending: &PendingMnemonic,
    selected_order: &[usize],
    password: &str,
    vault_path: &Path,
) -> Result<String, String> {
    // Counts characters, not bytes: `"👍👍👍"` is 12 bytes but 3 characters,
    // and byte length would wave it through as if it met the minimum.
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }

    // Checked before the KDF as well as at write time. The `create_new`
    // below is the authoritative guard (it can't be raced); this early
    // check just avoids burning ~10s of Argon2id on a doomed attempt.
    if vault_path.exists() {
        return Err("a wallet already exists on this device".to_string());
    }

    let mut guard = pending
        .0
        .lock()
        .map_err(|_| "wallet creation state is unavailable")?;
    let creation = guard
        .as_ref()
        .ok_or("no wallet creation is in progress")?;

    // Verification now happens entirely on slot numbers: the frontend
    // reports which confirmation slots were clicked and in what order, and
    // `bank` — which only this process has — maps each slot back to a
    // position in the phrase. The phrase is not read at all here.
    //
    // `bank.get(slot)` rather than indexing: `selected_order` is untrusted
    // input from the webview and may contain out-of-range or repeated
    // values, which must fail the check rather than panic.
    let confirmed = selected_order.len() == creation.bank.len()
        && selected_order
            .iter()
            .enumerate()
            .all(|(expected_position, &slot)| {
                creation
                    .bank
                    .get(slot)
                    .is_some_and(|&word_index| word_index == expected_position)
            });

    if !confirmed {
        // Deliberately does NOT clear the pending mnemonic: a mis-click on
        // the confirm screen is an ordinary user error, and discarding the
        // phrase here would force them to restart with a different one.
        // Nothing has been written at this point.
        return Err("the recovery phrase confirmation did not match".to_string());
    }

    // Past this point the phrase is confirmed and we're committing.
    let result = (|| {
        let seed = creation.mnemonic.to_seed("");
        let account = EvmAccountKey::derive(&seed, 0)
            .map_err(|_| "failed to derive an account from the recovery phrase".to_string())?;
        let address = account.address().to_checksummed_hex();

        // What gets sealed is the **mnemonic**, not the derived seed, and
        // unlock re-derives the seed from it (mnemonic -> seed is
        // deterministic, so nothing is lost by not storing the seed).
        //
        // Deliberate tradeoff, per architecture spec §D.5: the mnemonic is
        // the more dangerous secret to have sealed here, because it is
        // *portable* — an attacker who cracks the vault can type it into any
        // wallet on any device, whereas a bare seed is useful only to
        // software that speaks this exact derivation scheme. That extra
        // exposure is accepted in exchange for recoverability: sealing only
        // the seed would permanently foreclose the authenticated
        // reveal/export flow, leaving a user who lost their paper backup
        // holding a wallet they can never migrate or restore elsewhere.
        let sealed = creation
            .mnemonic
            .expose_secret(|phrase| {
                SealedVault::seal(phrase.as_bytes(), password, KdfParams::DESKTOP_DEFAULT)
            })
            .map_err(|_| "failed to encrypt the wallet".to_string())?;

        write_vault_atomically(vault_path, &sealed.to_bytes())?;

        Ok(address)
    })();

    // Cleared only once the wallet is durably on disk. On failure the phrase
    // stays pending so the user can retry without restarting the flow —
    // safe now that the write is atomic, since a failed attempt persists
    // nothing. The tradeoff is that the mnemonic lives in memory longer on
    // that path than it would if we discarded it unconditionally.
    if result.is_ok() {
        *guard = None;
    }
    result
}

/// The checksummed address for EVM account `index` of the currently
/// unlocked wallet, powering the frontend's account switcher and its send-
/// destination picker. Requires an unlocked session — an address derived
/// from a mnemonic that isn't in memory can't be returned.
///
/// Bounds checking is deliberately NOT duplicated here: `EvmAccountKey::derive`
/// already rejects `index >= 2^31` (the hardened-key range) with
/// `DerivationError::IndexOutOfRange` — see `crypto/src/derivation.rs`. This
/// command just maps that existing rejection to the same string-error
/// convention every other command in this module uses. The frontend also
/// caps how many indices it will ever ask for (`MAX_ACCOUNTS` in
/// `main.ts`) — an open-ended "derive account #4 billion" isn't something
/// the UI invites, even though this command would reject it safely on its
/// own.
#[tauri::command]
fn get_account_address(index: u32, unlocked: State<'_, UnlockedWallet>) -> Result<String, String> {
    get_account_address_impl(index, &unlocked)
}

/// The testable core of [`get_account_address`].
fn get_account_address_impl(index: u32, unlocked: &UnlockedWallet) -> Result<String, String> {
    let guard = unlocked
        .0
        .lock()
        .map_err(|_| "wallet session state is unavailable")?;
    let session = guard.as_ref().ok_or("wallet is locked")?;

    let seed = session.mnemonic.to_seed("");
    let account = EvmAccountKey::derive(&seed, index)
        .map_err(|_| "failed to derive the requested account".to_string())?;
    Ok(account.address().to_checksummed_hex())
}

/// The Base58 Solana address for Solana account `index` of the currently
/// unlocked wallet — the display-only counterpart of [`get_account_address`]
/// for the app's new, separate Solana account type (see
/// `crypto/src/solana.rs`'s module doc comment for why Solana derivation is
/// a genuinely different algorithm from EVM's, not a variant of it).
///
/// DISPLAY ONLY at this phase: no balance fetching, no signing. This command
/// exists purely to prove the derivation module is correctly wired into the
/// app's existing account architecture, mirroring the same
/// derivation-index pattern `get_account_address` already uses for EVM
/// accounts — see the project notes on why balance fetching and signing are
/// each their own later, separately-reviewed phase.
///
/// Bounds checking, same story as `get_account_address`: not duplicated
/// here, since `SolanaAccountKey::derive` already rejects an out-of-range
/// index (see `crypto/src/solana.rs`).
#[tauri::command]
fn get_solana_account_address(index: u32, unlocked: State<'_, UnlockedWallet>) -> Result<String, String> {
    get_solana_account_address_impl(index, &unlocked)
}

/// The testable core of [`get_solana_account_address`].
fn get_solana_account_address_impl(index: u32, unlocked: &UnlockedWallet) -> Result<String, String> {
    let guard = unlocked
        .0
        .lock()
        .map_err(|_| "wallet session state is unavailable")?;
    let session = guard.as_ref().ok_or("wallet is locked")?;

    let seed = session.mnemonic.to_seed("");
    let account = SolanaAccountKey::derive(&seed, index)
        .map_err(|_| "failed to derive the requested account".to_string())?;
    Ok(account.address())
}

/// The bech32 native SegWit Bitcoin address for Bitcoin account `index` of
/// the currently unlocked wallet -- the display-only counterpart of
/// [`get_account_address`]/[`get_solana_account_address`] for the app's
/// newest, separate Bitcoin account type (see `crypto/src/bitcoin.rs`'s
/// module doc comment for why Bitcoin derivation reuses EVM's BIP-32
/// machinery but not its address encoding).
///
/// DISPLAY ONLY at this phase: no UTXO handling, no transaction
/// construction, no signing -- same staged-rollout discipline as
/// `get_solana_account_address` before it. Bitcoin derivation (Phase A) was
/// verified byte-for-byte against the official BIP-84 test vectors and
/// cross-checked against three independent reference wallets before this
/// command was written.
///
/// Bounds checking, same story as `get_account_address`: not duplicated
/// here, since `BitcoinAccountKey::derive` already rejects an out-of-range
/// index (see `crypto/src/bitcoin.rs`).
#[tauri::command]
fn get_bitcoin_account_address(index: u32, unlocked: State<'_, UnlockedWallet>) -> Result<String, String> {
    get_bitcoin_account_address_impl(index, &unlocked)
}

/// The testable core of [`get_bitcoin_account_address`].
fn get_bitcoin_account_address_impl(index: u32, unlocked: &UnlockedWallet) -> Result<String, String> {
    let guard = unlocked
        .0
        .lock()
        .map_err(|_| "wallet session state is unavailable")?;
    let session = guard.as_ref().ok_or("wallet is locked")?;

    let seed = session.mnemonic.to_seed("");
    let account = BitcoinAccountKey::derive(&seed, index)
        .map_err(|_| "failed to derive the requested account".to_string())?;
    Ok(account.address())
}

/// How many Solana accounts this wallet has created, persisted (see
/// `read_solana_account_count`). Does NOT require an unlocked session --
/// it's a plain integer read from a non-secret sidecar file, not a
/// derivation, so there is nothing here that depends on the mnemonic being
/// in memory. The frontend calls this right after unlock to know how many
/// `get_solana_account_address` calls to make, mirroring how EVM's
/// `MAX_ACCOUNTS` constant tells `loadAccounts` how many indices to derive
/// -- except this one reflects a real, persisted count instead of a fixed
/// ceiling.
#[tauri::command]
fn get_solana_account_count(app: AppHandle) -> Result<u32, String> {
    let path = solana_accounts_path(&app)?;
    Ok(read_solana_account_count(&path))
}

/// Derive and persist one more Solana account: read the current count,
/// derive account `count` (the next unused index), write `count + 1` back
/// atomically, and return the new account's address. Requires an unlocked
/// session, same as every other command that derives from the mnemonic.
///
/// The persist-then-derive ordering matters: if derivation somehow failed
/// after the count were already incremented, the frontend would believe an
/// account exists that was never actually shown to the user -- deriving
/// FIRST, and only persisting the new count once that succeeds, means a
/// failure here leaves the count exactly where it was, not silently ahead
/// of what the user has actually seen.
#[tauri::command]
fn add_solana_account(app: AppHandle, unlocked: State<'_, UnlockedWallet>) -> Result<String, String> {
    let path = solana_accounts_path(&app)?;
    add_solana_account_impl(&unlocked, &path)
}

/// The testable core of [`add_solana_account`].
fn add_solana_account_impl(unlocked: &UnlockedWallet, path: &Path) -> Result<String, String> {
    let current_count = read_solana_account_count(path);
    let new_index = current_count; // 0-based index of the account being added.

    let address = get_solana_account_address_impl(new_index, unlocked)?;

    write_solana_account_count(path, current_count + 1)?;

    Ok(address)
}

/// Sign an EIP-1559 Sepolia transaction sending from account `from_index` of
/// the currently-unlocked wallet, and return the raw signed transaction as a
/// `0x`-prefixed hex string, ready for `eth_sendRawTransaction`.
///
/// `from_index` is which of the wallet's own accounts the frontend's account
/// switcher currently has active — this used to be hardcoded to account 0,
/// back when only one account was ever exposed; now that the UI can select
/// any derived account, signing has to follow it. Bounds checking is the
/// same story as [`get_account_address`]: not duplicated here, because
/// `EvmAccountKey::derive` below already rejects an out-of-range index.
///
/// Does NOT broadcast. Signing and broadcasting are deliberately separate:
/// the frontend already owns RPC communication via `viem`, and duplicating
/// that in Rust would mean two places that need to agree on how to talk to
/// an endpoint, with no benefit — a signed transaction is not secret (it is
/// about to go out over the public network), so handing it back for the
/// frontend to broadcast leaks nothing that broadcasting itself wouldn't.
///
/// `to`/`value_wei`/fees are untrusted input from the webview and are
/// parsed strictly: a malformed address or a numeric string that doesn't
/// parse cleanly is rejected outright, never guessed at or coerced.
///
/// The chain-id checks are deliberately redundant with the frontend only
/// ever constructing transactions for a network it thinks is sendable —
/// this command is the last line of defense before a real signature is
/// produced, so it does not trust the caller's chain_id, however that
/// value got here. Two checks, not one: first that it's a chain this app
/// recognizes at all (`require_supported_chain_id` — see
/// `SUPPORTED_CHAIN_IDS` for the full list), then the separate, narrower
/// requirement that this specific chain is one this app will actually sign
/// for (`require_sendable_chain_id` — see `SENDABLE_CHAIN_IDS`; every
/// mainnet is read-only for now, see that check's own comment below for
/// why this is deliberate, not a bug). Every other numeric argument
/// (nonce, fees, gas limit) is taken as given once past basic parsing:
/// those come from the RPC node's own `getTransactionCount`/fee-estimate
/// responses, not from the user, and
/// this command has no independent way to second-guess them.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn sign_transaction(
    to: String,
    value_wei: String,
    nonce: u64,
    max_fee_per_gas: String,
    max_priority_fee_per_gas: String,
    gas_limit: u64,
    chain_id: u64,
    from_index: u32,
    unlocked: State<'_, UnlockedWallet>,
) -> Result<String, String> {
    sign_transaction_impl(
        &unlocked,
        &to,
        &value_wei,
        nonce,
        &max_fee_per_gas,
        &max_priority_fee_per_gas,
        gas_limit,
        chain_id,
        from_index,
    )
}

/// The testable core of [`sign_transaction`].
#[allow(clippy::too_many_arguments)]
fn sign_transaction_impl(
    unlocked: &UnlockedWallet,
    to: &str,
    value_wei: &str,
    nonce: u64,
    max_fee_per_gas: &str,
    max_priority_fee_per_gas: &str,
    gas_limit: u64,
    chain_id: u64,
    from_index: u32,
) -> Result<String, String> {
    require_supported_chain_id(chain_id)?;
    // As of the 2026-08-22 policy reversal, `SENDABLE_CHAIN_IDS` equals
    // `SUPPORTED_CHAIN_IDS` -- every mainnet this app can read is now also
    // one it will sign for. This call is not dead code, though: the two
    // lists remain separate on purpose (see `SENDABLE_CHAIN_IDS`'s own doc
    // comment) so a future restriction only has to change one list, not
    // remove this call site.
    require_sendable_chain_id(chain_id)?;

    // Strict EIP-55 checksum validation — rejects malformed input outright
    // rather than attempting to "fix" casing or accept an unchecksummed
    // address. `None` selects plain EIP-55 rather than EIP-1191's
    // chain-specific checksum variant.
    let to_address = AlloyAddress::parse_checksummed(&to, None)
        .map_err(|_| "recipient address is not a well-formed, checksummed address".to_string())?;

    // `U256`'s `FromStr` (verified against ruint's source) accepts plain
    // decimal or a "0x"-prefixed hex string and rejects anything else
    // cleanly — no separate radix argument needed.
    let value: U256 = value_wei
        .parse()
        .map_err(|_| "amount is not a valid integer".to_string())?;
    let max_fee_per_gas = parse_gas_price(&max_fee_per_gas, "max fee per gas")?;
    let max_priority_fee_per_gas =
        parse_gas_price(&max_priority_fee_per_gas, "max priority fee per gas")?;

    let unsigned = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(to_address),
        value,
        access_list: AccessList::default(),
        input: AlloyBytes::default(),
    };

    sign_unsigned_transaction(&unsigned, from_index, unlocked)
}

/// Encode a Solidity `transfer(address,uint256)` call — the standard ERC-20
/// transfer function, selector `0xa9059cbb` — via `alloy`'s `sol!`-generated
/// `SolCall` implementation, never hand-packed. The selector is not just
/// assumed to be right because it came out of the macro: it's checked
/// against the real, standardized value on every call, so a mistake in this
/// function's Solidity signature (which the macro compiles down to a
/// selector at compile time) would surface immediately at runtime instead
/// of silently invoking the wrong function on whatever contract `to` points
/// at — the single most dangerous failure mode for a token send.
fn encode_erc20_transfer(to: AlloyAddress, amount: U256) -> Result<Vec<u8>, String> {
    let encoded = IERC20::transferCall { to, amount }.abi_encode();

    const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    if encoded.get(..4) != Some(TRANSFER_SELECTOR.as_slice()) {
        // Not expected to be reachable — `sol!` derives the selector from
        // the function signature at compile time — but this function signs
        // real transactions, so an internal encoding mistake gets caught
        // here rather than trusted blind.
        return Err("internal error: encoded ERC-20 transfer calldata has an unexpected function selector".to_string());
    }

    Ok(encoded)
}

/// Sign an EIP-1559 Sepolia transaction that calls `transfer(address,uint256)`
/// on `token_address` — an ERC-20 token send — from account `from_index` of
/// the currently-unlocked wallet, returning the raw signed transaction the
/// same way [`sign_transaction`] does.
///
/// This is a separate command from [`sign_transaction`], not that command
/// generalized with an optional `data` field: an ERC-20 transfer has a
/// materially different shape (the transaction's own `to` is a contract, not
/// the fund recipient; `value` is always zero; the recipient and amount live
/// inside ABI-encoded `data`), and threading that distinction through a
/// single command's parameters — "when `data` is present, some other
/// argument means something different" — would be exactly the kind of
/// implicit, easy-to-misuse API shape this codebase avoids elsewhere.
/// Keeping them separate makes each command's parameters mean one thing.
///
/// `token_address` is checksum-validated the same as any address, but note
/// its ROLE here differs from a plain ETH send's `to`: it's a contract being
/// called, not a fund recipient, and is never trusted beyond "well-formed,
/// checksummed address" — encoding failures or a non-token contract there
/// are the RPC node's problem to reject at broadcast time, not something
/// this command can detect.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn sign_token_transfer(
    token_address: String,
    to: String,
    amount_raw: String,
    nonce: u64,
    max_fee_per_gas: String,
    max_priority_fee_per_gas: String,
    gas_limit: u64,
    chain_id: u64,
    from_index: u32,
    unlocked: State<'_, UnlockedWallet>,
) -> Result<String, String> {
    sign_token_transfer_impl(
        &unlocked,
        &token_address,
        &to,
        &amount_raw,
        nonce,
        &max_fee_per_gas,
        &max_priority_fee_per_gas,
        gas_limit,
        chain_id,
        from_index,
    )
}

/// The testable core of [`sign_token_transfer`].
#[allow(clippy::too_many_arguments)]
fn sign_token_transfer_impl(
    unlocked: &UnlockedWallet,
    token_address: &str,
    to: &str,
    amount_raw: &str,
    nonce: u64,
    max_fee_per_gas: &str,
    max_priority_fee_per_gas: &str,
    gas_limit: u64,
    chain_id: u64,
    from_index: u32,
) -> Result<String, String> {
    // Same two-layer rule as sign_transaction_impl, no exceptions for token
    // sends: this is the last line of defense before a real signature is
    // produced, so it does not trust the caller's chain_id.
    require_supported_chain_id(chain_id)?;
    // See sign_transaction_impl's identical check -- same reasoning, kept
    // as its own call site even though both lists agree today.
    require_sendable_chain_id(chain_id)?;

    let token_contract = AlloyAddress::parse_checksummed(token_address, None).map_err(|_| {
        "token contract address is not a well-formed, checksummed address".to_string()
    })?;
    let recipient = AlloyAddress::parse_checksummed(to, None)
        .map_err(|_| "recipient address is not a well-formed, checksummed address".to_string())?;

    // The token's smallest-unit amount (e.g. USDC's 6-decimal raw integer),
    // already converted from a human amount by the frontend using the
    // token's real on-chain `decimals()` — this command has no way to
    // second-guess that conversion, only to parse the integer strictly.
    let amount: U256 = amount_raw
        .parse()
        .map_err(|_| "amount is not a valid integer".to_string())?;

    let max_fee_per_gas = parse_gas_price(max_fee_per_gas, "max fee per gas")?;
    let max_priority_fee_per_gas =
        parse_gas_price(max_priority_fee_per_gas, "max priority fee per gas")?;

    let calldata = encode_erc20_transfer(recipient, amount)?;

    let unsigned = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        // The transaction calls the TOKEN CONTRACT, not the recipient --
        // the recipient only appears as an encoded parameter inside `input`.
        to: TxKind::Call(token_contract),
        // No ETH moves with an ERC-20 transfer call; the transferred value
        // is entirely inside `calldata`.
        value: U256::ZERO,
        access_list: AccessList::default(),
        input: AlloyBytes::from(calldata),
    };

    sign_unsigned_transaction(&unsigned, from_index, unlocked)
}

/// Shared signing core for both [`sign_transaction_impl`] (plain ETH sends)
/// and [`sign_token_transfer_impl`] (ERC-20 sends): derive the sending
/// account, sign `unsigned`'s EIP-1559 signing hash, and self-check the
/// result before returning it. Factored out specifically so the self-check
/// — recover the signer from the signature this same call just produced,
/// and refuse to return anything that doesn't recover to the expected
/// account — can never accidentally exist in one signing path and not the
/// other; both call this, so both get it automatically.
fn sign_unsigned_transaction(
    unsigned: &TxEip1559,
    from_index: u32,
    unlocked: &UnlockedWallet,
) -> Result<String, String> {
    let guard = unlocked
        .0
        .lock()
        .map_err(|_| "wallet session state is unavailable")?;
    let session = guard.as_ref().ok_or("wallet is locked")?;

    let seed = session.mnemonic.to_seed("");
    let account = EvmAccountKey::derive(&seed, from_index)
        .map_err(|_| "failed to derive the sending account".to_string())?;

    // Only the raw signed bytes leave this closure — the signing key
    // itself never does.
    let raw_signed_hex = account.expose_secret(|signing_key| -> Result<String, String> {
        let signing_hash = unsigned.signature_hash();

        // RFC6979-deterministic (same key + same hash always produces the
        // same signature, so no signing-time RNG that could be weak or
        // reused), and — verified against k256's own source, not assumed —
        // k256's SigningKey<Secp256k1> normalizes the resulting signature
        // to low-S form and adjusts the recovery ID to match before
        // returning it. Ethereum's mempool rejects high-S signatures
        // (EIP-2), so a signer that didn't do this would produce
        // transactions real nodes refuse — normalize_s() is deliberately
        // NOT called again here, because calling it on an
        // already-normalized signature without also re-deriving the
        // matching recovery ID would desynchronize the two.
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(signing_hash.as_slice())
            .map_err(|_| "failed to sign transaction".to_string())?;

        let r = U256::from_be_slice(signature.r().to_bytes().as_ref());
        let s = U256::from_be_slice(signature.s().to_bytes().as_ref());
        let alloy_signature = PrimitiveSignature::new(r, s, recovery_id.is_y_odd());

        // Self-check before this ever leaves the process: recover the
        // signer from the signature this same call just produced, and
        // confirm it's actually account `from_index`. A signature that
        // doesn't recover to the account that supposedly made it is not a
        // transaction that should ever be returned for broadcast,
        // regardless of what upstream produced it — and regardless of
        // whether it's a plain ETH send or a token-transfer call, this
        // check applies identically to both.
        let recovered = alloy_signature
            .recover_address_from_prehash(&signing_hash)
            .map_err(|_| "produced signature failed self-verification".to_string())?;
        let expected_sender = AlloyAddress::new(*account.address().as_bytes());
        if recovered != expected_sender {
            return Err("produced signature did not recover to the sending account".to_string());
        }

        let signed = unsigned.clone().into_signed(alloy_signature);
        let mut raw = Vec::with_capacity(signed.eip2718_encoded_length());
        signed.eip2718_encode(&mut raw);

        Ok(format!("0x{}", hex_encode(&raw)))
    })?;

    Ok(raw_signed_hex)
}

/// Parse a gas price field: strict integer parsing via `U256` (rejecting
/// anything that doesn't parse cleanly, per the same rule as `value_wei`),
/// then a checked narrowing to `u128` — `TxEip1559`'s actual field type —
/// rather than a silent truncation. A value that overflows `u128` here
/// would otherwise wrap into a wildly wrong, much smaller fee, which is
/// exactly the kind of silent-wrong-number bug that must be a hard error
/// in anything that spends real funds.
fn parse_gas_price(value: &str, field_name: &str) -> Result<u128, String> {
    let as_u256: U256 = value
        .parse()
        .map_err(|_| format!("{field_name} is not a valid integer"))?;
    u128::try_from(&as_u256).map_err(|_| format!("{field_name} is too large"))
}

/// Lowercase hex encoding with no external dependency for this one call
/// site — `alloy::primitives::hex` would work equally well, but the
/// standard library has no built-in encoder, and pulling in a whole crate
/// for six lines is not proportionate.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Sign a Solana SOL transfer from account `from_index` of the currently
/// unlocked wallet, returning the fully-signed transaction as a base64
/// string, ready for the frontend to submit via the `sendTransaction` RPC
/// method. Mirrors [`sign_transaction`]'s split exactly: this command signs
/// and nothing else — broadcasting happens in the frontend
/// (`desktop/src/solana.ts`), since a signed transaction isn't secret and
/// duplicating RPC communication in Rust would just be two places that need
/// to agree on how to talk to an endpoint, for no benefit.
///
/// Proven against real mainnet before any UI called it: a temporary,
/// now-removed one-off checkpoint panel used this exact command to send a
/// real, entire-balance transfer between two of this wallet's own Solana
/// accounts, independently confirmed on-chain (signature, sender,
/// recipient, and amount all cross-checked via direct RPC, not just the
/// app's own success message) before the checkpoint panel was removed. That
/// verified real signing/broadcast still stands — it is not undone by the
/// restriction below, and was the correct way to prove this signer works.
///
/// This command itself is NOT temporary — it's the real signing primitive
/// the Solana send flow calls. `network` is still checked against
/// `SOLANA_SENDABLE_NETWORKS` (`require_sendable_solana_network`) before
/// any signature is produced — but as of the 2026-08-22 policy reversal
/// (see that constant's own doc comment), `mainnet-beta` now passes that
/// check too, same as every EVM mainnet now passes `SENDABLE_CHAIN_IDS`.
/// This function no longer refuses mainnet sends; the frontend's one-time
/// mainnet warning gate (`desktop/src/main.ts`) is what now carries the
/// "this hasn't been audited" disclosure that the hard block used to.
///
/// `to`/`lamports`/`recent_blockhash` are untrusted frontend input and
/// parsed strictly, the same discipline as every EVM signing command in
/// this file — a malformed address or blockhash is rejected outright, never
/// guessed at.
#[tauri::command]
fn sign_solana_transaction(
    to: String,
    lamports: u64,
    recent_blockhash: String,
    network: String,
    from_index: u32,
    unlocked: State<'_, UnlockedWallet>,
) -> Result<String, String> {
    sign_solana_transaction_impl(&unlocked, &to, lamports, &recent_blockhash, &network, from_index)
}

/// The testable core of [`sign_solana_transaction`].
fn sign_solana_transaction_impl(
    unlocked: &UnlockedWallet,
    to: &str,
    lamports: u64,
    recent_blockhash: &str,
    network: &str,
    from_index: u32,
) -> Result<String, String> {
    // Checked first, before parsing anything else — same ordering as
    // `sign_transaction_impl`'s own chain-id checks: this is the last line
    // of defense before a real signature is produced, so it does not trust
    // the caller's `network` string, however that value got here, and does
    // not do any other work first.
    require_sendable_solana_network(network)?;

    let to_pubkey: SolanaPubkey = to
        .parse()
        .map_err(|_| "recipient is not a well-formed Solana address".to_string())?;
    let blockhash: SolanaHash = recent_blockhash
        .parse()
        .map_err(|_| "recent blockhash is not well-formed".to_string())?;

    let guard = unlocked
        .0
        .lock()
        .map_err(|_| "wallet session state is unavailable")?;
    let session = guard.as_ref().ok_or("wallet is locked")?;

    let seed = session.mnemonic.to_seed("");
    let account = SolanaAccountKey::derive(&seed, from_index)
        .map_err(|_| "failed to derive the sending account".to_string())?;

    // The sender's own pubkey, derived the same way `get_solana_account_address`
    // derives the address it displays -- not re-parsed from that display
    // string, so there is no path where the two could ever disagree.
    let from_pubkey: SolanaPubkey = account
        .address()
        .parse()
        .map_err(|_| "internal error: derived Solana address failed to re-parse".to_string())?;

    let transfer_ix = solana_system_interface::instruction::transfer(&from_pubkey, &to_pubkey, lamports);
    let message = SolanaMessage::new_with_blockhash(&[transfer_ix], Some(&from_pubkey), &blockhash);

    // Only the raw signed bytes leave this closure — the signing key itself
    // never does. Same shape as `sign_unsigned_transaction`'s EVM
    // equivalent.
    let signed_base64 = account.expose_secret(|signing_key| -> Result<String, String> {
        let message_bytes = message.serialize();
        let signature: Ed25519Signature = signing_key.sign(&message_bytes);

        // Self-check before this ever leaves the process, same reasoning as
        // every EVM signing command's self-check: verify the signature
        // against the message and the account's own public key before
        // returning anything for broadcast.
        signing_key
            .verifying_key()
            .verify_strict(&message_bytes, &signature)
            .map_err(|_| "produced signature failed self-verification".to_string())?;

        let solana_signature = SolanaSignature::from(signature.to_bytes());
        let transaction = SolanaTransaction {
            signatures: vec![solana_signature],
            message,
        };

        let wire_bytes = bincode::serialize(&transaction)
            .map_err(|_| "failed to serialize the signed transaction".to_string())?;
        Ok(BASE64_STANDARD.encode(wire_bytes))
    })?;

    Ok(signed_base64)
}

/// DIAGNOSTIC ONLY — proves `cryptwallet-crypto` and `cryptwallet-vault` are
/// actually linked into the app and working, exercised across the Tauri IPC
/// boundary. MUST be removed before any real release; this is scaffolding
/// to verify crate wiring, not a real feature.
///
/// Gated behind `debug_assertions` so it is physically absent from release
/// builds — not just unregistered, but not compiled into the binary at all.
///
/// The mnemonic and seed generated here never leave this function and are
/// never stored or logged — only the derived (public) address is returned.
/// Both are dropped (and zeroized, per `crypto`'s own `ZeroizeOnDrop`
/// guarantees) at the end of this function's scope.
#[cfg(debug_assertions)]
#[tauri::command]
fn core_health_check() -> String {
    let crypto_summary = match SecretMnemonic::generate(WordCount::Twelve) {
        Ok(mnemonic) => {
            let seed = mnemonic.to_seed("");
            match EvmAccountKey::derive(&seed, 0) {
                Ok(account) => format!("crypto: ok (derived {})", account.address()),
                Err(_) => "crypto: FAILED".to_string(),
            }
        }
        Err(_) => "crypto: FAILED".to_string(),
    };

    const VAULT_TEST_PLAINTEXT: &[u8] = b"health check";
    const VAULT_TEST_PASSWORD: &str = "throwaway-diagnostic-password-not-a-real-secret";

    let vault_summary = match SealedVault::seal(
        VAULT_TEST_PLAINTEXT,
        VAULT_TEST_PASSWORD,
        KdfParams::DESKTOP_DEFAULT,
    ) {
        Ok(vault) => match vault.open(VAULT_TEST_PASSWORD) {
            Ok(decrypted) if decrypted.as_bytes() == VAULT_TEST_PLAINTEXT => "vault: ok",
            _ => "vault: FAILED",
        },
        Err(_) => "vault: FAILED",
    };

    format!("{crypto_summary} | {vault_summary}")
}

/// Etherscan V2 API base URL -- the same one `desktop/src/etherscan.ts`
/// called directly before this command existed; see that module's own doc
/// comment for the endpoint's own verification (one host for every chain,
/// selected via `chainid`).
const ETHERSCAN_API_BASE_URL: &str = "https://api.etherscan.io/v2/api";

/// Fetch a raw Etherscan V2 API list response (`txlist` or `tokentx`) for
/// `address` on `chain_id`, attaching this app's Etherscan API key
/// server-side. This is the fix for a real credential-leak finding: the key
/// used to live in the frontend as a Vite build-time env var, which meant
/// it was inlined in plaintext into the built JS bundle -- readable by
/// anyone who inspected a shipped app's webview resources. It now lives
/// only in this process's environment (`ETHERSCAN_API_KEY`, loaded from
/// `desktop/src-tauri/.env` by `dotenvy::dotenv()` in `run()`) and never
/// crosses into the webview/frontend in any form.
///
/// Returns the raw JSON response body as a string, deliberately UNPARSED:
/// envelope unwrapping (`status`/`message`/`result`), the "no history isn't
/// an error" special case, and per-entry field validation all stay in
/// `desktop/src/etherscan.ts` exactly as before this command existed -- this
/// is a thin network+key relay, not a second copy of that parsing logic
/// written twice in two languages.
///
/// `action` is checked against an exact allowlist before it's used to build
/// the request -- untrusted frontend input gets the same "don't trust it,
/// validate before use" treatment as every other command in this file, even
/// though the actual risk here is low (worst case with an unchecked action
/// is a malformed request Etherscan itself would reject).
///
/// No secret material of this wallet's own is involved -- address/chain_id
/// are public, and the API key is a third-party service credential, not
/// anything derived from the mnemonic -- so this doesn't need an unlocked
/// session.
#[tauri::command]
async fn fetch_etherscan_list(chain_id: u64, action: String, address: String) -> Result<String, String> {
    if action != "txlist" && action != "tokentx" {
        return Err("unsupported Etherscan action".to_string());
    }

    let api_key = std::env::var("ETHERSCAN_API_KEY").map_err(|_| {
        "No Etherscan API key is configured (set ETHERSCAN_API_KEY in desktop/src-tauri/.env).".to_string()
    })?;

    let mut url = reqwest::Url::parse(ETHERSCAN_API_BASE_URL)
        .map_err(|_| "internal error: malformed Etherscan base URL".to_string())?;
    url.query_pairs_mut()
        .append_pair("chainid", &chain_id.to_string())
        .append_pair("module", "account")
        .append_pair("action", &action)
        .append_pair("address", &address)
        .append_pair("startblock", "0")
        .append_pair("endblock", "99999999")
        .append_pair("page", "1")
        // Most recent 100 entries -- a read-only history view, not a full
        // ledger export; covers "what did I just do" for a wallet this
        // young without needing pagination UI yet.
        .append_pair("offset", "100")
        .append_pair("sort", "desc")
        .append_pair("apikey", &api_key);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Could not reach Etherscan: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("Etherscan returned HTTP {}", response.status()));
    }

    response
        .text()
        .await
        .map_err(|e| format!("failed to read Etherscan response: {e}"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Loads desktop/src-tauri/.env (gitignored) into this process's
    // environment if present -- the only thing it currently supplies is
    // ETHERSCAN_API_KEY (see `fetch_etherscan_list`). Deliberately
    // `ok()`-ignored: a missing `.env` is expected and fine (matches how a
    // missing VITE_ETHERSCAN_API_KEY was already handled before this
    // command existed) -- transaction history just won't be available,
    // nothing else in this app depends on it.
    dotenvy::dotenv().ok();

    let unlocked = UnlockedWallet::default();

    // Idle-timeout sweeper: clears the session once it has sat unused past
    // SESSION_IDLE_TIMEOUT. Holds its own Arc handle, so it keeps running
    // for the process lifetime independent of any command.
    let sweeper = unlocked.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(SESSION_SWEEP_INTERVAL);
        sweeper.clear_if_expired(Instant::now(), SESSION_IDLE_TIMEOUT);
    });

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(PendingMnemonic::default())
        .manage(unlocked)
        // Clear the session the moment the window loses focus (covers
        // minimize and switching away on every platform), is asked to close,
        // or is destroyed. Immediate lock on switch-away is the common case;
        // the idle timer above is the backstop for a window left focused.
        //
        // UX note for when a real post-unlock UI exists: `Focused(false)`
        // also fires on a routine alt-tab (e.g. to a password manager), so
        // this will feel aggressive then and should probably emit an event
        // that returns the frontend to the unlock screen. Today only the
        // (public) address is shown post-unlock, so there is nothing to hide
        // and the frontend is intentionally left untouched.
        .on_window_event(|window, event| {
            if matches!(
                event,
                WindowEvent::Focused(false)
                    | WindowEvent::CloseRequested { .. }
                    | WindowEvent::Destroyed
            ) {
                window.state::<UnlockedWallet>().clear();
            }
        });

    // The handler list is the only part that differs between debug and
    // release. It's branched here rather than hoisted into a shared `let`
    // because `generate_handler!`'s type isn't resolved until it's chained
    // onto `.invoke_handler()` (doing otherwise fails to compile, E0282).
    #[cfg(debug_assertions)]
    let builder = builder.invoke_handler(tauri::generate_handler![
        core_health_check,
        generate_new_mnemonic,
        confirm_and_seal_wallet,
        wallet_exists,
        unlock_wallet,
        lock_wallet,
        get_account_address,
        get_solana_account_address,
        get_solana_account_count,
        add_solana_account,
        get_bitcoin_account_address,
        fetch_etherscan_list,
        sign_transaction,
        sign_token_transfer,
        sign_solana_transaction,
        reveal_mnemonic,
        export_evm_private_key,
        export_solana_private_key
    ]);
    #[cfg(not(debug_assertions))]
    let builder = builder.invoke_handler(tauri::generate_handler![
        generate_new_mnemonic,
        confirm_and_seal_wallet,
        wallet_exists,
        unlock_wallet,
        lock_wallet,
        get_account_address,
        get_solana_account_address,
        get_solana_account_count,
        add_solana_account,
        get_bitcoin_account_address,
        fetch_etherscan_list,
        sign_transaction,
        sign_token_transfer,
        sign_solana_transaction,
        reveal_mnemonic,
        export_evm_private_key,
        export_solana_private_key
    ]);

    builder
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A password comfortably over `MIN_PASSWORD_LEN`, so these tests
    /// exercise the confirm logic rather than the length check.
    const TEST_PASSWORD: &str = "test-password-not-a-real-secret";

    /// `unlock_impl` with a no-op delay and a failures file beside the vault,
    /// so tests exercise the counter without ever sleeping for real.
    fn try_unlock(
        unlocked: &UnlockedWallet,
        password: &str,
        vault_path: &Path,
    ) -> Result<String, String> {
        let failures = vault_path.with_file_name(UNLOCK_FAILURES_FILENAME);
        unlock_impl(unlocked, password, vault_path, &failures, |_| {})
    }

    /// Seeds `PendingMnemonic` the same way `generate_new_mnemonic` does,
    /// returning the state, the phrase words, and the slot order that a
    /// user clicking correctly would produce.
    fn pending_with_mnemonic() -> (PendingMnemonic, Vec<String>, Vec<usize>) {
        let mnemonic = SecretMnemonic::generate(WordCount::Twelve).expect("generation succeeds");
        let words: Vec<String> =
            mnemonic.expose_secret(|phrase| phrase.split_whitespace().map(str::to_string).collect());
        let bank = shuffled_indices(words.len());

        // Clicking correctly means picking, for each phrase position in
        // turn, whichever slot happens to hold that word.
        let correct_slots: Vec<usize> = (0..words.len())
            .map(|position| {
                bank.iter()
                    .position(|&word_index| word_index == position)
                    .expect("every phrase position appears in the bank exactly once")
            })
            .collect();

        (
            PendingMnemonic(Mutex::new(Some(PendingCreation {
                mnemonic,
                bank,
            }))),
            words,
            correct_slots,
        )
    }

    /// An `UnlockedWallet` with a freshly-generated (real `OsRng`, not a
    /// fixed test seed — `SecretMnemonic::from_entropy_for_testing` is
    /// `pub(crate)` to the crypto crate and not reachable from here)
    /// mnemonic already in session. The signing tests below don't need a
    /// *reproducible* seed, only internal self-consistency: derive
    /// account 0's address here, sign with the same session, and confirm
    /// the signature recovers to that same address.
    fn unlocked_with_fresh_mnemonic() -> UnlockedWallet {
        let mnemonic = SecretMnemonic::generate(WordCount::Twelve).expect("generation succeeds");
        let unlocked = UnlockedWallet::default();
        *unlocked.0.lock().expect("lock") = Some(UnlockedSession {
            mnemonic,
            unlocked_at: Instant::now(),
        });
        unlocked
    }

    #[test]
    fn signature_recovers_to_the_signing_account() {
        let unlocked = unlocked_with_fresh_mnemonic();

        // The expected signer, derived independently from the same session
        // for comparison — not read back out of the signing path itself.
        let expected_address = {
            let guard = unlocked.0.lock().expect("lock");
            let seed = guard.as_ref().expect("session present").mnemonic.to_seed("");
            EvmAccountKey::derive(&seed, 0)
                .expect("derive account 0")
                .address()
                .to_checksummed_hex()
        };
        // Recipient: account 1 of the same wallet, so its address is
        // guaranteed well-formed and correctly checksummed by our own
        // (EIP-55-vector-tested) implementation, rather than a hand-typed
        // literal whose checksum casing this test would be trusting blind.
        let recipient = get_account_address_impl(1, &unlocked).expect("derive account 1");

        let raw_hex = sign_transaction_impl(
            &unlocked,
            &recipient,
            "1000000000000000", // 0.001 ETH, in wei
            0,
            "20000000000", // 20 gwei
            "1000000000",  // 1 gwei
            21000,
            SEPOLIA_CHAIN_ID,
            0, // from account 0, matching `expected_address` above
        )
        .expect("signing should succeed");

        assert!(raw_hex.starts_with("0x"));
        // EIP-2718 type byte 0x02 (EIP-1559) must be the first byte after
        // the 0x prefix -- confirms this is actually a typed transaction,
        // not a bare RLP list a naive `eth_sendRawTransaction` call would
        // silently misinterpret.
        assert!(raw_hex.starts_with("0x02"), "expected an EIP-1559 (type 2) envelope, got: {raw_hex}");

        // Independent verification: decode the raw bytes and recover the
        // signer via the exact path a real Ethereum node uses to validate
        // an incoming transaction. This does NOT reuse
        // sign_transaction_impl's own internal self-check -- it re-derives
        // everything from the returned bytes alone, so it would catch a
        // bug even if that internal check were ever removed or broken.
        let raw_bytes: Vec<u8> =
            alloy::primitives::hex::decode(&raw_hex[2..]).expect("valid hex");
        let signed = alloy::consensus::Signed::<TxEip1559>::eip2718_decode(&mut raw_bytes.as_slice())
            .expect("decode the signed envelope");

        // Recovery must be against the *signing* hash (what ECDSA actually
        // signed: keccak256(0x02 || rlp(unsigned fields))) -- NOT
        // `signed.hash()`, which is the final tx hash computed *from* the
        // completed signature and would not recover correctly.
        let signing_hash = signed.tx().signature_hash();
        let recovered = signed
            .signature()
            .recover_address_from_prehash(&signing_hash)
            .expect("signature recovers");

        let expected = AlloyAddress::parse_checksummed(&expected_address, None)
            .expect("our own checksummed output must itself be valid");
        assert_eq!(
            recovered, expected,
            "signature must recover to the account that produced it"
        );
    }

    /// A syntactically valid (well-formed base58, correct length) but
    /// otherwise arbitrary hash, standing in for a recent blockhash in
    /// tests that only exercise signing, never broadcast -- these tests
    /// have no RPC connection and no reason to need a real, currently-valid
    /// blockhash.
    const FAKE_BLOCKHASH: &str = "11111111111111111111111111111111";

    #[test]
    fn solana_signature_recovers_to_the_signing_account() {
        let unlocked = unlocked_with_fresh_mnemonic();

        // Expected signer, derived independently for comparison -- not read
        // back out of the signing path itself. Same discipline as the EVM
        // version of this test above.
        let expected_address = {
            let guard = unlocked.0.lock().expect("lock");
            let seed = guard.as_ref().expect("session present").mnemonic.to_seed("");
            SolanaAccountKey::derive(&seed, 0)
                .expect("derive account 0")
                .address()
        };
        let recipient = get_solana_account_address_impl(1, &unlocked).expect("derive account 1");

        // "devnet": arbitrary now that every network is sendable (see
        // `sign_solana_transaction_succeeds_for_mainnet_beta` below for the
        // mainnet-beta case specifically) -- this test is about the signing
        // math itself, not which network was passed.
        let signed_base64 =
            sign_solana_transaction_impl(&unlocked, &recipient, 1_000_000, FAKE_BLOCKHASH, "devnet", 0)
                .expect("signing should succeed");

        // Independent verification: decode the returned bytes and verify
        // the signature against the signer's own public key via a fresh
        // ed25519 check -- does NOT reuse sign_solana_transaction_impl's own
        // internal self-check, so it would catch a bug even if that check
        // were ever removed or broken.
        let wire_bytes = BASE64_STANDARD.decode(&signed_base64).expect("valid base64");
        let transaction: SolanaTransaction =
            bincode::deserialize(&wire_bytes).expect("valid transaction wire format");

        assert_eq!(transaction.signatures.len(), 1);
        assert_eq!(
            transaction.message.account_keys[0].to_string(),
            expected_address,
            "fee payer / signer must be account 0"
        );

        let signer_pubkey: SolanaPubkey = expected_address.parse().expect("our own address must re-parse");
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&signer_pubkey.to_bytes())
            .expect("our own derived pubkey must be a valid ed25519 point");

        let message_bytes = transaction.message.serialize();
        let signature = Ed25519Signature::from_bytes(transaction.signatures[0].as_array());
        verifying_key
            .verify_strict(&message_bytes, &signature)
            .expect("signature must verify against the signer's own public key");
    }

    #[test]
    fn sign_solana_transaction_requires_an_unlocked_session() {
        let unlocked = UnlockedWallet::default();
        let error = sign_solana_transaction_impl(
            &unlocked,
            "11111111111111111111111111111111",
            1_000_000,
            FAKE_BLOCKHASH,
            "devnet",
            0,
        )
        .expect_err("locked wallet must refuse");
        assert_eq!(error, "wallet is locked");
    }

    #[test]
    fn sign_solana_transaction_rejects_a_malformed_recipient() {
        let unlocked = unlocked_with_fresh_mnemonic();
        let result =
            sign_solana_transaction_impl(&unlocked, "not-a-solana-address", 1_000_000, FAKE_BLOCKHASH, "devnet", 0);
        assert!(result.is_err(), "malformed recipient must be rejected");
    }

    #[test]
    fn sign_solana_transaction_rejects_a_malformed_blockhash() {
        let unlocked = unlocked_with_fresh_mnemonic();
        let recipient = get_solana_account_address_impl(1, &unlocked).expect("derive account 1");
        let result = sign_solana_transaction_impl(&unlocked, &recipient, 1_000_000, "not-a-hash", "devnet", 0);
        assert!(result.is_err(), "malformed blockhash must be rejected");
    }

    #[test]
    fn require_sendable_solana_network_allows_mainnet_beta_devnet_and_testnet() {
        // Post-2026-08-22 policy reversal (see `SOLANA_SENDABLE_NETWORKS`'s
        // own doc comment): every network this app knows about for Solana,
        // mainnet-beta included, is sendable now.
        assert!(require_sendable_solana_network("mainnet-beta").is_ok());
        assert!(require_sendable_solana_network("devnet").is_ok());
        assert!(require_sendable_solana_network("testnet").is_ok());
        // A network Solana itself doesn't recognize is still refused --
        // this remains a real allowlist, not a check that always passes.
        let error = require_sendable_solana_network("not-a-real-cluster")
            .expect_err("an unrecognized cluster name must be refused");
        assert_eq!(error, "Sending is not yet supported on this network");
    }

    #[test]
    fn sign_solana_transaction_succeeds_for_mainnet_beta() {
        // The actual policy-reversal enforcement: a fully unlocked wallet
        // with a well-formed recipient/blockhash now DOES produce a
        // mainnet-beta signature -- the explicit, deliberate opposite of
        // this test's pre-reversal name/assertion
        // (`sign_solana_transaction_refuses_to_sign_for_mainnet_beta`).
        let unlocked = unlocked_with_fresh_mnemonic();
        let recipient = get_solana_account_address_impl(1, &unlocked).expect("derive account 1");
        let signed_base64 = sign_solana_transaction_impl(
            &unlocked,
            &recipient,
            1_000_000,
            FAKE_BLOCKHASH,
            "mainnet-beta",
            0,
        )
        .expect("mainnet-beta signing must now succeed");
        assert!(!signed_base64.is_empty());
    }

    #[test]
    fn require_supported_chain_id_allows_all_twelve_known_chains_and_rejects_others() {
        for id in SUPPORTED_CHAIN_IDS {
            assert!(
                require_supported_chain_id(id).is_ok(),
                "expected chain id {id} to be recognized"
            );
        }
        assert_eq!(SUPPORTED_CHAIN_IDS.len(), 12, "this test should cover every entry");

        // A representative sample of real, well-known chain IDs that are
        // simply not in this app's allowlist -- being a real EVM chain
        // elsewhere doesn't make it supported here.
        assert!(require_supported_chain_id(43114).is_err()); // Avalanche C-Chain
        assert!(require_supported_chain_id(250).is_err()); // Fantom Opera
        assert!(require_supported_chain_id(324).is_err()); // zkSync Era
        assert!(require_supported_chain_id(0).is_err());
        assert!(require_supported_chain_id(u64::MAX).is_err());
    }

    #[test]
    fn require_sendable_chain_id_allows_every_supported_chain_including_every_mainnet() {
        // Post-2026-08-22 policy reversal (see `SENDABLE_CHAIN_IDS`'s own
        // doc comment): `SENDABLE_CHAIN_IDS` now equals `SUPPORTED_CHAIN_IDS`
        // exactly -- every chain this app can read, it can now also sign for,
        // mainnets included. This test's pre-reversal name/assertion
        // (`..._allows_every_testnet_and_rejects_every_mainnet`) is the
        // direct opposite of current policy.
        for id in SUPPORTED_CHAIN_IDS {
            assert!(
                require_sendable_chain_id(id).is_ok(),
                "expected chain id {id} to be sendable"
            );
        }
        assert_eq!(SENDABLE_CHAIN_IDS.len(), 12, "this test should cover every entry");

        // A chain id this app doesn't recognize at all is still refused --
        // this remains a real allowlist, not a check that always passes.
        let error = require_sendable_chain_id(43114) // Avalanche C-Chain
            .expect_err("an unsupported chain id must be refused");
        assert_eq!(error, "Sending is not yet supported on this network");
    }

    #[test]
    fn unrecognized_chain_id_is_rejected_before_any_signing() {
        // Deliberately locked (no session at all) so that if the chain-id
        // check were NOT first, this would fail with "wallet is locked"
        // instead -- getting the chain-id-specific message proves that
        // gate runs before any attempt to touch signing state.
        let unlocked = UnlockedWallet::default();

        let result = sign_transaction_impl(
            &unlocked,
            "0x0000000000000000000000000000000000dEaD",
            "0",
            0,
            "0",
            "0",
            21000,
            43114, // Avalanche C-Chain -- not in SUPPORTED_CHAIN_IDS at all, must be refused
            0,
        );

        let error = result.expect_err("an unrecognized chain id must be rejected");
        assert!(
            error.contains("unsupported chain ID"),
            "expected an unsupported-chain-id error, got: {error}"
        );
        assert!(
            !error.to_lowercase().contains("locked"),
            "got a 'wallet locked' error instead of a chain-id error -- the \
             chain-id check ran after touching session state, not before: {error}"
        );
    }

    #[test]
    fn mainnet_is_a_recognized_and_now_sendable_chain_id() {
        // Post-2026-08-22 policy reversal (see `SENDABLE_CHAIN_IDS`'s own
        // doc comment), mainnet is recognized AND sendable -- this test's
        // pre-reversal name/assertion (`..._but_sending_is_refused`) is the
        // direct opposite of current policy.
        assert!(require_supported_chain_id(MAINNET_CHAIN_ID).is_ok());
        assert!(require_sendable_chain_id(MAINNET_CHAIN_ID).is_ok());
    }

    #[test]
    fn malformed_recipient_address_is_rejected() {
        let unlocked = unlocked_with_fresh_mnemonic();

        let malformed = [
            "not an address",
            "0x123",
            "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        ];
        for bad in malformed {
            let result = sign_transaction_impl(
                &unlocked,
                bad,
                "0",
                0,
                "0",
                "0",
                21000,
                SEPOLIA_CHAIN_ID,
                0,
            );
            assert!(result.is_err(), "expected {bad:?} to be rejected");
        }

        // The subtler case: syntactically a valid 40-hex-char address, but
        // not checksummed (all-lowercase). This is exactly what
        // "well-formed, checksummed" (not just well-formed) rules out --
        // parse_checksummed must refuse it rather than silently accept the
        // unchecksummed casing.
        let unchecksummed = "0x0000000000000000000000000000000000dead";
        let result = sign_transaction_impl(
            &unlocked,
            unchecksummed,
            "0",
            0,
            "0",
            "0",
            21000,
            SEPOLIA_CHAIN_ID,
            0,
        );
        assert!(
            result.is_err(),
            "an unchecksummed (all-lowercase) address must be rejected, not silently accepted"
        );
    }

    #[test]
    fn erc20_transfer_encoding_matches_the_standard_selector_and_layout() {
        let recipient = AlloyAddress::from([0x11u8; 20]);
        let amount = U256::from(1_234_567u64);

        let calldata = encode_erc20_transfer(recipient, amount).expect("encoding succeeds");

        // Built independently of encode_erc20_transfer's own internals --
        // this does not just call the same function again and compare, it
        // hand-assembles the expected ABI layout byte by byte, so it would
        // catch a bug in the real implementation rather than agreeing with
        // it by construction.
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // transfer(address,uint256) selector
        let mut address_word = [0u8; 32]; // left-padded: 12 zero bytes + the 20 address bytes
        address_word[12..].copy_from_slice(recipient.as_slice());
        expected.extend_from_slice(&address_word);
        expected.extend_from_slice(&amount.to_be_bytes::<32>()); // uint256, big-endian, 32 bytes

        assert_eq!(calldata.len(), 4 + 32 + 32, "selector + two 32-byte ABI words");
        assert_eq!(calldata, expected);
        assert_eq!(
            &calldata[..4],
            &[0xa9, 0x05, 0x9c, 0xbb],
            "must start with the real transfer(address,uint256) selector 0xa9059cbb"
        );
    }

    #[test]
    fn token_transfer_signature_recovers_to_the_signing_account() {
        let unlocked = unlocked_with_fresh_mnemonic();

        let expected_address = {
            let guard = unlocked.0.lock().expect("lock");
            let seed = guard.as_ref().expect("session present").mnemonic.to_seed("");
            EvmAccountKey::derive(&seed, 0)
                .expect("derive account 0")
                .address()
                .to_checksummed_hex()
        };
        let recipient = get_account_address_impl(1, &unlocked).expect("derive account 1");
        // A syntactically valid, checksummed address standing in for a
        // token contract -- this test only exercises signing, not contract
        // interaction, so it doesn't need to be the real USDC address.
        let token_address = get_account_address_impl(2, &unlocked).expect("derive account 2");

        let raw_hex = sign_token_transfer_impl(
            &unlocked,
            &token_address,
            &recipient,
            "1000000", // 1.0 USDC at 6 decimals, in raw units
            0,
            "20000000000",
            "1000000000",
            65_000, // a token transfer costs meaningfully more than a plain 21000 ETH send
            SEPOLIA_CHAIN_ID,
            0,
        )
        .expect("signing should succeed");

        assert!(raw_hex.starts_with("0x02"), "expected an EIP-1559 (type 2) envelope, got: {raw_hex}");

        // Independent verification, same discipline as
        // signature_recovers_to_the_signing_account: decode the raw bytes
        // and recover the signer via the exact path a real node would, not
        // by reusing sign_token_transfer_impl's own internal self-check.
        let raw_bytes: Vec<u8> = alloy::primitives::hex::decode(&raw_hex[2..]).expect("valid hex");
        let signed = alloy::consensus::Signed::<TxEip1559>::eip2718_decode(&mut raw_bytes.as_slice())
            .expect("decode the signed envelope");

        let signing_hash = signed.tx().signature_hash();
        let recovered = signed
            .signature()
            .recover_address_from_prehash(&signing_hash)
            .expect("signature recovers");
        let expected = AlloyAddress::parse_checksummed(&expected_address, None)
            .expect("our own checksummed output must itself be valid");
        assert_eq!(
            recovered, expected,
            "signature must recover to the account that produced it"
        );

        // And the transaction actually IS a token-contract call, not an ETH
        // send that happened to reuse this test's addresses: `to` is the
        // token contract, `value` is zero, and `input` decodes back to
        // exactly the recipient and amount this test asked for.
        let expected_token_contract = AlloyAddress::parse_checksummed(&token_address, None)
            .expect("token address is valid");
        assert_eq!(signed.tx().to, TxKind::Call(expected_token_contract));
        assert_eq!(signed.tx().value, U256::ZERO);

        let decoded = IERC20::transferCall::abi_decode(signed.tx().input.as_ref(), true)
            .expect("input decodes as a transfer() call");
        let expected_recipient =
            AlloyAddress::parse_checksummed(&recipient, None).expect("recipient is valid");
        assert_eq!(decoded.to, expected_recipient);
        assert_eq!(decoded.amount, U256::from(1_000_000u64));
    }

    #[test]
    fn token_transfer_unrecognized_chain_id_is_rejected_before_any_signing() {
        // Deliberately locked, same reasoning as
        // unrecognized_chain_id_is_rejected_before_any_signing: proves the
        // chain-id check runs before anything touches session state.
        let unlocked = UnlockedWallet::default();

        let result = sign_token_transfer_impl(
            &unlocked,
            "0x0000000000000000000000000000000000dEaD",
            "0x0000000000000000000000000000000000dEaD",
            "0",
            0,
            "0",
            "0",
            65_000,
            43114, // Avalanche C-Chain -- not in SUPPORTED_CHAIN_IDS at all, must be refused
            0,
        );

        let error = result.expect_err("an unrecognized chain id must be rejected");
        assert!(error.contains("unsupported chain ID"), "expected an unsupported-chain-id error, got: {error}");
        assert!(
            !error.to_lowercase().contains("locked"),
            "chain-id check must run before touching session state: {error}"
        );
    }

    #[test]
    fn token_transfer_mainnet_is_recognized_and_now_sendable() {
        // Same reasoning as mainnet_is_a_recognized_and_now_sendable_chain_id
        // -- token-transfer signing consults the exact same two allowlist
        // functions, so there is nothing token-specific to re-derive here.
        assert!(require_supported_chain_id(MAINNET_CHAIN_ID).is_ok());
        assert!(require_sendable_chain_id(MAINNET_CHAIN_ID).is_ok());
    }

    #[test]
    fn token_transfer_requires_an_unlocked_session() {
        let unlocked = UnlockedWallet::default();

        // A real, correctly-checksummed address, independent of the (locked)
        // `unlocked` session under test -- needed so this test actually
        // reaches the session-lock check rather than failing address
        // parsing first. A hand-typed literal risks exactly that: EIP-55
        // checksum casing isn't something to eyeball.
        let seed = SecretMnemonic::generate(WordCount::Twelve)
            .expect("generation succeeds")
            .to_seed("");
        let address = EvmAccountKey::derive(&seed, 0)
            .expect("derive account 0")
            .address()
            .to_checksummed_hex();

        let result = sign_token_transfer_impl(
            &unlocked,
            &address,
            &address,
            "0",
            0,
            "0",
            "0",
            65_000,
            SEPOLIA_CHAIN_ID,
            0,
        );

        assert_eq!(result, Err("wallet is locked".to_string()));
    }

    #[test]
    fn token_transfer_malformed_token_or_recipient_address_is_rejected() {
        let unlocked = unlocked_with_fresh_mnemonic();
        let valid = get_account_address_impl(1, &unlocked).expect("derive account 1");

        // Malformed TOKEN address, valid recipient.
        let result = sign_token_transfer_impl(
            &unlocked, "not an address", &valid, "0", 0, "0", "0", 65_000, SEPOLIA_CHAIN_ID, 0,
        );
        assert!(result.is_err(), "a malformed token contract address must be rejected");

        // Valid token address, malformed recipient.
        let result = sign_token_transfer_impl(
            &unlocked, &valid, "not an address", "0", 0, "0", "0", 65_000, SEPOLIA_CHAIN_ID, 0,
        );
        assert!(result.is_err(), "a malformed recipient address must be rejected");

        // Same subtler case as sign_transaction's own test: syntactically
        // valid but unchecksummed (all-lowercase) must also be refused, for
        // both roles.
        let unchecksummed = "0x0000000000000000000000000000000000dead";
        let result = sign_token_transfer_impl(
            &unlocked, unchecksummed, &valid, "0", 0, "0", "0", 65_000, SEPOLIA_CHAIN_ID, 0,
        );
        assert!(result.is_err(), "an unchecksummed token address must be rejected");
        let result = sign_token_transfer_impl(
            &unlocked, &valid, unchecksummed, "0", 0, "0", "0", 65_000, SEPOLIA_CHAIN_ID, 0,
        );
        assert!(result.is_err(), "an unchecksummed recipient address must be rejected");
    }

    #[test]
    fn get_account_address_matches_direct_derivation_and_varies_by_index() {
        let unlocked = unlocked_with_fresh_mnemonic();

        let expected_0 = {
            let guard = unlocked.0.lock().expect("lock");
            let seed = guard.as_ref().expect("session present").mnemonic.to_seed("");
            EvmAccountKey::derive(&seed, 0)
                .expect("derive account 0")
                .address()
                .to_checksummed_hex()
        };

        let account_0 = get_account_address_impl(0, &unlocked).expect("derive account 0");
        let account_1 = get_account_address_impl(1, &unlocked).expect("derive account 1");

        assert_eq!(account_0, expected_0, "must match direct derivation, not just be well-formed");
        assert_ne!(account_0, account_1, "different indices must derive different addresses");
    }

    #[test]
    fn get_account_address_requires_an_unlocked_session() {
        let unlocked = UnlockedWallet::default();
        let error = get_account_address_impl(0, &unlocked).expect_err("locked wallet must refuse");
        assert_eq!(error, "wallet is locked");
    }

    #[test]
    fn get_account_address_rejects_the_hardened_range() {
        let unlocked = unlocked_with_fresh_mnemonic();
        // Relies on the same bounds check `EvmAccountKey::derive` already
        // enforces (see crypto/src/derivation.rs) rather than a second copy
        // of the `>= 2^31` comparison here.
        let result = get_account_address_impl(0x8000_0000, &unlocked);
        assert!(result.is_err(), "hardened-range index must be rejected");
    }

    #[test]
    fn get_solana_account_address_matches_direct_derivation_and_varies_by_index() {
        let unlocked = unlocked_with_fresh_mnemonic();

        let expected_0 = {
            let guard = unlocked.0.lock().expect("lock");
            let seed = guard.as_ref().expect("session present").mnemonic.to_seed("");
            SolanaAccountKey::derive(&seed, 0).expect("derive account 0").address()
        };

        let account_0 = get_solana_account_address_impl(0, &unlocked).expect("derive account 0");
        let account_1 = get_solana_account_address_impl(1, &unlocked).expect("derive account 1");

        assert_eq!(account_0, expected_0, "must match direct derivation, not just be well-formed");
        assert_ne!(account_0, account_1, "different indices must derive different addresses");
    }

    #[test]
    fn get_solana_account_address_requires_an_unlocked_session() {
        let unlocked = UnlockedWallet::default();
        let error = get_solana_account_address_impl(0, &unlocked).expect_err("locked wallet must refuse");
        assert_eq!(error, "wallet is locked");
    }

    #[test]
    fn get_solana_account_address_rejects_the_hardened_range() {
        let unlocked = unlocked_with_fresh_mnemonic();
        // Relies on the same bounds check `SolanaAccountKey::derive` already
        // enforces (see crypto/src/solana.rs) rather than a second copy of
        // the `>= 2^31` comparison here.
        let result = get_solana_account_address_impl(0x8000_0000, &unlocked);
        assert!(result.is_err(), "hardened-range index must be rejected");
    }

    #[test]
    fn get_bitcoin_account_address_matches_direct_derivation_and_varies_by_index() {
        let unlocked = unlocked_with_fresh_mnemonic();

        let expected_0 = {
            let guard = unlocked.0.lock().expect("lock");
            let seed = guard.as_ref().expect("session present").mnemonic.to_seed("");
            BitcoinAccountKey::derive(&seed, 0).expect("derive account 0").address()
        };

        let account_0 = get_bitcoin_account_address_impl(0, &unlocked).expect("derive account 0");
        let account_1 = get_bitcoin_account_address_impl(1, &unlocked).expect("derive account 1");

        assert_eq!(account_0, expected_0, "must match direct derivation, not just be well-formed");
        assert_ne!(account_0, account_1, "different indices must derive different addresses");
    }

    #[test]
    fn get_bitcoin_account_address_requires_an_unlocked_session() {
        let unlocked = UnlockedWallet::default();
        let error = get_bitcoin_account_address_impl(0, &unlocked).expect_err("locked wallet must refuse");
        assert_eq!(error, "wallet is locked");
    }

    #[test]
    fn get_bitcoin_account_address_rejects_the_hardened_range() {
        let unlocked = unlocked_with_fresh_mnemonic();
        // Relies on the same bounds check `BitcoinAccountKey::derive` already
        // enforces (see crypto/src/bitcoin.rs) rather than a second copy of
        // the `>= 2^31` comparison here.
        let result = get_bitcoin_account_address_impl(0x8000_0000, &unlocked);
        assert!(result.is_err(), "hardened-range index must be rejected");
    }

    #[tokio::test]
    async fn fetch_etherscan_list_rejects_an_unrecognized_action() {
        // Checked before any network call is attempted, same "don't trust
        // untrusted frontend input, validate before use" discipline as
        // every other command in this file -- this test only needs to
        // prove the check fires, not touch the real Etherscan API.
        let result = fetch_etherscan_list(1, "not-a-real-action".to_string(), "0x0".to_string()).await;
        let error = result.expect_err("an unrecognized action must be rejected");
        assert_eq!(error, "unsupported Etherscan action");
    }

    #[test]
    fn correct_word_order_seals_a_vault() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();

        let address = confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path)
            .expect("correct order should seal");

        assert!(address.starts_with("0x"), "expected a checksummed address");
        assert_eq!(address.len(), 42);
        assert!(path.exists(), "vault file should have been written");

        // The pending mnemonic must not survive a successful seal.
        assert!(
            pending.0.lock().expect("lock").is_none(),
            "pending mnemonic should be cleared after sealing"
        );
    }

    #[test]
    fn sealed_vault_reopens_and_rederives_the_same_address() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, words, correct_slots) = pending_with_mnemonic();

        let created_address =
            confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path).expect("seal succeeds");

        // The unlock path, exercised end to end: read the vault, decrypt it,
        // re-import the phrase, re-derive the seed and account. This is the
        // property that sealing the *mnemonic* rather than the seed exists
        // to guarantee — if it ever breaks, a user who lost their paper
        // backup is holding an unrecoverable wallet.
        let bytes = fs::read(&path).expect("read vault back");
        let vault = SealedVault::from_bytes(&bytes).expect("parse sealed vault");
        let decrypted = vault.open(TEST_PASSWORD).expect("open with correct password");

        let phrase = std::str::from_utf8(decrypted.as_bytes()).expect("phrase is valid utf-8");
        let restored = SecretMnemonic::import(phrase).expect("sealed phrase must re-import");
        let restored_address = EvmAccountKey::derive(&restored.to_seed(""), 0)
            .expect("derive from restored phrase")
            .address()
            .to_checksummed_hex();

        assert_eq!(
            created_address, restored_address,
            "a restored wallet must derive the same address it was created with"
        );
        // And what was sealed really is the phrase the user wrote down.
        assert_eq!(phrase.split_whitespace().collect::<Vec<_>>(), words);
    }

    /// Seal a fresh vault, unlock it (so both an on-disk vault and an
    /// unlocked in-memory session exist -- the real sequence reveal/export
    /// always follows), and return everything a reveal/export test needs:
    /// the wallet's own state, the vault path, the failures-counter path
    /// beside it, and the exact phrase words that were sealed (for
    /// asserting a reveal returns them verbatim).
    fn sealed_and_unlocked_wallet() -> (UnlockedWallet, PathBuf, PathBuf, Vec<String>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let failures = path.with_file_name(UNLOCK_FAILURES_FILENAME);
        let (pending, words, correct_slots) = pending_with_mnemonic();
        confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path).expect("seal succeeds");

        let unlocked = UnlockedWallet::default();
        try_unlock(&unlocked, TEST_PASSWORD, &path).expect("unlock with the just-set password");

        (unlocked, path, failures, words, dir)
    }

    #[test]
    fn reveal_mnemonic_returns_the_exact_sealed_phrase() {
        let (unlocked, path, failures, words, _dir) = sealed_and_unlocked_wallet();

        let revealed = reveal_mnemonic_impl(&unlocked, TEST_PASSWORD, &path, &failures, |_| {})
            .expect("reveal should succeed with the correct password");

        assert_eq!(revealed.split_whitespace().collect::<Vec<_>>(), words);
    }

    #[test]
    fn reveal_mnemonic_requires_an_unlocked_session() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let failures = path.with_file_name(UNLOCK_FAILURES_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();
        confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path).expect("seal succeeds");

        // Deliberately never unlocked -- reveal must refuse even though the
        // vault on disk is real and the password below is correct for it.
        let unlocked = UnlockedWallet::default();
        let error = reveal_mnemonic_impl(&unlocked, TEST_PASSWORD, &path, &failures, |_| {})
            .expect_err("a locked session must refuse to reveal, regardless of password correctness");
        assert_eq!(error, "wallet is locked");
    }

    #[test]
    fn reveal_mnemonic_rejects_the_wrong_password_even_with_a_session_unlocked() {
        let (unlocked, path, failures, _words, _dir) = sealed_and_unlocked_wallet();

        // An unlocked session is not sufficient on its own -- this is the
        // property the whole re-authentication requirement exists for.
        let error = reveal_mnemonic_impl(&unlocked, "the-wrong-passphrase", &path, &failures, |_| {})
            .expect_err("wrong password must be rejected even with an active session");
        assert_eq!(error, "could not unlock the wallet: check your passphrase");
    }

    #[test]
    fn reveal_mnemonic_wrong_password_increments_the_same_failure_counter_as_unlock() {
        let (unlocked, path, failures, _words, _dir) = sealed_and_unlocked_wallet();
        // `sealed_and_unlocked_wallet` already unlocked successfully once,
        // which resets the counter -- start from a known zero.
        assert_eq!(read_unlock_failures(&failures), 0);

        let _ = reveal_mnemonic_impl(&unlocked, "wrong", &path, &failures, |_| {});
        assert_eq!(
            read_unlock_failures(&failures),
            1,
            "a failed reveal must count against the same throttle a failed unlock does -- \
             it is just as much a passphrase-guessing surface"
        );
    }

    #[test]
    fn export_evm_private_key_matches_direct_derivation_and_varies_by_index() {
        let (unlocked, path, failures, _words, _dir) = sealed_and_unlocked_wallet();

        let expected_0 = {
            let guard = unlocked.0.lock().expect("lock");
            let seed = guard.as_ref().expect("session present").mnemonic.to_seed("");
            EvmAccountKey::derive(&seed, 0)
                .expect("derive account 0")
                .expose_secret(|k| format!("0x{}", hex_encode(&k.to_bytes())))
        };

        let exported_0 = export_evm_private_key_impl(&unlocked, TEST_PASSWORD, 0, &path, &failures, |_| {})
            .expect("export should succeed");
        let exported_1 = export_evm_private_key_impl(&unlocked, TEST_PASSWORD, 1, &path, &failures, |_| {})
            .expect("export should succeed");

        assert_eq!(exported_0, expected_0, "must match direct derivation, not just be well-formed");
        assert!(exported_0.starts_with("0x"));
        assert_eq!(exported_0.len(), 66, "0x + 64 hex chars (32 bytes)");
        assert_ne!(exported_0, exported_1, "different indices must derive different keys");
    }

    #[test]
    fn export_evm_private_key_requires_an_unlocked_session() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let failures = path.with_file_name(UNLOCK_FAILURES_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();
        confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path).expect("seal succeeds");

        let unlocked = UnlockedWallet::default();
        let error = export_evm_private_key_impl(&unlocked, TEST_PASSWORD, 0, &path, &failures, |_| {})
            .expect_err("a locked session must refuse to export");
        assert_eq!(error, "wallet is locked");
    }

    #[test]
    fn export_solana_private_key_matches_direct_derivation_and_varies_by_index() {
        let (unlocked, path, failures, _words, _dir) = sealed_and_unlocked_wallet();

        let expected_0 = {
            let guard = unlocked.0.lock().expect("lock");
            let seed = guard.as_ref().expect("session present").mnemonic.to_seed("");
            SolanaAccountKey::derive(&seed, 0)
                .expect("derive account 0")
                .expose_secret(|k| bs58::encode(k.to_keypair_bytes()).into_string())
        };

        let exported_0 = export_solana_private_key_impl(&unlocked, TEST_PASSWORD, 0, &path, &failures, |_| {})
            .expect("export should succeed");
        let exported_1 = export_solana_private_key_impl(&unlocked, TEST_PASSWORD, 1, &path, &failures, |_| {})
            .expect("export should succeed");

        assert_eq!(exported_0, expected_0, "must match direct derivation, not just be well-formed");
        assert_ne!(exported_0, exported_1, "different indices must derive different keys");
        // A different key space entirely from the EVM export above, not
        // merely a different value -- proves this isn't accidentally
        // exporting the same underlying key material through two encoders.
        let evm_0 = export_evm_private_key_impl(&unlocked, TEST_PASSWORD, 0, &path, &failures, |_| {})
            .expect("export should succeed");
        assert_ne!(exported_0, evm_0);
    }

    #[test]
    fn export_solana_private_key_requires_an_unlocked_session() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let failures = path.with_file_name(UNLOCK_FAILURES_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();
        confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path).expect("seal succeeds");

        let unlocked = UnlockedWallet::default();
        let error = export_solana_private_key_impl(&unlocked, TEST_PASSWORD, 0, &path, &failures, |_| {})
            .expect_err("a locked session must refuse to export");
        assert_eq!(error, "wallet is locked");
    }

    #[test]
    fn read_solana_account_count_defaults_to_one_when_the_file_is_missing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(SOLANA_ACCOUNTS_FILENAME);
        assert!(!path.exists());
        assert_eq!(read_solana_account_count(&path), 1);
    }

    #[test]
    fn read_solana_account_count_defaults_to_one_when_the_file_is_unparseable_or_zero() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(SOLANA_ACCOUNTS_FILENAME);

        fs::write(&path, "not a number").expect("write garbage");
        assert_eq!(read_solana_account_count(&path), 1);

        // 0 is nonsensical -- account 0 always exists the moment a wallet
        // does, so a persisted 0 is corrupt state, not a real "zero
        // accounts" case. Falls back to the same safe floor as missing/
        // unparseable, rather than trusting a value that would make
        // `add_solana_account` re-derive index 0 as if it were new.
        fs::write(&path, "0").expect("write zero");
        assert_eq!(read_solana_account_count(&path), 1);
    }

    #[test]
    fn write_then_read_solana_account_count_round_trips() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(SOLANA_ACCOUNTS_FILENAME);

        write_solana_account_count(&path, 3).expect("write succeeds");
        assert_eq!(read_solana_account_count(&path), 3);

        // Overwriting an existing count must succeed -- this file is meant
        // to be legitimately rewritten every time an account is added,
        // unlike the vault file's "never overwrite" rule.
        write_solana_account_count(&path, 4).expect("overwrite succeeds");
        assert_eq!(read_solana_account_count(&path), 4);
    }

    #[test]
    fn add_solana_account_derives_the_next_index_and_persists_the_new_count() {
        let (unlocked, _vault_path, _failures, _words, dir) = sealed_and_unlocked_wallet();
        let accounts_path = dir.path().join(SOLANA_ACCOUNTS_FILENAME);

        // Starting fresh: no file yet, so the first add derives index 1
        // (account 0 is always implicit).
        assert_eq!(read_solana_account_count(&accounts_path), 1);

        let expected_index_1 = {
            let guard = unlocked.0.lock().expect("lock");
            let seed = guard.as_ref().expect("session present").mnemonic.to_seed("");
            SolanaAccountKey::derive(&seed, 1).expect("derive account 1").address()
        };

        let added_address =
            add_solana_account_impl(&unlocked, &accounts_path).expect("add should succeed");

        assert_eq!(added_address, expected_index_1, "must derive the real next index, not a placeholder");
        assert_eq!(
            read_solana_account_count(&accounts_path),
            2,
            "count must be persisted immediately after a successful add"
        );

        // A second add derives index 2, proving this isn't hardcoded to
        // "always derive index 1" -- it must track the persisted count.
        let expected_index_2 = {
            let guard = unlocked.0.lock().expect("lock");
            let seed = guard.as_ref().expect("session present").mnemonic.to_seed("");
            SolanaAccountKey::derive(&seed, 2).expect("derive account 2").address()
        };
        let second_added = add_solana_account_impl(&unlocked, &accounts_path).expect("second add should succeed");
        assert_eq!(second_added, expected_index_2);
        assert_eq!(read_solana_account_count(&accounts_path), 3);
    }

    #[test]
    fn add_solana_account_requires_an_unlocked_session() {
        let dir = tempfile::tempdir().expect("temp dir");
        let accounts_path = dir.path().join(SOLANA_ACCOUNTS_FILENAME);

        let unlocked = UnlockedWallet::default();
        let error = add_solana_account_impl(&unlocked, &accounts_path)
            .expect_err("a locked session must refuse to add an account");
        assert_eq!(error, "wallet is locked");

        // A failed add (locked session) must not have advanced the count --
        // see add_solana_account_impl's own doc comment on the
        // derive-before-persist ordering this proves.
        assert_eq!(
            read_solana_account_count(&accounts_path),
            1,
            "a failed add must leave the persisted count untouched"
        );
    }

    #[test]
    fn password_one_character_under_the_minimum_is_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();

        let just_short: String = "a".repeat(MIN_PASSWORD_LEN - 1);
        let result = confirm_and_seal_impl(&pending, &correct_slots, &just_short, &path);

        assert!(result.is_err(), "boundary is inclusive of the minimum only");
        assert!(!path.exists());
    }

    #[test]
    fn password_length_is_counted_in_characters_not_bytes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();

        // Three emoji: 12 bytes, but only 3 characters. A byte-length check
        // would accept this as if it met a 12-character minimum.
        let emoji = "👍👍👍";
        assert_eq!(emoji.len(), 12);
        assert!(emoji.chars().count() < MIN_PASSWORD_LEN);

        let result = confirm_and_seal_impl(&pending, &correct_slots, emoji, &path);

        assert!(result.is_err(), "byte length must not satisfy the minimum");
        assert!(!path.exists());
    }

    #[test]
    fn out_of_range_and_repeated_slots_are_rejected_without_panicking() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (pending, _words, correct_slots) = pending_with_mnemonic();

        // `selected_order` is untrusted input from the webview. Indexing
        // `bank` directly with these would panic; the check must simply fail.
        let out_of_range = vec![usize::MAX; correct_slots.len()];
        let path = dir.path().join("a.vault");
        assert!(confirm_and_seal_impl(&pending, &out_of_range, TEST_PASSWORD, &path).is_err());
        assert!(!path.exists());

        // A repeated slot is the right length but cannot be a real ordering.
        let repeated = vec![correct_slots[0]; correct_slots.len()];
        let path = dir.path().join("b.vault");
        assert!(confirm_and_seal_impl(&pending, &repeated, TEST_PASSWORD, &path).is_err());
        assert!(!path.exists());

        // Too few slots.
        let path = dir.path().join("c.vault");
        assert!(confirm_and_seal_impl(&pending, &correct_slots[..3], TEST_PASSWORD, &path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn unlock_returns_the_address_the_wallet_was_created_with() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();

        let created = confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path)
            .expect("seal succeeds");

        let unlocked = UnlockedWallet::default();
        let opened = try_unlock(&unlocked, TEST_PASSWORD, &path).expect("unlock succeeds");

        assert_eq!(created, opened);
        assert!(
            unlocked.0.lock().expect("lock").is_some(),
            "unlocking must hold the mnemonic for the session"
        );
    }

    #[test]
    fn unlock_with_wrong_passphrase_fails_without_leaking_why() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();
        confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path).expect("seal succeeds");

        let unlocked = UnlockedWallet::default();
        let error = try_unlock(&unlocked, "the-wrong-passphrase", &path)
            .expect_err("wrong passphrase must fail");

        // Fixed string, for the same reason as above: scanning for phrase
        // words collides with ordinary English (`unlock` and `check` are
        // both BIP-39 words and both appear in this message).
        assert_eq!(error, "could not unlock the wallet: check your passphrase");
        // Must not distinguish a wrong passphrase from a corrupt file.
        assert!(!error.to_lowercase().contains("corrupt"));
        assert!(!error.to_lowercase().contains("tamper"));
        assert!(
            unlocked.0.lock().expect("lock").is_none(),
            "a failed unlock must not leave a session open"
        );
    }

    #[test]
    fn old_seed_format_vault_reports_a_version_error_not_a_decryption_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();
        confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path).expect("seal succeeds");

        // Rewind the version byte to 1 — what the seed-sealing build wrote.
        // The container layout is identical, so this is byte-for-byte what
        // an old vault looks like to the parser.
        let mut bytes = fs::read(&path).expect("read vault");
        bytes[0] = 1;
        fs::write(&path, &bytes).expect("write downgraded vault");

        let unlocked = UnlockedWallet::default();
        let error = try_unlock(&unlocked, TEST_PASSWORD, &path)
            .expect_err("a v1 vault must be refused");

        assert!(
            error.contains("earlier version"),
            "expected a version message, got: {error}"
        );
        // Detected before the passphrase is used, so the *correct* passphrase
        // still produces the version error rather than a decryption error.
        assert!(!error.contains("passphrase") || error.contains("recovery phrase"));
    }

    #[test]
    fn locking_clears_the_session() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();
        confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path).expect("seal succeeds");

        let unlocked = UnlockedWallet::default();
        try_unlock(&unlocked, TEST_PASSWORD, &path).expect("unlock succeeds");
        assert!(unlocked.0.lock().expect("lock").is_some());

        // Mirrors what `lock_wallet` does to the same state.
        *unlocked.0.lock().expect("lock") = None;
        assert!(unlocked.0.lock().expect("lock").is_none());
    }

    #[test]
    fn unlock_with_no_wallet_present_says_so() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);

        let unlocked = UnlockedWallet::default();
        let error =
            try_unlock(&unlocked, TEST_PASSWORD, &path).expect_err("missing file must fail");

        assert!(error.contains("no wallet"), "got: {error}");
    }

    #[test]
    fn unlock_delay_schedule_is_free_then_doubling_then_capped() {
        // First three misses are free.
        assert_eq!(unlock_delay(0), Duration::ZERO);
        assert_eq!(unlock_delay(1), Duration::ZERO);
        assert_eq!(unlock_delay(2), Duration::ZERO);
        // Then doubling from 1s.
        assert_eq!(unlock_delay(3), Duration::from_secs(1));
        assert_eq!(unlock_delay(4), Duration::from_secs(2));
        assert_eq!(unlock_delay(5), Duration::from_secs(4));
        assert_eq!(unlock_delay(11), Duration::from_secs(256));
        // Capped at 5 minutes, and never overflows even at the extreme.
        assert_eq!(unlock_delay(12), Duration::from_secs(300));
        assert_eq!(unlock_delay(1000), Duration::from_secs(300));
        assert_eq!(unlock_delay(u32::MAX), Duration::from_secs(300));
    }

    #[test]
    fn failed_unlock_increments_persisted_counter_and_success_resets_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let failures = path.with_file_name(UNLOCK_FAILURES_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();
        confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path).expect("seal");

        let unlocked = UnlockedWallet::default();

        // Two wrong attempts persist a count of 2 (still under the free
        // threshold, so no real sleep is incurred by the no-op delay).
        assert_eq!(read_unlock_failures(&failures), 0);
        assert!(try_unlock(&unlocked, "wrong-passphrase-1", &path).is_err());
        assert_eq!(read_unlock_failures(&failures), 1);
        assert!(try_unlock(&unlocked, "wrong-passphrase-2", &path).is_err());
        assert_eq!(read_unlock_failures(&failures), 2);

        // A correct unlock clears the counter file entirely.
        try_unlock(&unlocked, TEST_PASSWORD, &path).expect("correct passphrase unlocks");
        assert!(!failures.exists(), "success must reset the throttle");
    }

    #[test]
    fn wrong_format_and_missing_file_do_not_increment_the_counter() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let failures = path.with_file_name(UNLOCK_FAILURES_FILENAME);
        let unlocked = UnlockedWallet::default();

        // Missing file: not a guessing attempt.
        assert!(try_unlock(&unlocked, TEST_PASSWORD, &path).is_err());
        assert_eq!(read_unlock_failures(&failures), 0);

        // Old-format vault: also not a passphrase guess.
        let (pending, _w, slots) = pending_with_mnemonic();
        confirm_and_seal_impl(&pending, &slots, TEST_PASSWORD, &path).expect("seal");
        let mut bytes = fs::read(&path).expect("read");
        bytes[0] = 1;
        fs::write(&path, &bytes).expect("downgrade");
        assert!(try_unlock(&unlocked, TEST_PASSWORD, &path).is_err());
        assert_eq!(read_unlock_failures(&failures), 0);
    }

    #[test]
    fn idle_session_is_cleared_after_the_timeout_but_not_before() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();
        confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path).expect("seal");

        let unlocked = UnlockedWallet::default();
        try_unlock(&unlocked, TEST_PASSWORD, &path).expect("unlock");

        let now = Instant::now();
        // Not yet expired: a check "now" against a 10-minute timeout leaves it.
        unlocked.clear_if_expired(now, SESSION_IDLE_TIMEOUT);
        assert!(unlocked.0.lock().expect("lock").is_some());

        // A check dated far in the future clears it.
        let later = now + SESSION_IDLE_TIMEOUT + Duration::from_secs(1);
        unlocked.clear_if_expired(later, SESSION_IDLE_TIMEOUT);
        assert!(
            unlocked.0.lock().expect("lock").is_none(),
            "an idle session past the timeout must be cleared"
        );
    }

    #[test]
    fn clear_wipes_an_unlocked_session() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();
        confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path).expect("seal");

        let unlocked = UnlockedWallet::default();
        try_unlock(&unlocked, TEST_PASSWORD, &path).expect("unlock");
        assert!(unlocked.0.lock().expect("lock").is_some());

        // This is what the window blur/close handlers call.
        unlocked.clear();
        assert!(unlocked.0.lock().expect("lock").is_none());
    }

    #[test]
    fn wrong_word_order_is_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();

        // Same words, wrong order — the ordering is the whole point of the
        // confirm step, so this must fail even though the set matches.
        let mut swapped = correct_slots.clone();
        swapped.swap(0, 1);

        let result = confirm_and_seal_impl(&pending, &swapped, TEST_PASSWORD, &path);

        assert!(result.is_err(), "wrong order must not be accepted");
        // Still pending, so the user can retry without losing the phrase.
        assert!(
            pending.0.lock().expect("lock").is_some(),
            "a mis-click should leave the phrase available to retry"
        );
    }

    #[test]
    fn failed_confirm_leaves_no_vault_file_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();

        let reversed: Vec<usize> = correct_slots.iter().rev().copied().collect();
        let result = confirm_and_seal_impl(&pending, &reversed, TEST_PASSWORD, &path);

        assert!(result.is_err());
        assert!(
            !path.exists(),
            "a failed confirmation must not write a vault file"
        );
    }

    #[test]
    fn existing_vault_is_never_overwritten() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        fs::write(&path, b"pretend this is an existing wallet").expect("write fixture");
        let (pending, _words, correct_slots) = pending_with_mnemonic();

        let result = confirm_and_seal_impl(&pending, &correct_slots, TEST_PASSWORD, &path);

        assert!(result.is_err(), "must refuse to overwrite an existing vault");
        assert_eq!(
            fs::read(&path).expect("read back"),
            b"pretend this is an existing wallet",
            "the existing vault file must be left byte-for-byte intact"
        );
    }

    #[test]
    fn short_password_is_rejected_before_anything_is_written() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();

        let result = confirm_and_seal_impl(&pending, &correct_slots, "short", &path);

        assert!(result.is_err());
        assert!(!path.exists());
    }

    #[test]
    fn errors_never_contain_phrase_words() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(VAULT_FILENAME);
        let (pending, _words, correct_slots) = pending_with_mnemonic();

        let mut swapped = correct_slots.clone();
        swapped.swap(0, 1);
        let error = confirm_and_seal_impl(&pending, &swapped, TEST_PASSWORD, &path)
            .expect_err("wrong order errors");

        // Asserts the message is a fixed string, rather than scanning it for
        // phrase words. The scanning version was unsound and intermittently
        // failed: `match`, `check`, `unlock` and `phrase` are all BIP-39
        // wordlist entries *and* ordinary English that appears in these very
        // error strings, so a generated phrase containing one produced a
        // false positive roughly 2% of the time.
        //
        // Equality is also the stronger property: it fails if anything is
        // ever interpolated into this message, secret or not.
        assert_eq!(error, "the recovery phrase confirmation did not match");
    }
}
