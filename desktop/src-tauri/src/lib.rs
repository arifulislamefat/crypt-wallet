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
use cryptwallet_crypto::{EvmAccountKey, SecretMnemonic, WordCount};
use cryptwallet_vault::{KdfParams, SealedVault, VaultError};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use tauri::{AppHandle, Manager, State, WindowEvent};
use zeroize::Zeroizing;

/// Sepolia's chain ID. `sign_transaction` refuses to sign for anything
/// else — see that function's doc comment for why this check exists at
/// all despite the frontend already only ever sending this value.
const SEPOLIA_CHAIN_ID: u64 = 11155111;

/// Filename of the sealed vault inside the app data directory.
const VAULT_FILENAME: &str = "wallet.vault";

/// Filename of the persisted consecutive-failed-unlock counter, kept next to
/// the vault in app data. Survives process restart on purpose: an in-memory
/// counter is reset simply by killing and relaunching the app, which is
/// exactly the scripted-attack case the rate limit is meant to slow.
const UNLOCK_FAILURES_FILENAME: &str = "unlock-failures";

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
    // Read by get_second_account_address and sign_transaction to re-derive
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
    // memory-only counter would not.
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

    // Seed is re-derived from the phrase rather than stored — deterministic,
    // so nothing is lost by not persisting it.
    let address = EvmAccountKey::derive(&mnemonic.to_seed(""), 0)
        .map_err(|_| "failed to derive an account from the recovery phrase".to_string())?
        .address()
        .to_checksummed_hex();

    // Success resets the throttle.
    let _ = fs::remove_file(failures_path);

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

/// The address of EVM account index 1 ("Account 2") for the currently
/// unlocked wallet — the fixed send destination for the first real-
/// transaction test. Sending between two addresses this wallet itself
/// controls means a signing or broadcast mistake can't move funds anywhere
/// the user doesn't already hold them; free-form recipients are a later
/// step with their own address-entry validation UX.
#[tauri::command]
fn get_second_account_address(unlocked: State<'_, UnlockedWallet>) -> Result<String, String> {
    get_second_account_address_impl(&unlocked)
}

/// The testable core of [`get_second_account_address`].
fn get_second_account_address_impl(unlocked: &UnlockedWallet) -> Result<String, String> {
    let guard = unlocked
        .0
        .lock()
        .map_err(|_| "wallet session state is unavailable")?;
    let session = guard.as_ref().ok_or("wallet is locked")?;

    let seed = session.mnemonic.to_seed("");
    let account = EvmAccountKey::derive(&seed, 1)
        .map_err(|_| "failed to derive the second account".to_string())?;
    Ok(account.address().to_checksummed_hex())
}

/// Sign an EIP-1559 Sepolia transaction sending from account 0 of the
/// currently-unlocked wallet, and return the raw signed transaction as a
/// `0x`-prefixed hex string, ready for `eth_sendRawTransaction`.
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
/// The `chain_id == 11155111` check is deliberately redundant with the
/// frontend only ever constructing Sepolia transactions — this command is
/// the last line of defense before a real signature is produced, so it
/// does not trust the caller's chain_id, however that value got here.
/// Every other numeric argument (nonce, fees, gas limit) is taken as given
/// once past basic parsing: those come from the RPC node's own
/// `getTransactionCount`/fee-estimate responses, not from the user, and
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
) -> Result<String, String> {
    if chain_id != SEPOLIA_CHAIN_ID {
        return Err(format!(
            "refusing to sign: expected chain ID {SEPOLIA_CHAIN_ID} (Sepolia), got {chain_id}"
        ));
    }

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

    let guard = unlocked
        .0
        .lock()
        .map_err(|_| "wallet session state is unavailable")?;
    let session = guard.as_ref().ok_or("wallet is locked")?;

    let seed = session.mnemonic.to_seed("");
    let account = EvmAccountKey::derive(&seed, 0)
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
        // confirm it's actually account 0. A signature that doesn't
        // recover to the account that supposedly made it is not a
        // transaction that should ever be returned for broadcast,
        // regardless of what upstream produced it.
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
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
        get_second_account_address,
        sign_transaction
    ]);
    #[cfg(not(debug_assertions))]
    let builder = builder.invoke_handler(tauri::generate_handler![
        generate_new_mnemonic,
        confirm_and_seal_wallet,
        wallet_exists,
        unlock_wallet,
        lock_wallet,
        get_second_account_address,
        sign_transaction
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
        let recipient = get_second_account_address_impl(&unlocked).expect("derive account 1");

        let raw_hex = sign_transaction_impl(
            &unlocked,
            &recipient,
            "1000000000000000", // 0.001 ETH, in wei
            0,
            "20000000000", // 20 gwei
            "1000000000",  // 1 gwei
            21000,
            SEPOLIA_CHAIN_ID,
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

    #[test]
    fn wrong_chain_id_is_rejected_before_any_signing() {
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
            1, // Ethereum mainnet, not Sepolia -- must be refused
        );

        let error = result.expect_err("a non-Sepolia chain id must be rejected");
        assert!(
            error.contains("chain ID"),
            "expected a chain-id error, got: {error}"
        );
        assert!(
            !error.to_lowercase().contains("locked"),
            "got a 'wallet locked' error instead of a chain-id error -- the \
             chain-id check ran after touching session state, not before: {error}"
        );
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
            let result =
                sign_transaction_impl(&unlocked, bad, "0", 0, "0", "0", 21000, SEPOLIA_CHAIN_ID);
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
        );
        assert!(
            result.is_err(),
            "an unchecksummed (all-lowercase) address must be rejected, not silently accepted"
        );
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
