//! Solana key derivation (SLIP-0010 ed25519) and address encoding.
//!
//! ## Why this is a fundamentally different module from `derivation.rs`/`evm.rs`
//!
//! Every EVM chain in this crate shares one derivation algorithm (BIP-32
//! over secp256k1) and one address rule (Keccak256 of the public key point).
//! Solana shares neither:
//!
//! - **Curve**: ed25519, not secp256k1. Standard BIP-32 is defined in terms
//!   of secp256k1 point arithmetic and does not apply to ed25519 at all.
//! - **Derivation algorithm**: [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md),
//!   not BIP-32. SLIP-10 extends BIP-32's HMAC-SHA512 construction to other
//!   curves, but for ed25519 specifically it only defines *hardened*
//!   derivation — there is no non-hardened child-key algorithm for ed25519,
//!   because ed25519 public keys can't support the "derive a child public
//!   key without the private key" property BIP-32's non-hardened path
//!   relies on. Every level of every path this module derives is therefore
//!   hardened, including the address-index level that EVM's
//!   `derivation.rs` leaves non-hardened.
//! - **Address rule**: a Solana address is simply the Base58 encoding of the
//!   raw 32-byte ed25519 public key. No hashing, no checksum, no version
//!   byte (unlike Bitcoin's Base58Check) — see [`SolanaAccountKey::address`].
//!
//! ## Derivation path
//!
//! `m/44'/501'/{account}'/0'` — coin_type 501 is Solana's registered
//! SLIP-44 value (<https://github.com/satoshilabs/slips/blob/master/slip-0044.md>).
//! This exact path (all four levels hardened, including the trailing `/0'`)
//! is Phantom's documented default/primary derivation path — confirmed
//! directly against Phantom's own help-center documentation before use, the
//! same discipline as every chain ID in this codebase. It differs from the
//! `bip44` fallback path some wallets/tools also support
//! (`m/44'/501'/{account}'`, no trailing `/0'`) — if a future need arises to
//! import a wallet created under that convention, it is a distinct,
//! separately-added path, not a bug in this one.
//!
//! `{account}` here plays the same "Account 1, Account 2, ..." role as
//! `derivation.rs`'s `index` — increasing account numbers are how this app
//! presents multiple accounts from one seed, on every chain.

use crate::mnemonic::Seed;
use hmac::{Hmac, Mac};
use sha2::Sha512;

/// Errors from Solana key derivation. As with the EVM module, no variant
/// carries key material.
#[derive(Debug, thiserror::Error)]
pub enum SolanaDerivationError {
    /// The account index was `>= 2^31`, which is the hardened-key range
    /// boundary. Every level ed25519 SLIP-10 derives is already hardened
    /// (see module doc comment), so this isn't about crossing into a
    /// different derivation mode the way it is for EVM — it's simply that
    /// `2^31 + index` would overflow `u32` for an index at or above this
    /// boundary, and silently wrapping would derive an unexpected key.
    #[error("account index out of range")]
    IndexOutOfRange,
}

/// The BIP-32/SLIP-10 hardened-index boundary — same constant and meaning
/// as `derivation.rs`'s `HARDENED_OFFSET`, duplicated here rather than
/// shared because the two modules are deliberately independent (see this
/// file's module doc comment) and importing one hand-rolled constant across
/// that boundary isn't worth coupling them for.
const HARDENED_OFFSET: u32 = 0x8000_0000;

/// SLIP-10's fixed HMAC key for ed25519 master-key generation. Verbatim
/// from the spec: <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>,
/// "Master key generation" section — this exact ASCII string, not a value
/// this implementation chose.
const ED25519_SEED_KEY: &[u8] = b"ed25519 seed";

type HmacSha512 = Hmac<Sha512>;

/// SLIP-10 ed25519 master key generation: `I = HMAC-SHA512(key = "ed25519
/// seed", data = seed)`, split into `IL` (private key) and `IR` (chain
/// code). `seed` here is this crate's 64-byte BIP-39 seed — SLIP-10 accepts
/// any seed of 128 to 512 bits, so the standard 64-byte BIP-39 seed is a
/// valid, unmodified input; no re-hashing or truncation happens first.
fn master_key(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    // HMAC accepts a key of any length, so construction cannot fail here —
    // `expect` is the correct tool for a genuinely infallible call, not a
    // shortcut around error handling (see the crate-level
    // `#![warn(clippy::expect_used)]`: this is a deliberate, justified use,
    // not an oversight).
    let mut mac = HmacSha512::new_from_slice(ED25519_SEED_KEY).expect("HMAC accepts any key length");
    mac.update(seed);
    let i = mac.finalize().into_bytes();

    let mut il = [0u8; 32];
    let mut ir = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    ir.copy_from_slice(&i[32..]);
    (il, ir)
}

/// SLIP-10 ed25519 child key derivation (hardened only — ed25519 has no
/// other kind, see module doc comment): `I = HMAC-SHA512(key = chain_code,
/// data = 0x00 || private_key || ser32(index))`, where `index` already has
/// the hardened bit set by the caller.
fn child_key(private_key: &[u8; 32], chain_code: &[u8; 32], hardened_index: u32) -> ([u8; 32], [u8; 32]) {
    let mut mac =
        HmacSha512::new_from_slice(chain_code).expect("HMAC accepts any key length, including this 32-byte one");
    mac.update(&[0u8]);
    mac.update(private_key);
    mac.update(&hardened_index.to_be_bytes());
    let i = mac.finalize().into_bytes();

    let mut il = [0u8; 32];
    let mut ir = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    ir.copy_from_slice(&i[32..]);
    (il, ir)
}

/// A derived ed25519 signing key for one Solana account.
///
/// Mirrors [`crate::derivation::EvmAccountKey`]'s shape and scope
/// deliberately: derivation and address encoding only, no transaction
/// construction or signing method here yet (signing is a later,
/// separately-reviewed phase, once this derivation module itself — and its
/// address output — has been cross-checked against an independent reference
/// wallet).
#[derive(zeroize::ZeroizeOnDrop)]
pub struct SolanaAccountKey {
    signing_key: ed25519_dalek::SigningKey,
}

impl std::fmt::Debug for SolanaAccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SolanaAccountKey(<redacted>)")
    }
}

impl SolanaAccountKey {
    /// Derive Solana account `index` (the hardened `account'` level of
    /// `m/44'/501'/{index}'/0'`) from a BIP-39 seed. See the module doc
    /// comment for why this path, and for why every level is hardened.
    pub fn derive(seed: &Seed, index: u32) -> Result<Self, SolanaDerivationError> {
        if index >= HARDENED_OFFSET {
            return Err(SolanaDerivationError::IndexOutOfRange);
        }

        let (k, c) = master_key(&seed.0);
        let (k, c) = child_key(&k, &c, HARDENED_OFFSET + 44);
        let (k, c) = child_key(&k, &c, HARDENED_OFFSET + 501);
        let (k, c) = child_key(&k, &c, HARDENED_OFFSET + index);
        let (k, _c) = child_key(&k, &c, HARDENED_OFFSET);

        // SLIP-10's `IL` is used directly as the 32-byte ed25519 private
        // key seed -- `SigningKey::from_bytes` performs the standard RFC
        // 8032 SHA-512 expansion/clamping internally, the same step every
        // conformant ed25519 implementation performs from this same
        // 32-byte value. Confirmed against this exact seed value
        // independently, outside this crate's own dependency tree, using
        // Python's `cryptography` library during this module's
        // development (see the test vector below).
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&k);

        Ok(Self { signing_key })
    }

    /// This account's Solana address: the Base58 (Bitcoin-alphabet)
    /// encoding of the raw 32-byte ed25519 public key, with no hashing, no
    /// checksum, and no version byte. This is the actual, complete address
    /// rule Solana uses — not a simplification. Confirmed against
    /// Solana's own address format (a "Solana address" and "a Solana
    /// account's public key" are the same 32 bytes, Base58-encoded) rather
    /// than assumed from Bitcoin-style Base58Check conventions, which do
    /// not apply here.
    pub fn address(&self) -> String {
        bs58::encode(self.signing_key.verifying_key().as_bytes()).into_string()
    }

    /// Expose the underlying ed25519 signing key for the duration of `f`.
    /// See [`crate::derivation::EvmAccountKey::expose_secret`]'s doc
    /// comment — same contract, same reasoning, same shared name so one
    /// `grep -r expose_secret` finds every site across the workspace that
    /// touches raw secret material.
    ///
    /// Signing itself is deliberately NOT implemented in this crate yet —
    /// Solana transaction construction (message serialization, the wire
    /// format) belongs with whatever audited library/hand-verified format
    /// code ends up handling it in `desktop/src-tauri`, not here.
    pub fn expose_secret<R>(&self, f: impl FnOnce(&ed25519_dalek::SigningKey) -> R) -> R {
        f(&self.signing_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::SecretMnemonic;

    /// SLIP-0010's own published "Test vector 1 for ed25519"
    /// (<https://github.com/satoshilabs/slips/blob/master/slip-0010.md>),
    /// covering the master key and the first two hardened derivation
    /// steps. Independently re-derived from the spec's algorithm using
    /// Python's stdlib `hmac`/`hashlib` (not copied from a single scraped
    /// source) before being hard-coded here — same discipline as the
    /// BIP-39 vector in `mnemonic.rs`.
    #[test]
    fn slip10_official_test_vector_1_master_and_two_hardened_children() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").expect("valid hex");

        let (m_priv, m_cc) = master_key(&seed);
        assert_eq!(
            hex::encode(m_priv),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex::encode(m_cc),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
        );

        let (c0_priv, c0_cc) = child_key(&m_priv, &m_cc, HARDENED_OFFSET);
        assert_eq!(
            hex::encode(c0_priv),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
        assert_eq!(
            hex::encode(c0_cc),
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"
        );

        let (c1_priv, c1_cc) = child_key(&c0_priv, &c0_cc, HARDENED_OFFSET + 1);
        assert_eq!(
            hex::encode(c1_priv),
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"
        );
        assert_eq!(
            hex::encode(c1_cc),
            "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"
        );
    }

    /// The same seed's master and `m/0'` ed25519 *public* keys, checked
    /// against an ed25519 keygen done outside this crate's dependency tree
    /// (Python's `cryptography` library) — proves `ed25519-dalek`'s
    /// `SigningKey::from_bytes` -> `verifying_key()` step (the part this
    /// crate does NOT hand-roll) agrees with an independent implementation,
    /// not just that the derivation arithmetic above is self-consistent.
    #[test]
    fn slip10_derived_public_keys_match_an_independent_ed25519_keygen() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").expect("valid hex");

        let (m_priv, m_cc) = master_key(&seed);
        let master_signing_key = ed25519_dalek::SigningKey::from_bytes(&m_priv);
        assert_eq!(
            hex::encode(master_signing_key.verifying_key().as_bytes()),
            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
        );

        let (c0_priv, _) = child_key(&m_priv, &m_cc, HARDENED_OFFSET);
        let child_signing_key = ed25519_dalek::SigningKey::from_bytes(&c0_priv);
        assert_eq!(
            hex::encode(child_signing_key.verifying_key().as_bytes()),
            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"
        );
    }

    /// Full pipeline, end to end: a BIP-39 mnemonic (fixed test entropy,
    /// same `[0x11; 32]` pattern `derivation.rs`'s own tests use) -> this
    /// crate's real seed derivation -> this module's real
    /// `m/44'/501'/0'/0'` path -> Base58 address. The expected address was
    /// computed independently, outside this crate, using Python's
    /// `mnemonic` package for the BIP-39 phrase/seed and `cryptography` +
    /// `base58` for SLIP-10 derivation and encoding — a genuine external
    /// cross-check of this module's actual public API, not just its
    /// internal arithmetic.
    ///
    /// NOT yet cross-checked against a reference *wallet* (Phantom) — that
    /// requires importing a test mnemonic into Phantom by hand and is a
    /// step for you to do before this derivation is trusted for anything
    /// beyond this automated test. See the project's own stated bar for
    /// EVM Phase 1 (cross-checked against MetaMask) — this is the same bar,
    /// not yet met for Solana.
    #[test]
    fn full_pipeline_from_test_mnemonic_matches_independent_python_derivation() {
        let entropy = [0x11u8; 32];
        let seed = SecretMnemonic::from_entropy_for_testing(&entropy)
            .expect("valid entropy")
            .to_seed("");

        let account0 = SolanaAccountKey::derive(&seed, 0).expect("derivation should succeed");
        assert_eq!(account0.address(), "756ad1GVwuiWGSZPaqJBJKtC74wKMfMGzAAKTcYbXsZ8");
    }

    #[test]
    fn derivation_is_deterministic() {
        let entropy = [0x22u8; 32];
        let seed = SecretMnemonic::from_entropy_for_testing(&entropy)
            .expect("valid entropy")
            .to_seed("");

        let key_a = SolanaAccountKey::derive(&seed, 0).expect("derivation should succeed");
        let key_b = SolanaAccountKey::derive(&seed, 0).expect("derivation should succeed");
        assert_eq!(key_a.address(), key_b.address());
    }

    #[test]
    fn different_account_indexes_produce_different_addresses() {
        let entropy = [0x33u8; 32];
        let seed = SecretMnemonic::from_entropy_for_testing(&entropy)
            .expect("valid entropy")
            .to_seed("");

        let account_0 = SolanaAccountKey::derive(&seed, 0).expect("derivation should succeed");
        let account_1 = SolanaAccountKey::derive(&seed, 1).expect("derivation should succeed");
        assert_ne!(account_0.address(), account_1.address());
    }

    #[test]
    fn different_seeds_produce_different_addresses() {
        let seed_a = SecretMnemonic::from_entropy_for_testing(&[0x44u8; 32])
            .expect("valid entropy")
            .to_seed("");
        let seed_b = SecretMnemonic::from_entropy_for_testing(&[0x55u8; 32])
            .expect("valid entropy")
            .to_seed("");

        let key_a = SolanaAccountKey::derive(&seed_a, 0).expect("derivation should succeed");
        let key_b = SolanaAccountKey::derive(&seed_b, 0).expect("derivation should succeed");
        assert_ne!(key_a.address(), key_b.address());
    }

    #[test]
    fn hardened_range_index_is_rejected() {
        let seed = SecretMnemonic::from_entropy_for_testing(&[0x66u8; 32])
            .expect("valid entropy")
            .to_seed("");

        assert!(SolanaAccountKey::derive(&seed, HARDENED_OFFSET - 1).is_ok());
        assert!(matches!(
            SolanaAccountKey::derive(&seed, HARDENED_OFFSET),
            Err(SolanaDerivationError::IndexOutOfRange)
        ));
        assert!(matches!(
            SolanaAccountKey::derive(&seed, u32::MAX),
            Err(SolanaDerivationError::IndexOutOfRange)
        ));
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let seed = SecretMnemonic::from_entropy_for_testing(&[0x77u8; 32])
            .expect("valid entropy")
            .to_seed("");
        let key = SolanaAccountKey::derive(&seed, 0).expect("derivation should succeed");

        assert_eq!(format!("{key:?}"), "SolanaAccountKey(<redacted>)");
    }
}
