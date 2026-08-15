//! Password-based encrypted-at-rest storage for secret material.
//!
//! ## What this protects, and what it doesn't
//!
//! This crate turns "a password + some secret bytes" into "an opaque
//! encrypted blob that can only be read back with the same password," and
//! back again. That's the *entire* scope. It deliberately does NOT:
//! - touch the filesystem (no `std::fs` anywhere in this crate — the caller
//!   decides where the serialized bytes get stored, which keeps this crate
//!   testable and reusable across Android/Desktop/Extension without
//!   depending on any platform's storage API)
//! - talk to a platform keystore (Android Keystore, OS keychain) — per the
//!   architecture spec's real design (§D.3), the *output* of this crate
//!   (the serialized vault bytes) is what a platform integration layer
//!   would additionally wrap with hardware-backed storage; this crate is
//!   the portable core underneath that, not a replacement for it
//! - decide what the "password" actually is in the finished app (app
//!   passcode vs. a separate export passphrase, per the distinction drawn
//!   in `mnemonic.rs`'s doc comments in Phase 1) — that's a caller decision
//!
//! ## Cryptographic construction
//!
//! ```text
//! seal(plaintext, password):
//!   salt      = random 16 bytes                    (OS CSPRNG)
//!   nonce     = random 24 bytes                     (OS CSPRNG, XChaCha-sized)
//!   key       = Argon2id(password, salt, params)    (32-byte output)
//!   ciphertext + tag = XChaCha20-Poly1305(key, nonce, plaintext)
//!   key is zeroized immediately after use
//!   -> stored: { params, salt, nonce, ciphertext+tag }
//!
//! open(vault, password):
//!   key = Argon2id(password, vault.salt, vault.params)
//!   plaintext = XChaCha20-Poly1305-decrypt(key, vault.nonce, vault.ciphertext)
//!               (fails closed if the auth tag doesn't verify — wrong
//!                password and tampered ciphertext produce the exact same
//!                error, which is inherent to how AEAD tag verification
//!                works, not something this code has to special-case)
//!   key is zeroized immediately after use
//! ```

use crate::params::KdfParams;
use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand_core::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Nonce/salt randomness uses `rand_core::OsRng` directly (the same
// already-verified CSPRNG pattern from Phase 1's `mnemonic.rs`), rather than
// the `aead` crate's own `OsRng` re-export, so exactly one CSPRNG source is
// used consistently across both the crypto and vault crates.

/// Format version byte. Bumping this is how a future change to the on-disk
/// layout stays distinguishable from today's — `open()` should refuse to
/// parse a version it doesn't recognize rather than guess.
const FORMAT_VERSION: u8 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20Poly1305's extended nonce size
const PARAMS_LEN: usize = 12; // KdfParams::to_bytes() length

/// Errors from sealing or opening a vault.
///
/// `Open` deliberately does not distinguish "wrong password" from
/// "corrupted/tampered ciphertext" from "truncated data" in most cases —
/// telling an attacker which of those happened is a real (if narrow) oracle,
/// and the correct user-facing behavior is identical either way: "couldn't
/// unlock, check your password." `InvalidParams` and `Malformed` are kept
/// separate from `WrongPasswordOrCorrupted` only because they can occur
/// before any password is even involved (e.g. a genuinely truncated file),
/// so conflating them wouldn't hide anything meaningful — but they're
/// intentionally still generic about *what specifically* is malformed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VaultError {
    /// Password derivation or decryption failed. Covers wrong password AND
    /// tampered/corrupted ciphertext — see doc comment above for why these
    /// are deliberately not distinguished.
    #[error("failed to unlock vault: incorrect password or corrupted data")]
    WrongPasswordOrCorrupted,
    /// The stored KDF parameters were out of the sane bounds this crate
    /// enforces (see `params.rs`) — most likely a corrupted or malicious
    /// vault file, not a real one this crate produced.
    #[error("invalid or corrupted vault parameters")]
    InvalidParams,
    /// The serialized bytes are too short or otherwise not shaped like a
    /// vault this crate could have produced.
    #[error("malformed vault data")]
    Malformed,
    /// Unsupported format version — most likely opening a vault produced by
    /// a newer (or, less likely, much older) version of this crate.
    #[error("unsupported vault format version")]
    UnsupportedVersion,
    /// The OS RNG or the underlying crypto primitive failed unexpectedly.
    #[error("cryptographic operation failed")]
    CryptoFailure,
}

/// Decrypted secret bytes, zeroized on drop, never `Debug`-printed in full —
/// same pattern as `Seed`/`SecretMnemonic` in the `crypto` crate. Whatever
/// this vault was protecting (a BIP-39 seed, a raw private key, anything
/// else) comes back out wrapped in this, not as a bare `Vec<u8>`.
#[derive(ZeroizeOnDrop)]
pub struct DecryptedSecret(Vec<u8>);

impl DecryptedSecret {
    /// Borrow the decrypted bytes. Callers should copy out only what they
    /// need and let this wrapper (and therefore the rest) get zeroized as
    /// soon as possible, rather than holding this alive longer than needed.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for DecryptedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecryptedSecret(<redacted>)")
    }
}

/// An encrypted, password-protected blob. Safe to serialize and store
/// anywhere (disk, platform keystore-wrapped storage, etc.) — everything in
/// this struct except the params is either random or encrypted; there is no
/// plaintext secret data in a `SealedVault`'s fields or its serialized form.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedVault {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>, // includes the appended Poly1305 auth tag
}

impl std::fmt::Debug for SealedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Not secret data (it's ciphertext, salt, nonce, and cost params —
        // none of that is the plaintext), so a normal Debug impl is fine and
        // useful, unlike the *_secret* types above.
        f.debug_struct("SealedVault")
            .field("params", &self.params)
            .field("salt", &hex::encode(self.salt))
            .field("nonce", &hex::encode(self.nonce))
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl SealedVault {
    /// Encrypt `plaintext` under `password`, using the given KDF parameters
    /// (see `params.rs` for why these are explicit rather than hardcoded).
    ///
    /// `plaintext` is taken by reference and NOT zeroized by this function —
    /// that's the caller's responsibility for whatever type they passed in
    /// (e.g. `crypto::Seed` and `crypto::SecretMnemonic` already zeroize
    /// themselves; if a caller passes a bare `Vec<u8>`/`&[u8]` here, they
    /// still own zeroizing it after this call returns).
    pub fn seal(
        plaintext: &[u8],
        password: &str,
        params: KdfParams,
    ) -> Result<Self, VaultError> {
        let mut salt = [0u8; SALT_LEN];
        rand_core::OsRng.fill_bytes(&mut salt);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand_core::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let mut key = derive_key(password, &salt, params)?;

        let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_ref()));
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| VaultError::CryptoFailure)?;

        key.zeroize();

        Ok(Self { params, salt, nonce: nonce_bytes, ciphertext })
    }

    /// Decrypt this vault with `password`. See `VaultError::WrongPasswordOrCorrupted`'s
    /// doc comment for why wrong-password and tampered-data both surface the
    /// same error here.
    pub fn open(&self, password: &str) -> Result<DecryptedSecret, VaultError> {
        let mut key = derive_key(password, &self.salt, self.params)?;
        let nonce = XNonce::from_slice(&self.nonce);

        let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_ref()));
        let result = cipher.decrypt(nonce, self.ciphertext.as_ref());

        key.zeroize();

        match result {
            Ok(plaintext) => Ok(DecryptedSecret(plaintext)),
            Err(_) => Err(VaultError::WrongPasswordOrCorrupted),
        }
    }

    /// Serialize to bytes: `[version(1) | params(12) | salt(16) | nonce(24) | ciphertext(rest)]`.
    /// No length prefix needed on `ciphertext` since it's always the final
    /// field — the whole point of putting it last.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + PARAMS_LEN + SALT_LEN + NONCE_LEN + self.ciphertext.len());
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&self.params.to_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse from the format `to_bytes` produces. Rejects unrecognized
    /// version bytes and out-of-range KDF params (see `params.rs`) rather
    /// than guessing at intent.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        const HEADER_LEN: usize = 1 + PARAMS_LEN + SALT_LEN + NONCE_LEN;
        if bytes.len() < HEADER_LEN {
            return Err(VaultError::Malformed);
        }
        if bytes[0] != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion);
        }

        let params_bytes: [u8; PARAMS_LEN] = bytes[1..1 + PARAMS_LEN]
            .try_into()
            .expect("length checked above");
        let params = KdfParams::from_bytes(&params_bytes)?;

        let salt_start = 1 + PARAMS_LEN;
        let salt: [u8; SALT_LEN] = bytes[salt_start..salt_start + SALT_LEN]
            .try_into()
            .expect("length checked above");

        let nonce_start = salt_start + SALT_LEN;
        let nonce: [u8; NONCE_LEN] = bytes[nonce_start..nonce_start + NONCE_LEN]
            .try_into()
            .expect("length checked above");

        let ciphertext = bytes[nonce_start + NONCE_LEN..].to_vec();
        if ciphertext.is_empty() {
            return Err(VaultError::Malformed);
        }

        Ok(Self { params, salt, nonce, ciphertext })
    }
}

/// Derive a 32-byte key from `password` + `salt` using Argon2id.
///
/// VERIFY ON BUILD: `Argon2::new(Algorithm::Argon2id, Version::V0x13, params)`
/// and `Params::new(m_cost, t_cost, p_cost, output_len)` are the constructor
/// shapes documented for the `argon2` crate at spec-writing time — same
/// caveat as Phase 1's `bip32` calls: not compiled in this environment, so
/// treat this as the first place to check against a compiler error.
///
/// Deliberately uses `hash_password_into` (the raw-output KDF API), NOT
/// `hash_password`/the PHC-string password-hashing API — the `argon2`
/// crate's own docs explicitly warn against using the PHC-string API to
/// derive encryption keys; that API is designed for password *verification*
/// (checking a login attempt against a stored hash), which is a different
/// problem with different security properties than "produce 32 bytes to use
/// as an AEAD key."
fn derive_key(password: &str, salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Key32, VaultError> {
    let argon2_params = argon2::Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32), // output length in bytes
    )
    .map_err(|_| VaultError::InvalidParams)?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2_params);

    let mut key = Key32([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key.0)
        .map_err(|_| VaultError::CryptoFailure)?;

    Ok(key)
}

/// A 32-byte derived key, zeroized on drop. Wrapping this in its own type
/// (rather than passing a bare `[u8; 32]` around) means the zeroize-on-drop
/// guarantee travels with the value automatically wherever it's used or
/// returned, instead of relying on every call site remembering to zero it
/// manually.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Key32([u8; 32]);

impl AsRef<[u8]> for Key32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_recovers_original_plaintext() {
        let plaintext = b"this is definitely not a real recovery phrase";
        let vault = SealedVault::seal(plaintext, "correct horse battery staple", KdfParams::DESKTOP_DEFAULT)
            .expect("seal should succeed");

        let opened = vault.open("correct horse battery staple").expect("open with correct password should succeed");
        assert_eq!(opened.as_bytes(), plaintext);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let plaintext = b"secret data";
        let vault = SealedVault::seal(plaintext, "right-password", KdfParams::DESKTOP_DEFAULT)
            .expect("seal should succeed");

        let result = vault.open("wrong-password");
        assert_eq!(result.err(), Some(VaultError::WrongPasswordOrCorrupted));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let plaintext = b"secret data";
        let mut vault = SealedVault::seal(plaintext, "a-password", KdfParams::DESKTOP_DEFAULT)
            .expect("seal should succeed");

        // Flip one bit in the ciphertext — the Poly1305 tag must catch this.
        vault.ciphertext[0] ^= 0x01;

        let result = vault.open("a-password");
        assert_eq!(result.err(), Some(VaultError::WrongPasswordOrCorrupted));
    }

    #[test]
    fn tampered_salt_is_rejected() {
        // Tampering the salt changes the derived key, which is a different
        // (but equally important) attack surface than tampering the
        // ciphertext directly — both must fail closed.
        let plaintext = b"secret data";
        let mut vault = SealedVault::seal(plaintext, "a-password", KdfParams::DESKTOP_DEFAULT)
            .expect("seal should succeed");

        vault.salt[0] ^= 0x01;

        let result = vault.open("a-password");
        assert_eq!(result.err(), Some(VaultError::WrongPasswordOrCorrupted));
    }

    #[test]
    fn same_plaintext_and_password_produce_different_ciphertext_each_time() {
        // This is the property that proves salt/nonce are actually being
        // freshly randomized on every call, not reused or hardcoded — a
        // deterministic seal() would be a serious vulnerability (nonce
        // reuse breaks XChaCha20-Poly1305's confidentiality guarantees).
        let plaintext = b"same secret both times";
        let vault_a = SealedVault::seal(plaintext, "same-password", KdfParams::DESKTOP_DEFAULT)
            .expect("seal should succeed");
        let vault_b = SealedVault::seal(plaintext, "same-password", KdfParams::DESKTOP_DEFAULT)
            .expect("seal should succeed");

        assert_ne!(vault_a.salt, vault_b.salt);
        assert_ne!(vault_a.nonce, vault_b.nonce);
        assert_ne!(vault_a.ciphertext, vault_b.ciphertext);
    }

    #[test]
    fn serialized_bytes_never_contain_the_plaintext() {
        // A cheap, meaningful sanity check that this is actually encrypting
        // the data, not just storing it with a wrapper — a distinctive
        // plaintext should never appear verbatim in the serialized output.
        let distinctive_plaintext = b"UNMISTAKABLE_MARKER_STRING_0xDEADBEEF_1234567890";
        let vault = SealedVault::seal(distinctive_plaintext, "a-password", KdfParams::DESKTOP_DEFAULT)
            .expect("seal should succeed");

        let serialized = vault.to_bytes();
        let serialized_as_lossy_string = String::from_utf8_lossy(&serialized);
        assert!(!serialized_as_lossy_string.contains("UNMISTAKABLE_MARKER_STRING"));
    }

    #[test]
    fn serialize_round_trip_then_decrypt() {
        let plaintext = b"round trip through bytes too";
        let vault = SealedVault::seal(plaintext, "a-password", KdfParams::DESKTOP_DEFAULT)
            .expect("seal should succeed");

        let bytes = vault.to_bytes();
        let reconstructed = SealedVault::from_bytes(&bytes).expect("parsing our own output must succeed");

        let opened = reconstructed.open("a-password").expect("open should succeed");
        assert_eq!(opened.as_bytes(), plaintext);
    }

    #[test]
    fn from_bytes_rejects_truncated_data() {
        let result = SealedVault::from_bytes(&[1, 2, 3]);
        assert_eq!(result.err(), Some(VaultError::Malformed));
    }

    #[test]
    fn from_bytes_rejects_unknown_version() {
        let plaintext = b"secret data";
        let vault = SealedVault::seal(plaintext, "a-password", KdfParams::DESKTOP_DEFAULT)
            .expect("seal should succeed");
        let mut bytes = vault.to_bytes();
        bytes[0] = 99; // not a version this crate produced

        let result = SealedVault::from_bytes(&bytes);
        assert_eq!(result.err(), Some(VaultError::UnsupportedVersion));
    }

    #[test]
    fn debug_output_never_contains_decrypted_plaintext() {
        let plaintext = b"UNMISTAKABLE_DEBUG_TEST_MARKER";
        let vault = SealedVault::seal(plaintext, "a-password", KdfParams::DESKTOP_DEFAULT)
            .expect("seal should succeed");
        let opened = vault.open("a-password").expect("open should succeed");

        let debug_output = format!("{opened:?}");
        assert_eq!(debug_output, "DecryptedSecret(<redacted>)");
    }
}
