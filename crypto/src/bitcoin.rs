//! Bitcoin key derivation (BIP-32/BIP-84) and native SegWit (P2WPKH) address
//! encoding.
//!
//! ## Why this reuses `derivation.rs`'s machinery, unlike `solana.rs`
//!
//! Bitcoin uses secp256k1 and plain BIP-32 — the exact same curve and
//! derivation algorithm `derivation.rs` already implements for EVM chains,
//! just a different path prefix. This is a fundamentally different
//! situation from Solana (ed25519, SLIP-10, a different derivation
//! algorithm entirely — see `solana.rs`'s own module doc comment on why
//! that module is independent of this one). Here, reusing the same
//! `bip32`/`k256` machinery — rather than re-deriving a parallel, redundant
//! implementation of the identical algorithm — is the more honest design:
//! this module shares [`crate::derivation::DerivationError`] rather than
//! defining its own, because the failure modes genuinely are the same
//! (same crate, same hardened-boundary math, same "seed failed to produce
//! a master key" case).
//!
//! What Bitcoin actually needs of its own: a different derivation path
//! (BIP-84, not BIP-44), and an entirely different address encoding — an
//! EVM address is `Keccak256(pubkey point)[12..]`; a native SegWit Bitcoin
//! address is `bech32(witness_version=0, RIPEMD160(SHA256(compressed
//! pubkey)))`. That encoding is this module's real, non-shared content.
//!
//! ## Derivation path: BIP-84 (native SegWit), not BIP-44 or BIP-49
//!
//! `m/84'/0'/0'/0/{index}` — BIP-84 is the modern default most wallets
//! (Sparrow, Electrum's "native segwit" mode, and others) now use for new
//! wallets, producing `bc1...` addresses (P2WPKH) rather than the legacy
//! `1...` (P2PKH, BIP-44) or `3...` (P2SH-wrapped SegWit, BIP-49) formats.
//! `coin_type 0` is Bitcoin's registered SLIP-44 value
//! (<https://github.com/satoshilabs/slips/blob/master/slip-0044.md>).
//! Account and change are fixed at `0'`/`0` respectively, matching this
//! crate's existing EVM policy of one account tree per "Account N" the UI
//! exposes, not a deeper multi-account-per-chain hierarchy.
//!
//! This path was cross-checked against Sparrow before being trusted — see
//! the project notes on the cross-wallet verification for this phase.

use crate::derivation::DerivationError;
use crate::mnemonic::Seed;
use bip32::{DerivationPath, XPrv};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::str::FromStr;

/// The BIP-32 hardened-index boundary, same constant and meaning as
/// `derivation.rs`'s own — duplicated rather than imported across that
/// module boundary for the same reason `solana.rs` duplicates it: not
/// worth coupling two otherwise-independent chain modules over one shared
/// literal.
const HARDENED_OFFSET: u32 = 0x8000_0000;

/// BIP-84 path prefix: `purpose' / coin_type' / account' / change`, with
/// `account` fixed at `0'` and `change` fixed at `0` (external/receiving
/// chain, not the internal change chain) — see this module's own doc
/// comment for why.
const BITCOIN_PATH_PREFIX: &str = "m/84'/0'/0'/0";

/// A derived secp256k1 signing key for one Bitcoin account, with its
/// native SegWit (P2WPKH) address. Mirrors [`crate::derivation::EvmAccountKey`]'s
/// shape and scope deliberately: derivation and address encoding only, no
/// signing/transaction-construction method here yet — that's a later,
/// separately-reviewed phase (UTXO handling and transaction construction
/// are a materially bigger surface than EVM's or Solana's signing ever
/// was, and are explicitly out of scope for this phase).
pub struct BitcoinAccountKey {
    xprv: XPrv,
}

impl std::fmt::Debug for BitcoinAccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BitcoinAccountKey(<redacted>)")
    }
}

impl BitcoinAccountKey {
    /// Derive Bitcoin account `index` (the BIP-84 `address_index` level,
    /// non-hardened) from a BIP-39 seed. Multiple "accounts" in the wallet
    /// UI are modeled as increasing `index` here, the same convention
    /// [`crate::derivation::EvmAccountKey::derive`] uses.
    pub fn derive(seed: &Seed, index: u32) -> Result<Self, DerivationError> {
        // Same reasoning as EvmAccountKey::derive: reject the hardened
        // range before it reaches the path string, where the parser would
        // otherwise silently reinterpret it as a *hardened* index.
        if index >= HARDENED_OFFSET {
            return Err(DerivationError::IndexOutOfRange);
        }

        let path_string = format!("{BITCOIN_PATH_PREFIX}/{index}");
        let path = DerivationPath::from_str(&path_string).map_err(|_| DerivationError::InvalidPath)?;

        let master = XPrv::new(&seed.0).map_err(|_| DerivationError::MasterKeyDerivation)?;
        let xprv = path
            .iter()
            .try_fold(master, |key, child_number| key.derive_child(child_number))
            .map_err(|_| DerivationError::ChildDerivation)?;

        Ok(Self { xprv })
    }

    /// This account's native SegWit (P2WPKH, BIP-84) mainnet address —
    /// `bc1...`. Construction, step by step, each step named explicitly
    /// rather than folded into one opaque expression, since a mistake in
    /// any single step here silently produces a wrong-but-valid-looking
    /// address:
    ///
    /// 1. The COMPRESSED (33-byte, `0x02`/`0x03`-prefixed) SEC1 encoding
    ///    of the public key — NOT the uncompressed 65-byte encoding EVM's
    ///    address derivation starts from (see `evm.rs`). Using the
    ///    uncompressed point here would silently produce an address for a
    ///    public key no wallet derived from this same seed would ever
    ///    recognize as its own.
    /// 2. HASH160 = RIPEMD160(SHA256(compressed pubkey)) — Bitcoin's
    ///    standard pubkey-hash construction, the same one every address
    ///    type (P2PKH, P2SH, P2WPKH) builds on.
    /// 3. Bech32-encode HASH160 as a witness version 0 program, human-
    ///    readable part `"bc"` (mainnet) — `bech32::segwit::encode`
    ///    handles the BIP-173 (not BIP-350/bech32m; that's witness
    ///    version 1+, Taproot) checksum choice internally based on the
    ///    witness version passed in.
    pub fn address(&self) -> String {
        let verifying_key = self.xprv.private_key().verifying_key();
        let compressed_pubkey = verifying_key.to_encoded_point(true);

        let sha256_digest = Sha256::digest(compressed_pubkey.as_bytes());
        let hash160 = Ripemd160::digest(sha256_digest);

        bech32::segwit::encode(bech32::hrp::BC, bech32::segwit::VERSION_0, &hash160)
            .expect("a 20-byte witness version 0 program is always valid to encode")
    }

    /// Expose the underlying secp256k1 signing key for the duration of
    /// `f`. Deliberately shares the `expose_secret` name with every other
    /// `expose_secret` in this crate — see
    /// [`crate::derivation::EvmAccountKey::expose_secret`]'s doc comment
    /// for why (one `grep -r expose_secret` finds every site that touches
    /// raw secret material).
    ///
    /// Signing itself is deliberately NOT implemented in this crate —
    /// Bitcoin transaction construction (input/output selection, sighash
    /// computation, witness serialization) is out of scope for this
    /// phase, and belongs with an audited library when it's built, not
    /// hand-rolled here.
    pub fn expose_secret<R>(&self, f: impl FnOnce(&k256::ecdsa::SigningKey) -> R) -> R {
        f(self.xprv.private_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::SecretMnemonic;

    /// BIP-84's own official test vector
    /// (<https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki>,
    /// "Test vectors" section): the standard 12-word all-zero-entropy
    /// mnemonic, no passphrase, addresses at the first external and change
    /// paths. NOT trusted from that single scraped page -- independently
    /// re-derived from scratch during this module's development using
    /// Python's stdlib hmac/hashlib for the BIP-32 math (via the `ecdsa`
    /// PyPI package for the secp256k1 point arithmetic) and the `bech32`
    /// PyPI package for the address encoding, reproducing these exact
    /// addresses byte-for-byte before they were hard-coded here -- same
    /// discipline as the SLIP-10 vector verification for Solana, which
    /// caught a transcription error last time this exact "verify
    /// independently, don't trust a single source" step was skipped.
    #[test]
    fn bip84_official_test_vector() {
        let mnemonic = SecretMnemonic::import(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .expect("valid BIP-39 mnemonic");
        let seed = mnemonic.to_seed("");

        let account0 = BitcoinAccountKey::derive(&seed, 0).expect("derive account 0");
        assert_eq!(account0.address(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");

        let account1 = BitcoinAccountKey::derive(&seed, 1).expect("derive account 1");
        assert_eq!(account1.address(), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    }

    #[test]
    fn derivation_is_deterministic() {
        let entropy = [0x11u8; 32];
        let seed = SecretMnemonic::from_entropy_for_testing(&entropy)
            .expect("valid entropy")
            .to_seed("");

        let key_a = BitcoinAccountKey::derive(&seed, 0).expect("derivation should succeed");
        let key_b = BitcoinAccountKey::derive(&seed, 0).expect("derivation should succeed");
        assert_eq!(key_a.address(), key_b.address());
    }

    #[test]
    fn different_account_indexes_produce_different_addresses() {
        let entropy = [0x22u8; 32];
        let seed = SecretMnemonic::from_entropy_for_testing(&entropy)
            .expect("valid entropy")
            .to_seed("");

        let account_0 = BitcoinAccountKey::derive(&seed, 0).expect("derivation should succeed");
        let account_1 = BitcoinAccountKey::derive(&seed, 1).expect("derivation should succeed");
        assert_ne!(account_0.address(), account_1.address());
    }

    #[test]
    fn different_seeds_produce_different_addresses() {
        let seed_a = SecretMnemonic::from_entropy_for_testing(&[0x33u8; 32])
            .expect("valid entropy")
            .to_seed("");
        let seed_b = SecretMnemonic::from_entropy_for_testing(&[0x44u8; 32])
            .expect("valid entropy")
            .to_seed("");

        let key_a = BitcoinAccountKey::derive(&seed_a, 0).expect("derivation should succeed");
        let key_b = BitcoinAccountKey::derive(&seed_b, 0).expect("derivation should succeed");
        assert_ne!(key_a.address(), key_b.address());
    }

    #[test]
    fn hardened_range_index_is_rejected() {
        let seed = SecretMnemonic::from_entropy_for_testing(&[0x55u8; 32])
            .expect("valid entropy")
            .to_seed("");

        assert!(BitcoinAccountKey::derive(&seed, HARDENED_OFFSET - 1).is_ok());
        assert!(matches!(
            BitcoinAccountKey::derive(&seed, HARDENED_OFFSET),
            Err(DerivationError::IndexOutOfRange)
        ));
        assert!(matches!(
            BitcoinAccountKey::derive(&seed, u32::MAX),
            Err(DerivationError::IndexOutOfRange)
        ));
    }

    #[test]
    fn addresses_always_start_with_the_native_segwit_mainnet_prefix() {
        let seed = SecretMnemonic::from_entropy_for_testing(&[0x66u8; 32])
            .expect("valid entropy")
            .to_seed("");
        let account = BitcoinAccountKey::derive(&seed, 0).expect("derivation should succeed");
        assert!(
            account.address().starts_with("bc1q"),
            "expected a native SegWit v0 (P2WPKH) mainnet address, got: {}",
            account.address()
        );
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let seed = SecretMnemonic::from_entropy_for_testing(&[0x77u8; 32])
            .expect("valid entropy")
            .to_seed("");
        let key = BitcoinAccountKey::derive(&seed, 0).expect("derivation should succeed");
        assert_eq!(format!("{key:?}"), "BitcoinAccountKey(<redacted>)");
    }
}
