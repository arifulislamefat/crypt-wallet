//! BIP-32/44 hierarchical deterministic key derivation.
//!
//! ## Design decision this module encodes (flagged in the architecture spec, §D.2.1)
//!
//! All EVM-compatible chains (Ethereum, and every EVM-compatible network:
//! Polygon, Arbitrum, Optimism, Base, BNB Smart Chain, Avalanche C-Chain,
//! etc.) derive from **one shared path family under `coin_type 60`**
//! (Ethereum's SLIP-44 coin type — see
//! <https://github.com/satoshilabs/slips/blob/master/slip-0044.md>), producing
//! **one address reused across every EVM network**. Chain separation happens
//! at the transaction level via chain ID (EIP-155), not via a different
//! derivation path per EVM chain — even though SLIP-44 technically registers
//! separate coin types for some of them. This matches the "one address, many
//! networks" model users expect from MetaMask, Trust Wallet, and Bitget's
//! own UX, and is what the architecture spec recommended pending your
//! sign-off. If you want per-chain derivation instead, that's a different,
//! also-valid design — tell me and this module changes.
//!
//! Non-EVM chains (Bitcoin, Solana, etc.) are explicitly NOT covered by this
//! module — each needs its own curve (Bitcoin: secp256k1 but different
//! address encodings per BIP-44/49/84/86; Solana: ed25519 via SLIP-0010, a
//! different derivation algorithm entirely, not plain BIP-32) and belongs in
//! its own reviewed module in a later phase, per the roadmap.

use crate::mnemonic::Seed;
use bip32::{DerivationPath, XPrv};
use std::str::FromStr;

/// Errors from key derivation. As with `MnemonicError`, no variant carries
/// key material or seed bytes.
#[derive(Debug, thiserror::Error)]
pub enum DerivationError {
    /// The seed failed to produce a valid BIP-32 master key. Vanishingly
    /// unlikely for a real 64-byte BIP-39 seed (this only happens for
    /// degenerate/invalid-length seed input), but handled explicitly rather
    /// than unwrapped — see the crate-level `#![warn(clippy::unwrap_used)]`.
    #[error("failed to derive master key from seed")]
    MasterKeyDerivation,
    /// The requested derivation path string didn't parse.
    #[error("invalid derivation path")]
    InvalidPath,
    /// Child key derivation failed for the given path/index.
    #[error("child key derivation failed")]
    ChildDerivation,
}

/// BIP-44 path prefix shared by all EVM chains under this crate's derivation
/// policy: `purpose' / coin_type' / account' / change`, with `account` fixed
/// at 0 and `change` fixed at 0 (external chain) for Phase 1. `coin_type 60`
/// is Ethereum's registered SLIP-44 value.
const EVM_PATH_PREFIX: &str = "m/44'/60'/0'/0";

/// A derived secp256k1 signing key for one EVM account.
///
/// Phase 1 deliberately exposes only [`EvmAccountKey::address`] — no
/// signing method yet. Signing is a later, separately-reviewed phase once
/// this derivation module itself has been checked, per the incremental
/// process you asked for.
///
/// No `#[derive(ZeroizeOnDrop)]` here: `bip32::XPrv` (`ExtendedPrivateKey`)
/// doesn't implement `Zeroize` itself, so the derive macro can't verify
/// this struct. That's not a workaround — the private key scalar is still
/// protected one layer down: `xprv`'s inner `k256::ecdsa::SigningKey`
/// implements `ZeroizeOnDrop` on its own, and Rust drops struct fields
/// (including nested ones) automatically regardless of whether the outer
/// struct derives anything, so the actual secret bytes are zeroized when
/// this struct is dropped either way.
///
/// Known Phase 1 gap, accepted rather than silently ignored: `XPrv`'s
/// `attrs` field (chain code, parent fingerprint, depth) is NOT zeroized
/// on drop — bip32 keeps `attrs` private and exposes no way to reach in
/// and clear it. Lower severity than key exposure (chain code alone can't
/// derive private keys — it only enables deriving sibling *public* keys,
/// and only if an attacker also has a parent public key), but it's a real
/// residual gap, not a non-issue.
pub struct EvmAccountKey {
    xprv: XPrv,
}

impl std::fmt::Debug for EvmAccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EvmAccountKey(<redacted>)")
    }
}

impl EvmAccountKey {
    /// Derive EVM account `index` (the BIP-44 `address_index` level) from a
    /// BIP-39 seed. Multiple "accounts" in the wallet UI (Account 1,
    /// Account 2, ...) are modeled as increasing `index` here, which is how
    /// most EVM wallets present multiple accounts from one seed.
    ///
    /// NOTE on this implementation: `XPrv::new` / `.derive_path` are the
    /// method names documented for the `bip32` crate at spec-writing time
    /// (docs.rs/bip32). This has **not been compiled** in the environment
    /// this was written in (no network access to fetch crates), so treat
    /// the exact method names as "verify on first `cargo build`" rather than
    /// guaranteed — a mismatch here is a compile error, not a silent bug,
    /// so it's a safe class of thing to fix iteratively.
    pub fn derive(seed: &Seed, index: u32) -> Result<Self, DerivationError> {
        let path_string = format!("{EVM_PATH_PREFIX}/{index}");
        let path =
            DerivationPath::from_str(&path_string).map_err(|_| DerivationError::InvalidPath)?;

        let master = XPrv::new(&seed.0).map_err(|_| DerivationError::MasterKeyDerivation)?;
        let xprv = path
            .iter()
            .try_fold(master, |key, child_number| key.derive_child(child_number))
            .map_err(|_| DerivationError::ChildDerivation)?;

        Ok(Self { xprv })
    }

    /// The checksummed (EIP-55) Ethereum-style address for this key, valid
    /// across every EVM-compatible network under this crate's derivation
    /// policy (see module-level design-decision note).
    ///
    /// VERIFY ON BUILD: `xprv.private_key()` returning `&k256::ecdsa::SigningKey`
    /// is the accessor the `bip32` crate is documented to expose for the
    /// `secp256k1` feature at spec-writing time, but — same caveat as
    /// `derive()` above — this line specifically should be the first place
    /// you look if `cargo build` reports a missing-method error here.
    pub fn address(&self) -> crate::evm::Address {
        let signing_key: &k256::ecdsa::SigningKey = self.xprv.private_key();
        crate::evm::Address::from_signing_key(signing_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::SecretMnemonic;

    #[test]
    fn derivation_is_deterministic() {
        let entropy = [0x11u8; 32];
        let seed = SecretMnemonic::from_entropy_for_testing(&entropy)
            .expect("valid entropy")
            .to_seed("");

        let key_a = EvmAccountKey::derive(&seed, 0).expect("derivation should succeed");
        let key_b = EvmAccountKey::derive(&seed, 0).expect("derivation should succeed");

        // Same seed + same path must always produce the same address. This
        // is the property the whole recovery-from-phrase feature depends on
        // — if it ever fails, "restore my wallet" silently produces the
        // wrong addresses, which is a fund-loss-adjacent bug class.
        assert_eq!(key_a.address(), key_b.address());
    }

    #[test]
    fn different_account_indexes_produce_different_addresses() {
        let entropy = [0x22u8; 32];
        let seed = SecretMnemonic::from_entropy_for_testing(&entropy)
            .expect("valid entropy")
            .to_seed("");

        let account_0 = EvmAccountKey::derive(&seed, 0).expect("derivation should succeed");
        let account_1 = EvmAccountKey::derive(&seed, 1).expect("derivation should succeed");

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

        let key_a = EvmAccountKey::derive(&seed_a, 0).expect("derivation should succeed");
        let key_b = EvmAccountKey::derive(&seed_b, 0).expect("derivation should succeed");

        assert_ne!(key_a.address(), key_b.address());
    }

    // Deliberately NOT included here: a hard-coded "seed X derives address Y"
    // vector. I have not independently verified such a vector against a
    // second, independent implementation (e.g. ethers.js / MetaMask) inside
    // this environment, and asserting one without that cross-check would be
    // exactly the kind of unverified claim the project brief told me not to
    // guess on. Before Phase 1 is considered "done," add this test using a
    // vector you (or I, with search/tooling in a follow-up) have
    // cross-checked against an independent reference wallet — this is called
    // out explicitly in the README's "before you trust this" checklist.
}
