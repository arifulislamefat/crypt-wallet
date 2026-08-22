//! `cryptwallet-crypto` — Phase 1 of Crypt Wallet's core.
//!
//! Scope of this crate, deliberately narrow: BIP-39 mnemonic generation and
//! import, BIP-32/44 hierarchical derivation and EVM address derivation
//! (`derivation.rs`/`evm.rs`), SLIP-10 ed25519 derivation and Solana
//! address derivation (`solana.rs`) — see that module's own doc comment for
//! why it's a genuinely separate algorithm, not a variant of the EVM path —
//! and BIP-32/BIP-84 native SegWit Bitcoin derivation and address
//! derivation (`bitcoin.rs`), which shares its derivation algorithm with
//! EVM (same curve, same BIP-32) but not its address encoding.
//!
//! Explicitly OUT of scope for this crate (by design, not oversight):
//! - Transaction construction, RLP encoding, and the EIP-1559/EIP-2718
//!   signing rules. This crate exposes exactly one seam for signing —
//!   [`EvmAccountKey::expose_secret`], which hands out the raw `k256`
//!   signing key — and stops there. Everything downstream of that (building
//!   the transaction, hashing it per spec, constructing the signed envelope)
//!   lives in `desktop/src-tauri` via the audited `alloy` crate, not here.
//! - Any form of storage, serialization to disk, or networking. This crate
//!   never touches a filesystem, a socket, or a logging framework. That is
//!   a structural security property, not just a convention: there is no
//!   `std::fs`, `std::net`, or logging crate anywhere in this crate's
//!   dependency tree, so it is not merely "unlikely" that a mnemonic leaks
//!   to disk or a log from inside this crate — it is impossible without
//!   modifying this crate's dependencies, which is itself something a
//!   reviewer/CI check should flag (see the dependency-audit note in the
//!   accompanying README).
//!
//! Every public type that can hold secret material (`SecretMnemonic`,
//! `Seed`, `EvmAccountKey`) is `ZeroizeOnDrop` and has a hand-written
//! `Debug` impl that prints a redaction marker instead of the actual bytes,
//! so `{:?}`-ing one of these types into a log line — the single most common
//! real-world way wallets have leaked secrets — prints `<redacted>` instead
//! of key material.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod bitcoin;
pub mod derivation;
pub mod evm;
pub mod mnemonic;
pub mod solana;

pub use bitcoin::BitcoinAccountKey;
pub use derivation::{DerivationError, EvmAccountKey};
pub use evm::Address;
pub use mnemonic::{MnemonicError, Seed, SecretMnemonic, WordCount};
pub use solana::{SolanaAccountKey, SolanaDerivationError};
