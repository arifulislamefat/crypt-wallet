//! `cryptwallet-crypto` — Phase 1 of Crypt Wallet's core.
//!
//! Scope of this crate, deliberately narrow: BIP-39 mnemonic generation and
//! import, BIP-32/44 hierarchical derivation, and EVM address derivation.
//!
//! Explicitly OUT of scope for this crate (by design, not oversight):
//! - Transaction construction or signing (comes in a later phase, once this
//!   module has been reviewed — signing reuses the keys derived here).
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

pub mod derivation;
pub mod evm;
pub mod mnemonic;

pub use derivation::{DerivationError, EvmAccountKey};
pub use evm::Address;
pub use mnemonic::{MnemonicError, Seed, SecretMnemonic, WordCount};
