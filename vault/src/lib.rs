//! `cryptwallet-vault` — Phase 2 of Crypt Wallet's core.
//!
//! Scope: password-based encrypted-at-rest storage for arbitrary secret
//! byte material (a BIP-39 seed, a raw private key, anything else Phase 1
//! or a later chain module produces), using Argon2id key derivation and
//! XChaCha20-Poly1305 authenticated encryption.
//!
//! Explicitly OUT of scope for this crate (by design):
//! - Filesystem or platform-keystore I/O — see `vault.rs`'s module doc for
//!   why that boundary matters.
//! - Any coupling to the `crypto` crate's types (`Seed`, `SecretMnemonic`).
//!   This crate operates on plain `&[u8]` so it stays independently
//!   testable and reusable; wiring "seal a `Seed`" together is a caller
//!   concern, likely in the platform integration layer built in a later
//!   phase.
//!
//! Same secret-handling conventions as Phase 1's `crypto` crate: every type
//! that can hold decrypted secret material is `ZeroizeOnDrop` with a
//! hand-written `Debug` that redacts instead of printing real bytes.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod params;
pub mod vault;

pub use params::KdfParams;
pub use vault::{DecryptedSecret, SealedVault, VaultError};
