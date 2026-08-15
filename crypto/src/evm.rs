//! Ethereum-style address derivation and EIP-55 checksum encoding.
//!
//! ## Why `Keccak256` and not `Sha3_256`
//!
//! Ethereum's address/hash function is the *original* Keccak submission's
//! padding, not the NIST-finalized SHA3-256 (NIST changed the padding byte
//! during standardization, after Ethereum had already shipped). They produce
//! **different digests for the same input**. This is a well-known footgun:
//! using the wrong one silently produces a wrong-but-valid-looking address.
//! The `sha3` crate (RustCrypto) exports both as distinct types —
//! `Keccak256` (what we use here) and `Sha3_256` (NIST-final, do not use for
//! Ethereum) — specifically because of this history.
//!
//! ## Address derivation rule
//!
//! `address = last 20 bytes of Keccak256(X || Y)`, where `X || Y` is the
//! *uncompressed* secp256k1 public key point's 64 coordinate bytes, with the
//! leading `0x04` SEC1 tag byte stripped before hashing. This is the rule
//! specified in the Ethereum Yellow Paper and implemented identically by
//! go-ethereum, ethers-rs/alloy, and every other conformant client.
//!
//! ## EIP-55 mixed-case checksum
//!
//! Purely a display/typo-detection convention layered on top of the address
//! above — it does not change which address a checksummed string refers to.
//! Implemented here per the EIP-55 reference algorithm at
//! <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md>, and tested
//! against that spec's own published test vectors (see tests below) rather
//! than a vector I generated myself, so the test is a genuine external check.

use sha3::{Digest, Keccak256};

/// A 20-byte Ethereum-style address, valid across every EVM-compatible
/// network under this crate's derivation policy (see `derivation.rs`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address([u8; 20]);

/// Errors constructing an [`Address`] from an untrusted public-key encoding.
#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    /// The supplied bytes were not a valid secp256k1 public-key encoding.
    #[error("invalid public key encoding")]
    InvalidPublicKey,
}

impl Address {
    /// Core address derivation: given the 64-byte uncompressed secp256k1
    /// public-key point (`X || Y`, no leading `0x04` tag byte), compute the
    /// Ethereum-style address. This is the fully independent, spec-checked
    /// core of this module — everything else in this file is either display
    /// formatting (EIP-55) or plumbing to get here from a key type.
    pub fn from_uncompressed_xy(xy: &[u8; 64]) -> Self {
        let hash = Keccak256::digest(xy);
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);
        Self(address_bytes)
    }

    /// Adapter from a `k256` signing key (as held by [`crate::derivation::EvmAccountKey`])
    /// to an address: derive the verifying (public) key, take its
    /// uncompressed SEC1 encoding, strip the tag byte, and hash.
    pub fn from_signing_key(signing_key: &k256::ecdsa::SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false); // false = uncompressed
        let bytes = encoded_point.as_bytes(); // 65 bytes: 0x04 || X(32) || Y(32)
        let mut xy = [0u8; 64];
        xy.copy_from_slice(&bytes[1..65]);
        Self::from_uncompressed_xy(&xy)
    }

    /// Raw 20 address bytes.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// EIP-55 mixed-case checksummed hex string, with `0x` prefix.
    pub fn to_checksummed_hex(&self) -> String {
        let lower_hex: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        let hash = Keccak256::digest(lower_hex.as_bytes());

        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (i, c) in lower_hex.chars().enumerate() {
            if c.is_ascii_digit() {
                out.push(c);
                continue;
            }
            // Nibble i of the hash: even i -> high nibble, odd i -> low nibble.
            let hash_byte = hash[i / 2];
            let nibble = if i % 2 == 0 { hash_byte >> 4 } else { hash_byte & 0x0f };
            if nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
        }
        out
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_checksummed_hex())
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Addresses are NOT secret — unlike mnemonic.rs/derivation.rs, a
        // normal Debug impl here is fine and useful for logs/diagnostics.
        write!(f, "Address({})", self.to_checksummed_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EIP-55's own published test vectors, taken directly from the
    /// reference Python implementation in the EIP-55 spec itself:
    /// <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md>
    /// This is an external, spec-sourced check — not a vector generated by
    /// the code under test, which is the only kind of test that actually
    /// catches an implementation bug rather than just confirming the code
    /// agrees with itself.
    #[test]
    fn eip55_official_test_vectors() {
        let vectors = [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ];

        for expected_checksummed in vectors {
            let hex_no_prefix = &expected_checksummed[2..];
            let mut bytes = [0u8; 20];
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex_no_prefix[i * 2..i * 2 + 2], 16)
                    .expect("test vector hex must be well-formed");
            }
            let address = Address(bytes);
            assert_eq!(
                address.to_checksummed_hex(),
                expected_checksummed,
                "EIP-55 checksum mismatch for {expected_checksummed}"
            );
        }
    }

    #[test]
    fn checksum_only_changes_letter_casing_never_digits_or_length() {
        let address = Address([0xAB; 20]);
        let checksummed = address.to_checksummed_hex();
        assert_eq!(checksummed.len(), 42); // "0x" + 40 hex chars
        assert!(checksummed.to_lowercase().starts_with("0xabababab"));
    }

    #[test]
    fn same_key_material_always_derives_same_address() {
        let xy = [0x42u8; 64];
        let a1 = Address::from_uncompressed_xy(&xy);
        let a2 = Address::from_uncompressed_xy(&xy);
        assert_eq!(a1, a2);
    }

    #[test]
    fn different_key_material_derives_different_addresses() {
        let a1 = Address::from_uncompressed_xy(&[0x11u8; 64]);
        let a2 = Address::from_uncompressed_xy(&[0x22u8; 64]);
        assert_ne!(a1, a2);
    }
}
