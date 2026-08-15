//! Argon2id cost parameters for the vault's key-derivation step.
//!
//! ## Why these are an explicit, stored value — not a hardcoded constant
//!
//! Two independent reasons:
//!
//! 1. **Platform tuning.** A mobile device and a desktop have very different
//!    safe memory/CPU budgets for a KDF that runs every time the app
//!    unlocks. The architecture spec (§D.3) calls this out explicitly:
//!    "tune, don't copy one config everywhere." This crate deliberately does
//!    NOT hardcode one set of parameters as *the* answer — that decision
//!    belongs to each platform integration layer (Android/Desktop/Extension),
//!    built in a later phase, which knows its own device constraints.
//! 2. **Forward compatibility.** If recommended Argon2 parameters change in
//!    the future (they have, industry-wide, as hardware has gotten faster),
//!    a vault sealed with today's parameters must still be *openable* later
//!    even after the app's default parameters change. That's only possible
//!    if the parameters used are stored alongside the ciphertext, not
//!    assumed. See `VaultParams` in `vault.rs` — every sealed vault carries
//!    its own params so it remains self-describing and decryptable
//!    regardless of what the app's "current default" becomes.

use zeroize::Zeroize;

/// Argon2id cost parameters. `Copy` and not secret — these describe *how
/// hard* the KDF is, not any key material itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB. Argon2's primary defense: forces an attacker
    /// trying many passwords in parallel (e.g. on GPUs/ASICs) to pay this
    /// much memory *per guess*, which is the expensive resource to scale.
    pub memory_kib: u32,
    /// Number of passes over memory.
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
}

impl KdfParams {
    /// A conservative desktop-class default: 256 MiB memory, 3 iterations,
    /// 4-way parallelism. Meaningfully above the OWASP *minimum*
    /// recommendation (19 MiB / 2 iterations, aimed at web login forms
    /// serving many concurrent users cheaply) — deliberately higher here,
    /// because this KDF protects direct access to bearer-asset key material
    /// on a device the user unlocks infrequently, not a login form serving
    /// thousands of requests per second. Cost asymmetry (slow for the
    /// legitimate user who unlocks a few times a day, very expensive for an
    /// attacker brute-forcing offline) is the entire point.
    ///
    /// NOT necessarily appropriate for a memory-constrained mobile device —
    /// see the module doc comment. The Android integration layer (a later
    /// phase) should pick its own tested value, likely lower than this.
    pub const DESKTOP_DEFAULT: Self = Self {
        memory_kib: 256 * 1024, // 256 MiB
        iterations: 3,
        parallelism: 4,
    };

    /// Serialize to a fixed 12-byte representation (three big-endian u32s),
    /// for embedding in a vault's on-disk header.
    pub fn to_bytes(self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.memory_kib.to_be_bytes());
        out[4..8].copy_from_slice(&self.iterations.to_be_bytes());
        out[8..12].copy_from_slice(&self.parallelism.to_be_bytes());
        out
    }

    /// Parse from the 12-byte representation. Bounds-checks against sane
    /// minimums so a corrupted or malicious header can't force, say,
    /// `iterations: 0` (which could produce a weak or degenerate key) or an
    /// absurd memory request that becomes its own denial-of-service vector.
    pub fn from_bytes(bytes: &[u8; 12]) -> Result<Self, super::VaultError> {
        let memory_kib = u32::from_be_bytes(bytes[0..4].try_into().expect("4-byte slice"));
        let iterations = u32::from_be_bytes(bytes[4..8].try_into().expect("4-byte slice"));
        let parallelism = u32::from_be_bytes(bytes[8..12].try_into().expect("4-byte slice"));

        const MIN_MEMORY_KIB: u32 = 8 * 1024; // 8 MiB floor — below this, Argon2id's
                                               // memory-hardness stops meaningfully
                                               // slowing down GPU/ASIC attackers.
        const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024; // 2 GiB ceiling — a sanity bound
                                                       // against a corrupted header
                                                       // triggering a huge allocation.
        if memory_kib < MIN_MEMORY_KIB || memory_kib > MAX_MEMORY_KIB {
            return Err(super::VaultError::InvalidParams);
        }
        if iterations == 0 || iterations > 64 {
            return Err(super::VaultError::InvalidParams);
        }
        if parallelism == 0 || parallelism > 16 {
            return Err(super::VaultError::InvalidParams);
        }

        Ok(Self { memory_kib, iterations, parallelism })
    }
}

// KdfParams holds no secret data (it's cost *parameters*, not key material),
// so it doesn't need ZeroizeOnDrop — but implementing Zeroize costs nothing
// and keeps this type composable with other zeroizing structures without a
// caller having to think about which fields are and aren't sensitive.
impl Zeroize for KdfParams {
    fn zeroize(&mut self) {
        self.memory_kib.zeroize();
        self.iterations.zeroize();
        self.parallelism.zeroize();
    }
}
