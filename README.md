# Crypt Wallet — core crates

## Status

**Phase 1 (`crypto`): DONE, actually verified — not just written.** Builds
clean, all 17 tests pass, and EVM derivation was independently cross-checked
against MetaMask using a throwaway test mnemonic (address matched exactly).
This is the gate that matters most for a wallet, and it passed.

**Phase 2 (`vault`): delivered, NOT yet verified.** Written with the same
rigor as Phase 1 — real crate APIs confirmed against docs.rs where possible,
security decisions documented inline — but, same honest caveat as before,
**not compiled in the environment this was written in.** Run the build/test
checklist below before trusting it.

---

## Phase 1 — `crypto` crate

Mnemonic generation/import + BIP-32/44 derivation for one chain family (EVM),
with the official BIP-39 test vector suite passing, per the Phase 1 gate you
set.

## What this is, and isn't

**Is:** the key-derivation core — mnemonic → seed → EVM private key → address.
No signing, no storage, no networking. That's intentional scope for Phase 1
(see `src/lib.rs`'s module doc comment) and matches the roadmap: this module
gets reviewed before signing code is built on top of it.

**Isn't:** compiled or run in the environment this was written in. That
environment has no Rust toolchain and no network access to fetch crates from
crates.io — I checked both before writing this note, rather than assume. What
that means concretely:

- Every fact I could verify **without** compiling — the SLIP-44 coin type
  registry, the `bip39` crate's public API (confirmed against its docs.rs
  page for the exact pinned-version method signatures), the BIP-39 seed test
  vector (independently re-derived with Python's stdlib PBKDF2 during
  writing, not just copied from one source), and the EIP-55 checksum test
  vectors (pulled directly from the EIP-55 spec's own reference
  implementation) — **is verified**, not guessed.
- The handful of spots where I'm relying on the `bip32` crate's method names
  from documentation rather than a compiler (`XPrv::new`, `.derive_path`,
  `.private_key()`) are marked `VERIFY ON BUILD` in the code comments right
  at the call site. If any of these are slightly off, Rust's compiler will
  say so immediately and specifically — that's a fast, safe class of failure
  compared to, say, a wrong derivation path silently producing a different
  valid-looking address, which is why the effort in this delivery went into
  verifying the latter category, not the former.

## Before you (or an auditor) trust this module

1. `cd crypto && cargo build` — resolve real dependency versions, fix any
   method-name mismatches flagged above (should be small, obvious diffs).
2. `cargo test` — confirms the BIP-39 vector, the EIP-55 vectors, and the
   determinism/uniqueness property tests all pass.
3. **Add an independently cross-checked seed→address vector.** I deliberately
   did *not* hard-code a "this seed derives this Ethereum address" test,
   because I have no way to independently verify one in this environment
   (no way to run a second reference implementation to cross-check against).
   Generate one test mnemonic, derive `m/44'/60'/0'/0/0` with this code,
   and independently confirm the resulting address against a second,
   trusted implementation (e.g. import the same test-only phrase into
   MetaMask or run it through `ethers.js`'s `Mnemonic`/`HDNodeWallet`) before
   this module is considered validated. This is the single most important
   remaining check before Phase 1 is actually "done," not just "written."
4. `cargo audit` / `cargo deny check` once `Cargo.lock` exists, per the
   dependency-hygiene requirement in the architecture spec.

## Security decisions made in this module (why, not just what)

- **`OsRng` is constructed inside `SecretMnemonic::generate`, not accepted as
  a parameter.** A more "flexible" API would take `impl RngCore`. Narrower
  was the deliberate choice: it's structurally impossible for any caller,
  now or after a future refactor, to accidentally wire in a non-cryptographic
  RNG. The only way to get a non-random mnemonic anywhere in this crate is
  through `from_entropy_for_testing`, which is `#[cfg(test)]`-gated and does
  not exist in a release build.
- **Every secret-holding type (`SecretMnemonic`, `Seed`, `EvmAccountKey`) is
  `ZeroizeOnDrop` and has a hand-written `Debug` that prints `<redacted>`.**
  The most common real-world way wallets have leaked secrets isn't a
  sophisticated attack — it's a developer's `println!("{:?}", key)` or a
  logging framework that captures `Debug` output ending up in a shared log.
  Making the redaction the *only* thing `{:?}` can print removes that failure
  mode structurally rather than relying on every future contributor
  remembering not to log secrets.
- **Error enums never carry the invalid input.** `MnemonicError::InvalidMnemonic`
  doesn't say *which* word was bad or *why* — both because that's a
  (small) oracle for an attacker probing checksum validity, and because
  it closes off the possibility of a bad phrase fragment ending up in an
  error string that gets logged.
- **This crate has no `std::fs`, `std::net`, or logging dependency at all.**
  Not a convention — a structural property you (or an auditor) can check by
  reading `Cargo.toml`: there is no dependency in this crate's tree capable
  of writing to disk or a socket. A future PR that adds one to this specific
  crate should be an immediate review flag.
- **EVM chains share one derivation path family (`coin_type 60`), not one
  path per chain.** Per the architecture spec's flagged decision §D.2.1 —
  documented again at the top of `derivation.rs` since it's exactly the kind
  of decision that should be re-legible from the code itself, not just a
  chat message.

## Scoped hostile review (Phase 1 only — a preview of the full Section 10 pass)

Applying your "pretend you're an attacker" instruction narrowly to what
actually exists yet, ranked CRITICAL/HIGH/MEDIUM/LOW:

| Finding | Rank | Note |
|---|---|---|
| No seed→address vector cross-checked against an independent implementation | **HIGH** | Called out in the checklist above. Until this is done, a subtle derivation bug (wrong path math, off-by-one in hardened-index encoding, etc.) could silently produce wrong-but-valid addresses. This is the single highest-priority gap in Phase 1 right now. |
| `reveal()` returns a plain `String`, not a zeroizing wrapper | **MEDIUM** | Documented as a known gap in the doc comment. The UI layer must immediately wrap it; until that's built and reviewed, treat the phrase as living slightly longer in memory than the rest of this module's design intends. |
| No constant-time guarantees asserted for the derivation/hashing path | **LOW** | `k256` and `sha3` are both designed with side-channel resistance in mind for their core operations, but this hasn't been independently verified here, and side-channel analysis is generally a job for the external audit (§K, Phase 9), not something to assert from a code review alone. |
| Code has not been compiled or executed in this session | **note, not a ranked finding** | Repeating this plainly rather than letting it hide in a caveat: nothing here should be treated as "working" until you've run `cargo build && cargo test` yourself and it passes. |

No CRITICAL findings at this stage — but that reflects the *narrow* scope of
what exists (no signing, no storage, no networking yet), not a claim about
the eventual full application. Please don't read "no CRITICAL findings in a
200-line derivation module" as "the wallet is secure" — it isn't a claim I'm
making, and it shouldn't be read as one.

---

## Phase 2 — `vault` crate

Password-based encrypted-at-rest storage: Argon2id key derivation +
XChaCha20-Poly1305 authenticated encryption, per §D.3 of the architecture
spec. Deliberately decoupled from `crypto`'s types (`Seed`, `SecretMnemonic`)
— this crate seals/opens plain `&[u8]`, so it stays independently testable;
wiring "seal a `Seed`" together is a platform-integration-layer concern for
a later phase.

### Build/test checklist (same process as Phase 1)

1. `cd vault && cargo build` (or `cargo build --workspace` from the repo
   root, now that there are two crates) — this pulls in `argon2` and
   `chacha20poly1305` for the first time and will surface any issues with
   the two spots marked `VERIFY ON BUILD` in `vault.rs`:
   - `Argon2::new(Algorithm::Argon2id, Version::V0x13, params)` /
     `argon2::Params::new(...)` — the KDF constructor
   - `chacha20poly1305::Key::from_slice(...)` / `XNonce::from_slice(...)` —
     wrapping raw bytes into the types the cipher API expects
2. `cargo test --workspace` — 10 tests, including two I'd flag as most
   important to see pass:
   - `tampered_ciphertext_is_rejected` / `tampered_salt_is_rejected` — proves
     the vault fails closed on tampered data, not just wrong passwords
   - `same_plaintext_and_password_produce_different_ciphertext_each_time` —
     proves salt/nonce are genuinely randomized per call, not reused or
     hardcoded (nonce reuse would be a real vulnerability here, not a
     theoretical one)
3. **No independent cross-check needed for this phase** the way Phase 1
   needed MetaMask — there's no second "reference wallet" to compare an
   encrypted blob against. The tests above (tamper-rejection, non-determinism,
   round-trip, "plaintext never appears in serialized output") are the
   actual verification for this kind of module; a passing suite here carries
   more weight than it did in Phase 1, precisely because there's no external
   oracle to check against.

### Security decisions made in this module

- **KDF parameters are stored per-vault, never hardcoded as one global
  constant** — see `params.rs`'s module doc comment for the two independent
  reasons (platform tuning, forward compatibility if recommended parameters
  change later). `KdfParams::DESKTOP_DEFAULT` is a starting point for desktop
  use, explicitly *not* claimed appropriate for mobile.
- **`hash_password_into` (raw KDF output), not `hash_password` (PHC-string
  password hashing)** — the `argon2` crate's own documentation explicitly
  warns against using the PHC-string API to derive encryption keys. Using
  the wrong one of these two APIs is an easy mistake with a real security
  difference; the choice made here is documented at the call site, not just
  in this README, so it stays visible in the code itself.
- **XChaCha20-Poly1305 (24-byte nonce), not base ChaCha20-Poly1305 (12-byte
  nonce)** — with a 96-bit nonce, generating it randomly on every encryption
  carries meaningful collision risk over many re-encryptions of the same
  vault (e.g. every settings change); XChaCha's 192-bit nonce space makes
  "just randomize it every time" safe without needing persistent nonce-counter
  state, which is a simpler and more failure-resistant design.
- **Wrong password and tampered ciphertext deliberately produce the identical
  error** (`WrongPasswordOrCorrupted`) — distinguishing them would be a (small
  but real) oracle for an attacker, and the correct user-facing message is
  the same either way.
- **`KdfParams::from_bytes` bounds-checks memory/iteration/parallelism** on
  parse, rather than trusting whatever a stored vault file claims — a
  corrupted or maliciously crafted header shouldn't be able to force a
  degenerate (fast/weak) KDF configuration or an absurd memory allocation.

### Scoped hostile review — Phase 2 only

| Finding | Rank | Note |
|---|---|---|
| Not compiled in this session | **note, not ranked** | Same caveat as Phase 1 — run the checklist above before trusting this. |
| No platform keystore integration yet | **expected gap, not a finding** | By design for this phase — see the crate-level doc comment. The output of `SealedVault::to_bytes()` is what a later platform layer should additionally protect with Android Keystore / OS keychain, not a replacement for that layer. |
| `DESKTOP_DEFAULT` params haven't been benchmarked on real hardware | **LOW** | 256 MiB / 3 iterations / 4-way parallelism is a reasonable starting point, not a measured one — worth timing on actual target devices before shipping, since Argon2id's cost should be tuned to a concrete "unlock takes about N milliseconds" target, not just picked. |
| No test exercises the `InvalidParams` path via a genuinely corrupted (not just wrong-version) header | **LOW** | `from_bytes_rejects_truncated_data` and `from_bytes_rejects_unknown_version` exist; a third test tampering specifically with the params bytes (e.g. setting iterations to 0) to confirm `KdfParams::from_bytes`'s bounds-checking actually fires would close this gap — flagging as a good next addition, not a blocker. |

No CRITICAL or HIGH findings — but again, that reflects this module's narrow,
already-well-trodden scope (password-based AEAD is about as standard as
applied cryptography gets), not a claim about the wallet as a whole.

---

## Next step

Once you've run Phase 2's build/test checklist and it's clean, tell me the
results and I'll move to Phase 3 per the roadmap: wiring `crypto` and `vault`
together into an actual Android MVP (create/import wallet, one EVM testnet,
send/receive, Keystore-backed storage, biometric unlock) — the first point
where this stops being two isolated crates and becomes an app.
