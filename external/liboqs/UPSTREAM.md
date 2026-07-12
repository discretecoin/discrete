# liboqs vendored snapshot

Upstream: https://github.com/open-quantum-safe/liboqs
Tag: 0.13.0
Commit: 21b3f8b0fadbb19e2c6a5df0f165c953ead164e1

This is a pruned source-only snapshot. The following directories were removed
from the upstream tree because they are unused by Karbo (we only need
ML-KEM-768 and ML-DSA-65):

  src/kem/{bike,classic_mceliece,frodokem,hqc,kyber,ntruprime}
  src/sig/{cross,dilithium,falcon,mayo,sphincs,uov}
  src/sig_stfl/{lms,xmss}
  tests/, docs/, cpp/, zephyr/, scripts/
  flake.lock, flake.nix

`src/sig_stfl/sig_stfl.{c,h}` is retained because liboqs unconditionally links
it (the file holds the stateful-signature API surface and is referenced by
`src/oqs.h`); with both XMSS and LMS disabled it compiles to a no-op shim.

To refresh from upstream:
  1. git clone --branch <new-tag> https://github.com/open-quantum-safe/liboqs <tmp>
  2. rm -rf the directories listed above from <tmp>
  3. Replace external/liboqs/ with <tmp>/, preserving this UPSTREAM.md.
  4. Re-apply the Karbo PQ patches listed below.
  5. Update the Tag and Commit lines above.

## Karbo PQ patches

These are local deltas required by Karbo PQ Phase 1 (transaction version 3).
Each is a small, surgical addition — no upstream behaviour is changed.

### 1. ML-DSA-65 deterministic keygen — `_keypair_derand`

Files touched:
  - src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/sign.h
  - src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/sign.c
  - src/sig/ml_dsa/sig_ml_dsa.h
  - src/sig/ml_dsa/sig_ml_dsa_65.c

What was added:
  - `crypto_sign_keypair_derand(pk, sk, seed)` in the Dilithium reference
    impl. Identical to `crypto_sign_keypair` except `seedbuf` is sourced
    from a caller-supplied 32-byte seed instead of `randombytes`.
  - `OQS_SIG_ml_dsa_65_keypair_derand(pk, sk, seed)` thin wrapper plus the
    `OQS_SIG_ml_dsa_65_length_keypair_seed = 32` constant.

Why: the wallet's long-term ML-DSA-65 spend keypair is derived
deterministically from `spend_seed = HKDF(seed_master,
"discrete-pq-spend-root-v1", L=32)` (PqSeed.h; see docs/PQ-OWNERSHIP-FIX.md).
Without a derand keygen, the same spend key cannot be re-derived on demand
(wallet recovery from the seed). Upstream liboqs only ships the `_derand`
variant for ML-KEM, not ML-DSA, hence the patch.

Upstream tracking: open-quantum-safe/liboqs#2128 covers a similar request.
If upstream ships an equivalent API, drop our patch in favour of it.

### 2. ML-KEM-768 explicit-message encapsulation — `_encaps_derand`

Files touched:
  - src/kem/ml_kem/kem_ml_kem.h
  - src/kem/ml_kem/kem_ml_kem_768.c

What was added:
  - `OQS_KEM_ml_kem_768_encaps_derand(ct, ss, pk, coins)`, a narrow public
    wrapper over mlkem-native's reentrant `Encaps_Internal` entry point.
  - The wrapper deliberately calls the always-built portable C backend on all
    architectures. It preserves mlkem-native's public-key modulus check and
    cleanses ciphertext/shared-secret outputs before returning an error.

Why: payer payment proofs retain the fresh 32-byte ML-KEM message used for each
output and later re-encapsulate without changing process-global OQS RNG state.
This application interface is deliberately outside strict FIPS 203 conformance;
see docs/PQ-PAYMENT-PROOF.md for the specialist-review gate.
