# PQ Phase 1 — Wallet Key Roles & View / Tracking Wallets

A PQ identity has **two** independent keypairs, derived deterministically from
the wallet seed (see `src/crypto_pq/PqSeed.h`):

| Key | Primitive | Secret derives from | Public lives in |
|-----|-----------|---------------------|-----------------|
| **view** | ML-KEM-768 | `view_seed = HKDF(seed, "discrete-pq-view-root-v1", L=64)` | the address |
| **spend** | ML-DSA-65 | `spend_seed = HKDF(seed, "discrete-pq-spend-root-v1", L=32)` | the address |

This is the post-quantum analogue of the CryptoNote (view, spend) key pair.
The view key handles *detection and decryption*; the spend key handles
*authorization*. They are separable, which gives three capability tiers.

## Capability tiers

| Tier | Holds | Can do | Cannot do |
|------|-------|--------|-----------|
| **Full wallet** | seed → `viewSk` + `spendSk` (+ both pubs) | scan, compute balance, **spend** | — |
| **View / tracking wallet** | `viewSk` + `spendPub` | scan, compute balance, recognise owned outputs, detect when they are spent | **spend** (no `spendSk`) |
| **Public / address only** | `viewPub` + `spendPub` (the address) | receive (others can pay it) | scan, spend |

### What a view / tracking wallet can do
`PqScanKeys { viewSk, spendPub }` (`src/crypto_pq/PqScan.h`) is exactly the
tracking-wallet credential. With it a holder can:

- **Detect incoming outputs** — `kem_decaps(viewSk, kemCt)` recovers the shared
  secret, the AEAD tag confirms ownership, and `rho` is decrypted.
- **See amounts** — amounts are plain (Phase 1), and the AEAD binds the amount,
  so the tracking wallet reads the exact value of each owned output.
- **Recompute the ownership commitment** — `spendCommit(spendPub, rho)` matches
  the on-chain commit, confirming the output belongs to this identity.
- **Track spend status** — because `nullifier = SHA3(spendPub ‖ rho)` and the
  tracking wallet has both `spendPub` and the recovered `rho`, it can compute
  each owned output's nullifier and watch the chain for it, learning when an
  output is spent — without being able to spend it.

### What it cannot do
Spending requires an ML-DSA signature under `spendSk` (`txSigningDigest` signed
in each `PqInput`). A tracking wallet has only `spendPub`, so it can neither
forge that signature nor derive `spendSk`. This is the same guarantee that
blocks the *sender* from spending (see `docs/PQ-OWNERSHIP-FIX.md`): authority
rests solely on the spend secret.

## Privacy / trust notes
- Handing out `viewSk` is a deliberate disclosure: the recipient learns **which
  outputs are yours and their amounts**, and can correlate them (they hold your
  keys). This is the standard view-key trade-off (as in Monero) — use it for
  auditors, accounting, or watch-only setups you trust.
- **External observers** (without `viewSk`) cannot link unspent outputs: the
  output carries only `SHA3(spendPub ‖ rho)`, `rho` is AEAD-encrypted, and
  `spendPub` is not on chain until a spend. (Spends do reveal `spendPub`, so an
  identity's *spends* are publicly linkable — the accepted Phase-1 trade-off.)
- A tracking wallet never needs and never holds `spendSk`; the full wallet
  re-derives `spendSk` from the seed on demand at spend time and does not
  persist it.

## Code map
- `deriveViewKeys(seed) → (viewPub, viewSk)` and
  `deriveSpendKeys(seed) → (spendPub, spendSk)` — `src/crypto_pq/PqSeed.h`.
- `PqScanKeys { viewSk, spendPub }` + `scanPqOutput/scanPqOutputs` —
  `src/crypto_pq/PqScan.h` (the tracking-wallet scan path).
- Spending (full wallet only) uses `spendSk` to sign `txSigningDigest`
  (`src/crypto_pq/PqDerive.h`) — added in a later session.
