# PQ Phase 1 — Ownership-Model Fix (deviation from draft spec v2.4)

Status: **normative for this implementation**, supersedes the draft on the points
below. Decided 2026-06-04. Awaiting external post-quantum crypto sign-off.

## The flaw in the draft

The draft (`Karbowanec_PQ_Proposal_v2.4`, §4 / §6) derives the per-output spend
key entirely from the ML-KEM shared secret `ss`:

```
ss          = ML-KEM.Encaps(view_pub)        // sender side (output creation)
ss          = ML-KEM.Decaps(view_sk, kem_ct) // recipient side (scan/spend)
spend_seed  = HKDF-SHA3-256(ss, "karbo-pq-spend-seed-v1" || out_context)
(pk_i, sk_i)= ML-DSA.KeyGen(xi = spend_seed)
```

A KEM establishes the **same** `ss` for both parties. The **sender runs Encaps
and therefore knows `ss`**. Since `sk_i` is a deterministic function of `ss` and
public data (`out_context`), the sender can reconstruct `sk_i` and **sign a spend
of the output it just created**.

Consequence: every payment is clawable. The sender can race the recipient to
spend received funds at any time before the recipient does. No payment is ever
final. The draft's claim (§7) that "only the holder of `view_sk` can claim
ownership" conflates **scanning** (which needs `view_sk` *or* being the sender)
with **spending** (which here needs only `ss`, held by both). `view_sk` confers
no spending exclusivity, because it is used only to recover the `ss` the sender
already has.

This is unfixable while the structure is preserved: the `spend_commit` is created
by the sender, so the sender must be able to compute the spend public key, so the
sender can compute the secret key. A recipient-only secret must enter the spend
key — but the draft's address holds only the view key, so there is nowhere for
such a secret to live.

## The fix: a long-term ML-DSA-65 spend key

Give each identity a **long-term ML-DSA-65 spend keypair**, derived from the
seed's spend branch (which the draft left "reserved"):

```
spend_seed            = HKDF-SHA3-256(seed_master, salt=0, info="karbo-pq-spend-root-v1", L=32)
(spend_pub, spend_sk) = ML-DSA-65.KeyGen(xi = spend_seed)
```

- `spend_pub` (1952 B) is published **in the address**, alongside the ML-KEM
  `view_pub`. The address checksum covers both keys.
- Output binding becomes `spend_commit = SHA3-256("karbo-pq-spend-commit-v1" ||
  spend_pub || rho)`. The sender knows `spend_pub` (public, from the address) and
  chooses `rho`, so it can still build the output — but it **cannot sign**
  (no `spend_sk`).
- To spend, the owner reveals `auth_pub = spend_pub` and `rho_reveal = rho`, and
  signs the tx digest with `spend_sk`. The sender, lacking `spend_sk`, is
  excluded. ✓
- `nullifier = SHA3-256("karbo-pq-nullifier-v1" || spend_pub || rho)`. `rho` is
  per-output unique, so reusing one spend key across many outputs still yields
  distinct nullifiers; double-spend = reusing the same `(spend_pub, rho)`.

### Properties preserved
- **Receiving private / unspent outputs unlinkable.** The output carries only the
  hash `spend_commit`; `rho` is AEAD-encrypted; `spend_pub` is not on chain until
  a spend. An observer cannot link two unspent outputs to one identity, nor — even
  after a later spend reveals `spend_pub` — link the identity's *other* unspent
  outputs (it would need their secret `rho`).
- **Public spend linkability.** Spends reveal `spend_pub`, so all spends by one
  identity are linkable — exactly the Phase-1 trade-off the draft already accepts
  (§2, §19).
- **Quantum-safe spend authorization** rests on ML-DSA-65, unchanged.

### Costs
- Address grows by 1952 bytes (now `view_pub` 1184 + `spend_pub` 1952).
- The per-output ML-DSA keygen at scan/spend disappears; one long-term key
  instead (simpler and cheaper).
- A single spend key per identity; per-output *spend* unlinkability is not
  provided (would require the Merkle/XMSS one-time-key approach the draft
  deliberately removed — rejected here for its address-exhaustion + state cost).

## Concrete changes vs. draft
- **Address (`PqAddress`)**: add `spendPub` (ML-DSA-65); checksum preimage =
  `version || varint(networkPrefix) || viewPub || spendPub`.
- **Seed chain (`PqSeed`)**: the spend branch is now USED — `deriveSpendSeed` →
  `deriveSpendKeys` (ML-DSA-65). View branch unchanged (L=64; see below).
- **Derivations (`PqDerive`)**: `deriveSpendSeed(ss, out_context)` and the
  `karbo-pq-spend-seed-v1` domain are **removed** (no per-output spend key).
  `spend_commit` / `nullifier` now bind the long-term `spend_pub`. `aead_key`
  (rho delivery) and all other derivations unchanged.

## Unrelated cemented decision recorded here
- **ML-KEM view seed at L=64.** FIPS 203 ML-KEM.KeyGen consumes 64 bytes (`d||z`);
  the draft's `view_seed` at L=32 is under-specified. We derive `view_seed`
  directly at L=64. (ML-DSA.KeyGen takes a 32-byte `xi`, so the spend branch
  correctly stays L=32.)
