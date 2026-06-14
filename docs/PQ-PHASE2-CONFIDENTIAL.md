# PQ Phase 2+ — Confidential Amounts & Future Unlinkability (design notes)

Status: **design intent / not implemented.** Phase 1 (plain PQ) is what's built
today. This records the agreed direction so the transaction-version ladder and
the wire/consensus shape are reserved correctly. Everything here is gated behind
external parameter + soundness audit before any fork commitment.

## Transaction-version ladder on `dev/pq1` (CT-less branch)

Keep these distinct — do **not** conflate the transaction-version axis with the
block-major-version (activation) axis.

| tx version | meaning | activates at block major | status |
|-----------|---------|---------------------------|--------|
| **v1** | classical CryptoNote (KeyInput/KeyOutput, ring sigs) | v1–v5 | shipped (legacy) |
| **v2** | **PQ plain amounts** — `TX_PQ` / `TX_BRIDGE`, ML-KEM view + ML-DSA spend, plain on-chain amounts | **v6** | **IMPLEMENTED (Phase 1)** |
| **v3** | **PQ confidential amounts** — denomination-bundle hidden values (Idea 2 below) | **v7** | PLANNED (Phase 2) |
| v4 | reserved — possible PQ unlinkability (Idea 1 below) | v8 | SPECULATIVE (Phase 3) |

Rationale for a **new transaction version (v3)** rather than a `txType` under v2:
isolation. v2 stays strictly plain so the hot path never touches commitment /
proof code — the same reasoning the CT line used when it version-bumped instead
of relaxing an existing version. Block major **v7** is already reserved in
`CryptoNoteConfig.h` (`BLOCK_MAJOR_VERSION_7`, comment "reserved for future
CPQ"). The exact v3/v7 binding is finalized when Phase 2 starts; this doc just
reserves the slot so v2 = plain-PQ is never overloaded.

The plain-PQ surface from Phase 1 is **forward-compatible and reused unchanged**
by v3: address format (ML-KEM view + ML-DSA spend), the long-term spend key /
nullifier ownership model (docs/PQ-OWNERSHIP-FIX.md), and the per-output ML-KEM
delivery channel (the reserved `karbo-pq-ct-mask-v1` domain derives commitment
openings from the same KEM session). v3 only swaps `PqOutput`'s plain `amount`
for a committed denomination bundle.

---

## Idea 2 (Phase 2, the priority) — PQ-GK denomination bundles

Hidden amounts that keep the Groth–Kohlweiss "denomination membership" mental
model from CT, upgraded to a fixed-slot hidden vector per output.

- Public denomination set `D = {0, 1e10, 2e10, …, 1e17}`; `K = 8` slots/output.
- Each output commits to `K` denominations (padded with the `0` denomination), so
  observers cannot read how many nonzero digits the amount had — strictly more
  private than one-note-per-denomination.
- **Membership IS the range proof.** Proving each committed value lies in `D`
  (a lattice one-out-of-many proof) inherently bounds it to a non-negative,
  in-range denomination. No generic 64-bit lattice range proof, and no
  "negative mod-q value" inflation attack — every value is provably one of the
  public denominations.

### Commitment + balance
Module-SIS/LWE additive commitment `C = A·r + value·U mod Q` (binding from SIS,
hiding from LWE). Balance is homomorphic:

```
Σ C_in + plain_in·U − Σ C_out − plain_out·U − fee·U = A·r_delta
```

with a short ZK proof that the residual opens to **zero value**. Avoid carry
machinery via either: a modulus `Q` larger than the max possible Σ value (so
modular equality ⇒ integer equality), or a single prime `q` with the sum
provably bounded (`K · max_denom · max_outputs < q`). **Real parameter work**,
not vibes: the modulus must also sit in a lattice-secure regime. The balance +
membership proofs are the **supply-integrity centerpiece** and the audit focus.

### Refinements adopted (vs. the naïve sketch)
1. **One value-commitment per output + one aggregate bundle proof** (the K×|D|
   one-hot matrix proof), rather than K exposed slot-commitments. Balance then
   sums one commitment per output — smaller, simpler balance surface.
2. **Bind `valueCommitRoot` into the ML-DSA signing digest** (and
   `spendCommit = H(spendPub ‖ rho ‖ valueCommitRoot)`), so a relayer cannot
   swap commitments/proofs under a still-valid signature — the same malleability
   lesson applied to the v2 digest (txType/unlockHeight/extra binding).
3. **AEAD-bind the encrypted payload** (`rho` + denomination indexes + openings)
   to `out_context ‖ valueCommitRoot`, so a tampered commitment fails at the
   recipient (mirrors today's amount-binding aad).

### Sketch wire shape (v3 confidential output)
```
struct PqHiddenOutput {
  vector<uint8_t> kemCt;          // ML-KEM ciphertext (unchanged from v2)
  vector<uint8_t> encPayload;     // AEAD(rho + denom indexes + openings)
  Hash            spendCommit;    // H(spendPub || rho || valueCommitRoot)
  PqValueCommit   valueCommit;    // single Module-SIS commitment to the amount
  PqBundleProof   bundleProof;    // one-out-of-many over K denomination slots
};
// tx body also carries a PqBalanceProof (residual opens to zero value).
```
Spending, nullifiers, address, and KEM delivery are **identical to v2** — only
the output value representation changes.

### Research basis (concepts, not pinned params)
Lattice confidential transactions (LACT+), lattice RingCT (LRCT v2.0), short
lattice one-out-of-many proofs, the corrector-free balance/range line (Gao
2025), and classical Groth–Kohlweiss as the conceptual ancestor.

---

## Idea 1 (Phase 3, speculative) — Self-IBE lattice stealth + IB-linkable rings

A possible *future* route to **unlinkable** PQ spends (the axis we deprioritized
— "good to have, not critical"). It does **not** hide amounts by itself; it would
compose on top of Idea 2.

- Each wallet is its own identity-based-encryption authority; the address carries
  an IBE master public key.
- Per-output identity `id = H("karbo-pq-output-id" ‖ kemCt ‖ context ‖ output_index)`.
- The **public** spend target for `id` is computable by anyone from `master_pub`
  (sender-computable, like ECC `P = H(rA)G + B`); the **per-output signing
  secret** requires `Extract(master_sk, id)` — recipient-only. This is the true
  PQ analog of the EC stealth homomorphism we lacked: sender creates a public
  target it cannot spend.
- An identity-based **linkable ring signature** over output identities then gives
  sender-ambiguity + a double-spend linking tag (replacing the SHA3 nullifier).

Why it's deferred: lattice IBE (GPV/ABB trapdoor + preimage sampling on every
spend) plus identity-based linkable ring signatures over lattices (Gao-style
logarithmic IB ring sigs / IB dual-ring) are recent, unstandardized, unaudited,
and heavy (large keys, per-spend trapdoor sampling). It targets the lower-priority
axis and is the furthest from shippable — a research bet, recorded so the v4 /
block-v8 slot is reserved for it.

---

## What this means for Phase 1 work
Nothing changes in the v2 implementation. Keep building Phase 1 (account
registry, free-reg, wallet UX, integration). The reservations above ensure v3
(confidential) and v4 (unlinkable) land without overloading v2 or the block
major ladder.
