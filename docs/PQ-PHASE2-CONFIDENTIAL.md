# PQ Phase 2 Confidential Amounts

Status: design intent only. Discrete ships today as a PQ-from-genesis plain-amount
chain: every non-coinbase transaction is `TX_PQ` or `TX_FREE_REG` under
`TRANSACTION_VERSION_1`.

This note records the preferred direction for a future confidential-amount fork.
No wire field, parameter, proof system, or activation rule in this document is
consensus until it is implemented, audited, and frozen in `https://docs.discrete.cash/#/consensus/pq-wire-format`.

## Direction

The priority is hidden amounts while preserving the current PQ ownership model:

- ML-KEM remains the per-output delivery channel.
- ML-DSA spend authority and nullifier ownership remain the spend model.
- The output amount is replaced by a committed denomination bundle.
- A balance proof shows inputs, outputs, and fee sum to zero value.
- The signing digest binds the value commitment root so relayers cannot swap
  commitments under a valid spend signature.
- The encrypted output payload is authenticated against the output context and
  value commitment root so recipients reject tampered commitments.

## Open Work

The proof system and parameters must be selected before any implementation is
accepted. The audit focus is supply integrity: denomination membership, balance,
overflow bounds, commitment binding, and transaction malleability.

Future unlinkability research is out of scope for this repository until a concrete
post-quantum construction is selected and reviewed.

## Reference Implementation: BTX SMILE2 (reviewed 2026-07-05)

[btxchain/btx](https://github.com/btxchain/btx) (MIT license) is a
Bitcoin-derived post-quantum chain whose shielded pool implements the SMILE
lattice confidential-transaction construction (Lyubashevsky–Nguyen–Seiler,
CRYPTO 2021, eprint 2021/564) end to end in `src/shielded/smile2/`: BDLOP
commitments under one shared randomness, recursive base-32 one-out-of-many
membership, amounts as base-4 digits in NTT slots (range proof folded into
the main proof), carry-polynomial balance, and revealed serial numbers.
Their `doc/btx-smile-implementation-spec.md` is a complete implementation
guide (proof-size formulas, prime-selection criteria, per-component test
specifications), and the SMILE paper text is mirrored in their
`doc/research/`.

BTX is equally valuable as a failure catalog. An external audit found two
critical breaks after launch — nullifiers not cryptographically bound to the
proven spend key (double spend, their C2/C-002) and proofless
transparent-to-shielded pool credits (inflation, their C3) — and the pool
was hardened, then sunset at block 125000 (exit-only since). Measured launch
reality: 1-in/2-out spend = 51 KB proof, 10–22 s prove, ~300 ms verify at
ring size ≤ 32; the large-anonymity-set recursion never shipped in
production.

### Worth borrowing for the hidden-amount fork

- **A licensed cross-validation oracle.** Unlike Abelian `pqringct` (no
  license), BTX is MIT: statement shapes, wire encoders, and the adversarial
  test corpus (`src/test/smile2_*_tests.cpp`: forged serials, recomputed
  Fiat-Shamir seeds, carry forgery, context-binding mismatch, oversized
  shapes) can be ported. Ring parameters differ (their d=128, q=2^32−959
  with 32 degree-4 NTT slots vs the groundwork module's d=256, 48-bit q), so
  scenarios and statements transfer; raw test vectors do not.
- **Proof-size knobs validated at scale:** omit every commitment the
  verifier can reconstruct and bind it with a digest instead (BTX carries
  small residues plus 32-byte binding digests); Dilithium-style low-bit
  compression of the binding commitment rows (their `COMPRESS_D = 12` — a
  knob the groundwork module has not pulled); entropy coding of Gaussian
  responses (~15–20%); the paper's bimodal rejection sampling
  (σ ≈ 0.675·T vs the standard 11·T, ~10x smaller masks; the one-bit leak
  is acceptable for one-time openings).
- **β-ary membership confirmed by measurement.** BTX measured
  Groth–Kohlweiss at ~112 KB for N=2^15 against a ≤20 KB SMILE base-32
  recursion target — direct evidence for the groundwork plan's β-ary
  generalization at large N. SMILE Appendix E plus their `membership.cpp`
  recursion (`ComputeNextP`, garbage-polynomial framework check) are the
  blueprint.
- **Single-commitment amortization.** SMILE places every proof component
  (selectors, amounts, garbage terms) in one commitment opened by one masked
  vector, so proof size grows weakly with inputs (their 1x2 = 51 KB →
  2x4 = 84 KB). This is the blueprint for the planned aggregate bundle
  proof across the K denomination slots.
- **Keep the CRT-large-Q balance design.** BTX's digit/carry balance proof
  produced a real forgery surface (a carry polynomial forged to absorb the
  fee; mandatory carry-validity checks were retrofitted). The
  no-carry CRT-large-Q route eliminates that class entirely.
- **Transcript hygiene checklist:** bind all commitments into the transcript
  before any challenge; add a proof-binding hash H(transcript || z); bind
  the anonymity/context so proofs cannot be replayed across contexts. BTX
  retrofitted all three after launch (their wire v3).
- **Do not copy:** their monomial challenge space (c = ±X^k, ~2^8
  challenges, weak per-round soundness with admittedly untuned rejection
  rules). Use the paper's challenge distribution.

### Design decision: denomination bundles over an integrated range proof (2026-07-05)

The BTX/SMILE amount layer was evaluated as an alternative to denomination
bundles: amounts encoded as 32 base-4 digits in the NTT slot constants
(exact 64-bit values), with digit constraints and a carry polynomial folded
into the single SMILE proof. **Verdict: keep denomination bundles.**

- **No carry surface.** The base-4 encoding needs a carry polynomial to lift
  digit-wise equality mod q to integer equality, and that exact component is
  where BTX's audit trouble concentrated (the C1 inflation-forge claim; the
  mandatory carry-validity checks retrofitted in their wire v3, without
  which a forger absorbs the fee). The CRT-large-Q route deletes the class:
  balance is one zero-opening, and per-slot membership in D bounds every
  committed value. The soundness story fits on a page.
- **Prover stays wallet-friendly.** Denomination membership runs over
  |D| ≈ 8–16 per slot. BTX's folded amount machinery lives inside a proof
  that took 10–22 s to build at ring 32 — prover cost is why their full
  anonymity-set configuration never shipped.
- **Zero migration.** The slot encoding requires X^d+1 to split into
  degree-4 factors (their d=128, q=2^32−959). The groundwork ring (d=256,
  48-bit q, fully splitting) is exactly the incompatible shape their own
  spec §3.1 rules out. Adopting it means a new prime search, new NTT, and
  redone security estimation; denominations build on the module that is
  already green.
- **Matches the chain.** The plain-amount tier already decomposes every
  value through the 64-denomination table; Phase 2 keeps that model and
  hides which denominations. The SMILE encoding would replace the amount
  model entirely.
- **Comparable size anyway.** Their measured 1x2 proof is 51 KB (including
  ring-32 membership); the denomination estimate is 45–65 KB per 1-in/2-out
  with no size knobs pulled yet. Bimodal masking, t0 compression, and
  entropy coding apply to both schemes equally.

**Accepted cost (state in any spec/whitepaper):** quantization. An amount
needing more nonzero digits than K slots must split across outputs, so
output count can correlate with amount complexity — a mild structural leak
the SMILE encoding does not have. Uniform zero-padded K slots hide digit
count within an output; a fixed output-count policy or padding outputs
mitigate the rest.

**Upgrade path if the expressiveness wall is ever hit:** base-β digit
encoding done paper-faithfully — with the mandatory carry-validity checks
BTX learned about in production — priced honestly as a ring-parameter
migration. The piece worth taking from their amount layer regardless is the
amortization architecture (one commitment and one masked opening shared
across the K slot proofs), which is the planned aggregate bundle proof.

### Worth borrowing for the later untraceability fork

Recorded here as reference for the unlinkability stage, which remains out of
scope until a construction is selected:

- **Serial-to-key binding is the #1 consensus test.** BTX shipped serials
  that were not forced to derive from the proven spend key — a critical
  double-spend hole. Fix shape: a mask `w_sn = ⟨b_sn, y0⟩` bound into the
  transcript before the challenge, with the verifier checking
  `⟨b_sn, z0⟩ = w_sn + c0·serial`. The membership statement must force the
  revealed serial to come from the same secret opened in the proof; encode
  this as named adversarial tests (their `f1`–`f5` serial tests are the
  template).
- **Structurally gate every pool-credit path.** Their second critical was a
  proofless mint into the shielded pool. A `pool liability >= 0` invariant
  is necessary but not sufficient: every credit path that is not the
  proof-checked one must be structurally disabled and individually tested.
- **Registry/witness data model.** Consensus state commits the full
  account-leaf payload; the on-wire spend witness stays lean
  (leaf index + leaf commitment + sibling path ≈ 106 bytes in BTX), with
  the proof binding the hidden spender to the public leaf. Light-client
  inclusion proofs measured ~13.5 KB.
- **DoS discipline:** a failed mempool proof must never trigger expensive
  state rebuilds; enforce size and relay-budget caps before running
  verification.
- **Design the emergency brake in from day one:** unshield velocity cap,
  exit-only sunset mode, and a narrow recovery-exit path. BTX needed all
  three under fire; retrofitting them was consensus-critical surgery.
- **Prover-cost reality anchor:** 10–22 s proving at ring ≤ 32 is what kept
  BTX's 2^15 anonymity set from ever shipping. Size the pool window and
  prover budget against measured numbers, not paper targets.
