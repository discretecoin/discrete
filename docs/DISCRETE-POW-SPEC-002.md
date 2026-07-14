# DISCRETE-POW-SPEC-002 — DiscretePower-2: signature-tape proof of work

Status: **DRAFT, revision D** — replaces DiscretePower-1 and all earlier
DiscretePower-2 drafts in the pre-launch reference implementation.

Revision history:

- **rev A — four chained signatures:** rejected. It multiplied block signature
  weight and validation cost for only linear delegation friction.
- **rev B — pre-phase plus deterministic midpoint signature:** rejected. Its
  security claims depended on deterministic ML-DSA signing, which consensus
  cannot distinguish from hedged signing. An adversarial signer could generate
  multiple valid signatures for one message and amortize the pre-phase.
- **rev C — four unmodified yespower calls with signature chunks:** rejected.
  A pool could retain the signature and interactively relay four 64-byte
  yespower inputs and four 32-byte outputs. The construction did not enforce
  transfer of the full signature and multiplied runtime without increasing
  active memory.
- **rev D — this document:** one ML-DSA-65 signature and one modified
  yespower-derived execution. The canonical signature is injected directly
  into the evolving state throughout S-box generation, large-memory filling,
  and read/write mixing.

Supersedes: DiscretePower-1 (`get_block_longhash` in
`src/CryptoNoteCore/CryptoNoteFormatUtils.cpp`, block signature validation in
`src/CryptoNoteCore/Blockchain.cpp`) and DISCRETE-POW-SPEC-002 revisions A–C.
Discrete has not launched; revision D replaces the previous construction in
place with no fork gating or compatibility path. All `DiscretePower/v1/*`
and obsolete revision-C transcript domains are retired.

## 1. Motivation

DiscretePower-1 signs every candidate with ML-DSA-65, hashes the 3,309-byte
signature to a short digest, and feeds that digest to yespower. This binds PoW
to the reward identity but permits cheap remote delegation: a pool can retain
the reward key, sign candidate headers, and transmit only a short digest to
workers.

Revision C attempted to make delegation carry the entire signature by splitting
it into four chunks consumed by four separate yespower calls. That argument
was incomplete. A pool could keep each chunk, receive the preceding yespower
output from a worker, and transmit only the next 64-byte yespower input. Four
stages created an interactive protocol, not a full-signature data requirement.

Revision D removes the fixed compression boundary. The raw canonical
ML-DSA-65 signature is padded to a 3,312-byte tape and consumed as 414
little-endian 64-bit words inside the yespower-derived memory loops. A tape word
is injected before each memory-store or memory-index operation. The tape cycles
throughout the complete memory-hard execution, so a delegating key holder must
choose among:

1. transferring the signature tape, or an equivalent per-candidate
   representation, to the worker;
2. remaining involved as an interactive tape oracle throughout the execution;
3. computing substantially all of the memory-hard work itself.

The construction remains **identity-bound and delegation-hostile**, not
pool-proof. It does not prevent off-chain reward sharing, custodial mining,
local-key farms, or botnets using independent keys.

Block weight remains one ML-DSA-65 signature per block, identical to
DiscretePower-1.

## 2. Design goals

Revision D has the following goals:

- Bind every PoW candidate and coinbase reward to one ML-DSA-65 spend key.
- Require one valid ML-DSA signature for every explored candidate.
- Prevent hedged-signature grinding from reusing memory-hard work.
- Remove any consensus-defined 32-byte or 64-byte summary that substitutes for
  the signature before memory-hard execution.
- Make remote-key delegation carry approximately one canonical signature of
  candidate-specific data, or maintain fine-grained interaction throughout the
  memory-hard execution.
- Preserve stateless block validation and one-signature block weight.
- Remain practical on commodity x86-64 and ARM64 CPUs.

It does **not** claim:

- strong non-outsourceability in the Miller–Kosba–Katz–Shi sense;
- prevention of all pools or variance-sharing arrangements;
- botnet resistance;
- permanent ASIC or FPGA resistance;
- an information-theoretic 3,312-byte lower bound on every possible delegation
  protocol.

## 3. Primitives and notation

- `SHAKE256(m, n)` — SHAKE-256 with `n` output bytes.
- `Sign(sk, m)` / `Verify(pk, m, sig)` — ML-DSA-65. Hedged and deterministic
  signing are both valid; verification is identical. Canonical signature
  length is 3,309 bytes.
- `yespower-dp2(H, P, tape)` — the modified yespower-derived function defined
  in §6. It is based on yespower 1.0 but is a distinct consensus algorithm.
- `LE32(b)` / `LE64(b)` — little-endian decoding.
- `ROTL32(x, n)` — 32-bit left rotation.
- `||` — byte concatenation.
- `u32(x)` — `x` reduced modulo `2^32`.

All domain tags are the exact ASCII bytes shown, without a terminator.

## 4. Consensus constants

```text
DP2_VERSION             = 2
DP2_MLDSA_PARAMETER_SET = ML-DSA-65
DP2_SIG_LEN             = 3309
DP2_TAPE_LEN            = 3312
DP2_TAPE_WORD_BYTES     = 8
DP2_TAPE_WORDS          = 414

DP2_YESPOWER_VERSION    = YESPOWER_1_0
DP2_N                   = 4096       // 16 MiB large V memory
DP2_R                   = 32

DP2_PHASE_SBOX          = 0
DP2_PHASE_FILL          = 1
DP2_PHASE_RW            = 2
DP2_PHASE_FINAL         = 3
```

`DP2_N = 4096, DP2_R = 32` is the revision-D draft parameter set. It allocates
`128 × r × N = 16,777,216` bytes for the large `V` array per active mining
thread, plus the ordinary yespower S-box and working state. Parameters MUST be
frozen before mainnet after the benchmark process in §12.

ML-DSA implementation constants MUST be compile-time checked against
`DP2_SIG_LEN`.

## 5. Top-level construction

For a block candidate `B` and miner spend keypair `(sk, pk)`:

```text
blob = get_block_hashing_blob(B)

H = SHAKE256(
      "DiscretePower/v2/header" || blob,
      64)

P = SHAKE256(
      "DiscretePower/v2/memory",
      32)

m = SHAKE256(
      "DiscretePower/v2/sign" || H,
      64)

sig = Sign(sk, m)                         // exactly 3309 bytes

tape = sig || 0x80 || 0x00 || 0x00       // exactly 3312 bytes

y = yespower-dp2(
      input = H,
      personalization = P,
      tape = tape,
      N = DP2_N,
      r = DP2_R)

PoW = SHAKE256(
        "DiscretePower/v2/final" || H || y,
        32)

accept iff integer_le(PoW) < target
```

`integer_le` interprets the 32-byte PoW value using the chain's existing
canonical difficulty comparison convention. Implementations MUST not introduce
a second byte-order convention.

The 64-byte `H` and `m` avoid reducing ML-DSA-65 authentication to a 32-byte
application digest. The final PoW remains 32 bytes.

### 5.1 Signature-tape encoding

The canonical tape is formed directly from the canonical ML-DSA-65 signature:

```text
tape[0 .. 3308] = sig[0 .. 3308]
tape[3309]      = 0x80
tape[3310]      = 0x00
tape[3311]      = 0x00
```

The delimiter is fixed even though the signature length is already fixed. It
prevents accidental equivalence with zero-padding conventions if a future
implementation incorrectly treats the final partial word as variable-length.

The tape MUST NOT be replaced by:

- a hash of the complete signature;
- an XOF expansion seeded by a short signature digest;
- a post-absorption SHAKE/Keccak state supplied by a miner;
- a Merkle root with externally supplied leaves;
- any other short caller-provided summary.

The consensus implementation derives the tape locally from the verified block
signature.

### 5.2 Signing-mode indifference

Consensus does not require or detect deterministic ML-DSA signing. A hedged
signer may generate multiple valid signatures for the same `m`; a deterministic
signer normally varies the nonce and therefore `H` and `m`.

Every distinct valid signature produces a distinct tape and enters the
memory-hard state before the first S-box entry is stored. No memory-hard prefix
is reusable across signature variants. Only cheap header hashing, signature
verification setup, and yespower's initial PBKDF setup may be reused.

### 5.3 Presigning

A key holder MAY presign candidate headers or nonce ranges. Revision D does not
claim a latency wall or prohibit presigning. Every presigned candidate still
requires one signature and one candidate-specific tape. A new previous-block
hash or any coinbase/template change invalidates the signature because both are
inside `blob`.

## 6. `yespower-dp2`

`yespower-dp2` starts from yespower 1.0 with parameters `N = DP2_N` and
`r = DP2_R`. PBKDF, personalization handling, `blockmix_salsa`,
`blockmix_pwxform`, S-box dimensions, loop counts, and final HMAC-SHA256 remain
unchanged except for the injection points explicitly defined below.

Because its memory loops are modified, this algorithm MUST be named and exposed
as `yespower-dp2`; it MUST NOT be represented as ordinary or unmodified
yespower 1.0.

### 6.1 Canonical state-word access

The injection rule is specified over the logical little-endian 32-bit word
array `X[0 .. 32r-1]` before implementation-specific SIMD layout.

`GET(X, q)` returns logical word `q`.
`XOR(X, q, v)` replaces logical word `q` with `GET(X, q) XOR v`.

Reference and optimized implementations MAY keep SIMD-shuffled internal state,
but they MUST implement `GET` and `XOR` so the logical transcript matches this
specification exactly. No architecture-dependent reinterpretation is allowed.

### 6.2 Global injection counter

One unsigned 64-bit counter `ctr` is initialized to zero immediately before the
first S-box-generation `smix1` call. It is shared across all injection points
for one yespower-dp2 execution and increments exactly once after each injection.
It is not reset between phases.

The tape word used at an injection point is:

```text
q  = ctr mod DP2_TAPE_WORDS
lo = LE32(tape[8q + 0 .. 8q + 3])
hi = LE32(tape[8q + 4 .. 8q + 7])
```

The first 414 injection points therefore consume every tape byte exactly once.
Later points cycle through the tape again.

### 6.3 Injection function

For logical state `X`, yespower block parameter `r`, phase `phase`, phase-local
iteration `i`, tape `tape`, and global counter `ctr`:

```text
words = 32 * r                         // 32 for S-box phase, 1024 otherwise
mask  = words - 1                      // words is a power of two here

q  = ctr mod 414
lo = LE32(tape[8q + 0 .. 8q + 3])
hi = LE32(tape[8q + 4 .. 8q + 7])

phase_constant =
    0x243F6A88 when phase = DP2_PHASE_SBOX
    0x85A308D3 when phase = DP2_PHASE_FILL
    0x13198A2E when phase = DP2_PHASE_RW
    0x03707344 when phase = DP2_PHASE_FINAL

selector = u32(
    GET(X, 0)
    XOR ROTL32(GET(X, words / 2), 7)
    XOR ROTL32(GET(X, words - 1), 17)
    XOR u32(0x9E3779B9 * u32(ctr + 1))
    XOR u32(0x7F4A7C15 * u32(i + 1))
    XOR phase_constant)

lane0 = selector AND mask
delta = ((selector >> 16) AND mask) OR 1       // odd and non-zero
lane1 = (lane0 + delta) AND mask               // lane1 != lane0

XOR(X, lane0, lo)
XOR(X, lane1, hi)

ctr = ctr + 1
```

All arithmetic is unsigned and reduced modulo `2^32` where shown. Shifts and
rotations use 32-bit operands. `lane0` and `lane1` are logical state-word
indices, not raw SIMD-array indices.

The phase constants are fixed domain separators for the injection schedule.
They carry no independent cryptographic claim.

### 6.4 Injection points

The ordinary yespower 1.0 `smix` structure is retained:

```text
smix1(B, 1, Sbytes / 128, S, X, ctx)      // S-box generation
smix1(B, r, N, V, X, ctx)                 // large-memory fill
smix2(B, r, N, Nloop_rw, V, X, ctx)       // read/write mixing
smix2(B, r, N, Nloop_final, V, X, ctx)    // final 0-or-2 loop
```

Revision D inserts `dp2_inject` as follows.

#### S-box-generation `smix1`

For each iteration `i`, after `X` is available and before `V_i <- X`:

```text
dp2_inject(X, r=1, phase=DP2_PHASE_SBOX, i, tape, ctr)
V_i <- X
... ordinary smix1 iteration continues ...
```

#### Large-memory-fill `smix1`

For each iteration `i`, before `V_i <- X` and before any state-dependent
`Wrap(Integerify(X), i)` operation:

```text
dp2_inject(X, r=DP2_R, phase=DP2_PHASE_FILL, i, tape, ctr)
V_i <- X
... ordinary smix1 iteration continues ...
```

#### Read/write `smix2`

For each iteration `i`, before `j <- Integerify(X) mod N`:

```text
dp2_inject(X, r=DP2_R, phase=DP2_PHASE_RW, i, tape, ctr)
j <- Integerify(X) mod N
... ordinary smix2 iteration continues ...
```

#### Final `smix2`

For each iteration `i`, before `j <- Integerify(X) mod N`:

```text
dp2_inject(X, r=DP2_R, phase=DP2_PHASE_FINAL, i, tape, ctr)
j <- Integerify(X) mod N
... ordinary smix2 iteration continues ...
```

If the ordinary yespower loop count makes the final phase zero iterations, no
final-phase injection occurs. Counter continuity remains unchanged.

### 6.5 Why injection continues through all phases

Injecting the signature only during an early prefix would permit a key holder
to compute that prefix and hand a checkpoint to the worker. Revision D cycles
the tape through S-box generation, the full `V` fill, and the data-dependent
read/write loops.

A worker that does not possess the tape cannot continue the specified execution
from an early checkpoint. A pool may still:

- send all 3,312 tape bytes;
- serve tape words interactively until the worker has cached the tape;
- transmit a larger equivalent internal state;
- perform the remaining memory-hard work itself.

The specification does not claim a formal lower bound against arbitrary future
compression. It does rule out the revision-C four-message relay and any
consensus-sanctioned short digest substitute.

## 7. Candidate space and grinding

The PoW value is a deterministic function of `(blob, sig)` after `sig` has been
created.

For a fixed header message `m`:

- a hedged signer may create a fresh valid `sig` and therefore a fresh tape;
- a deterministic signer normally changes the nonce, producing a fresh `H`,
  `m`, and `sig`.

In either case, each candidate costs:

```text
1 ML-DSA-65 signature
+ 1 complete yespower-dp2 execution
+ SHAKE-256 transcript hashing
```

A new signature changes the state before the first S-box entry is stored and is
re-injected throughout the execution. Memory-hard work from a different
signature cannot be reused under the specified algorithm.

## 8. Block format, block identity, and reward binding

The block carries:

- `minerSpendPk` — the ML-DSA-65 public key in coinbase `extra`, as in
  DiscretePower-1;
- `powSignature` — exactly one canonical ML-DSA-65 signature of exactly
  `DP2_SIG_LEN` bytes, serialized outside the hashing blob.

### 8.1 Hashing blob

`get_block_hashing_blob(B)` MUST include all consensus fields that determine the
candidate template, including:

- previous block hash;
- timestamp and difficulty-related header fields;
- nonce;
- transaction commitment / Merkle root;
- complete coinbase transaction commitment;
- `minerSpendPk` through the coinbase commitment.

It MUST exclude `powSignature` to avoid circular signing.

### 8.2 Canonical block ID

The canonical full block serialization, and therefore the canonical block ID,
MUST include `powSignature`. Two valid hedged signatures over the same hashing
blob produce two distinct full blocks and distinct block IDs.

```text
block_id = H_block(canonical_full_block_including_powSignature)
```

Header/PoW caches MUST key on the signature as well as the hashing blob. A cache
entry for one signature MUST NOT be reused for another signature over the same
header.

### 8.3 Reward binding

There is no second reward signature. The PoW signature is the reward binding:

1. `powSignature` MUST verify against `minerSpendPk` over recomputed `m`;
2. the coinbase MUST contain exactly one reward output committed to the same
   `minerSpendPk` under the existing Discrete rule.

Changing the coinbase, reward key, transaction root, previous block hash, or
nonce changes `blob`, then `H` and `m`, and invalidates the signature.

Block signature weight remains 3,309 bytes per block. At a 90-second target,
this is approximately 1.16 GB decimal per year before serialization overhead.

## 9. Validation algorithm

Given block `B`, `minerSpendPk`, and `powSignature`:

```text
1. Reject unless powSignature length is exactly 3309 bytes.
2. Recompute blob, H, P, and m.
3. Verify(minerSpendPk, m, powSignature).
   If verification fails: REJECT before any yespower-dp2 work.
4. Reconstruct tape = powSignature || 0x80 || 0x00 || 0x00.
5. Run one complete yespower-dp2(H, P, tape) execution.
6. Compute PoW = SHAKE256("DiscretePower/v2/final" || H || y, 32).
7. Reject unless PoW satisfies the target.
8. Enforce the single coinbase output commitment to minerSpendPk.
9. Ensure the canonical full block ID commits to powSignature.
```

The signature-first ordering cheaply rejects random malformed signatures.
It does not prevent an attacker from generating its own valid key and forcing
normal PoW validation work; ordinary peer admission, header-relay, duplicate,
and rate-limit protections remain necessary.

Validation is stateless with respect to chain history beyond the ordinary block
header and difficulty context. The PoW does not read a trailing blockchain
window, mutable cache, or reorg-sensitive record set.

## 10. Delegation cost model

### 10.1 Enforced properties

Against a remote key holder using the specified consensus algorithm:

- every candidate contains one valid ML-DSA-65 signature;
- every distinct signature creates a distinct tape;
- no memory-hard prefix is reusable across different signatures;
- a normal remote worker needs the 3,312-byte tape, or equivalent
  candidate-specific information, to execute independently;
- withholding the tape requires fine-grained interaction or local computation
  throughout the memory-hard phases;
- a 32-byte or 64-byte signature digest is insufficient.

### 10.2 Straightforward remote-key bandwidth

For aggregate candidate rate `A` candidates per second, transmitting the
canonical tape costs:

```text
pool egress = 3312 * A bytes/second
```

Examples:

```text
A = 100,000/s   -> 331.2 MB/s decimal
A = 1,000,000/s -> 3.312 GB/s decimal
```

A worker at `h` candidates per second receives:

```text
3312 * h bytes/second
```

This is a cost model, not a proof that no compressed or specialized protocol
can ever do better.

### 10.3 Interactive tape service

The pool may send 8-byte tape words as they are needed. The first 414 injection
points touch every word once. After receiving all words, the worker can cache
the entire tape; total useful payload is still 3,312 bytes per candidate.
Batching can hide latency, so revision D does not claim that interaction alone
prevents pooling.

### 10.4 Local-key mining

A farm, bot, or rented machine that holds its own reward key incurs no network
tape transfer and behaves like a solo miner. Consensus cannot determine whether
that machine is honestly owned, rented, compromised, or centrally controlled.

## 11. Security claims and non-claims

### 11.1 Claims

- **Reward-identity binding:** a valid block pays the ML-DSA identity that
  signed its hashing blob.
- **Per-candidate signer involvement:** every candidate includes a valid
  signature over the candidate header digest.
- **Mode-independent grinding cost:** deterministic and hedged signing both
  require a complete yespower-dp2 execution per signature candidate.
- **No reusable memory-hard prefix:** signature injection begins before the
  first S-box entry is stored and continues through all memory phases.
- **Delegation data/interaction tax:** a remote worker requires the canonical
  tape or equivalent candidate-specific information throughout execution; no
  fixed short digest defined by consensus substitutes for it.
- **Tip and template binding:** previous block hash and coinbase commitment are
  inside the signed hashing blob.
- **One-signature block weight:** exactly one ML-DSA-65 signature is stored per
  block.

### 11.2 Non-claims

- **Not pool-proof:** a pool may build signing infrastructure and stream tapes.
- **Not strongly non-outsourceable:** a worker cannot redirect the signed
  coinbase to itself, and no PQ zero-knowledge theft mechanism is provided.
- **No botnet resistance:** per-bot keys avoid the central tape channel and are
  indistinguishable from many solo miners.
- **No permanent ASIC resistance:** yespower-dp2 is a new yespower-derived
  algorithm whose CPU/GPU/FPGA/ASIC ratios require independent benchmarking.
- **No formal bandwidth lower bound:** the 3,312-byte figure describes the
  canonical tape and obvious equivalent protocols, not an information-theoretic
  theorem.
- **No automatic variance reduction:** miners still face solo-block variance;
  off-chain insurance and payout sharing cannot be prohibited by consensus.

### 11.3 New-algorithm risk

Modifying yespower's memory loops means revision D no longer inherits upstream
yespower test vectors or implementation assurance for the changed algorithm.
The unchanged components remain useful engineering foundations, but the new
injection schedule, optimized implementations, and hardware behavior require
independent review. Mainnet activation without cross-platform differential
testing and external cryptographic/PoW review is not recommended.

## 12. Parameter tuning and benchmark gate

Before mainnet freeze, benchmark at minimum:

```text
N=2048, r=32    // 8 MiB
N=4096, r=32    // 16 MiB, revision-D draft default
N=8192, r=32    // 32 MiB
```

Target systems:

- x86-64 without AVX2 reliance;
- x86-64 SSE2/AVX optimized builds;
- ARM64 desktop/server cores;
- representative integrated and discrete GPUs;
- at least one FPGA feasibility review if available.

Measure:

- ML-DSA sign and verify time;
- total candidate time;
- initial PBKDF time;
- S-box-generation time;
- large-memory-fill time;
- read/write-mix time;
- memory bandwidth and cache-miss behavior;
- scaling by physical core and SMT thread;
- reference versus optimized transcript equivalence;
- delegated bandwidth per unit of useful hash rate.

The final `N` should make signing a meaningful but non-dominant fraction of
solo mining, avoid excessive validation cost, and preserve useful commodity-CPU
participation. No parameter choice should be described as permanent ASIC
resistance.

## 13. Test plan

### 13.1 Known-answer transcript

Check in a frozen vector containing:

- hashing blob;
- `minerSpendPk`;
- canonical `powSignature`;
- `H`, `P`, and `m`;
- complete padded tape;
- yespower initial `B` digest;
- global counter and logical-X digest after injection points 1, 414, and 768;
- digest of the completed S-box;
- digest of `X` and `V` after large-memory fill;
- digest after read/write mixing;
- raw yespower-dp2 output `y`;
- final `PoW`.

Large internal arrays may be represented by SHAKE-256 or SHA-256 digests in the
vector, but the digest algorithm and byte serialization MUST be specified and
frozen.

### 13.2 Reference/optimized differential tests

For many random `(H, tape)` pairs, assert byte-identical output between:

- the scalar/reference implementation;
- every enabled optimized x86-64 implementation;
- ARM64 implementation;
- debug and release builds.

The reference implementation is authoritative if an optimized path disagrees.

### 13.3 Prove/verify round trips

Generate multiple ML-DSA-65 keypairs and random block templates. Assert that:

- `dp2_prove` output verifies with `dp2_verify`;
- changing nonce, previous block hash, transaction root, coinbase, or miner key
  invalidates the original signature before yespower-dp2;
- two valid hedged signatures over the same `m` produce different tapes and
  different PoW transcripts.

### 13.4 Rejection and DoS ordering

Test distinct rejection reasons for:

- missing, truncated, or oversized signature;
- signature bit flip at the start, middle, and end;
- wrong public key;
- valid signature over a different `m`;
- coinbase committed to another key;
- PoW above target;
- malformed serialization;
- duplicate block with alternate signature.

Instrument test builds to assert that signature-length and signature-verify
failures execute zero yespower-dp2 calls.

### 13.5 Injection coverage

Instrument the custom yespower path to assert for one execution:

- global counter starts at zero and never resets between phases;
- the first 414 injections use tape words `0..413` exactly once;
- every phase uses the expected phase identifier;
- injections occur before every specified `V` store or memory index;
- logical lane indices are identical in reference and optimized builds.

An internal-only test may bypass ML-DSA verification, flip each tape word, and
confirm that the final output changes. This is a regression test, not a
cryptographic proof.

### 13.6 Serialization and block identity

Assert that:

- `powSignature` survives block serialize/deserialize byte-for-byte;
- it is excluded from the hashing blob;
- it is included in full block serialization and block ID;
- alternate valid signatures over the same blob produce distinct block IDs;
- PoW caches distinguish alternate signatures.

### 13.7 Miner soak test

Run multi-thread mining with thread-local scratch allocation, repeated template
updates, nonce rollover, shutdown, and key zeroization. Confirm no per-attempt
heap allocation and no cross-thread tape or scratch-state reuse.

## 14. Pruning

`powSignature` MAY be pruned at depth greater than or equal to
`CRYPTONOTE_FINALITY_DEPTH` only under the chain's explicit PQ-signature
pruning/checkpoint model.

Because the canonical block ID commits to the signature:

- archival/seed nodes MUST retain it;
- pruned nodes MUST retain the already-validated block ID and required metadata;
- a node validating from genesis without trusted checkpoints MUST obtain the
  original signature;
- pruning MUST NOT redefine historical block IDs.

If PQ-signature pruning infrastructure is not implemented, retain every PoW
signature and leave pruning as a documented future hook.

## 15. Implementation cautions

- Do not call the modified function ordinary `yespower` in consensus-facing
  code or documentation.
- Do not inject a digest of `sig`; inject the canonical padded tape words.
- Do not derive the complete tape from a short XOF seed or expose a caller-
  supplied sponge state.
- Do not reset the injection counter between memory phases.
- Do not move injection after `V_i <- X` or after `j <- Integerify(X)`.
- Do not use raw SIMD-array indices as consensus lane indices.
- Do not permit architecture-specific lane ordering.
- Do not cache PoW solely by hashing blob; the signature is part of the PoW
  candidate and block ID.
- Verify ML-DSA before allocating or executing the large memory-hard path when
  validating untrusted blocks.
- Use disposable hot mining accounts and existing key locking/zeroization;
  do not expose a valuable long-term wallet key directly to high-frequency
  mining code.

## 16. Retired designs

- **DiscretePower-1:** signature compressed before the memory-hard core;
  identity-bound but cheap to delegate.
- **Revision A:** four stored signatures.
- **Revision B:** deterministic-signing consensus assumption and reusable
  pre-phase.
- **Revision C:** four unmodified yespower calls; vulnerable to interactive
  64-byte input relaying.
- **`dev/pow-window` trailing-window sampler:** separate research track;
  revision D remains stateless and does not depend on historical scratch data.

## Appendix A. Reference-implementation injection schedule (normative for Discrete)

Section 6.4 specifies injection relative to the idealized textbook `smix1`/`smix2`
loop shape (`V_i <- X`, `j <- Integerify(X)`). The Discrete reference implements
`yespower-dp2` by instrumenting the actual yespower 1.0 `smix1`/`smix2` in
`src/crypto/yespower.c` (guarded so plain `yespower` with a NULL tape is
byte-for-byte unchanged, which is a built-in differential anchor). The concrete,
frozen injection schedule is:

- The global counter `ctr` starts at 0 immediately before the S-box-generation
  `smix1` and is never reset; the phase-local iteration `i` restarts at 0 at the
  start of each of the three executed phases (`SBOX`, `FILL`, `RW`).
- **`smix1` (S-box generation and large-memory fill):** `dp2_inject` runs on the
  primary sequential input block-set of every `blockmix`/`blockmix_xor` in the
  fill, immediately **before** that mixing step consumes and rewrites the state
  into its `V` slot — i.e. before each `V`-store/state-defining step, never after.
- **`smix2` (read/write mixing):** `dp2_inject` runs on `X` immediately **before**
  each `blockmix_xor_save` whose `Integerify` return selects the next `V_j`.
- yespower 1.0 executes only the S-box, fill, and read/write phases; the
  `DP2_PHASE_FINAL` loop has zero iterations and therefore never injects, exactly
  as §6.4 permits. Counter continuity is preserved regardless.
- `GET`/`XOR` address the logical little-endian 32-bit word array over the
  SIMD-shuffled `salsa20_blk_t` storage using the fixed inverse of
  `salsa20_simd_shuffle`, so the logical transcript is identical on every
  little-endian target (x86-64 scalar/SSE2/AVX and ARM64) without any
  architecture-specific reinterpretation.

Because a NULL/all-zero tape makes every injection a no-op, `yespower-dp2` with a
zero tape equals stock `yespower 1.0`; the test suite asserts this equivalence as
the anchor that the unmodified memory-hard machinery is preserved.
