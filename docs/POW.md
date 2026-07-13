# DiscretePower-1: identity-bound post-quantum proof of work

Status: implemented in the pre-launch reference implementation. The exact code is
`get_block_longhash` in `src/CryptoNoteCore/CryptoNoteFormatUtils.cpp` and block
signature validation in `src/CryptoNoteCore/Blockchain.cpp`.

## Exact construction

DiscretePower-1 is a conservative composition of NIST SHAKE-256, ML-DSA-65,
and the yespower 1.0 memory-hard core. For each nonce, the miner computes:

```
blob    = get_block_hashing_blob(B)
H       = SHAKE256("DiscretePower/v1/header" || blob, 32)
sig     = ML-DSA-65.Sign(minerSpendSk, H)
Q       = SHAKE256("DiscretePower/v1/signature" || sig, 32)
X       = SHAKE256("DiscretePower/v1/input" || H || Q, 64)
P       = SHAKE256("DiscretePower/v1/memory", 32)
Y       = yespower-1.0(X, pers=P)   // N=2048, r=32, ~8 MiB
PoW     = SHAKE256("DiscretePower/v1/final" || H || Q || Y, 32)
```

Consensus verifies the full ML-DSA signature against the spend public key in the
coinbase extra, requires the single coinbase output to commit to the same spend key,
and checks the final SHAKE-256 value against the difficulty target. The 3,309-byte
signature is compressed into `Q`; the memory-hard core receives the fixed 64-byte
`X`. yespower internally retains its established BLAKE-256/pwxform/Salsa-derived
implementation; DiscretePower does not claim to replace or redesign that core.

Because the nonce is in `blob` and therefore `H`, every nonce attempt requires a fresh
signature. Five pinned domains separate the header, signature, memory input,
personalization, and final target transcripts from every other protocol use.

## What the construction guarantees

- **Reward-identity binding.** A valid block pays the ML-DSA identity that signed it.
  A worker cannot change the coinbase recipient under an existing signed job.
- **Per-attempt signer involvement.** A conventional pool cannot send one unsigned
  template and let workers vary an unrestricted nonce range; every candidate needs a
  signature from the reward identity.
- **Tip binding.** The previous block hash is in the signed and hashed header.
- **Memory-hard core.** yespower uses an ~8 MiB scratchpad per active attempt.

## What it does not prove

This is not a formally strong non-outsourceable scratch-off puzzle. A custodial pool can
  retain the reward key, sign batches of candidate nonces, distribute `(H, Q)` jobs,
accept lower-difficulty shares, and pay workers off-chain. The signing service must scale
with aggregate attempt rate, which is friction, not impossibility. The scheme therefore
raises the cost of conventional delegation and blocks unsigned reward redirection, but it
does not justify claims that pools, hosted mining, or rental are closed by construction.

Strong non-outsourceability has a stricter goal: effective outsourcing should let a worker
steal a winning reward without leaving evidence, making the pool unable to enforce honest
participation. Miller, Kosba, Katz, and Shi formalize that property in
[Nonoutsourceable Scratch-Off Puzzles](https://www.cs.umd.edu/~jkatz/papers/nonoutsourceable_full.pdf).
Adapting such a construction to a post-quantum chain would require a new, reviewed
protocol (and likely post-quantum encryption plus zero-knowledge machinery); it is not a
safe assumption to add to the current memory-hard loop.

## Reevaluation of blockchain-dependent scratchpads

### Karbo whole-history sampling

Karbo's signed-PoW branch derives eight heights from the candidate hash, fetches the small
hashing blob at each height across prior history, concatenates them, and runs yespower.
The sampled bytes are public and compact enough to cache by height. This makes the PoW
chain-aware and inconveniences generic stateless rental software, but a custom pool or
farm can keep the table and distribute complete jobs. Its working set grows with chain
length and its DB/alternative-chain lookup paths add consensus complexity without strong
possession or non-outsourceability guarantees.

### Discrete's dropped trailing-window sampler

The experimental `dev/pow-window` design is stronger as a *working-set* construction:

- 10,800 trailing blocks (~11 days);
- a deterministic 16 KiB record expanded from each block's full bytes;
- ~170 MiB bounded resident set;
- 4,096 sequential 64-byte fetches whose next address depends on the prior slice;
- main-chain, DB-rebuild, and alternative-chain record paths covered by reorg/replay tests.

Compared with Karbo, the bounded window avoids unbounded growth, full-block-derived records
defeat the tiny hashing-blob cache shortcut, and the sequential walk better establishes
recent-chain possession. It can discourage SPV/stateless mining and commodity rental APIs.
It still does **not** stop a purpose-built pool: all records are public, workers can hold
the same 170 MiB set, and the pool can continue to sign candidate jobs.

The engineering costs are significant: consensus now depends on byte-identical full-block
and transaction reconstruction across live cache, database rebuilds, reorgs, and
alternative branches; validation becomes stateful; cache-miss/DoS behavior expands; and
light validation becomes harder. A dataset small enough for ordinary CPUs is also small
enough for farms and botnets.

## Recommendation

Keep DiscretePower-1 for the candidate protocol, with the limited claims above. Do not
merge either blockchain sampler as a non-outsourceability fix.

If recent-chain possession is independently desired, continue `dev/pow-window` as a
testnet research track with cross-platform deterministic vectors, cache/DB/alt-chain
differential tests, adversarial cache-miss benchmarks, IBD measurements, and a written
threat model. Prefer it over Karbo's unbounded eight-blob sampler, but adopt it only for
measured full-node-mining benefits.

For actual pool resistance, research a post-quantum **strong non-outsourceable puzzle**
whose worker gains an undetectable reward-stealing capability when given enough work.
Until that exists and is independently reviewed, describe the deployed mechanism as
identity-bound or delegation-resistant—not pool-proof.
