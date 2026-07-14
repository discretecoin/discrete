# DiscretePower-2: identity-bound post-quantum proof of work

Status: implemented in the pre-launch reference implementation. The authoritative
specification is [DISCRETE-POW-SPEC-002.md](DISCRETE-POW-SPEC-002.md) (revision D).
The code is `dp2_prove` / `dp2_verify` and `get_block_longhash` in
`src/CryptoNoteCore/CryptoNoteFormatUtils.cpp`, the `yespower-dp2` core in
`src/crypto/yespower.c`, and block validation in `src/CryptoNoteCore/Blockchain.cpp`.

DiscretePower-1 (which compressed the signature to a 32-byte digest before the
memory-hard core) is **retired**; it was cheap to delegate because a pool could
transmit only that short digest to workers.

## Exact construction (summary — see the spec for the normative text)

For each candidate block `B` and miner spend keypair `(sk, pk)`:

```
blob = get_block_hashing_blob(B)                      // excludes powSignature
H    = SHAKE256("DiscretePower/v2/header" || blob, 64)
P    = SHAKE256("DiscretePower/v2/memory", 32)
m    = SHAKE256("DiscretePower/v2/sign"   || H, 64)
sig  = ML-DSA-65.Sign(sk, m)                          // exactly 3309 bytes
tape = sig || 0x80 || 0x00 || 0x00                    // exactly 3312 bytes
Y    = yespower-dp2(input=H, pers=P, tape=tape, N=4096, r=32)   // 16 MiB (draft)
PoW  = SHAKE256("DiscretePower/v2/final" || H || Y, 32)
accept iff PoW < target
```

`yespower-dp2` is yespower 1.0 with the **raw signature tape injected throughout
the memory-hard loops** — 8 bytes are XORed into the evolving state before every
`V`-store / memory-index step, cycling the whole 3,312-byte tape through S-box
generation, the large-memory fill, and the read/write mixing. It is a distinct
consensus algorithm and must never be presented as ordinary yespower. With an
all-zero tape the injection is a no-op and `yespower-dp2` collapses to stock
yespower 1.0 — the differential anchor asserted by the tests.

Validation verifies the ML-DSA-65 signature over `m` **before** running any
yespower-dp2 (the DoS bound: a garbage block costs one signature verification),
then checks `PoW < target`, then enforces the single coinbase output committing to
the same spend key. There is no separate reward signature — the PoW signature is
the reward binding.

## What the construction guarantees

- **Reward-identity binding.** A valid block pays the ML-DSA identity that signed it.
- **Per-candidate signer involvement.** Every candidate carries a valid signature
  over the header digest `m`; no memory-hard prefix is reusable across signatures,
  because injection begins before the first S-box entry is stored.
- **Delegation data/interaction tax.** A remote worker needs the full 3,312-byte
  candidate-specific tape (or equivalent), not a short digest, throughout execution.
- **Tip and template binding.** The previous block hash and coinbase commitment are
  inside the signed hashing blob.

## What it does not claim

The mechanism is **identity-bound and delegation-hostile**, not pool-proof. A pool
can build signing infrastructure and stream tapes; custodial mining, local-key
farms, and per-key botnets remain possible. It is not strongly non-outsourceable in
the Miller–Kosba–Katz–Shi sense, and yespower-dp2 is a new yespower-derived
algorithm whose hardware ratios and parameters (§12 of the spec) require independent
benchmarking and review before mainnet.

The dropped `dev/pow-window` trailing-window sampler remains a separate research
track; revision D is stateless and does not depend on historical scratch data.
