# Discrete Proof-of-Work: signed yespower

Discrete's Proof-of-Work is **yespower over the block's signed hashing blob**.
It applies to every block (v1+); there is no version gating. Because it is a pure
function of the block (no blockchain access), it lives as the free function
`CryptoNote::get_block_longhash(const Block&, Crypto::Hash&)` in
`src/CryptoNoteCore/CryptoNoteFormatUtils.cpp`; `Blockchain::checkProofOfWork`
and `Core::getBlockLongHash` call it. There is no hashing-blob cache (the
`m_blobs` RAM cache, the `hashing_blobs` LMDB table, and the `--without-blobs`
flag were removed) — only the pure `get_block_hashing_blob` /
`get_signed_block_hashing_blob` helpers remain, used for signing.

## The scheme

```
pot = signedHashingBlob(B)        // block header (nonce, previousBlockHash, …)
                                  //   + miner ML-DSA signature over it
PoW = yespower(pot)               // y_slow_hash, N=2048 r=32 → 8 MiB
```

The miner signs the block's hashing blob with the ML-DSA spend key that controls
the coinbase reward, then hashes the signed blob with yespower. Because the
signature covers the nonce, the block must be re-signed on every attempt.

## What this buys, and why it is enough

- **Non-outsourceable / anti-pool-rental.** A nonce is only valid alongside a
  signature from the reward-controlling key, so you cannot hand work to a rented
  or custodial miner without handing them the reward. This kills NiceHash-style
  rental and trustless custodial pools. It needs no blockchain access.
- **ASIC-resistant / CPU-egalitarian.** yespower is memory-hard (8 MiB
  scratchpad), which is the actual ASIC-resistance mechanism.
- **Tip-bound for free.** `previousBlockHash` is part of the hashed header, so a
  valid PoW can only be produced for the current chain head — mining already
  requires knowing the tip, without any extra machinery.

## Why not mix in blockchain data

An earlier iteration sampled pseudo-random bytes from recent blocks into the
hash, to force miners to possess (and stay synced to) recent chain history. It
was removed:

- **It protects against no adversary who matters.** Any dataset small enough for
  a casual CPU miner (~100–200 MiB) is trivially held by a farm or a botnet, so
  it neither raises the botnet floor nor excludes farms nor helps against 51%.
  Its only real effect is a decentralization *nicety* ("miners should run a
  synced node"), and even that is largely subsumed by the tip-binding above.
- **The cost is consensus risk.** Chain-mixing makes the PoW depend on
  reconstructing byte-identical records across the live cache, the DB, and
  alt-chain entries, plus a cache lifecycle, alt-tx resolution, and difficulty
  edge cases — a large fork-risk surface for a weak benefit.

Botnet/farm exclusion is a hardware-scarcity (GPU-bound PoW) or capital/stake
question, layered separately if ever desired — not something a CPU PoW can
provide, and not attempted here.
