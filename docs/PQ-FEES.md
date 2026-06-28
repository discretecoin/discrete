# Discrete PQ Fee Reference

## Parameters

| Constant | Value | Meaning |
|---|---|---|
| `COIN` | 100 | atomic units per XDS (2 decimal places) |
| `MIN_PQ_FEE_PER_4000_BYTES` | 1 | atoms per 4000 serialized bytes |
| `MINIMUM_FEE` | 1 | base minimum-fee display/API value |
| `MAXIMUM_FEE` | 100 | wallet UI cap (1.00 XDS) |

## Fee floor formula

```
floor = ceil(MIN_PQ_FEE_PER_4000_BYTES * tx_bytes / 4000)
      = (MIN_PQ_FEE_PER_4000_BYTES * tx_bytes + 3999) / 4000   [integer]
```

Consensus enforces `fee >= floor`. The wallet sends `fee = floor + 1` (one-atom margin).

## Typical transaction sizes and fees (rate = 1 atom / 4000 B)

| Transaction type | Approx. size | Floor (atoms) | Floor (XDS) |
|---|---|---|---|
| 1-in / 1-out TX_PQ | ~6 500 B | 2 | 0.02 |
| 1-in / 2-out TX_PQ | ~7 700 B | 2 | 0.02 |
| 2-in / 2-out TX_PQ | ~11 000 B | 3 | 0.03 |
| 32-in / 64-out TX_PQ (max) | ~246 000 B | 62 | 0.62 |

Sizes are dominated by ML-DSA-65 signatures (3 309 B/input) and ML-KEM-768 ciphertexts (1 088 B/output).

## Rationale

With `COIN = 100` (2 decimal places) a per-byte rate of 1 atom/byte would make the
minimum fee for a 1-in/2-out transaction **77 XDS** — completely unacceptable. A rate of
1 atom per 4000 serialized bytes with ceiling division brings the floor to **0.02 XDS** for
a typical transfer, at the scale of `MINIMUM_FEE = 0.01 XDS`. Because PQ transactions are
large (multi-KB ML-DSA signatures), the per-byte rate is kept low so absolute fees stay
modest even for big multi-input spends.

`MAXIMUM_FEE = 100` (1.00 XDS) gives comfortable headroom above the largest valid tx floor
(~0.66 XDS for a 256 KB transaction) while still providing a sensible UI sanity cap.
