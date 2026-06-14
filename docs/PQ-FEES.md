# Discrete PQ Fee Reference

## Parameters

| Constant | Value | Meaning |
|---|---|---|
| `COIN` | 100 | atomic units per XDS (2 decimal places) |
| `MIN_PQ_FEE_PER_1000_BYTES` | 1 | atoms per 1000 serialized bytes |
| `MINIMUM_FEE` | 1 | floor for legacy/min-fee display |
| `MAXIMUM_FEE` | 100 | wallet UI cap (1.00 XDS) |

## Fee floor formula

```
floor = ceil(MIN_PQ_FEE_PER_1000_BYTES * tx_bytes / 1000)
      = (MIN_PQ_FEE_PER_1000_BYTES * tx_bytes + 999) / 1000   [integer]
```

Consensus enforces `fee >= floor`. The wallet sends `fee = floor + 1` (one-atom margin).

## Typical transaction sizes and fees (rate = 1 atom/KB)

| Transaction type | Approx. size | Floor (atoms) | Floor (XDS) |
|---|---|---|---|
| 1-in / 1-out TX_PQ | ~6 500 B | 7 | 0.07 |
| 1-in / 2-out TX_PQ | ~7 700 B | 8 | 0.08 |
| 2-in / 2-out TX_PQ | ~11 000 B | 11 | 0.11 |
| 8-in / 16-out TX_PQ (max) | ~48 000 B | 48 | 0.48 |

Sizes are dominated by ML-DSA-65 signatures (3 309 B/input) and ML-KEM-768 ciphertexts (1 088 B/output).

## Rationale

With `COIN = 100` (2 decimal places) a per-byte rate of 1 atom/byte would make the
minimum fee for a 1-in/2-out transaction **77 XDS** — completely unacceptable.
Switching to a per-1000-bytes rate with ceiling division brings the floor to **0.08 XDS**
for a typical transfer, matching the scale of `MINIMUM_FEE = 0.01 XDS`.

`MAXIMUM_FEE = 100` (1.00 XDS) gives comfortable headroom above the largest valid tx floor
(0.49 XDS for a 48 KB transaction) while still providing a sensible UI sanity cap.
