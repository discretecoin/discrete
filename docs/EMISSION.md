# Discrete emission policy

Discrete has **no fixed supply cap.** Block issuance follows a decaying
exponential curve early on and then settles into a **perpetual 2%-per-year tail**
(Milton Friedman's *k-percent rule*). This document is the authoritative
description of that policy; the implementation is
`Currency::calculateReward()` in `src/CryptoNoteCore/Currency.cpp`, and every
minted atom is validated exactly against it by
`Blockchain::validate_miner_transaction()`.

## Per-block reward

For a block whose parent left `A = alreadyGeneratedCoins` in circulation, the
base reward (before block-size penalty and fees) is:

```
reward(A) = max( exponential(A), tail(A) )

exponential(A) = (S - A) >> k            if A < S
               = TAIL_EMISSION_REWARD     otherwise

tail(A)        = (A * 2 / 100) / B
```

where

| symbol | parameter | value |
|--------|-----------|-------|
| `S` | `EMISSION_CURVE_TARGET` | `2_100_000_000` atoms (21,000,000.00 XDS) |
| `k` | `EMISSION_SPEED_FACTOR` | `18` |
| `B` | blocks per year = `EXPECTED_NUMBER_OF_BLOCKS_PER_DAY * 365` | `960 * 365 = 350_400` |
| — | `COIN` (atoms per XDS) | `100` (2 decimals) |
| — | `TAIL_EMISSION_REWARD` | `100` atoms (vestigial, see below) |

### Two phases

1. **Exponential phase (early).** While the exponential term dominates, each
   block mints `(S - A) >> 18`, i.e. ~`1/262144` of the remaining distance to
   `S`. This front-loads issuance: the supply climbs quickly toward `S` and the
   reward halves roughly every `18 * ln(2) / ...` — in practice it shrinks by a
   constant fraction per block.

2. **Perpetual tail phase (forever after).** Once the circulating supply is
   large enough that `2%/year` exceeds the decaying exponential reward, the
   `tail(A)` term wins and stays in control. Because it is **2% of an
   ever-growing base**, the reward grows with the supply and the total supply
   increases without bound at a long-run rate of **~2% per annum**.

`EMISSION_CURVE_TARGET` is therefore **not a supply ceiling.** It is only the
parameter that shapes the initial exponential curve. Roughly ~21,000,000 XDS is
issued through the exponential phase before the tail takes over; after that the
supply keeps growing at ~2%/yr indefinitely.

`TAIL_EMISSION_REWARD` (100 atoms = 1.00 XDS) is only the floor of the
*exponential* term for `A >= S`. Since the 2% tail overtakes the exponential
term well before `A` reaches `S`, this constant is effectively vestigial and is
never the effective reward in practice.

## Why a perpetual tail

A perpetual, predictable tail:

- **Funds security forever.** There is always a block subsidy, so miner revenue
  never collapses to fee-only. This avoids the long-term security-budget problem
  faced by hard-capped chains.
- **Is deterministic and auditable.** The reward is a pure function of
  `alreadyGeneratedCoins`, which is itself consensus state. Anyone can recompute
  the exact emission at any height; there is no discretionary or hidden
  issuance.
- **Targets stable, low inflation.** As the base grows, a fixed *2% of supply*
  is a shrinking real burden relative to economic activity, approximating the
  Friedman rule of a constant money-growth rate.

## Consensus enforcement (no hidden emission)

The coinbase amount is not trusted. For every non-genesis block,
`validate_miner_transaction()`:

- recomputes `reward = getBlockReward(...)` from the parent's
  `alreadyGeneratedCoins`, the median block size, and the block's fees;
- requires the coinbase output sum to equal that `reward` **exactly** — a block
  that mints even one atom too many **or too few** is rejected;
- restricts non-genesis coinbase to a single output bound to the block signer.

The genesis block is the sole exception: its coinbase is the frozen
1,050,000 XDS Treasury Reserve (5% of `EMISSION_CURVE_TARGET`), fixed forever by
`GENESIS_COINBASE_TX_HEX` and built into every node, so it cannot be altered by
a peer. See [GENESIS.md](GENESIS.md).

## Launch parameters that affect emission

- `EMISSION_CURVE_TARGET`, `EMISSION_SPEED_FACTOR` — shape/pace of the
  exponential phase.
- `DIFFICULTY_TARGET` (90 s) feeds `EXPECTED_NUMBER_OF_BLOCKS_PER_DAY`, which
  sets `B` and thus the per-block tail. If the block time changes, the tail's
  per-block amount changes but the ~2%/yr rate does not.

Changing any of these after launch is a hard fork.
