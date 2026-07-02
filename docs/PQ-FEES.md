# Discrete PQ Fee Reference

## Parameters

| Constant | Value | Meaning |
|---|---|---|
| `COIN` | 100 | atomic units per XDS (2 decimal places) |
| `MINIMUM_FEE` | 1 | flat fee floor: 0.01 XDS per transaction |
| `TX_EXTRA_FEE_FREE_BYTES` | 3200 | tx_extra bytes included in the flat fee |
| `TX_EXTRA_FEE_CHUNK_BYTES` | 100 | surcharge granularity for extra bytes |
| `MAXIMUM_FEE` | 100 | wallet UI cap (1.00 XDS) |

## Fee floor formula

```
surcharge = extra_bytes <= 3200 ? 0
          : MINIMUM_FEE * ceil((extra_bytes - 3200) / 100)
floor     = MINIMUM_FEE + surcharge
```

Consensus enforces `fee >= floor` (`pqTxFeeFloor` in CryptoNoteConfig.h, applied by
`checkPqTransactionInputs`). The wallet sends `fee = floor` exactly — the fee does not
depend on the serialized size, so no measurement margin is needed.

## What this means in practice

| Transaction | tx_extra | Fee |
|---|---|---|
| Any normal transfer (any input/output count) | empty or payment id (~35 B) | **0.01 XDS** |
| Paid account-number registration | registration tag (3137 B) | **0.01 XDS** |
| Transfer with maximal extra | 4096 B | 0.10 XDS |
| Free account registration (`TX_FREE_REG`) | reg + PoW tags | 0 (anti-spam PoW instead) |

`tx_extra` is consensus-capped at `MAX_EXTRA_SIZE_PQ` = 4096 bytes
(`checkPqTransactionSemantic`), so the largest possible fee floor is 0.10 XDS.

## Rationale

PQ transactions are intrinsically large (an ML-DSA-65 signature is 3 309 B per input, an
ML-KEM-768 ciphertext 1 088 B per output), and none of that size is the user's choice. A
size-proportional fee therefore punished normal usage and made the quoted fee vary
unpredictably with input count — bad UX for no deterrent value. The flat fee makes every
ordinary transfer cost exactly `MINIMUM_FEE` = **0.01 XDS**.

The one thing a user *can* bloat is the free-form `tx_extra` field, so bytes beyond the
free allowance carry a surcharge of one `MINIMUM_FEE` per started 100-byte chunk. The
free allowance (3 200 B) is sized so every protocol-required extra fits without
surcharge — in particular a paid account-number registration, whose tag is
1 + 1184 (ML-KEM view pub) + 1952 (ML-DSA spend pub) = 3 137 bytes.

Trade-off to be aware of: with the flat floor, a maximal 256 KB consolidation
transaction also pays 0.01 XDS, so chain-bloat cost is bounded by the block-size
penalty (miner reward shrinks for blocks above the median size) rather than by fees.
`MAXIMUM_FEE` = 100 (1.00 XDS) remains a wallet-side sanity cap.
