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

Consensus enforces `fee >= floor` through `pqTxFeeFloor` and
`checkPqTransactionInputs`. The wallet uses this floor exactly unless the caller supplies
a larger explicit fee.

## What this means in practice

| Transaction | tx_extra | Fee floor |
|---|---|---:|
| Normal transfer at any allowed input/output count | empty or payment id (~35 B) | **0.01 XDS** |
| Paid account-number registration | registration tag (3137 B) | **0.01 XDS** |
| Transfer with maximal extra | 4096 B | **0.10 XDS** |
| Free account registration (`TX_FREE_REG`) | reg + PoW tags | 0 (anti-spam PoW instead) |

## Rationale and explicit trade-off

PQ transactions have a high protocol-imposed baseline: an ML-DSA-65 signature is 3,309
bytes per input and an ML-KEM-768 ciphertext is 1,088 bytes per output. Discrete currently
chooses a predictable flat base fee and uses consensus input/output/transaction-size caps,
miner transaction selection, and the dynamic block-size penalty as the primary size
controls. The free-form `tx_extra` field receives a separate surcharge because it can be
expanded without performing a payment function.

Output count is also partly protocol-driven rather than arbitrary: canonical denomination
decomposition turns 1,234 atoms into outputs of 1,000, 200, 30, and 4 atoms. A naïve
per-output fee would charge users according to an amount's decimal decomposition.

Input and output counts are still user-controlled. Consequently, a maximal 256 KiB
transaction can pay the same 0.01 XDS base fee as a small transfer. That is a deliberate
policy trade-off, not a claim that all transaction size is unavoidable. A future change to
weight-based or per-input/output pricing would be a consensus policy decision requiring
economic analysis, wallet changes, tests, and a fork; it is not assumed here.

The free allowance (3,200 B) fits every required extra, including a 3,137-byte paid
account registration tag. `MAXIMUM_FEE` = 100 (1.00 XDS) remains a wallet-side sanity cap.
