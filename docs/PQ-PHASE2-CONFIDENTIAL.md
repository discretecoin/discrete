# PQ Phase 2 Confidential Amounts

Status: design intent only. Discrete ships today as a PQ-from-genesis plain-amount
chain: every non-coinbase transaction is `TX_PQ` or `TX_FREE_REG` under
`TRANSACTION_VERSION_1`.

This note records the preferred direction for a future confidential-amount fork.
No wire field, parameter, proof system, or activation rule in this document is
consensus until it is implemented, audited, and frozen in `docs/PQ-WIRE-FROZEN.md`.

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
