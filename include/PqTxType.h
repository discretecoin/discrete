// Copyright (c) 2026, The Discrete developers
//
// Discrete — post-quantum-only cryptocurrency.
// There is no legacy→PQ migration ("bridge") type: Discrete starts from genesis
// with no legacy chain to migrate from.

#pragma once

#include <cstdint>

namespace CryptoNote {

// PQ transaction sub-types carried in TransactionPrefix::txType.
//   TX_PQ       — normal PQ-to-PQ transfer, pre-v2 delivery era
//   TX_PQ_V2    — the same transfer, declaring outContext-v2 delivery
//   TX_FREE_REG — zero-fee account-number registration (no inputs/outputs)
//   txType == 0 — coinbase (BaseInput only)
//
// Value 0x02 is permanently RESERVED (it was the never-deployed legacy bridge
// subtype) and MUST stay rejected by consensus — do not reuse it without a hard
// fork. Removing the name does not change the wire: any tx with txType==0x02
// still falls through to the "unknown PQ tx subtype" reject path.
//
// TX_PQ_V2 exists because the delivery format is NOT visible on the wire: a
// PqOutput is {kemCt, encPayload, spendCommit} either way, and the out_context
// that separates pre-v2 from v2 is derived by the recipient and never
// transmitted. A validator therefore cannot inspect an output and tell which
// derivation produced it. The subtype is a WRITER DECLARATION, made binding by
// refusing the old declaration after the activation height: it does not prove
// any particular output decrypts under v2, it guarantees that software still
// emitting the pre-v2 derivation fails loudly instead of paying into an output
// its recipient may never find. Spending pre-fork outputs stays legal forever —
// the rule constrains how outputs are CREATED, never what they reference.
//
// txType is inside the §8.1 signing digest, so the declaration is signature-
// bound for free and an old signature cannot be relabelled in flight.
enum PqTxType : uint8_t {
  TX_COINBASE = 0x00,
  TX_PQ       = 0x01,
  TX_FREE_REG = 0x03,
  TX_PQ_V2    = 0x04,
};

// True for the ordinary transfer family (PqInput -> PqOutput), whichever
// delivery era declared it. Use this for every "is this a transfer" test; use
// an explicit == TX_PQ_V2 only where the delivery format itself matters.
inline bool isPqTransfer(uint8_t txType) {
  return txType == TX_PQ || txType == TX_PQ_V2;
}

}  // namespace CryptoNote
