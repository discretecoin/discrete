// Copyright (c) 2026, The Discrete developers
//
// Discrete — post-quantum-only cryptocurrency.
// There is no legacy→PQ migration ("bridge") type: Discrete starts from genesis
// with no legacy chain to migrate from.

#pragma once

#include <cstdint>

namespace CryptoNote {

// PQ transaction sub-types carried in TransactionPrefix::txType.
//   TX_PQ       — normal PQ-to-PQ transfer (PqInput → PqOutput)
//   TX_FREE_REG — zero-fee account-number registration (no inputs/outputs)
//   txType == 0 — coinbase (BaseInput only)
//
// Value 0x02 is permanently RESERVED (it was the never-deployed legacy bridge
// subtype) and MUST stay rejected by consensus — do not reuse it without a hard
// fork. Removing the name does not change the wire: any tx with txType==0x02
// still falls through to the "unknown PQ tx subtype" reject path.
enum PqTxType : uint8_t {
  TX_COINBASE = 0x00,
  TX_PQ       = 0x01,
  TX_FREE_REG = 0x03,
};

}  // namespace CryptoNote
