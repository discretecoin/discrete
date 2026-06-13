// Copyright (c) 2026, The Discrete developers
//
// Discrete — post-quantum-only cryptocurrency.
// TX_BRIDGE (legacy→PQ migration) is absent: Discrete starts from genesis
// with no legacy chain to migrate from.

#pragma once

#include <cstdint>

namespace CryptoNote {

// PQ transaction sub-types carried in TransactionPrefix::txType.
//   TX_PQ       — normal PQ-to-PQ transfer (PqInput → PqOutput)
//   TX_FREE_REG — zero-fee account-number registration (no inputs/outputs)
//   txType == 0 — coinbase (BaseInput only)
enum PqTxType : uint8_t {
  TX_COINBASE = 0x00,
  TX_PQ       = 0x01,
  // TX_BRIDGE (0x02) does not exist in Discrete — there is no legacy chain.
  // The value is reserved here only so that code ported from dev/pq that
  // references TX_BRIDGE compiles; consensus rejects any tx with txType==0x02.
  TX_BRIDGE   = 0x02,
  TX_FREE_REG = 0x03,
};

}  // namespace CryptoNote
