// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.

#pragma once

#include <cstdint>

namespace CryptoNote {

// Activation heights of the pending upgrade (parameters::PQ_TRANSCRIPT_V2_HEIGHT,
// parameters::PQ_GROUPED_AUTH_HEIGHT and their _TESTNET twins). They come from the
// Currency, so mainnet, testnet and test chains each run their own schedule and
// consensus and wallets read the same one. The defaults are "never": a caller that
// does not set them signs and validates under today's rules.
struct PqUpgradeHeights {
  uint32_t transcriptV2 = 0xFFFFFFFFu;
  uint32_t groupedAuth  = 0xFFFFFFFFu;
};

}  // namespace CryptoNote
