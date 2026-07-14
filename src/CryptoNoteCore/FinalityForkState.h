// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Discrete is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#pragma once

#include <cstdint>
#include "CryptoTypes.h"

namespace CryptoNote {

// Detected first-seen-finality fork state. Populated when a node refuses a reorg
// that forks deeper than CRYPTONOTE_FINALITY_DEPTH. This is OPERATOR MESSAGING
// only — pure chain data, derived deterministically from the refused block. It is
// never an input to the accept/reject decision. peer_split (the "may be on a
// minority fork" hint) is a separate human heuristic computed live at read time.
struct FinalityForkState {
  bool active = false;
  uint32_t localTipHeight = 0;
  Crypto::Hash localTipHash{};
  uint32_t competingTipHeight = 0;   // highest competing block seen (higher work, refused)
  Crypto::Hash competingTipHash{};
  uint32_t divergenceHeight = 0;     // last common ancestor
  uint32_t refusedDepth = 0;         // main blocks that would be discarded
};

} // namespace CryptoNote
