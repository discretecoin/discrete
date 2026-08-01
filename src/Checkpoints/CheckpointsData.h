// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2026, The Karbo developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <cstddef>
#include <initializer_list>

namespace CryptoNote {

struct CheckpointData {
  uint32_t height;
  const char* blockId;
};

// A checkpoint pins a block ID that transitively commits — through the prevHash 
// chain and tx Merkle roots — to the whole header/transaction history below it, 
// so inside the checkpoint zone the node may skip the expensive per-block 
// re-validation (yespower + per-input ML-DSA verification) during initial sync. 
// That fast-sync skip is intended.
//
// Both preconditions for pinning Discrete checkpoints are now met: genuine
// Discrete block IDs exist, and the block ID is a witness commitment
// (discretePowerBlockId over the hashing blob AND b.signature), so an in-zone
// block carrying a garbage signature cannot share a pinned ID.
//
// Every entry MUST be a mainnet block ID read from a node synced past it and
// confirmed against a second independent node — a wrong ID hard-stalls every
// node that ships it, and heights below it stay in-zone with the validation
// skip applied but no pin. Heights must be strictly ascending. Pin only heights
// far deeper than CRYPTONOTE_FINALITY_DEPTH, and note that --rollback-to-height
// refuses to roll back into the checkpoint zone. Well-formedness is enforced by
// the checkpoints.list_is_well_formed test; correctness of the ID is not
// machine-checkable here.
const std::initializer_list<CheckpointData> CHECKPOINTS = {
  { 5500, "b2ef2ae4d5c1cd5ab3c9fa59f3f4abe60311d06a3dee67590028b33c44dabdaf" }
};

}
