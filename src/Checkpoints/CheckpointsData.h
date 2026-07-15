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

// Discrete launches with NO hardcoded checkpoints yet. A checkpoint pins a block
// ID that transitively commits — through the prevHash chain and tx Merkle roots —
// to the whole header/transaction history below it, so inside the checkpoint zone
// the node may skip the expensive per-block re-validation (yespower + per-input
// ML-DSA verification) during initial sync. That fast-sync skip is intended and
// will be used once real Discrete checkpoints exist.
//
// The inherited Karbo list removed here was invalid DATA, not a broken mechanism:
// its entries (heights 3,436 .. 1,266,456) pinned ANOTHER chain's block IDs, which
// (a) hard-stall a Discrete node at height 3,436 (no Discrete block ID ever equals
// a Karbo hash) and (b) leave every height below the last entry in-zone with the
// validation skip applied but no pin to anchor it.
//
// Add real Discrete checkpoints here only once genuine Discrete block IDs exist
// AND the block ID commits to the block signature (witness commitment), so that an
// in-zone block carrying a garbage signature cannot share a pinned ID. Keep this
// list empty until then; enforced by the checkpoints.list_is_empty test.
const std::initializer_list<CheckpointData> CHECKPOINTS = {
};

}
