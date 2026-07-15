// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Functional test for the node-local first-seen finality rule
// (CRYPTONOTE_FINALITY_DEPTH). The accept/reject decision lives in
// Checkpoints::is_alternative_block_allowed / is_finality_violation and is a pure
// function of heights + hardcoded checkpoints — no peer counts, no timers, no
// node-local state. These tests pin exactly that:
//   * a reorg deeper than the finality depth is refused (outside checkpoint zones);
//   * a reorg at or shallower than the depth is accepted;
//   * the is_in_checkpoint_zone exemption is preserved;
//   * the young-chain case does not underflow (the bug that would appear once the
//     rule is always-on from genesis).

#include "gtest/gtest.h"

#include "Checkpoints/Checkpoints.h"
#include "Checkpoints/CheckpointsData.h"
#include "CryptoNoteConfig.h"
#include <Logging/LoggerGroup.h>

using namespace CryptoNote;

namespace {
const uint32_t D = CryptoNote::parameters::CRYPTONOTE_FINALITY_DEPTH; // 10

// blockchain_height is the CHAIN LENGTH (tip height + 1); block_height is the
// height of the alternative block (= last-common-ancestor + 1). A reorg of depth
// (blockchain_height - block_height) is refused when that exceeds D.
Checkpoints noCheckpoints(Logging::LoggerGroup& logger) { return Checkpoints(logger); }
}

// A reorg exactly at the finality depth is allowed; one block deeper is refused.
TEST(finality_depth, boundary_at_depth)
{
  Logging::LoggerGroup logger;
  Checkpoints cp = noCheckpoints(logger);

  const uint32_t chainLen = 100; // tip height 99
  // depth = chainLen - block_height. block_height = chainLen - D = 90 -> depth D (allowed).
  EXPECT_FALSE(cp.is_finality_violation(chainLen, chainLen - D));       // depth == D
  EXPECT_TRUE (cp.is_alternative_block_allowed(chainLen, chainLen - D));

  EXPECT_TRUE (cp.is_finality_violation(chainLen, chainLen - D - 1));   // depth == D+1
  EXPECT_FALSE(cp.is_alternative_block_allowed(chainLen, chainLen - D - 1));
}

// Anything meaningfully deeper than the depth is refused.
TEST(finality_depth, deep_reorg_refused)
{
  Logging::LoggerGroup logger;
  Checkpoints cp = noCheckpoints(logger);

  EXPECT_TRUE (cp.is_finality_violation(100, 50));
  EXPECT_FALSE(cp.is_alternative_block_allowed(100, 50));
  EXPECT_TRUE (cp.is_finality_violation(1000, 1));
  EXPECT_FALSE(cp.is_alternative_block_allowed(1000, 1));
}

// Shallow reorgs (normal fork resolution) are untouched.
TEST(finality_depth, shallow_reorgs_allowed)
{
  Logging::LoggerGroup logger;
  Checkpoints cp = noCheckpoints(logger);

  for (uint32_t depth = 1; depth <= D; ++depth) {
    const uint32_t chainLen = 500;
    const uint32_t bh = chainLen - depth;
    EXPECT_FALSE(cp.is_finality_violation(chainLen, bh)) << "depth=" << depth;
    EXPECT_TRUE (cp.is_alternative_block_allowed(chainLen, bh)) << "depth=" << depth;
  }
}

// The critical always-on-from-genesis case: on a chain younger than the finality
// depth the subtractive form (block_height < blockchain_height - D) would wrap
// around and wrongly reject every shallow reorg. The additive form must not.
TEST(finality_depth, young_chain_no_underflow)
{
  Logging::LoggerGroup logger;
  Checkpoints cp = noCheckpoints(logger);

  for (uint32_t chainLen = 1; chainLen <= D + 1; ++chainLen) {
    for (uint32_t bh = 1; bh < chainLen; ++bh) {
      EXPECT_FALSE(cp.is_finality_violation(chainLen, bh))
        << "chainLen=" << chainLen << " bh=" << bh;
      EXPECT_TRUE(cp.is_alternative_block_allowed(chainLen, bh))
        << "chainLen=" << chainLen << " bh=" << bh;
    }
  }

  // First height at which the rule can fire at all is chainLen = D + 2 (block 1,
  // depth D+1).
  EXPECT_TRUE (cp.is_finality_violation(D + 2, 1));
  EXPECT_FALSE(cp.is_alternative_block_allowed(D + 2, 1));
}

// The is_in_checkpoint_zone exemption is preserved exactly: a fork that would be
// too deep is NOT flagged as a finality violation while it is inside the
// checkpoint zone (historical sync stays governed by the checkpoint rules).
TEST(finality_depth, checkpoint_zone_exempt)
{
  Logging::LoggerGroup logger;
  Checkpoints cp = noCheckpoints(logger);
  cp.add_checkpoint(1000, "0000000000000000000000000000000000000000000000000000000000000000");

  // Deep fork below the last checkpoint: exempt from the finality rule.
  EXPECT_FALSE(cp.is_finality_violation(1100, 980)); // 980 <= 1000 -> in checkpoint zone

  // Deep fork ABOVE the checkpoint zone: the finality rule applies.
  EXPECT_TRUE (cp.is_finality_violation(1100, 1080)); // depth 20, not exempt
  EXPECT_FALSE(cp.is_alternative_block_allowed(1100, 1080));

  // Shallow fork above the checkpoint zone: allowed.
  EXPECT_FALSE(cp.is_finality_violation(1100, 1095)); // depth 5
  EXPECT_TRUE (cp.is_alternative_block_allowed(1100, 1095));
}

// Discrete must ship with NO hardcoded checkpoints yet. Inside the checkpoint
// zone the main-chain admission path legitimately skips the expensive per-block
// re-validation (yespower + per-input ML-DSA verification) because a pinned block
// ID transitively commits, through the prevHash chain and tx Merkle roots, to the
// whole history below it — that is the standard fast-sync optimization and is
// wanted. The inherited Karbo list is invalid DATA, not a broken mechanism: its
// entries pin another chain's block IDs, so they (a) hard-stall Discrete at the
// first entry, height 3,436 (no Discrete block ID ever matches a Karbo hash), and
// (b) leave heights below it in-zone with the validation skip applied but no pin.
// Real Discrete checkpoints may be added once genuine block IDs exist AND the
// block ID commits to the block signature (witness commitment) so an in-zone
// garbage-signature block cannot share a pinned ID; update this guard then.
TEST(checkpoints, list_is_empty)
{
  EXPECT_EQ(CryptoNote::CHECKPOINTS.size(), 0u)
      << "CHECKPOINTS must be empty until genuine Discrete block IDs exist and the "
         "block ID commits to the signature; inherited Karbo entries stall the chain "
         "at height 3,436 and skip validation on unpinned in-zone heights";
}

// The decision is deterministic and a pure function of its arguments — repeated
// calls agree, and there is no peer/timer input to the signature at all.
TEST(finality_depth, deterministic)
{
  Logging::LoggerGroup logger;
  Checkpoints cp = noCheckpoints(logger);
  for (int i = 0; i < 3; ++i) {
    EXPECT_TRUE(cp.is_finality_violation(100, 80));
    EXPECT_FALSE(cp.is_finality_violation(100, 91));
  }
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
