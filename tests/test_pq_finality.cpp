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
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "PqAddress.h"
#include "crypto_pq/PqDsa.h"
#include <Common/StringTools.h>
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

// Inside the checkpoint zone the main-chain admission path legitimately skips the
// expensive per-block re-validation (yespower + per-input ML-DSA verification)
// because a pinned block ID transitively commits, through the prevHash chain and
// tx Merkle roots, to the whole history below it — that is the standard fast-sync
// optimization and is wanted. It is only sound because the Discrete block ID is a
// witness commitment that also covers b.signature, so an in-zone block carrying a
// garbage signature cannot share a pinned ID.
//
// A malformed entry is far worse than no entry: a bad ID hard-stalls every node
// that ships it, and leaves the heights below it in-zone with the validation skip
// applied but no pin (that is exactly how the inherited Karbo list failed — it
// pinned another chain's IDs and stalled Discrete at height 3,436). This guard
// pins the shape of the list; that an ID is the real mainnet block at that height
// is not machine-checkable here and must be confirmed against two synced nodes.
TEST(checkpoints, list_is_well_formed)
{
  uint32_t previousHeight = 0;
  bool first = true;
  for (const auto& cp : CryptoNote::CHECKPOINTS) {
    EXPECT_NE(cp.height, 0u) << "genesis must not be pinned as a checkpoint";
    if (!first) {
      EXPECT_GT(cp.height, previousHeight)
          << "checkpoint heights must be strictly ascending, got " << cp.height
          << " after " << previousHeight;
    }
    previousHeight = cp.height;
    first = false;

    ASSERT_NE(cp.blockId, nullptr) << "checkpoint at height " << cp.height << " has a null ID";
    const std::string id(cp.blockId);
    EXPECT_EQ(id.size(), 64u)
        << "checkpoint at height " << cp.height << " must be a 64-char hex block ID";
    for (char c : id) {
      EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
          << "checkpoint at height " << cp.height << " must be lowercase hex, got '" << c << "'";
    }

    Crypto::Hash parsed;
    EXPECT_TRUE(Common::podFromHex(id, parsed))
        << "checkpoint at height " << cp.height << " does not parse as a block ID";
    EXPECT_NE(parsed, CryptoNote::NULL_HASH)
        << "checkpoint at height " << cp.height << " is the null hash";

    // A checkpoint shallower than the finality depth would pin a block that the
    // first-seen finality rule can still legitimately reorg away.
    EXPECT_GT(cp.height, D)
        << "checkpoint at height " << cp.height << " is within the finality depth " << D;
  }
}

// The list must actually load into a Checkpoints instance the way Daemon.cpp and
// PaymentGateService.cpp load it — a duplicate height or unparseable ID is
// dropped there with only a warning, so assert every entry is accepted.
TEST(checkpoints, list_loads_into_checkpoints)
{
  Logging::LoggerGroup logger;
  Checkpoints cp(logger);
  for (const auto& entry : CryptoNote::CHECKPOINTS) {
    EXPECT_TRUE(cp.add_checkpoint(entry.height, entry.blockId))
        << "checkpoint at height " << entry.height << " was rejected by add_checkpoint";
  }
  for (const auto& entry : CryptoNote::CHECKPOINTS) {
    EXPECT_TRUE(cp.is_in_checkpoint_zone(entry.height));
    Crypto::Hash expected;
    ASSERT_TRUE(Common::podFromHex(std::string(entry.blockId), expected));
    EXPECT_TRUE(cp.check_block(entry.height, expected));
  }
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

// ─── Signed DNS checkpoint records ──────────────────────────────────────────
// The TXT-embedded-signature format these tests used to cover is gone: an
// ML-DSA-65 signature (3309 B) cannot fit a 4096-wire-byte TXT record, so the
// record is now a pointer to an HTTPS-hosted signed JSON file. Round-trip,
// genesis binding, any-of-N, and every malformed/reject class are covered
// against the live scheme in tests/test_dns_checkpoint.cpp
// (PqDnsCheckpointTests). Only the config-level signer check remains here.

// The signer list shipped in CryptoNoteConfig.h must contain only valid mainnet
// PQ addresses — a typo here would silently fail-close DNS checkpoints in a
// release build (the loader logs and drops unparseable entries).
TEST(dns_checkpoints, provisioned_signer_addresses_decode)
{
  for (size_t i = 0; i < CryptoNote::DNS_CHECKPOINT_SIGNERS_COUNT; ++i) {
    const char* entry = CryptoNote::DNS_CHECKPOINT_SIGNERS[i];
    ASSERT_NE(entry, nullptr) << "sentinel inside the counted range at index " << i;
    PqAddress addr;
    EXPECT_TRUE(decodePqAddress(std::string(entry), /*testnet=*/false, addr))
        << "DNS_CHECKPOINT_SIGNERS[" << i << "] is not a valid mainnet PQ address";
  }
  // The sentinel itself sits one past the counted range.
  EXPECT_EQ(CryptoNote::DNS_CHECKPOINT_SIGNERS[CryptoNote::DNS_CHECKPOINT_SIGNERS_COUNT],
            nullptr);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
