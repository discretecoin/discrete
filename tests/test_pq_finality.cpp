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

// ─── Signed DNS checkpoint records ──────────────────────────────────────────
// Checkpoints::verify_signed_dns_record is the sole gate between a DNS TXT
// string and add_checkpoint. The signed payload is genesis-bound
// ("<genesis_hex>:<height>:<hash_hex>"), so these tests pin both the accept
// path and every reject class, including cross-chain replay.

namespace {

Crypto::Hash patternHash(uint8_t mult, uint8_t add) {
  Crypto::Hash h{};
  for (size_t i = 0; i < sizeof(h.data); ++i) {
    h.data[i] = static_cast<uint8_t>(i * mult + add);
  }
  return h;
}

CryptoPQ::DsaKeypairSeed fixedSeed(uint8_t base) {
  CryptoPQ::DsaKeypairSeed s{};
  for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(base + i);
  return s;
}

// A well-formed record signed by `sk` for `genesis`, plus its parts.
struct SignedRecord {
  uint32_t height;
  std::string hashHex;
  std::string record;
};

SignedRecord makeSignedRecord(const CryptoPQ::DsaSecretKey& sk,
                              const Crypto::Hash& genesis, uint32_t height) {
  SignedRecord r;
  r.height = height;
  r.hashHex = Common::podToHex(patternHash(5, 9));
  const std::string payload =
      Common::podToHex(genesis) + ":" + std::to_string(height) + ":" + r.hashHex;
  r.record = std::to_string(height) + ":" + r.hashHex + ":" + signMessagePq(payload, sk);
  return r;
}

}  // namespace

TEST(dns_checkpoints, signed_record_round_trip)
{
  auto kp = CryptoPQ::dsa_keygen_from_seed(fixedSeed(0x11));
  const Crypto::Hash genesis = patternHash(3, 1);
  const SignedRecord sr = makeSignedRecord(kp.second, genesis, 4321);

  uint32_t height = 0;
  std::string hashStr, why;
  EXPECT_EQ(Checkpoints::verify_signed_dns_record(sr.record, {kp.first}, genesis,
                                                  height, hashStr, why),
            Checkpoints::DnsRecordStatus::Accepted) << why;
  EXPECT_EQ(height, 4321u);
  EXPECT_EQ(hashStr, sr.hashHex);
}

// Cross-chain replay: the identical record, valid on chain A, must be rejected
// by a node whose genesis differs — this is the binding the payload prefix buys.
TEST(dns_checkpoints, record_bound_to_genesis)
{
  auto kp = CryptoPQ::dsa_keygen_from_seed(fixedSeed(0x22));
  const Crypto::Hash genesisA = patternHash(3, 1);
  const Crypto::Hash genesisB = patternHash(3, 2);
  const SignedRecord sr = makeSignedRecord(kp.second, genesisA, 777);

  uint32_t height = 0;
  std::string hashStr, why;
  EXPECT_EQ(Checkpoints::verify_signed_dns_record(sr.record, {kp.first}, genesisA,
                                                  height, hashStr, why),
            Checkpoints::DnsRecordStatus::Accepted) << why;
  EXPECT_EQ(Checkpoints::verify_signed_dns_record(sr.record, {kp.first}, genesisB,
                                                  height, hashStr, why),
            Checkpoints::DnsRecordStatus::BadSignature);
}

// Any-of-N: a record from signer B passes when B is anywhere in the list; a
// signer outside the list fails.
TEST(dns_checkpoints, any_of_n_signers)
{
  auto kpA = CryptoPQ::dsa_keygen_from_seed(fixedSeed(0x33));
  auto kpB = CryptoPQ::dsa_keygen_from_seed(fixedSeed(0x44));
  auto kpEvil = CryptoPQ::dsa_keygen_from_seed(fixedSeed(0x55));
  const Crypto::Hash genesis = patternHash(7, 3);

  const SignedRecord byB = makeSignedRecord(kpB.second, genesis, 1000);
  const SignedRecord byEvil = makeSignedRecord(kpEvil.second, genesis, 1000);

  uint32_t height = 0;
  std::string hashStr, why;
  EXPECT_EQ(Checkpoints::verify_signed_dns_record(byB.record, {kpA.first, kpB.first},
                                                  genesis, height, hashStr, why),
            Checkpoints::DnsRecordStatus::Accepted) << why;
  EXPECT_EQ(Checkpoints::verify_signed_dns_record(byEvil.record, {kpA.first, kpB.first},
                                                  genesis, height, hashStr, why),
            Checkpoints::DnsRecordStatus::BadSignature);
}

// Every malformed-record class fails closed, before any signature work.
TEST(dns_checkpoints, malformed_records_rejected)
{
  auto kp = CryptoPQ::dsa_keygen_from_seed(fixedSeed(0x66));
  const Crypto::Hash genesis = patternHash(9, 5);
  const std::string hash64 = Common::podToHex(patternHash(5, 9));

  uint32_t height = 0;
  std::string hashStr, why;
  const std::vector<CryptoPQ::DsaPublicKey> signers{kp.first};

  // No delimiter at all.
  EXPECT_EQ(Checkpoints::verify_signed_dns_record("junk", signers, genesis,
                                                  height, hashStr, why),
            Checkpoints::DnsRecordStatus::Malformed);
  // Legacy 2-field unsigned format.
  EXPECT_EQ(Checkpoints::verify_signed_dns_record("123:" + hash64, signers, genesis,
                                                  height, hashStr, why),
            Checkpoints::DnsRecordStatus::Malformed);
  // Hash of the wrong length.
  EXPECT_EQ(Checkpoints::verify_signed_dns_record("123:abcdef:sig", signers, genesis,
                                                  height, hashStr, why),
            Checkpoints::DnsRecordStatus::Malformed);
  // Height with trailing garbage.
  EXPECT_EQ(Checkpoints::verify_signed_dns_record("12x:" + hash64 + ":sig", signers,
                                                  genesis, height, hashStr, why),
            Checkpoints::DnsRecordStatus::Malformed);
  // Non-hex hash of the right length.
  std::string notHex(64, 'z');
  EXPECT_EQ(Checkpoints::verify_signed_dns_record("123:" + notHex + ":sig", signers,
                                                  genesis, height, hashStr, why),
            Checkpoints::DnsRecordStatus::Malformed);
  // Well-formed fields but garbage signature text.
  EXPECT_EQ(Checkpoints::verify_signed_dns_record("123:" + hash64 + ":notasig", signers,
                                                  genesis, height, hashStr, why),
            Checkpoints::DnsRecordStatus::BadSignature);
}

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
