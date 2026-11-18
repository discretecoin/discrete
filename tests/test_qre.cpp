// Copyright (c) 2026, The Discrete developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "Qre/QreVerifier.h"
#include "crypto_pq/PqDsa.h"
#include "crypto_pq/PqHash.h"
#include "gtest/gtest.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using Qre::Bytes;
using Qre::Hash;
using Qre::Status;
using Key = std::pair<CryptoPQ::DsaPublicKey, CryptoPQ::DsaSecretKey>;

template<typename Range>
void append(Bytes& out, const Range& bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}

template<typename Integer>
void littleEndian(Bytes& out, Integer value) {
  for (size_t i = 0; i < sizeof(value); ++i) {
    out.push_back(static_cast<uint8_t>(value));
    value >>= 8;
  }
}

Hash filled(uint8_t byte) {
  Hash hash{};
  hash.fill(byte);
  return hash;
}

Bytes domain(const std::string& purpose) {
  const std::string text = "discrete-qre-" + purpose + "-v1";
  return Bytes(text.begin(), text.end());
}

template<typename Range>
Hash digest(const std::string& purpose, const Range& data) {
  Bytes tagged = domain(purpose);
  append(tagged, data);
  return CryptoPQ::sha3_256(tagged.data(), tagged.size());
}

std::string hex(const Hash& hash) {
  const char digits[] = "0123456789abcdef";
  std::string out;
  for (uint8_t byte : hash) {
    out += digits[byte >> 4];
    out += digits[byte & 15];
  }
  return out;
}

const std::array<Key, 4>& keys() {
  static const auto value = [] {
    std::array<Key, 4> result;
    for (size_t i = 0; i < result.size(); ++i) {
      CryptoPQ::DsaKeypairSeed seed{};
      seed.fill(static_cast<uint8_t>(i + 1));
      result[i] = CryptoPQ::dsa_keygen_from_seed(seed);
    }
    return result;
  }();
  return value;
}

// Build transcripts from the RFC fields without using the verifier's decoder.
Bytes policy(bool transcriptOnly = false, uint32_t records = 64, uint32_t checks = 32,
             uint32_t age = 60, uint32_t window = 60) {
  Bytes out{1, 1, 4, 3, 1};
  for (auto limit : {window, age, 5U, records, checks}) littleEndian(out, limit);
  std::vector<CryptoPQ::DsaPublicKey> roster;
  for (size_t i = 0; i < keys().size(); ++i) {
    auto key = keys()[i].first;
    if (transcriptOnly) key.fill(static_cast<uint8_t>(i + 1));
    roster.push_back(key);
  }
  std::sort(roster.begin(), roster.end());
  for (const auto& key : roster) append(out, key);
  return out;
}

constexpr uint64_t startTime = 1800000000;

Bytes context(const Bytes& pinned, uint64_t start = startTime,
              uint32_t observedHeight = 115, uint32_t referenceHeight = 125,
              uint64_t duration = 60) {
  Bytes out{1, 1};
  out.insert(out.end(), 16, 0x11);
  append(out, filled(0x22));
  append(out, digest("policy", pinned));
  littleEndian(out, uint64_t{1});
  littleEndian(out, uint64_t{7});
  append(out, filled(0x33));
  littleEndian(out, uint32_t{130});
  append(out, filled(0x44));
  littleEndian(out, uint32_t{90});
  append(out, filled(0x55));
  littleEndian(out, observedHeight);
  littleEndian(out, referenceHeight);
  littleEndian(out, start);
  littleEndian(out, start + duration);
  return out;
}

Bytes statement(uint8_t reference = 0x77) {
  Bytes out;
  append(out, filled(0x66));
  append(out, filled(reference));
  return out;
}

Hash statementId(const Bytes& ctx, const Bytes& branch) {
  Bytes out;
  append(out, digest("context", ctx));
  append(out, branch);
  return digest("statement", out);
}

Bytes message(const Bytes& ctx, const Bytes& branch, const Hash& signer, uint64_t when) {
  Bytes out = domain("observation");
  append(out, digest("context", ctx));
  append(out, statementId(ctx, branch));
  littleEndian(out, when);
  append(out, signer);
  return out;
}

Bytes envelope(const Bytes& ctx, const Bytes& branch, size_t index, uint64_t when) {
  const auto& key = keys().at(index);
  const auto signer = digest("key", key.first);
  const auto msg = message(ctx, branch, signer, when);
  Bytes out;
  append(out, signer);
  littleEndian(out, when);
  append(out, CryptoPQ::dsa_sign(key.second, msg.data(), msg.size()));
  return out;
}

Bytes bundle(const Bytes& ctx, const Bytes& branch, std::vector<Bytes> envelopes) {
  Bytes out = ctx;
  append(out, branch);
  out.push_back(static_cast<uint8_t>(envelopes.size()));
  std::sort(envelopes.begin(), envelopes.end());
  for (const auto& item : envelopes) append(out, item);
  return out;
}

class QreTest : public ::testing::Test {
protected:
  Bytes pinned = policy();
  Bytes ctx = context(pinned);
  Bytes branch = statement();
  uint64_t now = startTime + 30;

  Bytes delivery(std::initializer_list<size_t> indices, const Bytes& selected,
                 uint64_t when) const {
    std::vector<Bytes> envelopes;
    for (size_t i : indices) envelopes.push_back(envelope(ctx, selected, i, when));
    return bundle(ctx, selected, envelopes);
  }

  Bytes votes(std::initializer_list<size_t> indices) const {
    return delivery(indices, branch, now);
  }

  Qre::Result inspect(const std::vector<Bytes>& inputs) const {
    return Qre::inspect(pinned, ctx, inputs, now);
  }
};

TEST_F(QreTest, MatchesPublishedTranscript) {
  auto fixture = policy(true);
  auto request = context(fixture);
  CryptoPQ::DsaPublicKey first{};
  first.fill(1);
  auto msg = message(request, branch, digest("key", first), now);
  ASSERT_EQ(request.size(), 226u);
  ASSERT_EQ(msg.size(), 131u);
  EXPECT_EQ(hex(digest("policy", fixture)), "dd62157cafd49d714504526897585e80819083da0c2d6d5727be3c3bc105c0bf");
  auto empty = Qre::inspect(fixture, request, {}, now);
  ASSERT_EQ(empty.status, Status::Insufficient) << empty.reason;
  EXPECT_EQ(hex(empty.contextId), "71ed68a51e926b02f9a982866c7a8fe81abd3cbb53298548c2fa29263d0db18d");
  EXPECT_EQ(hex(statementId(request, branch)), "04a4aca6bb9ed1b5d40bac4ca0df026ace440fb8d06e27ff0ea26f26fdff4dbc");
  EXPECT_EQ(hex(CryptoPQ::sha3_256(msg.data(), msg.size())), "c1b18a6867359df3a279f621cfd441e4b0799bdea12a49c9199587dc67317d8b");
}

TEST_F(QreTest, CountsDistinctPinnedKeysOnOneStatement) {
  EXPECT_EQ(inspect({}).status, Status::Insufficient);
  auto two = votes({0, 1});
  EXPECT_EQ(inspect({two, two, votes({0})}).status, Status::Insufficient);
  auto exact = inspect({two, votes({2})});
  ASSERT_EQ(exact.status, Status::Quorum) << exact.reason;
  ASSERT_EQ(exact.groups.size(), 1u);
  EXPECT_EQ(exact.groups[0].statementId, statementId(ctx, branch));
  EXPECT_EQ(exact.groups[0].observationHash, filled(0x66));
  EXPECT_EQ(exact.groups[0].referenceHash, filled(0x77));
  EXPECT_EQ(exact.groups[0].signers.size(), 3u);
  EXPECT_EQ(inspect({votes({0, 1, 2, 3})}).status, Status::Quorum);

  auto other = statement(0x78);
  EXPECT_EQ(inspect({two, delivery({2, 3}, other, now)}).status, Status::Insufficient);
  auto minority = inspect({votes({0, 1, 2}), delivery({3}, other, now)});
  ASSERT_EQ(minority.status, Status::Quorum) << minority.reason;
  EXPECT_EQ(minority.groups.size(), 2u);
  auto conflict = inspect({votes({0, 1, 2}), delivery({0}, other, now)});
  ASSERT_EQ(conflict.status, Status::Equivocation) << conflict.reason;
  ASSERT_EQ(conflict.equivocators.size(), 1u);
  EXPECT_EQ(conflict.equivocators[0], digest("key", keys()[0].first));
}

TEST_F(QreTest, EvidenceIdentityIsIndependentOfFrameOrderAndRepeatedSignatures) {
  auto signedPair = votes({1, 2});
  auto later = votes({0});
  auto earlier = delivery({0}, branch, now - 1);
  auto first = inspect({later, signedPair, earlier});
  auto second = inspect({earlier, votes({0}), signedPair});
  ASSERT_EQ(first.status, Status::Quorum);
  ASSERT_EQ(second.status, Status::Quorum);
  ASSERT_EQ(first.groups.size(), 1u);
  ASSERT_EQ(second.groups.size(), 1u);
  std::vector<std::pair<Hash, uint64_t>> records;
  for (size_t i = 0; i < 3; ++i) records.emplace_back(digest("key", keys()[i].first), i == 0 ? now - 1 : now);
  std::sort(records.begin(), records.end());
  Bytes proof;
  append(proof, statementId(ctx, branch));
  proof.push_back(3);
  for (const auto& record : records) {
    append(proof, record.first);
    littleEndian(proof, record.second);
  }
  EXPECT_EQ(first.groups[0].evidenceId, digest("evidence", proof));
  EXPECT_EQ(first.groups[0].evidenceId, second.groups[0].evidenceId);
}

TEST_F(QreTest, RefusesNoncanonicalFramesAndDiscardsPartialResults) {
  auto one = votes({0});
  ASSERT_EQ(one.size(), 3640u);
  for (size_t length = one.size(); length-- > 0;) {
    one.resize(length);
    ASSERT_EQ(inspect({one}).status, Status::Invalid) << length;
  }
  one = votes({0});
  one.push_back(0);
  EXPECT_EQ(inspect({one}).status, Status::Invalid);
  auto two = votes({0, 1});
  constexpr size_t start = 291, stride = 3349;
  std::swap_ranges(two.begin() + start, two.begin() + start + stride, two.begin() + start + stride);
  EXPECT_EQ(inspect({two}).status, Status::Invalid);
  EXPECT_EQ(inspect({votes({1, 1})}).status, Status::Invalid);
  auto valid = votes({0, 1, 2});
  for (size_t offset : {size_t{0}, size_t{2}, size_t{226}, size_t{258},
                        size_t{290}, size_t{291}, size_t{323}, valid.size() - 1}) {
    auto damaged = valid;
    damaged[offset] ^= 1;
    auto result = inspect({valid, damaged});
    EXPECT_EQ(result.status, Status::Invalid) << offset;
    EXPECT_TRUE(result.groups.empty()) << offset;
    EXPECT_TRUE(result.equivocators.empty()) << offset;
  }
}

TEST_F(QreTest, RefusesWrongContextAndPolicy) {
  auto valid = votes({0, 1, 2});
  for (size_t offset : {2, 18, 50, 82, 90, 98, 130, 134, 166, 170, 202, 206, 210, 218}) {
    auto changed = ctx;
    changed[offset] ^= 1;
    EXPECT_EQ(Qre::inspect(pinned, changed, {valid}, now).status, Status::Invalid) << offset;
  }
  for (auto threshold : {2, 4}) {
    auto bad = pinned;
    bad[3] = static_cast<uint8_t>(threshold);
    EXPECT_EQ(Qre::inspect(bad, context(bad), {}, now).status, Status::Invalid);
  }
  for (const auto& unusable : {policy(false, 2, 32), policy(false, 64, 2)}) {
    EXPECT_EQ(Qre::inspect(unusable, context(unusable), {}, now).status, Status::Invalid);
  }
  auto duplicate = pinned;
  std::copy_n(duplicate.begin() + 25, CryptoPQ::kDsaPublicKeyBytes,
              duplicate.begin() + 25 + CryptoPQ::kDsaPublicKeyBytes);
  EXPECT_EQ(Qre::inspect(duplicate, context(duplicate), {}, now).status, Status::Invalid);
  auto overflow = context(pinned, startTime, std::numeric_limits<uint32_t>::max() - 4, 5);
  EXPECT_EQ(Qre::inspect(pinned, overflow, {}, now).status, Status::Invalid);
  auto tooShallow = context(pinned, startTime, 115, 124);
  EXPECT_EQ(Qre::inspect(pinned, tooShallow, {}, now).status, Status::Invalid);
}

TEST_F(QreTest, EnforcesClockBoundsAndWorkLimits) {
  auto fresh = votes({0, 1, 2});
  EXPECT_EQ(Qre::inspect(pinned, ctx, {fresh}, startTime - 1).status, Status::Invalid);
  EXPECT_EQ(Qre::inspect(pinned, ctx, {fresh}, startTime + 60).status, Status::Invalid);
  EXPECT_EQ(inspect({delivery({0}, branch, startTime - 1)}).status, Status::Invalid);
  EXPECT_EQ(inspect({delivery({0}, branch, startTime + 60)}).status, Status::Invalid);
  EXPECT_EQ(inspect({delivery({0}, branch, now + 6)}).status, Status::Invalid);
  EXPECT_EQ(inspect({delivery({0}, branch, now + 5)}).status, Status::Insufficient);
  EXPECT_EQ(inspect(std::vector<Bytes>(33, votes({0}))).status, Status::Invalid);
  EXPECT_EQ(inspect(std::vector<Bytes>(65, votes({0}))).status, Status::Invalid);
  auto lowQuota = policy(false, 3);
  auto request = context(lowQuota);
  std::vector<Bytes> four;
  for (size_t i = 0; i < 4; ++i) four.push_back(envelope(request, branch, i, now));
  EXPECT_EQ(Qre::inspect(lowQuota, request, {bundle(request, branch, four)}, now).status,
            Status::Invalid);
}

TEST_F(QreTest, AuthenticatedAgeOutPreservesEquivocationEvidence) {
  pinned = policy(false, 64, 32, 10);
  ctx = context(pinned);
  const auto quorum = votes({0, 1, 2});
  const auto other = statement(0x78);
  auto staleDissent = delivery({3}, other, now - 11);
  auto staleConflict = delivery({0}, other, now - 11);
  EXPECT_EQ(inspect({delivery({0, 1, 2}, branch, now - 10)}).status, Status::Quorum);
  EXPECT_EQ(inspect({delivery({0, 1, 2}, branch, now - 11)}).status, Status::Insufficient);
  EXPECT_EQ(inspect({quorum, staleDissent}).status, Status::Quorum);
  EXPECT_EQ(inspect({quorum, staleConflict}).status, Status::Equivocation);
  EXPECT_EQ(inspect({staleConflict, quorum}).status, Status::Equivocation);
  staleConflict.back() ^= 1;
  auto invalid = inspect({staleConflict, quorum});
  EXPECT_EQ(invalid.status, Status::Invalid);
  EXPECT_TRUE(invalid.groups.empty());
}

void writeFixture(const std::string& path, const Bytes& data) {
  std::ofstream out(path, std::ios::binary);
  out.exceptions(std::ios::badbit | std::ios::failbit);
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  out.close();
}

void writeCliFixtures(const std::string& dir) {
  const auto now = static_cast<uint64_t>(std::time(nullptr));
  auto pinned = policy(false, 64, 32, 3600, 3600);
  auto ctx = context(pinned, now - 3, 115, 125, 3600);
  auto branch = statement();
  writeFixture(dir + "/policy", pinned);
  writeFixture(dir + "/context", ctx);
  for (size_t i = 0; i < 3; ++i)
    writeFixture(dir + "/vote" + std::to_string(i), bundle(ctx, branch, {envelope(ctx, branch, i, now)}));
  auto other = statement(0x78);
  writeFixture(dir + "/other", bundle(ctx, other, {envelope(ctx, other, 0, now)}));
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 3 && std::string(argv[1]) == "--write-cli-fixtures") {
    writeCliFixtures(argv[2]);
    return 0;
  }
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
