// Copyright (c) 2026, The Discrete developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>

#include "Wallet/SentPaymentsStore.h"

namespace {

template <typename T>
void appendNative(std::string& bytes, T value) {
  bytes.append(reinterpret_cast<const char*>(&value), sizeof(value));
}

Crypto::Hash hashWithByte(uint8_t value) {
  Crypto::Hash hash{};
  std::memset(hash.data, value, sizeof(hash.data));
  return hash;
}

std::string oneRecordPrefix(const Crypto::Hash& txid, uint32_t recipients) {
  std::string bytes;
  appendNative<uint8_t>(bytes, 1);
  appendNative<uint64_t>(bytes, 1);
  bytes.append(reinterpret_cast<const char*>(txid.data), sizeof(txid.data));
  appendNative<uint32_t>(bytes, recipients);
  return bytes;
}

void appendEntry(std::string& bytes, const std::string& address,
                 uint64_t amount, const std::string& proof) {
  appendNative<uint64_t>(bytes, address.size());
  bytes.append(address);
  appendNative<uint64_t>(bytes, amount);
  appendNative<uint64_t>(bytes, proof.size());
  bytes.append(proof);
}

CryptoNote::SentPaymentRecord sampleRecord(const std::string& address) {
  CryptoNote::SentPaymentRecord record;
  record.recipients.push_back({address, 42, "proof"});
  return record;
}

bool loadBytes(CryptoNote::SentPaymentsStore& store, const std::string& bytes,
               std::string* error = nullptr) {
  std::stringstream stream(bytes);
  return store.load(stream, error);
}

TEST(SentPaymentsStore, RoundTripsAndAcceptsSixtyFourRecipients) {
  CryptoNote::SentPaymentsStore original;
  CryptoNote::SentPaymentRecord record;
  for (uint32_t i = 0; i < 64; ++i) {
    record.recipients.push_back({"address-" + std::to_string(i), i, "proof"});
  }
  ASSERT_TRUE(original.recordChecked(hashWithByte(1), record));

  std::stringstream encoded;
  original.save(encoded);
  CryptoNote::SentPaymentsStore decoded;
  std::string error;
  ASSERT_TRUE(decoded.load(encoded, &error)) << error;
  ASSERT_EQ(decoded.size(), 1u);
  const auto* found = decoded.find(hashWithByte(1));
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->recipients.size(), 64u);
  EXPECT_EQ(found->recipients.back().address, "address-63");
}

TEST(SentPaymentsStore, RejectionDoesNotDestroyExistingEvidence) {
  CryptoNote::SentPaymentsStore store;
  ASSERT_TRUE(store.recordChecked(hashWithByte(9), sampleRecord("preserve-me")));

  std::string oversizedCount;
  appendNative<uint8_t>(oversizedCount, 1);
  appendNative<uint64_t>(oversizedCount, 100001);
  std::string error;
  EXPECT_FALSE(loadBytes(store, oversizedCount, &error));
  EXPECT_NE(error.find("record count"), std::string::npos);
  const auto* preserved = store.find(hashWithByte(9));
  ASSERT_NE(preserved, nullptr);
  EXPECT_EQ(preserved->recipients.front().address, "preserve-me");
}

TEST(SentPaymentsStore, RejectsUnserializableRecordsBeforeInsertion) {
  CryptoNote::SentPaymentsStore store;
  CryptoNote::SentPaymentRecord tooMany;
  tooMany.recipients.resize(65);
  EXPECT_FALSE(store.recordChecked(hashWithByte(10), tooMany));
  EXPECT_TRUE(store.empty());

  CryptoNote::SentPaymentRecord oversizedAddress;
  oversizedAddress.recipients.push_back(
      {std::string(16 * 1024 + 1, 'a'), 1, "proof"});
  EXPECT_FALSE(store.recordChecked(hashWithByte(11), oversizedAddress));
  EXPECT_TRUE(store.empty());

  ASSERT_TRUE(store.recordChecked(hashWithByte(12), sampleRecord("valid")));
  EXPECT_TRUE(store.remove(hashWithByte(12)));
  EXPECT_TRUE(store.recordChecked(hashWithByte(13), sampleRecord("replacement")));
  std::stringstream encoded;
  EXPECT_NO_THROW(store.save(encoded));
}

TEST(SentPaymentsStore, RejectsOversizedRecipientCountBeforeReserve) {
  CryptoNote::SentPaymentsStore store;
  std::string error;
  EXPECT_FALSE(loadBytes(store, oneRecordPrefix(hashWithByte(2), 65), &error));
  EXPECT_NE(error.find("recipient count"), std::string::npos);
}

TEST(SentPaymentsStore, RejectsOversizedStringsWithoutAllocatingThem) {
  CryptoNote::SentPaymentsStore store;
  std::string bytes = oneRecordPrefix(hashWithByte(3), 1);
  appendNative<uint64_t>(bytes, 16 * 1024 + 1);
  std::string error;
  EXPECT_FALSE(loadBytes(store, bytes, &error));
  EXPECT_NE(error.find("address"), std::string::npos);

  bytes = oneRecordPrefix(hashWithByte(3), 1);
  appendNative<uint64_t>(bytes, 1);
  bytes.push_back('a');
  appendNative<uint64_t>(bytes, 7);
  appendNative<uint64_t>(bytes, 1024 * 1024 + 1);
  EXPECT_FALSE(loadBytes(store, bytes, &error));
  EXPECT_NE(error.find("proof"), std::string::npos);
}

TEST(SentPaymentsStore, RejectsDuplicateTransactionIds) {
  const Crypto::Hash txid = hashWithByte(4);
  std::string bytes;
  appendNative<uint8_t>(bytes, 1);
  appendNative<uint64_t>(bytes, 2);
  for (int i = 0; i < 2; ++i) {
    bytes.append(reinterpret_cast<const char*>(txid.data), sizeof(txid.data));
    appendNative<uint32_t>(bytes, 1);
    appendEntry(bytes, "address", 1, "proof");
  }
  CryptoNote::SentPaymentsStore store;
  std::string error;
  EXPECT_FALSE(loadBytes(store, bytes, &error));
  EXPECT_NE(error.find("duplicate"), std::string::npos);
}

TEST(SentPaymentsStore, RejectsTruncationTrailingDataAndUnknownVersion) {
  CryptoNote::SentPaymentsStore store;
  std::string valid = oneRecordPrefix(hashWithByte(5), 1);
  appendEntry(valid, "address", 1, "proof");

  std::string error;
  EXPECT_FALSE(loadBytes(store, valid.substr(0, valid.size() - 1), &error));
  EXPECT_FALSE(loadBytes(store, valid + "x", &error));

  std::string unknown = valid;
  unknown[0] = 2;
  EXPECT_FALSE(loadBytes(store, unknown, &error));
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
