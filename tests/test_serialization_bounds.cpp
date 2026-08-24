// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Regression tests for wire-supplied container counts. A peer controls the
// element count of every vector/map in a transaction or block, and that count
// used to size the container before a single element was read — so a blob of a
// few dozen bytes could ask a node to allocate gigabytes. These tests pin the
// bound: a count must be backed by real input, and a count that does not fit
// size_t is rejected rather than truncated.

#include "gtest/gtest.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <new>
#include <limits>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Common/MemoryInputStream.h"
#include "Common/StringOutputStream.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/SerializationOverloads.h"

using namespace CryptoNote;

namespace {

// Little-endian base-128 varint, the encoding every container count uses.
void appendVarint(std::vector<uint8_t>& out, uint64_t value) {
  while (value >= 0x80) {
    out.push_back(static_cast<uint8_t>((value & 0x7F) | 0x80));
    value >>= 7;
  }
  out.push_back(static_cast<uint8_t>(value));
}

// std::vector has no member serialize(), and the free overload lives in
// namespace CryptoNote, so call it explicitly rather than through operator().
template <typename T>
bool tryDeserializeVector(const std::vector<uint8_t>& blob, std::vector<T>& out) {
  try {
    Common::MemoryInputStream stream(blob.data(), blob.size());
    BinaryInputStreamSerializer serializer(stream);
    return CryptoNote::serialize(out, "arr", serializer);
  } catch (const std::exception&) {
    return false;
  }
}

template <typename T>
std::vector<uint8_t> serializeVector(std::vector<T>& in) {
  std::string out;
  Common::StringOutputStream stream(out);
  BinaryOutputStreamSerializer serializer(stream);
  CryptoNote::serialize(in, "arr", serializer);
  return std::vector<uint8_t>(out.begin(), out.end());
}


// A vector allocator that records the largest single request it is asked for and
// refuses anything wild. It makes the "does the parser size the container from
// the declared count?" question directly observable instead of inferring it from
// timing: a parser that pre-sizes asks for count * sizeof(T) up front, a parser
// that grows with the input never asks for more than it has decoded.
std::size_t g_peakRequestBytes = 0;
constexpr std::size_t kAllocatorRefusalBytes = 64u << 20;

template <typename T>
struct TrackingAllocator {
  using value_type = T;

  TrackingAllocator() = default;
  template <typename U> TrackingAllocator(const TrackingAllocator<U>&) {}

  T* allocate(std::size_t n) {
    const std::size_t bytes = n * sizeof(T);
    g_peakRequestBytes = std::max(g_peakRequestBytes, bytes);
    if (bytes > kAllocatorRefusalBytes) {
      throw std::bad_alloc();
    }
    return static_cast<T*>(::operator new(bytes));
  }

  void deallocate(T* p, std::size_t) { ::operator delete(p); }

  template <typename U> bool operator==(const TrackingAllocator<U>&) const { return true; }
  template <typename U> bool operator!=(const TrackingAllocator<U>&) const { return false; }
};

using TrackedHashes = std::vector<Crypto::Hash, TrackingAllocator<Crypto::Hash>>;

bool tryDeserializeTracked(const std::vector<uint8_t>& blob, TrackedHashes& out) {
  try {
    Common::MemoryInputStream stream(blob.data(), blob.size());
    BinaryInputStreamSerializer serializer(stream);
    return CryptoNote::serializeContainer(out, "arr", serializer);
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace

// --- Raw container counts --------------------------------------------------

TEST(SerializationBounds, HugeCountIsNotPreAllocated) {
  // 6 bytes claiming 2^40 32-byte hashes: 32 TiB if the count were believed.
  std::vector<uint8_t> blob;
  appendVarint(blob, uint64_t(1) << 40);
  blob.insert(blob.end(), 4, 0x00);

  g_peakRequestBytes = 0;
  TrackedHashes hashes;
  EXPECT_FALSE(tryDeserializeTracked(blob, hashes));
  EXPECT_LT(g_peakRequestBytes, std::size_t(1) << 20)
      << "the declared element count was allocated before any element was read";
  EXPECT_TRUE(hashes.empty());
}

TEST(SerializationBounds, HugeVectorCountIsRejectedWithoutAllocating) {
  std::vector<uint8_t> blob;
  appendVarint(blob, uint64_t(1) << 60);
  blob.insert(blob.end(), 4, 0x00);

  std::vector<Crypto::Hash> hashes;
  const auto start = std::chrono::steady_clock::now();
  EXPECT_FALSE(tryDeserializeVector(blob, hashes));
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
  EXPECT_TRUE(hashes.empty());
}

TEST(SerializationBounds, CountBeyondSizeTypeIsRejected) {
  std::vector<uint8_t> blob;
  appendVarint(blob, std::numeric_limits<uint64_t>::max());
  blob.insert(blob.end(), 4, 0x00);

  std::vector<Crypto::Hash> hashes;
  EXPECT_FALSE(tryDeserializeVector(blob, hashes));
}

TEST(SerializationBounds, CountJustBeyondAvailableBytesIsRejected) {
  // Declares one more element than the blob can supply.
  std::vector<uint8_t> blob;
  appendVarint(blob, 3);
  for (int i = 0; i < 2; ++i) {
    blob.insert(blob.end(), sizeof(Crypto::Hash), static_cast<uint8_t>(i));
  }

  std::vector<Crypto::Hash> hashes;
  EXPECT_FALSE(tryDeserializeVector(blob, hashes));
}

TEST(SerializationBounds, HonestCountStillFillsTheContainer) {
  // Same tracked container, an honest count: the elements must all arrive, so
  // the bound is a pre-allocation cap and not a size limit.
  TrackedHashes original(2000);
  for (std::size_t i = 0; i < original.size(); ++i) {
    for (std::size_t j = 0; j < sizeof(Crypto::Hash); ++j) {
      original[i].data[j] = static_cast<uint8_t>(i + j);
    }
  }
  std::string out;
  Common::StringOutputStream stream(out);
  BinaryOutputStreamSerializer writer(stream);
  ASSERT_TRUE(CryptoNote::serializeContainer(original, "arr", writer));

  TrackedHashes restored;
  ASSERT_TRUE(tryDeserializeTracked(std::vector<uint8_t>(out.begin(), out.end()), restored));
  ASSERT_EQ(original.size(), restored.size());
  EXPECT_EQ(0, std::memcmp(original.back().data, restored.back().data, sizeof(Crypto::Hash)));
}

TEST(SerializationBounds, WellFormedVectorStillRoundTrips) {
  std::vector<Crypto::Hash> original(3);
  for (size_t i = 0; i < original.size(); ++i) {
    for (size_t j = 0; j < sizeof(Crypto::Hash); ++j) {
      original[i].data[j] = static_cast<uint8_t>(i * 31 + j);
    }
  }
  const std::vector<uint8_t> blob = serializeVector(original);

  std::vector<Crypto::Hash> restored;
  ASSERT_TRUE(tryDeserializeVector(blob, restored));
  ASSERT_EQ(original.size(), restored.size());
  for (size_t i = 0; i < original.size(); ++i) {
    EXPECT_EQ(0, std::memcmp(original[i].data, restored[i].data, sizeof(Crypto::Hash)));
  }
}

TEST(SerializationBounds, LargeButHonestVectorIsAccepted) {
  // Well past the pre-allocation cap: the bound must not become a size limit.
  std::vector<uint32_t> original(50000);
  for (size_t i = 0; i < original.size(); ++i) {
    original[i] = static_cast<uint32_t>(i);
  }
  const std::vector<uint8_t> blob = serializeVector(original);

  std::vector<uint32_t> restored;
  ASSERT_TRUE(tryDeserializeVector(blob, restored));
  ASSERT_EQ(original.size(), restored.size());
  EXPECT_EQ(original.back(), restored.back());
}

// --- Whole protocol objects ------------------------------------------------

TEST(SerializationBounds, TinyTransactionBlobWithHugeInputCountIsRejected) {
  // version | txType | unlockHeight | inputs count ... then nothing.
  std::vector<uint8_t> blob;
  appendVarint(blob, 2);                    // transaction version
  blob.push_back(0x01);                     // txType TX_PQ
  appendVarint(blob, 0);                    // unlockHeight
  appendVarint(blob, uint64_t(1) << 55);    // inputs

  Transaction tx;
  const auto start = std::chrono::steady_clock::now();
  EXPECT_FALSE(fromBinaryArray(tx, BinaryArray(blob.begin(), blob.end())));
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
}

TEST(SerializationBounds, TinyBlockBlobWithHugeTransactionCountIsRejected) {
  std::vector<uint8_t> blob;
  appendVarint(blob, 1);                    // majorVersion
  appendVarint(blob, 0);                    // minorVersion
  blob.insert(blob.end(), 32, 0x00);        // previousBlockHash
  appendVarint(blob, uint64_t(1) << 55);    // some later count

  Block block;
  const auto start = std::chrono::steady_clock::now();
  EXPECT_FALSE(fromBinaryArray(block, BinaryArray(blob.begin(), blob.end())));
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
