// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Regression tests for the wallet key-derivation and container-encryption
// contract.

#include "gtest/gtest.h"

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "Wallet/WalletIndices.h"
#include "crypto/chacha8.h"

namespace {

Crypto::Hash makeSalt(uint8_t base) {
  Crypto::Hash salt{};
  for (std::size_t i = 0; i < sizeof(salt.data); ++i) {
    salt.data[i] = static_cast<uint8_t>(base * 7 + i);
  }
  return salt;
}

// RAII guard so a forced-failure test can never leak the flag into its neighbours.
struct ForcedKdfFailure {
  ForcedKdfFailure() { Crypto::kdf_forced_failure() = true; }
  ~ForcedKdfFailure() { Crypto::kdf_forced_failure() = false; }
};

}  // namespace

// --- KDF failure must be reported, never silently keyed --------------------

TEST(WalletKdf, FailureIsReportedAndKeyIsNotTheSentinel) {
  Crypto::chacha8_key key;
  std::memset(&key, 0x5A, sizeof(key));

  ForcedKdfFailure forced;
  Crypto::cn_context context;
  EXPECT_FALSE(Crypto::generate_chacha8_key(context, "correct horse", key));

  // yespower writes an all-0xFF binary on failure. That value is public, so it
  // must never survive as an encryption key.
  Crypto::chacha8_key sentinel;
  std::memset(&sentinel, 0xFF, sizeof(sentinel));
  EXPECT_NE(0, std::memcmp(&key, &sentinel, sizeof(key)));

  Crypto::chacha8_key zero;
  std::memset(&zero, 0, sizeof(zero));
  EXPECT_EQ(0, std::memcmp(&key, &zero, sizeof(key)));
}

TEST(WalletKdf, SucceedsWhenNotForcedToFail) {
  Crypto::chacha8_key key;
  Crypto::cn_context context;
  ASSERT_TRUE(Crypto::generate_chacha8_key(context, "correct horse", key));

  Crypto::chacha8_key sentinel;
  std::memset(&sentinel, 0xFF, sizeof(sentinel));
  EXPECT_NE(0, std::memcmp(&key, &sentinel, sizeof(key)));
}

// --- Salted derivation -----------------------------------------------------

TEST(WalletKdf, SamePasswordDifferentSaltDerivesDifferentKeys) {
  const std::string password = "shared password";
  Crypto::Hash sa = makeSalt(1), sb = makeSalt(2);
  ASSERT_NE(0, std::memcmp(sa.data, sb.data, sizeof(sa.data)));

  Crypto::chacha8_key a, b;
  ASSERT_TRUE(Crypto::generate_chacha8_key_salted(password, sa, a));
  ASSERT_TRUE(Crypto::generate_chacha8_key_salted(password, sb, b));
  EXPECT_NE(0, std::memcmp(&a, &b, sizeof(a)));
}

TEST(WalletKdf, SaltedDerivationDiffersFromLegacyUnsalted) {
  // An all-zero salt must not collapse onto the legacy password-only input, or a
  // migrated wallet would keep its pre-migration key.
  const std::string password = "shared password";
  Crypto::Hash zeroSalt{};
  Crypto::chacha8_key salted, legacy;
  ASSERT_TRUE(Crypto::generate_chacha8_key_salted(password, zeroSalt, salted));
  Crypto::cn_context context;
  ASSERT_TRUE(Crypto::generate_chacha8_key(context, password, legacy));
  EXPECT_NE(0, std::memcmp(&salted, &legacy, sizeof(salted)));
}

TEST(WalletKdf, SamePasswordSameSaltIsDeterministic) {
  const std::string password = "shared password";
  Crypto::chacha8_key a, b;
  ASSERT_TRUE(Crypto::generate_chacha8_key_salted(password, makeSalt(3), a));
  ASSERT_TRUE(Crypto::generate_chacha8_key_salted(password, makeSalt(3), b));
  EXPECT_EQ(0, std::memcmp(&a, &b, sizeof(a)));
}

TEST(WalletKdf, SaltedFailureAlsoZeroesTheKey) {
  Crypto::chacha8_key key;
  std::memset(&key, 0x5A, sizeof(key));

  ForcedKdfFailure forced;
  EXPECT_FALSE(Crypto::generate_chacha8_key_salted("pw", makeSalt(4), key));

  Crypto::chacha8_key zero;
  std::memset(&zero, 0, sizeof(zero));
  EXPECT_EQ(0, std::memcmp(&key, &zero, sizeof(key)));
}


// --- Authenticated seed records -------------------------------------------

namespace {

CryptoPQ::SeedMaster makeSeed(uint8_t base) {
  CryptoPQ::SeedMaster seed{};
  for (std::size_t i = 0; i < seed.size(); ++i) {
    seed[i] = static_cast<uint8_t>(base + i);
  }
  return seed;
}

}  // namespace

class SeedRecordTest : public ::testing::Test {
protected:
  void SetUp() override {
    header = CryptoNote::makeContainerHeader();
    ASSERT_TRUE(CryptoNote::deriveContainerKey("pw", header, key));
  }

  CryptoNote::ContainerStoragePrefix header{};
  Crypto::chacha8_key key{};
};

TEST_F(SeedRecordTest, RoundTrips) {
  const CryptoPQ::SeedMaster seed = makeSeed(11);
  CryptoNote::EncryptedWalletRecord record =
      CryptoNote::encryptSeedRecord(seed, 1234, key, header);

  CryptoPQ::SeedMaster out{};
  uint64_t timestamp = 0;
  ASSERT_TRUE(CryptoNote::decryptSeedRecord(record, out, timestamp, key, header));
  EXPECT_EQ(seed, out);
  EXPECT_EQ(1234u, timestamp);
}

TEST_F(SeedRecordTest, WrongPasswordIsRejected) {
  CryptoNote::EncryptedWalletRecord record =
      CryptoNote::encryptSeedRecord(makeSeed(11), 1234, key, header);

  Crypto::chacha8_key other{};
  ASSERT_TRUE(CryptoNote::deriveContainerKey("other pw", header, other));

  CryptoPQ::SeedMaster out{};
  uint64_t timestamp = 0;
  EXPECT_FALSE(CryptoNote::decryptSeedRecord(record, out, timestamp, other, header));
}

TEST_F(SeedRecordTest, TamperedCiphertextIsRejected) {
  CryptoNote::EncryptedWalletRecord record =
      CryptoNote::encryptSeedRecord(makeSeed(11), 1234, key, header);
  record.data[0] ^= 0x01;

  CryptoPQ::SeedMaster out{};
  uint64_t timestamp = 0;
  EXPECT_FALSE(CryptoNote::decryptSeedRecord(record, out, timestamp, key, header));
}

TEST_F(SeedRecordTest, TamperedTagIsRejected) {
  CryptoNote::EncryptedWalletRecord record =
      CryptoNote::encryptSeedRecord(makeSeed(11), 1234, key, header);
  record.data[sizeof(record.data) - 1] ^= 0x01;

  CryptoPQ::SeedMaster out{};
  uint64_t timestamp = 0;
  EXPECT_FALSE(CryptoNote::decryptSeedRecord(record, out, timestamp, key, header));
}

TEST_F(SeedRecordTest, TamperedNonceIsRejected) {
  CryptoNote::EncryptedWalletRecord record =
      CryptoNote::encryptSeedRecord(makeSeed(11), 1234, key, header);
  record.nonce[0] ^= 0x01;

  CryptoPQ::SeedMaster out{};
  uint64_t timestamp = 0;
  EXPECT_FALSE(CryptoNote::decryptSeedRecord(record, out, timestamp, key, header));
}

TEST_F(SeedRecordTest, EditedHeaderFieldsAreRejected) {
  CryptoNote::EncryptedWalletRecord record =
      CryptoNote::encryptSeedRecord(makeSeed(11), 1234, key, header);

  CryptoPQ::SeedMaster out{};
  uint64_t timestamp = 0;

  // Each protected field on its own. The key is unchanged in every case; it is
  // the associated data that fails.
  CryptoNote::ContainerStoragePrefix forged = header;
  forged.version ^= 1;
  EXPECT_FALSE(CryptoNote::decryptSeedRecord(record, out, timestamp, key, forged));

  forged = header;
  forged.kdf ^= 1;
  EXPECT_FALSE(CryptoNote::decryptSeedRecord(record, out, timestamp, key, forged));

  forged = header;
  forged.kdfN ^= 1;
  EXPECT_FALSE(CryptoNote::decryptSeedRecord(record, out, timestamp, key, forged));

  forged = header;
  forged.kdfR ^= 1;
  EXPECT_FALSE(CryptoNote::decryptSeedRecord(record, out, timestamp, key, forged));

  forged = header;
  forged.salt[0] ^= 1;
  EXPECT_FALSE(CryptoNote::decryptSeedRecord(record, out, timestamp, key, forged));
}

TEST_F(SeedRecordTest, EveryEncryptionDrawsAFreshNonce) {
  // Re-encrypting the same seed under the same key is exactly what a rescan does
  // to every record in the container, right before the cache blob is rewritten.
  // A repeat would put two plaintexts under one keystream.
  const CryptoPQ::SeedMaster seed = makeSeed(11);
  std::set<std::vector<uint8_t> > nonces;
  for (int i = 0; i < 64; ++i) {
    CryptoNote::EncryptedWalletRecord record =
        CryptoNote::encryptSeedRecord(seed, 1234, key, header);
    std::vector<uint8_t> nonce(std::begin(record.nonce), std::end(record.nonce));
    EXPECT_TRUE(nonces.insert(nonce).second) << "nonce reused on iteration " << i;
  }
}

// --- Authenticated cache blob ---------------------------------------------

TEST_F(SeedRecordTest, CacheBlobRoundTripsAndDetectsTampering) {
  const std::string plain = "wallet cache contents";
  std::vector<uint8_t> sealed =
      CryptoNote::encryptContainerBlob(plain.data(), plain.size(), key, header);

  std::vector<uint8_t> out;
  ASSERT_TRUE(CryptoNote::decryptContainerBlob(sealed.data(), sealed.size(), key, header, out));
  EXPECT_EQ(plain, std::string(out.begin(), out.end()));

  // A stream cipher with no tag would hand back flipped plaintext here instead of
  // refusing.
  std::vector<uint8_t> tampered = sealed;
  tampered[tampered.size() - 1] ^= 0x01;
  EXPECT_FALSE(CryptoNote::decryptContainerBlob(tampered.data(), tampered.size(), key, header, out));

  tampered = sealed;
  tampered[CryptoPQ::kAeadNonceBytes] ^= 0x01;
  EXPECT_FALSE(CryptoNote::decryptContainerBlob(tampered.data(), tampered.size(), key, header, out));

  CryptoNote::ContainerStoragePrefix forged = header;
  forged.salt[3] ^= 1;
  EXPECT_FALSE(CryptoNote::decryptContainerBlob(sealed.data(), sealed.size(), key, forged, out));
}

TEST_F(SeedRecordTest, CacheAndRecordsUseSeparateDomains) {
  // A record must not be interchangeable with a cache blob under the same key.
  const CryptoPQ::SeedMaster seed = makeSeed(11);
  CryptoNote::EncryptedWalletRecord record =
      CryptoNote::encryptSeedRecord(seed, 1234, key, header);

  std::vector<uint8_t> asBlob;
  asBlob.insert(asBlob.end(), std::begin(record.nonce), std::end(record.nonce));
  asBlob.insert(asBlob.end(), std::begin(record.data), std::end(record.data));

  std::vector<uint8_t> out;
  EXPECT_FALSE(CryptoNote::decryptContainerBlob(asBlob.data(), asBlob.size(), key, header, out));
}

// --- Per-wallet salt -------------------------------------------------------

TEST(ContainerHeader, FreshHeadersCarryDistinctSalts) {
  CryptoNote::ContainerStoragePrefix a = CryptoNote::makeContainerHeader();
  CryptoNote::ContainerStoragePrefix b = CryptoNote::makeContainerHeader();
  EXPECT_NE(0, std::memcmp(a.salt, b.salt, sizeof(a.salt)));
  EXPECT_EQ(CryptoNote::WALLET_CONTAINER_VERSION, a.version);
  EXPECT_EQ(CryptoNote::WALLET_KDF_YESPOWER_SALTED, a.kdf);
}

TEST(ContainerHeader, SamePasswordInTwoWalletsGivesDifferentKeys) {
  CryptoNote::ContainerStoragePrefix a = CryptoNote::makeContainerHeader();
  CryptoNote::ContainerStoragePrefix b = CryptoNote::makeContainerHeader();

  Crypto::chacha8_key ka, kb;
  ASSERT_TRUE(CryptoNote::deriveContainerKey("same password", a, ka));
  ASSERT_TRUE(CryptoNote::deriveContainerKey("same password", b, kb));
  EXPECT_NE(0, std::memcmp(&ka, &kb, sizeof(ka)));

  // And a record from one wallet does not open under the other's key.
  CryptoNote::EncryptedWalletRecord record =
      CryptoNote::encryptSeedRecord(makeSeed(3), 99, ka, a);
  CryptoPQ::SeedMaster out{};
  uint64_t timestamp = 0;
  EXPECT_FALSE(CryptoNote::decryptSeedRecord(record, out, timestamp, kb, b));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
