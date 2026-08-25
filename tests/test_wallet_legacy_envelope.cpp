// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// The simplewallet file format. Versions 1-3 encrypted with raw ChaCha8 under a
// key derived from the password alone: no authentication tag, so anyone who
// could write the file could flip chosen bits of the decrypted plaintext, and no
// salt, so one key derivation served every wallet with that password.
//
// These tests pin the replacement envelope and the compatibility it has to keep:
// old files still open, new files are salted and authenticated, and a file saved
// after opening an old one has been upgraded.

#include "gtest/gtest.h"

#include <cstring>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <utility>

#include "CryptoNoteCore/Account.h"
#include "Wallet/WalletErrors.h"
#include "Wallet/MiningKeyLoader.h"
#include "Common/StdOutputStream.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "WalletLegacy/KeysStorage.h"
#include "WalletLegacy/WalletLegacySerializer.h"
#include "crypto/crypto-util.h"
#include "crypto_pq/PqAead.h"
#include "Logging/ConsoleLogger.h"

using namespace CryptoNote;

namespace {

// A PQ simplewallet account: the master seed IS the spend secret, and
// cn_fast_hash(seed) sits in the spend public slot as the integrity check.
AccountBase makeAccount(uint8_t base) {
  Crypto::SecretKey seed;
  for (std::size_t i = 0; i < sizeof(seed.data); ++i) {
    seed.data[i] = static_cast<uint8_t>(base * 13 + i);
  }

  AccountKeys keys{};
  keys.spendSecretKey = seed;
  Crypto::Hash checksum;
  Crypto::cn_fast_hash(seed.data, sizeof(seed.data), checksum);
  std::memcpy(keys.address.spendPublicKey.data, checksum.data, sizeof(checksum.data));

  AccountBase account;
  account.setAccountKeys(keys);
  account.set_createtime(1700000000);
  return account;
}

std::string saveWallet(AccountBase& account, const std::string& password,
                       const std::string& cache, uint32_t contentVersion) {
  WalletLegacySerializer serializer(account, contentVersion);
  std::stringstream out;
  serializer.serialize(out, password, false, cache);
  return out.str();
}

uint8_t firstByte(const std::string& blob) {
  return static_cast<uint8_t>(blob[0]);
}

void appendVarint(std::string& blob, uint64_t value) {
  while (value >= 0x80) {
    blob.push_back(static_cast<char>((value & 0x7f) | 0x80));
    value >>= 7;
  }
  blob.push_back(static_cast<char>(value));
}

struct ScopedFileRemoval {
  explicit ScopedFileRemoval(std::string filePath) : path(std::move(filePath)) {}
  ~ScopedFileRemoval() {
    if (!path.empty()) {
      std::remove(path.c_str());
    }
  }
  std::string path;
};

}  // namespace

TEST(WalletLegacyEnvelope, RoundTripsAndKeepsTheContentVersion) {
  AccountBase account = makeAccount(2);
  const std::string blob = saveWallet(account, "pw", "cache bytes",
                                      WalletLegacySerializer::STANDARD_VERSION);

  EXPECT_EQ(WalletLegacySerializer::AUTHENTICATED_ENVELOPE, firstByte(blob));

  AccountBase restored;
  WalletLegacySerializer reader(restored);
  std::stringstream in(blob);
  std::string cache;
  reader.deserialize(in, "pw", cache);

  EXPECT_EQ("cache bytes", cache);
  EXPECT_EQ(WalletLegacySerializer::STANDARD_VERSION, reader.loadedVersion());
  EXPECT_EQ(0, std::memcmp(restored.getAccountKeys().spendSecretKey.data,
                           account.getAccountKeys().spendSecretKey.data,
                           sizeof(Crypto::SecretKey)));
}

TEST(WalletLegacyEnvelope, ProtectedSpendVersionSurvivesTheEnvelope) {
  // The content version carries meaning to the wallet (v3 = protected-spend
  // metadata present), so the envelope must not flatten it.
  AccountBase account = makeAccount(3);
  const std::string blob = saveWallet(account, "pw", "cache",
                                      WalletLegacySerializer::PROTECTED_SPEND_VERSION);

  AccountBase restored;
  WalletLegacySerializer reader(restored);
  std::stringstream in(blob);
  std::string cache;
  reader.deserialize(in, "pw", cache);

  EXPECT_EQ(WalletLegacySerializer::PROTECTED_SPEND_VERSION, reader.loadedVersion());
}

TEST(WalletLegacyEnvelope, WrongPasswordIsRejected) {
  AccountBase account = makeAccount(4);
  const std::string blob = saveWallet(account, "pw", "cache",
                                      WalletLegacySerializer::STANDARD_VERSION);

  AccountBase restored;
  WalletLegacySerializer reader(restored);
  std::stringstream in(blob);
  std::string cache;
  EXPECT_ANY_THROW(reader.deserialize(in, "not pw", cache));

  std::stringstream check(blob);
  WalletLegacySerializer probe(restored);
  EXPECT_FALSE(probe.deserialize(check, "not pw"));

  std::stringstream right(blob);
  WalletLegacySerializer probeRight(restored);
  EXPECT_TRUE(probeRight.deserialize(right, "pw"));
}

TEST(WalletLegacyEnvelope, TamperedCiphertextIsRejected) {
  AccountBase account = makeAccount(5);
  const std::string blob = saveWallet(account, "pw", "cache",
                                      WalletLegacySerializer::STANDARD_VERSION);

  // Flip a byte in the middle of the sealed payload. Without a tag this would
  // decrypt to modified plaintext instead of failing.
  std::string tampered = blob;
  tampered[tampered.size() / 2] ^= 0x01;

  AccountBase restored;
  WalletLegacySerializer reader(restored);
  std::stringstream in(tampered);
  std::string cache;
  EXPECT_ANY_THROW(reader.deserialize(in, "pw", cache));
}

TEST(WalletLegacyEnvelope, TamperedTagIsRejected) {
  AccountBase account = makeAccount(6);
  const std::string blob = saveWallet(account, "pw", "cache",
                                      WalletLegacySerializer::STANDARD_VERSION);

  std::string tampered = blob;
  tampered[tampered.size() - 1] ^= 0x01;

  AccountBase restored;
  WalletLegacySerializer reader(restored);
  std::stringstream in(tampered);
  std::string cache;
  EXPECT_ANY_THROW(reader.deserialize(in, "pw", cache));
}

TEST(WalletLegacyEnvelope, TwoWalletsWithOnePasswordDifferInEveryByteButTheMarker) {
  // Different salts mean different keys, so nothing about one file helps with
  // the other -- including the work spent deriving its key.
  AccountBase a = makeAccount(7);
  AccountBase b = makeAccount(7);
  const std::string first = saveWallet(a, "same password", "cache",
                                       WalletLegacySerializer::STANDARD_VERSION);
  const std::string second = saveWallet(b, "same password", "cache",
                                        WalletLegacySerializer::STANDARD_VERSION);

  ASSERT_EQ(first.size(), second.size());
  EXPECT_EQ(firstByte(first), firstByte(second));
  EXPECT_NE(0, std::memcmp(first.data() + 1, second.data() + 1, first.size() - 1));
}

TEST(WalletLegacyEnvelope, MarkerStaysBelowTheContainerRange) {
  // Both wallet products identify a file by its first byte: 6 and above means a
  // container. A simplewallet file must not be mistaken for one.
  EXPECT_LT(WalletLegacySerializer::AUTHENTICATED_ENVELOPE, 6u);
  EXPECT_GT(WalletLegacySerializer::AUTHENTICATED_ENVELOPE,
            WalletLegacySerializer::PROTECTED_SPEND_VERSION);
}


// A file written by the old code must still open, and the wallet must report the
// content version it actually carried. This is the compatibility half of the
// envelope change: without it, upgrading the software would strand every
// existing simplewallet file.
namespace {

// The pre-upgrade writer: version | iv | ChaCha8(payload), no tag, unsalted key.
std::string saveWalletOldEnvelope(AccountBase& account, const std::string& password,
                                  const std::string& cache, uint32_t contentVersion) {
  // Build the same plaintext the old serializer built.
  std::stringstream plainArchive;
  Common::StdOutputStream plainStream(plainArchive);
  BinaryOutputStreamSerializer serializer(plainStream);

  WALLET_LEGACY_SERIALIZATION_VERSION = contentVersion;

  if (contentVersion >= WalletLegacySerializer::PROTECTED_SPEND_VERSION) {
    KeysStorage guard{};
    guard.creationTimestamp = UINT64_C(0x4453574C56334744);
    guard.serialize(serializer, "protected_spend_compatibility_guard");
  }

  KeysStorage keys;
  const AccountKeys acc = account.getAccountKeys();
  keys.creationTimestamp = account.get_createtime();
  keys.spendPublicKey = acc.address.spendPublicKey;
  keys.spendSecretKey = acc.spendSecretKey;
  keys.viewPublicKey = acc.address.viewPublicKey;
  keys.viewSecretKey = acc.viewSecretKey;
  keys.serialize(serializer, "keys");

  bool hasDetails = false;
  serializer(hasDetails, "has_details");
  serializer.binary(const_cast<std::string&>(cache), "cache");

  const std::string plain = plainArchive.str();

  Crypto::chacha8_key key;
  Crypto::cn_context context;
  if (!Crypto::generate_chacha8_key(context, password, key)) {
    return std::string();
  }
  std::string cipher(plain.size(), '\0');
  Crypto::chacha8_iv iv = Crypto::randomChachaIV();
  if (!plain.empty()) {
    Crypto::chacha8(plain.data(), plain.size(), key, iv, &cipher[0]);
  }

  std::stringstream out;
  Common::StdOutputStream output(out);
  BinaryOutputStreamSerializer s(output);
  s.beginObject("wallet");
  s(contentVersion, "version");
  Crypto::serialize(iv, "iv", s);
  s(cipher, "data");
  s.endObject();
  return out.str();
}

}  // namespace

TEST(WalletLegacyEnvelope, OldEnvelopeStillOpens) {
  AccountBase account = makeAccount(9);
  const std::string blob = saveWalletOldEnvelope(account, "pw", "old cache",
                                                 WalletLegacySerializer::STANDARD_VERSION);
  ASSERT_FALSE(blob.empty());
  ASSERT_EQ(WalletLegacySerializer::STANDARD_VERSION, firstByte(blob));

  AccountBase restored;
  WalletLegacySerializer reader(restored);
  std::stringstream in(blob);
  std::string cache;
  reader.deserialize(in, "pw", cache);

  EXPECT_EQ("old cache", cache);
  EXPECT_EQ(WalletLegacySerializer::STANDARD_VERSION, reader.loadedVersion());
  EXPECT_EQ(0, std::memcmp(restored.getAccountKeys().spendSecretKey.data,
                           account.getAccountKeys().spendSecretKey.data,
                           sizeof(Crypto::SecretKey)));
}

TEST(WalletLegacyEnvelope, OldEnvelopeIsRewrittenOnSave) {
  AccountBase account = makeAccount(10);
  const std::string oldBlob = saveWalletOldEnvelope(account, "pw", "cache",
                                                    WalletLegacySerializer::STANDARD_VERSION);
  ASSERT_FALSE(oldBlob.empty());

  AccountBase restored;
  WalletLegacySerializer reader(restored);
  std::stringstream in(oldBlob);
  std::string cache;
  reader.deserialize(in, "pw", cache);

  // Saving the wallet again is what upgrades it, and simplewallet saves on close.
  const std::string newBlob = saveWallet(restored, "pw", cache, reader.loadedVersion());
  EXPECT_EQ(WalletLegacySerializer::AUTHENTICATED_ENVELOPE, firstByte(newBlob));

  AccountBase reopened;
  WalletLegacySerializer reader2(reopened);
  std::stringstream in2(newBlob);
  std::string cache2;
  reader2.deserialize(in2, "pw", cache2);
  EXPECT_EQ(cache, cache2);
  EXPECT_EQ(0, std::memcmp(reopened.getAccountKeys().spendSecretKey.data,
                           account.getAccountKeys().spendSecretKey.data,
                           sizeof(Crypto::SecretKey)));
}

TEST(WalletLegacyEnvelope, OldEnvelopeWithAWrongPasswordIsStillRejected) {
  AccountBase account = makeAccount(11);
  const std::string blob = saveWalletOldEnvelope(account, "pw", "cache",
                                                 WalletLegacySerializer::STANDARD_VERSION);
  ASSERT_FALSE(blob.empty());

  AccountBase restored;
  WalletLegacySerializer reader(restored);
  std::stringstream in(blob);
  std::string cache;
  EXPECT_ANY_THROW(reader.deserialize(in, "wrong", cache));
}

TEST(WalletLegacyEnvelope, RejectsTrailingBytesInAuthenticatedAndLegacyFiles) {
  AccountBase account = makeAccount(12);
  const std::string authenticated = saveWallet(
      account, "pw", "cache", WalletLegacySerializer::STANDARD_VERSION);
  const std::string legacy = saveWalletOldEnvelope(
      account, "pw", "cache", WalletLegacySerializer::STANDARD_VERSION);

  for (const std::string& blob : {authenticated, legacy}) {
    AccountBase restored;
    WalletLegacySerializer reader(restored);
    std::stringstream in(blob + "trailing");
    std::string cache;
    EXPECT_ANY_THROW(reader.deserialize(in, "pw", cache));
  }
}

TEST(WalletLegacyEnvelope, RejectsDeclaredCiphertextLargerThanTheRemainingFile) {
  std::string authenticated;
  appendVarint(authenticated, WalletLegacySerializer::AUTHENTICATED_ENVELOPE);
  appendVarint(authenticated, sizeof(Crypto::Hash));
  authenticated.append(sizeof(Crypto::Hash), '\0');
  appendVarint(authenticated, CryptoPQ::kAeadNonceBytes);
  authenticated.append(CryptoPQ::kAeadNonceBytes, '\0');
  appendVarint(authenticated, 1024);  // no ciphertext bytes follow

  std::string legacy;
  appendVarint(legacy, WalletLegacySerializer::STANDARD_VERSION);
  legacy.append(sizeof(Crypto::chacha8_iv), '\0');
  appendVarint(legacy, 1024);  // no ciphertext bytes follow

  for (const std::string& blob : {authenticated, legacy}) {
    AccountBase restored;
    WalletLegacySerializer reader(restored);
    std::stringstream input(blob);
    std::string cache;
    EXPECT_ANY_THROW(reader.deserialize(input, "pw", cache));
  }
}

TEST(WalletLegacyEnvelope, MiningKeyLoaderMatchesCanonicalReaderForLegacyVersionsOneThroughThree) {
  Logging::ConsoleLogger logger(Logging::ERROR);

  for (uint32_t version = 1; version <= WalletLegacySerializer::PROTECTED_SPEND_VERSION; ++version) {
    AccountBase account = makeAccount(static_cast<uint8_t>(20 + version));
    const std::string blob = saveWalletOldEnvelope(account, "pw", "cache", version);
    ASSERT_FALSE(blob.empty()) << "version " << version;

    AccountBase canonicalAccount;
    WalletLegacySerializer canonicalReader(canonicalAccount);
    std::stringstream canonicalInput(blob);
    std::string canonicalCache;
    ASSERT_NO_THROW(canonicalReader.deserialize(canonicalInput, "pw", canonicalCache))
        << "version " << version;

    const std::string path =
        "mining_key_loader_legacy_v" + std::to_string(version) + ".wallet";
    std::remove(path.c_str());
    ScopedFileRemoval cleanup(path);
    {
      std::ofstream output(path, std::ios::binary | std::ios::trunc);
      ASSERT_TRUE(output.good());
      output.write(blob.data(), static_cast<std::streamsize>(blob.size()));
      ASSERT_TRUE(output.good());
    }

    Crypto::SecretKey loaded{};
    ASSERT_NO_THROW(loaded = loadMiningSpendSecret(path, "pw", logger))
        << "version " << version;
    EXPECT_EQ(0, std::memcmp(loaded.data,
                             canonicalAccount.getAccountKeys().spendSecretKey.data,
                             sizeof(loaded.data)))
        << "version " << version;

    {
      std::ifstream unchangedInput(path, std::ios::binary);
      const std::string unchanged((std::istreambuf_iterator<char>(unchangedInput)),
                                  std::istreambuf_iterator<char>());
      EXPECT_EQ(unchanged, blob) << "loader modified version " << version;
    }
    EXPECT_EQ(std::remove(path.c_str()), 0) << "version " << version;
    cleanup.path.clear();
  }
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
