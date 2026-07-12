// Copyright (c) 2026, The Karbo developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "gtest/gtest.h"

#include <cstring>
#include <fstream>

#include <boost/filesystem.hpp>

#include "Wallet/PaymentProofArchive.h"
#include "Common/StringTools.h"
#include "crypto_pq/PqPaymentProof.h"
#include "crypto_pq/PqOutputBuilder.h"

#ifdef _WIN32
#include <windows.h>
#include <Aclapi.h>
#endif

namespace {

Crypto::Hash cryptoHash(const char* text) {
  const auto h = CryptoPQ::sha3_256(text, std::strlen(text));
  Crypto::Hash result{};
  std::memcpy(result.data, h.data(), h.size());
  return result;
}

CryptoPQ::Hash256 hash256(const Crypto::Hash& h) {
  CryptoPQ::Hash256 result{};
  std::memcpy(result.data(), h.data, result.size());
  return result;
}

CryptoNote::SentPaymentRecord recordFor(const Crypto::Hash& genesis,
                                        const Crypto::Hash& txid) {
  CryptoPQ::KemKeypairSeed viewSeed{};
  CryptoPQ::DsaKeypairSeed spendSeed{};
  viewSeed[0] = 7;
  spendSeed[0] = 9;
  CryptoNote::ResolvedRecipient recipient{
      CryptoPQ::kem_keygen_from_seed(viewSeed).first,
      CryptoPQ::dsa_keygen_from_seed(spendSeed).first, 3};
  CryptoPQ::Rho rho{};
  rho[0] = 42;
  const auto proof = CryptoNote::makePqPaymentProof(
      hash256(genesis), hash256(txid), recipient, {{0, rho}});
  const std::string encoded = CryptoNote::encodePqPaymentProof(proof, false);
  return {{{"duplicate-label", 11, encoded}, {"duplicate-label", 22, encoded}}};
}

struct ArchiveFixture : testing::Test {
  boost::filesystem::path root = boost::filesystem::temp_directory_path() /
                                  boost::filesystem::unique_path("proof-archive-%%%%-%%%%");
  std::string wallet = (root / "wallet.bin").string();
  Crypto::Hash genesis = cryptoHash("archive genesis");
  Crypto::Hash txid = cryptoHash("archive transaction");
  void SetUp() override { boost::filesystem::create_directories(root); }
  void TearDown() override { boost::system::error_code ec; boost::filesystem::remove_all(root, ec); }
};

TEST_F(ArchiveFixture, RoundTripPreservesOrderedDuplicateRows) {
  const auto original = recordFor(genesis, txid);
  const std::string bytes = CryptoNote::PaymentProofArchive::encodeRecord(genesis, txid, original);
  Crypto::Hash decodedGenesis{}, decodedTx{};
  CryptoNote::SentPaymentRecord decoded;
  ASSERT_TRUE(CryptoNote::PaymentProofArchive::decodeRecord(bytes, decodedGenesis, decodedTx, decoded));
  ASSERT_EQ(decoded.recipients.size(), 2u);
  EXPECT_EQ(decoded.recipients[0].address, "duplicate-label");
  EXPECT_EQ(decoded.recipients[0].amount, 11u);
  EXPECT_EQ(decoded.recipients[1].amount, 22u);
  EXPECT_EQ(decoded.recipients[0].proof, original.recipients[0].proof);
}

TEST_F(ArchiveFixture, EveryDurabilityBoundaryFailsBeforePublishingRecord) {
  const auto record = recordFor(genesis, txid);
  for (auto fault : {CryptoNote::PaymentProofArchive::Fault::Create,
                     CryptoNote::PaymentProofArchive::Fault::Write,
                     CryptoNote::PaymentProofArchive::Fault::Flush,
                     CryptoNote::PaymentProofArchive::Fault::Rename}) {
    CryptoNote::SentPaymentsStore store;
    CryptoNote::PaymentProofArchive archive;
    archive.configure(wallet, genesis, store);
    archive.setFaultForTests(fault);
    EXPECT_THROW(archive.persist(txid, record), std::exception);
    EXPECT_FALSE(boost::filesystem::exists(boost::filesystem::path(archive.directory()) /
                                           (Common::podToHex(txid) + ".pproof")));
  }
}

TEST_F(ArchiveFixture, DurableRecordSurvivesReloadAndIsIdempotent) {
  const auto record = recordFor(genesis, txid);
  CryptoNote::SentPaymentsStore first;
  CryptoNote::PaymentProofArchive archive;
  archive.configure(wallet, genesis, first);
  archive.persist(txid, record);
  EXPECT_NO_THROW(archive.persist(txid, record));

  CryptoNote::SentPaymentsStore reloaded;
  CryptoNote::PaymentProofArchive second;
  std::vector<std::string> warnings;
  second.configure(wallet, genesis, reloaded, &warnings);
  EXPECT_TRUE(warnings.empty());
  const auto* found = reloaded.find(txid);
  ASSERT_NE(found, nullptr);
  ASSERT_EQ(found->recipients.size(), 2u);
  EXPECT_EQ(found->recipients[1].amount, 22u);
}

TEST_F(ArchiveFixture, ConflictIsNotOverwrittenAndCorruptNeighborIsIsolated) {
  const auto record = recordFor(genesis, txid);
  CryptoNote::SentPaymentsStore store;
  CryptoNote::PaymentProofArchive archive;
  archive.configure(wallet, genesis, store);
  archive.persist(txid, record);
  auto conflict = record;
  conflict.recipients[0].amount++;
  EXPECT_THROW(archive.persist(txid, conflict), std::exception);

  const Crypto::Hash corruptTx = cryptoHash("corrupt neighbor");
  const auto corruptPath = boost::filesystem::path(archive.directory()) /
                           (Common::podToHex(corruptTx) + ".pproof");
  std::ofstream bad(corruptPath.string(), std::ios::binary);
  bad << "corrupt";
  bad.close();

  CryptoNote::SentPaymentsStore reloaded;
  CryptoNote::PaymentProofArchive second;
  std::vector<std::string> warnings;
  second.configure(wallet, genesis, reloaded, &warnings);
  EXPECT_FALSE(warnings.empty());
  EXPECT_NE(reloaded.find(txid), nullptr);
  EXPECT_EQ(reloaded.find(corruptTx), nullptr);
}

TEST_F(ArchiveFixture, ExplicitRowDeletionAtomicallyReplacesTheRecord) {
  auto record = recordFor(genesis, txid);
  CryptoNote::SentPaymentsStore store;
  CryptoNote::PaymentProofArchive archive;
  archive.configure(wallet, genesis, store);
  archive.persist(txid, record);
  record.recipients.erase(record.recipients.begin());
  archive.replaceAfterExplicitDeletion(txid, record);

  CryptoNote::SentPaymentsStore reloaded;
  CryptoNote::PaymentProofArchive second;
  second.configure(wallet, genesis, reloaded);
  const auto* found = reloaded.find(txid);
  ASSERT_NE(found, nullptr);
  ASSERT_EQ(found->recipients.size(), 1u);
  EXPECT_EQ(found->recipients[0].amount, 22u);
}

TEST_F(ArchiveFixture, AuthoritativeArchiveReplacesStaleCacheConflict) {
  const auto authoritative = recordFor(genesis, txid);
  CryptoNote::SentPaymentsStore initial;
  CryptoNote::PaymentProofArchive archive;
  archive.configure(wallet, genesis, initial);
  archive.persist(txid, authoritative);

  auto stale = authoritative;
  stale.recipients[0].amount++;
  CryptoNote::SentPaymentsStore cache;
  cache.record(txid, stale);
  std::vector<std::string> warnings;
  CryptoNote::PaymentProofArchive reloaded;
  reloaded.configure(wallet, genesis, cache, &warnings);
  ASSERT_FALSE(warnings.empty());
  const auto* found = cache.find(txid);
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->recipients[0].amount, authoritative.recipients[0].amount);
}

TEST_F(ArchiveFixture, AuthoritativeDeletionCannotBeResurrectedByStaleCache) {
  const auto record = recordFor(genesis, txid);
  CryptoNote::SentPaymentsStore initial;
  CryptoNote::PaymentProofArchive archive;
  archive.configure(wallet, genesis, initial);
  archive.persist(txid, record);
  archive.erase(txid);

  CryptoNote::SentPaymentsStore staleCache;
  staleCache.record(txid, record);
  std::vector<std::string> warnings;
  CryptoNote::PaymentProofArchive reloaded;
  reloaded.configure(wallet, genesis, staleCache, &warnings);
  EXPECT_EQ(staleCache.find(txid), nullptr);
  EXPECT_FALSE(warnings.empty());
}

TEST_F(ArchiveFixture, FirstConfigurationMigratesExistingEncryptedCache) {
  const auto record = recordFor(genesis, txid);
  CryptoNote::SentPaymentsStore cache;
  cache.record(txid, record);
  CryptoNote::PaymentProofArchive archive;
  archive.configure(wallet, genesis, cache);

  CryptoNote::SentPaymentsStore reloaded;
  CryptoNote::PaymentProofArchive second;
  second.configure(wallet, genesis, reloaded);
  const auto* found = reloaded.find(txid);
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->recipients[1].amount, 22u);
}

TEST_F(ArchiveFixture, ExportCannotAliasAuthoritativeArchive) {
  const auto record = recordFor(genesis, txid);
  CryptoNote::SentPaymentsStore store;
  CryptoNote::PaymentProofArchive archive;
  archive.configure(wallet, genesis, store);
  archive.persist(txid, record);

  const auto inside = boost::filesystem::path(archive.directory()) / "export.pproof";
  EXPECT_THROW(archive.exportRecord(txid, record, inside.string()), std::exception);

  const auto outside = root / "export.pproof";
  EXPECT_NO_THROW(archive.exportRecord(txid, record, outside.string()));
  EXPECT_TRUE(boost::filesystem::exists(outside));
}

#ifdef _WIN32
TEST_F(ArchiveFixture, WindowsArchiveDaclIsProtectedAndOwnerOnly) {
  const auto record = recordFor(genesis, txid);
  CryptoNote::SentPaymentsStore store;
  CryptoNote::PaymentProofArchive archive;
  archive.configure(wallet, genesis, store);
  archive.persist(txid, record);

  HANDLE token = nullptr;
  ASSERT_TRUE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
  DWORD tokenSize = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &tokenSize);
  std::vector<uint8_t> tokenInfo(tokenSize);
  ASSERT_TRUE(GetTokenInformation(
      token, TokenUser, tokenInfo.data(), tokenSize, &tokenSize));
  CloseHandle(token);
  const PSID currentUser =
      reinterpret_cast<TOKEN_USER*>(tokenInfo.data())->User.Sid;

  for (const auto& path : {
           boost::filesystem::path(archive.directory()),
           boost::filesystem::path(archive.directory()) /
               (Common::podToHex(txid) + ".pproof")}) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    ASSERT_EQ(GetNamedSecurityInfoW(
                  const_cast<LPWSTR>(path.wstring().c_str()), SE_FILE_OBJECT,
                  DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
                  &descriptor),
              ERROR_SUCCESS);
    ASSERT_NE(descriptor, nullptr);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    ASSERT_TRUE(GetSecurityDescriptorControl(descriptor, &control, &revision));
    EXPECT_NE(control & SE_DACL_PROTECTED, 0);
    ACL_SIZE_INFORMATION info{};
    ASSERT_TRUE(GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation));
    ASSERT_GE(info.AceCount, 1u);
    for (DWORD i = 0; i < info.AceCount; ++i) {
      void* rawAce = nullptr;
      ASSERT_TRUE(GetAce(dacl, i, &rawAce));
      const auto* header = static_cast<ACE_HEADER*>(rawAce);
      ASSERT_EQ(header->AceType, ACCESS_ALLOWED_ACE_TYPE);
      const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(rawAce);
      EXPECT_TRUE(EqualSid(currentUser, const_cast<DWORD*>(&ace->SidStart)));
    }
    LocalFree(descriptor);
  }
}
#endif

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
