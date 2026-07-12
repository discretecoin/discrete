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
  CryptoPQ::KemEncapsMessage message{};
  message[0] = 42;
  const auto proof = CryptoNote::makePqPaymentProof(
      hash256(genesis), hash256(txid), recipient, {{0, message}});
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

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
