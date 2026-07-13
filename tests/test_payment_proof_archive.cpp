// Copyright (c) 2026, The Karbo developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "gtest/gtest.h"

#include <cstring>

#include <boost/filesystem.hpp>

#include "Wallet/PaymentProofArchive.h"
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
  CryptoPQ::Rho rho{};
  rho[0] = 42;
  const auto proof = CryptoNote::makePqPaymentProof(
      hash256(genesis), hash256(txid), recipient, {{0, rho}});
  const std::string encoded = CryptoNote::encodePqPaymentProof(proof, false);
  return {{{"duplicate-label", 11, encoded}, {"duplicate-label", 22, encoded}}};
}

struct CodecFixture : testing::Test {
  boost::filesystem::path root = boost::filesystem::temp_directory_path() /
                                  boost::filesystem::unique_path("proof-codec-%%%%-%%%%");
  Crypto::Hash genesis = cryptoHash("archive genesis");
  Crypto::Hash txid = cryptoHash("archive transaction");
  void SetUp() override { boost::filesystem::create_directories(root); }
  void TearDown() override { boost::system::error_code ec; boost::filesystem::remove_all(root, ec); }
};

TEST_F(CodecFixture, RoundTripPreservesOrderedDuplicateRows) {
  const auto original = recordFor(genesis, txid);
  const std::string bytes = CryptoNote::PaymentProofArchive::encodeRecord(genesis, txid, original);
  Crypto::Hash decodedGenesis{}, decodedTx{};
  CryptoNote::SentPaymentRecord decoded;
  ASSERT_TRUE(CryptoNote::PaymentProofArchive::decodeRecord(bytes, decodedGenesis, decodedTx, decoded));
  EXPECT_EQ(std::memcmp(decodedGenesis.data, genesis.data, 32), 0);
  EXPECT_EQ(std::memcmp(decodedTx.data, txid.data, 32), 0);
  ASSERT_EQ(decoded.recipients.size(), 2u);
  EXPECT_EQ(decoded.recipients[0].address, "duplicate-label");
  EXPECT_EQ(decoded.recipients[0].amount, 11u);
  EXPECT_EQ(decoded.recipients[1].amount, 22u);
  EXPECT_EQ(decoded.recipients[0].proof, original.recipients[0].proof);
}

TEST_F(CodecFixture, ExportWritesFileThatReadsBackAndDecodes) {
  const auto original = recordFor(genesis, txid);
  const std::string path = (root / "export.pproof").string();
  ASSERT_NO_THROW(
      CryptoNote::PaymentProofArchive::exportRecord(genesis, txid, original, path));
  ASSERT_TRUE(boost::filesystem::exists(path));

  const std::string bytes = CryptoNote::PaymentProofArchive::readExternalFile(path);
  Crypto::Hash decodedGenesis{}, decodedTx{};
  CryptoNote::SentPaymentRecord decoded;
  ASSERT_TRUE(CryptoNote::PaymentProofArchive::decodeRecord(bytes, decodedGenesis, decodedTx, decoded));
  ASSERT_EQ(decoded.recipients.size(), 2u);
  EXPECT_EQ(decoded.recipients[1].amount, 22u);
}

TEST_F(CodecFixture, DecodeRejectsCorruptBytes) {
  Crypto::Hash g{}, t{};
  CryptoNote::SentPaymentRecord decoded;
  std::string why;
  EXPECT_FALSE(CryptoNote::PaymentProofArchive::decodeRecord("corrupt", g, t, decoded, &why));
  EXPECT_FALSE(why.empty());
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
