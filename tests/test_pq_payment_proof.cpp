// Copyright (c) 2026, The Karbo developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "gtest/gtest.h"

#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqPaymentProof.h"

#include <cstring>

namespace {

CryptoPQ::Hash256 hashOf(const char* text) {
  return CryptoPQ::sha3_256(text, std::strlen(text));
}

struct ProofFixture {
  CryptoPQ::KemSecretKey viewSk{};
  CryptoNote::ResolvedRecipient recipient;
  CryptoPQ::Hash256 genesisId = hashOf("test genesis");
  CryptoNote::PqPaymentProofTransaction tx;
  std::vector<CryptoPQ::KemEncapsMessage> messages;
  CryptoNote::PqPaymentProof proof;

  ProofFixture() {
    CryptoPQ::KemKeypairSeed viewSeed{};
    CryptoPQ::DsaKeypairSeed spendSeed{};
    viewSeed[0] = 3;
    spendSeed[0] = 5;
    auto viewKeys = CryptoPQ::kem_keygen_from_seed(viewSeed);
    auto spendKeys = CryptoPQ::dsa_keygen_from_seed(spendSeed);
    recipient.viewPub = viewKeys.first;
    recipient.spendPub = spendKeys.first;
    recipient.subaddrIndexT = 17;
    viewSk = viewKeys.second;

    tx.txid = hashOf("final transaction");
    tx.inputsHash = hashOf("canonical inputs");
    for (uint32_t i = 0; i < 2; ++i) {
      CryptoPQ::KemEncapsMessage message{};
      message[0] = static_cast<uint8_t>(11 + i);
      message[31] = static_cast<uint8_t>(91 + i);
      messages.push_back(message);
      const auto encapsulation = CryptoPQ::kem_encaps_explicit(recipient.viewPub, message);
      CryptoPQ::Rho rho{};
      rho[0] = static_cast<uint8_t>(21 + i);
      const uint64_t amount = i == 0 ? 400 : 600;
      const auto built = CryptoPQ::buildPqOutput(
          encapsulation.first, encapsulation.second, recipient.spendPub,
          tx.inputsHash, i, amount, rho, recipient.subaddrIndexT);
      CryptoPQ::PqScanOutput output;
      output.outputIndex = i;
      output.amount = amount;
      output.kemCt = built.kemCt;
      output.encPayload = built.encPayload;
      output.spendCommit = built.spendCommit;
      tx.outputs.push_back(std::move(output));
    }

    // Deliberately supply reverse order: assembly must canonicalize by index.
    proof = CryptoNote::makePqPaymentProof(
        genesisId, tx.txid, recipient,
        {{1, messages[1]}, {0, messages[0]}});
  }
};

TEST(PqPaymentProof, RoundTripAndFullScanTotal) {
  ProofFixture f;
  ASSERT_EQ(f.proof.entries.size(), 2u);
  EXPECT_EQ(f.proof.entries[0].outputIndex, 0u);
  EXPECT_EQ(f.proof.entries[1].outputIndex, 1u);
  EXPECT_EQ(CryptoNote::verifyPqPaymentProof(f.proof, f.genesisId, f.tx, f.recipient), 1000u);

  const std::string encoded = CryptoNote::encodePqPaymentProof(f.proof, false);
  EXPECT_EQ(encoded.rfind("disctxp1", 0), 0u);
  CryptoNote::PqPaymentProof decoded;
  ASSERT_TRUE(CryptoNote::decodePqPaymentProof(encoded, false, decoded));
  EXPECT_EQ(CryptoNote::verifyPqPaymentProof(decoded, f.genesisId, f.tx, f.recipient), 1000u);
  EXPECT_FALSE(CryptoNote::decodePqPaymentProof(encoded, true, decoded));

  std::string damaged = encoded;
  damaged.back() = damaged.back() == 'q' ? 'p' : 'q';
  EXPECT_FALSE(CryptoNote::decodePqPaymentProof(damaged, decoded));
}

TEST(PqPaymentProof, RejectsWrongMessageAndForeignViewKey) {
  ProofFixture f;
  auto wrongMessage = f.proof;
  wrongMessage.entries[0].message[0] ^= 1;
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   wrongMessage, f.genesisId, f.tx, f.recipient),
               CryptoNote::PqPaymentProofError);

  CryptoPQ::KemKeypairSeed seed{};
  seed[0] = 99;
  auto foreign = f.recipient;
  foreign.viewPub = CryptoPQ::kem_keygen_from_seed(seed).first;
  auto foreignProof = f.proof;
  foreignProof.recipientDescriptorHash = CryptoNote::pqRecipientDescriptorHash(foreign);
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   foreignProof, f.genesisId, f.tx, foreign),
               CryptoNote::PqPaymentProofError);
}

TEST(PqPaymentProof, RejectsWrongSpendKeyAndSubaddressIndex) {
  ProofFixture f;
  CryptoPQ::DsaKeypairSeed seed{};
  seed[0] = 100;
  auto wrongSpend = f.recipient;
  wrongSpend.spendPub = CryptoPQ::dsa_keygen_from_seed(seed).first;
  auto wrongSpendProof = f.proof;
  wrongSpendProof.recipientDescriptorHash = CryptoNote::pqRecipientDescriptorHash(wrongSpend);
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   wrongSpendProof, f.genesisId, f.tx, wrongSpend),
               CryptoNote::PqPaymentProofError);

  auto wrongT = f.recipient;
  ++wrongT.subaddrIndexT;
  auto wrongTProof = f.proof;
  wrongTProof.recipientDescriptorHash = CryptoNote::pqRecipientDescriptorHash(wrongT);
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   wrongTProof, f.genesisId, f.tx, wrongT),
               CryptoNote::PqPaymentProofError);
}

TEST(PqPaymentProof, RejectsChangedAmountPayloadAndCommitment) {
  ProofFixture f;
  auto changedAmount = f.tx;
  ++changedAmount.outputs[0].amount;
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   f.proof, f.genesisId, changedAmount, f.recipient),
               CryptoNote::PqPaymentProofError);

  auto changedPayload = f.tx;
  changedPayload.outputs[0].encPayload[0] ^= 1;
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   f.proof, f.genesisId, changedPayload, f.recipient),
               CryptoNote::PqPaymentProofError);

  auto changedCommitment = f.tx;
  changedCommitment.outputs[0].spendCommit[0] ^= 1;
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   f.proof, f.genesisId, changedCommitment, f.recipient),
               CryptoNote::PqPaymentProofError);
}

TEST(PqPaymentProof, RejectsNetworkTransactionRecipientAndDuplicateIndex) {
  ProofFixture f;
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   f.proof, hashOf("other genesis"), f.tx, f.recipient),
               CryptoNote::PqPaymentProofError);

  auto otherTx = f.tx;
  otherTx.txid = hashOf("other tx");
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   f.proof, f.genesisId, otherTx, f.recipient),
               CryptoNote::PqPaymentProofError);

  auto wrongRecipient = f.recipient;
  wrongRecipient.subaddrIndexT = 1;
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   f.proof, f.genesisId, f.tx, wrongRecipient),
               CryptoNote::PqPaymentProofError);

  auto duplicate = f.proof;
  duplicate.entries.push_back(duplicate.entries.front());
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   duplicate, f.genesisId, f.tx, f.recipient),
               CryptoNote::PqPaymentProofError);
}

TEST(PqPaymentProof, RejectsOverReportingForeignOutput) {
  ProofFixture f;
  CryptoPQ::DsaKeypairSeed foreignSeed{};
  foreignSeed[0] = 44;
  const auto foreignSpend = CryptoPQ::dsa_keygen_from_seed(foreignSeed).first;
  CryptoPQ::KemEncapsMessage message{};
  message[0] = 77;
  const auto encapsulation = CryptoPQ::kem_encaps_explicit(f.recipient.viewPub, message);
  CryptoPQ::Rho rho{};
  rho[0] = 88;
  const uint32_t index = static_cast<uint32_t>(f.tx.outputs.size());
  const auto built = CryptoPQ::buildPqOutput(
      encapsulation.first, encapsulation.second, foreignSpend, f.tx.inputsHash,
      index, 9000, rho, f.recipient.subaddrIndexT);
  CryptoPQ::PqScanOutput output;
  output.outputIndex = index;
  output.amount = 9000;
  output.kemCt = built.kemCt;
  output.encPayload = built.encPayload;
  output.spendCommit = built.spendCommit;
  f.tx.outputs.push_back(std::move(output));

  auto overReported = f.proof;
  overReported.entries.push_back({index, message});
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   overReported, f.genesisId, f.tx, f.recipient),
               CryptoNote::PqPaymentProofError);
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
