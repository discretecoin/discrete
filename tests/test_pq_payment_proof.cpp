// Copyright (c) 2026, The Discrete developers
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
  CryptoNote::ResolvedRecipient recipient;
  CryptoPQ::Hash256 genesisId = hashOf("test genesis");
  CryptoNote::PqPaymentProofTransaction tx;
  std::vector<CryptoPQ::Rho> rhos;
  CryptoNote::PqPaymentProof proof;

  ProofFixture() {
    CryptoPQ::KemKeypairSeed viewSeed{};
    CryptoPQ::DsaKeypairSeed spendSeed{};
    viewSeed[0] = 3;
    spendSeed[0] = 5;
    recipient.viewPub = CryptoPQ::kem_keygen_from_seed(viewSeed).first;
    recipient.spendPub = CryptoPQ::dsa_keygen_from_seed(spendSeed).first;
    recipient.subaddrIndexT = 17;

    tx.txid = hashOf("final transaction");
    tx.inputsHash = hashOf("canonical inputs");
    for (uint32_t i = 0; i < 2; ++i) {
      auto encapsulation = CryptoPQ::kem_encaps(recipient.viewPub);
      CryptoPQ::Rho rho{};
      rho[0] = static_cast<uint8_t>(21 + i);
      rho[31] = static_cast<uint8_t>(71 + i);
      rhos.push_back(rho);
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
        genesisId, tx.txid, recipient, {{1, rhos[1]}, {0, rhos[0]}});
  }
};

TEST(PqPaymentProof, RoundTripAndSpendAuthorityTotal) {
  ProofFixture f;
  ASSERT_EQ(f.proof.version, 2u);
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

TEST(PqPaymentProof, RejectsWrongRhoAndSpendKey) {
  ProofFixture f;
  auto wrongRho = f.proof;
  wrongRho.entries[0].rho[0] ^= 1;
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   wrongRho, f.genesisId, f.tx, f.recipient),
               CryptoNote::PqPaymentProofError);

  CryptoPQ::DsaKeypairSeed seed{};
  seed[0] = 100;
  auto wrongSpend = f.recipient;
  wrongSpend.spendPub = CryptoPQ::dsa_keygen_from_seed(seed).first;
  auto relabeled = f.proof;
  relabeled.spendAuthorityHash = CryptoNote::pqSpendAuthorityHash(wrongSpend.spendPub);
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   relabeled, f.genesisId, f.tx, wrongSpend),
               CryptoNote::PqPaymentProofError);
}

TEST(PqPaymentProof, DoesNotClaimViewKeyOrSubaddressDelivery) {
  ProofFixture f;
  CryptoPQ::KemKeypairSeed seed{};
  seed[0] = 99;
  auto sameAuthority = f.recipient;
  sameAuthority.viewPub = CryptoPQ::kem_keygen_from_seed(seed).first;
  ++sameAuthority.subaddrIndexT;

  // The verifier intentionally proves only the on-chain spend commitment.
  // A recipient-signed receipt is required to prove view-key/T delivery.
  EXPECT_EQ(CryptoNote::verifyPqPaymentProof(
                f.proof, f.genesisId, f.tx, sameAuthority),
            1000u);
}

TEST(PqPaymentProof, RejectsChangedCommitment) {
  ProofFixture f;
  auto changedCommitment = f.tx;
  changedCommitment.outputs[0].spendCommit[0] ^= 1;
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   f.proof, f.genesisId, changedCommitment, f.recipient),
               CryptoNote::PqPaymentProofError);
}

TEST(PqPaymentProof, RejectsNetworkTransactionAndDuplicateIndex) {
  ProofFixture f;
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   f.proof, hashOf("other genesis"), f.tx, f.recipient),
               CryptoNote::PqPaymentProofError);

  auto otherTx = f.tx;
  otherTx.txid = hashOf("other tx");
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   f.proof, f.genesisId, otherTx, f.recipient),
               CryptoNote::PqPaymentProofError);

  auto duplicate = f.proof;
  duplicate.entries.push_back(duplicate.entries.front());
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   duplicate, f.genesisId, f.tx, f.recipient),
               CryptoNote::PqPaymentProofError);
}

TEST(PqPaymentProof, RejectsOverReportingForeignSpendAuthority) {
  ProofFixture f;
  CryptoPQ::DsaKeypairSeed foreignSeed{};
  foreignSeed[0] = 44;
  const auto foreignSpend = CryptoPQ::dsa_keygen_from_seed(foreignSeed).first;
  auto encapsulation = CryptoPQ::kem_encaps(f.recipient.viewPub);
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
  overReported.entries.push_back({index, rho});
  EXPECT_THROW(CryptoNote::verifyPqPaymentProof(
                   overReported, f.genesisId, f.tx, f.recipient),
               CryptoNote::PqPaymentProofError);
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
