// Copyright (c) 2026, The Discrete developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "gtest/gtest.h"

#include "AccountNumber.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqPaymentProof.h"
#include "Rpc/CoreRpcServerCommandsDefinitions.h"

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

// The proof is authority-only, so it cannot distinguish one deposit subaddress
// of an account from another: every routing index verifies identically. Anything
// that credits an invoice from this result alone is crediting the wrong thing.
TEST(PqPaymentProof, VerdictIsIdenticalForEveryRoutingIndex) {
  ProofFixture f;
  const uint64_t routes[] = { 0, 1, 2, 17, 4294967295ULL, 4294967296ULL,
                              18446744073709551615ULL };
  for (uint64_t t : routes) {
    auto recipient = f.recipient;
    recipient.subaddrIndexT = t;
    EXPECT_EQ(1000u, CryptoNote::verifyPqPaymentProof(f.proof, f.genesisId, f.tx, recipient))
        << "routing index " << t << " changed the verdict, which the proof cannot support";
  }
}

TEST(PqPaymentProof, RpcResultDoesNotClaimTheRoute) {
  CryptoNote::COMMAND_RPC_CHECK_TRANSACTION_PROOF::response res;
  // The default must be the safe one: a caller that forgets to look still does
  // not read a route confirmation that was never established.
  EXPECT_FALSE(res.route_verified);
  EXPECT_FALSE(res.spend_authority_valid);
}

// --- the legacy verdict field --------------------------------------------
//
// check_transaction_proof answers three fields, but settlement software written
// before route_verified existed reads only signature_valid, and credits an
// invoice on it. Because the proof verifies identically for every T, answering
// "valid" to a request that named ONE deposit would let such a client settle a
// different invoice than the one that was paid. So a request that asserts a
// route gets a negative legacy verdict, while a current client still reads the
// whole picture from spend_authority_valid and route_verified.
//
// This is the predicate the handler uses to make that call.

TEST(PqPaymentProof, DepositFormIsRecognisedAsARouteAssertion) {
  const uint32_t fp = 0x5A3C1;
  const CryptoNote::AccountNumber account{1234, 7};

  // H-I-A-T-C asserts one specific deposit.
  for (uint32_t t : {0u, 1u, 2u, 99u, 4294967295u}) {
    const std::string deposit = account.toStringWithIndex(t, fp);
    EXPECT_TRUE(CryptoNote::namesDepositRoute(deposit)) << deposit;
  }
}

TEST(PqPaymentProof, BaseNumbersAndAddressesAssertNoRoute) {
  const uint32_t fp = 0x5A3C1;
  const CryptoNote::AccountNumber account{1234, 7};

  // H-I-A-C names an account, not a deposit within it. Nothing was claimed about
  // routing, so the legacy field stays meaningful.
  EXPECT_FALSE(CryptoNote::namesDepositRoute(account.toString(fp)));

  // A full address carries both keys and never goes through the registry.
  EXPECT_FALSE(CryptoNote::namesDepositRoute(
      "disc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"));

  // Malformed input asserts nothing either; it is refused earlier for being
  // unparseable, and must not be mistaken for a route claim on the way there.
  for (const char* junk : {"", "-", "1-2-3", "1-2-ABCD", "not a destination",
                           "1-2-ABCD-9-", "1-2-ABCD-9-Z9"}) {
    EXPECT_FALSE(CryptoNote::namesDepositRoute(junk)) << "[" << junk << "]";
  }
}

// A checksum failure must not flip the answer to "no route asserted" in a way
// that would make a deposit-form request look like a base-account one.
TEST(PqPaymentProof, ACorruptedDepositNumberStillDoesNotVerifyAsABaseAccount) {
  const uint32_t fp = 0x5A3C1;
  const CryptoNote::AccountNumber account{1234, 7};
  std::string deposit = account.toStringWithIndex(3, fp);
  ASSERT_TRUE(CryptoNote::namesDepositRoute(deposit));

  // Break the check character. It is now not a valid destination at all, and the
  // handler rejects it before reaching the proof.
  deposit.back() = (deposit.back() == 'Z') ? 'Y' : 'Z';
  CryptoNote::AccountNumber parsed;
  uint32_t parsedFp = 0;
  EXPECT_FALSE(CryptoNote::namesDepositRoute(deposit));
  EXPECT_FALSE(CryptoNote::AccountNumber::fromString(deposit, parsed, parsedFp));
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
