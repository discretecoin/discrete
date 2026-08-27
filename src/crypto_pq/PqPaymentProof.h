// Copyright (c) 2026, The Discrete developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "PqDsa.h"
#include "PqHash.h"
#include "PqKem.h"
#include "PqScan.h"

namespace CryptoNote {

constexpr uint8_t kPqPaymentProofVersion = 2;
constexpr char kPqPaymentProofHrpMainnet[] = "disctxp";
constexpr char kPqPaymentProofHrpTestnet[] = "tdisctxp";
constexpr std::size_t kMaxPqPaymentProofEntries = 64;

struct ResolvedRecipient {
  CryptoPQ::KemPublicKey viewPub{};
  CryptoPQ::DsaPublicKey spendPub{};
  uint64_t subaddrIndexT = 0;
};

struct PqPaymentProofEntry {
  uint32_t outputIndex = 0;
  CryptoPQ::Rho rho{};
};

struct PqPaymentProof {
  uint8_t version = kPqPaymentProofVersion;
  CryptoPQ::Hash256 genesisId{};
  CryptoPQ::Hash256 txid{};
  CryptoPQ::Hash256 spendAuthorityHash{};
  std::vector<PqPaymentProofEntry> entries;
};

// Transaction data needed by the pure verifier. The caller fetches/resolves the
// chain transaction, computes its canonical txid and inputs hash, and translates
// its PQ outputs. This keeps proof verification independent of wallet/node I/O.
struct PqPaymentProofTransaction {
  CryptoPQ::Hash256 txid{};
  CryptoPQ::Hash256 inputsHash{};
  std::vector<CryptoPQ::PqScanOutput> outputs;
};

class PqPaymentProofError : public std::runtime_error {
public:
  explicit PqPaymentProofError(const std::string& message) : std::runtime_error(message) {}
};

CryptoPQ::Hash256 pqSpendAuthorityHash(const CryptoPQ::DsaPublicKey& spendPub);

PqPaymentProof makePqPaymentProof(
    const CryptoPQ::Hash256& genesisId,
    const CryptoPQ::Hash256& txid,
    const ResolvedRecipient& recipient,
    std::vector<PqPaymentProofEntry> entries);

std::string encodePqPaymentProof(const PqPaymentProof& proof, bool testnet);
bool decodePqPaymentProof(const std::string& encoded, PqPaymentProof& proof);
bool decodePqPaymentProof(const std::string& encoded, bool testnet, PqPaymentProof& proof);

// Verify that every listed on-chain output commits to recipient.spendPub under
// the supplied rho and return their public amount total.
//
// This is a SPEND-AUTHORITY proof and nothing more. It does not claim ML-KEM /
// view-key delivery, and it does not attribute the payment to a SingleKeyIndex
// routing index T: recipient.subaddrIndexT is not read here and no field of the
// proof commits to it, so the same proof verifies identically for every T of the
// same account. Callers that need the route — invoice and deposit crediting —
// must establish it by decrypting the output with the recipient's view key.
uint64_t verifyPqPaymentProof(
    const PqPaymentProof& proof,
    const CryptoPQ::Hash256& expectedGenesisId,
    const PqPaymentProofTransaction& tx,
    const ResolvedRecipient& recipient);

}  // namespace CryptoNote
