// Copyright (c) 2026, The Karbo developers
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

constexpr uint8_t kPqPaymentProofVersion = 1;
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
  CryptoPQ::KemEncapsMessage message{};

  ~PqPaymentProofEntry();
};

struct PqPaymentProof {
  uint8_t version = kPqPaymentProofVersion;
  CryptoPQ::Hash256 genesisId{};
  CryptoPQ::Hash256 txid{};
  CryptoPQ::Hash256 recipientDescriptorHash{};
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

CryptoPQ::Hash256 pqRecipientDescriptorHash(const ResolvedRecipient& recipient);

PqPaymentProof makePqPaymentProof(
    const CryptoPQ::Hash256& genesisId,
    const CryptoPQ::Hash256& txid,
    const ResolvedRecipient& recipient,
    std::vector<PqPaymentProofEntry> entries);

std::string encodePqPaymentProof(const PqPaymentProof& proof, bool testnet);
bool decodePqPaymentProof(const std::string& encoded, PqPaymentProof& proof);
bool decodePqPaymentProof(const std::string& encoded, bool testnet, PqPaymentProof& proof);

// Perform the complete receiver scan predicate for every proof entry and return
// the checked total. Throws PqPaymentProofError on any binding, index, KEM,
// payload, amount, T, or spend-commit failure.
uint64_t verifyPqPaymentProof(
    const PqPaymentProof& proof,
    const CryptoPQ::Hash256& expectedGenesisId,
    const PqPaymentProofTransaction& tx,
    const ResolvedRecipient& recipient);

}  // namespace CryptoNote
