// Copyright (c) 2026, The Karbo developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "PqPaymentProof.h"

#include <algorithm>
#include <cstring>
#include <limits>

#include "PqBech32.h"
#include "PqDerive.h"

namespace CryptoNote {

namespace {

constexpr char kSpendAuthorityDomain[] = "discrete-pq-spend-authority-v1";
constexpr std::size_t kFixedProofBytes = 1 + 32 + 32 + 32 + 4;
constexpr std::size_t kEntryBytes = 4 + 32;
static_assert(sizeof(CryptoPQ::Rho) == 32, "payment proof rho size mismatch");

void appendLe32(std::string& out, uint32_t value) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>(value >> (8 * i)));
}

bool takeLe32(const std::string& in, std::size_t& offset, uint32_t& value) {
  if (offset + 4 > in.size()) return false;
  value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<uint32_t>(static_cast<uint8_t>(in[offset + i])) << (8 * i);
  }
  offset += 4;
  return true;
}

template <std::size_t N>
bool takeArray(const std::string& in, std::size_t& offset, std::array<uint8_t, N>& out) {
  if (offset + N > in.size()) return false;
  std::memcpy(out.data(), in.data() + offset, N);
  offset += N;
  return true;
}

bool parsePayload(const std::string& payload, PqPaymentProof& proof) {
  if (payload.size() < kFixedProofBytes) return false;
  std::size_t offset = 0;
  proof = {};
  proof.version = static_cast<uint8_t>(payload[offset++]);
  if (proof.version != kPqPaymentProofVersion ||
      !takeArray(payload, offset, proof.genesisId) ||
      !takeArray(payload, offset, proof.txid) ||
      !takeArray(payload, offset, proof.spendAuthorityHash)) {
    return false;
  }
  uint32_t count = 0;
  if (!takeLe32(payload, offset, count) || count == 0 ||
      count > kMaxPqPaymentProofEntries ||
      payload.size() - offset != static_cast<std::size_t>(count) * kEntryBytes) {
    return false;
  }
  proof.entries.resize(count);
  for (auto& entry : proof.entries) {
    if (!takeLe32(payload, offset, entry.outputIndex) ||
        !takeArray(payload, offset, entry.rho)) {
      proof = {};
      return false;
    }
  }
  return true;
}

std::string proofPayload(const PqPaymentProof& proof) {
  if (proof.version != kPqPaymentProofVersion || proof.entries.empty() ||
      proof.entries.size() > kMaxPqPaymentProofEntries) {
    throw PqPaymentProofError("invalid payment proof shape");
  }
  std::string payload;
  payload.reserve(kFixedProofBytes + proof.entries.size() * kEntryBytes);
  payload.push_back(static_cast<char>(proof.version));
  payload.append(reinterpret_cast<const char*>(proof.genesisId.data()), proof.genesisId.size());
  payload.append(reinterpret_cast<const char*>(proof.txid.data()), proof.txid.size());
  payload.append(reinterpret_cast<const char*>(proof.spendAuthorityHash.data()),
                 proof.spendAuthorityHash.size());
  appendLe32(payload, static_cast<uint32_t>(proof.entries.size()));
  for (const auto& entry : proof.entries) {
    appendLe32(payload, entry.outputIndex);
    payload.append(reinterpret_cast<const char*>(entry.rho.data()), entry.rho.size());
  }
  return payload;
}

}  // namespace

CryptoPQ::Hash256 pqSpendAuthorityHash(const CryptoPQ::DsaPublicKey& spendPub) {
  std::string preimage(kSpendAuthorityDomain, sizeof(kSpendAuthorityDomain) - 1);
  preimage.append(reinterpret_cast<const char*>(spendPub.data()), spendPub.size());
  return CryptoPQ::sha3_256(preimage.data(), preimage.size());
}

PqPaymentProof makePqPaymentProof(
    const CryptoPQ::Hash256& genesisId,
    const CryptoPQ::Hash256& txid,
    const ResolvedRecipient& recipient,
    std::vector<PqPaymentProofEntry> entries) {
  if (entries.empty() || entries.size() > kMaxPqPaymentProofEntries) {
    throw PqPaymentProofError("payment proof must contain 1..64 entries");
  }
  std::sort(entries.begin(), entries.end(),
            [](const auto& a, const auto& b) { return a.outputIndex < b.outputIndex; });
  if (std::adjacent_find(entries.begin(), entries.end(),
                         [](const auto& a, const auto& b) {
                           return a.outputIndex == b.outputIndex;
                         }) != entries.end()) {
    throw PqPaymentProofError("duplicate payment proof output index");
  }
  PqPaymentProof proof;
  proof.genesisId = genesisId;
  proof.txid = txid;
  proof.spendAuthorityHash = pqSpendAuthorityHash(recipient.spendPub);
  proof.entries = std::move(entries);
  return proof;
}

std::string encodePqPaymentProof(const PqPaymentProof& proof, bool testnet) {
  return encodeBech32m(testnet ? kPqPaymentProofHrpTestnet : kPqPaymentProofHrpMainnet,
                       proofPayload(proof));
}

bool decodePqPaymentProof(const std::string& encoded, PqPaymentProof& proof) {
  std::string payload;
  if (!decodeBech32m(encoded, kPqPaymentProofHrpMainnet, payload) &&
      !decodeBech32m(encoded, kPqPaymentProofHrpTestnet, payload)) {
    return false;
  }
  return parsePayload(payload, proof);
}

bool decodePqPaymentProof(const std::string& encoded, bool testnet, PqPaymentProof& proof) {
  std::string payload;
  if (!decodeBech32m(encoded,
                     testnet ? kPqPaymentProofHrpTestnet : kPqPaymentProofHrpMainnet,
                     payload)) {
    return false;
  }
  return parsePayload(payload, proof);
}

uint64_t verifyPqPaymentProof(
    const PqPaymentProof& proof,
    const CryptoPQ::Hash256& expectedGenesisId,
    const PqPaymentProofTransaction& tx,
    const ResolvedRecipient& recipient) {
  if (proof.version != kPqPaymentProofVersion) {
    throw PqPaymentProofError("unsupported payment proof version");
  }
  if (proof.genesisId != expectedGenesisId) {
    throw PqPaymentProofError("payment proof network mismatch");
  }
  if (proof.txid != tx.txid) {
    throw PqPaymentProofError("payment proof transaction mismatch");
  }
  if (proof.spendAuthorityHash != pqSpendAuthorityHash(recipient.spendPub)) {
    throw PqPaymentProofError("payment proof spend authority mismatch");
  }
  if (proof.entries.empty() || proof.entries.size() > kMaxPqPaymentProofEntries) {
    throw PqPaymentProofError("invalid payment proof entry count");
  }

  std::vector<bool> seen(tx.outputs.size(), false);
  uint64_t total = 0;
  for (const auto& entry : proof.entries) {
    if (entry.outputIndex >= tx.outputs.size() || seen[entry.outputIndex]) {
      throw PqPaymentProofError("duplicate or out-of-range payment proof output index");
    }
    seen[entry.outputIndex] = true;
    const CryptoPQ::PqScanOutput& output = tx.outputs[entry.outputIndex];
    if (output.outputIndex != entry.outputIndex) {
      throw PqPaymentProofError("non-canonical transaction output index");
    }

    if (CryptoPQ::spendCommit(recipient.spendPub, entry.rho) != output.spendCommit) {
      throw PqPaymentProofError("payment proof spend commitment mismatch");
    }
    if (total > std::numeric_limits<uint64_t>::max() - output.amount) {
      throw PqPaymentProofError("payment proof amount overflow");
    }
    total += output.amount;
  }
  return total;
}

}  // namespace CryptoNote
