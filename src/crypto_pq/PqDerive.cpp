// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Discrete is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Discrete is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Discrete.  If not, see <http://www.gnu.org/licenses/>.

#include "PqDerive.h"

#include <cstring>

namespace CryptoPQ {

namespace {

// Append the bytes of a domain tag, excluding the trailing NUL terminator.
template <std::size_t N>
void appendDomain(std::vector<uint8_t>& buf, const char (&tag)[N]) {
  // N includes the NUL; hash N-1 bytes.
  buf.insert(buf.end(), tag, tag + (N - 1));
}

void appendBytes(std::vector<uint8_t>& buf, const void* p, std::size_t n) {
  const auto* b = static_cast<const uint8_t*>(p);
  buf.insert(buf.end(), b, b + n);
}

void appendLe32(std::vector<uint8_t>& buf, uint32_t v) {
  buf.push_back(static_cast<uint8_t>(v & 0xFF));
  buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

void appendLe64(std::vector<uint8_t>& buf, uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
  }
}

}  // namespace

Hash256 inputsHash(const std::vector<InputRef>& inputs) noexcept {
  std::vector<uint8_t> buf;
  buf.reserve(sizeof(kDomainInputsHash) + inputs.size() * 36);
  appendDomain(buf, kDomainInputsHash);
  for (const auto& in : inputs) {
    appendBytes(buf, in.prevTxid.data(), in.prevTxid.size());
    appendLe32(buf, in.prevOutIndex);
  }
  return sha3_256(buf.data(), buf.size());
}

Hash256 outContext(const Hash256& inputsHash,
                   const KemCiphertext& kemCt,
                   uint32_t outputIndex) noexcept {
  std::vector<uint8_t> buf;
  buf.reserve(sizeof(kDomainOutContextV2) + 32 + kemCt.size() + 4);
  appendDomain(buf, kDomainOutContextV2);
  appendBytes(buf, inputsHash.data(), inputsHash.size());
  appendBytes(buf, kemCt.data(), kemCt.size());
  appendLe32(buf, outputIndex);
  return sha3_256(buf.data(), buf.size());
}

Hash256 legacyOutContextV1(const Hash256& inputsHash,
                           const KemCiphertext& kemCt,
                           uint32_t outputIndex,
                           uint64_t subaddrIndexT) noexcept {
  std::vector<uint8_t> buf;
  buf.reserve(sizeof(kDomainOutContext) + 32 + kemCt.size() + 4 + 8);
  appendDomain(buf, kDomainOutContext);
  appendBytes(buf, inputsHash.data(), inputsHash.size());
  appendBytes(buf, kemCt.data(), kemCt.size());
  appendLe32(buf, outputIndex);
  appendLe64(buf, subaddrIndexT);
  return sha3_256(buf.data(), buf.size());
}

Hash256 deriveAeadKey(const KemShared& ss, const Hash256& outContext) noexcept {
  std::vector<uint8_t> info;
  info.reserve(sizeof(kDomainAeadKey) + outContext.size());
  appendDomain(info, kDomainAeadKey);
  appendBytes(info, outContext.data(), outContext.size());
  return hkdf_sha3_256(ss.data(), ss.size(), info.data(), info.size());
}

Hash256 spendCommit(const DsaPublicKey& spendPub, const Rho& rho) noexcept {
  std::vector<uint8_t> buf;
  buf.reserve(sizeof(kDomainSpendCommit) + spendPub.size() + rho.size());
  appendDomain(buf, kDomainSpendCommit);
  appendBytes(buf, spendPub.data(), spendPub.size());
  appendBytes(buf, rho.data(), rho.size());
  return sha3_256(buf.data(), buf.size());
}

Hash256 nullifier(const DsaPublicKey& spendPub, const Rho& rho,
                  const Hash256& prevTxid, uint32_t prevOutIndex) noexcept {
  std::vector<uint8_t> buf;
  buf.reserve(sizeof(kDomainNullifier) + spendPub.size() + rho.size() + prevTxid.size() + 4);
  appendDomain(buf, kDomainNullifier);
  appendBytes(buf, spendPub.data(), spendPub.size());
  appendBytes(buf, rho.data(), rho.size());
  appendBytes(buf, prevTxid.data(), prevTxid.size());
  appendLe32(buf, prevOutIndex);
  return sha3_256(buf.data(), buf.size());
}

Rho coinbaseRho(const DsaPublicKey& spendPub, uint32_t height,
                uint32_t outputIndex) noexcept {
  std::vector<uint8_t> buf;
  buf.reserve(sizeof(kDomainCoinbaseRho) + spendPub.size() + 4 + 4);
  appendDomain(buf, kDomainCoinbaseRho);
  appendBytes(buf, spendPub.data(), spendPub.size());
  appendLe32(buf, height);
  appendLe32(buf, outputIndex);
  return sha3_256(buf.data(), buf.size());
}

namespace {

// The transcript body shared by both versions: everything the transaction commits
// to except the per-input signatures.
void appendUnsignedTxBody(std::vector<uint8_t>& buf, const UnsignedTx& tx) {
  buf.push_back(tx.version);
  buf.push_back(tx.txType);
  appendLe64(buf, tx.unlockHeight);
  appendLe32(buf, static_cast<uint32_t>(tx.inputs.size()));
  for (const auto& in : tx.inputs) {
    appendBytes(buf, in.prevTxid.data(), in.prevTxid.size());
    appendLe32(buf, in.prevOutIndex);
    appendBytes(buf, in.authPub.data(), in.authPub.size());
    appendBytes(buf, in.rhoReveal.data(), in.rhoReveal.size());
  }
  appendLe32(buf, static_cast<uint32_t>(tx.outputs.size()));
  for (const auto& out : tx.outputs) {
    buf.push_back(out.type);
    appendLe64(buf, out.amount);
    appendLe64(buf, out.unlockHeight);
    appendBytes(buf, out.kemCt.data(), out.kemCt.size());
    appendBytes(buf, out.encPayload.data(), out.encPayload.size());
    appendBytes(buf, out.spendCommit.data(), out.spendCommit.size());
  }
  appendLe32(buf, static_cast<uint32_t>(tx.extra.size()));
  appendBytes(buf, tx.extra.data(), tx.extra.size());
  appendLe64(buf, tx.fee);
}

}  // namespace

Hash256 txSigningDigest(const UnsignedTx& tx) noexcept {
  std::vector<uint8_t> buf;
  appendDomain(buf, kDomainTxSign);
  appendUnsignedTxBody(buf, tx);
  return sha3_256(buf.data(), buf.size());
}

Hash256 txSigningDigestV2(const UnsignedTx& tx, const Hash256& chainId,
                          uint32_t inputIndex) noexcept {
  std::vector<uint8_t> buf;
  appendDomain(buf, kDomainTxSignV2);
  appendBytes(buf, chainId.data(), chainId.size());
  appendUnsignedTxBody(buf, tx);
  appendLe32(buf, inputIndex);
  return sha3_256(buf.data(), buf.size());
}

}  // namespace CryptoPQ
