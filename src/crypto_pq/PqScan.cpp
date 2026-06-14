// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#include "PqScan.h"

#include <array>
#include <cstring>

#include "PqAead.h"

namespace CryptoPQ {

std::optional<PqOwnedOutput> scanPqOutput(const PqScanKeys& keys,
                                          const Hash256& inputsHash,
                                          const PqScanOutput& out,
                                          uint64_t subaddrIndexT) {
  // 1. Recover the shared secret. FIPS 203 decaps never errors; on a non-owned
  //    or malformed ciphertext it returns a pseudorandom secret, so the AEAD
  //    tag below is the real ownership filter.
  KemShared ss = kem_decaps(keys.viewSk, out.kemCt);

  // 2. Per-output context (binds inputs_hash, kem_ct, output_index, T).
  Hash256 oc = outContext(inputsHash, out.kemCt, out.outputIndex, subaddrIndexT);

  // 3. Decrypt rho||T. aad = out_context || LE64(amount) — binds the on-chain
  //    amount, so a tampered amount fails here.
  Hash256 aeadKey = deriveAeadKey(ss, oc);  // Hash256 == AeadKey
  AeadNonce nonce{};                        // 12 zero bytes
  std::array<uint8_t, 40> aad{};
  std::memcpy(aad.data(), oc.data(), oc.size());
  for (int i = 0; i < 8; ++i) {
    aad[32 + i] = static_cast<uint8_t>((out.amount >> (8 * i)) & 0xFF);
  }

  std::optional<std::vector<uint8_t>> maybePt =
      aead_decrypt(aeadKey, nonce, aad.data(), aad.size(),
                   out.encPayload.data(), out.encPayload.size());
  if (!maybePt || maybePt->size() != 40) {
    return std::nullopt;  // not ours, or amount/payload tampered — silent
  }

  Rho rho{};
  std::memcpy(rho.data(), maybePt->data(), 32);

  // Verify the T in the payload matches the T used to derive outContext.
  // A tampered T would have produced a different key, so this is belt-and-braces.
  uint64_t recoveredT = 0;
  for (int i = 0; i < 8; ++i)
    recoveredT |= static_cast<uint64_t>((*maybePt)[32 + i]) << (8 * i);
  if (recoveredT != subaddrIndexT) {
    return std::nullopt;
  }

  // 4. Final ownership gate: recompute spend_commit with OUR long-term spend
  //    public key. A garbage output that decrypts under our key but binds a
  //    different spend key is discarded here.
  if (spendCommit(keys.spendPub, rho) != out.spendCommit) {
    return std::nullopt;
  }

  PqOwnedOutput owned;
  owned.outputIndex = out.outputIndex;
  owned.amount = out.amount;
  owned.subaddrIndexT = subaddrIndexT;
  owned.rho = rho;
  owned.outContext = oc;
  return owned;
}

std::vector<PqOwnedOutput> scanPqOutputs(const PqScanKeys& keys,
                                         const Hash256& inputsHash,
                                         const std::vector<PqScanOutput>& outputs,
                                         uint64_t subaddrIndexT) {
  std::vector<PqOwnedOutput> owned;
  for (const auto& o : outputs) {
    if (auto rec = scanPqOutput(keys, inputsHash, o, subaddrIndexT)) {
      owned.push_back(*rec);
    }
  }
  return owned;
}

std::optional<PqAggregateOwned> scanPqOutputAggregate(
    const KemSecretKey& viewSk,
    const std::vector<DsaPublicKey>& spendPubs,
    const Hash256& inputsHash,
    const PqScanOutput& out) {
  // 1. The one expensive step: decapsulate with the shared view key.
  KemShared ss = kem_decaps(viewSk, out.kemCt);

  // 2. Iterate T = 0..spendPubs.size()-1. Each T gives a distinct outContext
  //    (and thus a distinct AEAD key). The output was built with T=spendPubIndex,
  //    so only the matching T decrypts successfully.
  AeadNonce nonce{};
  for (std::size_t i = 0; i < spendPubs.size(); ++i) {
    const uint64_t T = static_cast<uint64_t>(i);
    Hash256 oc = outContext(inputsHash, out.kemCt, out.outputIndex, T);
    Hash256 aeadKey = deriveAeadKey(ss, oc);

    std::array<uint8_t, 40> aad{};
    std::memcpy(aad.data(), oc.data(), oc.size());
    for (int j = 0; j < 8; ++j)
      aad[32 + j] = static_cast<uint8_t>((out.amount >> (8 * j)) & 0xFF);

    auto maybePt = aead_decrypt(aeadKey, nonce, aad.data(), aad.size(),
                                out.encPayload.data(), out.encPayload.size());
    if (!maybePt || maybePt->size() != 40) continue;

    // Verify recovered T matches the index we tried.
    uint64_t recoveredT = 0;
    for (int j = 0; j < 8; ++j)
      recoveredT |= static_cast<uint64_t>((*maybePt)[32 + j]) << (8 * j);
    if (recoveredT != T) continue;

    Rho rho{};
    std::memcpy(rho.data(), maybePt->data(), 32);

    if (spendCommit(spendPubs[i], rho) != out.spendCommit) continue;

    PqAggregateOwned res;
    res.record.outputIndex = out.outputIndex;
    res.record.amount = out.amount;
    res.record.subaddrIndexT = T;
    res.record.rho = rho;
    res.record.outContext = oc;
    res.spendPubIndex = i;
    return res;
  }
  return std::nullopt;
}

}  // namespace CryptoPQ
