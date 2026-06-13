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
                                          const PqScanOutput& out) {
  // 1. Recover the shared secret. FIPS 203 decaps never errors; on a non-owned
  //    or malformed ciphertext it returns a pseudorandom secret, so the AEAD
  //    tag below is the real ownership filter.
  KemShared ss = kem_decaps(keys.viewSk, out.kemCt);

  // 2. Per-output context (binds inputs_hash, kem_ct, output_index).
  Hash256 oc = outContext(inputsHash, out.kemCt, out.outputIndex);

  // 3. Decrypt rho. aad = out_context || LE64(amount) — binds the on-chain
  //    amount, so a tampered amount fails here.
  Hash256 aeadKey = deriveAeadKey(ss, oc);  // Hash256 == AeadKey
  AeadNonce nonce{};                        // 12 zero bytes
  std::array<uint8_t, 40> aad{};
  std::memcpy(aad.data(), oc.data(), oc.size());
  for (int i = 0; i < 8; ++i) {
    aad[32 + i] = static_cast<uint8_t>((out.amount >> (8 * i)) & 0xFF);
  }

  std::optional<std::vector<uint8_t>> maybeRho =
      aead_decrypt(aeadKey, nonce, aad.data(), aad.size(),
                   out.encPayload.data(), out.encPayload.size());
  if (!maybeRho || maybeRho->size() != 32) {
    return std::nullopt;  // not ours, or amount/payload tampered — silent
  }

  Rho rho{};
  std::memcpy(rho.data(), maybeRho->data(), 32);

  // 4. Final ownership gate: recompute spend_commit with OUR long-term spend
  //    public key. A garbage output that decrypts under our key but binds a
  //    different spend key is discarded here.
  if (spendCommit(keys.spendPub, rho) != out.spendCommit) {
    return std::nullopt;
  }

  PqOwnedOutput owned;
  owned.outputIndex = out.outputIndex;
  owned.amount = out.amount;
  owned.rho = rho;
  owned.outContext = oc;
  return owned;
}

std::vector<PqOwnedOutput> scanPqOutputs(const PqScanKeys& keys,
                                         const Hash256& inputsHash,
                                         const std::vector<PqScanOutput>& outputs) {
  std::vector<PqOwnedOutput> owned;
  for (const auto& o : outputs) {
    if (auto rec = scanPqOutput(keys, inputsHash, o)) {
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

  Hash256 oc = outContext(inputsHash, out.kemCt, out.outputIndex);
  Hash256 aeadKey = deriveAeadKey(ss, oc);

  AeadNonce nonce{};
  std::array<uint8_t, 40> aad{};
  std::memcpy(aad.data(), oc.data(), oc.size());
  for (int i = 0; i < 8; ++i) {
    aad[32 + i] = static_cast<uint8_t>((out.amount >> (8 * i)) & 0xFF);
  }

  std::optional<std::vector<uint8_t>> maybeRho =
      aead_decrypt(aeadKey, nonce, aad.data(), aad.size(),
                   out.encPayload.data(), out.encPayload.size());
  if (!maybeRho || maybeRho->size() != 32) {
    return std::nullopt;  // not for this service, or tampered
  }
  Rho rho{};
  std::memcpy(rho.data(), maybeRho->data(), 32);

  // 2. Cheap per-deposit-key check (SHA3 only, no further KEM work).
  for (std::size_t i = 0; i < spendPubs.size(); ++i) {
    if (spendCommit(spendPubs[i], rho) == out.spendCommit) {
      PqAggregateOwned res;
      res.record.outputIndex = out.outputIndex;
      res.record.amount = out.amount;
      res.record.rho = rho;
      res.record.outContext = oc;
      res.spendPubIndex = i;
      return res;
    }
  }
  return std::nullopt;
}

}  // namespace CryptoPQ
