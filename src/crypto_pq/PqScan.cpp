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

#include "PqScan.h"

#include <array>
#include <cstring>

#include "PqAead.h"
#include "Common/SecureMemory.h"

namespace CryptoPQ {

namespace {

// Pure AEAD mechanics under a given, already-computed context: no ownership
// check. Returns the recovered (rho, T) plaintext on success, nullopt if the
// tag fails to verify (not ours under this context, or tampered).
struct DecryptedPayload {
  Rho rho{};
  uint64_t subaddrIndexT = 0;
};

std::optional<DecryptedPayload> tryDecrypt(const KemShared& ss, const Hash256& oc,
                                           const PqScanOutput& out) {
  // aad = out_context || LE64(amount) — binds the on-chain amount, so a
  // tampered amount fails here.
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
    return std::nullopt;  // not ours under this context, or payload tampered
  }

  DecryptedPayload dp;
  std::memcpy(dp.rho.data(), maybePt->data(), 32);
  for (int i = 0; i < 8; ++i)
    dp.subaddrIndexT |= static_cast<uint64_t>((*maybePt)[32 + i]) << (8 * i);
  return dp;
}

// Final ownership gate shared by every recognition path: recompute
// spend_commit with OUR long-term spend public key. A garbage output that
// decrypts under our key but binds a different spend key is discarded here.
std::optional<PqOwnedOutput> finishOwned(const DsaPublicKey& spendPub,
                                         const PqScanOutput& out,
                                         const DecryptedPayload& dp,
                                         const Hash256& oc) {
  if (spendCommit(spendPub, dp.rho) != out.spendCommit) {
    return std::nullopt;
  }
  PqOwnedOutput owned;
  owned.outputIndex = out.outputIndex;
  owned.amount = out.amount;
  owned.subaddrIndexT = dp.subaddrIndexT;
  owned.rho = dp.rho;
  owned.outContext = oc;
  return owned;
}

// Fast recognition path: try outContext-v2 (T-independent; T is read back
// from the decrypted payload), then fall back once to the legacy pre-v2
// derivation at T=0. Callers that own issued SingleKeyIndex T values use
// scanPqOutputLegacyTWindow after this O(1) path misses.
std::optional<PqOwnedOutput> tryOwned(const KemShared& ss, const DsaPublicKey& spendPub,
                                      const Hash256& inputsHash, const PqScanOutput& out) {
  Hash256 ocV2 = outContext(inputsHash, out.kemCt, out.outputIndex);
  if (auto dp = tryDecrypt(ss, ocV2, out)) {
    if (auto owned = finishOwned(spendPub, out, *dp, ocV2)) {
      return owned;
    }
  }

  Hash256 ocLegacy = legacyOutContextV1(inputsHash, out.kemCt, out.outputIndex, /*T=*/0);
  if (auto dp = tryDecrypt(ss, ocLegacy, out)) {
    // Belt-and-braces: the legacy key was derived at T=0, so the payload's T
    // must also read back as 0 (a mismatch means a tampered/malformed payload).
    if (dp->subaddrIndexT == 0) {
      if (auto owned = finishOwned(spendPub, out, *dp, ocLegacy)) {
        return owned;
      }
    }
  }

  return std::nullopt;
}

std::optional<PqOwnedOutput> tryOwnedLegacyTWindow(
    const KemShared& ss, const DsaPublicKey& spendPub,
    const Hash256& inputsHash, const PqScanOutput& out,
    uint64_t firstT, uint64_t maxT) {
  for (uint64_t t = firstT; t < maxT; ++t) {
    Hash256 oc = legacyOutContextV1(inputsHash, out.kemCt, out.outputIndex, t);
    auto dp = tryDecrypt(ss, oc, out);
    if (dp && dp->subaddrIndexT == t) {
      if (auto owned = finishOwned(spendPub, out, *dp, oc)) {
        return owned;
      }
    }
  }
  return std::nullopt;
}

}  // namespace

std::optional<PqOwnedOutput> scanPqOutputWithSharedSecret(
    const KemShared& sharedSecret,
    const DsaPublicKey& recipientSpendPub,
    const Hash256& inputsHash,
    const PqScanOutput& out) {
  return tryOwned(sharedSecret, recipientSpendPub, inputsHash, out);
}

std::optional<PqOwnedOutput> scanPqOutput(const PqScanKeys& keys,
                                          const Hash256& inputsHash,
                                          const PqScanOutput& out) {
  // Recover the shared secret. FIPS 203 decaps never errors; on a non-owned
  // or malformed ciphertext it returns a pseudorandom secret, so the AEAD
  // tag inside tryOwned is the real ownership filter.
  KemShared ss = kem_decaps(keys.viewSk, out.kemCt);
  Tools::SecretLock sharedSecretLock(ss.data(), ss.size());
  return scanPqOutputWithSharedSecret(ss, keys.spendPub, inputsHash, out);
}

std::optional<PqOwnedOutput> scanPqOutputWithLegacyTWindow(
    const PqScanKeys& keys, const Hash256& inputsHash,
    const PqScanOutput& out, uint64_t maxT) {
  // Decapsulate exactly once. The common current-format path returns before any
  // enumeration; tryOwned also covers the legacy T=0 compatibility case.
  KemShared ss = kem_decaps(keys.viewSk, out.kemCt);
  Tools::SecretLock sharedSecretLock(ss.data(), ss.size());
  if (auto owned = tryOwned(ss, keys.spendPub, inputsHash, out)) {
    return owned;
  }

  // T=0 was already attempted by tryOwned, so the bounded compatibility scan
  // starts at 1 and never repeats either the KEM or the T=0 AEAD work.
  return tryOwnedLegacyTWindow(ss, keys.spendPub, inputsHash, out, 1, maxT);
}

std::optional<PqOwnedOutput> scanPqOutputLegacyTWindow(const PqScanKeys& keys,
                                                       const Hash256& inputsHash,
                                                       const PqScanOutput& out,
                                                       uint64_t maxT) {
  KemShared ss = kem_decaps(keys.viewSk, out.kemCt);
  Tools::SecretLock sharedSecretLock(ss.data(), ss.size());
  return tryOwnedLegacyTWindow(ss, keys.spendPub, inputsHash, out, 0, maxT);
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
  // Spec 1 (aggregated-multikey): one shared ML-KEM view key decapsulates the
  // output; the DEPOSIT is distinguished by which deposit spend key the output
  // commits to (the spec's distinguisher), NOT by the subaddress index. A Spec-1
  // deposit address is a plain PQ address, so the sender uses subaddress T=0.
  //
  // So: decapsulate once, decrypt once (v2, falling back to legacy T=0), then
  // test spendCommit against each deposit spend key to find the matching deposit.
  KemShared ss = kem_decaps(viewSk, out.kemCt);
  Tools::SecretLock sharedSecretLock(ss.data(), ss.size());

  Hash256 oc = outContext(inputsHash, out.kemCt, out.outputIndex);
  auto dp = tryDecrypt(ss, oc, out);
  if (!dp) {
    oc = legacyOutContextV1(inputsHash, out.kemCt, out.outputIndex, /*T=*/0);
    dp = tryDecrypt(ss, oc, out);
  }
  if (!dp || dp->subaddrIndexT != 0) return std::nullopt;

  // Route by deposit spend key: the matching deposit is the one whose spendPub
  // reproduces the on-chain spendCommit.
  for (std::size_t i = 0; i < spendPubs.size(); ++i) {
    if (spendCommit(spendPubs[i], dp->rho) != out.spendCommit) continue;

    PqAggregateOwned res;
    res.record.outputIndex = out.outputIndex;
    res.record.amount = out.amount;
    res.record.subaddrIndexT = dp->subaddrIndexT;
    res.record.rho = dp->rho;
    res.record.outContext = oc;
    res.spendPubIndex = i;
    return res;
  }
  return std::nullopt;
}

}  // namespace CryptoPQ
