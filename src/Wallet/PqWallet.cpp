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

#include "PqWallet.h"

#include <algorithm>

#include "Common/StringTools.h"
#include "crypto/crypto-util.h"
#include "crypto_pq/PqHash.h"

namespace CryptoNote {

namespace {
// Any PQ address (base58 ~4300 chars, bech32m ~5000) is vastly longer than a
// classical Karbo address (~98, ~187 with payment id). This length floor cheaply
// rejects classical strings before any decode work; it sits comfortably below
// the shortest real PQ address.
constexpr std::size_t kMinPqAddressChars = 300;

template <typename ArrayT>
void appendHex(std::string& out, const ArrayT& bytes) {
  out += Common::toHex(bytes.data(), bytes.size());
}

template <typename ArrayT>
bool readHexField(const std::string& hex, std::size_t& offset, ArrayT& bytes) {
  const std::size_t hexLen = bytes.size() * 2;
  if (offset + hexLen > hex.size()) {
    return false;
  }
  size_t decoded = 0;
  if (!Common::fromHex(hex.substr(offset, hexLen), bytes.data(), bytes.size(), decoded) ||
      decoded != bytes.size()) {
    return false;
  }
  offset += hexLen;
  return true;
}
}  // namespace

CryptoPQ::SeedMaster pqSeedMasterFromSpendSecret(const Crypto::SecretKey& spendSecretKey) noexcept {
  // HKDF default instantiation (salt = 0x00*32, L = 32). The classical 32-byte
  // spend scalar is the IKM; the domain string isolates the PQ master seed from
  // any other use of the spend key.
  CryptoPQ::Hash256 okm = CryptoPQ::hkdf_sha3_256(
      spendSecretKey.data, sizeof(spendSecretKey.data),
      kPqWalletSeedDomain, sizeof(kPqWalletSeedDomain) - 1);
  CryptoPQ::SeedMaster seed{};
  std::copy(okm.begin(), okm.end(), seed.begin());
  return seed;
}

CryptoPQ::SeedMaster generatePqSeedMaster() {
  CryptoPQ::SeedMaster seed{};
  secure_random_bytes(seed.data(), seed.size());
  return seed;
}

PqWalletKeys derivePqWalletKeys(const Crypto::SecretKey& spendSecretKey) {
  return derivePqWalletKeys(pqSeedMasterFromSpendSecret(spendSecretKey));
}

PqWalletKeys derivePqWalletKeys(const CryptoPQ::SeedMaster& seedMaster) {
  PqWalletKeys keys;
  keys.seedMaster = seedMaster;

  auto view = CryptoPQ::deriveViewKeys(keys.seedMaster);
  keys.viewPub = view.first;
  keys.viewSk  = view.second;

  auto spend = CryptoPQ::deriveSpendKeys(keys.seedMaster);
  keys.spendPub = spend.first;
  keys.spendSk  = spend.second;

  return keys;
}

PqTrackingKeys pqTrackingKeys(const PqWalletKeys& keys) {
  PqTrackingKeys tracking;
  tracking.viewPub = keys.viewPub;
  tracking.viewSk = keys.viewSk;
  tracking.spendPub = keys.spendPub;
  return tracking;
}

PqAddress pqWalletAddress(const PqWalletKeys& keys, uint64_t networkPrefix) {
  return makePqAddress(networkPrefix, keys.viewPub, keys.spendPub);
}

PqAddress pqWalletAddress(const PqTrackingKeys& keys, uint64_t networkPrefix) {
  return makePqAddress(networkPrefix, keys.viewPub, keys.spendPub);
}

PqAddress pqWalletAddress(const Crypto::SecretKey& spendSecretKey, uint64_t networkPrefix) {
  return pqWalletAddress(derivePqWalletKeys(spendSecretKey), networkPrefix);
}

CryptoPQ::PqScanKeys pqScanKeys(const PqWalletKeys& keys) {
  return CryptoPQ::PqScanKeys{ keys.viewSk, keys.spendPub };
}

CryptoPQ::PqScanKeys pqScanKeys(const PqTrackingKeys& keys) {
  return CryptoPQ::PqScanKeys{ keys.viewSk, keys.spendPub };
}

std::string encodePqTrackingKey(const PqTrackingKeys& keys) {
  std::string out = kPqTrackingKeyPrefix;
  out.reserve(out.size() + (keys.viewPub.size() + keys.spendPub.size() + keys.viewSk.size()) * 2);
  appendHex(out, keys.viewPub);
  appendHex(out, keys.spendPub);
  appendHex(out, keys.viewSk);
  return out;
}

bool decodePqTrackingKey(const std::string& encoded, PqTrackingKeys& keys) {
  const std::string prefix(kPqTrackingKeyPrefix);
  if (encoded.compare(0, prefix.size(), prefix) != 0) {
    return false;
  }

  const std::string hex = encoded.substr(prefix.size());
  const std::size_t expectedHex =
      (keys.viewPub.size() + keys.spendPub.size() + keys.viewSk.size()) * 2;
  if (hex.size() != expectedHex) {
    return false;
  }

  PqTrackingKeys parsed;
  std::size_t offset = 0;
  if (!readHexField(hex, offset, parsed.viewPub) ||
      !readHexField(hex, offset, parsed.spendPub) ||
      !readHexField(hex, offset, parsed.viewSk) ||
      offset != hex.size()) {
    return false;
  }

  keys = parsed;
  return true;
}

bool isPqAddressString(const std::string& s) {
  if (s.size() < kMinPqAddressChars) {
    return false;
  }
  PqAddress out;
  return parsePqAddress(s, out, nullptr);
}

bool parsePqAddress(const std::string& s, PqAddress& out, PqAddressEncoding* encoding) {
  if (decodePqAddress(s, out, PqAddressEncoding::Base58)) {
    if (encoding) *encoding = PqAddressEncoding::Base58;
    return true;
  }
  if (decodePqAddress(s, out, PqAddressEncoding::Bech32m)) {
    if (encoding) *encoding = PqAddressEncoding::Bech32m;
    return true;
  }
  return false;
}

}  // namespace CryptoNote
