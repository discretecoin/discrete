// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2019, Karbo developers
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

#pragma once

#include <vector>
#include <ostream>
#include <istream>

#include "crypto/hash.h"
#include "crypto/chacha8.h"

namespace CryptoNote {
class AccountBase;
class ISerializer;
}

namespace CryptoNote {

class WalletLegacySerializer {
public:
  static constexpr uint32_t STANDARD_VERSION = 2;
  static constexpr uint32_t PROTECTED_SPEND_VERSION = 3;

  // Outer envelope marker. A file starting with this instead of a content
  // version is salted and authenticated:
  //
  //   AUTHENTICATED_ENVELOPE | salt(32) | nonce(12) | AEAD(payload) || tag
  //
  // and the content version lives inside the payload. Keeping it separate from
  // the content version leaves STANDARD_VERSION / PROTECTED_SPEND_VERSION
  // meaning exactly what they meant before.
  //
  // Versions 1-3 are the old envelope: raw ChaCha8 with no tag, under a key
  // derived from the password alone. Unauthenticated means anyone who can write
  // the file can flip chosen bits of the decrypted plaintext, and unsalted means
  // one derivation serves every wallet with that password. Those files still
  // open, and are rewritten in the new envelope on the next save.
  //
  // The value has to stay below 6: both wallet products identify a file by its
  // first byte, and 6 and above means "container".
  static constexpr uint32_t AUTHENTICATED_ENVELOPE = 4;

  explicit WalletLegacySerializer(
      CryptoNote::AccountBase& account,
      uint32_t serializationVersion = STANDARD_VERSION);

  void serialize(std::ostream& stream, const std::string& password, bool saveDetailed, const std::string& cache);
  void deserialize(std::istream& stream, const std::string& password, std::string& cache);
  bool deserialize(std::istream& stream, const std::string& password);
  uint32_t loadedVersion() const { return loadedWalletSerializationVersion; }

private:
  void saveProtectedSpendCompatibilityGuard(CryptoNote::ISerializer& serializer);
  void loadProtectedSpendCompatibilityGuard(CryptoNote::ISerializer& serializer);
  void saveKeys(CryptoNote::ISerializer& serializer);
  void loadKeys(CryptoNote::ISerializer& serializer);

  // Legacy envelope (versions 1-3), read-only apart from the test that pins it.
  Crypto::chacha8_iv encrypt(const std::string& plain, const std::string& password, std::string& cipher);
  void decrypt(const std::string& cipher, std::string& plain, Crypto::chacha8_iv iv, const std::string& password);

  // Read the payload out of either envelope. Throws WRONG_PASSWORD when the
  // password is wrong or, in the new envelope, when the file has been tampered
  // with; the two are deliberately indistinguishable.
  void readPayload(std::istream& stream, const std::string& password,
                   std::string& payload, uint32_t& contentVersion);

  CryptoNote::AccountBase& account;
  const uint32_t walletSerializationVersion;
  uint32_t loadedWalletSerializationVersion;
};

extern uint32_t WALLET_LEGACY_SERIALIZATION_VERSION;

} //namespace CryptoNote
