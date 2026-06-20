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

#include "MiningKeyLoader.h"

#include <array>
#include <fstream>
#include <system_error>

#include "Common/FileMappedVector.h"
#include "Common/MemoryInputStream.h"
#include "Common/StdInputStream.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"   // NULL_SECRET_KEY
#include "Logging/LoggerRef.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "crypto/chacha8.h"
#include "crypto/crypto.h"                     // Crypto::cn_context
#include "crypto/crypto-util.h"                // sodium_memzero

#include "WalletErrors.h"
#include "WalletIndices.h"          // EncryptedWalletRecord, ContainerStorage
#include "WalletLegacy/KeysStorage.h"  // legacy single-blob keypair DTO
#include "WalletSerializationV2.h"  // version constants
#include "WalletUtils.h"            // throwIfKeysMissmatch

using namespace Crypto;

namespace CryptoNote {

namespace {

// On-disk container prefix. Must match WalletGreen::ContainerStoragePrefix — it
// is part of the wallet file format, not a private implementation detail.
#pragma pack(push, 1)
struct ContainerStoragePrefix {
  uint8_t version;
  Crypto::chacha8_iv nextIv;
  EncryptedWalletRecord encryptedViewKeys;
};
#pragma pack(pop)

// Mirrors WalletGreen::decryptKeyPair. Zeroizes its plaintext scratch buffer so
// no decrypted key material survives on the stack past this call.
void decryptKeyPair(const EncryptedWalletRecord& cipher, PublicKey& publicKey,
                    SecretKey& secretKey, uint64_t& creationTimestamp,
                    const chacha8_key& key) {
  std::array<char, sizeof(cipher.data)> buffer;
  chacha8(cipher.data, sizeof(cipher.data), key, cipher.iv, buffer.data());

  Common::MemoryInputStream stream(buffer.data(), buffer.size());
  BinaryInputStreamSerializer serializer(stream);
  serializer(publicKey, "publicKey");
  serializer(secretKey, "secretKey");
  serializer.binary(&creationTimestamp, sizeof(uint64_t), "creationTimestamp");

  sodium_memzero(buffer.data(), buffer.size());
}

// Read the spend secret from a legacy (pre-FileMappedVector) container. The
// whole wallet is a single chacha8 blob holding a KeysStorage at its head; we
// decrypt it, take the keypair, and ignore the transaction-history details that
// follow. Mirrors WalletLegacySerializer::deserialize but is strictly read-only
// (it never rewrites the file), so no in-place upgrade is forced on the user —
// we only need the keys.
Crypto::SecretKey loadLegacySpendSecret(const std::string& path,
                                        const std::string& password) {
  std::ifstream file(path, std::ios_base::binary);
  if (!file) {
    throw std::system_error(make_error_code(error::WRONG_STATE),
                            "Failed to open wallet '" + path + "'");
  }

  // Outer envelope: version, chacha8 IV, encrypted blob.
  uint32_t version = 0;
  chacha8_iv iv;
  std::string cipher;
  {
    Common::StdInputStream stdStream(file);
    BinaryInputStreamSerializer envelope(stdStream);
    envelope.beginObject("wallet");
    envelope(version, "version");
    envelope(iv, "iv");
    envelope(cipher, "data");
    envelope.endObject();
  }

  chacha8_key key;
  {
    cn_context cnContext;
    generate_chacha8_key(cnContext, password, key);
  }
  std::string plain(cipher.size(), '\0');
  chacha8(cipher.data(), cipher.size(), key, iv, &plain[0]);
  sodium_memzero(&key, sizeof(key));

  // Parse the keypair off the head of the decrypted blob. A wrong password
  // decrypts to garbage, which here surfaces as a serializer runtime_error.
  KeysStorage keys;
  try {
    Common::MemoryInputStream plainStream(plain.data(), plain.size());
    BinaryInputStreamSerializer serializer(plainStream);
    keys.serialize(serializer, "keys");
  } catch (const std::exception&) {
    sodium_memzero(&plain[0], plain.size());
    sodium_memzero(&keys, sizeof(keys));
    throw std::system_error(make_error_code(error::WRONG_PASSWORD),
                            "Wrong password, or corrupt wallet");
  }
  sodium_memzero(&plain[0], plain.size());  // keypair extracted; drop the plaintext

  Crypto::SecretKey spendSecret = keys.spendSecretKey;
  try {
    // A wrong password that happened to parse still yields a keypair that fails
    // these scalar/point checks (throwIfKeysMissmatch -> WRONG_PASSWORD).
    throwIfKeysMissmatch(keys.viewSecretKey, keys.viewPublicKey,
        "View key check failed (wrong password, or corrupt wallet)");
    if (spendSecret == NULL_SECRET_KEY) {
      throw std::system_error(make_error_code(error::WRONG_STATE),
          "Wallet is view-only (tracking) and has no spend key, so it cannot mine");
    }
    throwIfKeysMissmatch(spendSecret, keys.spendPublicKey,
        "Spend key check failed (wrong password, or corrupt wallet)");
  } catch (...) {
    sodium_memzero(&spendSecret, sizeof(spendSecret));
    sodium_memzero(&keys, sizeof(keys));
    throw;
  }
  sodium_memzero(&keys, sizeof(keys));
  return spendSecret;
}

}  // namespace

Crypto::SecretKey loadMiningSpendSecret(const std::string& path,
                                        const std::string& password,
                                        Logging::ILogger& log) {
  Logging::LoggerRef logger(log, "mining-key");

  // The on-disk version byte selects the parser: legacy (pre-FileMappedVector)
  // containers hold the keypair in a single chacha8 blob, the current WalletGreen
  // container uses a FileMappedVector. We only need the spend secret, so read
  // whichever is present — both paths are strictly read-only and never rewrite
  // the file, so no in-place upgrade is forced on the user.
  {
    std::ifstream probe(path, std::ios_base::binary);
    int peeked = probe.peek();
    if (peeked == EOF) {
      throw std::system_error(make_error_code(error::WRONG_VERSION),
                              "Failed to read wallet version from '" + path + "'");
    }
    uint8_t version = static_cast<uint8_t>(peeked);
    if (version < WalletSerializerV2::MIN_VERSION) {
      return loadLegacySpendSecret(path, password);
    }
    if (version > WalletSerializerV2::SERIALIZATION_VERSION) {
      throw std::system_error(make_error_code(error::WRONG_VERSION),
                              "Unsupported wallet version " + std::to_string(version));
    }
  }

  chacha8_key key;
  {
    cn_context cnContext;
    generate_chacha8_key(cnContext, password, key);
  }

  ContainerStorage storage;
  try {
    storage.open(path, Common::FileMappedVectorOpenMode::OPEN, sizeof(ContainerStoragePrefix));
  } catch (...) {
    sodium_memzero(&key, sizeof(key));
    throw;
  }

  Crypto::SecretKey spendSecret = NULL_SECRET_KEY;
  try {
    const ContainerStoragePrefix* prefix =
        reinterpret_cast<const ContainerStoragePrefix*>(storage.prefix());

    // Validating the view keypair also validates the password: a wrong password
    // yields garbage that fails the key/scalar check below.
    PublicKey viewPub;
    SecretKey viewSec;
    uint64_t ts;
    decryptKeyPair(prefix->encryptedViewKeys, viewPub, viewSec, ts, key);
    throwIfKeysMissmatch(viewSec, viewPub,
        "View key check failed (wrong password, or corrupt wallet)");
    sodium_memzero(&viewSec, sizeof(viewSec));

    if (storage.size() == 0) {
      throw std::system_error(make_error_code(error::WRONG_PASSWORD),
                              "Wallet container holds no spend keys");
    }

    PublicKey spendPub;
    uint64_t spendTs;
    decryptKeyPair(storage[0], spendPub, spendSecret, spendTs, key);

    if (spendSecret == NULL_SECRET_KEY) {
      throw std::system_error(make_error_code(error::WRONG_STATE),
          "Wallet is view-only (tracking) and has no spend key, so it cannot mine");
    }
    throwIfKeysMissmatch(spendSecret, spendPub,
        "Spend key check failed (wrong password, or corrupt wallet)");
  } catch (...) {
    sodium_memzero(&spendSecret, sizeof(spendSecret));
    sodium_memzero(&key, sizeof(key));
    storage.close();
    throw;
  }

  sodium_memzero(&key, sizeof(key));
  storage.close();
  return spendSecret;
}

}  // namespace CryptoNote
