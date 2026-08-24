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

#include "MiningKeyLoader.h"

#include <array>
#include <fstream>
#include <system_error>

#include "Common/FileMappedVector.h"
#include "Common/MemoryInputStream.h"
#include "Common/StdInputStream.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"   // NULL_SECRET_KEY
#include "CryptoNoteCore/CryptoNoteSerialization.h"  // chacha8_iv serialize overload
#include "Logging/LoggerRef.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "crypto/chacha8.h"
#include "crypto/crypto.h"                     // Crypto::cn_context
#include "crypto/crypto-util.h"                // sodium_memzero

#include "WalletErrors.h"
#include "WalletIndices.h"          // ContainerStorage(Prefix), seed-record codec
#include "WalletLegacy/WalletLegacySerializer.h"
#include "crypto_pq/PqAead.h"
#include "WalletLegacy/KeysStorage.h"  // simplewallet single-blob keystore DTO
#include "WalletSerializationV2.h"  // version constants

using namespace Crypto;

namespace CryptoNote {

namespace {

// Read the master seed from a simplewallet (WalletLegacy) container: a single
// chacha8 blob whose head is a KeysStorage. The wallet's PQ identity derives from
// spendSecretKey (now the 32-byte master seed), so that is what we return.
// Strictly read-only (never rewrites the file).
Crypto::SecretKey loadLegacyMasterSeed(const std::string& path, const std::string& password) {
  std::ifstream file(path, std::ios_base::binary);
  if (!file) {
    throw std::system_error(make_error_code(error::WRONG_STATE),
                            "Failed to open wallet '" + path + "'");
  }

  uint32_t version = 0;
  std::string plain;
  {
    Common::StdInputStream stdStream(file);
    BinaryInputStreamSerializer envelope(stdStream);
    envelope.beginObject("wallet");
    envelope(version, "version");

    if (version == WalletLegacySerializer::AUTHENTICATED_ENVELOPE) {
      std::string saltField, nonceField, dataField;
      envelope(saltField, "salt");
      envelope(nonceField, "nonce");
      envelope(dataField, "data");
      envelope.endObject();

      if (saltField.size() != sizeof(Crypto::Hash) ||
          nonceField.size() != CryptoPQ::kAeadNonceBytes ||
          dataField.size() < CryptoPQ::kAeadTagBytes) {
        throw std::system_error(make_error_code(error::WRONG_PASSWORD),
                                "Wrong password, or corrupt wallet");
      }

      Crypto::Hash salt{};
      std::memcpy(salt.data, saltField.data(), sizeof(salt.data));

      chacha8_key key;
      if (!Crypto::generate_chacha8_key_salted(password, salt, key)) {
        sodium_memzero(&key, sizeof(key));
        throw std::system_error(make_error_code(error::INTERNAL_WALLET_ERROR),
                                "Password key derivation failed");
      }

      CryptoPQ::AeadNonce nonce{};
      std::memcpy(nonce.data(), nonceField.data(), nonce.size());
      CryptoPQ::AeadKey aeadKey{};
      std::memcpy(aeadKey.data(), key.data, aeadKey.size());
      sodium_memzero(&key, sizeof(key));

      auto opened = CryptoPQ::aead_decrypt(aeadKey, nonce, salt.data, sizeof(salt.data),
                                           dataField.data(), dataField.size());
      sodium_memzero(aeadKey.data(), aeadKey.size());
      if (!opened) {
        throw std::system_error(make_error_code(error::WRONG_PASSWORD),
                                "Wrong password, or corrupt wallet");
      }

      // Skip the content version that leads the authenticated payload. It is a
      // varint, so read it rather than assuming a width.
      Common::MemoryInputStream payloadStream(opened->data(), opened->size());
      BinaryInputStreamSerializer payloadSerializer(payloadStream);
      uint32_t contentVersion = 0;
      payloadSerializer(contentVersion, "content_version");

      plain.assign(opened->begin() + payloadStream.getPosition(), opened->end());
      sodium_memzero(opened->data(), opened->size());
    } else {
      chacha8_iv iv;
      std::string cipher;
      envelope(iv, "iv");
      envelope(cipher, "data");
      envelope.endObject();

      chacha8_key key;
      cn_context cnContext;
      if (!generate_chacha8_key(cnContext, password, key)) {
        sodium_memzero(&key, sizeof(key));
        throw std::system_error(make_error_code(error::INTERNAL_WALLET_ERROR),
                                "Password key derivation failed");
      }
      plain.assign(cipher.size(), '\0');
      chacha8(cipher.data(), cipher.size(), key, iv, &plain[0]);
      sodium_memzero(&key, sizeof(key));
    }
  }

  KeysStorage keys;
  try {
    Common::MemoryInputStream plainStream(plain.data(), plain.size());
    BinaryInputStreamSerializer serializer(plainStream);
    keys.serialize(serializer, "keys");
  } catch (const std::exception&) {
    sodium_memzero(&plain[0], plain.size());
    sodium_memzero(&keys, sizeof(keys));
    throw std::system_error(make_error_code(error::WRONG_PASSWORD), "Wrong password, or corrupt wallet");
  }
  sodium_memzero(&plain[0], plain.size());

  Crypto::SecretKey seed = keys.spendSecretKey;
  // Password check: cn_fast_hash(seed) is stored in the spendPublicKey slot.
  Crypto::Hash checksum;
  Crypto::cn_fast_hash(seed.data, sizeof(seed.data), checksum);
  bool ok = std::memcmp(checksum.data, keys.spendPublicKey.data, sizeof(checksum.data)) == 0;
  sodium_memzero(&keys, sizeof(keys));
  if (!ok) {
    sodium_memzero(&seed, sizeof(seed));
    throw std::system_error(make_error_code(error::WRONG_PASSWORD), "Wrong password, or corrupt wallet");
  }
  if (seed == NULL_SECRET_KEY) {
    sodium_memzero(&seed, sizeof(seed));
    throw std::system_error(make_error_code(error::WRONG_STATE),
        "Wallet is view-only (tracking) and has no master seed, so it cannot mine");
  }
  return seed;
}

}  // namespace

Crypto::SecretKey loadMiningSpendSecret(const std::string& path,
                                        const std::string& password,
                                        Logging::ILogger& log) {
  Logging::LoggerRef logger(log, "mining-key");

  // Read-only: open the PQ wallet container and return its master seed (record 0).
  // The same seed the wallet derives its PQ identity from is what the daemon needs
  // to derive the matching PQ mining keys (deriveMinerPqKeys). The format (prefix +
  // encrypted seed record) is shared with WalletGreen via WalletIndices.h, so there
  // is a single source of truth. Pre-v9 (classical) wallets are not supported.
  {
    std::ifstream probe(path, std::ios_base::binary);
    // Distinguish "no such file" from "empty file" from "bad version byte".
    // Reporting all three as a version failure sent operators looking for a
    // format mismatch when the real cause was a path that never existed.
    if (!probe.is_open()) {
      throw std::system_error(make_error_code(error::WALLET_NOT_FOUND),
                              "Cannot open wallet file '" + path + "'");
    }
    int peeked = probe.peek();
    if (peeked == EOF) {
      throw std::system_error(make_error_code(error::WRONG_VERSION),
                              "Wallet file '" + path + "' is empty");
    }
    uint8_t version = static_cast<uint8_t>(peeked);
    if (version < WalletSerializerV2::MIN_VERSION) {
      // simplewallet (WalletLegacy) container — read its master seed directly.
      return loadLegacyMasterSeed(path, password);
    }
    if (version > WalletSerializerV2::SERIALIZATION_VERSION) {
      throw std::system_error(make_error_code(error::WRONG_VERSION),
                              "Unsupported wallet version " + std::to_string(version));
    }
  }

  // This reader never writes, so it does not upgrade a version-9 file; it only
  // has to be able to read one. Open the wallet in a wallet front-end once to
  // convert it.
  ContainerStorage storage;
  storage.open(path, Common::FileMappedVectorOpenMode::OPEN, sizeof(ContainerStoragePrefix));

  const ContainerStoragePrefix& header =
      *reinterpret_cast<const ContainerStoragePrefix*>(storage.prefix());
  if (header.version != WALLET_CONTAINER_VERSION) {
    storage.close();
    throw std::system_error(make_error_code(error::WRONG_VERSION),
                            "Wallet file predates the authenticated container format; "
                            "open it in a wallet once to upgrade it");
  }

  chacha8_key key;
  if (!deriveContainerKey(password, header, key)) {
    sodium_memzero(&key, sizeof(key));
    storage.close();
    throw std::system_error(make_error_code(error::INTERNAL_WALLET_ERROR),
                            "Password key derivation failed");
  }

  CryptoPQ::SeedMaster seedMaster{};
  try {
    if (storage.size() == 0) {
      throw std::system_error(make_error_code(error::WRONG_PASSWORD),
                              "Wallet container holds no master seed");
    }

    // Record 0 is the primary identity. Its authentication tag is the password
    // check: a wrong password and a tampered record both fail it.
    uint64_t ts = 0;
    if (!decryptSeedRecord(storage[0], seedMaster, ts, key, header)) {
      throw std::system_error(make_error_code(error::WRONG_PASSWORD),
                              "Wrong password, or corrupt wallet");
    }

    if (seedMaster == CryptoPQ::SeedMaster{}) {
      throw std::system_error(make_error_code(error::WRONG_STATE),
          "Wallet is view-only (tracking) and has no master seed, so it cannot mine");
    }
  } catch (...) {
    sodium_memzero(seedMaster.data(), seedMaster.size());
    sodium_memzero(&key, sizeof(key));
    storage.close();
    throw;
  }

  sodium_memzero(&key, sizeof(key));
  storage.close();

  // Return the seed bytes as a Crypto::SecretKey-sized blob (the daemon feeds it to
  // deriveMinerPqKeys, which treats it as the PQ master seed).
  Crypto::SecretKey seed;
  std::memcpy(seed.data, seedMaster.data(), sizeof(seed.data));
  sodium_memzero(seedMaster.data(), seedMaster.size());
  return seed;
}

}  // namespace CryptoNote
