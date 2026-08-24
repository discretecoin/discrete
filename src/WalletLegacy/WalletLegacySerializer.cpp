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

#include "WalletLegacySerializer.h"

#include <cstring>
#include <stdexcept>

#include "Common/MemoryInputStream.h"
#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "WalletLegacy/WalletUserTransactionsCache.h"
#include "Wallet/WalletErrors.h"
#include "Wallet/WalletUtils.h"
#include "WalletLegacy/KeysStorage.h"

using namespace Common;

namespace {

// A simplewallet file starts with its varint serialization version (1 or 2); a
// greenwallet/walletd container starts with the ContainerStoragePrefix version
// byte (6 was the first container format, 9 is current — see WalletIndices.h).
// Peek at the first byte to refuse a container with a pointed error instead of
// decrypting garbage and reporting a wrong password.
const int FIRST_CONTAINER_FORMAT_VERSION = 6;

void throwIfContainerFile(std::istream& stream) {
  const int first = stream.peek();
  if (first != std::char_traits<char>::eof() && first >= FIRST_CONTAINER_FORMAT_VERSION) {
    throw std::system_error(make_error_code(CryptoNote::error::CONTAINER_WALLET_FILE));
  }
}

} // anonymous namespace

namespace CryptoNote {

uint32_t WALLET_LEGACY_SERIALIZATION_VERSION = 2;

WalletLegacySerializer::WalletLegacySerializer(CryptoNote::AccountBase& account,
                                               uint32_t serializationVersion) :
  account(account),
  walletSerializationVersion(serializationVersion),
  loadedWalletSerializationVersion(0)
{
  if (walletSerializationVersion < 1 ||
      walletSerializationVersion > PROTECTED_SPEND_VERSION) {
    throw std::invalid_argument("unsupported wallet serialization version");
  }
}

void WalletLegacySerializer::serialize(std::ostream& stream, const std::string& password, bool saveDetailed, const std::string& cache) {
  // set serialization version global variable
  CryptoNote::WALLET_LEGACY_SERIALIZATION_VERSION = walletSerializationVersion;

  std::stringstream plainArchive;
  StdOutputStream plainStream(plainArchive);
  CryptoNote::BinaryOutputStreamSerializer serializer(plainStream);
  if (walletSerializationVersion >= PROTECTED_SPEND_VERSION) {
    saveProtectedSpendCompatibilityGuard(serializer);
  }
  saveKeys(serializer);

  // The classical detailed transaction cache is gone on the PQ wallet (history
  // lives in the WalletLedger, persisted in the `cache` blob below). Always write
  // has_details=false; older files that carried details still load (see below).
  (void)saveDetailed;
  bool hasDetails = false;
  serializer(hasDetails, "has_details");

  serializer.binary(const_cast<std::string&>(cache), "cache");

  std::string plain = plainArchive.str();
  std::string cipher;

  Crypto::chacha8_iv iv = encrypt(plain, password, cipher);

  uint32_t version = walletSerializationVersion;
  StdOutputStream output(stream);
  CryptoNote::BinaryOutputStreamSerializer s(output);
  s.beginObject("wallet");
  s(version, "version");
  s(iv, "iv");
  s(cipher, "data");
  s.endObject();

  stream.flush();
}

void WalletLegacySerializer::saveKeys(CryptoNote::ISerializer& serializer) {
  CryptoNote::KeysStorage keys;
  CryptoNote::AccountKeys acc = account.getAccountKeys();

  keys.creationTimestamp = account.get_createtime();
  keys.spendPublicKey = acc.address.spendPublicKey;
  keys.spendSecretKey = acc.spendSecretKey;
  keys.viewPublicKey = acc.address.viewPublicKey;
  keys.viewSecretKey = acc.viewSecretKey;

  keys.serialize(serializer, "keys");
}

void WalletLegacySerializer::saveProtectedSpendCompatibilityGuard(
    CryptoNote::ISerializer& serializer) {
  // Version 2 readers do not reject unknown wallet versions. Put a complete,
  // deliberately invalid KeysStorage record before the real keys so an older
  // reader deterministically fails its seed-checksum test instead of opening a
  // v3 wallet and later stripping the embedded protected-spend metadata.
  CryptoNote::KeysStorage guard{};
  guard.creationTimestamp = UINT64_C(0x4453574C56334744); // "DSWLV3GD"
  guard.serialize(serializer, "protected_spend_compatibility_guard");
}

void WalletLegacySerializer::loadProtectedSpendCompatibilityGuard(
    CryptoNote::ISerializer& serializer) {
  CryptoNote::KeysStorage guard{};
  try {
    guard.serialize(serializer, "protected_spend_compatibility_guard");
  } catch (const std::runtime_error&) {
    throw std::system_error(make_error_code(CryptoNote::error::WRONG_PASSWORD));
  }

  CryptoNote::KeysStorage expected{};
  expected.creationTimestamp = UINT64_C(0x4453574C56334744);
  if (guard.creationTimestamp != expected.creationTimestamp ||
      std::memcmp(&guard.spendPublicKey, &expected.spendPublicKey,
                  sizeof(guard.spendPublicKey)) != 0 ||
      std::memcmp(&guard.spendSecretKey, &expected.spendSecretKey,
                  sizeof(guard.spendSecretKey)) != 0 ||
      std::memcmp(&guard.viewPublicKey, &expected.viewPublicKey,
                  sizeof(guard.viewPublicKey)) != 0 ||
      std::memcmp(&guard.viewSecretKey, &expected.viewSecretKey,
                  sizeof(guard.viewSecretKey)) != 0) {
    throw std::system_error(make_error_code(CryptoNote::error::WRONG_PASSWORD));
  }
}

Crypto::chacha8_iv WalletLegacySerializer::encrypt(const std::string& plain, const std::string& password, std::string& cipher) {
  Crypto::chacha8_key key;
  Crypto::cn_context context;
  if (!Crypto::generate_chacha8_key(context, password, key)) {
    throw std::system_error(make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR),
                            "Password key derivation failed");
  }

  cipher.resize(plain.size());

  Crypto::chacha8_iv iv = Crypto::randomChachaIV();
  Crypto::chacha8(plain.data(), plain.size(), key, iv, &cipher[0]);

  return iv;
}


void WalletLegacySerializer::deserialize(std::istream& stream, const std::string& password, std::string& cache) {
  throwIfContainerFile(stream);

  StdInputStream stdStream(stream);
  CryptoNote::BinaryInputStreamSerializer serializerEncrypted(stdStream);

  serializerEncrypted.beginObject("wallet");

  uint32_t version;
  serializerEncrypted(version, "version");
  if (version < 1 || version > PROTECTED_SPEND_VERSION) {
    throw std::runtime_error("unsupported wallet serialization version");
  }
  loadedWalletSerializationVersion = version;
  // set serialization version global variable
  CryptoNote::WALLET_LEGACY_SERIALIZATION_VERSION = version;

  Crypto::chacha8_iv iv;
  serializerEncrypted(iv, "iv");

  std::string cipher;
  serializerEncrypted(cipher, "data");

  serializerEncrypted.endObject();

  std::string plain;
  decrypt(cipher, plain, iv, password);

  MemoryInputStream decryptedStream(plain.data(), plain.size()); 
  CryptoNote::BinaryInputStreamSerializer serializer(decryptedStream);

  if (version >= PROTECTED_SPEND_VERSION) {
    loadProtectedSpendCompatibilityGuard(serializer);
  }
  loadKeys(serializer);

  // PQ-native: the wallet identity is the 32-byte master seed (spendSecretKey). The
  // spendPublicKey slot carries cn_fast_hash(seed) as a password/integrity checksum
  // (a wrong password decrypts to garbage whose hash won't match). There are no
  // classical key pairs left to cross-check.
  {
    const AccountKeys& acc = account.getAccountKeys();
    Crypto::Hash checksum;
    Crypto::cn_fast_hash(acc.spendSecretKey.data, sizeof(acc.spendSecretKey.data), checksum);
    if (std::memcmp(checksum.data, acc.address.spendPublicKey.data, sizeof(checksum.data)) != 0) {
      throw std::system_error(make_error_code(CryptoNote::error::WRONG_PASSWORD));
    }
  }

  bool detailsSaved;

  serializer(detailsSaved, "has_details");

  if (detailsSaved) {
    // Older wallet files carry a classical detailed transaction cache. Read and
    // discard it; the PQ wallet rebuilds history from the WalletLedger.
    WalletUserTransactionsCache legacyDetails;
    serializer(legacyDetails, "details");
  }

  serializer.binary(cache, "cache");
}

// used for password check
bool WalletLegacySerializer::deserialize(std::istream& stream, const std::string& password) {
  try {
    StdInputStream stdStream(stream);
    CryptoNote::BinaryInputStreamSerializer serializerEncrypted(stdStream);

    serializerEncrypted.beginObject("wallet");

    uint32_t version;
    serializerEncrypted(version, "version");
    if (version < 1 || version > PROTECTED_SPEND_VERSION) {
      return false;
    }
    loadedWalletSerializationVersion = version;
    // set serialization version global variable
    CryptoNote::WALLET_LEGACY_SERIALIZATION_VERSION = version;

    Crypto::chacha8_iv iv;
    serializerEncrypted(iv, "iv");

    std::string cipher;
    serializerEncrypted(cipher, "data");

    serializerEncrypted.endObject();

    std::string plain;
    decrypt(cipher, plain, iv, password);

    MemoryInputStream decryptedStream(plain.data(), plain.size());
    CryptoNote::BinaryInputStreamSerializer serializer(decryptedStream);

    if (version >= PROTECTED_SPEND_VERSION) {
      loadProtectedSpendCompatibilityGuard(serializer);
    }
    CryptoNote::KeysStorage keys;
    try {
      keys.serialize(serializer, "keys");
    }
    catch (const std::runtime_error&) {
      return false;
    }
    // Password check via the seed checksum (cn_fast_hash(seed) is stored in the
    // spendPublicKey slot — see deserialize() above).
    Crypto::Hash checksum;
    Crypto::cn_fast_hash(keys.spendSecretKey.data, sizeof(keys.spendSecretKey.data), checksum);
    if (std::memcmp(checksum.data, keys.spendPublicKey.data, sizeof(checksum.data)) != 0) {
      return false;
    }
  }
  catch (std::system_error&) {
    return false;
  }
  catch (std::exception&) {
    return false;
  }

  return true;
}

void WalletLegacySerializer::decrypt(const std::string& cipher, std::string& plain, Crypto::chacha8_iv iv, const std::string& password) {
  Crypto::chacha8_key key;
  Crypto::cn_context context;
  if (!Crypto::generate_chacha8_key(context, password, key)) {
    throw std::system_error(make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR),
                            "Password key derivation failed");
  }

  plain.resize(cipher.size());

  Crypto::chacha8(cipher.data(), cipher.size(), key, iv, &plain[0]);
}

void WalletLegacySerializer::loadKeys(CryptoNote::ISerializer& serializer) {
  CryptoNote::KeysStorage keys;

  try {
    keys.serialize(serializer, "keys");
  } catch (const std::runtime_error&) {
    throw std::system_error(make_error_code(CryptoNote::error::WRONG_PASSWORD));
  }

  CryptoNote::AccountKeys acc;
  acc.address.spendPublicKey = keys.spendPublicKey;
  acc.spendSecretKey = keys.spendSecretKey;
  acc.address.viewPublicKey = keys.viewPublicKey;
  acc.viewSecretKey = keys.viewSecretKey;

  account.setAccountKeys(acc);
  account.set_createtime(keys.creationTimestamp);
}

}
