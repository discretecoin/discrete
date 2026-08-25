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

#include <fstream>
#include <system_error>

#include "Common/FileMappedVector.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"   // NULL_SECRET_KEY
#include "Logging/LoggerRef.h"
#include "crypto/chacha8.h"
#include "crypto/crypto-util.h"                // sodium_memzero

#include "WalletErrors.h"
#include "WalletIndices.h"          // ContainerStorage(Prefix), seed-record codec
#include "WalletLegacy/WalletLegacySerializer.h"
#include "WalletSerializationV2.h"  // version constants

using namespace Crypto;

namespace CryptoNote {

namespace {

// Read the master seed from a simplewallet (WalletLegacy) container through the
// canonical wallet codec. This keeps the daemon's read-only mining path aligned
// with both backward-readable ChaCha8 versions and the authenticated envelope.
Crypto::SecretKey loadLegacyMasterSeed(const std::string& path, const std::string& password) {
  std::ifstream file(path, std::ios_base::binary);
  if (!file) {
    throw std::system_error(make_error_code(error::WRONG_STATE),
                            "Failed to open wallet '" + path + "'");
  }

  AccountBase account;
  std::string cache;
  struct Scrubber {
    AccountBase& account;
    std::string& cache;
    ~Scrubber() {
      account.setAccountKeys(AccountKeys{});
      if (!cache.empty()) sodium_memzero(&cache[0], cache.size());
    }
  } scrubber{account, cache};

  WalletLegacySerializer serializer(account);
  serializer.deserialize(file, password, cache);
  Crypto::SecretKey seed = account.getAccountKeys().spendSecretKey;
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
