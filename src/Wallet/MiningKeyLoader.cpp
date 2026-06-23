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
#include "WalletIndices.h"          // ContainerStorage(Prefix), seed-record codec
#include "WalletSerializationV2.h"  // version constants

using namespace Crypto;

namespace CryptoNote {

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
    int peeked = probe.peek();
    if (peeked == EOF) {
      throw std::system_error(make_error_code(error::WRONG_VERSION),
                              "Failed to read wallet version from '" + path + "'");
    }
    uint8_t version = static_cast<uint8_t>(peeked);
    if (version < WalletSerializerV2::MIN_VERSION || version > WalletSerializerV2::SERIALIZATION_VERSION) {
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

  CryptoPQ::SeedMaster seedMaster{};
  try {
    if (storage.size() == 0) {
      throw std::system_error(make_error_code(error::WRONG_PASSWORD),
                              "Wallet container holds no master seed");
    }

    // Record 0 is the primary identity. The magic check inside decryptSeedRecord
    // doubles as the password check (wrong password -> garbage -> magic mismatch).
    uint64_t ts = 0;
    if (!decryptSeedRecord(storage[0], seedMaster, ts, key)) {
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
