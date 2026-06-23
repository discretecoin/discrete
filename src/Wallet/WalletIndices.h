// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

#include <cstring>
#include <limits>
#include <map>
#include <unordered_map>

#include "ITransfersContainer.h"
#include "IWallet.h"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/random_access_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/member.hpp>

#include "Common/FileMappedVector.h"
#include "crypto/chacha8.h"
#include "crypto_pq/PqSeed.h"

namespace CryptoNote {

const uint64_t ACCOUNT_CREATE_TIME_ACCURACY = 60 * 60 * 24;
const uint32_t WALLET_INVALID_HD_INDEX = std::numeric_limits<uint32_t>::max();

// PQ-native wallet identity. The wallet's master secret is a post-quantum
// CryptoPQ::SeedMaster (32 CSPRNG bytes); every PQ key (view, spend, per-deposit
// spend) derives from it through the cemented PqSeed chain. There is no classical
// (Ed25519) keypair. A tracking (audit-only) wallet holds an all-zero seedMaster
// and carries its PqTrackingKeys credential separately (persisted in the PQ state
// blob); `tracking` records that distinction.
struct WalletRecord {
  CryptoPQ::SeedMaster seedMaster{};
  bool tracking = false;
  uint64_t pendingBalance = 0;
  uint64_t actualBalance = 0;
  time_t creationTimestamp = 0;
  uint32_t hdIndex = WALLET_INVALID_HD_INDEX;
};

#pragma pack(push, 1)
struct EncryptedWalletRecord {
  Crypto::chacha8_iv iv;
  // Encrypted payload: magic(4) || seedMaster(32) || creationTimestamp(8). The
  // magic doubles as the password check (a wrong password decrypts to garbage and
  // the magic won't match).
  uint8_t data[4 + sizeof(CryptoPQ::SeedMaster) + sizeof(uint64_t)];
};

// On-disk container header. PQ containers keep no key material here (the master
// seed lives in the body records); this is part of the wallet file format and is
// shared by WalletGreen and the daemon's read-only mining-key loader.
struct ContainerStoragePrefix {
  uint8_t version;
  Crypto::chacha8_iv nextIv;
};
#pragma pack(pop)

typedef Common::FileMappedVector<EncryptedWalletRecord> ContainerStorage;

// Magic prefix inside every encrypted seed record. A wrong password decrypts to
// garbage and this won't match, which is how a bad password is detected (the PQ
// master seed has no stored public counterpart to validate against).
constexpr uint8_t SEED_RECORD_MAGIC[4] = { 'D', 'P', 'Q', 'S' };

// Encrypt/decrypt a wallet record = magic || master seed || creation timestamp.
// Shared by WalletGreen and MiningKeyLoader so the file format lives in one place.
// decryptSeedRecord returns false when the magic doesn't match (i.e. wrong password).
inline EncryptedWalletRecord encryptSeedRecord(const CryptoPQ::SeedMaster& seedMaster, uint64_t creationTimestamp,
                                               const Crypto::chacha8_key& key, const Crypto::chacha8_iv& iv) {
  EncryptedWalletRecord result;
  unsigned char buffer[sizeof(result.data)];
  std::memcpy(buffer, SEED_RECORD_MAGIC, sizeof(SEED_RECORD_MAGIC));
  std::memcpy(buffer + sizeof(SEED_RECORD_MAGIC), seedMaster.data(), seedMaster.size());
  std::memcpy(buffer + sizeof(SEED_RECORD_MAGIC) + seedMaster.size(), &creationTimestamp, sizeof(uint64_t));
  result.iv = iv;
  Crypto::chacha8(buffer, sizeof(buffer), key, result.iv, reinterpret_cast<char*>(result.data));
  return result;
}

inline bool decryptSeedRecord(const EncryptedWalletRecord& cipher, CryptoPQ::SeedMaster& seedMaster,
                              uint64_t& creationTimestamp, const Crypto::chacha8_key& key) {
  unsigned char buffer[sizeof(cipher.data)];
  Crypto::chacha8(cipher.data, sizeof(cipher.data), key, cipher.iv, reinterpret_cast<char*>(buffer));
  if (std::memcmp(buffer, SEED_RECORD_MAGIC, sizeof(SEED_RECORD_MAGIC)) != 0) {
    return false;
  }
  std::memcpy(seedMaster.data(), buffer + sizeof(SEED_RECORD_MAGIC), seedMaster.size());
  std::memcpy(&creationTimestamp, buffer + sizeof(SEED_RECORD_MAGIC) + seedMaster.size(), sizeof(uint64_t));
  return true;
}

struct RandomAccessIndex {};
struct KeysIndex {};

struct WalletIndex {};
struct TransactionOutputIndex {};
struct BlockHeightIndex {};

struct TransactionHashIndex {};
struct TransactionIndex {};
struct BlockHashIndex {};

// PQ wallets are single-identity (one master seed) plus derived deposit addresses,
// so the container only needs positional access — there is no classical spend
// public key left to hash on.
typedef boost::multi_index_container <
  WalletRecord,
  boost::multi_index::indexed_by <
    boost::multi_index::random_access < boost::multi_index::tag <RandomAccessIndex> >
  >
> WalletsContainer;

struct UnlockTransactionJob {
  uint32_t blockHeight;
  Crypto::Hash transactionHash;
};

typedef boost::multi_index_container <
  UnlockTransactionJob,
  boost::multi_index::indexed_by <
    boost::multi_index::ordered_non_unique < boost::multi_index::tag <BlockHeightIndex>,
    BOOST_MULTI_INDEX_MEMBER(UnlockTransactionJob, uint32_t, blockHeight)
    >,
    boost::multi_index::hashed_non_unique < boost::multi_index::tag <TransactionHashIndex>,
      BOOST_MULTI_INDEX_MEMBER(UnlockTransactionJob, Crypto::Hash, transactionHash)
    >
  >
> UnlockTransactionJobs;

typedef boost::multi_index_container <
  CryptoNote::WalletTransaction,
  boost::multi_index::indexed_by <
    boost::multi_index::random_access < boost::multi_index::tag <RandomAccessIndex> >,
    boost::multi_index::hashed_unique < boost::multi_index::tag <TransactionIndex>,
      boost::multi_index::member<CryptoNote::WalletTransaction, Crypto::Hash, &CryptoNote::WalletTransaction::hash >
    >,
    boost::multi_index::ordered_non_unique < boost::multi_index::tag <BlockHeightIndex>,
      boost::multi_index::member<CryptoNote::WalletTransaction, uint32_t, &CryptoNote::WalletTransaction::blockHeight >
    >
  >
> WalletTransactions;

typedef std::pair<size_t, CryptoNote::WalletTransfer> TransactionTransferPair;
typedef std::vector<TransactionTransferPair> WalletTransfers;
typedef std::map<size_t, CryptoNote::Transaction> UncommitedTransactions;

typedef boost::multi_index_container<
  Crypto::Hash,
  boost::multi_index::indexed_by <
    boost::multi_index::random_access<
      boost::multi_index::tag<BlockHeightIndex>
    >,
    boost::multi_index::hashed_unique<
      boost::multi_index::tag<BlockHashIndex>,
      boost::multi_index::identity<Crypto::Hash>
    >
  >
> BlockHashesContainer;

}
