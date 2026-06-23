// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, Karbo developers
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

#include "WalletSerializationV2.h"

#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"

#include <algorithm>
#include <stdexcept>

using namespace Common;
using namespace Crypto;

namespace {

//DO NOT CHANGE IT
struct UnlockTransactionJobDtoV2 {
  uint32_t blockHeight;
  Hash transactionHash;
  Crypto::PublicKey walletSpendPublicKey;
};

//DO NOT CHANGE IT
struct WalletTransactionDtoV2 {
  WalletTransactionDtoV2() {
  }

  WalletTransactionDtoV2(const CryptoNote::WalletTransaction& wallet) {
    state = wallet.state;
    timestamp = wallet.timestamp;
    blockHeight = wallet.blockHeight;
    hash = wallet.hash;
    totalAmount = wallet.totalAmount;
    fee = wallet.fee;
    creationTime = wallet.creationTime;
    unlockHeight = wallet.unlockHeight;
    extra = wallet.extra;
    isBase = wallet.isBase;
    if (wallet.secretKey)
      secretKey = reinterpret_cast<const Crypto::SecretKey&>(wallet.secretKey.get());
  }

  CryptoNote::WalletTransactionState state;
  uint64_t timestamp;
  uint32_t blockHeight;
  Hash hash;
  int64_t totalAmount;
  uint64_t fee;
  uint64_t creationTime;
  uint64_t unlockHeight;
  std::string extra;
  bool isBase;
  boost::optional<Crypto::SecretKey> secretKey = CryptoNote::NULL_SECRET_KEY;
};

//DO NOT CHANGE IT
struct WalletTransferDtoV2 {
  WalletTransferDtoV2() {
  }

  WalletTransferDtoV2(const CryptoNote::WalletTransfer& tr) {
    address = tr.address;
    amount = tr.amount;
    type = static_cast<uint8_t>(tr.type);
  }

  std::string address;
  uint64_t amount;
  uint8_t type;
};

void serialize(UnlockTransactionJobDtoV2& value, CryptoNote::ISerializer& serializer) {
  serializer(value.blockHeight, "blockHeight");
  serializer(value.transactionHash, "transactionHash");
  serializer(value.walletSpendPublicKey, "walletSpendPublicKey");
}

void serialize(WalletTransactionDtoV2& value, CryptoNote::ISerializer& serializer) {
  typedef std::underlying_type<CryptoNote::WalletTransactionState>::type StateType;

  StateType state = static_cast<StateType>(value.state);
  serializer(state, "state");
  value.state = static_cast<CryptoNote::WalletTransactionState>(state);

  serializer(value.timestamp, "timestamp");
  CryptoNote::serializeBlockHeight(serializer, value.blockHeight, "blockHeight");
  serializer(value.hash, "hash");
  serializer(value.totalAmount, "totalAmount");
  serializer(value.fee, "fee");
  serializer(value.creationTime, "creationTime");
  serializer(value.unlockHeight, "unlockHeight");
  serializer(value.extra, "extra");
  serializer(value.isBase, "isBase");

  Crypto::SecretKey secretKey = reinterpret_cast<const Crypto::SecretKey&>(value.secretKey.get());
  serializer(secretKey, "secret_key");
  value.secretKey = secretKey;
}

void serialize(WalletTransferDtoV2& value, CryptoNote::ISerializer& serializer) {
  serializer(value.address, "address");
  serializer(value.amount, "amount");
  serializer(value.type, "type");
}

}

namespace CryptoNote {

WalletSerializerV2::WalletSerializerV2(
  AddressGenerationMode& addressGenerationMode,
  Crypto::SecretKey& deterministicSeed,
  uint32_t& nextDeterministicIndex,
  WalletsContainer& walletsContainer,
  std::string& extra,
  uint32_t transactionSoftLockTime,
  std::string& pqState
) :
  m_addressGenerationMode(addressGenerationMode),
  m_deterministicSeed(deterministicSeed),
  m_nextDeterministicIndex(nextDeterministicIndex),
  m_walletsContainer(walletsContainer),
  m_extra(extra),
  m_transactionSoftLockTime(transactionSoftLockTime),
  m_pqState(pqState)
{
}

void WalletSerializerV2::load(Common::IInputStream& source, uint8_t version) {
  CryptoNote::BinaryInputStreamSerializer s(source);

  uint8_t saveLevelValue;
  s(saveLevelValue, "saveLevel");
  WalletSaveLevel saveLevel = static_cast<WalletSaveLevel>(saveLevelValue);

  loadAddressGenerationState(s, version);
  loadKeyList(s, saveLevel == WalletSaveLevel::SAVE_ALL, version);
  normalizeAddressGenerationState();

  if (version <= LAST_CLASSICAL_VERSION) {
    // Classical sections present in older (<= v7) wallet files: read and discard.
    if (saveLevel == WalletSaveLevel::SAVE_KEYS_AND_TRANSACTIONS || saveLevel == WalletSaveLevel::SAVE_ALL) {
      skipLegacyTransactions(s);
      skipLegacyTransfers(s);
    }

    if (saveLevel == WalletSaveLevel::SAVE_ALL) {
      std::string legacyTransfersSynchronizer;
      s(legacyTransfersSynchronizer, "transfersSynchronizer");
      skipLegacyUnlockTransactionsJobs(s);
      UncommitedTransactions legacyUncommited;
      s(legacyUncommited, "uncommitedTransactions");
    }
  }

  if (saveLevel == WalletSaveLevel::SAVE_ALL) {
    loadPqState(s);
  }

  s(m_extra, "extra");
}

void WalletSerializerV2::save(Common::IOutputStream& destination, WalletSaveLevel saveLevel) {
  CryptoNote::BinaryOutputStreamSerializer s(destination);

  uint8_t saveLevelValue = static_cast<uint8_t>(saveLevel);
  s(saveLevelValue, "saveLevel");

  // v8 lean format: keys + address-gen state + PQ state + extra. No classical
  // balances/transactions/transfers/unlock-jobs/uncommitted sections.
  saveAddressGenerationState(s);
  saveKeyList(s);

  if (saveLevel == WalletSaveLevel::SAVE_ALL) {
    savePqState(s);
  }

  s(m_extra, "extra");
}

void WalletSerializerV2::loadPqState(CryptoNote::ISerializer& serializer) {
  // Optional field: pre-PQ wallet files omit it, leaving m_pqState as the empty
  // blob WalletGreen initialised (which triggers a normal PQ rescan).
  serializer(m_pqState, "pqState");
}

void WalletSerializerV2::savePqState(CryptoNote::ISerializer& serializer) {
  serializer(m_pqState, "pqState");
}

std::unordered_set<Crypto::PublicKey>& WalletSerializerV2::addedKeys() {
  return m_addedKeys;
}

std::unordered_set<Crypto::PublicKey>& WalletSerializerV2::deletedKeys() {
  return m_deletedKeys;
}

void WalletSerializerV2::loadAddressGenerationState(CryptoNote::ISerializer& serializer, uint8_t version) {
  if (version < HD_FIELDS_VERSION) {
    m_addressGenerationMode = AddressGenerationMode::INDEPENDENT_SPEND_KEYS;
    m_deterministicSeed = NULL_SECRET_KEY;
    m_nextDeterministicIndex = 0;
    return;
  }

  uint8_t mode = 0;
  serializer(mode, "addressGenerationMode");
  serializer(m_deterministicSeed, "deterministicSeed");
  serializer(m_nextDeterministicIndex, "nextDeterministicIndex");

  if (mode > static_cast<uint8_t>(AddressGenerationMode::INDEPENDENT_SPEND_KEYS)) {
    throw std::runtime_error("Invalid address generation mode in wallet cache");
  }

  m_addressGenerationMode = static_cast<AddressGenerationMode>(mode);
  if (m_addressGenerationMode == AddressGenerationMode::INDEPENDENT_SPEND_KEYS) {
    m_deterministicSeed = NULL_SECRET_KEY;
    m_nextDeterministicIndex = 0;
  } else if (m_deterministicSeed == NULL_SECRET_KEY) {
    throw std::runtime_error("HD wallet cache has an empty deterministic seed");
  }
}

void WalletSerializerV2::saveAddressGenerationState(CryptoNote::ISerializer& serializer) {
  uint8_t mode = static_cast<uint8_t>(m_addressGenerationMode);
  serializer(mode, "addressGenerationMode");
  serializer(m_deterministicSeed, "deterministicSeed");
  serializer(m_nextDeterministicIndex, "nextDeterministicIndex");
}

void WalletSerializerV2::normalizeAddressGenerationState() {
  if (m_addressGenerationMode == AddressGenerationMode::INDEPENDENT_SPEND_KEYS) {
    m_deterministicSeed = NULL_SECRET_KEY;
    m_nextDeterministicIndex = 0;
    return;
  }

  bool foundHdAddress = false;
  uint32_t maxHdIndex = 0;
  for (const auto& wallet : m_walletsContainer.get<RandomAccessIndex>()) {
    if (wallet.hdIndex != WALLET_INVALID_HD_INDEX) {
      foundHdAddress = true;
      maxHdIndex = std::max(maxHdIndex, wallet.hdIndex);
    }
  }

  if (foundHdAddress && m_nextDeterministicIndex <= maxHdIndex && maxHdIndex != WALLET_INVALID_HD_INDEX) {
    m_nextDeterministicIndex = maxHdIndex + 1;
  }
}

void WalletSerializerV2::loadKeyList(CryptoNote::ISerializer& serializer, bool /*hadBalances*/, uint8_t /*version*/) {
  // PQ-native (v9): the wallet's identity (the master seed) is loaded from the
  // container records before the cache; this section only restores per-record
  // hdIndex by position. The wallet is single-identity, so there is no added/deleted
  // key reconciliation.
  m_addedKeys.clear();
  m_deletedKeys.clear();

  size_t walletCount;
  serializer(walletCount, "walletCount");

  auto& index = m_walletsContainer.get<RandomAccessIndex>();
  for (size_t i = 0; i < walletCount; ++i) {
    CryptoPQ::SeedMaster seedMaster{};
    uint32_t hdIndex = WALLET_INVALID_HD_INDEX;
    serializer.binary(seedMaster.data(), seedMaster.size(), "seedMaster");
    serializer(hdIndex, "hdIndex");

    if (i < index.size()) {
      index.modify(std::next(index.begin(), i), [hdIndex](WalletRecord& wallet) {
        wallet.hdIndex = hdIndex;
      });
    }
  }
}

void WalletSerializerV2::saveKeyList(CryptoNote::ISerializer& serializer) {
  auto& index = m_walletsContainer.get<RandomAccessIndex>();
  auto walletCount = index.size();
  serializer(walletCount, "walletCount");
  for (auto wallet : index) {
    serializer.binary(wallet.seedMaster.data(), wallet.seedMaster.size(), "seedMaster");
    serializer(wallet.hdIndex, "hdIndex");
  }
}

void WalletSerializerV2::skipLegacyTransactions(CryptoNote::ISerializer& serializer) {
  uint64_t count = 0;
  serializer(count, "transactionCount");
  for (uint64_t i = 0; i < count; ++i) {
    WalletTransactionDtoV2 dto;
    serializer(dto, "transaction");
  }
}

void WalletSerializerV2::skipLegacyTransfers(CryptoNote::ISerializer& serializer) {
  uint64_t count = 0;
  serializer(count, "transferCount");
  for (uint64_t i = 0; i < count; ++i) {
    uint64_t txId = 0;
    serializer(txId, "transactionId");
    WalletTransferDtoV2 dto;
    serializer(dto, "transfer");
  }
}

void WalletSerializerV2::skipLegacyUnlockTransactionsJobs(CryptoNote::ISerializer& serializer) {
  uint64_t jobsCount = 0;
  serializer(jobsCount, "unlockTransactionsJobsCount");
  for (uint64_t i = 0; i < jobsCount; ++i) {
    UnlockTransactionJobDtoV2 dto;
    serializer(dto, "unlockTransactionsJob");
  }
}

} //namespace CryptoNote
