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

#include <unordered_set>

#include "Common/IInputStream.h"
#include "Common/IOutputStream.h"
#include "Serialization/ISerializer.h"
#include "ITransfersSynchronizer.h"
#include "Wallet/WalletIndices.h"

namespace CryptoNote {

class WalletSerializerV2 {
public:
  WalletSerializerV2(
    AddressGenerationMode& addressGenerationMode,
    Crypto::SecretKey& deterministicSeed,
    uint32_t& nextDeterministicIndex,
    WalletsContainer& walletsContainer,
    std::string& extra,
    uint32_t transactionSoftLockTime,
    std::string& pqState
  );

  void load(Common::IInputStream& source, uint8_t version);
  void save(Common::IOutputStream& destination, WalletSaveLevel saveLevel);

  std::unordered_set<Crypto::PublicKey>& addedKeys();
  std::unordered_set<Crypto::PublicKey>& deletedKeys();

  // v10 is the authenticated, salted container (see WalletIndices.h). v9 is the
  // same PQ-native record content under unauthenticated ChaCha8 with an unsalted
  // key; it is still readable so an existing wallet can be opened and migrated.
  // Older formats (v6-v8) carried classical key pairs and are not loadable.
  static const uint8_t MIN_VERSION = WALLET_CONTAINER_VERSION_LEGACY;
  static const uint8_t SERIALIZATION_VERSION = WALLET_CONTAINER_VERSION;
  static const uint8_t LAST_CLASSICAL_VERSION = 7;
  // hdIndex + the address-generation state were introduced at this version.
  static const uint8_t HD_FIELDS_VERSION = 7;

private:
  void loadAddressGenerationState(CryptoNote::ISerializer& serializer, uint8_t version);
  void saveAddressGenerationState(CryptoNote::ISerializer& serializer);
  void normalizeAddressGenerationState();

  void loadKeyList(CryptoNote::ISerializer& serializer, bool hadBalances, uint8_t version);
  void saveKeyList(CryptoNote::ISerializer& serializer);

  // Legacy (version <= LAST_CLASSICAL_VERSION) classical sections: read and
  // discard so older wallet files still load. v8 never writes them.
  void skipLegacyTransactions(CryptoNote::ISerializer& serializer);
  void skipLegacyTransfers(CryptoNote::ISerializer& serializer);
  void skipLegacyUnlockTransactionsJobs(CryptoNote::ISerializer& serializer);

  // Opaque PQ-wallet state blob (WalletLedgerConsumer sync cursor + WalletLedger),
  // produced/consumed by WalletGreen.
  void loadPqState(CryptoNote::ISerializer& serializer);
  void savePqState(CryptoNote::ISerializer& serializer);

  AddressGenerationMode& m_addressGenerationMode;
  Crypto::SecretKey& m_deterministicSeed;
  uint32_t& m_nextDeterministicIndex;
  WalletsContainer& m_walletsContainer;
  std::string& m_extra;
  uint32_t m_transactionSoftLockTime;
  std::string& m_pqState;

  std::unordered_set<Crypto::PublicKey> m_addedKeys;
  std::unordered_set<Crypto::PublicKey> m_deletedKeys;
};

} //namespace CryptoNote
