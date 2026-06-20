// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, The BBSCoin Developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2016-2026, The Karbo developers
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

#include "WalletGreen.h"

#include <algorithm>
#include <ctime>
#include <cassert>
#include <fstream>
#include <future>
#include <numeric>
#include <set>
#include <tuple>
#include <utility>
#include <vector>

#include <System/EventLock.h>
#include <System/RemoteContext.h>
#ifdef USE_LITE_WALLET
#include <boost/date_time/posix_time/posix_time.hpp>
#endif

#include "ITransaction.h"

#include "Common/Base58.h"
#include "Common/ScopeExit.h"
#include "Common/ShuffleGenerator.h"
#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "Common/StreamTools.h"
#include "Common/StringOutputStream.h"
#include "Common/StringTools.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "Wallet/TransactionBuilder.h"
#include "Wallet/PqWallet.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/PqRecipient.h"
#include "Denominations.h"
#include "AccountNumber.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/PqValidation.h"
#include "CryptoNoteCore/TransactionApi.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "crypto/crypto.h"
#include "crypto/random.h"
#include "Transfers/TransfersContainer.h"
#include "WalletSerializationV2.h"
#include "WalletErrors.h"
#include "WalletUtils.h"

extern "C"
{
#include "crypto/crypto-ops.h"
}

#undef ERROR

using namespace Common;
using namespace Crypto;
using namespace CryptoNote;
using namespace Logging;

namespace {

void asyncRequestCompletion(System::Event& requestFinished) {
  requestFinished.set();
}

CryptoNote::WalletEvent makeTransactionUpdatedEvent(size_t id) {
  CryptoNote::WalletEvent event;
  event.type = CryptoNote::WalletEventType::TRANSACTION_UPDATED;
  event.transactionUpdated.transactionIndex = id;

  return event;
}

CryptoNote::WalletEvent makeTransactionCreatedEvent(size_t id) {
  CryptoNote::WalletEvent event;
  event.type = CryptoNote::WalletEventType::TRANSACTION_CREATED;
  event.transactionCreated.transactionIndex = id;

  return event;
}

CryptoNote::WalletEvent makeMoneyUnlockedEvent() {
  CryptoNote::WalletEvent event;
  event.type = CryptoNote::WalletEventType::BALANCE_UNLOCKED;

  return event;
}

CryptoNote::WalletEvent makeSyncProgressUpdatedEvent(uint32_t current, uint32_t total) {
  CryptoNote::WalletEvent event;
  event.type = CryptoNote::WalletEventType::SYNC_PROGRESS_UPDATED;
  event.synchronizationProgressUpdated.processedBlockCount = current;
  event.synchronizationProgressUpdated.totalBlockCount = total;

  return event;
}

CryptoNote::WalletEvent makeSyncCompletedEvent() {
  CryptoNote::WalletEvent event;
  event.type = CryptoNote::WalletEventType::SYNC_COMPLETED;

  return event;
}

size_t getTransactionSize(const ITransactionReader& transaction) {
  return transaction.getTransactionData().size();
}

uint64_t calculateDonationAmount(uint64_t freeAmount, uint64_t donationThreshold, uint64_t dustThreshold) {
  std::vector<uint64_t> decomposedAmounts;
  decomposeAmount(freeAmount, dustThreshold, decomposedAmounts);

  std::sort(decomposedAmounts.begin(), decomposedAmounts.end(), std::greater<uint64_t>());

  uint64_t donationAmount = 0;
  for (auto amount: decomposedAmounts) {
    if (amount > donationThreshold - donationAmount) {
      continue;
    }

    donationAmount += amount;
  }

  assert(donationAmount <= freeAmount);
  return donationAmount;
}

}

namespace CryptoNote {

WalletGreen::WalletGreen(System::Dispatcher& dispatcher, const Currency& currency, INode& node, Logging::ILogger& logger, uint32_t transactionSoftLockTime) :
  m_dispatcher(dispatcher),
  m_currency(currency),
  m_node(node),
  m_logger(logger, "WalletGreen/empty"),
  m_stopped(false),
  m_blockchainSynchronizerStarted(false),
  m_blockchainSynchronizer(node, logger, currency.genesisBlockHash()),
  m_eventOccurred(m_dispatcher),
  m_readyEvent(m_dispatcher),
  m_state(WalletState::NOT_INITIALIZED),
  m_addressGenerationMode(AddressGenerationMode::INDEPENDENT_SPEND_KEYS),
  m_deterministicSeed(NULL_SECRET_KEY),
  m_nextDeterministicIndex(0),
  m_actualBalance(0),
  m_pendingBalance(0),
  m_transactionSoftLockTime(transactionSoftLockTime)
{
  m_upperTransactionSizeLimit = m_currency.maxTransactionSizeLimit();
  m_readyEvent.set();
}

WalletGreen::~WalletGreen() {
  if (m_state == WalletState::INITIALIZED) {
    doShutdown();
  }

  m_dispatcher.yield(); //let remote spawns finish
}

void WalletGreen::initialize(const std::string& path, const std::string& password) {
  Crypto::PublicKey viewPublicKey;
  Crypto::SecretKey viewSecretKey;
  Crypto::generate_keys(viewPublicKey, viewSecretKey);
  uint64_t creationTimestamp = time(nullptr);
  initWithKeys(path, password, viewPublicKey, viewSecretKey, creationTimestamp);
  m_logger(INFO, BRIGHT_WHITE) << "New container initialized, public view key " << viewPublicKey;
}

void WalletGreen::initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& viewSecretKey) {
  Crypto::PublicKey viewPublicKey;
  if (!Crypto::secret_key_to_public_key(viewSecretKey, viewPublicKey)) {
    m_logger(ERROR, BRIGHT_RED) << "initializeWithViewKey(" << viewSecretKey << ") Failed to convert secret key to public key";
    throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
  }
  uint64_t creationTimestamp = time(nullptr);
  initWithKeys(path, password, viewPublicKey, viewSecretKey, creationTimestamp);
  m_logger(INFO, BRIGHT_WHITE) << "Container initialized with view secret key, public view key " << viewPublicKey;
}

void WalletGreen::initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& viewSecretKey, const uint64_t& creationTimestamp) {
  Crypto::PublicKey viewPublicKey;
  if (!Crypto::secret_key_to_public_key(viewSecretKey, viewPublicKey)) {
    m_logger(ERROR, BRIGHT_RED) << "initializeWithViewKey(" << viewSecretKey << ") Failed to convert secret key to public key";
    throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
  }

  initWithKeys(path, password, viewPublicKey, viewSecretKey, creationTimestamp);
  m_logger(INFO, BRIGHT_WHITE) << "Container initialized with view secret key, public view key " << viewPublicKey;
}

void WalletGreen::initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& viewSecretKey, const uint32_t scanHeight) {
  Crypto::PublicKey viewPublicKey;
  if (!Crypto::secret_key_to_public_key(viewSecretKey, viewPublicKey)) {
    m_logger(ERROR, BRIGHT_RED) << "initializeWithViewKey(" << viewSecretKey << ") Failed to convert secret key to public key";
    throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
  }

  uint64_t creationTimestamp = scanHeightToTimestamp(scanHeight);

  initWithKeys(path, password, viewPublicKey, viewSecretKey, creationTimestamp);
  m_logger(INFO, BRIGHT_WHITE) << "Container initialized with view secret key, public view key " << viewPublicKey;
}

void WalletGreen::initializeWithPqTrackingKey(const std::string& path, const std::string& password,
                                              const PqTrackingKeys& pqTrackingKeys) {
  initializeWithPqTrackingKey(path, password, pqTrackingKeys, static_cast<uint64_t>(time(nullptr)));
}

void WalletGreen::initializeWithPqTrackingKey(const std::string& path, const std::string& password,
                                              const PqTrackingKeys& pqTrackingKeys,
                                              const uint64_t& creationTimestamp) {
  Crypto::PublicKey viewPublicKey;
  Crypto::SecretKey viewSecretKey;
  Crypto::generate_keys(viewPublicKey, viewSecretKey);

  initWithKeys(path, password, viewPublicKey, viewSecretKey, creationTimestamp);
  m_pqTrackingKeys.reset(new PqTrackingKeys(pqTrackingKeys));

  Crypto::PublicKey placeholderSpendPublicKey;
  Crypto::SecretKey placeholderSpendSecretKey;
  Crypto::generate_keys(placeholderSpendPublicKey, placeholderSpendSecretKey);
  createAddress(placeholderSpendPublicKey, creationTimestamp);

  m_logger(INFO, BRIGHT_WHITE) << "Container initialized with tracking key";
}

void WalletGreen::shutdown() {
  throwIfNotInitialized();
  doShutdown();

  m_dispatcher.yield(); //let remote spawns finish
  m_logger(INFO, BRIGHT_WHITE) << "Container shut down";
  m_logger = Logging::LoggerRef(m_logger.getLogger(), "WalletGreen/empty");
}

void WalletGreen::doShutdown() {
  stopBlockchainSynchronizer();
  m_blockchainSynchronizer.removeObserver(this);

  m_containerStorage.close();
  m_walletsContainer.clear();
  m_addressGenerationMode = AddressGenerationMode::INDEPENDENT_SPEND_KEYS;
  m_deterministicSeed = NULL_SECRET_KEY;
  m_nextDeterministicIndex = 0;
  m_pqTrackingKeys.reset();
  m_pqState.clear();
  clearCaches(true, true);

  std::queue<WalletEvent> noEvents;
  std::swap(m_events, noEvents);

  m_state = WalletState::NOT_INITIALIZED;
}

void WalletGreen::clearCaches(bool clearTransactions, bool clearCachedData) {
  if (clearTransactions) {
    m_transactions.clear();
    m_transfers.clear();
  }

  if (clearCachedData) {
    for (auto it = m_walletsContainer.begin(); it != m_walletsContainer.end(); ++it) {
      m_walletsContainer.modify(it, [](WalletRecord& wallet) {
        wallet.actualBalance = 0;
        wallet.pendingBalance = 0;
      });
    }

    if (!clearTransactions) {
      for (auto it = m_transactions.begin(); it != m_transactions.end(); ++it) {
        m_transactions.modify(it, [](WalletTransaction& tx) {
          tx.state = WalletTransactionState::CANCELLED;
          tx.blockHeight = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
        });
      }
    }

    if (m_pqConsumer) {
      m_blockchainSynchronizer.removeConsumer(m_pqConsumer.get());
      m_pqConsumer.reset();
    }

    m_uncommitedTransactions.clear();
    m_unlockTransactionsJob.clear();
    m_actualBalance = 0;
    m_pendingBalance = 0;
    m_blockchain.clear();
  }
}

void WalletGreen::decryptKeyPair(const EncryptedWalletRecord& cipher, PublicKey& publicKey, SecretKey& secretKey,
  uint64_t& creationTimestamp, const Crypto::chacha8_key& key) {

  std::array<char, sizeof(cipher.data)> buffer;
  chacha8(cipher.data, sizeof(cipher.data), key, cipher.iv, buffer.data());

  MemoryInputStream stream(buffer.data(), buffer.size());
  BinaryInputStreamSerializer serializer(stream);

  serializer(publicKey, "publicKey");
  serializer(secretKey, "secretKey");
  serializer.binary(&creationTimestamp, sizeof(uint64_t), "creationTimestamp");
}

void WalletGreen::decryptKeyPair(const EncryptedWalletRecord& cipher, PublicKey& publicKey, SecretKey& secretKey, uint64_t& creationTimestamp) const {
  decryptKeyPair(cipher, publicKey, secretKey, creationTimestamp, m_key);
}

EncryptedWalletRecord WalletGreen::encryptKeyPair(const PublicKey& publicKey, const SecretKey& secretKey, uint64_t creationTimestamp,
  const Crypto::chacha8_key& key, const Crypto::chacha8_iv& iv) {

  EncryptedWalletRecord result;

  std::string serializedKeys;
  StringOutputStream outputStream(serializedKeys);
  BinaryOutputStreamSerializer serializer(outputStream);

  serializer(const_cast<PublicKey&>(publicKey), "publicKey");
  serializer(const_cast<SecretKey&>(secretKey), "secretKey");
  serializer.binary(&creationTimestamp, sizeof(uint64_t), "creationTimestamp");

  assert(serializedKeys.size() == sizeof(result.data));

  result.iv = iv;
  chacha8(serializedKeys.data(), serializedKeys.size(), key, result.iv, reinterpret_cast<char*>(result.data));

  return result;
}

EncryptedWalletRecord WalletGreen::encryptKeyPair(const PublicKey& publicKey, const SecretKey& secretKey, uint64_t creationTimestamp) const {
  return encryptKeyPair(publicKey, secretKey, creationTimestamp, m_key, getNextIv());
}

Crypto::chacha8_iv WalletGreen::getNextIv() const {
  const auto* prefix = reinterpret_cast<const ContainerStoragePrefix*>(m_containerStorage.prefix());
  return prefix->nextIv;
}

void WalletGreen::incIv(Crypto::chacha8_iv& iv) {
  static_assert(sizeof(uint64_t) == sizeof(Crypto::chacha8_iv), "Bad Crypto::chacha8_iv size");
  uint64_t* i = reinterpret_cast<uint64_t*>(&iv);
  if (*i < std::numeric_limits<uint64_t>::max()) {
    ++(*i);
  } else {
    *i = 0;
  }
}

void WalletGreen::incNextIv() {
  static_assert(sizeof(uint64_t) == sizeof(Crypto::chacha8_iv), "Bad Crypto::chacha8_iv size");
  auto* prefix = reinterpret_cast<ContainerStoragePrefix*>(m_containerStorage.prefix());
  incIv(prefix->nextIv);
}

void WalletGreen::initWithKeys(const std::string& path, const std::string& password,
  const Crypto::PublicKey& viewPublicKey, const Crypto::SecretKey& viewSecretKey, const uint64_t& _creationTimestamp) {

  if (m_state != WalletState::NOT_INITIALIZED) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to initialize with keys: already initialized. Current state: " << m_state;
    throw std::system_error(make_error_code(CryptoNote::error::ALREADY_INITIALIZED));
  }

  throwIfStopped();

  ContainerStorage newStorage(path, Common::FileMappedVectorOpenMode::CREATE, sizeof(ContainerStoragePrefix));
  ContainerStoragePrefix* prefix = reinterpret_cast<ContainerStoragePrefix*>(newStorage.prefix());
  prefix->version = static_cast<uint8_t>(WalletSerializerV2::SERIALIZATION_VERSION);
  prefix->nextIv = Crypto::randomChachaIV();

  Crypto::cn_context cnContext;
  Crypto::generate_chacha8_key(cnContext, password, m_key);

  prefix->encryptedViewKeys = encryptKeyPair(viewPublicKey, viewSecretKey, _creationTimestamp, m_key, prefix->nextIv);

  newStorage.flush();
  m_containerStorage.swap(newStorage);
  incNextIv();

  m_viewPublicKey = viewPublicKey;
  m_viewSecretKey = viewSecretKey;
  m_password = password;
  m_path = path;
  m_logger = Logging::LoggerRef(m_logger.getLogger(), "WalletGreen/" + podToHex(m_viewPublicKey).substr(0, 5));

  assert(m_blockchain.empty());
  m_blockchain.push_back(m_currency.genesisBlockHash());

  m_blockchainSynchronizer.addObserver(this);

  m_state = WalletState::INITIALIZED;
}

void WalletGreen::save(WalletSaveLevel saveLevel, const std::string& extra) {
  m_logger(INFO, BRIGHT_WHITE) << "Saving container...";

  throwIfNotInitialized();
  throwIfStopped();

  stopBlockchainSynchronizer();

  try {
    saveWalletCache(m_containerStorage, m_key, saveLevel, extra);
  } catch (const std::exception& e) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to save container: " << e.what();
    startBlockchainSynchronizer();
    throw;
  }

  startBlockchainSynchronizer();
  m_logger(INFO, BRIGHT_WHITE) << "Container saved";
}

void WalletGreen::exportWallet(const std::string& path, bool encrypt, WalletSaveLevel saveLevel, const std::string& extra) {
  m_logger(INFO, BRIGHT_WHITE) << "Exporting container...";

  throwIfNotInitialized();
  throwIfStopped();

  stopBlockchainSynchronizer();

  try {
    bool storageCreated = false;
    Tools::ScopeExit failExitHandler([path, &storageCreated] {
      // Don't delete file if it has existed
      if (storageCreated) {
        boost::system::error_code ignore;
        boost::filesystem::remove(path, ignore);
      }
    });

    ContainerStorage newStorage(path, FileMappedVectorOpenMode::CREATE, m_containerStorage.prefixSize());
    storageCreated = true;

    chacha8_key newStorageKey;
    if (encrypt) {
      newStorageKey = m_key;
    } else {
      cn_context cnContext;
      generate_chacha8_key(cnContext, "", newStorageKey);
    }

    copyContainerStoragePrefix(m_containerStorage, m_key, newStorage, newStorageKey);
    copyContainerStorageKeys(m_containerStorage, m_key, newStorage, newStorageKey);
    saveWalletCache(newStorage, newStorageKey, saveLevel, extra);

    failExitHandler.cancel();

    m_logger(DEBUGGING) << "Container export finished";
  } catch (const std::exception& e) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to export container: " << e.what();
    startBlockchainSynchronizer();
    throw;
  }

  startBlockchainSynchronizer();
  m_logger(INFO, BRIGHT_WHITE) << "Container exported";
}

void WalletGreen::load(const std::string& path, const std::string& password, std::string& extra) {
  m_logger(INFO, BRIGHT_WHITE) << "Loading container...";

  if (m_state != WalletState::NOT_INITIALIZED) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to load: already initialized. Current state: " << m_state;
    throw std::system_error(make_error_code(error::WRONG_STATE));
  }

  throwIfStopped();

  stopBlockchainSynchronizer();

  Crypto::cn_context cnContext;
  generate_chacha8_key(cnContext, password, m_key);

  std::ifstream walletFileStream(path, std::ios_base::binary);
  int version = walletFileStream.peek();
  if (version == EOF) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to read wallet version";
    throw std::system_error(make_error_code(error::WRONG_VERSION), "Failed to read wallet version");
  }

  if (version < WalletSerializerV2::MIN_VERSION) {
    convertAndLoadWalletFile(path, std::move(walletFileStream));
  } else {
    walletFileStream.close();

    if (version > WalletSerializerV2::SERIALIZATION_VERSION) {
      m_logger(ERROR, BRIGHT_RED) << "Unsupported wallet version: " << version;
      throw std::system_error(make_error_code(error::WRONG_VERSION), "Unsupported wallet version");
    }

    loadContainerStorage(path);
    subscribeWallets();

    if (m_containerStorage.suffixSize() > 0) {
      try {
        std::unordered_set<Crypto::PublicKey> addedSpendKeys;
        std::unordered_set<Crypto::PublicKey> deletedSpendKeys;
        loadWalletCache(addedSpendKeys, deletedSpendKeys, extra);

        if (!addedSpendKeys.empty()) {
          m_logger(WARNING, BRIGHT_YELLOW) << "Found addresses not saved in container cache. Resynchronize container";
          clearCaches(false, true);
          subscribeWallets();
        }

        if (!deletedSpendKeys.empty()) {
          m_logger(WARNING, BRIGHT_YELLOW) << "Found deleted addresses saved in container cache. Remove its transactions";
          deleteOrphanTransactions(deletedSpendKeys);
        }

        // Upgrade wallet file to current version if needed, or if key sets changed.
        const uint8_t loadedVersion =
          reinterpret_cast<const ContainerStoragePrefix*>(m_containerStorage.prefix())->version;
        bool needUpgradeSave = !addedSpendKeys.empty() || !deletedSpendKeys.empty()
          || loadedVersion < WalletSerializerV2::SERIALIZATION_VERSION;

        if (needUpgradeSave) {
          saveWalletCache(m_containerStorage, m_key, WalletSaveLevel::SAVE_ALL, extra);
        }
      } catch (const std::exception& e) {
        m_logger(ERROR, BRIGHT_RED) << "Failed to load cache: " << e.what() << ", reset wallet data";
        clearCaches(true, true);
        subscribeWallets();
      }
    }
  }

  initPqConsumerForPrimary();

  m_blockchainSynchronizer.addObserver(this);

  assert(m_blockchain.empty());
  if (m_walletsContainer.get<RandomAccessIndex>().size() != 0) {
    initBlockchain(m_viewPublicKey);

    startBlockchainSynchronizer();
  } else {
    m_blockchain.push_back(m_currency.genesisBlockHash());
    m_logger(DEBUGGING) << "Add genesis block hash to blockchain";
  }

  m_password = password;
  m_path = path;
  m_extra = extra;

  m_state = WalletState::INITIALIZED;
  m_logger(INFO, BRIGHT_WHITE) << "Container loaded, view public key " << m_viewPublicKey <<
    ", wallet count " << m_walletsContainer.size() <<
    ", actual balance " << m_currency.formatAmount(m_actualBalance) <<
    ", pending balance " << m_currency.formatAmount(m_pendingBalance);
}

void WalletGreen::load(const std::string& path, const std::string& password) {
  std::string extra;
  load(path, password, extra);
}

void WalletGreen::loadContainerStorage(const std::string& path) {
  try {
    m_containerStorage.open(path, FileMappedVectorOpenMode::OPEN, sizeof(ContainerStoragePrefix));

    ContainerStoragePrefix* prefix = reinterpret_cast<ContainerStoragePrefix*>(m_containerStorage.prefix());
    assert(prefix->version >= WalletSerializerV2::MIN_VERSION);

    uint64_t creationTimestamp;
    decryptKeyPair(prefix->encryptedViewKeys, m_viewPublicKey, m_viewSecretKey, creationTimestamp);
    throwIfKeysMissmatch(m_viewSecretKey, m_viewPublicKey, "Restored view public key doesn't correspond to secret key");
    m_logger = Logging::LoggerRef(m_logger.getLogger(), "WalletGreen/" + podToHex(m_viewPublicKey).substr(0, 5));

    loadSpendKeys();

    m_logger(DEBUGGING) << "Container keys were successfully loaded";
  } catch (const std::exception& e) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to load container keys: " << e.what();

    m_walletsContainer.clear();
    m_containerStorage.close();

    throw;
  }
}

void WalletGreen::loadWalletCache(std::unordered_set<Crypto::PublicKey>& addedKeys, std::unordered_set<Crypto::PublicKey>& deletedKeys, std::string& extra) {
  assert(m_containerStorage.isOpened());

  BinaryArray contanerData;
  loadAndDecryptContainerData(m_containerStorage, m_key, contanerData);

  WalletSerializerV2 s(
    m_viewPublicKey,
    m_viewSecretKey,
    m_addressGenerationMode,
    m_deterministicSeed,
    m_nextDeterministicIndex,
    m_actualBalance,
    m_pendingBalance,
    m_walletsContainer,
    m_unlockTransactionsJob,
    m_transactions,
    m_transfers,
    m_uncommitedTransactions,
    extra,
    m_transactionSoftLockTime,
    m_pqState
  );

  Common::MemoryInputStream containerStream(contanerData.data(), contanerData.size());
  s.load(containerStream, reinterpret_cast<const ContainerStoragePrefix*>(m_containerStorage.prefix())->version);
  addedKeys = std::move(s.addedKeys());
  deletedKeys = std::move(s.deletedKeys());

  // The PQ consumer was (re)created during key/balance load; restore its sync
  // cursor + owned outputs from the persisted blob so it resumes instead of
  // rescanning from genesis. No-op when there is no PQ state or no consumer.
  restorePqStateBlob();

  m_logger(DEBUGGING) << "Container cache loaded";
}

void WalletGreen::saveWalletCache(ContainerStorage& storage, const Crypto::chacha8_key& key, WalletSaveLevel saveLevel, const std::string& extra) {
  m_logger(DEBUGGING) << "Saving cache...";

  WalletTransactions transactions;
  WalletTransfers transfers;

  if (saveLevel == WalletSaveLevel::SAVE_KEYS_AND_TRANSACTIONS) {
    filterOutTransactions(transactions, transfers, [](const WalletTransaction& tx) {
      return tx.state == WalletTransactionState::CREATED || tx.state == WalletTransactionState::DELETED;
    });

    for (auto it = transactions.begin(); it != transactions.end(); ++it) {
      transactions.modify(it, [](WalletTransaction& tx) {
        tx.state = WalletTransactionState::CANCELLED;
        tx.blockHeight = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
      });
    }
  } else if (saveLevel == WalletSaveLevel::SAVE_ALL) {
    filterOutTransactions(transactions, transfers, [](const WalletTransaction& tx) {
      return tx.state == WalletTransactionState::DELETED;
    });
  }

  // Capture the current PQ consumer cursor + owned outputs so they persist.
  buildPqStateBlob();

  std::string containerData;
  Common::StringOutputStream containerStream(containerData);

  WalletSerializerV2 s(
    m_viewPublicKey,
    m_viewSecretKey,
    m_addressGenerationMode,
    m_deterministicSeed,
    m_nextDeterministicIndex,
    m_actualBalance,
    m_pendingBalance,
    m_walletsContainer,
    m_unlockTransactionsJob,
    transactions,
    transfers,
    m_uncommitedTransactions,
    const_cast<std::string&>(extra),
    m_transactionSoftLockTime,
    m_pqState
  );

  s.save(containerStream, saveLevel);

  // Upgrade the prefix version if the storage was created/loaded with an older format.
  ContainerStoragePrefix* pfx = reinterpret_cast<ContainerStoragePrefix*>(storage.prefix());
  if (pfx->version < WalletSerializerV2::SERIALIZATION_VERSION) {
    m_logger(INFO) << "Upgrading wallet file format from v" << static_cast<int>(pfx->version)
                   << " to v" << static_cast<int>(WalletSerializerV2::SERIALIZATION_VERSION);
    pfx->version = WalletSerializerV2::SERIALIZATION_VERSION;
  }

  encryptAndSaveContainerData(storage, key, containerData.data(), containerData.size());
  storage.flush();

  m_extra = extra;

  m_logger(DEBUGGING) << "Container saving finished";
}

void WalletGreen::copyContainerStorageKeys(ContainerStorage& src, const chacha8_key& srcKey, ContainerStorage& dst, const chacha8_key& dstKey) {
  dst.reserve(src.size());

  dst.setAutoFlush(false);
  Tools::ScopeExit exitHandler([&dst] {
    dst.setAutoFlush(true);
    dst.flush();
  });

  size_t counter = 0;

  for (auto& encryptedSpendKeys : src) {
    Crypto::PublicKey publicKey;
    Crypto::SecretKey secretKey;
    uint64_t creationTimestamp;
    decryptKeyPair(encryptedSpendKeys, publicKey, secretKey, creationTimestamp, srcKey);

    // push_back() can resize container, and dstPrefix address can be changed, so it is requested for each key pair
    ContainerStoragePrefix* dstPrefix = reinterpret_cast<ContainerStoragePrefix*>(dst.prefix());
    Crypto::chacha8_iv keyPairIv = dstPrefix->nextIv;
    incIv(dstPrefix->nextIv);

    dst.push_back(encryptKeyPair(publicKey, secretKey, creationTimestamp, dstKey, keyPairIv));
  }
}

void WalletGreen::copyContainerStoragePrefix(ContainerStorage& src, const chacha8_key& srcKey, ContainerStorage& dst, const chacha8_key& dstKey) {
  ContainerStoragePrefix* srcPrefix = reinterpret_cast<ContainerStoragePrefix*>(src.prefix());
  ContainerStoragePrefix* dstPrefix = reinterpret_cast<ContainerStoragePrefix*>(dst.prefix());
  dstPrefix->version = srcPrefix->version;
  dstPrefix->nextIv = Crypto::randomChachaIV();

  Crypto::PublicKey publicKey;
  Crypto::SecretKey secretKey;
  uint64_t creationTimestamp;
  decryptKeyPair(srcPrefix->encryptedViewKeys, publicKey, secretKey, creationTimestamp, srcKey);
  dstPrefix->encryptedViewKeys = encryptKeyPair(publicKey, secretKey, creationTimestamp, dstKey, dstPrefix->nextIv);
  incIv(dstPrefix->nextIv);
}

void WalletGreen::encryptAndSaveContainerData(ContainerStorage& storage, const Crypto::chacha8_key& key, const void* containerData, size_t containerDataSize) {
  ContainerStoragePrefix* prefix = reinterpret_cast<ContainerStoragePrefix*>(storage.prefix());

  Crypto::chacha8_iv suffixIv = prefix->nextIv;
  incIv(prefix->nextIv);

  BinaryArray encryptedContainer;
  encryptedContainer.resize(containerDataSize);
  chacha8(containerData, containerDataSize, key, suffixIv, reinterpret_cast<char*>(encryptedContainer.data()));

  std::string suffix;
  Common::StringOutputStream suffixStream(suffix);
  BinaryOutputStreamSerializer suffixSerializer(suffixStream);
  suffixSerializer(suffixIv, "suffixIv");
  suffixSerializer(encryptedContainer, "encryptedContainer");

  storage.resizeSuffix(suffix.size());
  std::copy(suffix.begin(), suffix.end(), storage.suffix());
}

void WalletGreen::loadAndDecryptContainerData(ContainerStorage& storage, const Crypto::chacha8_key& key, BinaryArray& containerData) {
  Common::MemoryInputStream suffixStream(storage.suffix(), storage.suffixSize());
  BinaryInputStreamSerializer suffixSerializer(suffixStream);
  Crypto::chacha8_iv suffixIv;
  BinaryArray encryptedContainer;
  suffixSerializer(suffixIv, "suffixIv");
  suffixSerializer(encryptedContainer, "encryptedContainer");

  containerData.resize(encryptedContainer.size());
  chacha8(encryptedContainer.data(), encryptedContainer.size(), key, suffixIv, reinterpret_cast<char*>(containerData.data()));
}

void WalletGreen::deleteOrphanTransactions(const std::unordered_set<Crypto::PublicKey>& deletedKeys) {
  for (auto spendPublicKey : deletedKeys) {
    AccountPublicAddress deletedAccountAddress;
    deletedAccountAddress.spendPublicKey = spendPublicKey;
    deletedAccountAddress.viewPublicKey = m_viewPublicKey;
    auto deletedAddressString = m_currency.accountAddressAsString(deletedAccountAddress);

    std::vector<size_t> deletedTransactions;
    std::vector<size_t> updatedTransactions = deleteTransfersForAddress(deletedAddressString, deletedTransactions);
    deleteFromUncommitedTransactions(deletedTransactions);
  }
}

void WalletGreen::loadSpendKeys() {
  bool isTrackingMode;
  for (size_t i = 0; i < m_containerStorage.size(); ++i) {
    WalletRecord wallet;
    uint64_t creationTimestamp;
    decryptKeyPair(m_containerStorage[i], wallet.spendPublicKey, wallet.spendSecretKey, creationTimestamp);
    wallet.creationTimestamp = creationTimestamp;

    if (i == 0) {
      isTrackingMode = wallet.spendSecretKey == NULL_SECRET_KEY;
    } else if ((isTrackingMode && wallet.spendSecretKey != NULL_SECRET_KEY) || (!isTrackingMode && wallet.spendSecretKey == NULL_SECRET_KEY)) {
      throw std::system_error(make_error_code(error::BAD_ADDRESS), "All addresses must be whether tracking or not");
    }

    if (wallet.spendSecretKey != NULL_SECRET_KEY) {
      throwIfKeysMissmatch(wallet.spendSecretKey, wallet.spendPublicKey, "Restored spend public key doesn't correspond to secret key");
    } else {
      if (!Crypto::check_key(wallet.spendPublicKey)) {
        throw std::system_error(make_error_code(error::WRONG_PASSWORD), "Public spend key is incorrect");
      }
    }

    wallet.actualBalance = 0;
    wallet.pendingBalance = 0;

    m_walletsContainer.emplace_back(std::move(wallet));
  }
}

void WalletGreen::subscribeWallets() {
  // No-op: the classical TransfersSyncronizer is no longer a sync driver. Scanning
  // is done entirely by the PQ ledger consumer (created in initPqConsumer); each
  // WalletRecord.container already holds its unique synthetic key from loadSpendKeys
  // / clearCaches, and is never used as a real ITransfersContainer.
}

void WalletGreen::convertAndLoadWalletFile(const std::string& path, std::ifstream&& walletFileStream) {
  // Pre-v6 (classical Karbo) wallet files have no place on a post-quantum-from-genesis
  // chain: they hold ECC keys and a classical TransfersSyncronizer cache that the PQ
  // engine cannot use. The old WalletSerializerV1 import path is therefore retired.
  walletFileStream.close();
  m_logger(ERROR, BRIGHT_RED) << "Unsupported legacy wallet file: " << path;
  throw std::system_error(make_error_code(error::WRONG_VERSION),
    "Legacy (pre-v6) wallet files are not supported by the post-quantum wallet");
}

void WalletGreen::changePassword(const std::string& oldPassword, const std::string& newPassword) {
  throwIfNotInitialized();
  throwIfStopped();

  if (m_password.compare(oldPassword)) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to change password: the old password is wrong";
    throw std::system_error(make_error_code(error::WRONG_PASSWORD));
  }

  if (oldPassword == newPassword) {
    return;
  }

  Crypto::cn_context cnContext;
  Crypto::chacha8_key newKey;
  Crypto::generate_chacha8_key(cnContext, newPassword, newKey);

  m_containerStorage.atomicUpdate([this, newKey](ContainerStorage& newStorage) {
    copyContainerStoragePrefix(m_containerStorage, m_key, newStorage, newKey);
    copyContainerStorageKeys(m_containerStorage, m_key, newStorage, newKey);

    if (m_containerStorage.suffixSize() > 0) {
      BinaryArray containerData;
      loadAndDecryptContainerData(m_containerStorage, m_key, containerData);
      encryptAndSaveContainerData(newStorage, newKey, containerData.data(), containerData.size());
    }
  });

  m_key = newKey;
  m_password = newPassword;

  m_logger(INFO, BRIGHT_WHITE) << "Container password changed";
}

bool WalletGreen::pqRegistrationCoords(uint32_t& height, uint32_t& txIndex) const {
  if (m_pqRegResolved) {
    height = m_pqRegHeight;
    txIndex = m_pqRegTxIndex;
    return true;
  }
  std::string viewHex, spendHex;
  if (!getPqRegistrationKeysHex(viewHex, spendHex)) {
    return false;  // tracking wallet
  }
  bool registered = false;
  uint32_t h = 0, i = 0;
  std::promise<std::error_code> promise;
  auto future = promise.get_future();
  m_node.getPqAccount(viewHex, spendHex, registered, h, i,
                      [&promise](std::error_code ec) { promise.set_value(ec); });
  if (future.get() || !registered) {
    return false;
  }
  m_pqRegResolved = true;
  m_pqRegHeight = h;
  m_pqRegTxIndex = i;
  height = h;
  txIndex = i;
  return true;
}

size_t WalletGreen::getAddressCount() const {
  throwIfNotInitialized();
  throwIfStopped();

  if (pqEnabled()) {
    // PQ-native address space: the primary address plus every issued deposit.
    return static_cast<size_t>(1) + m_pqDepositCount;
  }
  return m_walletsContainer.get<RandomAccessIndex>().size();
}

AccountPublicAddress WalletGreen::getAccountPublicAddress(size_t index) const {
  throwIfNotInitialized();
  throwIfStopped();

  if (index >= m_walletsContainer.get<RandomAccessIndex>().size()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get address: invalid address index " << index;
    throw std::system_error(make_error_code(std::errc::invalid_argument));
  }

  const WalletRecord& wallet = m_walletsContainer.get<RandomAccessIndex>()[index];
  return { wallet.spendPublicKey, m_viewPublicKey };
}

std::string WalletGreen::getAddress(size_t index) const {
  if (pqEnabled()) {
    // Index 0 is the wallet's own PQ address; index i>0 is deposit i-1.
    if (index == 0) {
      return getPqAddress();
    }
    uint32_t depositIndex = static_cast<uint32_t>(index - 1);
    if (depositIndex >= m_pqDepositCount) {
      m_logger(ERROR, BRIGHT_RED) << "Failed to get address: invalid address index " << index;
      throw std::system_error(make_error_code(std::errc::invalid_argument));
    }
    uint32_t regH = 0, regI = 0;
    if (m_pqDepositScheme == PqDepositScheme::SingleKeyIndex && !pqRegistrationCoords(regH, regI)) {
      // H-I-T-C needs the account's on-chain coords; surface that it isn't ready.
      throw std::system_error(make_error_code(error::INTERNAL_WALLET_ERROR),
                              "single-key-index deposit address requires a confirmed registration");
    }
    return pqDepositAddress(depositIndex, regH, regI);
  }
  return m_currency.accountAddressAsString(getAccountPublicAddress(index));
}

KeyPair WalletGreen::getAddressSpendKey(size_t index) const {
  throwIfNotInitialized();
  throwIfStopped();

  if (index >= m_walletsContainer.get<RandomAccessIndex>().size()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get address spend key: invalid address index " << index;
    throw std::system_error(make_error_code(std::errc::invalid_argument));
  }

  const WalletRecord& wallet = m_walletsContainer.get<RandomAccessIndex>()[index];
  return {wallet.spendPublicKey, wallet.spendSecretKey};
}

KeyPair WalletGreen::getAddressSpendKey(const std::string& address) const {
  throwIfNotInitialized();
  throwIfStopped();

  CryptoNote::AccountPublicAddress pubAddr = parseAddress(address);

  auto it = m_walletsContainer.get<KeysIndex>().find(pubAddr.spendPublicKey);
  if (it == m_walletsContainer.get<KeysIndex>().end()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get address spend key: address not found " << address;
    throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND));
  }

  return {it->spendPublicKey, it->spendSecretKey};
}

KeyPair WalletGreen::getViewKey() const {
  throwIfNotInitialized();
  throwIfStopped();

  return {m_viewPublicKey, m_viewSecretKey};
}

AddressGenerationMode WalletGreen::getAddressGenerationMode() const {
  throwIfNotInitialized();
  throwIfStopped();

  return m_addressGenerationMode;
}

Crypto::SecretKey WalletGreen::getDeterministicSeed() const {
  throwIfNotInitialized();
  throwIfStopped();

  if (m_addressGenerationMode != AddressGenerationMode::HD_DETERMINISTIC || m_deterministicSeed == NULL_SECRET_KEY) {
    m_logger(ERROR, BRIGHT_RED) << "Container does not have an HD deterministic seed";
    throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
  }

  return m_deterministicSeed;
}

void WalletGreen::setAddressGenerationMode(AddressGenerationMode mode, const Crypto::SecretKey& deterministicSeed) {
  throwIfNotInitialized();
  throwIfStopped();

  if (!m_walletsContainer.get<RandomAccessIndex>().empty()) {
    m_logger(ERROR, BRIGHT_RED) << "Address generation mode can only be set before addresses are added";
    throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
  }

  if (mode == AddressGenerationMode::HD_DETERMINISTIC) {
    if (deterministicSeed == NULL_SECRET_KEY) {
      m_logger(ERROR, BRIGHT_RED) << "HD deterministic mode requires a non-null seed";
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
    }

    Crypto::PublicKey spendPublicKey;
    if (!Crypto::secret_key_to_public_key(deterministicSeed, spendPublicKey)) {
      m_logger(ERROR, BRIGHT_RED) << "HD deterministic seed cannot be converted to a public spend key";
      throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
    }

    Crypto::SecretKey deterministicViewSecretKey;
    CryptoNote::AccountBase::generateViewFromSpend(deterministicSeed, deterministicViewSecretKey);
    if (deterministicViewSecretKey != m_viewSecretKey) {
      m_logger(ERROR, BRIGHT_RED) << "HD deterministic seed does not match the container view key";
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
    }

    m_addressGenerationMode = AddressGenerationMode::HD_DETERMINISTIC;
    m_deterministicSeed = deterministicSeed;
    m_nextDeterministicIndex = 0;
    return;
  }

  if (mode == AddressGenerationMode::INDEPENDENT_SPEND_KEYS) {
    m_addressGenerationMode = AddressGenerationMode::INDEPENDENT_SPEND_KEYS;
    m_deterministicSeed = NULL_SECRET_KEY;
    m_nextDeterministicIndex = 0;
    return;
  }

  m_logger(ERROR, BRIGHT_RED) << "Unknown address generation mode";
  throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
}

CryptoNote::KeyPair WalletGreen::deriveHdSpendKey(uint32_t hdIndex) const {
  if (m_addressGenerationMode != AddressGenerationMode::HD_DETERMINISTIC || m_deterministicSeed == NULL_SECRET_KEY ||
      hdIndex == WALLET_INVALID_HD_INDEX) {
    m_logger(ERROR, BRIGHT_RED) << "HD spend key derivation requested for an invalid wallet state or index";
    throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
  }

  KeyPair spendKey;
  if (hdIndex == 0) {
    spendKey.secretKey = m_deterministicSeed;
  } else {
    static const char domain[] = "Karbo walletd HD spend v1";
    std::vector<uint8_t> derivationData;
    derivationData.reserve(sizeof(domain) - 1 + sizeof(m_deterministicSeed.data) + sizeof(m_viewSecretKey.data) + sizeof(hdIndex));
    const uint8_t* domainData = reinterpret_cast<const uint8_t*>(domain);
    derivationData.insert(derivationData.end(), domainData, domainData + sizeof(domain) - 1);
    derivationData.insert(derivationData.end(), m_deterministicSeed.data, m_deterministicSeed.data + sizeof(m_deterministicSeed.data));
    derivationData.insert(derivationData.end(), m_viewSecretKey.data, m_viewSecretKey.data + sizeof(m_viewSecretKey.data));
    derivationData.push_back(static_cast<uint8_t>(hdIndex));
    derivationData.push_back(static_cast<uint8_t>(hdIndex >> 8));
    derivationData.push_back(static_cast<uint8_t>(hdIndex >> 16));
    derivationData.push_back(static_cast<uint8_t>(hdIndex >> 24));
    Crypto::hash_to_scalar(derivationData.data(), derivationData.size(), spendKey.secretKey);
  }

  if (!Crypto::secret_key_to_public_key(spendKey.secretKey, spendKey.publicKey)) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to derive HD spend public key at index " << hdIndex;
    throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
  }

  return spendKey;
}

WalletGreen::NewAddressData WalletGreen::createHdAddressData(uint64_t creationTimestamp) {
  for (;;) {
    if (m_nextDeterministicIndex == WALLET_INVALID_HD_INDEX) {
      m_logger(ERROR, BRIGHT_RED) << "HD address index space is exhausted";
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
    }

    const uint32_t hdIndex = m_nextDeterministicIndex++;
    KeyPair spendKey = deriveHdSpendKey(hdIndex);
    if (m_walletsContainer.get<KeysIndex>().find(spendKey.publicKey) == m_walletsContainer.get<KeysIndex>().end()) {
      return NewAddressData{ spendKey.publicKey, spendKey.secretKey, creationTimestamp, hdIndex };
    }
  }
}

std::string WalletGreen::createAddress() {
  // PQ-native: "create address" mints a new deposit (a fresh ML-DSA spend key under
  // AggregatedMultikey, or the next subaddress index T under SingleKeyIndex) and
  // returns its address. The classical key-record path is used only for non-PQ
  // (tracking) containers.
  if (pqEnabled()) {
    uint32_t depositIndex = reservePqDepositIndex();
    return getAddress(static_cast<size_t>(depositIndex) + 1);
  }

  if (m_addressGenerationMode == AddressGenerationMode::HD_DETERMINISTIC) {
    return doCreateAddressList({ createHdAddressData(static_cast<uint64_t>(time(nullptr))) }).front();
  }

  KeyPair spendKey;
  Crypto::generate_keys(spendKey.publicKey, spendKey.secretKey);
  uint64_t creationTimestamp = static_cast<uint64_t>(time(nullptr));

  return doCreateAddress(spendKey.publicKey, spendKey.secretKey, creationTimestamp);
}

std::string WalletGreen::createAddress(uint32_t scanHeight) {
  if (pqEnabled()) {
    uint32_t depositIndex = reservePqDepositIndex();
    return getAddress(static_cast<size_t>(depositIndex) + 1);
  }
  const uint64_t creationTimestamp = scanHeightToTimestamp(scanHeight);
  if (m_addressGenerationMode == AddressGenerationMode::HD_DETERMINISTIC) {
    return doCreateAddressList({ createHdAddressData(creationTimestamp) }).front();
  }

  KeyPair spendKey;
  Crypto::generate_keys(spendKey.publicKey, spendKey.secretKey);
  return doCreateAddress(spendKey.publicKey, spendKey.secretKey, creationTimestamp);
}

std::string WalletGreen::createAddress(const Crypto::SecretKey& spendSecretKey, bool reset) {
  Crypto::PublicKey spendPublicKey;
  if (!Crypto::secret_key_to_public_key(spendSecretKey, spendPublicKey)) {
    m_logger(ERROR, BRIGHT_RED) << "createAddress(" << spendSecretKey << ") Failed to convert secret key to public key";
    throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
  }
  uint64_t creationTimestamp = reset ? 0 : static_cast<uint64_t>(time(nullptr));

  return doCreateAddress(spendPublicKey, spendSecretKey, creationTimestamp);
}

std::string WalletGreen::createAddress(const Crypto::SecretKey& spendSecretKey, const uint64_t& creationTimestamp) {
  Crypto::PublicKey spendPublicKey;
  if (!Crypto::secret_key_to_public_key(spendSecretKey, spendPublicKey)) {
    m_logger(ERROR, BRIGHT_RED) << "createAddress(" << spendSecretKey << ") Failed to convert secret key to public key";
    throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
  }

  return doCreateAddress(spendPublicKey, spendSecretKey, creationTimestamp);
}

std::string WalletGreen::createAddress(const Crypto::PublicKey& spendPublicKey, bool reset) {
  if (!Crypto::check_key(spendPublicKey)) {
    m_logger(ERROR, BRIGHT_RED) << "createAddress(" << spendPublicKey << ") Wrong public key format";
    throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "Wrong public key format");
  }
  uint64_t creationTimestamp = reset ? 0 : static_cast<uint64_t>(time(nullptr));

  return doCreateAddress(spendPublicKey, NULL_SECRET_KEY, creationTimestamp);
}

std::string WalletGreen::createAddress(const Crypto::PublicKey& spendPublicKey, const uint64_t& creationTimestamp) {
  if (!Crypto::check_key(spendPublicKey)) {
    m_logger(ERROR, BRIGHT_RED) << "createAddress(" << spendPublicKey << ") Wrong public key format";
    throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "Wrong public key format");
  }

  return doCreateAddress(spendPublicKey, NULL_SECRET_KEY, creationTimestamp);
}

std::string WalletGreen::createAddress(const Crypto::SecretKey& spendSecretKey, const uint32_t scanHeight) {
  Crypto::PublicKey spendPublicKey;
  if (!Crypto::secret_key_to_public_key(spendSecretKey, spendPublicKey)) {
    m_logger(ERROR, BRIGHT_RED) << "createAddress(" << spendSecretKey << ") Failed to convert secret key to public key";
    throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
  }
  uint64_t creationTimestamp = scanHeightToTimestamp(scanHeight);

  return doCreateAddress(spendPublicKey, spendSecretKey, creationTimestamp);
}

std::string WalletGreen::createAddress(const Crypto::PublicKey& spendPublicKey, const uint32_t scanHeight) {
  if (!Crypto::check_key(spendPublicKey)) {
    m_logger(ERROR, BRIGHT_RED) << "createAddress(" << spendPublicKey << ") Wrong public key format";
    throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "Wrong public key format");
  }
  uint64_t creationTimestamp = scanHeightToTimestamp(scanHeight);

  return doCreateAddress(spendPublicKey, NULL_SECRET_KEY, creationTimestamp);
}

std::vector<std::string> WalletGreen::createAddressList(const std::vector<Crypto::SecretKey>& spendSecretKeys, bool reset) {
  std::vector<NewAddressData> addressDataList(spendSecretKeys.size());
  for (size_t i = 0; i < spendSecretKeys.size(); ++i) {
    Crypto::PublicKey spendPublicKey;
    if (!Crypto::secret_key_to_public_key(spendSecretKeys[i], spendPublicKey)) {
      m_logger(ERROR, BRIGHT_RED) << "createAddressList(): failed to convert secret key to public key, secret key " << spendSecretKeys[i];
      throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
    }

    addressDataList[i].spendSecretKey = spendSecretKeys[i];
    addressDataList[i].spendPublicKey = spendPublicKey;
    addressDataList[i].creationTimestamp = reset ? 0 : static_cast<uint64_t>(time(nullptr));
  }

  return doCreateAddressList(addressDataList);
}

std::vector<std::string> WalletGreen::createAddressList(const std::vector<Crypto::SecretKey>& spendSecretKeys, const std::vector<uint64_t>&creationTimestamps) {
  if (spendSecretKeys.size() != creationTimestamps.size()) {
    m_logger(ERROR, BRIGHT_RED) << "createAddressList(): the sizes of keys and timestamps vectors do not match.";
    throw std::system_error(make_error_code(std::errc::invalid_argument));
  }
  std::vector<NewAddressData> addressDataList(spendSecretKeys.size());
  for (size_t i = 0; i < spendSecretKeys.size(); ++i) {
    Crypto::PublicKey spendPublicKey;
    if (!Crypto::secret_key_to_public_key(spendSecretKeys[i], spendPublicKey)) {
      m_logger(ERROR, BRIGHT_RED) << "createAddressList(): failed to convert secret key to public key, secret key " << spendSecretKeys[i];
      throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
    }

    addressDataList[i].spendSecretKey = spendSecretKeys[i];
    addressDataList[i].spendPublicKey = spendPublicKey;
    addressDataList[i].creationTimestamp = creationTimestamps[i];
  }

  return doCreateAddressList(addressDataList);
}

std::vector<std::string> WalletGreen::createAddressList(const std::vector<Crypto::SecretKey>& spendSecretKeys, const std::vector<uint32_t>& scanHeights) {
  if (spendSecretKeys.size() != scanHeights.size()) {
    m_logger(ERROR, BRIGHT_RED) << "createAddressList(): the sizes of keys and scan heights vectors do not match.";
    throw std::system_error(make_error_code(std::errc::invalid_argument));
  }
  std::vector<NewAddressData> addressDataList(spendSecretKeys.size());
  for (size_t i = 0; i < spendSecretKeys.size(); ++i) {
    Crypto::PublicKey spendPublicKey;
    if (!Crypto::secret_key_to_public_key(spendSecretKeys[i], spendPublicKey)) {
      m_logger(ERROR, BRIGHT_RED) << "createAddressList(): failed to convert secret key to public key, secret key " << spendSecretKeys[i];
      throw std::system_error(make_error_code(CryptoNote::error::KEY_GENERATION_ERROR));
    }

    addressDataList[i].spendSecretKey = spendSecretKeys[i];
    addressDataList[i].spendPublicKey = spendPublicKey;
    addressDataList[i].creationTimestamp = scanHeightToTimestamp(scanHeights[i]);
  }

  return doCreateAddressList(addressDataList);
}

std::string WalletGreen::doCreateAddress(const Crypto::PublicKey& spendPublicKey, const Crypto::SecretKey& spendSecretKey, uint64_t creationTimestamp, uint32_t hdIndex) {
  assert(creationTimestamp <= std::numeric_limits<uint64_t>::max() - m_currency.blockFutureTimeLimit());

  std::vector<NewAddressData> addressDataList;
  addressDataList.push_back(NewAddressData{ spendPublicKey, spendSecretKey, creationTimestamp, hdIndex });
  std::vector<std::string> addresses = doCreateAddressList(addressDataList);
  assert(addresses.size() == 1);

  return addresses.front();
}

std::vector<std::string> WalletGreen::doCreateAddressList(const std::vector<NewAddressData>& addressDataList) {
  throwIfNotInitialized();
  throwIfStopped();

  stopBlockchainSynchronizer();

  std::vector<std::string> addresses;
  try {
    uint64_t minCreationTimestamp = std::numeric_limits<uint64_t>::max();

    {
      if (addressDataList.size() > 1) {
        m_containerStorage.setAutoFlush(false);
      }

      Tools::ScopeExit exitHandler([this] {
        if (!m_containerStorage.getAutoFlush()) {
          m_containerStorage.setAutoFlush(true);
          m_containerStorage.flush();
        }
      });

      for (auto& addressData : addressDataList) {
        assert(addressData.creationTimestamp <= std::numeric_limits<uint64_t>::max() - m_currency.blockFutureTimeLimit());
        std::string address = addWallet(addressData.spendPublicKey, addressData.spendSecretKey, addressData.creationTimestamp, addressData.hdIndex);
        m_logger(INFO, BRIGHT_WHITE) << "New wallet added " << address << ", creation timestamp " << addressData.creationTimestamp;
        addresses.push_back(std::move(address));

        minCreationTimestamp = std::min(minCreationTimestamp, addressData.creationTimestamp);
      }
    }

    m_containerStorage.setAutoFlush(true);
    auto currentTime = static_cast<uint64_t>(time(nullptr));
    if (minCreationTimestamp + m_currency.blockFutureTimeLimit() < currentTime) {
      m_logger(DEBUGGING) << "Reset is required";
      save(WalletSaveLevel::SAVE_KEYS_AND_TRANSACTIONS, m_extra);
      shutdown();
      load(m_path, m_password);
    }
  } catch (const std::exception& e) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to add wallets: " << e.what();
    startBlockchainSynchronizer();
    throw;
  }

  startBlockchainSynchronizer();

  return addresses;
}

std::string WalletGreen::addWallet(const Crypto::PublicKey& spendPublicKey, const Crypto::SecretKey& spendSecretKey, uint64_t creationTimestamp, uint32_t hdIndex) {
  auto& index = m_walletsContainer.get<KeysIndex>();

  auto trackingMode = getTrackingMode();

  if ((trackingMode == WalletTrackingMode::TRACKING && spendSecretKey != NULL_SECRET_KEY) ||
      (trackingMode == WalletTrackingMode::NOT_TRACKING && spendSecretKey == NULL_SECRET_KEY)) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to add wallet: incompatible tracking mode and spend secret key, tracking mode=" << trackingMode <<
      ", spendSecretKey " << (spendSecretKey == NULL_SECRET_KEY ? "is null" : "is not null");
    throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
  }

  auto insertIt = index.find(spendPublicKey);
  if (insertIt != index.end()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to add wallet: address already exists, " <<
      m_currency.accountAddressAsString(AccountPublicAddress{spendPublicKey, m_viewPublicKey});
    throw std::system_error(make_error_code(error::ADDRESS_ALREADY_EXISTS));
  }

  m_containerStorage.push_back(encryptKeyPair(spendPublicKey, spendSecretKey, creationTimestamp));
  incNextIv();

  try {
    AccountSubscription sub;
    sub.keys.address.viewPublicKey = m_viewPublicKey;
    sub.keys.address.spendPublicKey = spendPublicKey;
    sub.keys.viewSecretKey = m_viewSecretKey;
    sub.keys.spendSecretKey = spendSecretKey;
    sub.transactionSpendableAge = m_transactionSoftLockTime;
    sub.syncStart.height = 0;
    sub.syncStart.timestamp = std::max(creationTimestamp, ACCOUNT_CREATE_TIME_ACCURACY) - ACCOUNT_CREATE_TIME_ACCURACY;

    WalletRecord wallet;
    wallet.spendPublicKey = spendPublicKey;
    wallet.spendSecretKey = spendSecretKey;
    wallet.creationTimestamp = static_cast<time_t>(creationTimestamp);
    wallet.hdIndex = hdIndex;

    index.insert(insertIt, std::move(wallet));
    m_logger(DEBUGGING) << "Wallet count " << m_walletsContainer.size();

    if (index.size() == 1) {
      // The PQ identity derives from the primary address's spend secret. Create the
      // consumer first so the block list (m_blockchain) can be seeded from it.
      initPqConsumer(spendSecretKey, sub.syncStart);
      initBlockchain(m_viewPublicKey);
    }

    auto address = m_currency.accountAddressAsString({ spendPublicKey, m_viewPublicKey });
    m_logger(DEBUGGING) << "Wallet added " << address << ", creation timestamp " << creationTimestamp;
    return address;
  } catch (const std::exception& e) {
    m_logger(ERROR) << "Failed to add wallet: " << e.what();

    try {
      m_containerStorage.pop_back();
    } catch (...) {
      m_logger(ERROR) << "Failed to rollback adding wallet to storage";
    }

    throw;
  }
}

uint64_t WalletGreen::getBlockTimestamp(const uint32_t blockHeight) {
  uint64_t timestamp = 0;

  auto getBlockTimestampCompleted = std::promise<std::error_code>();
  auto getBlockTimestampWaitFuture = getBlockTimestampCompleted.get_future();

  m_node.getBlockTimestamp(blockHeight, std::ref(timestamp),
    [&getBlockTimestampCompleted](std::error_code ec) {
    auto detachedPromise = std::move(getBlockTimestampCompleted);
    detachedPromise.set_value(ec);
  });

  std::error_code ec = getBlockTimestampWaitFuture.get();

  return timestamp;
}

uint64_t WalletGreen::scanHeightToTimestamp(const uint32_t scanHeight) {
  if (scanHeight == 0) {
    return 0;
  }

  /* Get the block timestamp from the node if the node has it */
  uint64_t timestamp = getBlockTimestamp(scanHeight);

  if (timestamp != 0) {
    return timestamp;
  }

  /* Get the amount of seconds since the blockchain launched */
  uint64_t secondsSinceLaunch = scanHeight * CryptoNote::parameters::DIFFICULTY_TARGET;

  /* Add a bit of a buffer in case of difficulty weirdness, blocks coming
     out too fast */
  secondsSinceLaunch = static_cast<uint64_t>(secondsSinceLaunch * 0.95);

  /* Get the genesis block timestamp and add the time since launch */
  timestamp = UINT64_C(1464595534) + secondsSinceLaunch;

  /* Timestamp in the future */
  if (timestamp >= static_cast<uint64_t>(std::time(nullptr))) {
    return getCurrentTimestampAdjusted();
  }

  return timestamp;
}

uint64_t WalletGreen::getCurrentTimestampAdjusted() {
  /* Get the current time as a unix timestamp */
  std::time_t time = std::time(nullptr);

  /* Take the amount of time a block can potentially be in the past/future */
  std::initializer_list<uint64_t> limits = {
    CryptoNote::parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT,
    CryptoNote::parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V1
  };

  /* Get the largest adjustment possible */
  uint64_t adjust = std::max(limits);

  /* Take the earliest timestamp that will include all possible blocks */
  return time - adjust;
}

void WalletGreen::reset(const uint64_t scanHeight)
{
    throwIfNotInitialized();
    throwIfStopped();

    /* Stop so things can't be added to the container as we're looping */
    stop();

    /* Grab the wallet encrypted prefix */
    auto* prefix = reinterpret_cast<ContainerStoragePrefix*>(m_containerStorage.prefix());

    uint64_t newTimestamp = scanHeightToTimestamp((uint32_t) scanHeight);

    /* Reencrypt with the new creation timestamp so we rescan from here when we relaunch */
    prefix->encryptedViewKeys = encryptKeyPair(m_viewPublicKey, m_viewSecretKey, newTimestamp);

    /* As a reference so we can update it */
    for (auto& encryptedSpendKeys : m_containerStorage)
    {
        Crypto::PublicKey publicKey;
        Crypto::SecretKey secretKey;
        uint64_t oldTimestamp;

        /* Decrypt the key pair we're pointing to */
        decryptKeyPair(encryptedSpendKeys, publicKey, secretKey, oldTimestamp);

        /* Re-encrypt with the new timestamp */
        encryptedSpendKeys = encryptKeyPair(publicKey, secretKey, newTimestamp);
    }

    /* Start again so we can save */
    start();

    /* Save just the keys + timestamp to file */
    save(CryptoNote::WalletSaveLevel::SAVE_KEYS_ONLY);

    /* Stop and shutdown */
    stop();

    /* Shutdown the wallet */
    shutdown();

    start();

    /* Reopen from truncated storage */
    load(m_path, m_password);
}

void WalletGreen::deleteAddress(const std::string& address) {
  throwIfNotInitialized();
  throwIfStopped();

  CryptoNote::AccountPublicAddress pubAddr = parseAddress(address);

  auto it = m_walletsContainer.get<KeysIndex>().find(pubAddr.spendPublicKey);
  if (it == m_walletsContainer.get<KeysIndex>().end()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to delete wallet: address not found " << address;
    throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND));
  }

  stopBlockchainSynchronizer();

  m_actualBalance -= it->actualBalance;
  m_pendingBalance -= it->pendingBalance;

  if (it->actualBalance != 0 || it->pendingBalance != 0) {
    m_logger(INFO, BRIGHT_WHITE) << "Container balance updated, actual " << m_currency.formatAmount(m_actualBalance) <<
      ", pending " << m_currency.formatAmount(m_pendingBalance);
  }

  auto addressIndex = std::distance(m_walletsContainer.get<RandomAccessIndex>().begin(), m_walletsContainer.project<RandomAccessIndex>(it));

#if !defined(NDEBUG)
  Crypto::PublicKey publicKey;
  Crypto::SecretKey secretKey;
  uint64_t creationTimestamp;
  decryptKeyPair(m_containerStorage[addressIndex], publicKey, secretKey, creationTimestamp);
  assert(publicKey == it->spendPublicKey);
  assert(secretKey == it->spendSecretKey);
  assert(creationTimestamp == static_cast<uint64_t>(it->creationTimestamp));
#endif

  m_containerStorage.erase(std::next(m_containerStorage.begin(), addressIndex));

  std::vector<size_t> deletedTransactions;
  std::vector<size_t> updatedTransactions = deleteTransfersForAddress(address, deletedTransactions);
  deleteFromUncommitedTransactions(deletedTransactions);

  m_walletsContainer.get<KeysIndex>().erase(it);
  m_logger(DEBUGGING) << "Wallet count " << m_walletsContainer.size();

  if (m_walletsContainer.get<RandomAccessIndex>().size() != 0) {
    startBlockchainSynchronizer();
  } else {
    m_blockchain.clear();
    m_blockchain.push_back(m_currency.genesisBlockHash());
  }

  for (auto transactionId: updatedTransactions) {
    pushEvent(makeTransactionUpdatedEvent(transactionId));
  }

  m_logger(INFO, BRIGHT_WHITE) << "Wallet deleted " << address;
}

namespace {
// Build a native WalletTransaction from a PQ ledger history row. WalletLedger's
// UNCONFIRMED_HEIGHT equals WALLET_UNCONFIRMED_TRANSACTION_HEIGHT (both uint32 max),
// so the height maps through directly.
WalletTransaction pqRowToWalletTx(const PqWalletTransaction& h) {
  WalletTransaction tx;
  tx.state = WalletTransactionState::SUCCEEDED;
  tx.timestamp = h.timestamp;
  tx.blockHeight = h.height;
  tx.hash = h.txid;
  tx.totalAmount = h.netAmount;
  tx.fee = h.fee;
  tx.creationTime = h.timestamp;
  tx.unlockHeight = 0;
  tx.extra.clear();
  tx.isBase = false;
  return tx;
}
}  // namespace

uint64_t WalletGreen::getActualBalance() const {
  throwIfNotInitialized();
  throwIfStopped();

  if (pqEnabled()) {
    // PQ is the native ledger. "Actual" = confirmed (total minus still-in-mempool).
    const auto& st = m_pqConsumer->state();
    uint64_t total = st.balance();
    uint64_t pending = st.pendingBalance();
    return total >= pending ? total - pending : 0;
  }
  return m_actualBalance;
}

uint64_t WalletGreen::getActualBalance(const std::string& address) const {
  throwIfNotInitialized();
  throwIfStopped();

  if (pqEnabled()) {
    // Map a PQ address back to its deposit bucket. Primary -> primary balance;
    // a deposit address -> that deposit's balance; unknown -> 0.
    if (address == getPqAddress()) {
      return m_pqConsumer->state().depositBalance(PQ_PRIMARY_DEPOSIT);
    }
    for (uint32_t i = 0; i < m_pqDepositCount; ++i) {
      if (address == getAddress(static_cast<size_t>(i) + 1)) {
        return m_pqConsumer->state().depositBalance(i);
      }
    }
    return 0;
  }

  const auto& wallet = getWalletRecord(address);
  return wallet.actualBalance;
}

uint64_t WalletGreen::getPendingBalance() const {
  throwIfNotInitialized();
  throwIfStopped();

  if (pqEnabled()) {
    return m_pqConsumer->state().pendingBalance();
  }
  return m_pendingBalance;
}

uint64_t WalletGreen::getPendingBalance(const std::string& address) const {
  throwIfNotInitialized();
  throwIfStopped();

  const auto& wallet = getWalletRecord(address);
  return wallet.pendingBalance;
}

size_t WalletGreen::getTransactionCount() const {
  throwIfNotInitialized();
  throwIfStopped();

  if (pqEnabled()) {
    return m_pqConsumer->state().historyCount();
  }
  return m_transactions.get<RandomAccessIndex>().size();
}

WalletTransaction WalletGreen::getTransaction(size_t transactionIndex) const {
  throwIfNotInitialized();
  throwIfStopped();

  if (pqEnabled()) {
    const auto& hist = m_pqConsumer->state().history();
    if (hist.size() <= transactionIndex) {
      m_logger(ERROR, BRIGHT_RED) << "Failed to get transaction: invalid index " << transactionIndex
                                  << ". Number of transactions: " << hist.size();
      throw std::system_error(make_error_code(CryptoNote::error::INDEX_OUT_OF_RANGE));
    }
    return pqRowToWalletTx(hist[transactionIndex]);
  }

  if (m_transactions.size() <= transactionIndex) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get transaction: invalid index " << transactionIndex << ". Number of transactions: " << m_transactions.size();
    throw std::system_error(make_error_code(CryptoNote::error::INDEX_OUT_OF_RANGE));
  }

  return m_transactions.get<RandomAccessIndex>()[transactionIndex];
}

size_t WalletGreen::getTransactionTransferCount(size_t transactionIndex) const {
  throwIfNotInitialized();
  throwIfStopped();

  auto bounds = getTransactionTransfersRange(transactionIndex);
  return static_cast<size_t>(std::distance(bounds.first, bounds.second));
}

WalletTransfer WalletGreen::getTransactionTransfer(size_t transactionIndex, size_t transferIndex) const {
  throwIfNotInitialized();
  throwIfStopped();

  auto bounds = getTransactionTransfersRange(transactionIndex);

  if (transferIndex >= static_cast<size_t>(std::distance(bounds.first, bounds.second))) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get transfer: invalid transfer index " << transferIndex << ". Transaction index " << transactionIndex <<
      " transfer count " << std::distance(bounds.first, bounds.second);
    throw std::system_error(make_error_code(std::errc::invalid_argument));
  }

  return std::next(bounds.first, transferIndex)->second;
}

WalletGreen::TransfersRange WalletGreen::getTransactionTransfersRange(size_t transactionIndex) const {
  auto val = std::make_pair(transactionIndex, WalletTransfer());

  auto bounds = std::equal_range(m_transfers.begin(), m_transfers.end(), val, [] (const TransactionTransferPair& a, const TransactionTransferPair& b) {
    return a.first < b.first;
  });

  return bounds;
}

size_t WalletGreen::transfer(const TransactionParameters& transactionParameters, Crypto::SecretKey& txSecretKey) {
  System::EventLock lk(m_readyEvent);

  throwIfNotInitialized();
  throwIfTrackingMode();
  throwIfStopped();

  m_logger(INFO, BRIGHT_WHITE) << "transfer" <<
    ", to " << WalletOrderListFormatter(m_currency, transactionParameters.destinations) <<
    ", fee " << m_currency.formatAmount(transactionParameters.fee) <<
    ", unlockHeightstamp " << transactionParameters.unlockHeightstamp;

  // PQ is the native ledger: resolve the destinations as PQ recipients and build,
  // sign and relay through the common sender. The classical ECC coin-selection path
  // is gone (every output on this chain is post-quantum).
  std::vector<PqSendOutput> recipients;
  recipients.reserve(transactionParameters.destinations.size());
  for (const auto& dst : transactionParameters.destinations) {
    CryptoPQ::KemPublicKey viewPub;
    CryptoPQ::DsaPublicKey spendPub;
    uint64_t subaddrT = 0;
    if (!resolvePqRecipient(m_node, dst.address, viewPub, spendPub, subaddrT)) {
      m_logger(ERROR, BRIGHT_RED) << "Invalid recipient: " << dst.address;
      throw std::system_error(make_error_code(error::BAD_ADDRESS));
    }
    recipients.push_back(PqSendOutput{viewPub, spendPub, dst.amount, subaddrT});
  }

  std::vector<uint8_t> extra(transactionParameters.extra.begin(), transactionParameters.extra.end());
  PqSendResult result = sendPqTransfer(recipients, transactionParameters.fee,
                                       transactionParameters.unlockHeightstamp, extra);
  txSecretKey = NULL_SECRET_KEY;  // PQ transactions carry no per-tx secret key

  size_t id = registerSentPqTransaction(result.tx);
  m_logger(INFO, BRIGHT_WHITE) << "PQ transaction sent, hash " << getObjectHash(result.tx) <<
    ", amount " << m_currency.formatAmount(result.sent) <<
    ", fee " << m_currency.formatAmount(result.fee);
  return id;
}

uint64_t WalletGreen::getBalanceMinusDust(const std::vector<std::string>& /*addresses*/)
{
  // PQ output amounts are drawn from the fixed canonical denomination table, so
  // there is no unspendable "dust"; the full confirmed balance is spendable.
  return getActualBalance();
}

CryptoNote::AccountPublicAddress WalletGreen::parseAccountAddressString(const std::string& addressString) const {
  CryptoNote::AccountPublicAddress address;

  if (!m_currency.parseAccountAddressString(addressString, address)) {
    m_logger(ERROR, BRIGHT_RED) << "Bad address: " << addressString;
    throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS));
  }

  return address;
}

size_t WalletGreen::makeTransaction(const TransactionParameters& /*sendingTransaction*/) {
  throwIfNotInitialized();
  throwIfTrackingMode();
  throwIfStopped();

  // Delayed (uncommitted) transactions relied on the classical build-without-relay
  // path. The PQ sender always builds-and-relays; a deferred PQ flow is not wired.
  throw std::system_error(make_error_code(std::errc::function_not_supported),
    "Delayed transactions are not supported on the post-quantum wallet");
}

void WalletGreen::commitTransaction(size_t transactionId) {
  System::EventLock lk(m_readyEvent);

  throwIfNotInitialized();
  throwIfStopped();
  throwIfTrackingMode();

  if (transactionId >= m_transactions.size()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to commit transaction: invalid index " << transactionId << ". Number of transactions: " << m_transactions.size();
    throw std::system_error(make_error_code(CryptoNote::error::INDEX_OUT_OF_RANGE));
  }

  auto txIt = std::next(m_transactions.get<RandomAccessIndex>().begin(), transactionId);
  if (m_uncommitedTransactions.count(transactionId) == 0 || txIt->state != WalletTransactionState::CREATED) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to commit transaction: bad transaction state. Transaction index " << transactionId << ", state " << txIt->state;
    throw std::system_error(make_error_code(error::TX_TRANSFER_IMPOSSIBLE));
  }

  std::error_code ec;

  try {
    auto relayTransactionCompleted = std::promise<std::error_code>();
    auto relayTransactionWaitFuture = relayTransactionCompleted.get_future();

    m_node.relayTransaction(m_uncommitedTransactions[transactionId], [&ec, &relayTransactionCompleted, this](std::error_code error) {
      auto detachedPromise = std::move(relayTransactionCompleted);
      detachedPromise.set_value(ec);
      });
    ec = relayTransactionWaitFuture.get();
  }
  catch (const std::exception& e) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to relay uncommited transaction: " << e.what();
  }

  if (!ec) {
    updateTransactionStateAndPushEvent(transactionId, WalletTransactionState::SUCCEEDED);
    m_uncommitedTransactions.erase(transactionId);
  } else {
    m_logger(ERROR, BRIGHT_RED) << "Failed to relay transaction: " << ec << ", " << ec.message() << ". Transaction index " << transactionId;
    throw std::system_error(ec);
  }

  m_logger(INFO, BRIGHT_WHITE) << "Delayed transaction sent, ID " << transactionId << ", hash " << m_transactions[transactionId].hash;
}

void WalletGreen::rollbackUncommitedTransaction(size_t transactionId) {
  Tools::ScopeExit releaseContext([this] {
    m_dispatcher.yield();
  });

  System::EventLock lk(m_readyEvent);

  throwIfNotInitialized();
  throwIfStopped();
  throwIfTrackingMode();

  if (transactionId >= m_transactions.size()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to rollback transaction: invalid index " << transactionId << ". Number of transactions: " << m_transactions.size();
    throw std::system_error(make_error_code(CryptoNote::error::INDEX_OUT_OF_RANGE));
  }

  auto txIt = m_transactions.get<RandomAccessIndex>().begin();
  std::advance(txIt, transactionId);
  if (m_uncommitedTransactions.count(transactionId) == 0 || txIt->state != WalletTransactionState::CREATED) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to rollback transaction: bad transaction state. Transaction index " << transactionId << ", state " << txIt->state;
    throw std::system_error(make_error_code(error::TX_CANCEL_IMPOSSIBLE));
  }

  removeUnconfirmedTransaction(getObjectHash(m_uncommitedTransactions[transactionId]));
  m_uncommitedTransactions.erase(transactionId);

  m_logger(INFO, BRIGHT_WHITE) << "Delayed transaction rolled back, ID " << transactionId << ", hash " << m_transactions[transactionId].hash;
}

void WalletGreen::updateTransactionStateAndPushEvent(size_t transactionId, WalletTransactionState state) {
  auto it = std::next(m_transactions.get<RandomAccessIndex>().begin(), transactionId);

  if (it->state != state) {
    m_transactions.get<RandomAccessIndex>().modify(it, [state](WalletTransaction& tx) {
      tx.state = state;
    });

    pushEvent(makeTransactionUpdatedEvent(transactionId));
    m_logger(DEBUGGING) << "Transaction state changed, ID " << transactionId << ", hash " << it->hash << ", new state " << it->state;
  }
}

WalletTransactionWithTransfers WalletGreen::getTransaction(const Crypto::Hash& transactionHash) const {
  throwIfNotInitialized();
  throwIfStopped();

  if (pqEnabled()) {
    const auto* row = m_pqConsumer->state().historyByTxid(transactionHash);
    if (row == nullptr) {
      m_logger(ERROR, BRIGHT_RED) << "Failed to get transaction: not found. Transaction hash " << transactionHash;
      throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND), "Transaction not found");
    }
    WalletTransactionWithTransfers w;
    w.transaction = pqRowToWalletTx(*row);
    // Counterparties aren't recoverable from owned-output scanning: report the net
    // effect against this wallet's own address.
    w.transfers.push_back(WalletTransfer{WalletTransferType::USUAL, getPqAddress(), row->netAmount});
    return w;
  }

  auto& hashIndex = m_transactions.get<TransactionIndex>();
  auto it = hashIndex.find(transactionHash);
  if (it == hashIndex.end()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get transaction: not found. Transaction hash " << transactionHash;
    throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND), "Transaction not found");
  }

  WalletTransactionWithTransfers walletTransaction;
  walletTransaction.transaction = *it;
  walletTransaction.transfers = getTransactionTransfers(*it);

  return walletTransaction;
}

std::vector<TransactionsInBlockInfo> WalletGreen::getTransactions(const Crypto::Hash& blockHash, size_t count) const {
  throwIfNotInitialized();
  throwIfStopped();

  auto& hashIndex = m_blockchain.get<BlockHashIndex>();
  auto it = hashIndex.find(blockHash);
  if (it == hashIndex.end()) {
    return std::vector<TransactionsInBlockInfo>();
  }

  auto heightIt = m_blockchain.project<BlockHeightIndex>(it);

  uint32_t blockIndex = static_cast<uint32_t>(std::distance(m_blockchain.get<BlockHeightIndex>().begin(), heightIt));
  return getTransactionsInBlocks(blockIndex, count);
}

std::vector<TransactionsInBlockInfo> WalletGreen::getTransactions(uint32_t blockIndex, size_t count) const {
  throwIfNotInitialized();
  throwIfStopped();

  return getTransactionsInBlocks(blockIndex, count);
}

std::vector<Crypto::Hash> WalletGreen::getBlockHashes(uint32_t blockIndex, size_t count) const {
  throwIfNotInitialized();
  throwIfStopped();

  auto& index = m_blockchain.get<BlockHeightIndex>();

  if (blockIndex >= index.size()) {
    return std::vector<Crypto::Hash>();
  }

  auto start = std::next(index.begin(), blockIndex);
  auto end = std::next(index.begin(), std::min(index.size(), blockIndex + count));
  return std::vector<Crypto::Hash>(start, end);
}

uint32_t WalletGreen::getBlockCount() const {
  throwIfNotInitialized();
  throwIfStopped();

  uint32_t blockCount = static_cast<uint32_t>(m_blockchain.size());
  assert(blockCount != 0);

  return blockCount;
}

std::vector<WalletTransactionWithTransfers> WalletGreen::getUnconfirmedTransactions() const {
  throwIfNotInitialized();
  throwIfStopped();

  std::vector<WalletTransactionWithTransfers> result;
  if (pqEnabled()) {
    std::string ownAddress = getPqAddress();
    for (const auto& row : m_pqConsumer->state().history()) {
      if (row.height != WalletLedger::UNCONFIRMED_HEIGHT) {
        continue;
      }
      WalletTransactionWithTransfers w;
      w.transaction = pqRowToWalletTx(row);
      w.transfers.push_back(WalletTransfer{WalletTransferType::USUAL, ownAddress, row.netAmount});
      result.push_back(std::move(w));
    }
    return result;
  }

  auto lowerBound = m_transactions.get<BlockHeightIndex>().lower_bound(WALLET_UNCONFIRMED_TRANSACTION_HEIGHT);
  for (auto it = lowerBound; it != m_transactions.get<BlockHeightIndex>().end(); ++it) {
    if (it->state != WalletTransactionState::SUCCEEDED) {
      continue;
    }

    WalletTransactionWithTransfers transaction;
    transaction.transaction = *it;
    transaction.transfers = getTransactionTransfers(*it);

    result.push_back(transaction);
  }

  return result;
}

std::vector<size_t> WalletGreen::getDelayedTransactionIds() const {
  throwIfNotInitialized();
  throwIfStopped();
  throwIfTrackingMode();

  std::vector<size_t> result;
  result.reserve(m_uncommitedTransactions.size());

  for (const auto& kv: m_uncommitedTransactions) {
    result.push_back(kv.first);
  }

  return result;
}

std::vector<TransactionOutputInformation> WalletGreen::getTransfers(size_t /*index*/, uint32_t /*flags*/) const {
  throwIfNotInitialized();
  throwIfStopped();
  throwIfTrackingMode();

  // Classical per-address output enumeration is gone; PQ outputs live in the
  // WalletLedger (queried via pqSpendableInputs / the deposit-balance accessors).
  return std::vector<TransactionOutputInformation>();
}

Crypto::SecretKey WalletGreen::getTransactionDeterministicSecretKey(Crypto::Hash& transactionHash) const {
  throwIfNotInitialized();
  throwIfStopped();

  auto getTransactionCompleted = std::promise<std::error_code>();
  auto getTransactionWaitFuture = getTransactionCompleted.get_future();
  CryptoNote::Transaction tx;
  m_node.getTransaction(std::move(transactionHash), std::ref(tx),
    [&getTransactionCompleted](std::error_code ec) {
    auto detachedPromise = std::move(getTransactionCompleted);
    detachedPromise.set_value(ec);
  });
  std::error_code ec = getTransactionWaitFuture.get();
  if (ec) {
    m_logger(ERROR) << "Failed to get tx: " << ec << ", " << ec.message();
    return CryptoNote::NULL_SECRET_KEY;
  }

  Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(tx.extra);
  KeyPair deterministicTxKeys;
  bool ok = generateDeterministicTransactionKeys(tx, m_viewSecretKey, deterministicTxKeys)
    && deterministicTxKeys.publicKey == txPubKey;

  return ok ? deterministicTxKeys.secretKey : CryptoNote::NULL_SECRET_KEY;
}

Crypto::SecretKey WalletGreen::getTransactionSecretKey(size_t transactionIndex) const {
  throwIfNotInitialized();
  throwIfStopped();

  if (m_transactions.size() <= transactionIndex) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get transaction: invalid index " << transactionIndex << ". Number of transactions: " << m_transactions.size();
    throw std::system_error(make_error_code(CryptoNote::error::INDEX_OUT_OF_RANGE));
  }

  Crypto::SecretKey txKey = m_transactions.get<RandomAccessIndex>()[transactionIndex].secretKey.get_value_or(CryptoNote::NULL_SECRET_KEY);
  if (txKey == CryptoNote::NULL_SECRET_KEY) {
    Crypto::Hash transactionHash = m_transactions.get<RandomAccessIndex>()[transactionIndex].hash;
    txKey = getTransactionDeterministicSecretKey(transactionHash);
  }

  return txKey;
}

Crypto::SecretKey WalletGreen::getTransactionSecretKey(Crypto::Hash& transactionHash) const {
  throwIfNotInitialized();
  throwIfStopped();

  auto txInfo = getTransaction(transactionHash);
  Crypto::SecretKey txKey = txInfo.transaction.secretKey.get_value_or(CryptoNote::NULL_SECRET_KEY);

  if (txKey == CryptoNote::NULL_SECRET_KEY) {
    txKey = getTransactionDeterministicSecretKey(transactionHash);
  }

  return txKey;
}

bool WalletGreen::getTransactionProof(const Crypto::Hash& transactionHash, const CryptoNote::AccountPublicAddress& destinationAddress, const Crypto::SecretKey& txKey, std::string& transactionProof) {
  return CryptoNote::getTransactionProof(transactionHash, destinationAddress, txKey, transactionProof, m_logger.getLogger());
}

std::string WalletGreen::signMessage(const std::string &message, const std::string& address) {
  throwIfNotInitialized();
  throwIfTrackingMode();
  throwIfStopped();

  // Discrete signs with the wallet's post-quantum (ML-DSA) spend key — the PQ
  // identity its address publishes — not the (unused) classical ECC key. A PQ
  // wallet has a single primary identity, so `address` (a per-address selector in
  // the classical multi-address model) is not used.
  (void)address;
  Crypto::SecretKey spendSecret = getAddressSpendKey(0).secretKey;
  if (spendSecret == NULL_SECRET_KEY) {
    throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS),
                            "wallet has no spend key to sign with");
  }
  PqWalletKeys keys = derivePqWalletKeys(spendSecret);
  return CryptoNote::signMessagePq(message, keys.spendSk);
}

bool WalletGreen::verifyMessage(const std::string &message, const std::string& address, const std::string &signature) {
  throwIfNotInitialized();
  throwIfStopped();

  try {
    // The signer is identified by its PQ (ML-DSA) spend key. Accept a raw PQ
    // address or an H-I-C / H-I-T-C account number (resolved via the node), the
    // same surface simplewallet and greenwallet accept.
    CryptoPQ::KemPublicKey viewPub;
    CryptoPQ::DsaPublicKey spendPub;
    uint64_t subaddrT = 0;
    if (!CryptoNote::resolvePqRecipient(m_node, address, viewPub, spendPub, subaddrT)) {
      m_logger(ERROR, BRIGHT_RED) << "Failed to verify message: not an address / account number: " << address;
      return false;
    }
    return CryptoNote::verifyMessagePq(message, spendPub, signature);
  }
  catch (const std::exception& e) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to verify message: " << e.what();
  }

  return false;
}

void WalletGreen::start() {
  m_logger(INFO, BRIGHT_WHITE) << "Starting container";
  m_stopped = false;
}

void WalletGreen::stop() {
  m_logger(INFO, BRIGHT_WHITE) << "Stopping container";
  m_stopped = true;
  m_eventOccurred.set();
}

WalletEvent WalletGreen::getEvent() {
  throwIfNotInitialized();
  throwIfStopped();

  while (m_events.empty()) {
    m_eventOccurred.wait();
    m_eventOccurred.clear();
    throwIfStopped();
  }

  WalletEvent event = std::move(m_events.front());
  m_events.pop();

  return event;
}

void WalletGreen::throwIfNotInitialized() const {
  if (m_state != WalletState::INITIALIZED) {
    m_logger(ERROR, BRIGHT_RED) << "WalletGreen is not initialized. Current state: " << m_state;
    throw std::system_error(make_error_code(CryptoNote::error::NOT_INITIALIZED));
  }
}

void WalletGreen::synchronizationProgressUpdated(uint32_t processedBlockCount, uint32_t totalBlockCount) {
  m_dispatcher.remoteSpawn([processedBlockCount, totalBlockCount, this]() { onSynchronizationProgressUpdated(processedBlockCount, totalBlockCount); });
}

void WalletGreen::synchronizationCompleted(std::error_code result) {
  m_dispatcher.remoteSpawn([this]() { onSynchronizationCompleted(); });
}

void WalletGreen::onSynchronizationProgressUpdated(uint32_t processedBlockCount, uint32_t totalBlockCount) {
  assert(processedBlockCount > 0);

  System::EventLock lk(m_readyEvent);

  m_logger(TRACE) << "onSynchronizationProgressUpdated processedBlockCount " << processedBlockCount << ", totalBlockCount " << totalBlockCount;

  if (m_state == WalletState::NOT_INITIALIZED) {
    return;
  }

  pushEvent(makeSyncProgressUpdatedEvent(processedBlockCount, totalBlockCount));
}

void WalletGreen::onSynchronizationCompleted() {
  System::EventLock lk(m_readyEvent);

  m_logger(TRACE) << "onSynchronizationCompleted";

  if (m_state == WalletState::NOT_INITIALIZED) {
    return;
  }

  pushEvent(makeSyncCompletedEvent());
}

void WalletGreen::blocksAdded(const std::vector<Crypto::Hash>& blockHashes) {
  System::EventLock lk(m_readyEvent);

  if (m_state == WalletState::NOT_INITIALIZED) {
    return;
  }

  m_blockchain.insert(m_blockchain.end(), blockHashes.begin(), blockHashes.end());
}

void WalletGreen::blocksRollback(uint32_t blockIndex) {
  System::EventLock lk(m_readyEvent);

  m_logger(TRACE) << "blocksRollback " << blockIndex;

  if (m_state == WalletState::NOT_INITIALIZED) {
    return;
  }

  auto& blockHeightIndex = m_blockchain.get<BlockHeightIndex>();
  blockHeightIndex.erase(std::next(blockHeightIndex.begin(), blockIndex), blockHeightIndex.end());
}

// IBlockchainConsumerObserver: block list + reorgs straight from the PQ consumer.
void WalletGreen::onBlocksAdded(IBlockchainConsumer* /*consumer*/, const std::vector<Crypto::Hash>& blockHashes) {
  m_dispatcher.remoteSpawn([this, blockHashes] () { blocksAdded(blockHashes); } );
}

void WalletGreen::onBlockchainDetach(IBlockchainConsumer* /*consumer*/, uint32_t blockIndex) {
  m_dispatcher.remoteSpawn([this, blockIndex] () { blocksRollback(blockIndex); } );
}

void WalletGreen::pushEvent(const WalletEvent& event) {
  m_events.push(event);
  m_eventOccurred.set();
}

size_t WalletGreen::getTransactionId(const Hash& transactionHash) const {
  auto it = m_transactions.get<TransactionIndex>().find(transactionHash);

  if (it == m_transactions.get<TransactionIndex>().end()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get transaction ID: hash not found. Transaction hash " << transactionHash;
    throw std::system_error(make_error_code(std::errc::invalid_argument));
  }

  auto rndIt = m_transactions.project<RandomAccessIndex>(it);
  auto txId = std::distance(m_transactions.get<RandomAccessIndex>().begin(), rndIt);

  return txId;
}

void WalletGreen::initPqConsumer(const Crypto::SecretKey& spendSecretKey,
                                 const SynchronizationStart& syncStart) {
  if (m_pqConsumer) {
    return;  // already created
  }
  if (spendSecretKey == NULL_SECRET_KEY) {
    if (m_pqTrackingKeys) {
      initPqConsumer(*m_pqTrackingKeys, syncStart);
    }
    return;
  }
  PqWalletKeys pqKeys = derivePqWalletKeys(spendSecretKey);
  m_pqConsumer.reset(new WalletLedgerConsumer(pqKeys, syncStart, m_logger.getLogger()));
  m_blockchainSynchronizer.addConsumer(m_pqConsumer.get());
  m_pqConsumer->addObserver(this);  // m_blockchain (block list) is fed from here
  syncPqDepositConfigToState();
}

void WalletGreen::initPqConsumer(const PqTrackingKeys& pqTrackingKeys,
                                 const SynchronizationStart& syncStart) {
  if (m_pqConsumer) {
    return;
  }
  m_pqConsumer.reset(new WalletLedgerConsumer(pqTrackingKeys, syncStart, m_logger.getLogger()));
  m_blockchainSynchronizer.addConsumer(m_pqConsumer.get());
  m_pqConsumer->addObserver(this);  // m_blockchain (block list) is fed from here
  syncPqDepositConfigToState();
}

void WalletGreen::initPqConsumerForPrimary() {
  if (m_pqConsumer || m_walletsContainer.get<RandomAccessIndex>().empty()) {
    return;
  }

  const auto& primary = m_walletsContainer.get<RandomAccessIndex>().front();
  SynchronizationStart syncStart;
  syncStart.height = 0;
  syncStart.timestamp = std::max(static_cast<uint64_t>(primary.creationTimestamp),
                                 ACCOUNT_CREATE_TIME_ACCURACY) - ACCOUNT_CREATE_TIME_ACCURACY;
  initPqConsumer(primary.spendSecretKey, syncStart);
}

void WalletGreen::syncPqDepositConfigToState() {
  if (m_pqConsumer) {
    m_pqConsumer->state().setDepositConfig(m_pqDepositScheme, m_pqDepositCount);
  }
}

void WalletGreen::buildPqStateBlob() {
  m_pqState.clear();
  if (!m_pqConsumer && !m_pqTrackingKeys) {
    return;
  }
  std::string consumerBlob;
  if (m_pqConsumer) {
    if (auto* consumerState = m_blockchainSynchronizer.getConsumerState(m_pqConsumer.get())) {
      std::stringstream consumerStream;
      consumerState->save(consumerStream);
      consumerBlob = consumerStream.str();
    }
  }

  std::stringstream stateStream;
  if (m_pqConsumer) {
    m_pqConsumer->state().save(stateStream);
  }
  std::string stateBlob = stateStream.str();

  // Frame: [u64 len || bytes] x4 (consumer sync cursor, WalletLedger, deposit
  // metadata, PQ tracking credential). The third and fourth sections are
  // append-only, so older blobs still load with defaults.
  std::stringstream out;
  auto writeSection = [&out](const std::string& s) {
    uint64_t len = s.size();
    out.write(reinterpret_cast<const char*>(&len), sizeof(len));
    if (len) out.write(s.data(), static_cast<std::streamsize>(s.size()));
  };
  writeSection(consumerBlob);
  writeSection(stateBlob);

  // Deposit metadata: [u8 scheme][LE32 depositCount].
  std::string depositBlob;
  depositBlob.push_back(static_cast<char>(static_cast<uint8_t>(m_pqDepositScheme)));
  for (int i = 0; i < 4; ++i) {
    depositBlob.push_back(static_cast<char>((m_pqDepositCount >> (8 * i)) & 0xFF));
  }
  writeSection(depositBlob);
  writeSection(m_pqTrackingKeys ? encodePqTrackingKey(*m_pqTrackingKeys) : std::string());

  m_pqState = out.str();
}

void WalletGreen::restorePqStateBlob() {
  if (m_pqState.empty()) {
    initPqConsumerForPrimary();
    return;
  }
  std::stringstream in(m_pqState);
  auto readSection = [&in](std::string& s) -> bool {
    uint64_t len = 0;
    in.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (!in) return false;
    s.resize(len);
    if (len) in.read(&s[0], static_cast<std::streamsize>(len));
    return static_cast<bool>(in);
  };
  std::string consumerBlob, stateBlob, depositBlob, trackingBlob;
  try {
    if (!readSection(consumerBlob)) {
      initPqConsumerForPrimary();
      return;
    }
    readSection(stateBlob);
    readSection(depositBlob);
    if (readSection(trackingBlob) && !trackingBlob.empty()) {
      PqTrackingKeys trackingKeys;
      if (decodePqTrackingKey(trackingBlob, trackingKeys)) {
        m_pqTrackingKeys.reset(new PqTrackingKeys(trackingKeys));
      }
    }

    initPqConsumerForPrimary();

    if (!m_pqConsumer) {
      return;
    }

    if (!consumerBlob.empty()) {
      std::stringstream cs(consumerBlob);
      m_blockchainSynchronizer.getConsumerState(m_pqConsumer.get())->load(cs);
    }
    if (!stateBlob.empty()) {
      std::stringstream ss(stateBlob);
      m_pqConsumer->state().load(ss);
    }
    // Deposit metadata (third section; absent on pre-deposit containers).
    if (depositBlob.size() >= 5) {
      m_pqDepositScheme = static_cast<PqDepositScheme>(static_cast<uint8_t>(depositBlob[0]));
      uint32_t count = 0;
      for (int i = 0; i < 4; ++i) {
        count |= static_cast<uint32_t>(static_cast<uint8_t>(depositBlob[1 + i])) << (8 * i);
      }
      m_pqDepositCount = count;
      m_pqDepositSchemeChosen = true;  // an existing container's scheme is fixed
    }
  } catch (const std::exception& e) {
    m_logger(WARNING) << "Failed to restore PQ state (" << e.what() << "); will rescan.";
  }
  // The scanner needs the restored scheme + count to attribute deposits.
  syncPqDepositConfigToState();
}

uint64_t WalletGreen::pqActualBalance() const {
  return m_pqConsumer ? m_pqConsumer->state().balance() : 0;
}

std::vector<PqSpendInput> WalletGreen::pqSpendableInputs() const {
  return m_pqConsumer ? m_pqConsumer->state().spendableInputs() : std::vector<PqSpendInput>{};
}

uint32_t WalletGreen::pqSyncedHeight() const {
  return m_pqConsumer ? m_pqConsumer->state().lastScannedHeight() : 0;
}

std::string WalletGreen::getPqAddress() const {
  throwIfNotInitialized();
  throwIfStopped();
  PqTrackingKeys keys;
  if (!getPqTrackingKeys(keys)) {
    return std::string();
  }
  PqAddress addr = pqWalletAddress(keys, CryptoNote::parameters::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
  return encodePqAddress(addr, PqAddressEncoding::Base58);
}

bool WalletGreen::getPqTrackingKeys(PqTrackingKeys& keys) const {
  throwIfNotInitialized();
  throwIfStopped();
  if (m_pqTrackingKeys) {
    keys = *m_pqTrackingKeys;
    return true;
  }
  if (getAddressCount() == 0) {
    return false;
  }
  KeyPair primary = getAddressSpendKey(0);
  if (primary.secretKey == NULL_SECRET_KEY) {
    return false;
  }
  keys = pqTrackingKeys(derivePqWalletKeys(primary.secretKey));
  return true;
}

bool WalletGreen::getPqRegistrationKeysHex(std::string& viewHex, std::string& spendHex) const {
  throwIfNotInitialized();
  throwIfStopped();
  if (getAddressCount() == 0) {
    return false;
  }
  KeyPair primary = getAddressSpendKey(0);
  if (primary.secretKey == NULL_SECRET_KEY) {
    return false;
  }
  PqWalletKeys keys = derivePqWalletKeys(primary.secretKey);
  viewHex = Common::toHex(keys.viewPub.data(), keys.viewPub.size());
  spendHex = Common::toHex(keys.spendPub.data(), keys.spendPub.size());
  return true;
}

PqSendResult WalletGreen::sendPqTransfer(const std::vector<PqSendOutput>& recipients,
                                         uint64_t fee, uint64_t unlockHeight,
                                         const std::vector<uint8_t>& extra) {
  throwIfNotInitialized();
  throwIfStopped();
  if (!pqEnabled()) {
    throw std::runtime_error("Spending is unavailable for this wallet");
  }
  KeyPair primary = getAddressSpendKey(0);
  if (primary.secretKey == NULL_SECRET_KEY) {
    throw std::runtime_error("tracking wallet cannot spend");
  }
  PqWalletKeys keys = derivePqWalletKeys(primary.secretKey);

  PqSendRequest req;
  req.recipients = recipients;
  req.explicitFee = fee;
  req.unlockHeight = unlockHeight;
  req.extra = extra;
  PqSendResult result = buildPqSend(m_pqConsumer->state().spendableInputs(), keys, req);

  std::promise<std::error_code> promise;
  auto future = promise.get_future();
  m_node.relayTransaction(result.tx, [&promise](std::error_code ec) { promise.set_value(ec); });
  std::error_code ec = future.get();
  if (ec) {
    throw std::system_error(ec, "failed to relay transaction");
  }
  return result;
}

size_t WalletGreen::registerSentPqTransaction(const Transaction& tx) {
  if (!m_pqConsumer) {
    return WALLET_INVALID_TRANSACTION_ID;
  }
  auto reader = createTransactionPrefix(tx);
  m_pqConsumer->addUnconfirmedTransaction(*reader);

  Crypto::Hash txid = getObjectHash(tx);
  const auto& hist = m_pqConsumer->state().history();
  for (size_t i = 0; i < hist.size(); ++i) {
    if (hist[i].txid == txid) {
      return i;
    }
  }
  return WALLET_INVALID_TRANSACTION_ID;
}

PqSendResult WalletGreen::registerPqAccountPaid() {
  throwIfNotInitialized();
  throwIfStopped();
  if (!pqEnabled()) {
    throw std::runtime_error("Registration is unavailable for this wallet");
  }
  KeyPair primary = getAddressSpendKey(0);
  if (primary.secretKey == NULL_SECRET_KEY) {
    throw std::runtime_error("tracking wallet cannot register account numbers");
  }
  PqWalletKeys keys = derivePqWalletKeys(primary.secretKey);

  // A paid registration is a fee-paying TX_PQ whose extra holds the registration
  // tag (consensus records it first-reg-wins). Pay the smallest denomination back
  // to ourselves so the transaction has a real output + fee.
  std::vector<uint8_t> extra;
  addPqAccountRegistrationToExtra(extra, keys.viewPub, keys.spendPub);
  PqSendOutput self{keys.viewPub, keys.spendPub, MIN_CT_DENOMINATION, 0 /*T*/, 0 /*unlock*/};
  return sendPqTransfer({self}, 0 /*auto fee*/, 0 /*unlock*/, extra);
}

void WalletGreen::setPqDepositScheme(PqDepositScheme scheme) {
  throwIfNotInitialized();
  throwIfStopped();
  if (m_pqDepositSchemeChosen) {
    throw std::runtime_error("deposit scheme is immutable after container creation");
  }
  m_pqDepositScheme = scheme;
  m_pqDepositSchemeChosen = true;
  syncPqDepositConfigToState();
}

uint32_t WalletGreen::reservePqDepositIndex() {
  throwIfNotInitialized();
  throwIfStopped();
  if (getAddressCount() == 0 || getAddressSpendKey(0).secretKey == NULL_SECRET_KEY) {
    throw std::runtime_error("tracking wallet cannot create deposit addresses");
  }
  if (m_pqDepositCount == std::numeric_limits<uint32_t>::max()) {
    throw std::runtime_error("deposit index space exhausted");
  }
  // The first call chooses the default scheme implicitly if it was never set, so
  // the persisted metadata records the scheme even for default (aggregated) wallets.
  m_pqDepositSchemeChosen = true;
  uint32_t reserved = m_pqDepositCount++;
  syncPqDepositConfigToState();  // the scanner must now watch the new deposit key
  return reserved;
}

std::string WalletGreen::pqDepositAddress(uint32_t index, uint32_t regBlockHeight,
                                          uint32_t regTxIndex) const {
  throwIfNotInitialized();
  throwIfStopped();
  if (getAddressCount() == 0) {
    return std::string();
  }
  KeyPair primary = getAddressSpendKey(0);
  if (primary.secretKey == NULL_SECRET_KEY) {
    return std::string();  // tracking wallet: cannot derive deposit spend keys
  }
  PqWalletKeys base = derivePqWalletKeys(primary.secretKey);

  if (m_pqDepositScheme == PqDepositScheme::SingleKeyIndex) {
    // Spec 2: one keypair; the deposit identity is the H-I-T-C account number.
    return CryptoNote::AccountNumber{regBlockHeight, regTxIndex}.toStringWithIndex(index);
  }

  // Spec 1: shared view key + a per-deposit ML-DSA spend key. The address carries
  // the deposit spend key so each deposit has its own spend authority.
  auto depositSpend = CryptoPQ::deriveDepositSpendKeys(base.seedMaster, index);
  PqAddress addr = makePqAddress(CryptoNote::parameters::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
                                 base.viewPub, depositSpend.first);
  return encodePqAddress(addr, PqAddressEncoding::Base58);
}

uint64_t WalletGreen::pqDepositBalance(uint32_t index) const {
  return m_pqConsumer ? m_pqConsumer->state().depositBalance(index) : 0;
}

std::map<uint32_t, uint64_t> WalletGreen::pqDepositBalances() const {
  return m_pqConsumer ? m_pqConsumer->state().depositBalances() : std::map<uint32_t, uint64_t>{};
}

Transaction WalletGreen::buildPqFreeRegTransaction(const Crypto::Hash& refBlockHash) const {
  throwIfNotInitialized();
  throwIfStopped();
  if (getAddressCount() == 0) {
    throw std::runtime_error("wallet has no addresses");
  }
  KeyPair primary = getAddressSpendKey(0);
  if (primary.secretKey == NULL_SECRET_KEY) {
    throw std::runtime_error("tracking wallet cannot register account numbers");
  }
  PqWalletKeys keys = derivePqWalletKeys(primary.secretKey);
  // Shared anti-spam PoW grind (same helper simplewallet uses → same target).
  uint64_t nonce = grindFreeRegPow(keys.viewPub, refBlockHash);
  return buildFreeRegTransaction(keys.viewPub, keys.spendPub, refBlockHash, nonce);
}

void WalletGreen::startBlockchainSynchronizer() {
  if (!m_walletsContainer.empty() && !m_blockchainSynchronizerStarted) {
    m_logger(DEBUGGING) << "Starting BlockchainSynchronizer";
    m_blockchainSynchronizer.start();
    m_blockchainSynchronizerStarted = true;
  }
}

void WalletGreen::stopBlockchainSynchronizer() {
  if (m_blockchainSynchronizerStarted) {
    m_logger(DEBUGGING) << "Stopping BlockchainSynchronizer";
    m_blockchainSynchronizer.stop();
    m_blockchainSynchronizerStarted = false;
  }
}

void WalletGreen::addUnconfirmedTransaction(const ITransactionReader& transaction) {
  try {
    auto addUnconfirmedTransactionCompleted = std::promise<std::error_code>();
    auto addUnconfirmedTransactionWaitFuture = addUnconfirmedTransactionCompleted.get_future();

    addUnconfirmedTransactionWaitFuture = m_blockchainSynchronizer.addUnconfirmedTransaction(transaction);

    std::error_code ec = addUnconfirmedTransactionWaitFuture.get();

    if (ec) {
      m_logger(ERROR, BRIGHT_RED) << "Failed to add unconfirmed transaction: " << ec << ", " << ec.message();
      throw std::system_error(ec, "Failed to add unconfirmed transaction");
    }
  } catch (const std::exception& e) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to add unconfirmed transaction: " << e.what();
  }

  m_logger(DEBUGGING) << "Unconfirmed transaction added to BlockchainSynchronizer, hash " << transaction.getTransactionHash();
}

void WalletGreen::removeUnconfirmedTransaction(const Crypto::Hash& transactionHash) {
  System::RemoteContext<void> context(m_dispatcher, [this, &transactionHash] {
    m_blockchainSynchronizer.removeUnconfirmedTransaction(transactionHash).get();
  });

  context.get();
  m_logger(DEBUGGING) << "Unconfirmed transaction removed from BlockchainSynchronizer, hash " << transactionHash;
}

const WalletRecord& WalletGreen::getWalletRecord(const PublicKey& key) const {
  auto it = m_walletsContainer.get<KeysIndex>().find(key);
  if (it == m_walletsContainer.get<KeysIndex>().end()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get wallet: not found. Spend public key " << key;
    throw std::system_error(make_error_code(error::WALLET_NOT_FOUND));
  }

  return *it;
}

const WalletRecord& WalletGreen::getWalletRecord(const std::string& address) const {
  CryptoNote::AccountPublicAddress pubAddr = parseAddress(address);
  return getWalletRecord(pubAddr.spendPublicKey);
}

CryptoNote::AccountPublicAddress WalletGreen::parseAddress(const std::string& address) const {
  CryptoNote::AccountPublicAddress pubAddr;

  if (!m_currency.parseAccountAddressString(address, pubAddr)) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to parse address: " << address;
    throw std::system_error(make_error_code(error::BAD_ADDRESS));
  }

  return pubAddr;
}

void WalletGreen::throwIfStopped() const {
  if (m_stopped) {
    m_logger(DEBUGGING, BRIGHT_RED) << "WalletGreen is already stopped";
    throw std::system_error(make_error_code(error::OPERATION_CANCELLED));
  }
}

void WalletGreen::throwIfTrackingMode() const {
  if (getTrackingMode() == WalletTrackingMode::TRACKING) {
    m_logger(ERROR, BRIGHT_RED) << "WalletGreen is in tracking mode";
    throw std::system_error(make_error_code(error::TRACKING_MODE));
  }
}

WalletGreen::WalletTrackingMode WalletGreen::getTrackingMode() const {
  if (m_walletsContainer.get<RandomAccessIndex>().empty()) {
    return WalletTrackingMode::NO_ADDRESSES;
  }

  return m_walletsContainer.get<RandomAccessIndex>().begin()->spendSecretKey == NULL_SECRET_KEY ?
        WalletTrackingMode::TRACKING : WalletTrackingMode::NOT_TRACKING;
}

std::vector<TransactionsInBlockInfo> WalletGreen::getTransactionsInBlocks(uint32_t blockIndex, size_t count) const {
  if (count == 0) {
    m_logger(ERROR, BRIGHT_RED) << "Bad argument: block count must be greater than zero";
    throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "blocks count must be greater than zero");
  }

  std::vector<TransactionsInBlockInfo> result;

  if (blockIndex >= m_blockchain.size()) {
    return result;
  }

  uint32_t stopIndex = static_cast<uint32_t>(std::min(m_blockchain.size(), blockIndex + count));

  if (pqEnabled()) {
    // PQ-native: group the ledger's confirmed history rows by block height. The
    // wallet's block-hash list (m_blockchain) still tracks the chain, so heights
    // map to hashes the same way. Counterparties aren't recoverable, so each tx
    // carries one net WalletTransfer against the wallet's own address.
    const auto& hist = m_pqConsumer->state().history();
    std::string ownAddress = getPqAddress();
    for (uint32_t height = blockIndex; height < stopIndex; ++height) {
      TransactionsInBlockInfo info;
      info.blockHash = m_blockchain[height];
      for (const auto& row : hist) {
        if (row.height != height) {
          continue;
        }
        WalletTransactionWithTransfers w;
        w.transaction = pqRowToWalletTx(row);
        w.transfers.push_back(WalletTransfer{WalletTransferType::USUAL, ownAddress, row.netAmount});
        info.transactions.push_back(std::move(w));
      }
      result.push_back(std::move(info));
    }
    return result;
  }

  auto& blockHeightIndex = m_transactions.get<BlockHeightIndex>();

  for (uint32_t height = blockIndex; height < stopIndex; ++height) {
    TransactionsInBlockInfo info;
    info.blockHash = m_blockchain[height];

    auto lowerBound = blockHeightIndex.lower_bound(height);
    auto upperBound = blockHeightIndex.upper_bound(height);
    for (auto it = lowerBound; it != upperBound; ++it) {
      if (it->state != WalletTransactionState::SUCCEEDED) {
        continue;
      }

      WalletTransactionWithTransfers transaction;
      transaction.transaction = *it;

      transaction.transfers = getTransactionTransfers(*it);

      info.transactions.emplace_back(std::move(transaction));
    }

    result.emplace_back(std::move(info));
  }

  return result;
}

Crypto::Hash WalletGreen::getBlockHashByIndex(uint32_t blockIndex) const {
  assert(blockIndex < m_blockchain.size());
  return m_blockchain.get<BlockHeightIndex>()[blockIndex];
}

std::vector<WalletTransfer> WalletGreen::getTransactionTransfers(const WalletTransaction& transaction) const {
  auto& transactionIdIndex = m_transactions.get<RandomAccessIndex>();

  auto it = transactionIdIndex.iterator_to(transaction);
  assert(it != transactionIdIndex.end());

  size_t transactionId = std::distance(transactionIdIndex.begin(), it);
  auto bounds = getTransactionTransfersRange(transactionId);

  std::vector<WalletTransfer> result;
  result.reserve(std::distance(bounds.first, bounds.second));

  for (auto it = bounds.first; it != bounds.second; ++it) {
    result.emplace_back(it->second);
  }

  return result;
}

void WalletGreen::filterOutTransactions(WalletTransactions& transactions, WalletTransfers& transfers, std::function<bool (const WalletTransaction&)>&& pred) const {
  size_t cancelledTransactions = 0;

  transactions.reserve(m_transactions.size());
  transfers.reserve(m_transfers.size());

  auto& index = m_transactions.get<RandomAccessIndex>();
  size_t transferIdx = 0;
  for (size_t i = 0; i < m_transactions.size(); ++i) {
    const WalletTransaction& transaction = index[i];

    if (pred(transaction)) {
      ++cancelledTransactions;

      while (transferIdx < m_transfers.size() && m_transfers[transferIdx].first == i) {
        ++transferIdx;
      }
    } else {
      transactions.emplace_back(transaction);

      while (transferIdx < m_transfers.size() && m_transfers[transferIdx].first == i) {
        transfers.emplace_back(i - cancelledTransactions, m_transfers[transferIdx].second);
        ++transferIdx;
      }
    }
  }
}

void WalletGreen::initBlockchain(const Crypto::PublicKey& /*viewPublicKey*/) {
  if (!m_pqConsumer) {
    return;
  }
  // The PQ consumer owns the wallet's sync cursor; its known block hashes seed the
  // local block list. Duplicate hashes (e.g. a genesis already pushed by initWithKeys)
  // are skipped by the container's unique block-hash index.
  std::vector<Crypto::Hash> blockchain = m_blockchainSynchronizer.getConsumerKnownBlocks(*m_pqConsumer);
  m_blockchain.insert(m_blockchain.end(), blockchain.begin(), blockchain.end());
}

bool WalletGreen::isMyAddress(const std::string& addressString) const {
  CryptoNote::AccountPublicAddress address = parseAccountAddressString(addressString);
  return m_viewPublicKey == address.viewPublicKey && m_walletsContainer.get<KeysIndex>().count(address.spendPublicKey) != 0;
}

std::vector<size_t> WalletGreen::deleteTransfersForAddress(const std::string& /*address*/, std::vector<size_t>& /*deletedTransactions*/) {
  // The classical per-address transfer tracking (m_transfers / m_transactions) is no
  // longer populated on a PQ chain, so there is nothing to delete here.
  return {};
}

void WalletGreen::deleteFromUncommitedTransactions(const std::vector<size_t>& deletedTransactions) {
  for (auto transactionId: deletedTransactions) {
    m_uncommitedTransactions.erase(transactionId);
  }
}

/* The blockchain events are sent to us from the blockchain synchronizer,
   but they appear to not get executed on the dispatcher until the synchronizer
   stops. After some investigation, it appears that we need to run this
   archaic line of code to run other code on the dispatcher? */
void WalletGreen::updateInternalCache() {
    System::RemoteContext<void> updateInternalBC(m_dispatcher, [this] () {});
    updateInternalBC.get();
}

size_t WalletGreen::getMaxTxSize()
{
  return m_upperTransactionSizeLimit;
}

bool WalletGreen::txIsTooLarge(const TransactionParameters& sendingTransaction)
{
  return getTxSize(sendingTransaction) > getMaxTxSize();
}

size_t WalletGreen::getTxSize(const TransactionParameters& /*sendingTransaction*/)
{
  // PQ transactions are built and size/count-coarsened internally by buildPqSend,
  // so the front-end never needs to pre-split by size: report 0 (never "too large").
  return 0;
}

void WalletGreen::clearCacheAndShutdown()
{
  stopBlockchainSynchronizer();
  m_blockchainSynchronizer.removeObserver(this);

  clearCaches(true, true);

  m_walletsContainer.clear();

  shutdown();
}

void WalletGreen::createViewWallet(const std::string &password,
                                   const std::string address,
                                   const Crypto::SecretKey &viewSecretKey,
                                   const std::string &path)
{
    CryptoNote::AccountPublicAddress publicKeys;
    uint64_t prefix;

    std::string data;

    if (!(Tools::Base58::decode_addr(address, prefix, data) &&
          fromBinaryArray(publicKeys, asBinaryArray(data)) &&
          // ::serialization::parse_binary(data, adr) &&
          check_key(publicKeys.spendPublicKey) &&
          check_key(publicKeys.viewPublicKey)))
    {
        throw std::runtime_error("Failed to parse address!");
    }

    initializeWithViewKey(path, password, viewSecretKey);
    createAddress(publicKeys.spendPublicKey);
}

} //namespace CryptoNote
