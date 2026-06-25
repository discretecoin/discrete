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
  // PQ-native: a fresh container has no addresses yet; the caller mints the primary
  // master seed (record 0) via createAddress().
  initContainer(path, password);
  m_logger(INFO, BRIGHT_WHITE) << "New container initialized";
}

void WalletGreen::initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& /*viewSecretKey*/) {
  // PQ has no classical view key; the argument is ignored. The wallet's audit
  // capability is the PQ tracking key (see initializeWithPqTrackingKey).
  initContainer(path, password);
  m_logger(INFO, BRIGHT_WHITE) << "Container initialized";
}

void WalletGreen::initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& /*viewSecretKey*/, const uint64_t& /*creationTimestamp*/) {
  initContainer(path, password);
  m_logger(INFO, BRIGHT_WHITE) << "Container initialized";
}

void WalletGreen::initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& /*viewSecretKey*/, const uint32_t /*scanHeight*/) {
  initContainer(path, password);
  m_logger(INFO, BRIGHT_WHITE) << "Container initialized";
}

void WalletGreen::initializeWithPqTrackingKey(const std::string& path, const std::string& password,
                                              const PqTrackingKeys& pqTrackingKeys) {
  initializeWithPqTrackingKey(path, password, pqTrackingKeys, static_cast<uint64_t>(time(nullptr)));
}

void WalletGreen::initializeWithPqTrackingKey(const std::string& path, const std::string& password,
                                              const PqTrackingKeys& pqTrackingKeys,
                                              const uint64_t& creationTimestamp) {
  initContainer(path, password);
  m_pqTrackingKeys.reset(new PqTrackingKeys(pqTrackingKeys));

  // Audit-only record 0: an all-zero master seed marks the wallet as tracking; the
  // scanning consumer is built from the imported PQ tracking credential.
  doCreateAddress(CryptoPQ::SeedMaster{}, true, creationTimestamp);

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

void WalletGreen::clearCaches(bool /*clearTransactions*/, bool clearCachedData) {
  if (clearCachedData) {
    // Drop the PQ ledger + block list so the next sync rescans from scratch. The
    // consumer is recreated by initPqConsumerForPrimary() on the following load.
    if (m_pqConsumer) {
      m_blockchainSynchronizer.removeConsumer(m_pqConsumer.get());
      m_pqConsumer.reset();
    }

    m_blockchain.clear();
    m_pqNotifiedTxCount = 0;
  }
}

bool WalletGreen::decryptSeed(const EncryptedWalletRecord& cipher, CryptoPQ::SeedMaster& seedMaster,
  uint64_t& creationTimestamp, const Crypto::chacha8_key& key) {
  return decryptSeedRecord(cipher, seedMaster, creationTimestamp, key);
}

bool WalletGreen::decryptSeed(const EncryptedWalletRecord& cipher, CryptoPQ::SeedMaster& seedMaster, uint64_t& creationTimestamp) const {
  return decryptSeedRecord(cipher, seedMaster, creationTimestamp, m_key);
}

EncryptedWalletRecord WalletGreen::encryptSeed(const CryptoPQ::SeedMaster& seedMaster, uint64_t creationTimestamp,
  const Crypto::chacha8_key& key, const Crypto::chacha8_iv& iv) {
  return encryptSeedRecord(seedMaster, creationTimestamp, key, iv);
}

EncryptedWalletRecord WalletGreen::encryptSeed(const CryptoPQ::SeedMaster& seedMaster, uint64_t creationTimestamp) const {
  return encryptSeed(seedMaster, creationTimestamp, m_key, getNextIv());
}

CryptoPQ::SeedMaster WalletGreen::primarySeedMaster() const {
  const auto& index = m_walletsContainer.get<RandomAccessIndex>();
  if (index.empty()) {
    throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "wallet has no addresses");
  }
  return index.front().seedMaster;
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

void WalletGreen::initContainer(const std::string& path, const std::string& password) {
  if (m_state != WalletState::NOT_INITIALIZED) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to initialize: already initialized. Current state: " << m_state;
    throw std::system_error(make_error_code(CryptoNote::error::ALREADY_INITIALIZED));
  }

  throwIfStopped();

  ContainerStorage newStorage(path, Common::FileMappedVectorOpenMode::CREATE, sizeof(ContainerStoragePrefix));
  ContainerStoragePrefix* prefix = reinterpret_cast<ContainerStoragePrefix*>(newStorage.prefix());
  prefix->version = static_cast<uint8_t>(WalletSerializerV2::SERIALIZATION_VERSION);
  prefix->nextIv = Crypto::randomChachaIV();

  Crypto::cn_context cnContext;
  Crypto::generate_chacha8_key(cnContext, password, m_key);

  newStorage.flush();
  m_containerStorage.swap(newStorage);

  m_password = password;
  m_path = path;

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

    if (m_containerStorage.suffixSize() > 0) {
      try {
        std::unordered_set<Crypto::PublicKey> addedSpendKeys;
        std::unordered_set<Crypto::PublicKey> deletedSpendKeys;
        loadWalletCache(addedSpendKeys, deletedSpendKeys, extra);

        if (!addedSpendKeys.empty()) {
          m_logger(WARNING, BRIGHT_YELLOW) << "Found addresses not saved in container cache. Resynchronize container";
          clearCaches(false, true);
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
      }
    }
  }

  initPqConsumerForPrimary();

  m_blockchainSynchronizer.addObserver(this);

  assert(m_blockchain.empty());
  if (m_walletsContainer.get<RandomAccessIndex>().size() != 0) {
    initBlockchain();

    startBlockchainSynchronizer();
  } else {
    m_blockchain.push_back(m_currency.genesisBlockHash());
    m_logger(DEBUGGING) << "Add genesis block hash to blockchain";
  }

  m_password = password;
  m_path = path;
  m_extra = extra;

  m_state = WalletState::INITIALIZED;
  m_logger(INFO, BRIGHT_WHITE) << "Container loaded, wallet count " << m_walletsContainer.size() <<
    ", balance " << m_currency.formatAmount(getActualBalance());
}

void WalletGreen::load(const std::string& path, const std::string& password) {
  std::string extra;
  load(path, password, extra);
}

void WalletGreen::loadContainerStorage(const std::string& path) {
  try {
    m_containerStorage.open(path, FileMappedVectorOpenMode::OPEN, sizeof(ContainerStoragePrefix));

    ContainerStoragePrefix* prefix = reinterpret_cast<ContainerStoragePrefix*>(m_containerStorage.prefix());
    if (prefix->version < WalletSerializerV2::MIN_VERSION) {
      throw std::system_error(make_error_code(error::WRONG_VERSION), "Unsupported wallet version");
    }

    // The password is verified inside loadSpendKeys via the record-0 seed magic.
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
    m_addressGenerationMode,
    m_deterministicSeed,
    m_nextDeterministicIndex,
    m_walletsContainer,
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

  // Capture the current PQ consumer cursor + owned outputs so they persist.
  buildPqStateBlob();

  std::string containerData;
  Common::StringOutputStream containerStream(containerData);

  WalletSerializerV2 s(
    m_addressGenerationMode,
    m_deterministicSeed,
    m_nextDeterministicIndex,
    m_walletsContainer,
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

  for (auto& encryptedSeed : src) {
    CryptoPQ::SeedMaster seed{};
    uint64_t creationTimestamp = 0;
    if (!decryptSeed(encryptedSeed, seed, creationTimestamp, srcKey)) {
      throw std::system_error(make_error_code(error::WRONG_PASSWORD), "Wrong password");
    }

    // push_back() can resize container, and dstPrefix address can be changed, so it is requested for each record
    ContainerStoragePrefix* dstPrefix = reinterpret_cast<ContainerStoragePrefix*>(dst.prefix());
    Crypto::chacha8_iv recordIv = dstPrefix->nextIv;
    incIv(dstPrefix->nextIv);

    dst.push_back(encryptSeed(seed, creationTimestamp, dstKey, recordIv));
  }
}

void WalletGreen::copyContainerStoragePrefix(ContainerStorage& src, const chacha8_key& /*srcKey*/, ContainerStorage& dst, const chacha8_key& /*dstKey*/) {
  // The prefix holds no key material on a PQ container (just version + IV); the
  // master seed lives in the body records, copied by copyContainerStorageKeys.
  ContainerStoragePrefix* srcPrefix = reinterpret_cast<ContainerStoragePrefix*>(src.prefix());
  ContainerStoragePrefix* dstPrefix = reinterpret_cast<ContainerStoragePrefix*>(dst.prefix());
  dstPrefix->version = srcPrefix->version;
  dstPrefix->nextIv = Crypto::randomChachaIV();
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

void WalletGreen::deleteOrphanTransactions(const std::unordered_set<Crypto::PublicKey>& /*deletedKeys*/) {
  // No classical per-address transaction/transfer state exists on a PQ chain, so
  // there are no orphaned transactions to prune when a key is removed.
}

void WalletGreen::loadSpendKeys() {
  bool isTrackingMode = false;
  for (size_t i = 0; i < m_containerStorage.size(); ++i) {
    WalletRecord wallet;
    uint64_t creationTimestamp = 0;
    CryptoPQ::SeedMaster seed{};
    if (!decryptSeed(m_containerStorage[i], seed, creationTimestamp)) {
      throw std::system_error(make_error_code(error::WRONG_PASSWORD), "Wrong password");
    }
    wallet.seedMaster = seed;
    wallet.tracking = (seed == CryptoPQ::SeedMaster{});  // all-zero seed = audit-only
    wallet.creationTimestamp = static_cast<time_t>(creationTimestamp);

    if (i == 0) {
      isTrackingMode = wallet.tracking;
    } else if (wallet.tracking != isTrackingMode) {
      throw std::system_error(make_error_code(error::BAD_ADDRESS), "All addresses must be whether tracking or not");
    }

    wallet.actualBalance = 0;
    wallet.pendingBalance = 0;

    m_walletsContainer.emplace_back(std::move(wallet));
  }
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

  // PQ-native address space: the primary address plus every issued deposit. A
  // container with no PQ identity yet (no consumer) exposes no addresses.
  if (!m_pqConsumer) {
    return 0;
  }
  return static_cast<size_t>(1) + m_pqDepositCount;
}

AccountPublicAddress WalletGreen::getAccountPublicAddress(size_t index) const {
  throwIfNotInitialized();
  throwIfStopped();

  if (index >= m_walletsContainer.get<RandomAccessIndex>().size()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get address: invalid address index " << index;
    throw std::system_error(make_error_code(std::errc::invalid_argument));
  }

  // PQ wallets have no classical account address; callers use getAddress()/getPqAddress().
  (void)m_walletsContainer.get<RandomAccessIndex>()[index];
  return AccountPublicAddress{};
}

std::string WalletGreen::getAddress(size_t index) const {
  // PQ-native: index 0 is the wallet's own PQ address; index i>0 is deposit i-1.
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

KeyPair WalletGreen::getAddressSpendKey(size_t index) const {
  throwIfNotInitialized();
  throwIfStopped();

  if (index >= m_walletsContainer.get<RandomAccessIndex>().size()) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get address spend key: invalid address index " << index;
    throw std::system_error(make_error_code(std::errc::invalid_argument));
  }

  const WalletRecord& wallet = m_walletsContainer.get<RandomAccessIndex>()[index];
  // The exportable secret is the PQ master seed; the "public key" is a non-secret
  // identifier (a hash of the seed), not a classical key.
  KeyPair kp{};
  std::memcpy(kp.secretKey.data, wallet.seedMaster.data(), sizeof(kp.secretKey.data));
  Crypto::cn_fast_hash(wallet.seedMaster.data(), wallet.seedMaster.size(),
                       reinterpret_cast<Crypto::Hash&>(kp.publicKey));
  return kp;
}

KeyPair WalletGreen::getAddressSpendKey(const std::string& address) const {
  throwIfNotInitialized();
  throwIfStopped();

  // PQ addresses are not classical CryptoNote addresses. The wallet's PQ identity
  // and every deposit subaddress derive from the single classical spend key at
  // index 0, so map any of our own PQ addresses back to it.
  uint32_t bucket = 0;
  if (pqResolveAddressBucket(address, bucket)) {
    return getAddressSpendKey(0);
  }

  m_logger(ERROR, BRIGHT_RED) << "Failed to get address spend key: address not found " << address;
  throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND));
}

KeyPair WalletGreen::getViewKey() const {
  throwIfNotInitialized();
  throwIfStopped();

  // PQ wallets have no classical view key; the audit credential is the PQ tracking
  // key (getPqTrackingKeys / encodePqTrackingKey).
  return KeyPair{};
}

AddressGenerationMode WalletGreen::getAddressGenerationMode() const {
  throwIfNotInitialized();
  throwIfStopped();

  return m_addressGenerationMode;
}

Crypto::SecretKey WalletGreen::getDeterministicSeed() const {
  throwIfNotInitialized();
  throwIfStopped();

  // The wallet's PQ master seed (record 0) IS the deterministic backup seed; the
  // same 32 bytes recover the entire PQ identity (and back the mnemonic).
  CryptoPQ::SeedMaster seed = primarySeedMaster();
  Crypto::SecretKey out;
  std::memcpy(out.data, seed.data(), sizeof(out.data));
  return out;
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

    // The 32 seed bytes become the PQ master seed for the primary address (record 0).
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

CryptoPQ::SeedMaster WalletGreen::createHdAddressData(uint64_t creationTimestamp) {
  (void)creationTimestamp;
  // The PQ wallet is single-identity: the "HD" master seed (set via
  // setAddressGenerationMode) is the primary seed; additional addresses are derived
  // deposits, not independent HD keys. Bootstrap from the deterministic seed bytes
  // if present, otherwise mint a fresh CSPRNG seed.
  if (m_deterministicSeed != NULL_SECRET_KEY) {
    CryptoPQ::SeedMaster seed{};
    std::memcpy(seed.data(), m_deterministicSeed.data, seed.size());
    return seed;
  }
  return generatePqSeedMaster();
}

std::string WalletGreen::createAddress() {
  // The first address bootstraps the wallet's primary spend secret (the seed the
  // PQ identity derives from); once that exists (the PQ consumer is live) every
  // further "create address" mints a PQ deposit (a fresh ML-DSA spend key under
  // AggregatedMultikey, or the next subaddress index T under SingleKeyIndex).
  if (m_pqConsumer) {
    uint32_t depositIndex = reservePqDepositIndex();
    return getAddress(static_cast<size_t>(depositIndex) + 1);
  }

  uint64_t creationTimestamp = static_cast<uint64_t>(time(nullptr));
  return doCreateAddress(createHdAddressData(creationTimestamp), false, creationTimestamp);
}

std::string WalletGreen::createAddress(uint32_t scanHeight) {
  // See createAddress(): bootstrap the primary, or mint a deposit once it exists.
  if (m_pqConsumer) {
    uint32_t depositIndex = reservePqDepositIndex();
    return getAddress(static_cast<size_t>(depositIndex) + 1);
  }
  const uint64_t creationTimestamp = scanHeightToTimestamp(scanHeight);
  return doCreateAddress(createHdAddressData(creationTimestamp), false, creationTimestamp);
}

namespace {
// Treat 32 imported secret bytes as a PQ master seed (used by the from-key /
// from-mnemonic restore paths).
CryptoPQ::SeedMaster seedFromSecret(const Crypto::SecretKey& secret) {
  CryptoPQ::SeedMaster seed{};
  std::memcpy(seed.data(), secret.data, seed.size());
  return seed;
}
[[noreturn]] void throwClassicalImportUnsupported() {
  throw std::system_error(make_error_code(std::errc::function_not_supported),
    "Importing a classical public spend key is not supported on the post-quantum wallet");
}
}  // namespace

std::string WalletGreen::createAddress(const Crypto::SecretKey& spendSecretKey, bool reset) {
  uint64_t creationTimestamp = reset ? 0 : static_cast<uint64_t>(time(nullptr));
  return doCreateAddress(seedFromSecret(spendSecretKey), false, creationTimestamp);
}

std::string WalletGreen::createAddress(const Crypto::SecretKey& spendSecretKey, const uint64_t& creationTimestamp) {
  return doCreateAddress(seedFromSecret(spendSecretKey), false, creationTimestamp);
}

std::string WalletGreen::createAddress(const Crypto::PublicKey&, bool) {
  throwClassicalImportUnsupported();
}

std::string WalletGreen::createAddress(const Crypto::PublicKey&, const uint64_t&) {
  throwClassicalImportUnsupported();
}

std::string WalletGreen::createAddress(const Crypto::SecretKey& spendSecretKey, const uint32_t scanHeight) {
  return doCreateAddress(seedFromSecret(spendSecretKey), false, scanHeightToTimestamp(scanHeight));
}

std::string WalletGreen::createAddress(const Crypto::PublicKey&, const uint32_t) {
  throwClassicalImportUnsupported();
}

std::string WalletGreen::doCreateAddress(const CryptoPQ::SeedMaster& seedMaster, bool tracking, uint64_t creationTimestamp, uint32_t hdIndex) {
  assert(creationTimestamp <= std::numeric_limits<uint64_t>::max() - m_currency.blockFutureTimeLimit());

  std::vector<NewAddressData> addressDataList;
  addressDataList.push_back(NewAddressData{ seedMaster, tracking, creationTimestamp, hdIndex });
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
        std::string address = addWallet(addressData.seedMaster, addressData.tracking, addressData.creationTimestamp, addressData.hdIndex);
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

std::string WalletGreen::addWallet(const CryptoPQ::SeedMaster& seedMaster, bool tracking, uint64_t creationTimestamp, uint32_t hdIndex) {
  auto& index = m_walletsContainer.get<RandomAccessIndex>();

  // Persist the encrypted seed record, then register the in-memory record.
  m_containerStorage.push_back(encryptSeed(seedMaster, creationTimestamp));
  incNextIv();

  try {
    WalletRecord wallet;
    wallet.seedMaster = seedMaster;
    wallet.tracking = tracking;
    wallet.creationTimestamp = static_cast<time_t>(creationTimestamp);
    wallet.hdIndex = hdIndex;

    index.push_back(std::move(wallet));
    m_logger(DEBUGGING) << "Wallet count " << m_walletsContainer.size();

    if (index.size() == 1) {
      // The PQ identity derives from the primary record's master seed. Create the
      // consumer first so the block list (m_blockchain) can be seeded from it.
      SynchronizationStart syncStart;
      syncStart.height = 0;
      syncStart.timestamp = std::max(creationTimestamp, ACCOUNT_CREATE_TIME_ACCURACY) - ACCOUNT_CREATE_TIME_ACCURACY;
      initPqConsumer(seedMaster, syncStart);
      initBlockchain();
    }

    std::string address = getPqAddress();
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

    uint64_t newTimestamp = scanHeightToTimestamp((uint32_t) scanHeight);

    /* Re-encrypt every seed record with the new creation timestamp so we rescan from
       here when we relaunch (the PQ container has no classical view key in the prefix). */
    for (auto& encryptedSeed : m_containerStorage)
    {
        CryptoPQ::SeedMaster seed{};
        uint64_t oldTimestamp = 0;
        if (decryptSeed(encryptedSeed, seed, oldTimestamp))
        {
            encryptedSeed = encryptSeed(seed, newTimestamp);
        }
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

  // PQ addresses (the primary identity and every deposit subaddress) are derived
  // from the wallet's single spend secret, not independent records that can be
  // individually removed. There is nothing to delete.
  (void)address;
  m_logger(ERROR, BRIGHT_RED) << "deleteAddress is not supported on a post-quantum wallet";
  throw std::system_error(make_error_code(std::errc::function_not_supported),
                          "Deleting addresses is not supported on the post-quantum wallet");
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

bool WalletGreen::pqResolveAddressBucket(const std::string& address, uint32_t& depositIndex) const {
  if (!m_pqConsumer) {
    return false;
  }
  if (address == getPqAddress()) {
    depositIndex = PQ_PRIMARY_DEPOSIT;
    return true;
  }
  for (uint32_t i = 0; i < m_pqDepositCount; ++i) {
    if (address == getAddress(static_cast<size_t>(i) + 1)) {
      depositIndex = i;
      return true;
    }
  }
  return false;
}

std::vector<WalletTransfer> WalletGreen::pqTransfersForTx(const Crypto::Hash& txid, int64_t fallbackNet) const {
  std::vector<WalletTransfer> transfers;
  if (m_pqConsumer) {
    // One transfer per OUR address the tx touched (primary + any deposits). External
    // counterparties aren't recoverable from owned-output scanning, by PQ design.
    for (const auto& kv : m_pqConsumer->state().transfersByDeposit(txid)) {
      std::string address = kv.first == PQ_PRIMARY_DEPOSIT
                                ? getPqAddress()
                                : getAddress(static_cast<size_t>(kv.first) + 1);
      transfers.push_back(WalletTransfer{WalletTransferType::USUAL, std::move(address), kv.second});
    }
  }
  if (transfers.empty()) {
    transfers.push_back(WalletTransfer{WalletTransferType::USUAL, getPqAddress(), fallbackNet});
  }
  return transfers;
}

uint64_t WalletGreen::getActualBalance() const {
  throwIfNotInitialized();
  throwIfStopped();

  // PQ is the native ledger. "Actual" = confirmed (total minus still-in-mempool).
  if (!m_pqConsumer) {
    return 0;
  }
  const auto& st = m_pqConsumer->state();
  uint64_t total = st.balance();
  uint64_t pending = st.pendingBalance();
  return total >= pending ? total - pending : 0;
}

uint64_t WalletGreen::getActualBalance(const std::string& address) const {
  throwIfNotInitialized();
  throwIfStopped();

  // Map a PQ address to its bucket; "actual" = that bucket's confirmed balance
  // (total minus its still-in-mempool pending). Unknown address -> 0.
  uint32_t bucket = 0;
  if (!pqResolveAddressBucket(address, bucket)) {
    return 0;
  }
  const auto& st = m_pqConsumer->state();
  uint64_t total = st.depositBalance(bucket);
  uint64_t pending = st.depositPendingBalance(bucket);
  return total >= pending ? total - pending : 0;
}

uint64_t WalletGreen::getPendingBalance() const {
  throwIfNotInitialized();
  throwIfStopped();

  return m_pqConsumer ? m_pqConsumer->state().pendingBalance() : 0;
}

uint64_t WalletGreen::getPendingBalance(const std::string& address) const {
  throwIfNotInitialized();
  throwIfStopped();

  // Per-bucket pending: the unspent, still-in-mempool balance attributed to this
  // address (primary or a deposit). Unknown address -> 0.
  uint32_t bucket = 0;
  if (!pqResolveAddressBucket(address, bucket)) {
    return 0;
  }
  return m_pqConsumer->state().depositPendingBalance(bucket);
}

size_t WalletGreen::getTransactionCount() const {
  throwIfNotInitialized();
  throwIfStopped();

  return m_pqConsumer ? m_pqConsumer->state().historyCount() : 0;
}

WalletTransaction WalletGreen::getTransaction(size_t transactionIndex) const {
  throwIfNotInitialized();
  throwIfStopped();

  const auto* hist = m_pqConsumer ? &m_pqConsumer->state().history() : nullptr;
  if (hist == nullptr || hist->size() <= transactionIndex) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get transaction: invalid index " << transactionIndex
                                << ". Number of transactions: " << (hist ? hist->size() : 0);
    throw std::system_error(make_error_code(CryptoNote::error::INDEX_OUT_OF_RANGE));
  }
  return pqRowToWalletTx((*hist)[transactionIndex]);
}

size_t WalletGreen::getTransactionTransferCount(size_t transactionIndex) const {
  throwIfNotInitialized();
  throwIfStopped();

  // A PQ history row reports one transfer per OUR address the tx touched (primary +
  // deposits); counterparties aren't recoverable from owned-output scanning.
  const auto* hist = m_pqConsumer ? &m_pqConsumer->state().history() : nullptr;
  if (hist == nullptr || transactionIndex >= hist->size()) {
    return 0;
  }
  const auto& row = (*hist)[transactionIndex];
  return pqTransfersForTx(row.txid, row.netAmount).size();
}

WalletTransfer WalletGreen::getTransactionTransfer(size_t transactionIndex, size_t transferIndex) const {
  throwIfNotInitialized();
  throwIfStopped();

  const auto* hist = m_pqConsumer ? &m_pqConsumer->state().history() : nullptr;
  if (hist != nullptr && transactionIndex < hist->size()) {
    const auto& row = (*hist)[transactionIndex];
    std::vector<WalletTransfer> transfers = pqTransfersForTx(row.txid, row.netAmount);
    if (transferIndex < transfers.size()) {
      return transfers[transferIndex];
    }
  }

  m_logger(ERROR, BRIGHT_RED) << "Failed to get transfer: invalid transfer index " << transferIndex
                              << ". Transaction index " << transactionIndex;
  throw std::system_error(make_error_code(std::errc::invalid_argument));
}

size_t WalletGreen::transfer(const TransactionParameters& transactionParameters, Crypto::SecretKey& txSecretKey) {
  // Note: no wallet lock is held here. Recipient resolution hits the node (for
  // account numbers) and must not pin the wallet's event loop, and sendPqTransfer
  // does its own short-lived locking around the ledger read + reservation.
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

  // The tx was registered in the ledger (as unconfirmed) by sendPqTransfer; return
  // its native history index.
  size_t id = pqHistoryIndex(getObjectHash(result.tx));
  m_logger(INFO, BRIGHT_WHITE) << "Transaction sent, hash " << getObjectHash(result.tx) <<
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

WalletTransactionWithTransfers WalletGreen::getTransaction(const Crypto::Hash& transactionHash) const {
  throwIfNotInitialized();
  throwIfStopped();

  const auto* row = m_pqConsumer ? m_pqConsumer->state().historyByTxid(transactionHash) : nullptr;
  if (row == nullptr) {
    m_logger(ERROR, BRIGHT_RED) << "Failed to get transaction: not found. Transaction hash " << transactionHash;
    throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND), "Transaction not found");
  }
  WalletTransactionWithTransfers w;
  w.transaction = pqRowToWalletTx(*row);
  w.transfers = pqTransfersForTx(row->txid, row->netAmount);
  return w;
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
  if (!m_pqConsumer) {
    return result;
  }
  for (const auto& row : m_pqConsumer->state().history()) {
    if (row.height != WalletLedger::UNCONFIRMED_HEIGHT) {
      continue;
    }
    WalletTransactionWithTransfers w;
    w.transaction = pqRowToWalletTx(row);
    w.transfers = pqTransfersForTx(row.txid, row.netAmount);
    result.push_back(std::move(w));
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

Crypto::SecretKey WalletGreen::getTransactionSecretKey(size_t transactionIndex) const {
  throwIfNotInitialized();
  throwIfStopped();

  // PQ transactions carry no per-tx secret key (stealth delivery is ML-KEM based),
  // so there is nothing to return for transaction proofs.
  (void)transactionIndex;
  return CryptoNote::NULL_SECRET_KEY;
}

Crypto::SecretKey WalletGreen::getTransactionSecretKey(Crypto::Hash& transactionHash) const {
  throwIfNotInitialized();
  throwIfStopped();

  (void)transactionHash;
  return CryptoNote::NULL_SECRET_KEY;
}

bool WalletGreen::getTransactionProof(const Crypto::Hash& transactionHash, const CryptoNote::AccountPublicAddress& destinationAddress, const Crypto::SecretKey& txKey, std::string& transactionProof) {
  return CryptoNote::getTransactionProof(transactionHash, destinationAddress, txKey, transactionProof, m_logger.getLogger());
}

std::string WalletGreen::signMessage(const std::string &message, const std::string& address) {
  throwIfNotInitialized();
  throwIfTrackingMode();
  throwIfStopped();

  // Discrete signs with the wallet's post-quantum (ML-DSA) spend key, derived from the
  // raw master seed exactly as the address publishes it (the SeedMaster overload — NOT
  // the legacy HKDF SecretKey overload), so the signature verifies against that address.
  CryptoPQ::SeedMaster seed = primarySeedMaster();
  if (seed == CryptoPQ::SeedMaster{}) {
    throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS),
                            "wallet has no spend key to sign with");
  }
  PqWalletKeys keys = derivePqWalletKeys(seed);

  // Per-subaddress signing: under AggregatedMultikey each deposit publishes its OWN
  // spend key, so signing FOR a deposit address uses that deposit's key — the verifier
  // checks the signature against the deposit address's spend pubkey. Under SingleKeyIndex
  // every address shares the one key; an empty selector signs as the primary. `address`
  // must be one of ours.
  CryptoPQ::DsaSecretKey signSk = keys.spendSk;
  if (!address.empty()) {
    uint32_t bucket = PQ_PRIMARY_DEPOSIT;
    if (!pqResolveAddressBucket(address, bucket)) {
      throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS),
                              "cannot sign for an address that is not owned by this wallet: " + address);
    }
    if (m_pqDepositScheme == PqDepositScheme::AggregatedMultikey && bucket != PQ_PRIMARY_DEPOSIT) {
      signSk = CryptoPQ::deriveDepositSpendKeys(keys.seedMaster, bucket).second;
    }
  }
  return CryptoNote::signMessagePq(message, signSk);
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

  // The PQ scan appends history rows as it processes blocks; announce them so the
  // txid->index map walletd builds from these events stays current.
  pushNewTransactionEvents();
  pushEvent(makeSyncProgressUpdatedEvent(processedBlockCount, totalBlockCount));
}

void WalletGreen::onSynchronizationCompleted() {
  System::EventLock lk(m_readyEvent);

  m_logger(TRACE) << "onSynchronizationCompleted";

  if (m_state == WalletState::NOT_INITIALIZED) {
    return;
  }

  // The pool path (onPoolUpdated) reports only through synchronizationCompleted, so
  // newly received mempool transactions are announced here.
  pushNewTransactionEvents();
  pushEvent(makeSyncCompletedEvent());
}

void WalletGreen::pushNewTransactionEvents() {
  if (!m_pqConsumer) {
    return;
  }

  size_t count = m_pqConsumer->state().historyCount();

  // A reorg or a dropped mempool transaction removes rows and re-indexes the rest,
  // shrinking the history. Re-baseline to the current size; nothing new to announce.
  if (m_pqNotifiedTxCount > count) {
    m_pqNotifiedTxCount = count;
    return;
  }

  for (size_t id = m_pqNotifiedTxCount; id < count; ++id) {
    pushEvent(makeTransactionCreatedEvent(id));
  }
  m_pqNotifiedTxCount = count;
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

void WalletGreen::initPqConsumer(const CryptoPQ::SeedMaster& seedMaster,
                                 const SynchronizationStart& syncStart) {
  if (m_pqConsumer) {
    return;  // already created
  }
  if (seedMaster == CryptoPQ::SeedMaster{}) {  // all-zero => tracking (audit-only) wallet
    if (m_pqTrackingKeys) {
      initPqConsumer(*m_pqTrackingKeys, syncStart);
    }
    return;
  }
  PqWalletKeys pqKeys = derivePqWalletKeys(seedMaster);
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
  initPqConsumer(primary.seedMaster, syncStart);
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

  // History rows already on disk are this wallet's past (walletd seeds its txid
  // index from them at load); baseline the announce cursor so they are not
  // re-announced. Rows discovered during this session's sync fire TRANSACTION_CREATED.
  m_pqNotifiedTxCount = m_pqConsumer ? m_pqConsumer->state().historyCount() : 0;
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
  CryptoPQ::SeedMaster seed = primarySeedMaster();
  if (seed == CryptoPQ::SeedMaster{}) {
    return false;  // tracking wallet without a stored credential
  }
  keys = pqTrackingKeys(derivePqWalletKeys(seed));
  return true;
}

bool WalletGreen::getPqRegistrationKeysHex(std::string& viewHex, std::string& spendHex) const {
  throwIfNotInitialized();
  throwIfStopped();
  if (getAddressCount() == 0) {
    return false;
  }
  CryptoPQ::SeedMaster seed = primarySeedMaster();
  if (seed == CryptoPQ::SeedMaster{}) {
    return false;
  }
  PqWalletKeys keys = derivePqWalletKeys(seed);
  viewHex = Common::toHex(keys.viewPub.data(), keys.viewPub.size());
  spendHex = Common::toHex(keys.spendPub.data(), keys.spendPub.size());
  return true;
}

PqSendResult WalletGreen::sendPqTransfer(const std::vector<PqSendOutput>& recipients,
                                         uint64_t fee, uint64_t unlockHeight,
                                         const std::vector<uint8_t>& extra,
                                         const std::vector<std::string>& sourceAddresses,
                                         const std::string& changeAddress) {
  throwIfNotInitialized();
  throwIfStopped();
  if (!pqEnabled()) {
    throw std::runtime_error("Spending is unavailable for this wallet");
  }
  CryptoPQ::SeedMaster seed = primarySeedMaster();
  if (seed == CryptoPQ::SeedMaster{}) {
    throw std::runtime_error("tracking wallet cannot spend");
  }
  PqWalletKeys keys = derivePqWalletKeys(seed);

  PqSendRequest req;
  req.recipients = recipients;
  req.explicitFee = fee;
  req.unlockHeight = unlockHeight;
  req.extra = extra;
  // The scheme drives per-input key selection inside buildPqSend (the one key vs a
  // per-deposit derived key for AggregatedMultikey deposit inputs).
  req.scheme = m_pqDepositScheme;
  // Restrict the spend to the requested source addresses (each resolved to a bucket).
  // Each must be one of our own addresses; an unknown one is rejected.
  for (const auto& a : sourceAddresses) {
    uint32_t bucket = 0;
    if (!pqResolveAddressBucket(a, bucket)) {
      throw std::system_error(make_error_code(error::BAD_ADDRESS),
                              "source address is not owned by this wallet: " + a);
    }
    req.sourceBuckets.push_back(bucket);
  }
  // Change destination (empty = primary). Must be one of our own addresses; route any
  // change there so it re-scans into that bucket.
  if (!changeAddress.empty()) {
    uint32_t changeBucket = 0;
    if (!pqResolveAddressBucket(changeAddress, changeBucket)) {
      throw std::system_error(make_error_code(error::CHANGE_ADDRESS_NOT_FOUND),
                              "change address is not owned by this wallet: " + changeAddress);
    }
    req.hasChangeDest = true;
    req.changeDest = pqChangeTemplate(changeBucket);
  }

  // Build + reserve under the wallet lock: reading the spendable set and registering
  // the tx (which marks its inputs spent and records the change/history) must be
  // atomic w.r.t. the sync thread, which mutates the ledger under the same lock.
  // Registering before relay also reserves the inputs so a second send can't reuse
  // them, mirroring the classical addUnconfirmedTransaction-before-relay.
  PqSendResult result;
  Crypto::Hash txid;
  {
    System::EventLock lk(m_readyEvent);
    result = buildPqSend(m_pqConsumer->state().spendableInputs(), keys, req);
    txid = getObjectHash(result.tx);
    auto reader = createTransactionPrefix(result.tx);
    m_pqConsumer->addUnconfirmedTransaction(*reader);
  }

  // Relay OUTSIDE the lock: the network round-trip must not pin the wallet's event
  // loop / sync. On failure, roll the reservation back (un-spend inputs, drop the
  // unconfirmed change + history) — the classical add-before-relay / delete-on-fail.
  std::promise<std::error_code> promise;
  auto future = promise.get_future();
  m_node.relayTransaction(result.tx, [&promise](std::error_code ec) { promise.set_value(ec); });
  std::error_code ec = future.get();
  if (ec) {
    System::EventLock lk(m_readyEvent);
    m_pqConsumer->removeUnconfirmedTransaction(txid);
    throw std::system_error(ec, "failed to relay transaction");
  }
  return result;
}

size_t WalletGreen::pqHistoryIndex(const Crypto::Hash& txid) const {
  if (!m_pqConsumer) {
    return WALLET_INVALID_TRANSACTION_ID;
  }
  System::EventLock lk(m_readyEvent);
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
  CryptoPQ::SeedMaster seed = primarySeedMaster();
  if (seed == CryptoPQ::SeedMaster{}) {
    throw std::runtime_error("tracking wallet cannot register account numbers");
  }
  PqWalletKeys keys = derivePqWalletKeys(seed);

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
  CryptoPQ::SeedMaster seed = primarySeedMaster();
  if (seed == CryptoPQ::SeedMaster{}) {
    return std::string();  // tracking wallet: cannot derive deposit spend keys
  }
  PqWalletKeys base = derivePqWalletKeys(seed);

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

PqSendOutput WalletGreen::pqChangeTemplate(uint32_t depositIndex) const {
  // Built exactly like a payment to that bucket's address, so the wallet re-scans the
  // change output back into the same bucket. The view key is shared across buckets.
  PqWalletKeys keys = derivePqWalletKeys(primarySeedMaster());
  PqSendOutput o{};
  o.amount = 0;
  o.unlockHeight = 0;
  o.recipientViewPub = keys.viewPub;
  if (depositIndex == PQ_PRIMARY_DEPOSIT) {
    o.recipientSpendPub = keys.spendPub;
    o.subaddrIndexT = 0;
  } else if (m_pqDepositScheme == PqDepositScheme::SingleKeyIndex) {
    // One spend key; the deposit is the subaddress index T carried in the output.
    o.recipientSpendPub = keys.spendPub;
    o.subaddrIndexT = depositIndex;
  } else {
    // AggregatedMultikey: the deposit has its own spend key (T = 0).
    o.recipientSpendPub = CryptoPQ::deriveDepositSpendKeys(keys.seedMaster, depositIndex).first;
    o.subaddrIndexT = 0;
  }
  return o;
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
  CryptoPQ::SeedMaster seed = primarySeedMaster();
  if (seed == CryptoPQ::SeedMaster{}) {
    throw std::runtime_error("tracking wallet cannot register account numbers");
  }
  PqWalletKeys keys = derivePqWalletKeys(seed);
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

  return m_walletsContainer.get<RandomAccessIndex>().begin()->tracking ?
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

  if (!m_pqConsumer) {
    return result;
  }

  // PQ-native: group the ledger's confirmed history rows by block height. The
  // wallet's block-hash list (m_blockchain) still tracks the chain, so heights
  // map to hashes the same way. Each tx carries one WalletTransfer per OUR address
  // it touched (counterparties aren't recoverable from owned-output scanning).
  const auto& hist = m_pqConsumer->state().history();
  for (uint32_t height = blockIndex; height < stopIndex; ++height) {
    TransactionsInBlockInfo info;
    info.blockHash = m_blockchain[height];
    for (const auto& row : hist) {
      if (row.height != height) {
        continue;
      }
      WalletTransactionWithTransfers w;
      w.transaction = pqRowToWalletTx(row);
      w.transfers = pqTransfersForTx(row.txid, row.netAmount);
      info.transactions.push_back(std::move(w));
    }
    result.push_back(std::move(info));
  }
  return result;
}

Crypto::Hash WalletGreen::getBlockHashByIndex(uint32_t blockIndex) const {
  assert(blockIndex < m_blockchain.size());
  return m_blockchain.get<BlockHeightIndex>()[blockIndex];
}

void WalletGreen::initBlockchain() {
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
  // PQ-native: an address is ours if it matches our primary PQ address or one of
  // our issued deposit subaddresses.
  uint32_t bucket = 0;
  return !addressString.empty() && pqResolveAddressBucket(addressString, bucket);
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

void WalletGreen::createViewWallet(const std::string& /*password*/,
                                   const std::string /*address*/,
                                   const Crypto::SecretKey& /*viewSecretKey*/,
                                   const std::string& /*path*/)
{
    // Classical (view-key + address) view wallets do not exist on a PQ chain; an
    // audit-only wallet is created from a PQ tracking key (initializeWithPqTrackingKey).
    throw std::system_error(make_error_code(std::errc::function_not_supported),
      "Classical view wallets are not supported on the post-quantum wallet; import a PQ tracking key instead");
}

} //namespace CryptoNote
