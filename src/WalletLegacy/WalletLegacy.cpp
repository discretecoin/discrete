// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2016-2026, The Karbo developers
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "WalletLegacy.h"

#include <algorithm>
#include <cstring>
#include <future>
#include <limits>
#include <numeric>
#include <crypto/random.h>
#include <set>
#include <tuple>
#include <utility>
#include <string.h>
#include <time.h>

#include "crypto/crypto.h"
#include "Common/Base58.h"
#include "Common/ShuffleGenerator.h"
#include "Wallet/PqWallet.h"
#include "Wallet/PqRecipient.h"
#include "Logging/ConsoleLogger.h"
#include "WalletLegacy/WalletHelper.h"
#include "WalletLegacy/WalletLegacyEvent.h"
#include "WalletLegacy/WalletLegacySerialization.h"
#include "WalletLegacy/WalletLegacySerializer.h"
#include "WalletLegacy/WalletUtils.h"
#include "Common/StringTools.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/TransactionApi.h"
#include "Mnemonics/electrum-words.h"

extern "C"
{
#include "crypto/keccak.h"
#include "crypto/crypto-ops.h"
}

using namespace Crypto;

namespace {

const uint64_t ACCOUNT_CREATE_TIME_ACCURACY = 24 * 60 * 60;

// Header on the wallet cache blob once it carries PQ sections. Absent on legacy
// (pre-PQ) caches, which were a bare transfers-sync blob.
constexpr char PQ_CACHE_MAGIC[] = {'K', 'P', 'Q', 'C', 'A', 'C', 'H', '1'};
constexpr int  PQ_CACHE_MAGIC_LEN = 8;
constexpr char PQ_TRACKING_MAGIC[] = {'K', 'P', 'Q', 'T', 'R', 'K', '1'};
constexpr int  PQ_TRACKING_MAGIC_LEN = 7;

template <typename ArrayT>
void appendArray(std::string& out, const ArrayT& bytes) {
  out.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

template <typename ArrayT>
bool readArray(const std::string& in, std::size_t& offset, ArrayT& bytes) {
  if (offset + bytes.size() > in.size()) {
    return false;
  }
  std::memcpy(bytes.data(), in.data() + offset, bytes.size());
  offset += bytes.size();
  return true;
}

std::string serializePqTrackingKeys(const CryptoNote::PqTrackingKeys& keys) {
  std::string out;
  out.reserve(PQ_TRACKING_MAGIC_LEN + keys.viewPub.size() + keys.viewSk.size() + keys.spendPub.size());
  out.append(PQ_TRACKING_MAGIC, PQ_TRACKING_MAGIC_LEN);
  appendArray(out, keys.viewPub);
  appendArray(out, keys.viewSk);
  appendArray(out, keys.spendPub);
  return out;
}

bool deserializePqTrackingKeys(const std::string& blob, CryptoNote::PqTrackingKeys& keys) {
  const std::size_t expectedSize = PQ_TRACKING_MAGIC_LEN +
      keys.viewPub.size() + keys.viewSk.size() + keys.spendPub.size();
  if (blob.size() != expectedSize ||
      std::memcmp(blob.data(), PQ_TRACKING_MAGIC, PQ_TRACKING_MAGIC_LEN) != 0) {
    return false;
  }

  CryptoNote::PqTrackingKeys parsed;
  std::size_t offset = PQ_TRACKING_MAGIC_LEN;
  if (!readArray(blob, offset, parsed.viewPub) ||
      !readArray(blob, offset, parsed.viewSk) ||
      !readArray(blob, offset, parsed.spendPub) ||
      offset != blob.size()) {
    return false;
  }

  keys = parsed;
  return true;
}

struct PqCacheSections {
  bool framed = false;
  std::string transfersCache;
  std::string consumerState;
  std::string pqState;
  std::string pqTrackingKeys;
};

bool readPqCacheSections(const std::string& cache, PqCacheSections& sections) {
  if (cache.empty()) {
    return false;
  }
  std::stringstream stream(cache);
  char magic[PQ_CACHE_MAGIC_LEN] = {0};
  stream.read(magic, PQ_CACHE_MAGIC_LEN);
  if (stream.gcount() != PQ_CACHE_MAGIC_LEN ||
      std::memcmp(magic, PQ_CACHE_MAGIC, PQ_CACHE_MAGIC_LEN) != 0) {
    return false;
  }

  sections.framed = true;
  auto readSection = [&stream](std::string& out) -> bool {
    uint64_t len = 0;
    stream.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (!stream) return false;
    out.resize(static_cast<std::size_t>(len));
    if (len) stream.read(&out[0], static_cast<std::streamsize>(len));
    return static_cast<bool>(stream);
  };

  if (!readSection(sections.transfersCache)) return true;
  if (!readSection(sections.consumerState)) return true;
  if (!readSection(sections.pqState)) return true;
  readSection(sections.pqTrackingKeys);  // optional fourth section
  return true;
}

void throwNotDefined() {
  throw std::runtime_error("The behavior is not defined!");
}

class ContextCounterHolder
{
public:
  ContextCounterHolder(CryptoNote::WalletAsyncContextCounter& shutdowner) : m_shutdowner(shutdowner) {}
  ~ContextCounterHolder() { m_shutdowner.delAsyncContext(); }

private:
  CryptoNote::WalletAsyncContextCounter& m_shutdowner;
};

template <typename F>
void runAtomic(std::mutex& mutex, F f) {
  std::unique_lock<std::mutex> lock(mutex);
  f();
}

class InitWaiter : public CryptoNote::IWalletLegacyObserver {
public:
  InitWaiter() : future(promise.get_future()) {}

  virtual void initCompleted(std::error_code result) override {
    promise.set_value(result);
  }

  std::error_code waitInit() {
    return future.get();
  }
private:
  std::promise<std::error_code> promise;
  std::future<std::error_code> future;
};


class SaveWaiter : public CryptoNote::IWalletLegacyObserver {
public:
  SaveWaiter() : future(promise.get_future()) {}

  virtual void saveCompleted(std::error_code result) override {
    promise.set_value(result);
  }

  std::error_code waitSave() {
    return future.get();
  }

private:
  std::promise<std::error_code> promise;
  std::future<std::error_code> future;
};

} //namespace

using namespace Logging;

namespace CryptoNote {

class SyncStarter : public CryptoNote::IWalletLegacyObserver {
public:
  SyncStarter(BlockchainSynchronizer& sync) : m_sync(sync) {}
  virtual ~SyncStarter() {}

  virtual void initCompleted(std::error_code result) override {
    if (!result) {
      m_sync.start();
    }
  }

  BlockchainSynchronizer& m_sync;
};

WalletLegacy::WalletLegacy(const CryptoNote::Currency& currency, INode& node, Logging::ILogger& log) :
  m_state(NOT_INITIALIZED),
  m_currency(currency),
  m_node(node),
  m_logger(log, "WalletLegacy"),
  m_isStopping(false),
  m_lastNotifiedActualBalance(0),
  m_lastNotifiedPendingBalance(0),
  m_lastNotifiedUnmixableBalance(0),
  m_lastNotifiedTransactionCount(0),
  m_blockchainSync(node, m_logger.getLogger(), currency.genesisBlockHash()),
  m_onInitSyncStarter(new SyncStarter(m_blockchainSync))
{
  addObserver(m_onInitSyncStarter.get());
}

WalletLegacy::~WalletLegacy() {
  removeObserver(m_onInitSyncStarter.get());

  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    if (m_state != NOT_INITIALIZED) {
      m_isStopping = true;
    }
  }

  m_blockchainSync.removeObserver(this);
  m_blockchainSync.stop();
  if (m_pqConsumer) {
    m_blockchainSync.removeConsumer(m_pqConsumer.get());
  }
  m_asyncContextCounter.waitAsyncContextsFinish();
}

void WalletLegacy::addObserver(IWalletLegacyObserver* observer) {
  m_observerManager.add(observer);
}

void WalletLegacy::removeObserver(IWalletLegacyObserver* observer) {
  m_observerManager.remove(observer);
}

namespace {
// Treat the wallet's 32-byte master secret as the PQ SeedMaster: PQ-native means
// the seed feeds the cemented PqSeed chain directly (no HKDF), matching WalletGreen
// and the daemon's deriveMinerPqKeys so the same wallet derives the same identity.
CryptoPQ::SeedMaster toSeedMaster(const Crypto::SecretKey& s) {
  CryptoPQ::SeedMaster sm{};
  std::memcpy(sm.data(), s.data, sm.size());
  return sm;
}
}  // namespace

void WalletLegacy::initAndGenerateNonDeterministic(const std::string& password) {
  {
    std::unique_lock<std::mutex> stateLock(m_cacheMutex);

    if (m_state != NOT_INITIALIZED) {
      throw std::system_error(make_error_code(error::ALREADY_INITIALIZED));
    }

    m_account.generate();
    m_password = password;
    m_pqTrackingKeys.reset();

    initSync();
  }

  m_observerManager.notify(&IWalletLegacyObserver::initCompleted, std::error_code());
}

void WalletLegacy::initAndGenerateDeterministic(const std::string& password) {
  {
    std::unique_lock<std::mutex> stateLock(m_cacheMutex);

    if (m_state != NOT_INITIALIZED) {
      throw std::system_error(make_error_code(error::ALREADY_INITIALIZED));
    }

    m_account.generateDeterministic();
    m_password = password;
    m_pqTrackingKeys.reset();

    initSync();
  }

  m_observerManager.notify(&IWalletLegacyObserver::initCompleted, std::error_code());
}

void WalletLegacy::initWithKeys(const AccountKeys& accountKeys, const std::string& password) {
  // Delegate to the scanHeight overload with 0 (sync from chain start).
  // scanHeightToTimestamp(0) returns 0; the initSync() formula
  //   max(createtime, ACCOUNT_CREATE_TIME_ACCURACY) - ACCOUNT_CREATE_TIME_ACCURACY
  // yields 0 for both createtime=0 and createtime=ACCOUNT_CREATE_TIME_ACCURACY, so
  // the sync behaviour is identical to the old standalone implementation.
  initWithKeys(accountKeys, password, 0);
}

uint64_t WalletLegacy::getBlockTimestamp(const uint32_t blockHeight) {
  uint64_t timestamp = 0;

  auto getBlockTimestampCompleted = std::promise<std::error_code>();
  auto getBlockTimestampWaitFuture = getBlockTimestampCompleted.get_future();

  m_node.getBlockTimestamp(std::move(blockHeight), std::ref(timestamp),
    [&getBlockTimestampCompleted](std::error_code ec) {
    auto detachedPromise = std::move(getBlockTimestampCompleted);
    detachedPromise.set_value(ec);
  });

  std::error_code ec = getBlockTimestampWaitFuture.get();

  if (ec) {
    m_logger(ERROR) << "Failed to get block timestamp: " << ec << ", " << ec.message();
  }

  return timestamp;
}

uint64_t getCurrentTimestampAdjusted() {
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

uint64_t WalletLegacy::scanHeightToTimestamp(const uint32_t scanHeight) {
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

void WalletLegacy::initWithKeys(const AccountKeys& accountKeys, const std::string& password, const uint32_t scanHeight) {
  {
    std::unique_lock<std::mutex> stateLock(m_cacheMutex);

    if (m_state != NOT_INITIALIZED) {
      throw std::system_error(make_error_code(error::ALREADY_INITIALIZED));
    }

    m_account.setAccountKeys(accountKeys);
    m_account.set_createtime(scanHeightToTimestamp(scanHeight));
    m_password = password;
    m_pqTrackingKeys.reset();

    initSync();
  }

  m_observerManager.notify(&IWalletLegacyObserver::initCompleted, std::error_code());
}

void WalletLegacy::initWithPqTrackingKeys(const AccountKeys& accountKeys, const PqTrackingKeys& pqTrackingKeys,
                                          const std::string& password) {
  initWithPqTrackingKeys(accountKeys, pqTrackingKeys, password, 0);
}

void WalletLegacy::initWithPqTrackingKeys(const AccountKeys& accountKeys, const PqTrackingKeys& pqTrackingKeys,
                                          const std::string& password, const uint32_t scanHeight) {
  {
    std::unique_lock<std::mutex> stateLock(m_cacheMutex);

    if (m_state != NOT_INITIALIZED) {
      throw std::system_error(make_error_code(error::ALREADY_INITIALIZED));
    }
    if (accountKeys.spendSecretKey != NULL_SECRET_KEY) {
      throw std::system_error(make_error_code(error::WRONG_PARAMETERS));
    }

    m_account.setAccountKeys(accountKeys);
    m_account.set_createtime(scanHeightToTimestamp(scanHeight));
    m_password = password;
    m_pqTrackingKeys.reset(new PqTrackingKeys(pqTrackingKeys));

    initSync();
  }

  m_observerManager.notify(&IWalletLegacyObserver::initCompleted, std::error_code());
}

void WalletLegacy::initAndLoad(std::istream& source, const std::string& password) {
  std::unique_lock<std::mutex> stateLock(m_cacheMutex);

  if (m_state != NOT_INITIALIZED) {
    throw std::system_error(make_error_code(error::ALREADY_INITIALIZED));
  }

  m_password = password;
  m_state = LOADING;
      
  m_asyncContextCounter.addAsyncContext();
  std::thread loader(&WalletLegacy::doLoad, this, std::ref(source));
  loader.detach();
}

void WalletLegacy::initSync() {
  SynchronizationStart syncStart;
  syncStart.height = 0;
  syncStart.timestamp = std::max(m_account.get_createtime(), ACCOUNT_CREATE_TIME_ACCURACY) - ACCOUNT_CREATE_TIME_ACCURACY;

  // PQ scanning consumer is the sole sync driver. Full wallets derive the PQ
  // identity from the spend secret; tracking wallets use a persisted view-only
  // PQ audit credential.
  const auto& keys = m_account.getAccountKeys();
  if (keys.spendSecretKey != NULL_SECRET_KEY) {
    PqWalletKeys pqKeys = derivePqWalletKeys(toSeedMaster(keys.spendSecretKey));
    m_pqConsumer.reset(new WalletLedgerConsumer(pqKeys, syncStart, m_logger.getLogger()));
    m_blockchainSync.addConsumer(m_pqConsumer.get());
  } else if (m_pqTrackingKeys) {
    m_pqConsumer.reset(new WalletLedgerConsumer(*m_pqTrackingKeys, syncStart, m_logger.getLogger()));
    m_blockchainSync.addConsumer(m_pqConsumer.get());
  }

  m_state = INITIALIZED;

  m_blockchainSync.addObserver(this);
}

void WalletLegacy::doLoad(std::istream& source) {
  ContextCounterHolder counterHolder(m_asyncContextCounter);
  try {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    
    std::string cache;
    WalletLegacySerializer serializer(m_account);
    serializer.deserialize(source, m_password, cache);

    m_pqTrackingKeys.reset();
    PqCacheSections pqSections;
    if (readPqCacheSections(cache, pqSections) && !pqSections.pqTrackingKeys.empty()) {
      PqTrackingKeys trackingKeys;
      if (deserializePqTrackingKeys(pqSections.pqTrackingKeys, trackingKeys)) {
        m_pqTrackingKeys.reset(new PqTrackingKeys(trackingKeys));
      }
    }

    initSync();

    try {
      // Only the PQ sections are loaded now; the legacy transfers-cache section (if
      // present in an older file) is ignored. The classical sync stack is gone.
      if (!cache.empty() && pqSections.framed) {
        if (m_pqConsumer && !pqSections.consumerState.empty()) {
          std::stringstream cs(pqSections.consumerState);
          m_blockchainSync.getConsumerState(m_pqConsumer.get())->load(cs);
        }
        if (m_pqConsumer && !pqSections.pqState.empty()) {
          std::stringstream ps(pqSections.pqState);
          m_pqConsumer->state().load(ps);
        }
      }
    } catch (const std::exception&) {
      // ignore cache loading errors
    }

    // History rows already on disk are this wallet's past; baseline the announce
    // cursor to them so reloading does not re-announce every old transaction. New
    // rows discovered during this session's sync grow past the baseline and fire.
    if (m_pqConsumer) {
      m_lastNotifiedTransactionCount.store(m_pqConsumer->state().historyCount());
    }

  } catch (std::system_error& e) {
    runAtomic(m_cacheMutex, [this] () {this->m_state = WalletLegacy::NOT_INITIALIZED;} );
    m_observerManager.notify(&IWalletLegacyObserver::initCompleted, e.code());
    return;
  } catch (std::exception&) {
    runAtomic(m_cacheMutex, [this] () {this->m_state = WalletLegacy::NOT_INITIALIZED;} );
    m_observerManager.notify(&IWalletLegacyObserver::initCompleted, make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR));
    return;
  }

  m_observerManager.notify(&IWalletLegacyObserver::initCompleted, std::error_code());
}

bool WalletLegacy::tryLoadWallet(std::istream& source, const std::string& password) {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  WalletLegacySerializer serializer(m_account);
  return serializer.deserialize(source, password);
}

void WalletLegacy::shutdown() {
  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);

    if (m_isStopping)
      throwNotDefined();

    m_isStopping = true;

    if (m_state != INITIALIZED)
      throwNotDefined();
  }

  m_blockchainSync.removeObserver(this);
  m_blockchainSync.stop();
  if (m_pqConsumer) {
    m_blockchainSync.removeConsumer(m_pqConsumer.get());
    m_pqConsumer.reset();
  }
  m_asyncContextCounter.waitAsyncContextsFinish();

  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    m_isStopping = false;
    m_state = NOT_INITIALIZED;

    m_lastNotifiedActualBalance = 0;
    m_lastNotifiedPendingBalance = 0;
    m_lastNotifiedUnmixableBalance = 0;
    m_lastNotifiedTransactionCount = 0;
  }
}

void WalletLegacy::reset() {
  try {
    std::error_code saveError;
    std::stringstream ss;
    {
      SaveWaiter saveWaiter;
      WalletHelper::IWalletRemoveObserverGuard saveGuarantee(*this, saveWaiter);
      save(ss, false, false);
      saveError = saveWaiter.waitSave();
    }

    if (!saveError) {
      shutdown();
      InitWaiter initWaiter;
      WalletHelper::IWalletRemoveObserverGuard initGuarantee(*this, initWaiter);
      initAndLoad(ss, m_password);
      initWaiter.waitInit();
    }
  } catch (std::exception& e) {
    m_logger(Logging::ERROR) << "exception in reset: " << e.what();
  }
}

void WalletLegacy::save(std::ostream& destination, bool saveDetailed, bool saveCache) {
  if(m_isStopping) {
    m_observerManager.notify(&IWalletLegacyObserver::saveCompleted, make_error_code(CryptoNote::error::OPERATION_CANCELLED));
    return;
  }

  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);

    throwIf(m_state != INITIALIZED, CryptoNote::error::WRONG_STATE);

    m_state = SAVING;
  }

  m_asyncContextCounter.addAsyncContext();
  std::thread saver(&WalletLegacy::doSave, this, std::ref(destination), saveDetailed, saveCache);
  saver.detach();
}

void WalletLegacy::doSave(std::ostream& destination, bool saveDetailed, bool saveCache) {
  ContextCounterHolder counterHolder(m_asyncContextCounter);

  try {
    m_blockchainSync.stop();
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    
    WalletLegacySerializer serializer(m_account);
    std::string cache;

    if (saveCache || m_pqTrackingKeys) {
      // Framed cache: magic || [u64 len || bytes] x4 (transfers, PQ consumer
      // cursor, PQ wallet state, PQ tracking credential). The classical transfers
      // section is now always empty (kept for wallet-file byte-compatibility); the
      // fourth section is optional for full wallets.
      std::stringstream combined;
      combined.write(PQ_CACHE_MAGIC, PQ_CACHE_MAGIC_LEN);
      auto writeSection = [&combined](const std::string& s) {
        uint64_t len = s.size();
        combined.write(reinterpret_cast<const char*>(&len), sizeof(len));
        if (len) combined.write(s.data(), s.size());
      };
      writeSection(std::string());  // empty classical transfers cache

      std::string consumerState, pqState;
      if (saveCache && m_pqConsumer) {
        std::stringstream cs;
        m_blockchainSync.getConsumerState(m_pqConsumer.get())->save(cs);
        consumerState = cs.str();
        std::stringstream ps;
        m_pqConsumer->state().save(ps);
        pqState = ps.str();
      }
      writeSection(consumerState);
      writeSection(pqState);
      writeSection(m_pqTrackingKeys ? serializePqTrackingKeys(*m_pqTrackingKeys) : std::string());
      cache = combined.str();
    }

    serializer.serialize(destination, m_password, saveDetailed, cache);

    m_state = INITIALIZED;
    m_blockchainSync.start(); //XXX: start can throw. what to do in this case?
  }
  catch (std::system_error& e) {
    runAtomic(m_cacheMutex, [this] () {this->m_state = WalletLegacy::INITIALIZED;} );
    m_observerManager.notify(&IWalletLegacyObserver::saveCompleted, e.code());
    return;
  }
  catch (std::exception&) {
    runAtomic(m_cacheMutex, [this] () {this->m_state = WalletLegacy::INITIALIZED;} );
    m_observerManager.notify(&IWalletLegacyObserver::saveCompleted, make_error_code(CryptoNote::error::INTERNAL_WALLET_ERROR));
    return;
  }

  m_observerManager.notify(&IWalletLegacyObserver::saveCompleted, std::error_code());
}

std::error_code WalletLegacy::changePassword(const std::string& oldPassword, const std::string& newPassword) {
  std::unique_lock<std::mutex> passLock(m_cacheMutex);

  throwIfNotInitialised();

  if (m_password.compare(oldPassword))
    return make_error_code(CryptoNote::error::WRONG_PASSWORD);

  //we don't let the user to change the password while saving
  m_password = newPassword;

  return std::error_code();
}

bool WalletLegacy::getSeed(std::string& electrum_words)
{
  // The 32-byte master seed IS the deterministic backup; the same words recover the
  // whole PQ identity. (There is no classical view key to cross-check anymore.)
  std::string lang = "English";
  Crypto::ElectrumWords::bytes_to_words(m_account.getAccountKeys().spendSecretKey, electrum_words, lang);
  return m_account.getAccountKeys().spendSecretKey != NULL_SECRET_KEY;
}

std::string WalletLegacy::getAddress() {
  throwIfNotInitialised();

  // PQ-native: expose the wallet's post-quantum address, matching greenwallet and
  // walletd. getPqAddress() locks m_cacheMutex internally (via getPqTrackingKeys),
  // so this must NOT hold the lock itself.
  return getPqAddress();
}

std::string WalletLegacy::sign_message(const std::string &message) {
  // Sign with the wallet's post-quantum (ML-DSA) spend key — its PQ identity — the
  // same as WalletGreen. The classical ECC key is gone.
  AccountKeys keys = m_account.getAccountKeys();
  if (keys.spendSecretKey == NULL_SECRET_KEY) {
    throw std::runtime_error("tracking wallet cannot sign messages");
  }
  PqWalletKeys pq = derivePqWalletKeys(toSeedMaster(keys.spendSecretKey));
  return CryptoNote::signMessagePq(message, pq.spendSk);
}

bool WalletLegacy::verify_message(const std::string &message, const CryptoNote::AccountPublicAddress &address, const std::string &signature) {
  return CryptoNote::verifyMessage(message, address, signature, m_logger.getLogger());
}

std::vector<Payments> WalletLegacy::getTransactionsByPaymentIds(const std::vector<PaymentId>& /*paymentIds*/) const {
  // PQ owned-output scanning cannot recover payment IDs, so there is no
  // payment-ID index to query.
  return {};
}

uint64_t WalletLegacy::actualBalance() {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  // PQ is the native ledger. "Actual" = confirmed (total minus still-in-mempool).
  if (!m_pqConsumer) {
    return 0;
  }
  uint64_t total = m_pqConsumer->state().balance();
  uint64_t pending = m_pqConsumer->state().pendingBalance();
  return total >= pending ? total - pending : 0;
}

uint64_t WalletLegacy::pqActualBalance() const {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  if (!m_pqConsumer) {
    return 0;
  }
  return m_pqConsumer->state().balance();
}

uint64_t WalletLegacy::pqUnlockedBalance() const {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  if (!m_pqConsumer) {
    return 0;
  }
  return m_pqConsumer->state().spendableBalance();
}

std::vector<PqSpendInput> WalletLegacy::pqSpendableInputs() const {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  if (!m_pqConsumer) {
    return {};
  }
  return m_pqConsumer->state().spendableInputs();
}

uint32_t WalletLegacy::pqSyncedHeight() const {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  if (!m_pqConsumer) {
    return 0;
  }
  return m_pqConsumer->state().lastScannedHeight();
}

bool WalletLegacy::getPqTrackingKeys(PqTrackingKeys& keys) const {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  if (m_pqTrackingKeys) {
    keys = *m_pqTrackingKeys;
    return true;
  }

  const AccountKeys& accountKeys = m_account.getAccountKeys();
  if (accountKeys.spendSecretKey == NULL_SECRET_KEY) {
    return false;
  }

  keys = pqTrackingKeys(derivePqWalletKeys(toSeedMaster(accountKeys.spendSecretKey)));
  return true;
}

std::string WalletLegacy::getPqAddress() const {
  PqTrackingKeys keys;
  if (!getPqTrackingKeys(keys)) {
    return std::string();
  }
  PqAddress addr = pqWalletAddress(keys, CryptoNote::parameters::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
  return encodePqAddress(addr, PqAddressEncoding::Base58);
}

PqSendResult WalletLegacy::sendPqTransfer(const std::vector<PqSendOutput>& recipients,
                                          uint64_t fee, uint64_t unlockHeight,
                                          const std::vector<uint8_t>& extra) {
  if (!pqEnabled()) {
    throw std::runtime_error("Spending is unavailable for this wallet");
  }
  AccountKeys keys;
  getAccountKeys(keys);
  if (keys.spendSecretKey == NULL_SECRET_KEY) {
    throw std::runtime_error("tracking wallet cannot spend");
  }
  PqWalletKeys pq = derivePqWalletKeys(toSeedMaster(keys.spendSecretKey));

  PqSendRequest req;
  req.recipients = recipients;
  req.explicitFee = fee;
  req.unlockHeight = unlockHeight;
  req.extra = extra;
  PqSendResult result = buildPqSend(pqSpendableInputs(), pq, req);

  std::promise<std::error_code> promise;
  auto future = promise.get_future();
  m_node.relayTransaction(result.tx, [&promise](std::error_code ec) { promise.set_value(ec); });
  std::error_code ec = future.get();
  if (ec) {
    throw std::system_error(ec, "failed to relay transaction");
  }
  return result;
}

uint64_t WalletLegacy::pendingBalance() {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  return m_pqConsumer ? m_pqConsumer->state().pendingBalance() : 0;
}

uint64_t WalletLegacy::unmixableBalance() {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  // PQ output amounts come from the fixed canonical denomination table, so there
  // is no "unmixable" (non-decomposable) balance.
  return 0;
}

size_t WalletLegacy::getTransactionCount() {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  return m_pqConsumer ? m_pqConsumer->state().historyCount() : 0;
}

size_t WalletLegacy::getTransferCount() {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  // PQ owned-output scanning cannot recover counterparties, so there is no
  // per-destination transfer detail (only the wallet's own net effect per tx).
  return 0;
}

TransactionId WalletLegacy::findTransactionByTransferId(TransferId /*transferId*/) {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  return WALLET_LEGACY_INVALID_TRANSACTION_ID;
}

bool WalletLegacy::getTransaction(TransactionId transactionId, WalletLegacyTransaction& transaction) {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  if (!m_pqConsumer) {
    return false;
  }
  const auto& hist = m_pqConsumer->state().history();
  if (transactionId >= hist.size()) {
    return false;
  }
  const PqWalletTransaction& h = hist[transactionId];

  // Map a PQ ledger history row onto the legacy transaction view. Counterparties
  // are not recoverable, so there are no per-transfer rows (transferCount = 0).
  transaction.firstTransferId = WALLET_LEGACY_INVALID_TRANSFER_ID;
  transaction.transferCount = 0;
  transaction.totalAmount = h.netAmount;
  transaction.fee = h.fee;
  transaction.sentTime = h.timestamp;
  transaction.unlockHeight = 0;
  transaction.hash = h.txid;
  transaction.secretKey = NULL_SECRET_KEY;
  transaction.isCoinbase = false;
  transaction.blockHeight = h.height;  // UNCONFIRMED_HEIGHT maps through (both uint32 max)
  transaction.timestamp = h.timestamp;
  transaction.extra.clear();
  transaction.state = WalletLegacyTransactionState::Active;
  return true;
}

bool WalletLegacy::getTransfer(TransferId /*transferId*/, WalletLegacyTransfer& /*transfer*/) {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  return false;  // no per-destination transfer detail on the PQ ledger
}

// Classical per-output enumeration is gone; PQ outputs live in the WalletLedger
// (TransactionOutputInformation describes ECC KeyOutputs, which a PQ wallet has none of).
size_t WalletLegacy::getUnlockedOutputsCount() {
  return 0;
}

std::vector<TransactionOutputInformation> WalletLegacy::getOutputs() {
  return {};
}

std::vector<TransactionOutputInformation> WalletLegacy::getLockedOutputs() {
  return {};
}

std::vector<TransactionOutputInformation> WalletLegacy::getUnlockedOutputs() {
  return {};
}

std::vector<TransactionSpentOutputInformation> WalletLegacy::getSpentOutputs() {
  return {};
}

TransactionId WalletLegacy::sendTransaction(const WalletLegacyTransfer& transfer, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockHeightstamp) {
  std::vector<WalletLegacyTransfer> transfers;
  transfers.push_back(transfer);
  throwIfNotInitialised();

  return sendTransaction(transfers, fee, extra, mixIn, unlockHeightstamp);
}

TransactionId WalletLegacy::sendTransaction(const std::vector<WalletLegacyTransfer>& transfers, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockHeightstamp) {
  throwIfNotInitialised();
  (void)mixIn;  // not applicable to PQ

  // PQ is the native ledger: resolve each destination as a PQ recipient and build,
  // sign and relay through the common sender. `extra` carries any tx-level tag (e.g.
  // a PQ account registration). Synchronous failures (bad address, insufficient
  // funds, relay error) propagate as exceptions, matching the legacy contract.
  std::vector<PqSendOutput> recipients;
  recipients.reserve(transfers.size());
  for (const auto& t : transfers) {
    if (t.amount < 0) {
      throw std::system_error(make_error_code(std::errc::invalid_argument));
    }
    CryptoPQ::KemPublicKey viewPub;
    CryptoPQ::DsaPublicKey spendPub;
    uint64_t subaddrT = 0;
    if (!resolvePqRecipient(m_node, t.address, viewPub, spendPub, subaddrT)) {
      throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS));
    }
    recipients.push_back(PqSendOutput{viewPub, spendPub, static_cast<uint64_t>(t.amount), subaddrT});
  }

  std::vector<uint8_t> extraBytes(extra.begin(), extra.end());
  PqSendResult result = sendPqTransfer(recipients, fee, unlockHeightstamp, extraBytes);  // builds + relays

  // Register the sent tx in the ledger so it has a native id/history row at once.
  TransactionId txId = WALLET_LEGACY_INVALID_TRANSACTION_ID;
  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    if (m_pqConsumer) {
      auto reader = createTransactionPrefix(result.tx);
      m_pqConsumer->addUnconfirmedTransaction(*reader);
      Crypto::Hash txid = getObjectHash(result.tx);
      const auto& hist = m_pqConsumer->state().history();
      for (size_t i = 0; i < hist.size(); ++i) {
        if (hist[i].txid == txid) { txId = i; break; }
      }
    }
  }

  std::deque<std::shared_ptr<WalletLegacyEvent>> events;
  events.push_back(std::make_shared<WalletSendTransactionCompletedEvent>(txId, std::error_code()));
  notifyClients(events);
  return txId;
}

TransactionId WalletLegacy::sendTransaction(const std::vector<WalletLegacyTransfer>& transfers, const std::list<TransactionOutputInformation>& /*selectedOuts*/, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockHeightstamp) {
  // PQ input selection is internal to buildPqSend; the caller-chosen output set is ignored.
  return sendTransaction(transfers, fee, extra, mixIn, unlockHeightstamp);
}

std::string WalletLegacy::prepareRawTransaction(TransactionId& transactionId, const std::vector<WalletLegacyTransfer>& transfers, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockHeightstamp) {
  throwIfNotInitialised();
  (void)mixIn;
  transactionId = WALLET_LEGACY_INVALID_TRANSACTION_ID;

  if (!pqEnabled()) {
    throw std::runtime_error("Spending is unavailable for this wallet");
  }
  AccountKeys keys;
  getAccountKeys(keys);
  if (keys.spendSecretKey == NULL_SECRET_KEY) {
    throw std::runtime_error("tracking wallet cannot spend");
  }

  std::vector<PqSendOutput> recipients;
  recipients.reserve(transfers.size());
  for (const auto& t : transfers) {
    if (t.amount < 0) {
      throw std::system_error(make_error_code(std::errc::invalid_argument));
    }
    CryptoPQ::KemPublicKey viewPub;
    CryptoPQ::DsaPublicKey spendPub;
    uint64_t subaddrT = 0;
    if (!resolvePqRecipient(m_node, t.address, viewPub, spendPub, subaddrT)) {
      throw std::system_error(make_error_code(CryptoNote::error::BAD_ADDRESS));
    }
    recipients.push_back(PqSendOutput{viewPub, spendPub, static_cast<uint64_t>(t.amount), subaddrT});
  }

  PqWalletKeys pq = derivePqWalletKeys(toSeedMaster(keys.spendSecretKey));
  PqSendRequest req;
  req.recipients = recipients;
  req.explicitFee = fee;
  req.unlockHeight = unlockHeightstamp;
  req.extra = std::vector<uint8_t>(extra.begin(), extra.end());
  PqSendResult result = buildPqSend(pqSpendableInputs(), pq, req);  // builds, does NOT relay

  return Common::toHex(toBinaryArray(result.tx));
}

std::string WalletLegacy::prepareRawTransaction(TransactionId& transactionId, const std::vector<WalletLegacyTransfer>& transfers, const std::list<CryptoNote::TransactionOutputInformation>& /*selectedOuts*/, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockHeightstamp) {
  return prepareRawTransaction(transactionId, transfers, fee, extra, mixIn, unlockHeightstamp);
}

std::string WalletLegacy::prepareRawTransaction(TransactionId& transactionId, const WalletLegacyTransfer& transfer, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockHeightstamp) {
  std::vector<WalletLegacyTransfer> transfers;
  transfers.push_back(transfer);
  throwIfNotInitialised();

  return prepareRawTransaction(transactionId, transfers, fee, extra, mixIn, unlockHeightstamp);
}

void WalletLegacy::sendTransactionCallback(WalletRequest::Callback callback, std::error_code ec) {
  ContextCounterHolder counterHolder(m_asyncContextCounter);
  std::deque<std::shared_ptr<WalletLegacyEvent> > events;

  boost::optional<std::shared_ptr<WalletRequest> > nextRequest;
  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    callback(events, nextRequest, ec);
  }

  notifyClients(events);

  if (nextRequest) {
    m_asyncContextCounter.addAsyncContext();
    (*nextRequest)->perform(m_node, std::bind(&WalletLegacy::synchronizationCallback, this, std::placeholders::_1, std::placeholders::_2));
  }
}

void WalletLegacy::synchronizationCallback(WalletRequest::Callback callback, std::error_code ec) {
  ContextCounterHolder counterHolder(m_asyncContextCounter);

  std::deque<std::shared_ptr<WalletLegacyEvent> > events;
  boost::optional<std::shared_ptr<WalletRequest> > nextRequest;
  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    callback(events, nextRequest, ec);
  }

  notifyClients(events);

  if (nextRequest) {
    m_asyncContextCounter.addAsyncContext();
    (*nextRequest)->perform(m_node, std::bind(&WalletLegacy::synchronizationCallback, this, std::placeholders::_1, std::placeholders::_2));
  }
}

std::error_code WalletLegacy::cancelTransaction(size_t transactionId) {
  return make_error_code(CryptoNote::error::TX_CANCEL_IMPOSSIBLE);
}

void WalletLegacy::synchronizationProgressUpdated(uint32_t current, uint32_t total) {
  auto deletedTransactions = deleteOutdatedUnconfirmedTransactions();

  // forward notification
  m_observerManager.notify(&IWalletLegacyObserver::synchronizationProgressUpdated, current, total);

  for (auto transactionId: deletedTransactions) {
    m_observerManager.notify(&IWalletLegacyObserver::transactionUpdated, transactionId);
  }

  // announce transactions the PQ scan just discovered, then balance changes
  notifyExternalTransactions();
  notifyIfBalanceChanged();
}

void WalletLegacy::synchronizationCompleted(std::error_code result) {
  if (result != std::make_error_code(std::errc::interrupted)) {
    m_observerManager.notify(&IWalletLegacyObserver::synchronizationCompleted, result);
  }

  if (result) {
    return;
  }

  auto deletedTransactions = deleteOutdatedUnconfirmedTransactions();
  std::for_each(deletedTransactions.begin(), deletedTransactions.end(), [&] (TransactionId transactionId) {
    m_observerManager.notify(&IWalletLegacyObserver::transactionUpdated, transactionId);
  });

  // The pool path (onPoolUpdated) reports only through synchronizationCompleted,
  // so newly received mempool transactions are announced here.
  notifyExternalTransactions();
  notifyIfBalanceChanged();
}

void WalletLegacy::notifyExternalTransactions() {
  if (!m_pqConsumer) {
    return;
  }

  // The PQ ledger appends a history row the first time a transaction touches this
  // wallet (its mempool sight, or — for coinbase — the block that mines it). Fire
  // externalTransactionCreated for every row not yet announced, mirroring the
  // classical notification simplewallet/walletd print incoming/outgoing lines from.
  size_t count = m_pqConsumer->state().historyCount();
  size_t announced = m_lastNotifiedTransactionCount.load();

  // A reorg or a dropped mempool transaction removes rows and re-indexes the rest,
  // shrinking the history. Re-baseline to the current size; nothing new to announce.
  if (announced > count) {
    m_lastNotifiedTransactionCount.store(count);
    return;
  }

  for (size_t id = announced; id < count; ++id) {
    m_observerManager.notify(&IWalletLegacyObserver::externalTransactionCreated, static_cast<TransactionId>(id));
  }
  m_lastNotifiedTransactionCount.store(count);
}

// ITransfersObserver callbacks came from the classical subscription, which no
// longer exists; PQ transaction state is tracked by the WalletLedger consumer.
void WalletLegacy::onTransactionUpdated(ITransfersSubscription* /*object*/, const Hash& /*transactionHash*/) {
}

void WalletLegacy::onTransactionDeleted(ITransfersSubscription* /*object*/, const Hash& /*transactionHash*/) {
}

void WalletLegacy::throwIfNotInitialised() {
  if (m_state == NOT_INITIALIZED || m_state == LOADING) {
    throw std::system_error(make_error_code(CryptoNote::error::NOT_INITIALIZED));
  }
}

void WalletLegacy::notifyClients(std::deque<std::shared_ptr<WalletLegacyEvent> >& events) {
  while (!events.empty()) {
    std::shared_ptr<WalletLegacyEvent> event = events.front();
    event->notify(m_observerManager);
    events.pop_front();
  }
}

void WalletLegacy::notifyIfBalanceChanged() {
  auto actual = actualBalance();
  auto prevActual = m_lastNotifiedActualBalance.exchange(actual);

  if (prevActual != actual) {
    m_observerManager.notify(&IWalletLegacyObserver::actualBalanceUpdated, actual);
  }

  auto pending = pendingBalance();
  auto prevPending = m_lastNotifiedPendingBalance.exchange(pending);

  if (prevPending != pending) {
    m_observerManager.notify(&IWalletLegacyObserver::pendingBalanceUpdated, pending);
  }

  auto unmixable = unmixableBalance();
  auto prevUnmixable = m_lastNotifiedUnmixableBalance.exchange(unmixable);

  if (prevUnmixable != unmixable) {
    m_observerManager.notify(&IWalletLegacyObserver::unmixableBalanceUpdated, unmixable);
  }

}

void WalletLegacy::getAccountKeys(AccountKeys& keys) {
  if (m_state == NOT_INITIALIZED) {
    throw std::system_error(make_error_code(CryptoNote::error::NOT_INITIALIZED));
  }

  keys = m_account.getAccountKeys();
}

bool WalletLegacy::isTrackingWallet() {
  AccountKeys keys;
  getAccountKeys(keys);
  
  return keys.spendSecretKey == boost::value_initialized<Crypto::SecretKey>();
}

std::vector<TransactionId> WalletLegacy::deleteOutdatedUnconfirmedTransactions() {
  // PQ mempool lifecycle is owned by the WalletLedger consumer; there is no
  // classical unconfirmed-transaction cache to prune.
  return {};
}

Crypto::SecretKey WalletLegacy::getTxKey(Crypto::Hash& txid) {
  // PQ transactions carry no per-tx secret key (stealth delivery is ML-KEM based).
  (void)txid;
  return NULL_SECRET_KEY;
}

bool WalletLegacy::get_tx_key(Crypto::Hash& txid, Crypto::SecretKey& txSecretKey) {
  (void)txid;
  txSecretKey = NULL_SECRET_KEY;
  m_logger(Logging::INFO) << "Post-quantum transactions carry no secret transaction key.";
  return false;
}

bool WalletLegacy::getTxProof(Crypto::Hash& txid, CryptoNote::AccountPublicAddress& address, Crypto::SecretKey& tx_key, std::string& sig_str) {
  return getTransactionProof(txid, address, tx_key, sig_str, m_logger.getLogger());
}

// Classical container introspection is gone; these described ECC KeyOutputs/inputs,
// which a PQ wallet does not have.
bool WalletLegacy::getTransactionInformation(const Crypto::Hash& /*transactionHash*/, TransactionInformation& /*info*/,
                                             uint64_t* /*amountIn*/, uint64_t* /*amountOut*/) const {
  return false;
};

std::vector<TransactionOutputInformation> WalletLegacy::getTransactionOutputs(const Crypto::Hash& /*transactionHash*/, uint32_t /*flags*/) const {
  return {};
};

std::vector<TransactionOutputInformation> WalletLegacy::getTransactionInputs(const Crypto::Hash& /*transactionHash*/, uint32_t /*flags*/) const {
  return {};
};

} //namespace CryptoNote
