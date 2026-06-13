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
#include "Logging/ConsoleLogger.h"
#include "WalletLegacy/WalletHelper.h"
#include "WalletLegacy/WalletLegacySerialization.h"
#include "WalletLegacy/WalletLegacySerializer.h"
#include "WalletLegacy/WalletUtils.h"
#include "Common/StringTools.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
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
  m_blockchainSync(node, m_logger.getLogger(), currency.genesisBlockHash()),
  m_transfersSync(currency, m_logger.getLogger(), m_blockchainSync, node),
  m_transferDetails(nullptr),
  m_transactionsCache(m_currency.mempoolTxLiveTime()),
  m_sender(nullptr),
  m_onInitSyncStarter(new SyncStarter(m_blockchainSync))
{
  addObserver(m_onInitSyncStarter.get());
}

WalletLegacy::~WalletLegacy() {
  removeObserver(m_onInitSyncStarter.get());

  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    if (m_state != NOT_INITIALIZED) {
      m_sender->stop();
      m_isStopping = true;
    }
  }

  m_blockchainSync.removeObserver(this);
  m_blockchainSync.stop();
  if (m_pqConsumer) {
    m_blockchainSync.removeConsumer(m_pqConsumer.get());
  }
  m_asyncContextCounter.waitAsyncContextsFinish();
  m_sender.reset();
}

void WalletLegacy::addObserver(IWalletLegacyObserver* observer) {
  m_observerManager.add(observer);
}

void WalletLegacy::removeObserver(IWalletLegacyObserver* observer) {
  m_observerManager.remove(observer);
}

void WalletLegacy::initAndGenerateNonDeterministic(const std::string& password) {
  {
    std::unique_lock<std::mutex> stateLock(m_cacheMutex);

    if (m_state != NOT_INITIALIZED) {
      throw std::system_error(make_error_code(error::ALREADY_INITIALIZED));
    }

    m_account.generate();
    m_password = password;

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
  AccountSubscription sub;
  sub.keys = reinterpret_cast<const AccountKeys&>(m_account.getAccountKeys());
  sub.transactionSpendableAge = CryptoNote::parameters::CRYPTONOTE_TX_SPENDABLE_AGE;
  sub.syncStart.height = 0;
  sub.syncStart.timestamp = std::max(m_account.get_createtime(), ACCOUNT_CREATE_TIME_ACCURACY) - ACCOUNT_CREATE_TIME_ACCURACY;
  
  auto& subObject = m_transfersSync.addSubscription(sub);
  m_transferDetails = &subObject.getContainer();
  subObject.addObserver(this);

  m_sender.reset(new WalletTransactionSender(m_currency, m_transactionsCache, m_account.getAccountKeys(), *m_transferDetails, m_node));

  // PQ scanning consumer. Requires a spend secret (the PQ identity is derived
  // from it); tracking wallets have none, so they get no PQ balance. Also gated
  const auto& keys = m_account.getAccountKeys();
  const bool pqScheduled = true;  // PQ is always active in Discrete
  if (pqScheduled && keys.spendSecretKey != NULL_SECRET_KEY) {
    PqWalletKeys pqKeys = derivePqWalletKeys(keys.spendSecretKey);
    // TODO(pq): persist the PQ consumer cursor + PqWalletState so the wallet
    // does not rescan PQ outputs from genesis on each load. Until PQ activates
    // (block v6) there are no PQ blocks, so the rescan is currently a no-op.
    m_pqConsumer.reset(new PqConsumer(pqKeys, sub.syncStart, m_logger.getLogger()));
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
    WalletLegacySerializer serializer(m_account, m_transactionsCache);
    serializer.deserialize(source, m_password, cache);

    initSync();

    try {
      if (!cache.empty()) {
        std::stringstream stream(cache);
        char magic[PQ_CACHE_MAGIC_LEN] = {0};
        stream.read(magic, PQ_CACHE_MAGIC_LEN);
        if (stream.gcount() == PQ_CACHE_MAGIC_LEN &&
            std::memcmp(magic, PQ_CACHE_MAGIC, PQ_CACHE_MAGIC_LEN) == 0) {
          auto readSection = [&stream](std::string& out) -> bool {
            uint64_t len = 0;
            stream.read(reinterpret_cast<char*>(&len), sizeof(len));
            if (!stream) return false;
            out.resize(len);
            if (len) stream.read(&out[0], static_cast<std::streamsize>(len));
            return static_cast<bool>(stream);
          };
          std::string transfersCache, consumerState, pqState;
          if (readSection(transfersCache)) {
            std::stringstream ts(transfersCache);
            m_transfersSync.load(ts);
          }
          if (readSection(consumerState) && m_pqConsumer && !consumerState.empty()) {
            std::stringstream cs(consumerState);
            m_blockchainSync.getConsumerState(m_pqConsumer.get())->load(cs);
          }
          if (readSection(pqState) && m_pqConsumer && !pqState.empty()) {
            std::stringstream ps(pqState);
            m_pqConsumer->state().load(ps);
          }
        } else {
          // Legacy (pre-PQ) cache: the whole blob is the transfers cache.
          std::stringstream legacy(cache);
          m_transfersSync.load(legacy);
        }
      }
    } catch (const std::exception&) {
      // ignore cache loading errors
    }

    // Read all output keys cache
    std::vector<TransactionOutputInformation> allTransfers;
    m_transferDetails->getOutputs(allTransfers, ITransfersContainer::IncludeAll);
    m_logger(Logging::INFO) << "Loaded " + std::to_string(allTransfers.size()) + " known transfer(s)";
    for (auto& o : allTransfers) {
      if (o.type != TransactionTypes::OutputType::Invalid) {
        m_transfersSync.addPublicKeysSeen(m_account.getAccountKeys().address, o.transactionHash, o.outputKey);
      }
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
  WalletLegacySerializer serializer(m_account, m_transactionsCache);
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

    m_sender->stop();
  }

  m_blockchainSync.removeObserver(this);
  m_blockchainSync.stop();
  m_asyncContextCounter.waitAsyncContextsFinish();

  m_sender.reset();
   
  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    m_isStopping = false;
    m_state = NOT_INITIALIZED;

    const auto& accountAddress = m_account.getAccountKeys().address;
    auto subObject = m_transfersSync.getSubscription(accountAddress);
    assert(subObject != nullptr);
    subObject->removeObserver(this);
    m_transfersSync.removeSubscription(accountAddress);
    m_transferDetails = nullptr;

    m_transactionsCache.reset();
    m_lastNotifiedActualBalance = 0;
    m_lastNotifiedPendingBalance = 0;
    m_lastNotifiedUnmixableBalance = 0;
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
    
    WalletLegacySerializer serializer(m_account, m_transactionsCache);
    std::string cache;

    if (saveCache) {
      std::stringstream transfersStream;
      m_transfersSync.save(transfersStream);
      std::string transfersCache = transfersStream.str();

      // Framed cache: magic || [u64 len || bytes] x3 (transfers, PQ consumer
      // cursor, PQ wallet state). The magic lets older/legacy caches (which were
      // a bare transfers blob) be detected and loaded on the fallback path.
      std::stringstream combined;
      combined.write(PQ_CACHE_MAGIC, PQ_CACHE_MAGIC_LEN);
      auto writeSection = [&combined](const std::string& s) {
        uint64_t len = s.size();
        combined.write(reinterpret_cast<const char*>(&len), sizeof(len));
        if (len) combined.write(s.data(), s.size());
      };
      writeSection(transfersCache);

      std::string consumerState, pqState;
      if (m_pqConsumer) {
        std::stringstream cs;
        m_blockchainSync.getConsumerState(m_pqConsumer.get())->save(cs);
        consumerState = cs.str();
        std::stringstream ps;
        m_pqConsumer->state().save(ps);
        pqState = ps.str();
      }
      writeSection(consumerState);
      writeSection(pqState);
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
  std::string lang = "English";
  Crypto::ElectrumWords::bytes_to_words(m_account.getAccountKeys().spendSecretKey, electrum_words, lang);

  Crypto::SecretKey second;
  keccak((uint8_t *)&m_account.getAccountKeys().spendSecretKey, sizeof(Crypto::SecretKey), (uint8_t *)&second, sizeof(Crypto::SecretKey));

  sc_reduce32((uint8_t *)&second);

  return memcmp(second.data, m_account.getAccountKeys().viewSecretKey.data, sizeof(Crypto::SecretKey)) == 0;
}

std::string WalletLegacy::getAddress() {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  return m_currency.accountAddressAsString(m_account);
}

std::string WalletLegacy::sign_message(const std::string &message) {
  return CryptoNote::signMessage(message, m_account.getAccountKeys());
}

bool WalletLegacy::verify_message(const std::string &message, const CryptoNote::AccountPublicAddress &address, const std::string &signature) {
  return CryptoNote::verifyMessage(message, address, signature, m_logger.getLogger());
}

std::vector<Payments> WalletLegacy::getTransactionsByPaymentIds(const std::vector<PaymentId>& paymentIds) const {
  return m_transactionsCache.getTransactionsByPaymentIds(paymentIds);
}

uint64_t WalletLegacy::actualBalance() {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  return m_transferDetails->balance(ITransfersContainer::IncludeKeyUnlocked) -
    m_transactionsCache.unconfrimedOutsAmount();
}

uint64_t WalletLegacy::pqActualBalance() const {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  if (!m_pqConsumer) {
    return 0;
  }
  return m_pqConsumer->state().balance();
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

Transaction WalletLegacy::createBridgeTransaction(const CryptoPQ::KemPublicKey& destViewPub,
                                                  const CryptoPQ::DsaPublicKey& destSpendPub,
                                                  uint64_t amount, uint64_t minimumFee,
                                                  uint64_t mixin, uint64_t& feeOut) {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  const auto& accKeys = m_account.getAccountKeys();
  if (accKeys.spendSecretKey == NULL_SECRET_KEY) {
    throw std::runtime_error("tracking wallet cannot bridge");
  }

  uint64_t bridgeFee = minimumFee != 0 ? minimumFee : m_node.getMinimalFee();
  if (bridgeFee == 0) {
    bridgeFee = m_currency.minimumFee();
  }
  if (amount > std::numeric_limits<uint64_t>::max() - bridgeFee) {
    throw std::runtime_error("bridge amount plus fee overflows");
  }
  const uint64_t targetWithFee = amount + bridgeFee;

  // Collect unlocked, spendable legacy key outputs, largest first.
  std::vector<TransactionOutputInformation> outs;
  m_transferDetails->getOutputs(outs, ITransfersContainer::IncludeKeyUnlocked);
  std::sort(outs.begin(), outs.end(),
            [](const TransactionOutputInformation& a, const TransactionOutputInformation& b) {
              return a.amount > b.amount;
            });

  std::vector<TransactionOutputInformation> chosen;
  uint64_t sumIn = 0;
  for (const auto& o : outs) {
    if (o.type != TransactionTypes::OutputType::Key) continue;
    if (chosen.size() >= 50) break;  // bound tx size
    chosen.push_back(o);
    sumIn += o.amount;
    if (sumIn >= targetWithFee) break;
  }
  if (sumIn < targetWithFee) {
    throw std::runtime_error("insufficient unlocked legacy balance to bridge");
  }

  // Resolve ring decoys for privacy (mixin>0). Mirrors the classical send path:
  // request mixin+1 random outs per input amount, drop the real one, splice the
  // real output in at its sorted position. On a sparse chain we use whatever
  // decoys the node returns rather than failing the bridge.
  std::vector<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount> mixOuts;
  if (mixin > 0) {
    std::vector<uint64_t> amounts;
    amounts.reserve(chosen.size());
    for (const auto& o : chosen) amounts.push_back(o.amount);
    std::promise<std::error_code> promise;
    auto future = promise.get_future();
    m_node.getRandomOutsByAmounts(std::move(amounts), mixin + 1, mixOuts,
                                  [&promise](std::error_code ec) { promise.set_value(ec); });
    if (future.get()) {
      mixOuts.clear();  // fall back to no decoys on RPC failure
    }
  }

  std::vector<BridgeLegacyInput> selected;
  for (size_t i = 0; i < chosen.size(); ++i) {
    const TransactionOutputInformation& td = chosen[i];
    BridgeLegacyInput bi;
    bi.senderKeys = accKeys;
    bi.keyInfo.amount = td.amount;

    if (i < mixOuts.size()) {
      std::sort(mixOuts[i].outs.begin(), mixOuts[i].outs.end(),
                [](const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry& a,
                   const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry& b) {
                  return a.global_amount_index < b.global_amount_index;
                });
      for (auto& oe : mixOuts[i].outs) {
        if (oe.global_amount_index == td.globalOutputIndex) continue;
        bi.keyInfo.outputs.push_back(
            TransactionTypes::GlobalOutput{oe.out_key, static_cast<uint32_t>(oe.global_amount_index)});
        if (bi.keyInfo.outputs.size() >= mixin) break;
      }
    }
    // Splice the real output in at its sorted position.
    auto it = std::find_if(bi.keyInfo.outputs.begin(), bi.keyInfo.outputs.end(),
                           [&](const TransactionTypes::GlobalOutput& g) {
                             return g.outputIndex >= td.globalOutputIndex;
                           });
    auto realIt = bi.keyInfo.outputs.insert(
        it, TransactionTypes::GlobalOutput{td.outputKey, td.globalOutputIndex});
    bi.keyInfo.realOutput.transactionPublicKey = td.transactionPublicKey;
    bi.keyInfo.realOutput.transactionIndex =
        static_cast<size_t>(realIt - bi.keyInfo.outputs.begin());
    bi.keyInfo.realOutput.outputInTransaction = td.outputInTransaction;
    selected.push_back(std::move(bi));
  }

  auto buildWith = [&](uint64_t change) {
    std::vector<PqSendOutput> outsPq;
    outsPq.push_back(PqSendOutput{destViewPub, destSpendPub, amount});
    std::vector<BridgeKeyOutput> outsKey;
    if (change > 0) {
      outsKey.push_back(BridgeKeyOutput{accKeys.address, change});
    }
    return buildBridgeTransaction(selected, outsPq, outsKey);
  };

  Transaction draft = buildWith(sumIn - amount);
  uint64_t fee = bridgeFee + m_currency.getFeePerByte(draft.extra.size(), bridgeFee);
  if (fee < bridgeFee || amount > std::numeric_limits<uint64_t>::max() - fee) {
    throw std::runtime_error("bridge amount plus fee overflows");
  }
  if (sumIn < amount + fee) {
    throw std::runtime_error("insufficient unlocked legacy balance to cover the bridge fee");
  }
  feeOut = fee;
  return buildWith(sumIn - amount - fee);
}

uint64_t WalletLegacy::pendingBalance() {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  uint64_t change = m_transactionsCache.unconfrimedOutsAmount() - m_transactionsCache.unconfirmedTransactionsAmount();
  return m_transferDetails->balance(ITransfersContainer::IncludeKeyNotUnlocked) + change;
}

uint64_t WalletLegacy::unmixableBalance() {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  std::vector<TransactionOutputInformation> outputs;
  m_transferDetails->getOutputs(outputs, ITransfersContainer::IncludeKeyUnlocked);

  uint64_t money = 0;

  for (size_t i = 0; i < outputs.size(); ++i) {
    const auto& out = outputs[i];
    if (!m_transactionsCache.isUsed(out)) {
      if (!is_valid_decomposed_amount(out.amount)) {
        money += out.amount;
      }
    }
  }

  return money;
}

size_t WalletLegacy::getTransactionCount() {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  return m_transactionsCache.getTransactionCount();
}

size_t WalletLegacy::getTransferCount() {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  return m_transactionsCache.getTransferCount();
}

TransactionId WalletLegacy::findTransactionByTransferId(TransferId transferId) {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  return m_transactionsCache.findTransactionByTransferId(transferId);
}

bool WalletLegacy::getTransaction(TransactionId transactionId, WalletLegacyTransaction& transaction) {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  return m_transactionsCache.getTransaction(transactionId, transaction);
}

bool WalletLegacy::getTransfer(TransferId transferId, WalletLegacyTransfer& transfer) {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
  throwIfNotInitialised();

  return m_transactionsCache.getTransfer(transferId, transfer);
}

size_t WalletLegacy::getUnlockedOutputsCount() {
  std::vector<TransactionOutputInformation> outputs;
  m_transferDetails->getOutputs(outputs, ITransfersContainer::IncludeKeyUnlocked);
  return outputs.size();
}

std::vector<TransactionOutputInformation> WalletLegacy::getOutputs() {
  std::vector<TransactionOutputInformation> outputs;
  m_transferDetails->getOutputs(outputs, ITransfersContainer::IncludeAll);
  return outputs;
}

std::vector<TransactionOutputInformation> WalletLegacy::getLockedOutputs() {
  std::vector<TransactionOutputInformation> outputs;
  m_transferDetails->getOutputs(outputs, ITransfersContainer::IncludeAllLocked);
  return outputs;
}

std::vector<TransactionOutputInformation> WalletLegacy::getUnlockedOutputs() {
  std::vector<TransactionOutputInformation> outputs;
  m_transferDetails->getOutputs(outputs, ITransfersContainer::IncludeAllUnlocked);
  return outputs;
}

std::vector<TransactionSpentOutputInformation> WalletLegacy::getSpentOutputs() {
  return m_transferDetails->getSpentOutputs();
}

TransactionId WalletLegacy::sendTransaction(const WalletLegacyTransfer& transfer, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockTimestamp) {
  std::vector<WalletLegacyTransfer> transfers;
  transfers.push_back(transfer);
  throwIfNotInitialised();

  return sendTransaction(transfers, fee, extra, mixIn, unlockTimestamp);
}

TransactionId WalletLegacy::sendTransaction(const std::vector<WalletLegacyTransfer>& transfers, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockTimestamp) {
  TransactionId txId = 0;
  std::shared_ptr<WalletRequest> request;
  std::deque<std::shared_ptr<WalletLegacyEvent>> events;
  throwIfNotInitialised();

  std::list<CryptoNote::TransactionOutputInformation> _selectedOuts = {};

  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    request = m_sender->makeSendRequest(txId, events, transfers, _selectedOuts, fee, extra, mixIn, unlockTimestamp);
  }

  notifyClients(events);

  if (request) {
    m_asyncContextCounter.addAsyncContext();
    request->perform(m_node, std::bind(&WalletLegacy::sendTransactionCallback, this, std::placeholders::_1, std::placeholders::_2));
  }

  return txId;
}

TransactionId WalletLegacy::sendTransaction(const std::vector<WalletLegacyTransfer>& transfers, const std::list<TransactionOutputInformation>& selectedOuts, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockTimestamp) {
  TransactionId txId = 0;
  std::shared_ptr<WalletRequest> request;
  std::deque<std::shared_ptr<WalletLegacyEvent>> events;
  throwIfNotInitialised();

  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    request = m_sender->makeSendRequest(txId, events, transfers, selectedOuts, fee, extra, mixIn, unlockTimestamp);
  }

  notifyClients(events);

  if (request) {
    m_asyncContextCounter.addAsyncContext();
    request->perform(m_node, std::bind(&WalletLegacy::sendTransactionCallback, this, std::placeholders::_1, std::placeholders::_2));
  }

  return txId;
}

std::string WalletLegacy::prepareRawTransaction(TransactionId& transactionId, const std::vector<WalletLegacyTransfer>& transfers, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockTimestamp) {
  std::deque<std::shared_ptr<WalletLegacyEvent>> events;
  throwIfNotInitialised();

  std::list<CryptoNote::TransactionOutputInformation> _selectedOuts = {};

  std::string tx_as_hex;

  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    tx_as_hex = m_sender->makeRawTransaction(transactionId, events, transfers, _selectedOuts, fee, extra, mixIn, unlockTimestamp);
  }

  notifyClients(events);

  return tx_as_hex;
}

std::string WalletLegacy::prepareRawTransaction(TransactionId& transactionId, const std::vector<WalletLegacyTransfer>& transfers, const std::list<CryptoNote::TransactionOutputInformation>& selectedOuts, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockTimestamp) {
  std::deque<std::shared_ptr<WalletLegacyEvent>> events;
  throwIfNotInitialised();

  std::string tx_as_hex;

  {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    tx_as_hex = m_sender->makeRawTransaction(transactionId, events, transfers, selectedOuts, fee, extra, mixIn, unlockTimestamp);
  }

  notifyClients(events);

  return tx_as_hex;
}

std::string WalletLegacy::prepareRawTransaction(TransactionId& transactionId, const WalletLegacyTransfer& transfer, uint64_t fee, const std::string& extra, uint64_t mixIn, uint64_t unlockTimestamp) {
  std::vector<WalletLegacyTransfer> transfers;
  transfers.push_back(transfer);
  throwIfNotInitialised();

  return prepareRawTransaction(transactionId, transfers, fee, extra, mixIn, unlockTimestamp);
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

  // check if balance has changed and notify client
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

  notifyIfBalanceChanged();
}

void WalletLegacy::onTransactionUpdated(ITransfersSubscription* object, const Hash& transactionHash) {
  std::shared_ptr<WalletLegacyEvent> event;

  TransactionInformation txInfo;
  uint64_t amountIn;
  uint64_t amountOut;
  if (m_transferDetails->getTransactionInformation(transactionHash, txInfo, &amountIn, &amountOut)) {
    std::unique_lock<std::mutex> lock(m_cacheMutex);
    event = m_transactionsCache.onTransactionUpdated(txInfo, static_cast<int64_t>(amountOut) - static_cast<int64_t>(amountIn));
  }

  if (event.get()) {
    event->notify(m_observerManager);
  }
}

void WalletLegacy::onTransactionDeleted(ITransfersSubscription* object, const Hash& transactionHash) {
  std::shared_ptr<WalletLegacyEvent> event;

  {
  std::unique_lock<std::mutex> lock(m_cacheMutex);
    event = m_transactionsCache.onTransactionDeleted(transactionHash);
  }

  if (event.get()) {
    event->notify(m_observerManager);
  }
}

void WalletLegacy::throwIfNotInitialised() {
  if (m_state == NOT_INITIALIZED || m_state == LOADING) {
    throw std::system_error(make_error_code(CryptoNote::error::NOT_INITIALIZED));
  }
  assert(m_transferDetails);
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
  std::lock_guard<std::mutex> lock(m_cacheMutex);
  return m_transactionsCache.deleteOutdatedTransactions();
}

/* Returns either deterministic key or stored in wallet cache
 * (returns null key if is absent in cache).
 * In order to generate deterministic key raw transaction is 
 * requested from Node.
 */
Crypto::SecretKey WalletLegacy::getTxKey(Crypto::Hash& txid) {
  TransactionId ti = m_transactionsCache.findTransactionByHash(txid);
  WalletLegacyTransaction transaction;
  getTransaction(ti, transaction);
  if (transaction.secretKey && NULL_SECRET_KEY != reinterpret_cast<const Crypto::SecretKey&>(transaction.secretKey.get())) {
    return reinterpret_cast<const Crypto::SecretKey&>(transaction.secretKey.get());
  } else {
    auto getTransactionCompleted = std::promise<std::error_code>();
    auto getTransactionWaitFuture = getTransactionCompleted.get_future();
    CryptoNote::Transaction tx;
    m_node.getTransaction(std::move(txid), std::ref(tx),
      [&getTransactionCompleted](std::error_code ec) {
      auto detachedPromise = std::move(getTransactionCompleted);
      detachedPromise.set_value(ec);
    });
    std::error_code ec = getTransactionWaitFuture.get();
    if (ec) {
      m_logger(ERROR) << "Failed to get tx: " << ec << ", " << ec.message();
      return reinterpret_cast<const Crypto::SecretKey&>(transaction.secretKey.get());
    }

    Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(tx.extra);
    const AccountKeys& accKeys = m_account.getAccountKeys();
    KeyPair deterministicTxKeys;
    bool ok = generateDeterministicTransactionKeys(tx, accKeys.viewSecretKey, deterministicTxKeys)
      && deterministicTxKeys.publicKey == txPubKey;

    return ok ? deterministicTxKeys.secretKey : reinterpret_cast<const Crypto::SecretKey&>(transaction.secretKey.get());
  }
}

bool WalletLegacy::get_tx_key(Crypto::Hash& txid, Crypto::SecretKey& txSecretKey) {
  TransactionId ti = m_transactionsCache.findTransactionByHash(txid);
  WalletLegacyTransaction transaction;
  getTransaction(ti, transaction);
  txSecretKey = transaction.secretKey.get();
  if (txSecretKey == NULL_SECRET_KEY) {
    m_logger(Logging::INFO) << "Transaction secret key is not stored in wallet cache.";
    return false;
  }

  return true;
}

bool WalletLegacy::getTxProof(Crypto::Hash& txid, CryptoNote::AccountPublicAddress& address, Crypto::SecretKey& tx_key, std::string& sig_str) {
  return getTransactionProof(txid, address, tx_key, sig_str, m_logger.getLogger());
}

bool compareTransactionOutputInformationByAmount(const TransactionOutputInformation &a, const TransactionOutputInformation &b) {
  return a.amount < b.amount;
}

std::string WalletLegacy::getReserveProof(const uint64_t &reserve, const std::string &message) {
  const CryptoNote::AccountKeys keys = m_account.getAccountKeys();

  if (keys.spendSecretKey == NULL_SECRET_KEY) {
    throw std::runtime_error("Reserve proof can only be generated by a full wallet");
  }

  if (actualBalance() == 0) {
    throw std::runtime_error("Zero balance");
  }

  if (actualBalance() < reserve) {
    throw std::runtime_error("Not enough balance for the requested minimum reserve amount");
  }

  // determine which outputs to include in the proof
  std::vector<TransactionOutputInformation> selected_transfers;
  m_transferDetails->getOutputs(selected_transfers, ITransfersContainer::IncludeAllUnlocked);

  // minimize the number of outputs included in the proof, by only picking the N largest outputs that can cover the requested min reserve amount
  std::sort(selected_transfers.begin(), selected_transfers.end(), compareTransactionOutputInformationByAmount);
  std::reverse(selected_transfers.begin(), selected_transfers.end());
  while (selected_transfers.size() >= 2 && selected_transfers[1].amount >= reserve)
    selected_transfers.erase(selected_transfers.begin());
  size_t sz = 0;
  uint64_t total = 0;
  while (total < reserve) {
    total += selected_transfers[sz].amount;
    ++sz;
  }
  selected_transfers.resize(sz);

  std::string reserveProof = "";
  bool r = CryptoNote::getReserveProof(selected_transfers, keys, reserve, message, reserveProof, m_logger.getLogger());
  if (!r) {
    throw std::runtime_error("Failed to get reserve proof");
  }

  return reserveProof;
}

bool WalletLegacy::getTransactionInformation(const Crypto::Hash& transactionHash, TransactionInformation& info,
                                             uint64_t* amountIn, uint64_t* amountOut) const {
  return m_transferDetails->getTransactionInformation(transactionHash, info, amountIn, amountOut);
};

std::vector<TransactionOutputInformation> WalletLegacy::getTransactionOutputs(const Crypto::Hash& transactionHash, uint32_t flags) const {
  return m_transferDetails->getTransactionOutputs(transactionHash, flags);
};

std::vector<TransactionOutputInformation> WalletLegacy::getTransactionInputs(const Crypto::Hash& transactionHash, uint32_t flags) const {
  return m_transferDetails->getTransactionInputs(transactionHash, flags);
};

} //namespace CryptoNote
