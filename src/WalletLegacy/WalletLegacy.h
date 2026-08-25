// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2016, The Monero Project
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

#pragma once

#include <list>
#include <map>
#include <istream>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>

#include "CryptoNote.h"
#include "IWalletLegacy.h"
#include "INode.h"
#include "Wallet/WalletErrors.h"
#include "Wallet/WalletAsyncContextCounter.h"
#include "Common/ObserverManager.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Currency.h"
#include "WalletLegacy/WalletUserTransactionsCache.h"
#include "WalletLegacy/WalletUnconfirmedTransactions.h"

#include "WalletLegacy/WalletRequest.h"

#include "Transfers/BlockchainSynchronizer.h"
#include "ITransfersSynchronizer.h"

#include "Wallet/WalletLedgerConsumer.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/PqSender.h"
#include "Wallet/SentPaymentsStore.h"
#include "Wallet/PaymentProofArchive.h"

#include <Logging/LoggerRef.h>

namespace CryptoNote {

class SyncStarter;

struct WalletSnapshotInfo {
  uint32_t serializationVersion = 0;
  bool isTracking = false;
  bool hasPqTrackingKeys = false;
  PqTrackingKeys pqTrackingKeys{};
  std::string protectedSpendMetadata;
};

class WalletLegacy :
  public IWalletLegacy,
  IBlockchainSynchronizerObserver,
  ITransfersObserver {

public:
  WalletLegacy(const CryptoNote::Currency& currency, INode& node, Logging::ILogger& log);
  virtual ~WalletLegacy();

  virtual void addObserver(IWalletLegacyObserver* observer) override;
  virtual void removeObserver(IWalletLegacyObserver* observer) override;

  virtual void initAndGenerateNonDeterministic(const std::string& password) override;
  virtual void initAndGenerateDeterministic(const std::string& password) override;
  void initAndGenerate(const std::string& password) { initAndGenerateDeterministic(password); }
  virtual void initAndLoad(std::istream& source, const std::string& password) override;
  virtual void initWithKeys(const AccountKeys& accountKeys, const std::string& password) override;
  virtual void initWithKeys(const AccountKeys& accountKeys, const std::string& password, const uint32_t scanHeight) override;
  void initWithPqTrackingKeys(const AccountKeys& accountKeys, const PqTrackingKeys& pqTrackingKeys, const std::string& password);
  void initWithPqTrackingKeys(const AccountKeys& accountKeys, const PqTrackingKeys& pqTrackingKeys, const std::string& password, const uint32_t scanHeight);
  virtual void shutdown() override;
  virtual void rescan() override;
  virtual void reset() override;
  virtual bool tryLoadWallet(std::istream& source, const std::string& password) override;

  virtual void save(std::ostream& destination, bool saveDetailed = true, bool saveCache = true) override;

  virtual std::error_code changePassword(const std::string& oldPassword, const std::string& newPassword) override;

  virtual std::string getAddress() override;

  virtual uint64_t actualBalance() override;
  virtual uint64_t pendingBalance() override;

  // --- PQ (post-quantum) balance / spend, concrete (not on IWalletLegacy) ----
  // Full wallets derive the PQ identity from the spend secret. PQ tracking
  // wallets instead hold a view-only PqTrackingKeys credential.
  bool pqEnabled() const { return static_cast<bool>(m_pqConsumer); }
  uint64_t pqActualBalance() const;
  // Balance currently spendable (coinbase maturity / timelocks reached). The
  // difference pqActualBalance() - pqUnlockedBalance() is still locked.
  uint64_t pqUnlockedBalance() const;
  std::vector<PqSpendInput> pqSpendableInputs() const;
  uint32_t pqSyncedHeight() const;
  bool pqScannerHasSpendSeed() const;
  bool getPqTrackingKeys(PqTrackingKeys& keys) const;
  // Opaque front-end metadata for externally protected spend authority. It is
  // persisted inside the password-encrypted wallet file, survives reset and
  // cache-free backups, and is never interpreted by the core.
  bool getPqProtectedSpendMetadata(std::string& metadata) const;
  bool setPqProtectedSpendMetadata(const std::string& metadata);
  // Fully decrypt and inspect a saved wallet without modifying the open wallet.
  // Protected-spend migration uses this to validate the staged tracking file
  // before it replaces the original full wallet.
  static bool inspectWalletSnapshot(std::istream& source,
                                    const std::string& password,
                                    WalletSnapshotInfo& info,
                                    std::string& error);
  std::string getPqAddress() const;
  // Convert an open full wallet into tracking-only state without restarting.
  // The caller receives the seed exactly once and must persist it safely before
  // saving the converted wallet. The existing PQ cache/history is preserved.
  bool detachPqSpendSeed(CryptoPQ::SeedMaster& seedMaster);
  // Roll back an in-memory detachment if the protected file could not be
  // validated or committed. This never runs after the on-disk full wallet has
  // been replaced.
  bool restorePqSpendSeed(const CryptoPQ::SeedMaster& seedMaster);
  // Verify and use an externally unlocked seed for one operation. The seed is
  // never copied into m_account and therefore can never enter an autosave.
  PqSendResult sendPqTransferWithSeed(const CryptoPQ::SeedMaster& seedMaster,
                                      const std::vector<PqSendOutput>& recipients,
                                      uint64_t fee = 0, uint64_t unlockHeight = 0,
                                      const std::vector<uint8_t>& extra = {},
                                      const std::vector<std::string>& recipientAddresses = {});
  PqSendResult preparePqTransferWithSeed(const CryptoPQ::SeedMaster& seedMaster,
                                         const std::vector<PqSendOutput>& recipients,
                                         uint64_t fee = 0, uint64_t unlockHeight = 0,
                                         const std::vector<uint8_t>& extra = {});
  // Build (denominate, two-pass fee, sign) and relay a PQ transfer to already-resolved
  // recipients via the common sender — the same deterministic path WalletGreen uses.
  // Throws on a tracking wallet, insufficient funds, or relay failure.
  PqSendResult sendPqTransfer(const std::vector<PqSendOutput>& recipients,
                              uint64_t fee = 0, uint64_t unlockHeight = 0,
                              const std::vector<uint8_t>& extra = {},
                              const std::vector<std::string>& recipientAddresses = {});
  // Build and sign through the same sender without relay or wallet-state changes.
  PqSendResult preparePqTransfer(const std::vector<PqSendOutput>& recipients,
                                 uint64_t fee = 0, uint64_t unlockHeight = 0,
                                 const std::vector<uint8_t>& extra = {});
  const SentPaymentRecord* getPaymentProofs(const Crypto::Hash& txid) const;
  bool copyPaymentProofs(const Crypto::Hash& txid, SentPaymentRecord& record) const;
  void exportPaymentProofs(const Crypto::Hash& txid, const std::string& path,
                           std::size_t recipientIndex = static_cast<std::size_t>(-1));
  Crypto::Hash importPaymentProofs(const std::string& path);
  bool deletePaymentProofs(const Crypto::Hash& txid,
                           std::size_t recipientIndex = static_cast<std::size_t>(-1));

  // Net amount of one transaction split by subaddress index T (SingleKeyIndex
  // attribution; PQ_PRIMARY_DEPOSIT means the primary address, which is where T=0
  // lands). Empty map if the tx is unknown. Display-only: T routes attribution,
  // not funds.
  std::map<uint32_t, int64_t> getTransactionSubaddressAmounts(TransactionId transactionId);

  virtual size_t getTransactionCount() override;
  virtual size_t getTransferCount() override;
  virtual size_t getUnlockedOutputsCount() override;

  virtual TransactionId findTransactionByTransferId(TransferId transferId) override;

  virtual bool getTransaction(TransactionId transactionId, WalletLegacyTransaction& transaction) override;
  virtual bool getTransfer(TransferId transferId, WalletLegacyTransfer& transfer) override;
  virtual std::vector<Payments> getTransactionsByPaymentIds(const std::vector<PaymentId>& paymentIds) const override;
  virtual void getAccountKeys(AccountKeys& keys) override;
  virtual bool getSeed(std::string& electrum_words) override;

  virtual std::vector<TransactionOutputInformation> getOutputs() override;
  virtual std::vector<TransactionOutputInformation> getLockedOutputs() override;
  virtual std::vector<TransactionOutputInformation> getUnlockedOutputs() override;
  virtual std::vector<TransactionSpentOutputInformation> getSpentOutputs() override;

  virtual TransactionId sendTransaction(const WalletLegacyTransfer& transfer, uint64_t fee, const std::string& extra = "", uint64_t ignoredPrivacyWidth = 0, uint64_t unlockHeightstamp = 0) override;
  virtual TransactionId sendTransaction(const std::vector<WalletLegacyTransfer>& transfers, uint64_t fee, const std::string& extra = "", uint64_t ignoredPrivacyWidth = 0, uint64_t unlockHeightstamp = 0) override;
  virtual TransactionId sendTransaction(const std::vector<WalletLegacyTransfer>& transfers, const std::list<TransactionOutputInformation>& selectedOuts, uint64_t fee, const std::string& extra = "", uint64_t ignoredPrivacyWidth = 0, uint64_t unlockHeightstamp = 0) override;
  virtual std::string prepareRawTransaction(TransactionId& transactionId, const WalletLegacyTransfer& transfer, uint64_t fee, const std::string& extra = "", uint64_t ignoredPrivacyWidth = 0, uint64_t unlockHeightstamp = 0) override;
  virtual std::string prepareRawTransaction(TransactionId& transactionId, const std::vector<WalletLegacyTransfer>& transfers, uint64_t fee, const std::string& extra = "", uint64_t ignoredPrivacyWidth = 0, uint64_t unlockHeightstamp = 0) override;
  virtual std::string prepareRawTransaction(TransactionId& transactionId, const std::vector<WalletLegacyTransfer>& transfers, const std::list<TransactionOutputInformation>& selectedOuts, uint64_t fee, const std::string& extra = "", uint64_t ignoredPrivacyWidth = 0, uint64_t unlockHeightstamp = 0) override;
  virtual std::error_code cancelTransaction(size_t transactionId) override;

  virtual bool getTransactionInformation(const Crypto::Hash& transactionHash, TransactionInformation& info,
      uint64_t* amountIn = nullptr, uint64_t* amountOut = nullptr) const override;
  virtual std::vector<TransactionOutputInformation> getTransactionOutputs(const Crypto::Hash& transactionHash, uint32_t flags = ITransfersContainer::IncludeDefault) const override;
  virtual std::vector<TransactionOutputInformation> getTransactionInputs(const Crypto::Hash& transactionHash, uint32_t flags) const override;

  virtual std::string sign_message(const std::string &message) override;

  TransactionId sendTransactionWithSeed(const CryptoPQ::SeedMaster& seedMaster,
                                        const std::vector<WalletLegacyTransfer>& transfers,
                                        uint64_t fee, const std::string& extra = "",
                                        uint64_t ignoredPrivacyWidth = 0,
                                        uint64_t unlockHeightstamp = 0);
  std::string prepareRawTransactionWithSeed(const CryptoPQ::SeedMaster& seedMaster,
                                            TransactionId& transactionId,
                                            const std::vector<WalletLegacyTransfer>& transfers,
                                            uint64_t fee, const std::string& extra = "",
                                            uint64_t ignoredPrivacyWidth = 0,
                                            uint64_t unlockHeightstamp = 0);
  std::string signMessageWithSeed(const CryptoPQ::SeedMaster& seedMaster,
                                  const std::string& message);

  virtual bool isTrackingWallet() override;

private:

  // IBlockchainSynchronizerObserver
  virtual void synchronizationProgressUpdated(uint32_t current, uint32_t total) override;
  virtual void synchronizationCompleted(std::error_code result) override;

  // ITransfersObserver
  virtual void onTransactionUpdated(ITransfersSubscription* object, const Crypto::Hash& transactionHash) override;
  virtual void onTransactionDeleted(ITransfersSubscription* object, const Crypto::Hash& transactionHash) override;

  void initSync();
  void throwIfNotInitialised();

  void save(std::ostream& destination, bool saveDetailed, bool saveCache, bool includeSentPayments);
  void doSave(std::ostream& destination, bool saveDetailed, bool saveCache, bool includeSentPayments);
  void rebuild(bool preserveSentPayments);
  void doLoad(std::istream& source);

  void synchronizationCallback(WalletRequest::Callback callback, std::error_code ec);
  void sendTransactionCallback(WalletRequest::Callback callback, std::error_code ec);
  void notifyClients(std::deque<std::shared_ptr<WalletLegacyEvent> >& events);
  void notifyIfBalanceChanged();
  // Announce PQ ledger history rows discovered since the last call via
  // externalTransactionCreated, so front-ends print incoming/outgoing notifications.
  void notifyExternalTransactions();

  PqWalletKeys deriveVerifiedSpendKeys(const CryptoPQ::SeedMaster& seedMaster) const;
  TransactionId sendTransactionImpl(const CryptoPQ::SeedMaster* seedMaster,
                                    const std::vector<WalletLegacyTransfer>& transfers,
                                    uint64_t fee, const std::string& extra,
                                    uint64_t ignoredPrivacyWidth,
                                    uint64_t unlockHeightstamp);
  std::string prepareRawTransactionImpl(const CryptoPQ::SeedMaster* seedMaster,
                                        TransactionId& transactionId,
                                        const std::vector<WalletLegacyTransfer>& transfers,
                                        uint64_t fee, const std::string& extra,
                                        uint64_t ignoredPrivacyWidth,
                                        uint64_t unlockHeightstamp);

  std::vector<TransactionId> deleteOutdatedUnconfirmedTransactions();

  uint64_t scanHeightToTimestamp(const uint32_t scanHeight);
  uint64_t getBlockTimestamp(const uint32_t blockHeight);

  enum WalletState
  {
    NOT_INITIALIZED = 0,
    INITIALIZED,
    LOADING,
    SAVING
  };

  WalletState m_state;
  mutable std::mutex m_cacheMutex;
  CryptoNote::AccountBase m_account;
  std::string m_password;
  const CryptoNote::Currency& m_currency;
  INode& m_node;

  // The block index a transaction built now expects to be validated at.
  //
  // Consensus judges a TX_PQ at the height of the block that carries it, and the
  // earliest such block is the one after the current tip. getLocalBlockCount() is
  // that index (tip + 1) and is the same quantity the node reports as its chain
  // height, so the wallet and the verifier read the activation boundary off the
  // same number.
  //
  // A transaction left in the mempool across the activation height is therefore
  // signed for a height it may no longer be mined at. Scheduling an activation
  // has to account for that window; see PQ_TRANSCRIPT_V2_HEIGHT, which is
  // deliberately unscheduled.
  uint32_t pqSigningHeight() const;
  Logging::LoggerRef m_logger;
  bool m_isStopping;

  std::atomic<uint64_t> m_lastNotifiedActualBalance;
  std::atomic<uint64_t> m_lastNotifiedPendingBalance;
  // Number of PQ ledger history rows already announced via externalTransactionCreated.
  std::atomic<size_t> m_lastNotifiedTransactionCount;

  BlockchainSynchronizer m_blockchainSync;
  // PQ output scanning is the sole sync driver. Tracking wallets use
  // m_pqTrackingKeys instead of a spend secret.
  std::unique_ptr<WalletLedgerConsumer> m_pqConsumer;
  std::unique_ptr<PqTrackingKeys> m_pqTrackingKeys;
  std::string m_pqProtectedSpendMetadata;

  // Payer-side recipient labels captured at send time (the counterparty address is
  // not recoverable from PQ output scanning). Keyed by txid, surfaced through the
  // legacy transfer accessors so the History view can show who a payment went to.
  // Serialized into the encrypted wallet independently of scan-cache retention.
  SentPaymentsStore m_sentPayments;

  WalletAsyncContextCounter m_asyncContextCounter;
  Tools::ObserverManager<CryptoNote::IWalletLegacyObserver> m_observerManager;

  std::unique_ptr<SyncStarter> m_onInitSyncStarter;
};

} //namespace CryptoNote
