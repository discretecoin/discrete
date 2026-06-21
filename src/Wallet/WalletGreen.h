// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
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

#pragma once

#include "IWallet.h"

#include <map>
#include <memory>
#include <queue>
#include <unordered_map>

#include "WalletIndices.h"

#include "Logging/LoggerRef.h"
#include <System/Dispatcher.h>
#include <System/Event.h>
#include "Transfers/TransfersSynchronizer.h"
#include "Transfers/BlockchainSynchronizer.h"
#include "Wallet/WalletLedgerConsumer.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/PqSender.h"
#include "../CryptoNoteConfig.h"

namespace CryptoNote {

class WalletGreen : public IWallet,
                    IBlockchainSynchronizerObserver,
                    IBlockchainConsumerObserver {
public:
  WalletGreen(System::Dispatcher& dispatcher, const Currency& currency, INode& node, Logging::ILogger& logger, uint32_t transactionSoftLockTime = CryptoNote::parameters::CRYPTONOTE_TX_SPENDABLE_AGE);
  virtual ~WalletGreen();

  INode& getNode() { return m_node; }

  // --- PQ (post-quantum) balance / spend (concrete; not on IWallet) ----------
  // Mirrors WalletLegacy. PQ is active from genesis. Full wallets derive this
  // state from the primary spend secret; tracking wallets hold a view-only audit
  // key that can scan balance/history but cannot spend or register account numbers.
  bool pqEnabled() const { return static_cast<bool>(m_pqConsumer); }
  uint64_t pqActualBalance() const;
  std::vector<PqSpendInput> pqSpendableInputs() const;
  uint32_t pqSyncedHeight() const;
  // The wallet's address (base58). Full wallets derive it from the primary spend
  // secret; tracking wallets use their imported audit key.
  std::string getPqAddress() const;
  bool getPqTrackingKeys(PqTrackingKeys& keys) const;
  // Hex-encode this wallet's identity pubkeys (view, spend) for account-number
  // registration queries. Returns false for tracking wallets because registration
  // is intentionally spend-authority-only.
  bool getPqRegistrationKeysHex(std::string& viewHex, std::string& spendHex) const;
  // Build a signed TX_FREE_REG registering this wallet's PQ identity, grinding the
  // anti-spam PoW against `refBlockHash` (a recent main-chain block). The caller
  // relays the returned transaction. Throws on a tracking wallet.
  Transaction buildPqFreeRegTransaction(const Crypto::Hash& refBlockHash) const;
  // Build (denominate, two-pass fee, sign) and relay a PQ transfer to already-resolved
  // recipients via the common sender. Returns the result (tx + fee + sent). Throws on a
  // tracking wallet, insufficient funds, or relay failure. The single PQ spend path
  // shared with WalletLegacy/simplewallet.
  PqSendResult sendPqTransfer(const std::vector<PqSendOutput>& recipients,
                              uint64_t fee = 0, uint64_t unlockHeight = 0,
                              const std::vector<uint8_t>& extra = {});
  // Register this wallet's PQ identity with a fee-paying TX_PQ: a self-payment of
  // the smallest denomination whose tx.extra carries the account-registration tag.
  // Returns the built+relayed result. Throws on a tracking wallet / insufficient
  // funds. (The fee-free alternative is buildPqFreeRegTransaction.)
  PqSendResult registerPqAccountPaid();

  // --- Deposit-wallet scheme (Spec 1 aggregated-multikey / Spec 2 single-key-index)
  // The scheme is chosen ONCE at container creation and persisted; it cannot be
  // changed for an existing container. setPqDepositScheme throws if the container
  // already has deposit state (i.e. is not freshly created).
  PqDepositScheme getPqDepositScheme() const { return m_pqDepositScheme; }
  uint32_t getPqDepositCount() const { return m_pqDepositCount; }
  void setPqDepositScheme(PqDepositScheme scheme);
  // Reserve and return the next deposit index (the Spec-1 deposit-key index, or the
  // Spec-2 subaddress T). Increments the persisted deposit count. Throws on a
  // tracking wallet.
  uint32_t reservePqDepositIndex();
  // The deposit address for `index` under THIS container's scheme:
  //  - AggregatedMultikey: base58 PQ address = (shared view key, deposit spend key
  //    #index). regBlockHeight/regTxIndex are ignored.
  //  - SingleKeyIndex: the H-I-T-C account number built from the account's on-chain
  //    registration coords (regBlockHeight=H, regTxIndex=I) and T=index. The caller
  //    resolves (H,I) from the node first.
  std::string pqDepositAddress(uint32_t index, uint32_t regBlockHeight, uint32_t regTxIndex) const;
  // Confirmed+unconfirmed PQ balance attributed to one deposit index, and the map
  // of all non-empty deposit balances by index (for walletd deposit attribution).
  uint64_t pqDepositBalance(uint32_t index) const;
  std::map<uint32_t, uint64_t> pqDepositBalances() const;

  virtual void initialize(const std::string& path, const std::string& password) override;
  virtual void initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& viewSecretKey) override;
  virtual void initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& viewSecretKey, const uint64_t& creationTimestamp) override;
  virtual void initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& viewSecretKey, const uint32_t scanHeight) override;
  void initializeWithPqTrackingKey(const std::string& path, const std::string& password, const PqTrackingKeys& pqTrackingKeys);
  void initializeWithPqTrackingKey(const std::string& path, const std::string& password, const PqTrackingKeys& pqTrackingKeys, const uint64_t& creationTimestamp);
  virtual void load(const std::string& path, const std::string& password, std::string& extra) override;
  virtual void load(const std::string& path, const std::string& password) override;
  virtual void shutdown() override;

  virtual void changePassword(const std::string& oldPassword, const std::string& newPassword) override;
  virtual void save(WalletSaveLevel saveLevel = WalletSaveLevel::SAVE_ALL, const std::string& extra = "") override;
  virtual void reset(const uint64_t scanHeight) override;
  virtual void exportWallet(const std::string& path, bool encrypt = true, WalletSaveLevel saveLevel = WalletSaveLevel::SAVE_ALL, const std::string& extra = "") override;

  virtual size_t getAddressCount() const override;
  virtual std::string getAddress(size_t index) const override;
  virtual AccountPublicAddress getAccountPublicAddress(size_t index) const override;
  virtual bool isMyAddress(const std::string& address) const override;
  virtual KeyPair getAddressSpendKey(size_t index) const override;
  virtual KeyPair getAddressSpendKey(const std::string& address) const override;
  virtual KeyPair getViewKey() const override;
  virtual AddressGenerationMode getAddressGenerationMode() const override;
  virtual Crypto::SecretKey getDeterministicSeed() const override;
  virtual void setAddressGenerationMode(AddressGenerationMode mode, const Crypto::SecretKey& deterministicSeed) override;
  virtual std::string createAddress() override;
  virtual std::string createAddress(uint32_t scanHeight) override;
  virtual std::string createAddress(const Crypto::SecretKey& spendSecretKey, bool reset = true) override;
  virtual std::string createAddress(const Crypto::PublicKey& spendPublicKey, bool reset = true) override;
  virtual std::string createAddress(const Crypto::SecretKey& spendSecretKey, const uint64_t& creationTimestamp) override;
  virtual std::string createAddress(const Crypto::PublicKey& spendPublicKey, const uint64_t& creationTimestamp) override;
  virtual std::string createAddress(const Crypto::SecretKey& spendSecretKey, const uint32_t scanHeight) override;
  virtual std::string createAddress(const Crypto::PublicKey& spendPublicKey, const uint32_t scanHeight) override;
  virtual std::vector<std::string> createAddressList(const std::vector<Crypto::SecretKey>& spendSecretKeys, bool reset = true) override;
  virtual std::vector<std::string> createAddressList(const std::vector<Crypto::SecretKey>& spendSecretKeys, const std::vector<uint64_t>&creationTimestamps) override;
  virtual std::vector<std::string> createAddressList(const std::vector<Crypto::SecretKey>& spendSecretKeys, const std::vector<uint32_t>& scanHeights) override;
  virtual void deleteAddress(const std::string& address) override;

  virtual uint64_t getActualBalance() const override;
  virtual uint64_t getActualBalance(const std::string& address) const override;
  virtual uint64_t getPendingBalance() const override;
  virtual uint64_t getPendingBalance(const std::string& address) const override;

  virtual size_t getTransactionCount() const override;
  virtual WalletTransaction getTransaction(size_t transactionIndex) const override;
  virtual Crypto::SecretKey getTransactionSecretKey(size_t transactionIndex) const override;
  virtual Crypto::SecretKey getTransactionSecretKey(Crypto::Hash& transactionHash) const override;

  virtual bool getTransactionProof(const Crypto::Hash& transactionHash, const CryptoNote::AccountPublicAddress& destinationAddress, const Crypto::SecretKey& txKey, std::string& transactionProof) override;

  virtual size_t getTransactionTransferCount(size_t transactionIndex) const override;
  virtual WalletTransfer getTransactionTransfer(size_t transactionIndex, size_t transferIndex) const override;

  virtual WalletTransactionWithTransfers getTransaction(const Crypto::Hash& transactionHash) const override;
  virtual std::vector<TransactionsInBlockInfo> getTransactions(const Crypto::Hash& blockHash, size_t count) const override;
  virtual std::vector<TransactionsInBlockInfo> getTransactions(uint32_t blockIndex, size_t count) const override;
  virtual std::vector<Crypto::Hash> getBlockHashes(uint32_t blockIndex, size_t count) const override;
  virtual uint32_t getBlockCount() const override;
  virtual std::vector<WalletTransactionWithTransfers> getUnconfirmedTransactions() const override;
  virtual std::vector<size_t> getDelayedTransactionIds() const override;
  virtual std::vector<TransactionOutputInformation> getTransfers(size_t index, uint32_t flags) const override;

  virtual std::string signMessage(const std::string &message, const std::string& address) override;
  virtual bool verifyMessage(const std::string &message, const std::string& address, const std::string &signature) override;

  virtual size_t transfer(const TransactionParameters& sendingTransaction, Crypto::SecretKey& txSecretKey) override;
  size_t transfer(const TransactionParameters& sendingTransaction) {
    Crypto::SecretKey txSecretKey;
    return transfer(sendingTransaction, txSecretKey);
  }

  virtual size_t makeTransaction(const TransactionParameters& sendingTransaction) override;
  virtual void commitTransaction(size_t) override;
  virtual void rollbackUncommitedTransaction(size_t) override;

  virtual void start() override;
  virtual void stop() override;
  virtual WalletEvent getEvent() override;

  void updateInternalCache();
  size_t getMaxTxSize();
  bool txIsTooLarge(const TransactionParameters& sendingTransaction);
  void clearCaches() { return clearCaches(true, true); };
  size_t getTxSize(const TransactionParameters &sendingTransaction);
  void clearCacheAndShutdown();
  void createViewWallet(const std::string &password, const std::string address, const Crypto::SecretKey &viewSecretKey, const std::string& path);

  uint64_t getBalanceMinusDust(const std::vector<std::string>& addresses);

protected:
  struct NewAddressData {
    Crypto::PublicKey spendPublicKey;
    Crypto::SecretKey spendSecretKey;
    uint64_t creationTimestamp;
    uint32_t hdIndex = WALLET_INVALID_HD_INDEX;
  };

  void throwIfNotInitialized() const;
  void throwIfStopped() const;
  void throwIfTrackingMode() const;
  void doShutdown();
  void clearCaches(bool clearTransactions, bool clearCachedData);
  void convertAndLoadWalletFile(const std::string& path, std::ifstream&& walletFileStream);
  static void decryptKeyPair(const EncryptedWalletRecord& cipher, Crypto::PublicKey& publicKey, Crypto::SecretKey& secretKey,
    uint64_t& creationTimestamp, const Crypto::chacha8_key& key);
  void decryptKeyPair(const EncryptedWalletRecord& cipher, Crypto::PublicKey& publicKey, Crypto::SecretKey& secretKey, uint64_t& creationTimestamp) const;
  static EncryptedWalletRecord encryptKeyPair(const Crypto::PublicKey& publicKey, const Crypto::SecretKey& secretKey, uint64_t creationTimestamp,
    const Crypto::chacha8_key& key, const Crypto::chacha8_iv& iv);
  EncryptedWalletRecord encryptKeyPair(const Crypto::PublicKey& publicKey, const Crypto::SecretKey& secretKey, uint64_t creationTimestamp) const;
  Crypto::chacha8_iv getNextIv() const;
  static void incIv(Crypto::chacha8_iv& iv);
  void incNextIv();
  void initWithKeys(const std::string& path, const std::string& password, const Crypto::PublicKey& viewPublicKey, const Crypto::SecretKey& viewSecretKey, const uint64_t& _creationTimestamp);
  CryptoNote::KeyPair deriveHdSpendKey(uint32_t hdIndex) const;
  NewAddressData createHdAddressData(uint64_t creationTimestamp);
  std::string doCreateAddress(const Crypto::PublicKey& spendPublicKey, const Crypto::SecretKey& spendSecretKey, uint64_t creationTimestamp, uint32_t hdIndex = WALLET_INVALID_HD_INDEX);
  std::vector<std::string> doCreateAddressList(const std::vector<NewAddressData>& addressDataList);

  Crypto::SecretKey getTransactionDeterministicSecretKey(Crypto::Hash& transactionHash) const;

  uint64_t getBlockTimestamp(const uint32_t blockHeight);
  uint64_t scanHeightToTimestamp(const uint32_t scanHeight);
  uint64_t getCurrentTimestampAdjusted();

  typedef std::pair<WalletTransfers::const_iterator, WalletTransfers::const_iterator> TransfersRange;

#pragma pack(push, 1)
  struct ContainerStoragePrefix {
    uint8_t version;
    Crypto::chacha8_iv nextIv;
    EncryptedWalletRecord encryptedViewKeys;
  };
#pragma pack(pop)

  virtual void synchronizationProgressUpdated(uint32_t processedBlockCount, uint32_t totalBlockCount) override;
  virtual void synchronizationCompleted(std::error_code result) override;

  void onSynchronizationProgressUpdated(uint32_t processedBlockCount, uint32_t totalBlockCount);
  void onSynchronizationCompleted();

  void blocksAdded(const std::vector<Crypto::Hash>& blockHashes);
  void blocksRollback(uint32_t blockIndex);

  // IBlockchainConsumerObserver: the PQ ledger consumer is the sole sync driver, so
  // the block list (m_blockchain) and reorg notifications come straight from it.
  virtual void onBlocksAdded(IBlockchainConsumer* consumer, const std::vector<Crypto::Hash>& blockHashes) override;
  virtual void onBlockchainDetach(IBlockchainConsumer* consumer, uint32_t blockIndex) override;

  std::string addWallet(const Crypto::PublicKey& spendPublicKey, const Crypto::SecretKey& spendSecretKey, uint64_t creationTimestamp, uint32_t hdIndex = WALLET_INVALID_HD_INDEX);
  size_t getTransactionId(const Crypto::Hash& transactionHash) const;
  void pushEvent(const WalletEvent& event);

  // Native history index (transaction id) of a PQ transaction by hash, or
  // WALLET_INVALID_TRANSACTION_ID if it is not in the ledger. Takes the wallet lock.
  size_t pqHistoryIndex(const Crypto::Hash& txid) const;
  void updateTransactionStateAndPushEvent(size_t transactionId, WalletTransactionState state);
  void startBlockchainSynchronizer();
  void stopBlockchainSynchronizer();
  // Create + register the PQ scanning consumer for the primary address. Full
  // wallets derive from a spend secret; tracking wallets use a PQ audit key.
  void initPqConsumer(const Crypto::SecretKey& spendSecretKey, const SynchronizationStart& syncStart);
  void initPqConsumer(const PqTrackingKeys& pqTrackingKeys, const SynchronizationStart& syncStart);
  void initPqConsumerForPrimary();
  // Serialize the PQ consumer's sync cursor + WalletLedger into m_pqState (for
  // save), and restore them from m_pqState into a live consumer (after load).
  void buildPqStateBlob();
  void restorePqStateBlob();
  // Push the current deposit scheme + count into the live WalletLedger so its
  // scanner attributes incoming deposits. Safe no-op without a PQ consumer.
  void syncPqDepositConfigToState();
  // Resolve (and cache) this wallet's own PQ registration coords (H,I) from the
  // node, needed to render SingleKeyIndex (H-I-T-C) deposit addresses. Returns
  // false if not registered / unavailable.
  bool pqRegistrationCoords(uint32_t& height, uint32_t& txIndex) const;
  void addUnconfirmedTransaction(const ITransactionReader& transaction);
  void removeUnconfirmedTransaction(const Crypto::Hash& transactionHash);

  void copyContainerStorageKeys(ContainerStorage& src, const Crypto::chacha8_key& srcKey, ContainerStorage& dst, const Crypto::chacha8_key& dstKey);
  static void copyContainerStoragePrefix(ContainerStorage& src, const Crypto::chacha8_key& srcKey, ContainerStorage& dst, const Crypto::chacha8_key& dstKey);
  void deleteOrphanTransactions(const std::unordered_set<Crypto::PublicKey>& deletedKeys);
  static void encryptAndSaveContainerData(ContainerStorage& storage, const Crypto::chacha8_key& key, const void* containerData, size_t containerDataSize);
  static void loadAndDecryptContainerData(ContainerStorage& storage, const Crypto::chacha8_key& key, BinaryArray& containerData);
  void loadSpendKeys();
  void loadContainerStorage(const std::string& path);
  void loadWalletCache(std::unordered_set<Crypto::PublicKey>& addedKeys, std::unordered_set<Crypto::PublicKey>& deletedKeys, std::string& extra);
  void saveWalletCache(ContainerStorage& storage, const Crypto::chacha8_key& key, WalletSaveLevel saveLevel, const std::string& extra);

  enum class WalletState {
    INITIALIZED,
    NOT_INITIALIZED
  };

  enum class WalletTrackingMode {
    TRACKING,
    NOT_TRACKING,
    NO_ADDRESSES
  };

  WalletTrackingMode getTrackingMode() const;

  TransfersRange getTransactionTransfersRange(size_t transactionIndex) const;
  std::vector<TransactionsInBlockInfo> getTransactionsInBlocks(uint32_t blockIndex, size_t count) const;
  Crypto::Hash getBlockHashByIndex(uint32_t blockIndex) const;

  std::vector<WalletTransfer> getTransactionTransfers(const WalletTransaction& transaction) const;
  void filterOutTransactions(WalletTransactions& transactions, WalletTransfers& transfers, std::function<bool (const WalletTransaction&)>&& pred) const;
  void initBlockchain(const Crypto::PublicKey& viewPublicKey);

  std::vector<size_t> deleteTransfersForAddress(const std::string& address, std::vector<size_t>& deletedTransactions);
  void deleteFromUncommitedTransactions(const std::vector<size_t>& deletedTransactions);

  System::Dispatcher& m_dispatcher;
  const Currency& m_currency;
  INode& m_node;
  mutable Logging::LoggerRef m_logger;
  bool m_stopped;

  WalletsContainer m_walletsContainer;
  ContainerStorage m_containerStorage;
  UnlockTransactionJobs m_unlockTransactionsJob;
  WalletTransactions m_transactions;
  WalletTransfers m_transfers; //sorted
  UncommitedTransactions m_uncommitedTransactions;

  bool m_blockchainSynchronizerStarted;
  BlockchainSynchronizer m_blockchainSynchronizer;
  // PQ output scanning consumer (created lazily for the primary address when a
  // spend secret or PQ tracking credential is present). It is the sole consumer
  // driving the BlockchainSynchronizer.
  std::unique_ptr<WalletLedgerConsumer> m_pqConsumer;
  std::unique_ptr<PqTrackingKeys> m_pqTrackingKeys;

  System::Event m_eventOccurred;
  std::queue<WalletEvent> m_events;
  mutable System::Event m_readyEvent;

  WalletState m_state;

  std::string m_password;
  Crypto::chacha8_key m_key;
  std::string m_path;
  std::string m_extra; // workaround for wallet reset
  std::string m_pqState; // persisted PQ consumer cursor + WalletLedger (see save/loadPqState)
  // Deposit-wallet scheme + how many deposit addresses have been issued. Persisted
  // inside m_pqState (a third framed section); defaults apply to pre-deposit containers.
  PqDepositScheme m_pqDepositScheme = PqDepositScheme::AggregatedMultikey;
  uint32_t m_pqDepositCount = 0;
  // True once the scheme has been chosen (at creation) or read back from a
  // persisted container; makes setPqDepositScheme reject any later change.
  bool m_pqDepositSchemeChosen = false;
  // Cache of this wallet's own PQ registration coords (H,I), resolved from the node
  // the first time a SingleKeyIndex (H-I-T-C) deposit address must be rendered.
  mutable bool m_pqRegResolved = false;
  mutable uint32_t m_pqRegHeight = 0;
  mutable uint32_t m_pqRegTxIndex = 0;

  Crypto::PublicKey m_viewPublicKey;
  Crypto::SecretKey m_viewSecretKey;
  AddressGenerationMode m_addressGenerationMode;
  Crypto::SecretKey m_deterministicSeed;
  uint32_t m_nextDeterministicIndex;

  uint64_t m_actualBalance;
  uint64_t m_pendingBalance;

  uint64_t m_upperTransactionSizeLimit;
  uint32_t m_transactionSoftLockTime;

  BlockHashesContainer m_blockchain;

  friend std::ostream& operator<<(std::ostream& os, CryptoNote::WalletGreen::WalletState state);
  friend std::ostream& operator<<(std::ostream& os, CryptoNote::WalletGreen::WalletTrackingMode mode);
  friend class TransferListFormatter;
};

} //namespace CryptoNote
