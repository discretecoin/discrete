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

#include <functional>
#include <map>
#include <memory>
#include <queue>
#include <unordered_map>

#include "WalletIndices.h"

#include "Logging/LoggerRef.h"
#include <System/Dispatcher.h>
#include <System/Event.h>
#include "Transfers/BlockchainSynchronizer.h"
#include "Wallet/WalletLedgerConsumer.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/PqSender.h"
#include "Wallet/PaymentProofArchive.h"
#include "../CryptoNoteConfig.h"

namespace CryptoNote {

class Currency;
class INode;

class WalletGreen : public IWallet,
                    IBlockchainSynchronizerObserver,
                    IBlockchainConsumerObserver {
public:
  WalletGreen(System::Dispatcher& dispatcher, const Currency& currency, INode& node, Logging::ILogger& logger, uint32_t transactionSoftLockTime = CryptoNote::parameters::CRYPTONOTE_TX_SPENDABLE_AGE);
  virtual ~WalletGreen();

  INode& getNode() { return m_node; }
  bool isTestnet() const;

  // --- PQ (post-quantum) balance / spend (concrete; not on IWallet) ----------
  // Mirrors WalletLegacy. PQ is active from genesis. Full wallets derive this
  // state from the primary spend secret; tracking wallets hold a view-only audit
  // key that can scan balance/history but cannot spend or register account numbers.
  bool pqEnabled() const { return static_cast<bool>(m_pqConsumer); }
  uint64_t pqActualBalance() const;
  // What can actually be spent right now: confirmed (out of the mempool) AND past
  // its per-output unlock height. pqActualBalance() minus this is the locked/pending
  // remainder. Mirrors WalletLegacy::pqUnlockedBalance and simplewallet's "Available".
  uint64_t pqSpendableBalance() const;
  uint64_t pqActualBalance(const std::string& address) const;
  uint64_t pqSpendableBalance(const std::string& address) const;
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
  // `sourceAddresses` (empty = spend from any bucket) restricts the spend to inputs
  // owned by those of the wallet's own addresses — each is a PQ address, an H-I-A-T-C
  // account number, or a numeric address index, resolved to a deposit bucket. Under
  // AggregatedMultikey each deposit input is signed with its own derived spend key.
  // `changeAddress` (empty = the primary identity) routes any change to one of OUR
  // addresses/deposits; it must be ours.
  PqSendResult sendPqTransfer(const std::vector<PqSendOutput>& recipients,
                              uint64_t fee = 0, uint64_t unlockHeight = 0,
                              const std::vector<uint8_t>& extra = {},
                              const std::vector<std::string>& sourceAddresses = {},
                              const std::string& changeAddress = {},
                              const std::vector<std::string>& recipientAddresses = {});
  // Build and sign through the same PQ sender, but do not reserve inputs, mutate
  // wallet history, persist payment proofs, or relay to the node.
  PqSendResult preparePqTransfer(const std::vector<PqSendOutput>& recipients,
                                 uint64_t fee = 0, uint64_t unlockHeight = 0,
                                 const std::vector<uint8_t>& extra = {},
                                 const std::vector<std::string>& sourceAddresses = {},
                                 const std::string& changeAddress = {});
  const SentPaymentRecord* getPaymentProofs(const Crypto::Hash& txid) const;
  bool copyPaymentProofs(const Crypto::Hash& txid, SentPaymentRecord& record) const;
  Crypto::Hash importPaymentProofs(const std::string& bytes);
  bool deletePaymentProofs(const Crypto::Hash& txid,
                           std::size_t recipientIndex = static_cast<std::size_t>(-1));
  // Register this wallet's PQ identity with a fee-paying TX_PQ: a self-payment of
  // the smallest denomination whose tx.extra carries the account-registration tag.
  // Returns the built+relayed result. Throws on a tracking wallet / insufficient
  // funds. (The fee-free alternative is buildPqFreeRegTransaction.)
  PqSendResult registerPqAccountPaid();

  // --- Deposit-wallet scheme (Spec 1 aggregated-multikey / Spec 2 single-key-index)
  // The scheme is chosen ONCE at container creation and persisted; it cannot be
  // changed for an existing container. setPqDepositScheme throws if the container
  // already has deposit state (i.e. is not freshly created).
  // Offline (one-shot) mode: never start background synchronization. Set it before
  // touching the container in a lifecycle that only WRITES one — generating or
  // re-keying it — and exits. Such a run has nothing to sync, and starting the
  // synchronizer anyway means teardown must join a worker that may be parked in an
  // unbounded node call, which is what kept `--generate-container` alive instead of
  // exiting. Not persisted; it describes the process, not the container.
  void setOfflineMode(bool offline) { m_offlineMode = offline; }
  bool offlineMode() const { return m_offlineMode; }
  // Whether background synchronization is currently running (there is a worker
  // thread that shutdown() has to join).
  bool synchronizationStarted() const { return m_blockchainSynchronizerStarted; }

  PqDepositScheme getPqDepositScheme() const { return m_pqDepositScheme; }
  // The lowest deposit index this container's scheme may ever issue.
  //  - AggregatedMultikey: 0. Deposit #i carries its OWN spend key,
  //    deriveDepositSpendKeys(seed, i), distinct from the primary's at every i,
  //    so index 0 is a perfectly good deposit.
  //  - SingleKeyIndex: 1. Deposits there are only a subaddress index T under the
  //    one key pair, and T=0 is the primary address itself — a plain Bech32m PQ
  //    address and a base H-I-A-C account number both send at T=0. Issuing
  //    H-I-A-0-C would make primary receipts and deposit-0 receipts the same
  //    on-chain output, attributable to neither.
  uint32_t getPqFirstDepositIndex() const {
    return m_pqDepositScheme == PqDepositScheme::SingleKeyIndex ? 1u : 0u;
  }
  // How many deposit addresses this container has issued (NOT the next index).
  uint32_t getPqDepositCount() const {
    const uint32_t first = getPqFirstDepositIndex();
    return m_pqNextDepositIndex > first ? m_pqNextDepositIndex - first : 0u;
  }
  // The deposit index of the `ordinal`-th issued deposit (ordinal is 0-based, so
  // this is what getAddress(ordinal + 1) renders).
  uint32_t getPqDepositIndexAt(uint32_t ordinal) const { return getPqFirstDepositIndex() + ordinal; }
  void setPqDepositScheme(PqDepositScheme scheme);
  // Reserve and return the next deposit index (the Spec-1 deposit-key index, or the
  // Spec-2 subaddress T, which starts at 1). Advances the persisted cursor. Throws
  // on a tracking wallet.
  uint32_t reservePqDepositIndex();
  // The deposit address for `index` under THIS container's scheme:
  //  - AggregatedMultikey: Bech32m PQ address = (shared view key, deposit spend key
  //    #index). regBlockHeight/regTxIndex are ignored.
  //  - SingleKeyIndex: the H-I-A-T-C account number built from the account's on-chain
  //    registration coords (regBlockHeight=H, regTxIndex=I) and T=index. The caller
  //    resolves (H,I) from the node first.
  std::string pqDepositAddress(uint32_t index, uint32_t regBlockHeight, uint32_t regTxIndex) const;
  // The 20-bit key fingerprint (account-number field A) for THIS wallet's own
  // identity, on this network. Returns 0 for a tracking wallet (no spend keys).
  uint32_t pqAccountFingerprint() const;
  // Confirmed+unconfirmed PQ balance attributed to one deposit index, and the map
  // of all non-empty deposit balances by index (for walletd deposit attribution).
  uint64_t pqDepositBalance(uint32_t index) const;
  std::map<uint32_t, uint64_t> pqDepositBalances() const;
  // MANUAL RECOVERY WINDOW EXTENSION (SingleKeyIndex only) — OFF by default
  // and not persisted across process restarts. Normal scanning already covers
  // every issued T. Set maxT above the issued cursor before reset() only when
  // recovering a legacy output whose local address metadata was lost. The
  // runtime value survives reset()'s internal shutdown/load cycle.
  void enableLegacyDepositRescan(uint32_t maxT);

  virtual void initialize(const std::string& path, const std::string& password) override;
  virtual void initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& viewSecretKey) override;
  virtual void initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& viewSecretKey, const uint64_t& creationTimestamp) override;
  virtual void initializeWithViewKey(const std::string& path, const std::string& password, const Crypto::SecretKey& viewSecretKey, const uint32_t scanHeight) override;
  void initializeWithPqTrackingKey(const std::string& path, const std::string& password, const PqTrackingKeys& pqTrackingKeys);
  void initializeWithPqTrackingKey(const std::string& path, const std::string& password, const PqTrackingKeys& pqTrackingKeys, const uint64_t& creationTimestamp);
  void initializeWithPqTrackingKey(const std::string& path, const std::string& password, const PqTrackingKeys& pqTrackingKeys, const uint32_t scanHeight);
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
  virtual void deleteAddress(const std::string& address) override;

  virtual uint64_t getActualBalance() const override;
  virtual uint64_t getActualBalance(const std::string& address) const override;
  virtual uint64_t getPendingBalance() const override;
  virtual uint64_t getPendingBalance(const std::string& address) const override;

  virtual size_t getTransactionCount() const override;
  virtual WalletTransaction getTransaction(size_t transactionIndex) const override;

  virtual size_t getTransactionTransferCount(size_t transactionIndex) const override;
  virtual WalletTransfer getTransactionTransfer(size_t transactionIndex, size_t transferIndex) const override;

  virtual WalletTransactionWithTransfers getTransaction(const Crypto::Hash& transactionHash) const override;
  virtual std::vector<TransactionsInBlockInfo> getTransactions(const Crypto::Hash& blockHash, size_t count) const override;
  virtual std::vector<TransactionsInBlockInfo> getTransactions(uint32_t blockIndex, size_t count) const override;
  virtual std::vector<Crypto::Hash> getBlockHashes(uint32_t blockIndex, size_t count) const override;
  virtual uint32_t getBlockCount() const override;
  virtual std::vector<WalletTransactionWithTransfers> getUnconfirmedTransactions() const override;
  virtual std::vector<TransactionOutputInformation> getTransfers(size_t index, uint32_t flags) const override;

  virtual std::string signMessage(const std::string &message, const std::string& address) override;
  virtual bool verifyMessage(const std::string &message, const std::string& address, const std::string &signature) override;

  virtual size_t transfer(const TransactionParameters& sendingTransaction, Crypto::SecretKey& txSecretKey) override;
  size_t transfer(const TransactionParameters& sendingTransaction) {
    Crypto::SecretKey txSecretKey;
    return transfer(sendingTransaction, txSecretKey);
  }

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
    CryptoPQ::SeedMaster seedMaster{};
    bool tracking = false;
    uint64_t creationTimestamp = 0;
    uint32_t hdIndex = WALLET_INVALID_HD_INDEX;
  };

  void throwIfNotInitialized() const;
  void throwIfStopped() const;
  void throwIfTrackingMode() const;
  void doShutdown();
  void clearCaches(bool clearTransactions, bool clearCachedData);
  void convertAndLoadWalletFile(const std::string& path, std::ifstream&& walletFileStream);
  // Encrypt/decrypt a wallet record (PQ master seed + creation timestamp) under
  // this container's key and header. decryptSeed returns false for a wrong
  // password and for a tampered record alike.
  bool decryptSeed(const EncryptedWalletRecord& cipher, CryptoPQ::SeedMaster& seedMaster,
                   uint64_t& creationTimestamp) const;
  EncryptedWalletRecord encryptSeed(const CryptoPQ::SeedMaster& seedMaster,
                                    uint64_t creationTimestamp) const;
  // The container's authenticated header.
  const ContainerStoragePrefix& containerHeader() const;
  // Open a version-9 container, decrypt it with the legacy unsalted key, and
  // rewrite it in the current format under a fresh salt. The original file is
  // only replaced once the rewritten one has been reopened and authenticated.
  void migrateLegacyContainer(const std::string& path, const std::string& password);
  // Wipe every secret this wallet holds: the container key, the password, and
  // the master seeds in the address records.
  void wipeSecrets();

  // Return the object to a clean NOT_INITIALIZED state after a load that failed
  // at any point. Safe to call however far the attempt got, including when a
  // component was never created, and safe to call more than once.
  void abortLoad();

public:
  // True while any secret is still resident. Never exposes a secret; it lets the
  // daemon report state and lets tests assert that closing a wallet, or failing
  // to open one, leaves nothing behind.
  bool hasResidentSecrets() const;

  // Test-only fault injection, in the same spirit as Crypto::kdf_forced_failure().
  //
  // The steps that run after the container has been opened — building the PQ
  // consumer, seeding the blockchain, starting the synchronizer — fail only under
  // conditions a unit test cannot practically create, yet they are exactly the
  // window in which the container key and the master seeds are already resident.
  // Setting this makes load() throw at that point so the cleanup can be checked.
  // Production never sets it; load() only reads it.
  static std::function<void()>& loadFaultInjector();

private:
  // Set up a fresh (empty) PQ wallet container: the prefix holds only the version
  // — there is no classical view key. The primary seed lands as record 0 via the
  // first createAddress()/doCreateAddress().
  void initContainer(const std::string& path, const std::string& password);
  // The wallet's primary PQ master seed (record 0). Throws if there are no addresses.
  CryptoPQ::SeedMaster primarySeedMaster() const;
  // Bootstrap seed for the primary address: the deterministic/imported seed bytes if
  // set (HD/import mode), otherwise a fresh CSPRNG seed.
  CryptoPQ::SeedMaster createHdAddressData(uint64_t creationTimestamp);
  std::string doCreateAddress(const CryptoPQ::SeedMaster& seedMaster, bool tracking, uint64_t creationTimestamp, uint32_t hdIndex = WALLET_INVALID_HD_INDEX);
  std::vector<std::string> doCreateAddressList(const std::vector<NewAddressData>& addressDataList);

  uint64_t getBlockTimestamp(const uint32_t blockHeight);
  uint64_t scanHeightToTimestamp(const uint32_t scanHeight);
  uint64_t getCurrentTimestampAdjusted();

  // ContainerStoragePrefix + the seed-record codec live in WalletIndices.h so the
  // daemon's read-only mining-key loader shares the exact wallet file format.

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

  std::string addWallet(const CryptoPQ::SeedMaster& seedMaster, bool tracking, uint64_t creationTimestamp, uint32_t hdIndex = WALLET_INVALID_HD_INDEX);
  void pushEvent(const WalletEvent& event);
  // Push a TRANSACTION_CREATED event for every PQ ledger history row the scanner has
  // discovered since the last call, so consumers (walletd's refresh loop) learn of
  // newly received/sent transactions. Runs on the dispatcher thread under m_readyEvent.
  void pushNewTransactionEvents();

  // Native history index (transaction id) of a PQ transaction by hash, or
  // WALLET_INVALID_TRANSACTION_ID if it is not in the ledger. Takes the wallet lock.
  size_t pqHistoryIndex(const Crypto::Hash& txid) const;
  // Map one of our own PQ addresses to its ledger bucket: the primary address ->
  // PQ_PRIMARY_DEPOSIT, a deposit address -> its deposit index. Returns false for an
  // address that is not ours. No wallet lock taken (callers already hold the ready gate).
  bool pqResolveAddressBucket(const std::string& address, uint32_t& depositIndex) const;
  // The change-output template (recipient view/spend pubkeys + subaddress T) for one of
  // our buckets, built exactly as a payment to that address would be so the wallet
  // re-scans the change into the same bucket. PQ_PRIMARY_DEPOSIT -> primary identity.
  PqSendOutput pqChangeTemplate(uint32_t depositIndex) const;
  // The user-facing address string for a ledger bucket (PQ_PRIMARY_DEPOSIT -> the
  // primary address, else the deposit address). Unlike getAddress() this never
  // throws on a bucket outside the issued range — SingleKeyIndex scanning finds
  // funds at any T — and falls back to the primary address when the deposit form
  // cannot be rendered.
  std::string pqBucketAddress(uint32_t bucket) const;
  // Build the per-(own-)address WalletTransfer list for a tx from the ledger's
  // per-bucket net (transfersByDeposit): PQ_PRIMARY_DEPOSIT -> primary address, else
  // the deposit address. Falls back to a single primary-address transfer carrying
  // `fallbackNet` when the tx touched no resolvable bucket.
  std::vector<WalletTransfer> pqTransfersForTx(const Crypto::Hash& txid, int64_t fallbackNet) const;
  void startBlockchainSynchronizer();
  void stopBlockchainSynchronizer();
  // Create + register the PQ scanning consumer for the primary address. Full
  // wallets derive from a spend secret; tracking wallets use a PQ audit key.
  void initPqConsumer(const CryptoPQ::SeedMaster& seedMaster, const SynchronizationStart& syncStart);
  void initPqConsumer(const PqTrackingKeys& pqTrackingKeys, const SynchronizationStart& syncStart);
  void initPqConsumerForPrimary();
  // Serialize the PQ consumer's sync cursor + WalletLedger into m_pqState (for
  // save), and restore them from m_pqState into a live consumer (after load).
  void buildPqStateBlob();
  void restorePqStateBlob();
  // Push the current deposit scheme + count into the live WalletLedger so its
  // scanner attributes incoming deposits. Safe no-op without a PQ consumer.
  void syncPqDepositConfigToState();
  // Lift the issuance cursor to the scheme's first issuable index. Call after the
  // scheme is chosen or read back: a fresh container starts the cursor at 0, and a
  // <=v0.9.6 SingleKeyIndex container persisted a plain COUNT whose value 0 or 1
  // both mean "nothing issuable remains below T=1".
  void normalizePqDepositCursor();
  // Resolve (and cache) this wallet's own PQ registration coords (H,I) from the
  // node, needed to render SingleKeyIndex (H-I-A-T-C) deposit addresses. Returns
  // false if not registered / unavailable.
  bool pqRegistrationCoords(uint32_t& height, uint32_t& txIndex) const;
  void addUnconfirmedTransaction(const ITransactionReader& transaction);
  void removeUnconfirmedTransaction(const Crypto::Hash& transactionHash);

  // Re-encrypt every seed record from src into dst. dst carries its own header,
  // so the records are bound to it and cannot be moved back.
  void copyContainerStorageKeys(ContainerStorage& src, const Crypto::chacha8_key& srcKey,
                                ContainerStorage& dst, const Crypto::chacha8_key& dstKey,
                                const ContainerStoragePrefix& dstHeader);
  void deleteOrphanTransactions(const std::unordered_set<Crypto::PublicKey>& deletedKeys);
  static void encryptAndSaveContainerData(ContainerStorage& storage, const Crypto::chacha8_key& key,
                                          const void* containerData, size_t containerDataSize);
  static void loadAndDecryptContainerData(ContainerStorage& storage, const Crypto::chacha8_key& key,
                                          BinaryArray& containerData);
  void loadSpendKeys();
  void loadContainerStorage(const std::string& path, const std::string& password);
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

  std::vector<TransactionsInBlockInfo> getTransactionsInBlocks(uint32_t blockIndex, size_t count) const;
  Crypto::Hash getBlockHashByIndex(uint32_t blockIndex) const;

  void initBlockchain();

  System::Dispatcher& m_dispatcher;
  const Currency& m_currency;
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
  mutable Logging::LoggerRef m_logger;
  bool m_stopped;

  WalletsContainer m_walletsContainer;
  ContainerStorage m_containerStorage;

  bool m_blockchainSynchronizerStarted;
  // See setOfflineMode(). Deliberately NOT cleared by doShutdown(): a one-shot
  // lifecycle keeps it across the internal save/shutdown/load reset.
  bool m_offlineMode = false;
  BlockchainSynchronizer m_blockchainSynchronizer;
  // PQ output scanning consumer (created lazily for the primary address when a
  // spend secret or PQ tracking credential is present). It is the sole consumer
  // driving the BlockchainSynchronizer.
  std::unique_ptr<WalletLedgerConsumer> m_pqConsumer;
  std::unique_ptr<PqTrackingKeys> m_pqTrackingKeys;
  SentPaymentsStore m_sentPayments;

  System::Event m_eventOccurred;
  std::queue<WalletEvent> m_events;
  mutable System::Event m_readyEvent;

  WalletState m_state;

  std::string m_password;
  Crypto::chacha8_key m_key;
  std::string m_path;
  std::string m_extra; // workaround for wallet reset
  std::string m_pqState; // persisted PQ consumer cursor + WalletLedger (see save/loadPqState)
  // Number of PQ ledger history rows already announced via TRANSACTION_CREATED.
  // Baselined to the loaded history after restore so a reload does not re-announce
  // past transactions; rows discovered during this session grow past it and fire.
  size_t m_pqNotifiedTxCount = 0;
  // Deposit-wallet scheme + the next deposit index to hand out. Persisted inside
  // m_pqState (a third framed section); defaults apply to pre-deposit containers.
  // The cursor is an INDEX, not a count: the first issuable index depends on the
  // scheme (see pqFirstDepositIndex), so the issued-deposit count is the difference.
  PqDepositScheme m_pqDepositScheme = PqDepositScheme::AggregatedMultikey;
  uint32_t m_pqNextDepositIndex = 0;
  // True once the scheme has been chosen (at creation) or read back from a
  // persisted container; makes setPqDepositScheme reject any later change.
  bool m_pqDepositSchemeChosen = false;
  // Volatile operator extension for legacy-v1 scanning beyond the persisted
  // issued cursor. Kept on WalletGreen so reset() can rebuild WalletLedger
  // without losing it; deliberately returns to zero in a new process.
  uint32_t m_pqLegacyTWindowMaxT = 0;
  // Cache of this wallet's own PQ registration coords (H,I), resolved from the node
  // the first time a SingleKeyIndex (H-I-A-T-C) deposit address must be rendered.
  mutable bool m_pqRegResolved = false;
  mutable uint32_t m_pqRegHeight = 0;
  mutable uint32_t m_pqRegTxIndex = 0;

  AddressGenerationMode m_addressGenerationMode;
  // Deterministic/imported PQ master seed (32 bytes). When set (HD or import mode),
  // the primary address (record 0) is bootstrapped from these bytes; otherwise a
  // fresh CSPRNG seed is minted. Empty for the default "mint a random seed" path.
  Crypto::SecretKey m_deterministicSeed;
  uint32_t m_nextDeterministicIndex;

  uint64_t m_upperTransactionSizeLimit;
  uint32_t m_transactionSoftLockTime;

  BlockHashesContainer m_blockchain;

  friend std::ostream& operator<<(std::ostream& os, CryptoNote::WalletGreen::WalletState state);
  friend std::ostream& operator<<(std::ostream& os, CryptoNote::WalletGreen::WalletTrackingMode mode);
};

} //namespace CryptoNote
