// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

#include <atomic>
#include <unordered_map>
#include <parallel_hashmap/phmap.h>

#include "Common/ObserverManager.h"
#include "Common/Util.h"
#include "Checkpoints/Checkpoints.h"
#include "CryptoNoteCore/BlockStats.h"
#include "CryptoNoteCore/FinalityForkState.h"
#include "CryptoNoteCore/LMDBBlockchainDB.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/IBlockchainStorageObserver.h"
#include "CryptoNoteCore/ICore.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteCore/ITransactionValidator.h"
#include "CryptoNoteCore/SwappedVector.h"        // kept for migrateFromSwappedVector
#include "CryptoNoteCore/UpgradeDetector.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/TransactionPool.h"

#include "CryptoNoteCore/MessageQueue.h"
#include "CryptoNoteCore/BlockchainMessages.h"
#include "CryptoNoteCore/IntrusiveLinkedList.h"

#include <Logging/LoggerRef.h>

#undef ERROR

using phmap::parallel_flat_hash_map;

namespace CryptoNote {

  struct NOTIFY_REQUEST_GET_OBJECTS_request;
  struct NOTIFY_RESPONSE_GET_OBJECTS_request;

  using CryptoNote::BlockInfo;
  class Blockchain : public CryptoNote::ITransactionValidator {
  public:
    Blockchain(const Currency& currency, tx_memory_pool& tx_pool, Logging::ILogger& logger);

    bool addObserver(IBlockchainStorageObserver* observer);
    bool removeObserver(IBlockchainStorageObserver* observer);

    // Commit any pending batch write txn immediately.  Called at clean shutdown
    // and before operations that need fully-committed state.
    bool flushBatch();

    // ITransactionValidator
    virtual bool checkTransactionInputs(const CryptoNote::Transaction& tx, BlockInfo& maxUsedBlock) override;
    virtual bool checkTransactionInputs(const CryptoNote::Transaction& tx, BlockInfo& maxUsedBlock, BlockInfo& lastFailed) override;
    virtual bool haveSpentKeyImages(const CryptoNote::Transaction& tx) override;
    virtual bool checkTransactionSize(size_t blobSize) override;

    bool init() { return init(Tools::getDefaultDataDirectory(), true); }
    bool init(const std::string& config_folder, bool load_existing);
    bool deinit();

    bool getLowerBound(uint64_t timestamp, uint64_t startOffset, uint32_t& height);
    std::vector<Crypto::Hash> getBlockIds(uint32_t startHeight, uint32_t maxCount);

    void setCheckpoints(Checkpoints&& chk_pts) { m_checkpoints = chk_pts; }
    bool getBlocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks, std::list<Transaction>& txs);
    bool getBlocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks);
    bool getWalletSyncBlocks(uint32_t startHeight, uint32_t blockCount,
                             uint32_t& currentHeight,
                             std::vector<WalletSyncBlockInfo>& blocks);
    bool getTransactionsWithOutputGlobalIndexes(const std::vector<Crypto::Hash>& txs_ids,
                                                std::list<Crypto::Hash>& missed_txs,
                                                std::vector<std::pair<Transaction, std::vector<uint32_t>>>& txs);
    bool getAlternativeBlocks(std::list<Block>& blocks);
    uint32_t getAlternativeBlocksCount();
    Crypto::Hash getBlockIdByHeight(uint32_t height);
    bool getBlockByHash(const Crypto::Hash& h, Block& blk);
    bool getBlockHeight(const Crypto::Hash& blockId, uint32_t& blockHeight);
    bool getTransactionHeight(const Crypto::Hash& txId, uint32_t& blockHeight);

    bool haveTransaction(const Crypto::Hash& id);
    bool haveTransactionKeyImagesAsSpent(const Transaction& tx);

    uint32_t getCurrentBlockchainHeight();
    Crypto::Hash getTailId();
    Crypto::Hash getTailId(uint32_t& height);
    Difficulty getDifficultyForNextBlock(const Crypto::Hash& prevHash);
    uint64_t getBlockTimestamp(uint32_t height);
    uint64_t getCoinsInCirculation();
    uint64_t getCoinsInCirculation(uint32_t height);
    bool getPqTransactionFee(const Transaction& tx, uint64_t& fee);
    uint8_t getBlockMajorVersionForHeight(uint32_t height) const;
    bool addNewBlock(const Block& bl, block_verification_context& bvc,
                     const PrevalidatedBlockProof* prevalidatedProof = nullptr);
    bool resetAndSetGenesisBlock(const Block& b);
    bool haveBlock(const Crypto::Hash& id);
    size_t getTotalTransactions();
    std::vector<Crypto::Hash> buildSparseChain();
    std::vector<Crypto::Hash> buildSparseChain(const Crypto::Hash& startBlockId);
    uint32_t findBlockchainSupplement(const std::vector<Crypto::Hash>& qblock_ids);
    std::vector<Crypto::Hash> findBlockchainSupplement(const std::vector<Crypto::Hash>& remoteBlockIds,
                                                        size_t maxCount,
                                                        uint32_t& totalBlockCount,
                                                        uint32_t& startBlockIndex);
    bool handleGetObjects(NOTIFY_REQUEST_GET_OBJECTS_request& arg,
                          NOTIFY_RESPONSE_GET_OBJECTS_request& rsp);
    bool getBackwardBlocksSize(size_t from_height, std::vector<size_t>& sz, size_t count);
    bool getTransactionOutputGlobalIndexes(const Crypto::Hash& tx_id, std::vector<uint32_t>& indexs);
    bool checkTransactionInputs(const Transaction& tx, uint32_t& pmax_used_block_height,
                                 Crypto::Hash& max_used_block_id, BlockInfo* tail = 0);
    uint64_t getCurrentCumulativeBlocksizeLimit();
    uint64_t blockDifficulty(size_t i);
    uint64_t blockCumulativeDifficulty(size_t i);
    bool getblockEntry(size_t i, uint64_t& block_cumulative_size, Difficulty& difficulty,
                       uint64_t& already_generated_coins, uint64_t& reward,
                       uint64_t& transactions_count, uint64_t& timestamp);
    bool getBlockStats(uint32_t startHeight, uint32_t endHeight, std::vector<BlockStatsEntry>& stats);
    bool getBlockStats(const std::vector<uint32_t>& heights, std::vector<BlockStatsEntry>& stats);
    bool getBlockContainingTransaction(const Crypto::Hash& txId, Crypto::Hash& blockId,
                                        uint32_t& blockHeight);
    bool getAlreadyGeneratedCoins(const Crypto::Hash& hash, uint64_t& generatedCoins);
    bool getBlockSize(const Crypto::Hash& hash, size_t& size);
    bool getGeneratedTransactionsNumber(uint32_t height, uint64_t& generatedTransactions);
    bool getOrphanBlockIdsByHeight(uint32_t height, std::vector<Crypto::Hash>& blockHashes);
    bool getBlockIdsByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd,
                                 uint32_t blocksNumberLimit,
                                 std::vector<Crypto::Hash>& hashes,
                                 uint32_t& blocksNumberWithinTimestamps);
    bool getTransactionIdsByPaymentId(const Crypto::Hash& paymentId,
                                       std::vector<Crypto::Hash>& transactionHashes);
    bool isBlockInMainChain(const Crypto::Hash& blockId);
    bool isInCheckpointZone(const uint32_t height);

    // First-seen finality (see CRYPTONOTE_FINALITY_DEPTH). Snapshot of the last
    // refused deep reorg, for operator messaging/recovery only — never consulted
    // by the accept/reject decision.
    FinalityForkState getFinalityForkState();
    // Operator-confirmed recovery: pop to just below the detected divergence
    // height so normal sync can re-adopt the majority chain. Refuses unless a
    // finality fork is currently flagged. Returns false with a reason otherwise.
    bool resyncToMajority(std::string& message);

    bool getCanonicalAccountRegistrationsCount(uint64_t& count);

    // PQ account registry. resolve: (height, txIndex) -> the registered view +
    // spend public keys (read from the registration tx's extra). lookup: a PQ
    // identity hash (viewPub+spendPub) -> its registration coordinates.
    bool resolvePqAccountNumber(uint32_t blockHeight, uint32_t txIndex,
                                std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE>& viewPub,
                                std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE>& spendPub);
    bool getPqAccountNumber(const Crypto::Hash& accountId,
                            uint32_t& blockHeight, uint32_t& txIndex);

    bool addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue);
    bool removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue);

    template<class t_ids_container, class t_blocks_container, class t_missed_container>
    bool getBlocks(const t_ids_container& block_ids, t_blocks_container& blocks,
                   t_missed_container& missed_bs) {
      std::lock_guard<std::recursive_mutex> lk(m_blockchain_lock);
      for (const auto& bl_id : block_ids) {
        try {
          uint32_t height = 0;
          if (!m_db.getHashHeight(bl_id, height)) {
            missed_bs.push_back(bl_id);
          } else {
            std::vector<uint8_t> data;
            if (!m_db.getBlockData(height, data)) {
              missed_bs.push_back(bl_id);
              continue;
            }
            Block blk;
            if (!fromBinaryArray(blk, data)) {
              missed_bs.push_back(bl_id);
              continue;
            }
            blocks.push_back(blk);
          }
        } catch (const std::exception& e) {
          logger(Logging::ERROR, Logging::BRIGHT_RED)
            << "Exception in Core getBlocks: " << e.what();
          return false;
        }
      }
      return true;
    }

    template<class t_ids_container, class t_tx_container, class t_missed_container>
    void getBlockchainTransactions(const t_ids_container& txs_ids, t_tx_container& txs,
                                    t_missed_container& missed_txs) {
      std::lock_guard<decltype(m_blockchain_lock)> bcLock(m_blockchain_lock);
      for (const auto& tx_id : txs_ids) {
        uint32_t block; uint16_t txSlot;
        if (!m_db.getTxIndex(tx_id, block, txSlot)) {
          missed_txs.push_back(tx_id);
        } else {
          TransactionEntry te = transactionByIndex({block, txSlot});
          txs.push_back(te.tx);
        }
      }
    }

    template<class t_ids_container, class t_tx_container, class t_missed_container>
    void getTransactions(const t_ids_container& txs_ids, t_tx_container& txs,
                         t_missed_container& missed_txs, bool checkTxPool = false) {
      if (checkTxPool) {
        std::lock_guard<decltype(m_tx_pool)> txLock(m_tx_pool);
        getBlockchainTransactions(txs_ids, txs, missed_txs);
        auto poolTxIds = std::move(missed_txs);
        missed_txs.clear();
        m_tx_pool.getTransactions(poolTxIds, txs, missed_txs);
      } else {
        getBlockchainTransactions(txs_ids, txs, missed_txs);
      }
    }

    // Debug
    void print_blockchain(uint64_t start_index, uint64_t end_index);
    void print_blockchain_index();
    void print_blockchain_outs(const std::string& file);

    struct TransactionIndex {
      uint32_t block;
      uint16_t transaction;

      void serialize(ISerializer& s) {
        s(block, "block");
        s(transaction, "tx");
      }
    };

    void rollbackBlockchainTo(uint32_t height);
    bool have_spend_tag_as_spent(const Crypto::KeyImage& tag);
    bool checkIfSpent(const Crypto::KeyImage& keyImage, uint32_t blockIndex);
    bool checkIfSpent(const Crypto::KeyImage& keyImage);
    bool is_tx_spendheight_unlocked(uint64_t unlock_height);
    bool is_tx_spendheight_unlocked(uint64_t unlock_height, uint32_t height);

    bool checkProofOfWork(Crypto::cn_context& context, const Block& block,
                           Difficulty currentDiffic, Crypto::Hash& proofOfWork);
    // Pure DiscretePower verification only. This must remain independent of
    // chain state so callers may execute it concurrently and apply its result
    // later in canonical order.
    bool prevalidateBlockProofOfWork(const Block& block, Crypto::Hash& proofOfWork) const;

  private:
    struct TransactionEntry {
      Transaction tx;
      std::vector<uint32_t> m_global_output_indexes;

      void serialize(ISerializer& s) {
        s(tx, "tx");
        s(m_global_output_indexes, "m_global_output_indexes");
      }
    };

    // Kept for use in migration and alt-chain handling
    struct BlockEntry {
      Block bl;
      uint32_t height                 = 0;
      uint64_t block_cumulative_size  = 0;
      Difficulty cumulative_difficulty = 0;
      uint64_t already_generated_coins = 0;
      std::vector<TransactionEntry> transactions;

      void serialize(ISerializer& s) {
        s(bl, "block");
        s(height, "height");
        s(block_cumulative_size, "block_cumulative_size");
        s(cumulative_difficulty, "cumulative_difficulty");
        s(already_generated_coins, "already_generated_coins");
        s(transactions, "transactions");
      }
    };

    typedef parallel_flat_hash_map<Crypto::Hash, BlockEntry> blocks_ext_by_hash;

    // ── LMDB-backed storage ───────────────────────────────────────────────
    LMDBBlockchainDB m_db;
    LMDBBlockView    m_blockView;

    // ── In-RAM caches ──────────────────────────────────────────────────────
    // Ephemeral alternative chains (never persisted, rebuilt from P2P each run)
    blocks_ext_by_hash      m_alternative_chains;
    // Orphan blocks index (never persisted, populated during session)
    std::unordered_multimap<uint32_t, Crypto::Hash> m_orphanBlocksIndex;

    // ── UpgradeDetectors (backed by LMDBBlockView) ─────────────────────────
    typedef BasicUpgradeDetector<LMDBBlockView> UpgradeDetector;

    const Currency& m_currency;
    tx_memory_pool& m_tx_pool;
    std::recursive_mutex m_blockchain_lock;
    Crypto::cn_context m_cn_context;
    Tools::ObserverManager<IBlockchainStorageObserver> m_observerManager;

    size_t m_current_block_cumul_sz_limit = 0;
    std::string m_config_folder;
    Checkpoints m_checkpoints;

    // First-seen-finality fork snapshot (operator messaging only, guarded by
    // m_blockchain_lock). Set when a deep reorg is refused, cleared on a
    // successful chain switch or operator-confirmed recovery.
    FinalityForkState m_finalityForkState;

    UpgradeDetector m_upgradeDetectorV2;
    UpgradeDetector m_upgradeDetectorV3;
    UpgradeDetector m_upgradeDetectorV4;
    UpgradeDetector m_upgradeDetectorV5;
    UpgradeDetector m_upgradeDetectorV6;
    UpgradeDetector m_upgradeDetectorV7;
    UpgradeDetector m_upgradeDetectorV8;

    // ── Batch-commit state (Monero-style) ──────────────────────────────────
    // Blocks written into the currently-open batch write txn (0 = no open txn).
    uint32_t m_batchCount = 0;
    // True when the currently-open batch write txn was started with MDB_NOSYNC
    // (fast-sync mode).  Reset to false when the batch is committed or aborted.
    bool m_batchFastMode = false;
    // Commit the batch write txn every this many blocks during initial sync.
    static constexpr uint32_t BATCH_SIZE = 1000;

    IntrusiveLinkedList<MessageQueue<BlockchainMessage>> m_messageQueueList;
    Logging::LoggerRef logger;

    // ── Private blockchain logic ───────────────────────────────────────────
    bool switch_to_alternative_blockchain(const std::list<Crypto::Hash>& alt_chain,
                                           bool discard_disconnected_chain);
    bool handle_alternative_block(const Block& b, const Crypto::Hash& id,
                                   block_verification_context& bvc,
                                   bool sendNewAlternativeBlockMessage = true,
                                   const PrevalidatedBlockProof* prevalidatedProof = nullptr);
    bool prevalidate_miner_transaction(const Block& b, uint32_t height);
    bool validate_miner_transaction(const Block& b, uint32_t height,
                                     size_t cumulativeBlockSize,
                                     uint64_t alreadyGeneratedCoins, uint64_t fee,
                                     uint64_t& reward, int64_t& emissionChange);
    bool validate_block_signature(const Block& b, const Crypto::Hash& id, uint32_t height);
    bool rollback_blockchain_switching(std::list<Block>& original_chain, size_t rollback_height);
    bool get_last_n_blocks_sizes(std::vector<size_t>& sz, size_t count);

    bool check_block_timestamp_main(const Block& b);
    bool check_block_timestamp(std::vector<uint64_t> timestamps, const Block& b);
    uint64_t get_adjusted_time();
    bool complete_timestamps_vector(uint8_t blockMajorVersion, uint64_t start_height,
                                     std::vector<uint64_t>& timestamps);
    bool checkBlockVersion(const Block& b);
    bool checkParentBlockSize(const Block& b, const Crypto::Hash& blockHash);
    bool checkCumulativeBlockSize(const Crypto::Hash& blockId, size_t cumulativeBlockSize,
                                   uint64_t height);
    std::vector<Crypto::Hash> doBuildSparseChain(const Crypto::Hash& startBlockId) const;
    bool getBlockCumulativeSize(const Block& block, size_t& cumulativeSize);
    bool update_next_cumulative_size_limit();

    // ── Batch-commit helpers ────────────────────────────────────────────────
    // True when the chain tip is more than 1 hour behind wall-clock time,
    // meaning we are doing initial block download and should batch commits.
    bool isSyncing() const;
    // Open a new LMDB write txn (+ enable MDB_NOSYNC) iff no batch is open.
    void beginBatchIfNeeded();
    // Increment batch counter; commit if batch is full or we've caught up.
    void commitBatchOrBlock(bool forceSingle = false);

    bool checkTransactionInputs(const Transaction& tx, const Crypto::Hash& tx_prefix_hash,
                                 uint32_t* pmax_used_block_height = nullptr);
    bool checkTransactionInputs(const Transaction& tx, uint32_t* pmax_used_block_height = nullptr);
    // TX_PQ input validation: resolves referenced outputs from the DB, runs the
    // context-free PQ checks (PqValidation), and rejects on-chain nullifier reuse.
    // No height gate — PQ is active from genesis.
    bool checkPqInputs(const Transaction& tx, uint32_t* pmax_used_block_height);
    // Sum of a TX_PQ's referenced-output amounts (resolved from the chain) — the
    // input-side value for fee/reward accounting, since PQ inputs carry no amount.
    uint64_t pqReferencedInputAmount(const Transaction& tx);
    // TX_FREE_REG chain-context checks: refBlockHash on the main chain within
    // FREE_REG_REF_WINDOW, and first-registration-wins. No height gate (PQ from genesis).
    bool checkFreeRegInputs(const Transaction& tx, uint32_t* pmax_used_block_height);
    // First-registration-wins: true if the tx carries a PQ account registration
    // whose identity is already in the on-chain registry.
    bool isPqAccountAlreadyRegistered(const Transaction& tx);

    // Returns by value (deserialized from tx_entries)
    TransactionEntry transactionByIndex(TransactionIndex index);

    bool pushBlock(const Block& blockData, const Crypto::Hash& id,
                   block_verification_context& bvc,
                   const PrevalidatedBlockProof* prevalidatedProof = nullptr);
    bool pushBlock(const Block& blockData, const std::vector<Transaction>& transactions,
                   const Crypto::Hash& blockHash, block_verification_context& bvc,
                   const PrevalidatedBlockProof* prevalidatedProof = nullptr);
    // Inner: writes a fully-formed BlockEntry to LMDB atomically
    bool pushBlock(BlockEntry& block, const Crypto::Hash& blockHash);
    void popBlock();
    bool pushTransaction(BlockEntry& block, const Crypto::Hash& transactionHash,
                          TransactionIndex transactionIndex);
    void popTransaction(const Transaction& transaction, const Crypto::Hash& transactionHash,
                         uint32_t blockHeight);
    void popTransactions(const BlockEntry& block, const Crypto::Hash& minerTransactionHash,
                          uint32_t blockHeight);
    bool checkCheckpoints(uint32_t& lastValidCheckpointHeight);
    void removeLastBlock();
    bool checkUpgradeHeight(const UpgradeDetector& upgradeDetector);
    // Snapshot a refused deep reorg into m_finalityForkState (call under
    // m_blockchain_lock). chainLen is the current chain length (tip height + 1).
    void recordFinalityFork(uint32_t chainLen, uint32_t altBlockHeight,
                            const Crypto::Hash& altBlockId);

    bool loadTransactions(const Block& block, std::vector<Transaction>& transactions);
    void saveTransactions(const std::vector<Transaction>& transactions);

    // One-time migration from legacy blocks.bin / blockindexes.bin
    bool migrateFromSwappedVector(const std::string& config_folder);

    void sendMessage(const BlockchainMessage& message);

    friend class LockedBlockchainStorage;
  };

  class LockedBlockchainStorage : boost::noncopyable {
  public:
    LockedBlockchainStorage(Blockchain& bc)
      : m_bc(bc), m_lock(bc.m_blockchain_lock) {}

    Blockchain* operator->() { return &m_bc; }

  private:
    Blockchain& m_bc;
    std::lock_guard<std::recursive_mutex> m_lock;
  };


} // namespace CryptoNote
