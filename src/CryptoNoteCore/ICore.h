// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2020, The Karbo developers
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

#include <cstdint>
#include <list>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

#include <CryptoNote.h>
#include "CryptoNoteCore/BlockStats.h"
#include "CryptoNoteCore/Difficulty.h"
#include "CryptoNoteCore/FinalityForkState.h"
#include "CryptoNoteCore/TransactionExtra.h"  // TX_EXTRA_PQ_*_SIZE for the PQ registry

#include "CryptoNoteCore/MessageQueue.h"
#include "CryptoNoteCore/BlockchainMessages.h"

namespace CryptoNote {

struct NOTIFY_RESPONSE_GET_OBJECTS_request;
struct NOTIFY_REQUEST_GET_OBJECTS_request;

class Currency;
class IBlock;
class ICoreObserver;
struct Block;
struct block_verification_context;
struct BlockFullInfo;
struct BlockShortInfo;
struct core_stat_info;
struct i_cryptonote_protocol;
struct Transaction;
struct KeyInput;
struct TransactionPrefixInfo;
struct tx_verification_context;

struct WalletSyncBlockInfo {
  uint32_t height = 0;
  Crypto::Hash hash{};
  Block block;
  std::vector<Transaction> transactions;
};

class ICore {
public:
  virtual ~ICore() {}

  virtual bool addObserver(ICoreObserver* observer) = 0;
  virtual bool removeObserver(ICoreObserver* observer) = 0;

  virtual bool have_block(const Crypto::Hash& id) = 0;
  virtual bool haveTransaction(const Crypto::Hash& id) = 0;
  virtual std::vector<Crypto::Hash> buildSparseChain() = 0;
  virtual std::vector<Crypto::Hash> buildSparseChain(const Crypto::Hash& startBlockId) = 0;
  virtual bool get_stat_info(CryptoNote::core_stat_info& st_inf) = 0;
  virtual bool on_idle() = 0;
  virtual void pause_mining() = 0;
  virtual void stop_mining_for_no_peers() = 0;
  virtual void update_block_template_and_resume_mining() = 0;
  virtual bool handle_incoming_block_blob(const CryptoNote::BinaryArray& block_blob, CryptoNote::block_verification_context& bvc, bool control_miner, bool relay_block) = 0;
  virtual bool handle_incoming_block(const Block& b, block_verification_context& bvc, bool control_miner, bool relay_block) = 0;
  virtual bool handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS_request& arg, NOTIFY_RESPONSE_GET_OBJECTS_request& rsp) = 0; //Deprecated. Should be removed with CryptoNoteProtocolHandler.
  virtual void on_synchronized() = 0;
  virtual size_t addChain(const std::vector<const IBlock*>& chain) = 0;

  virtual void get_blockchain_top(uint32_t& height, Crypto::Hash& top_id) = 0;
  virtual std::vector<Crypto::Hash> findBlockchainSupplement(const std::vector<Crypto::Hash>& remoteBlockIds, size_t maxCount,
    uint32_t& totalBlockCount, uint32_t& startBlockIndex) = 0;
  virtual bool get_tx_outputs_gindexs(const Crypto::Hash& tx_id, std::vector<uint32_t>& indexs) = 0;
  virtual i_cryptonote_protocol* get_protocol() = 0;
  virtual bool handle_incoming_tx(const BinaryArray& tx_blob, tx_verification_context& tvc, bool keeped_by_block) = 0; //Deprecated. Should be removed with CryptoNoteProtocolHandler.
  virtual std::vector<Transaction> getPoolTransactions() = 0;
  virtual bool getPoolTransaction(const Crypto::Hash& tx_hash, Transaction& transaction) = 0;
  virtual bool getPoolChanges(const Crypto::Hash& tailBlockId, const std::vector<Crypto::Hash>& knownTxsIds,
                              std::vector<Transaction>& addedTxs, std::vector<Crypto::Hash>& deletedTxsIds) = 0;
  virtual bool getPoolChangesLite(const Crypto::Hash& tailBlockId, const std::vector<Crypto::Hash>& knownTxsIds,
                              std::vector<TransactionPrefixInfo>& addedTxs, std::vector<Crypto::Hash>& deletedTxsIds) = 0;
  virtual void getPoolChanges(const std::vector<Crypto::Hash>& knownTxsIds, std::vector<Transaction>& addedTxs,
                              std::vector<Crypto::Hash>& deletedTxsIds) = 0;
  virtual bool queryBlocks(const std::vector<Crypto::Hash>& block_ids, uint64_t timestamp,
    uint32_t& start_height, uint32_t& current_height, uint32_t& full_offset, std::vector<BlockFullInfo>& entries) = 0;
  virtual bool queryBlocksLite(const std::vector<Crypto::Hash>& block_ids, uint64_t timestamp,
    uint32_t& start_height, uint32_t& current_height, uint32_t& full_offset, std::vector<BlockShortInfo>& entries) = 0;
  virtual bool getWalletSyncBlocks(uint32_t startHeight, uint32_t blockCount,
    uint32_t& currentHeight, std::vector<WalletSyncBlockInfo>& blocks) { return false; }

  virtual Crypto::Hash getBlockIdByHeight(uint32_t height) = 0;
  virtual bool getBlockByHash(const Crypto::Hash &h, Block &blk) = 0;
  virtual bool getBlockHeight(const Crypto::Hash& blockId, uint32_t& blockHeight) = 0;
  virtual bool getTransactionHeight(const Crypto::Hash &txId, uint32_t& blockHeight) = 0;
  virtual void getTransactions(const std::vector<Crypto::Hash>& txs_ids, std::list<Transaction>& txs, std::list<Crypto::Hash>& missed_txs, bool checkTxPool = false) = 0;
  virtual bool getTransactionsWithOutputGlobalIndexes(const std::vector<Crypto::Hash>& txs_ids, std::list<Crypto::Hash>& missed_txs, std::vector<std::pair<Transaction, std::vector<uint32_t>>>& txs) = 0;
  virtual bool getTransaction(const Crypto::Hash& id, Transaction& tx, bool checkTxPool = false) = 0;
  virtual bool getBackwardBlocksSizes(uint32_t fromHeight, std::vector<size_t>& sizes, size_t count) = 0;
  virtual bool getBlockSize(const Crypto::Hash& hash, size_t& size) = 0;
  virtual bool getAlreadyGeneratedCoins(const Crypto::Hash& hash, uint64_t& generatedCoins) = 0;
  virtual bool getBlockReward(uint8_t blockMajorVersion, size_t medianSize, size_t currentBlockSize, uint64_t alreadyGeneratedCoins, uint64_t fee,
                              uint64_t& reward, int64_t& emissionChange) = 0;
  virtual bool scanOutputkeysForIndices(const KeyInput& txInToKey, std::list<std::pair<Crypto::Hash, size_t>>& outputReferences) = 0;
  virtual bool getBlockDifficulty(uint32_t height, Difficulty& difficulty) = 0;
  virtual bool getBlockCumulativeDifficulty(uint32_t height, Difficulty& difficulty) = 0;
  virtual bool getBlockTimestamp(uint32_t height, uint64_t& timestamp) = 0;
  virtual bool getBlockContainingTx(const Crypto::Hash& txId, Crypto::Hash& blockId, uint32_t& blockHeight) = 0;

  virtual bool getGeneratedTransactionsNumber(uint32_t height, uint64_t& generatedTransactions) = 0;
  virtual bool getOrphanBlocksByHeight(uint32_t height, std::vector<Block>& blocks) = 0;
  virtual bool getBlocksByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t blocksNumberLimit, std::vector<Block>& blocks, uint32_t& blocksNumberWithinTimestamps) = 0;
  virtual bool getPoolTransactionsByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t transactionsNumberLimit, std::vector<Transaction>& transactions, uint64_t& transactionsNumberWithinTimestamps) = 0;
  virtual bool getTransactionsByPaymentId(const Crypto::Hash& paymentId, std::vector<Transaction>& transactions) = 0;
  virtual std::vector<Crypto::Hash> getTransactionHashesByPaymentId(const Crypto::Hash& paymentId) = 0;
  virtual uint64_t getMinimalFee(uint32_t height) = 0;
  virtual uint64_t getMinimalFee() = 0;
  virtual bool getPqTransactionFee(const Transaction& tx, uint64_t& fee) = 0;
  virtual uint64_t getNextBlockDifficulty() = 0;
  virtual uint64_t getTotalGeneratedAmount() = 0;
  virtual bool check_tx_fee(const Transaction& tx, const Crypto::Hash& txHash, size_t blobSize, tx_verification_context& tvc, uint32_t height) = 0;
  virtual size_t getPoolTransactionsCount() = 0;
  virtual size_t getBlockchainTotalTransactions() = 0;
  virtual uint32_t getCurrentBlockchainHeight() = 0;
  virtual uint8_t getBlockMajorVersionForHeight(uint32_t height) = 0;
  virtual uint8_t getCurrentBlockMajorVersion() = 0;
  virtual size_t getAlternativeBlocksCount() = 0;
  virtual bool getblockEntry(uint32_t height, uint64_t& block_cumulative_size, Difficulty& difficulty, uint64_t& already_generated_coins, uint64_t& reward, uint64_t& transactions_count, uint64_t& timestamp) = 0;
  virtual bool getBlockStats(uint32_t startHeight, uint32_t endHeight, std::vector<BlockStatsEntry>& stats) = 0;
  virtual bool getBlockStats(const std::vector<uint32_t>& heights, std::vector<BlockStatsEntry>& stats) = 0;

  virtual std::unique_ptr<IBlock> getBlock(const Crypto::Hash& blocksId) = 0;
  virtual bool handleIncomingTransaction(const Transaction& tx, const Crypto::Hash& txHash, size_t blobSize, tx_verification_context& tvc, bool keptByBlock, uint32_t height) = 0;
  virtual std::error_code executeLocked(const std::function<std::error_code()>& func) = 0;

  virtual bool addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) = 0;
  virtual bool removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) = 0;

  virtual void rollbackBlockchain(const uint32_t height) = 0;

  virtual bool getBlockLongHash(Crypto::cn_context &context, const Block& b, Crypto::Hash& res) = 0;

  virtual bool isInCheckpointZone(uint32_t height) const = 0;
  virtual uint32_t getFinalityDepth() const = 0;
  virtual FinalityForkState getFinalityForkState() = 0;
  // Operator-confirmed recovery: pop to just below the detected divergence height
  // and re-sync from the majority. Refuses unless a finality fork is currently
  // flagged, so it cannot be repurposed to force an ordinary deep reorg by hand.
  virtual bool resyncToMajority(std::string& message) = 0;

  virtual bool getCanonicalAccountRegistrationsCount(uint64_t& count) = 0;

  // PQ account registry. Concrete on Core (backed by the blockchain), but surfaced
  // on the interface so an in-process node — which holds only an ICore& — can
  // resolve account numbers for the wallet's send path, exactly as NodeRpcProxy
  // does over RPC. Without this an embedded-node wallet cannot send to an H-I-C /
  // H-I-T-C account number (the INode base stub reports not_supported).
  virtual bool resolvePqAccountNumber(uint32_t blockHeight, uint32_t txIndex,
                                      std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE>& viewPub,
                                      std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE>& spendPub) = 0;
  virtual bool getPqAccountNumber(const Crypto::Hash& accountId,
                                  uint32_t& blockHeight, uint32_t& txIndex) = 0;
};

} //namespace CryptoNote
