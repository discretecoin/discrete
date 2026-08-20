// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers, The Monero developers
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

#include "Blockchain.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <numeric>
#include <unordered_set>
#include <cstdio>
#include <cmath>
#include <ctime>
#include <cstring>
#include <filesystem>
#include <boost/foreach.hpp>
#include "Common/Math.h"
#include "Common/int-util.h"
#include "Common/ShuffleGenerator.h"
#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"
#include "Rpc/CoreRpcServerCommandsDefinitions.h"
#include "Serialization/BinarySerializationTools.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteTools.h"
#include "TransactionExtra.h"
#include "PqValidation.h"
#include "PqTxType.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqDsa.h"

#include "../crypto/hash.h"

using namespace Logging;
using namespace Common;

namespace {

std::string appendPath(const std::string& path, const std::string& fileName) {
  std::string result = path;
  if (!result.empty()) {
    result += '/';
  }
  result += fileName;
  return result;
}

} // anonymous namespace

namespace std {
bool operator<(const Crypto::Hash& hash1, const Crypto::Hash& hash2) {
  return memcmp(&hash1, &hash2, Crypto::HASH_SIZE) < 0;
}

bool operator<(const Crypto::KeyImage& keyImage1, const Crypto::KeyImage& keyImage2) {
  return memcmp(&keyImage1, &keyImage2, 32) < 0;
}
} // namespace std

namespace CryptoNote {

namespace {

BlockStatsEntry makeBlockStatsEntry(uint32_t height, const DbBlockMeta& meta, const DbBlockMeta* prevMeta) {
  BlockStatsEntry entry{};
  entry.height = height;
  entry.blockSize = meta.blockCumulativeSize;
  entry.alreadyGeneratedCoins = meta.alreadyGeneratedCoins;
  entry.timestamp = meta.timestamp;
  entry.transactionsCount = meta.txCount > 0 ? meta.txCount - 1 : 0;

  if (prevMeta == nullptr) {
    entry.difficulty = meta.cumulativeDifficulty;
    entry.reward = meta.alreadyGeneratedCoins;
  } else {
    entry.difficulty = meta.cumulativeDifficulty - prevMeta->cumulativeDifficulty;
    entry.reward = meta.alreadyGeneratedCoins - prevMeta->alreadyGeneratedCoins;
  }

  return entry;
}

} // anonymous namespace

// ─── Constructor ─────────────────────────────────────────────────────────────

Blockchain::Blockchain(const Currency& currency, tx_memory_pool& tx_pool,
                       ILogger& logger)
  : logger(logger, "Blockchain"),
    m_currency(currency),
    m_tx_pool(tx_pool),
    m_blockView(m_db),
    m_upgradeDetectorV2(currency, m_blockView, BLOCK_MAJOR_VERSION_2, logger),
    m_upgradeDetectorV3(currency, m_blockView, BLOCK_MAJOR_VERSION_3, logger),
    m_upgradeDetectorV4(currency, m_blockView, BLOCK_MAJOR_VERSION_4, logger),
    m_upgradeDetectorV5(currency, m_blockView, BLOCK_MAJOR_VERSION_5, logger),
    m_upgradeDetectorV6(currency, m_blockView, BLOCK_MAJOR_VERSION_6, logger),
    m_upgradeDetectorV7(currency, m_blockView, BLOCK_MAJOR_VERSION_7, logger),
    m_upgradeDetectorV8(currency, m_blockView, BLOCK_MAJOR_VERSION_8, logger),
    m_checkpoints(logger)
{
}

// ─── Observer management ─────────────────────────────────────────────────────

bool Blockchain::addObserver(IBlockchainStorageObserver* observer) {
  return m_observerManager.add(observer);
}

bool Blockchain::removeObserver(IBlockchainStorageObserver* observer) {
  return m_observerManager.remove(observer);
}

// ─── ITransactionValidator ───────────────────────────────────────────────────

bool Blockchain::checkTransactionInputs(const CryptoNote::Transaction& tx, BlockInfo& maxUsedBlock) {
  return checkTransactionInputs(tx, maxUsedBlock.height, maxUsedBlock.id);
}

bool Blockchain::checkTransactionInputs(const CryptoNote::Transaction& tx, BlockInfo& maxUsedBlock, BlockInfo& lastFailed) {
  BlockInfo tail;

  if (maxUsedBlock.empty()) {
    if (!lastFailed.empty() && getCurrentBlockchainHeight() > lastFailed.height &&
        getBlockIdByHeight(lastFailed.height) == lastFailed.id) {
      return false;
    }
    if (!checkTransactionInputs(tx, maxUsedBlock.height, maxUsedBlock.id, &tail)) {
      lastFailed = tail;
      return false;
    }
  } else {
    if (maxUsedBlock.height >= getCurrentBlockchainHeight()) {
      return false;
    }
    if (getBlockIdByHeight(maxUsedBlock.height) != maxUsedBlock.id) {
      if (lastFailed.id == getBlockIdByHeight(lastFailed.height)) {
        return false;
      }
    }
    if (!checkTransactionInputs(tx, maxUsedBlock.height, maxUsedBlock.id, &tail)) {
      lastFailed = tail;
      return false;
    }
  }
  return true;
}

bool Blockchain::haveSpentKeyImages(const CryptoNote::Transaction& tx) {
  return haveTransactionKeyImagesAsSpent(tx);
}

bool Blockchain::checkTransactionSize(size_t blobSize) {
  if (blobSize > getCurrentCumulativeBlocksizeLimit() - m_currency.minerTxBlobReservedSize()) {
    logger(ERROR) << "transaction is too big " << blobSize
                  << ", maximum allowed size is "
                  << (getCurrentCumulativeBlocksizeLimit() - m_currency.minerTxBlobReservedSize());
    return false;
  }
  return true;
}

// ─── Query helpers ───────────────────────────────────────────────────────────

bool Blockchain::haveTransaction(const Crypto::Hash& id) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t block; uint16_t txSlot;
  return m_db.getTxIndex(id, block, txSlot);
}

bool Blockchain::have_spend_tag_as_spent(const Crypto::KeyImage& tag) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  return m_db.hasSpentKey(tag);
}

bool Blockchain::checkIfSpent(const Crypto::KeyImage& keyImage, uint32_t blockIndex) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t spentHeight = 0;
  if (!m_db.getSpentKeyHeight(keyImage, spentHeight)) return false;
  return spentHeight <= blockIndex;
}

bool Blockchain::checkIfSpent(const Crypto::KeyImage& keyImage) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  return m_db.hasSpentKey(keyImage);
}

uint32_t Blockchain::getCurrentBlockchainHeight() {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  return m_db.getChainHeight();
}

// ─── init / deinit ───────────────────────────────────────────────────────────

bool Blockchain::init(const std::string& config_folder, bool load_existing) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);

  if (!config_folder.empty() && !Tools::create_directories_if_necessary(config_folder)) {
    logger(ERROR, BRIGHT_RED) << "Failed to create data directory: " << config_folder;
    return false;
  }
  m_config_folder = config_folder;

  // Open (or create) the LMDB environment directory
  std::string lmdbPath = appendPath(config_folder, "blockchain.lmdb");
  if (!Tools::create_directories_if_necessary(lmdbPath)) {
    logger(ERROR, BRIGHT_RED) << "Failed to create LMDB directory: " << lmdbPath;
    return false;
  }

  if (!m_db.open(lmdbPath)) {
    namespace fs = std::filesystem;

    // Check if another process already holds the exclusive lock
    if (LMDBBlockchainDB::isLocked(lmdbPath)) {
      logger(ERROR, BRIGHT_RED)
          << "The blockchain database at " << lmdbPath
          << " is already in use by another process. "
          << "Only one process can access the database at a time. "
          << "Please close the other instance and try again.";
      return false;
    }

    logger(WARNING, BRIGHT_YELLOW)
        << "Failed to open LMDB database at " << lmdbPath
        << ", attempting recovery...";

    // --- 1. Try clearing stale readers via a fresh raw env ---
    // Do NOT use m_db.getEnv() here — the open failed, the handle is invalid.
    {
      MDB_env* rawEnv = nullptr;
      if (mdb_env_create(&rawEnv) == MDB_SUCCESS) {
        // Open read-only just enough to call mdb_reader_check
        if (mdb_env_open(rawEnv, lmdbPath.c_str(), MDB_RDONLY, 0664) == MDB_SUCCESS) {
          int dead = 0;
          if (mdb_reader_check(rawEnv, &dead) == MDB_SUCCESS) {
            logger(INFO) << "Cleared " << dead << " stale LMDB reader(s)";
          } else {
            logger(WARNING) << "mdb_reader_check returned error";
          }
        } else {
          logger(WARNING) << "Could not open LMDB read-only for reader check";
        }
        mdb_env_close(rawEnv);
      } else {
        logger(WARNING) << "mdb_env_create failed during reader check";
      }
    }

    // --- 2. Retry open after reader cleanup ---
    if (m_db.open(lmdbPath)) {
      logger(INFO) << "LMDB opened successfully after stale reader cleanup";
    } else {
      // --- 3. Attempt salvage copy ---
      bool recovered = false;

      logger(WARNING) << "Attempting LMDB salvage copy...";

      fs::path origPath    = lmdbPath;
      fs::path salvagePath = fs::path(lmdbPath).parent_path() / "blockchain.lmdb.salvage";

      // Remove any leftover salvage directory from a prior crashed attempt,
      // then create a fresh empty directory — mdb_env_copy2 requires it to exist.
      bool salvageDirReady = false;
      try {
        if (fs::exists(salvagePath)) {
          fs::remove_all(salvagePath);
          logger(WARNING) << "Removed leftover salvage directory: " << salvagePath;
        }
        fs::create_directories(salvagePath);
        salvageDirReady = true;
      } catch (const std::exception& e) {
        logger(WARNING) << "Could not prepare salvage directory: " << e.what();
      }

      // Perform the salvage copy — env is created, used, and closed exactly once
      bool salvageCopyOk = false;
      {
        MDB_env* env = nullptr;
        do {
          if (!salvageDirReady) {
            logger(WARNING) << "Skipping salvage copy: destination directory unavailable";
            break;
          }
          if (mdb_env_create(&env) != MDB_SUCCESS) {
            logger(WARNING) << "mdb_env_create failed during salvage";
            break;
          }
          // Match your production schema's named-DB count
          if (mdb_env_set_maxdbs(env, 16) != MDB_SUCCESS) {
            logger(WARNING) << "mdb_env_set_maxdbs failed during salvage";
            mdb_env_close(env);
            env = nullptr;
            break;
          }
          if (mdb_env_open(env, lmdbPath.c_str(), MDB_RDONLY, 0664) != MDB_SUCCESS) {
            logger(WARNING) << "mdb_env_open (read-only for salvage) failed";
            mdb_env_close(env);
            env = nullptr;
            break;
          }
          int rc = mdb_env_copy2(env, salvagePath.string().c_str(), MDB_CP_COMPACT);
          if (rc != MDB_SUCCESS) {
            logger(WARNING) << "mdb_env_copy2 failed: " << mdb_strerror(rc);
          } else {
            logger(INFO) << "Salvage copy written to: " << salvagePath;
            salvageCopyOk = true;
          }
          // Always close exactly once here — no other close for this env
          mdb_env_close(env);
          env = nullptr;
        } while (false);

        // Safety net: if we broke out with env still open
        if (env) {
          mdb_env_close(env);
        }
      }

      // Rotate files and attempt to open the salvaged copy
      if (salvageCopyOk) {
        try {
          // Build a unique .corrupt name so we never overwrite a prior backup
          fs::path corruptPath = fs::path(lmdbPath + ".corrupt");
          if (fs::exists(corruptPath)) {
            // Append a counter suffix to avoid collision
            int suffix = 2;
            fs::path candidate;
            do {
              candidate = fs::path(lmdbPath + ".corrupt." + std::to_string(suffix++));
            } while (fs::exists(candidate) && suffix < 100);
            corruptPath = candidate;
          }

          fs::rename(origPath, corruptPath);
          logger(WARNING) << "Original (corrupt) DB moved to: " << corruptPath;

          fs::rename(salvagePath, origPath);
          logger(INFO) << "Salvage copy promoted to: " << origPath;

          if (m_db.open(lmdbPath)) {
            logger(INFO) << "LMDB recovered successfully from salvage copy";
            recovered = true;
          } else {
            logger(WARNING) << "Could not open salvaged DB — will proceed to rebuild";
          }
        } catch (const std::exception& e) {
          logger(WARNING) << "File rotation during salvage failed: " << e.what();
        }
      }

      // --- 4. Full rebuild — wipe and start fresh ---
      if (!recovered) {
        logger(ERROR, BRIGHT_RED)
            << "LMDB unrecoverable. Rebuilding database from scratch. "
               "A full blockchain resync will be required.";
        try {
          // Move whatever is left to a unique .corrupt path
          if (fs::exists(lmdbPath)) {
            fs::path corruptPath = fs::path(lmdbPath + ".corrupt");
            if (fs::exists(corruptPath)) {
              int suffix = 2;
              fs::path candidate;
              do {
                candidate = fs::path(lmdbPath + ".corrupt." + std::to_string(suffix++));
              } while (fs::exists(candidate) && suffix < 100);
              corruptPath = candidate;
            }
            fs::rename(lmdbPath, corruptPath);
            logger(WARNING) << "Unrecoverable DB moved to: " << corruptPath;
          }

          // Re-create an empty directory for a fresh environment
          fs::create_directories(lmdbPath);

          if (!m_db.open(lmdbPath)) {
            logger(ERROR, BRIGHT_RED)
                << "Failed to create fresh LMDB environment after rebuild";
            return false;
          }

          logger(WARNING) << "Fresh LMDB environment created. Blockchain resync required.";
        } catch (const std::exception& e) {
          logger(ERROR, BRIGHT_RED) << "Rebuild failed: " << e.what();
          return false;
        }
      }
    }
  }

  // Migration from legacy SwappedVector files.
  // Always checked when old block files exist so an interrupted migration
  // (LMDB non-empty but incomplete) is automatically resumed.
  {
    std::string blocksFile = appendPath(config_folder, m_currency.blocksFileName());
    FILE* f = fopen(blocksFile.c_str(), "rb");
    if (f) {
      fclose(f);
      logger(INFO, BRIGHT_WHITE) << "Old block data detected, checking migration status...";
      if (!migrateFromSwappedVector(config_folder)) {
        logger(WARNING, BRIGHT_YELLOW) << "Migration failed, continuing with current LMDB state.";
      }
    }
  }

  uint32_t chainHeight = m_db.getChainHeight();

  if (load_existing && chainHeight > 0) {
    // Verify genesis
    DbBlockMeta genMeta{};
    m_db.getBlockMeta(0, genMeta);
    Crypto::Hash firstBlockHash;
    memcpy(firstBlockHash.data, genMeta.hash, 32);
    if (firstBlockHash != m_currency.genesisBlockHash()) {
      logger(ERROR, BRIGHT_RED) << "Failed to init: genesis block mismatch. "
        "Probably you set --testnet flag with data dir with non-test blockchain or another network.";
      return false;
    }

    logger(INFO, BRIGHT_WHITE) << "Loading blockchain...";
  }

  chainHeight = m_db.getChainHeight();

  if (chainHeight == 0) {
    logger(INFO, BRIGHT_WHITE) << "Blockchain not loaded, generating genesis block.";
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    pushBlock(m_currency.genesisBlock(), get_block_hash(m_currency.genesisBlock()), bvc);
    if (bvc.m_verification_failed) {
      logger(ERROR, BRIGHT_RED) << "Failed to add genesis block to blockchain";
      return false;
    }
    chainHeight = m_db.getChainHeight();
  }

  uint32_t lastValidCheckpointHeight = 0;
  if (!checkCheckpoints(lastValidCheckpointHeight)) {
    logger(WARNING, BRIGHT_YELLOW) << "Invalid checkpoint found. Rollback blockchain to height=" << lastValidCheckpointHeight;
    rollbackBlockchainTo(lastValidCheckpointHeight);
    chainHeight = m_db.getChainHeight();
  }

  if (!m_upgradeDetectorV2.init() || !m_upgradeDetectorV3.init() ||
      !m_upgradeDetectorV4.init() || !m_upgradeDetectorV5.init() || !m_upgradeDetectorV6.init() ||
      !m_upgradeDetectorV7.init() || !m_upgradeDetectorV8.init()) {
    logger(ERROR, BRIGHT_RED) << "Failed to initialize upgrade detector.";
  }

  bool reinitUpgradeDetectors = false;
  auto checkAndRollback = [&](UpgradeDetector& ud) {
    if (!checkUpgradeHeight(ud)) {
      uint32_t upgradeHeight = ud.upgradeHeight();
      assert(upgradeHeight != UpgradeDetectorBase::UNDEF_HEIGHT);
      DbBlockMeta badMeta{};
      m_db.getBlockMeta(upgradeHeight + 1, badMeta);
      logger(WARNING, BRIGHT_YELLOW)
        << "Invalid block version at " << upgradeHeight + 1
        << ": real=" << static_cast<int>(badMeta.majorVersion)
        << " expected=" << static_cast<int>(ud.targetVersion())
        << ". Rollback blockchain to height=" << upgradeHeight;
      rollbackBlockchainTo(upgradeHeight);
      reinitUpgradeDetectors = true;
      return true;
    }
    return false;
  };

  if (checkAndRollback(m_upgradeDetectorV2)) {}
  else if (checkAndRollback(m_upgradeDetectorV3)) {}
  else if (checkAndRollback(m_upgradeDetectorV4)) {}
  else if (checkAndRollback(m_upgradeDetectorV5)) {}
  else if (checkAndRollback(m_upgradeDetectorV6)) {}
  else if (checkAndRollback(m_upgradeDetectorV7)) {}
  else if (checkAndRollback(m_upgradeDetectorV8)) {}

  if (reinitUpgradeDetectors &&
      (!m_upgradeDetectorV2.init() || !m_upgradeDetectorV3.init() ||
       !m_upgradeDetectorV4.init() || !m_upgradeDetectorV5.init() || !m_upgradeDetectorV6.init() ||
       !m_upgradeDetectorV7.init() || !m_upgradeDetectorV8.init())) {
    logger(ERROR, BRIGHT_RED) << "Failed to initialize upgrade detector";
    return false;
  }

  update_next_cumulative_size_limit();

  chainHeight = m_db.getChainHeight();
  DbBlockMeta tailMeta{};
  m_db.getBlockMeta(chainHeight - 1, tailMeta);
  uint64_t timestamp_diff = time(NULL) - tailMeta.timestamp;
  if (!tailMeta.timestamp) {
    timestamp_diff = time(NULL) - 1341378000;
  }

  logger(INFO, BRIGHT_GREEN)
    << "Blockchain initialized. last block: " << chainHeight - 1 << ", "
    << Common::timeIntervalToString(timestamp_diff)
    << " time ago, current difficulty: " << getDifficultyForNextBlock(getTailId());

  return true;
}

bool Blockchain::deinit() {
  assert(m_messageQueueList.empty());
  flushBatch();  // commit any pending IBD write txn before closing
  return true;
}

bool Blockchain::flushBatch() {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  if (m_batchCount == 0) return true;
  try {
    m_db.commitTxn();
    m_batchCount = 0;
  } catch (const std::exception& e) {
    m_db.abortTxn();
    m_batchCount = 0;
    if (m_batchFastMode) {
      m_db.setFastSyncMode(false);  // disable stale MDB_NOSYNC flag
      m_batchFastMode = false;
    }
    logger(ERROR, BRIGHT_RED) << "flushBatch: " << e.what();
    return false;
  }
  if (m_batchFastMode) {
    m_db.setFastSyncMode(false);  // disable MDB_NOSYNC + force flush to disk
    m_batchFastMode = false;
  }
  return true;
}

bool Blockchain::isSyncing() const {
  uint32_t h = m_db.getChainHeight();
  if (h == 0) return false;
  DbBlockMeta meta{};
  if (!m_db.getBlockMeta(h - 1, meta)) return false;
  auto now = static_cast<uint64_t>(time(nullptr));
  return now > meta.timestamp && (now - meta.timestamp) > 3600u;  // >1 hour behind
}

void Blockchain::beginBatchIfNeeded() {
  if (m_batchCount == 0) {
    m_db.growMapIfNeeded();  // preemptively resize if >=80% full
    bool shouldBeFast = isSyncing();
    // Reconcile MDB_NOSYNC state with the current sync status.
    // This also handles the case where a previous fast-mode batch was aborted
    // (via an early return) without disabling MDB_NOSYNC: the stale flag is
    // detected here and cleaned up before the new batch begins.
    if (m_batchFastMode && !shouldBeFast) {
      m_db.setFastSyncMode(false);  // disable MDB_NOSYNC + force flush
    } else if (!m_batchFastMode && shouldBeFast) {
      m_db.setFastSyncMode(true);
    }
    m_batchFastMode = shouldBeFast;
    m_db.beginWriteTxn();
  }
}

void Blockchain::commitBatchOrBlock(bool forceSingle) {
  ++m_batchCount;
  bool syncing = isSyncing();
  if (forceSingle || !syncing || m_batchCount >= BATCH_SIZE) {
    m_db.commitTxn();
    m_batchCount = 0;
    if (m_batchFastMode) {
      if (!syncing) {
        // Caught up to chain tip: disable fast mode and force a full flush
        // so the next live-block commit is fully durable.
        m_db.setFastSyncMode(false);
        m_batchFastMode = false;
      } else {
        // Still syncing but batch is full: checkpoint flush.
        // MDB_NOSYNC stays active; next batch continues in fast mode.
        // This ensures a crash causes a clean rollback to this height
        // rather than leaving the database in a corrupted state.
        m_db.syncToDisk();
      }
    }
  }
  // else: leave write txn open; next block reuses it
}

bool Blockchain::resetAndSetGenesisBlock(const Block& b) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  if (m_db.hasActiveTxn()) {
    m_db.abortTxn();
    m_batchCount = 0;
    if (m_batchFastMode) {
      m_db.setFastSyncMode(false);
      m_batchFastMode = false;
    }
  }

  m_db.clear();
  m_alternative_chains.clear();
  m_orphanBlocksIndex.clear();

  block_verification_context bvc = boost::value_initialized<block_verification_context>();
  addNewBlock(b, bvc);
  return bvc.m_added_to_main_chain && !bvc.m_verification_failed;
}

// ─── Tail / chain state ──────────────────────────────────────────────────────

Crypto::Hash Blockchain::getTailId(uint32_t& height) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  height = m_db.getChainHeight() - 1;
  return getTailId();
}

Crypto::Hash Blockchain::getTailId() {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t h = m_db.getChainHeight();
  if (h == 0) return NULL_HASH;
  DbBlockMeta meta{};
  m_db.getBlockMeta(h - 1, meta);
  Crypto::Hash hash;
  memcpy(hash.data, meta.hash, 32);
  return hash;
}

Crypto::Hash Blockchain::getBlockIdByHeight(uint32_t height) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  DbBlockMeta meta{};
  if (!m_db.getBlockMeta(height, meta)) return NULL_HASH;
  Crypto::Hash hash;
  memcpy(hash.data, meta.hash, 32);
  return hash;
}

bool Blockchain::getBlockByHash(const Crypto::Hash& blockHash, Block& b) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t height = 0;
  if (m_db.getHashHeight(blockHash, height)) {
    std::vector<uint8_t> bdata;
    if (!m_db.getBlockData(height, bdata)) return false;
    return fromBinaryArray(b, bdata);
  }
  auto it = m_alternative_chains.find(blockHash);
  if (it != m_alternative_chains.end()) {
    b = it->second.bl;
    return true;
  }
  return false;
}

bool Blockchain::getWalletSyncBlocks(uint32_t startHeight, uint32_t blockCount,
                                     uint32_t& currentHeight,
                                     std::vector<WalletSyncBlockInfo>& blocks) {
  std::lock_guard<decltype(m_blockchain_lock)> lock(m_blockchain_lock);
  const uint64_t requestedEnd = static_cast<uint64_t>(startHeight) + blockCount;
  const uint32_t endHeight = static_cast<uint32_t>(
      std::min<uint64_t>(requestedEnd, std::numeric_limits<uint32_t>::max()));

  std::vector<DbWalletSyncBlock> records;
  if (!m_db.getWalletSyncRange(startHeight, endHeight, currentHeight, records)) {
    return false;
  }

  blocks.reserve(blocks.size() + records.size());
  for (const auto& record : records) {
    WalletSyncBlockInfo result;
    result.height = record.meta.height;
    std::memcpy(result.hash.data, record.meta.hash, sizeof(result.hash.data));
    if (!fromBinaryArray(result.block, record.blockData)) {
      throw std::runtime_error("getWalletSyncBlocks: block deserialize failed at height " +
                               std::to_string(result.height));
    }

    result.transactions.reserve(record.transactionEntries.size());
    for (const auto& raw : record.transactionEntries) {
      if (raw.size() < sizeof(uint32_t)) {
        throw std::runtime_error("getWalletSyncBlocks: corrupt transaction entry");
      }
      uint32_t transactionSize = 0;
      std::memcpy(&transactionSize, raw.data(), sizeof(transactionSize));
      if (transactionSize > raw.size() - sizeof(transactionSize)) {
        throw std::runtime_error("getWalletSyncBlocks: truncated transaction entry");
      }
      Transaction transaction;
      const uint8_t* begin = raw.data() + sizeof(transactionSize);
      if (!fromBinaryArray(transaction, BinaryArray(begin, begin + transactionSize))) {
        throw std::runtime_error("getWalletSyncBlocks: transaction deserialize failed");
      }
      result.transactions.push_back(std::move(transaction));
    }
    if (result.transactions.size() != result.block.transactionHashes.size()) {
      throw std::runtime_error("getWalletSyncBlocks: transaction count mismatch");
    }
    blocks.push_back(std::move(result));
  }
  return true;
}

bool Blockchain::getBlockHeight(const Crypto::Hash& blockId, uint32_t& blockHeight) {
  std::lock_guard<decltype(m_blockchain_lock)> lock(m_blockchain_lock);
  return m_db.getHashHeight(blockId, blockHeight);
}

bool Blockchain::getTransactionHeight(const Crypto::Hash& txId, uint32_t& blockHeight) {
  std::lock_guard<decltype(m_blockchain_lock)> bcLock(m_blockchain_lock);
  uint32_t block; uint16_t txSlot;
  if (!m_db.getTxIndex(txId, block, txSlot)) return false;
  blockHeight = block;
  return true;
}

uint64_t Blockchain::getBlockTimestamp(uint32_t height) {
  DbBlockMeta meta{};
  m_db.getBlockMeta(height, meta);
  return meta.timestamp;
}

uint64_t Blockchain::getCoinsInCirculation() {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t h = m_db.getChainHeight();
  if (h == 0) return 0;
  DbBlockMeta meta{};
  m_db.getBlockMeta(h - 1, meta);
  return meta.alreadyGeneratedCoins;
}

uint64_t Blockchain::getCoinsInCirculation(uint32_t height) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  DbBlockMeta meta{};
  m_db.getBlockMeta(height, meta);
  return meta.alreadyGeneratedCoins;
}

uint8_t Blockchain::getBlockMajorVersionForHeight(uint32_t height) const {
  if (height > m_upgradeDetectorV8.upgradeHeight()) {
    return m_upgradeDetectorV8.targetVersion();
  } else if (height > m_upgradeDetectorV7.upgradeHeight()) {
    return m_upgradeDetectorV7.targetVersion();
  } else if (height > m_upgradeDetectorV6.upgradeHeight()) {
    return m_upgradeDetectorV6.targetVersion();
  } else if (height > m_upgradeDetectorV5.upgradeHeight()) {
    return m_upgradeDetectorV5.targetVersion();
  } else if (height > m_upgradeDetectorV4.upgradeHeight()) {
    return m_upgradeDetectorV4.targetVersion();
  } else if (height > m_upgradeDetectorV3.upgradeHeight()) {
    return m_upgradeDetectorV3.targetVersion();
  } else if (height > m_upgradeDetectorV2.upgradeHeight()) {
    return m_upgradeDetectorV2.targetVersion();
  } else {
    return BLOCK_MAJOR_VERSION_1;
  }
}

// ─── Difficulty ──────────────────────────────────────────────────────────────

Difficulty Blockchain::getDifficultyForNextBlock(const Crypto::Hash& prevHash) {
  if (prevHash == NULL_HASH) return 1;

  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);

  uint32_t chainHeight = m_db.getChainHeight();
  uint8_t  BlockMajorVersion = getBlockMajorVersionForHeight(chainHeight);
  uint32_t difficultyBlocksCount = std::min<uint32_t>(
    std::max<uint32_t>(chainHeight > 0 ? chainHeight - 1 : 1, 1),
    static_cast<uint32_t>(m_currency.difficultyBlocksCountByBlockVersion(BlockMajorVersion)));

  std::vector<uint64_t>       timestamps;
  std::vector<Difficulty> cumulative_difficulties;

  // ── Fast path: prevHash is the main-chain tip (normal sync) ──────────────
  // Instead of walking backwards by hash link (N separate LMDB txns), read
  // all N block_meta records in a single cursor scan.
  uint32_t prevHeight = 0;
  if (m_db.getHashHeight(prevHash, prevHeight)) {
    uint32_t fromHeight = (prevHeight + 1 >= difficultyBlocksCount)
                          ? prevHeight + 1 - difficultyBlocksCount : 0;

    std::vector<DbBlockMeta> metas;
    m_db.getBlockMetaRange(fromHeight, prevHeight, metas);

    timestamps.reserve(metas.size());
    cumulative_difficulties.reserve(metas.size());
    for (const auto& m : metas) {
      timestamps.push_back(m.timestamp);
      cumulative_difficulties.push_back(m.cumulativeDifficulty);
    }

    return m_currency.nextDifficulty(chainHeight, BlockMajorVersion,
                                      timestamps, cumulative_difficulties);
  }

  // ── Slow path: prevHash is on an alternative chain ───────────────────────
  // Walk backwards through the alt-chain then the main chain by hash links.
  uint32_t processed = 0;
  Crypto::Hash h = prevHash;
  while (processed < difficultyBlocksCount && h != NULL_HASH) {
    uint64_t       ts      = 0;
    Difficulty cumDiff = 0;
    Crypto::Hash   prevH{};

    auto it = m_alternative_chains.find(h);
    if (it != m_alternative_chains.end()) {
      const BlockEntry& b = it->second;
      ts      = b.bl.timestamp;
      cumDiff = b.cumulative_difficulty;
      prevH   = b.bl.previousBlockHash;
    } else {
      uint32_t bh = 0;
      if (!m_db.getHashHeight(h, bh)) {
        logger(ERROR) << "Can't find block " << h << " for difficulty calculation";
        return 0;
      }
      DbBlockMeta meta{};
      m_db.getBlockMeta(bh, meta);
      ts      = meta.timestamp;
      cumDiff = meta.cumulativeDifficulty;
      memcpy(prevH.data, meta.prevHash, 32);
    }

    timestamps.push_back(ts);
    cumulative_difficulties.push_back(cumDiff);
    ++processed;
    h = prevH;
  }

  std::reverse(timestamps.begin(), timestamps.end());
  std::reverse(cumulative_difficulties.begin(), cumulative_difficulties.end());

  return m_currency.nextDifficulty(chainHeight, BlockMajorVersion,
                                    timestamps, cumulative_difficulties);
}

// ─── Block size tracking ──────────────────────────────────────────────────────

bool Blockchain::getBackwardBlocksSize(size_t from_height, std::vector<size_t>& sz, size_t count) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t chainHeight = m_db.getChainHeight();
  if (!(from_height < chainHeight)) {
    logger(ERROR, BRIGHT_RED) << "getBackwardBlocksSize called with from_height="
      << from_height << ", blockchain height = " << chainHeight;
    return false;
  }
  uint32_t start_offset = static_cast<uint32_t>(
    (from_height + 1) - std::min((from_height + 1), count));

  // Read the range in a single cursor scan instead of one txn per block.
  std::vector<DbBlockMeta> metas;
  m_db.getBlockMetaRange(start_offset, static_cast<uint32_t>(from_height), metas);
  for (const auto& m : metas) sz.push_back(m.blockCumulativeSize);
  return true;
}

bool Blockchain::get_last_n_blocks_sizes(std::vector<size_t>& sz, size_t count) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t chainHeight = m_db.getChainHeight();
  if (chainHeight == 0) return true;
  return getBackwardBlocksSize(chainHeight - 1, sz, count);
}

uint64_t Blockchain::getCurrentCumulativeBlocksizeLimit() {
  return m_current_block_cumul_sz_limit;
}

// ─── Proof of Work ───────────────────────────────────────────────────────────

bool Blockchain::prevalidateBlockProofOfWork(const Block& block, Crypto::Hash& proofOfWork) const {
  // DiscretePower (https://docs.discrete.cash/#/consensus/pow §9). Stateless: a pure function
  // of the block. The ML-DSA-65 PoW signature is verified BEFORE the memory-hard
  // yespower-discrete runs, so a garbage block costs only one signature verification
  // (the DoS bound). discrete_power_verify keeps the exact spec ordering internally.
  BinaryArray blob;
  if (!get_block_hashing_blob(block, blob)) {
    logger(ERROR, BRIGHT_RED) << "Block PoW: failed to build hashing blob";
    return false;
  }
  std::array<uint8_t, CryptoNote::PQ_AUTH_PUB_SIZE> spendPubBytes;
  if (!getPqMinerSpendPubFromExtra(block.baseTransaction.extra, spendPubBytes)) {
    logger(ERROR, BRIGHT_RED) << "Block PoW: coinbase extra missing PQ miner spend pub";
    return false;
  }
  CryptoPQ::DsaPublicKey spendPub;
  std::copy(spendPubBytes.begin(), spendPubBytes.end(), spendPub.begin());

  DiscretePowerReject reason = DiscretePowerReject::None;
  if (!discrete_power_verify(blob, spendPub, block.signature, proofOfWork, &reason)) {
    switch (reason) {
    case DiscretePowerReject::BadLength:
      logger(ERROR, BRIGHT_RED) << "Block PoW: wrong signature length "
                                << block.signature.size() << " (expected " << parameters::DISCRETE_POWER_SIG_LEN << ")";
      break;
    case DiscretePowerReject::BadSignature:
      logger(ERROR, BRIGHT_RED) << "Block PoW: ML-DSA-65 signature verification failed "
                                   "(rejected before any yespower-discrete work)";
      break;
    default:
      logger(ERROR, BRIGHT_RED) << "Block PoW: yespower-discrete evaluation failed";
      break;
    }
    return false;
  }
  return true;
}

bool Blockchain::checkProofOfWork(Crypto::cn_context& context, const Block& block,
                                   Difficulty currentDiffic, Crypto::Hash& proofOfWork) {
  (void)context;
  if (!prevalidateBlockProofOfWork(block, proofOfWork)) {
    return false;
  }
  // PoW >= target — the caller logs the difficulty context.
  return check_hash(proofOfWork, currentDiffic);
}

// ─── Timestamp checks ────────────────────────────────────────────────────────

bool Blockchain::complete_timestamps_vector(uint8_t blockMajorVersion,
                                             uint64_t start_top_height,
                                             std::vector<uint64_t>& timestamps) {
  if (timestamps.size() >= m_currency.timestampCheckWindow(blockMajorVersion)) return true;

  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t chainHeight = m_db.getChainHeight();
  size_t need_elements = m_currency.timestampCheckWindow(blockMajorVersion) - timestamps.size();
  if (!(start_top_height < chainHeight)) {
    logger(ERROR, BRIGHT_RED) << "internal error: passed start_height=" << start_top_height
                               << " not less than chainHeight=" << chainHeight;
    return false;
  }
  size_t stop_offset = start_top_height > need_elements ? start_top_height - need_elements : 0;
  do {
    DbBlockMeta meta{};
    m_db.getBlockMeta(static_cast<uint32_t>(start_top_height), meta);
    timestamps.push_back(meta.timestamp);
    if (start_top_height == 0) break;
    --start_top_height;
  } while (start_top_height != stop_offset);
  return true;
}

bool Blockchain::check_block_timestamp_main(const Block& b) {
  if (b.timestamp > get_adjusted_time() + m_currency.blockFutureTimeLimit(b.majorVersion)) {
    time_t t = static_cast<time_t>(b.timestamp);
    auto tm = *std::localtime(&t);
    logger(INFO, BRIGHT_WHITE)
      << "Timestamp of block with id: " << get_block_hash(b)
      << ", " << b.timestamp
      << " (" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << ") is too far in the future";
    return false;
  }

  uint32_t chainHeight = m_db.getChainHeight();
  uint32_t window = static_cast<uint32_t>(m_currency.timestampCheckWindow(b.majorVersion));
  uint32_t fromH  = (chainHeight > window) ? chainHeight - window : 0;

  // Read the timestamp window in a single cursor scan (one read txn).
  std::vector<DbBlockMeta> metas;
  m_db.getBlockMetaRange(fromH, chainHeight - 1, metas);

  std::vector<uint64_t> timestamps;
  timestamps.reserve(metas.size());
  for (const auto& m : metas) timestamps.push_back(m.timestamp);

  return check_block_timestamp(std::move(timestamps), b);
}

bool Blockchain::check_block_timestamp(std::vector<uint64_t> timestamps, const Block& b) {
  if (timestamps.size() < m_currency.timestampCheckWindow(b.majorVersion)) return true;
  uint64_t median_ts = Common::medianValue(timestamps);
  if (b.timestamp < median_ts) {
    logger(INFO, BRIGHT_WHITE)
      << "Timestamp of block with id " << get_block_hash(b) << ", " << b.timestamp
      << " is less than median of last " << m_currency.timestampCheckWindow(b.majorVersion)
      << " blocks, " << median_ts << ", i.e. it's too deep in the past";
    return false;
  }
  return true;
}

uint64_t Blockchain::get_adjusted_time() {
  return time(NULL);
}

// ─── Block validation helpers ────────────────────────────────────────────────

bool Blockchain::checkBlockVersion(const Block& b) {
  uint32_t height = get_block_height(b);
  const uint8_t expectedBlockVersion = getBlockMajorVersionForHeight(height);
  if (b.majorVersion != expectedBlockVersion) {
    logger(TRACE) << "Block " << get_block_hash(b)
      << " has wrong major version: " << static_cast<int>(b.majorVersion)
      << ", at height " << height << " expected version is "
      << static_cast<int>(expectedBlockVersion);
    return false;
  }
  return true;
}

bool Blockchain::checkParentBlockSize(const Block& b, const Crypto::Hash& blockHash) {
  if (b.majorVersion == BLOCK_MAJOR_VERSION_2 || b.majorVersion == BLOCK_MAJOR_VERSION_3) {
    auto serializer = makeParentBlockSerializer(b, false, false);
    size_t parentBlockSize;
    if (!getObjectBinarySize(serializer, parentBlockSize)) {
      logger(ERROR, BRIGHT_RED) << "Block " << blockHash << ": failed to determine parent block size";
      return false;
    }
    if (parentBlockSize > 2 * 1024) {
      logger(INFO, BRIGHT_WHITE) << "Block " << blockHash
        << " contains too big parent block: " << parentBlockSize
        << " bytes, expected no more than " << 2 * 1024 << " bytes";
      return false;
    }
  }
  return true;
}

bool Blockchain::checkCumulativeBlockSize(const Crypto::Hash& blockId, size_t cumulativeBlockSize,
                                           uint64_t height) {
  size_t maxBlockCumulativeSize = m_currency.maxBlockCumulativeSize(height);
  if (cumulativeBlockSize > maxBlockCumulativeSize) {
    logger(INFO, BRIGHT_WHITE) << "Block " << blockId
      << " is too big: " << cumulativeBlockSize << " bytes, "
      << "expected no more than " << maxBlockCumulativeSize << " bytes";
    return false;
  }
  return true;
}

bool Blockchain::getBlockCumulativeSize(const Block& block, size_t& cumulativeSize) {
  std::vector<Transaction> blockTxs;
  std::vector<Crypto::Hash> missedTxs;
  getTransactions(block.transactionHashes, blockTxs, missedTxs, true);
  cumulativeSize = getObjectBinarySize(block.baseTransaction);
  for (const Transaction& tx : blockTxs) {
    cumulativeSize += getObjectBinarySize(tx);
  }
  return missedTxs.empty();
}

bool Blockchain::update_next_cumulative_size_limit() {
  uint8_t nextBlockMajorVersion = getBlockMajorVersionForHeight(m_db.getChainHeight());
  size_t nextBlockGrantedFullRewardZone =
    m_currency.blockGrantedFullRewardZoneByBlockVersion(nextBlockMajorVersion);

  std::vector<size_t> sz;
  get_last_n_blocks_sizes(sz, m_currency.rewardBlocksWindow());

  uint64_t median = Common::medianValue(sz);
  if (median <= nextBlockGrantedFullRewardZone) {
    median = nextBlockGrantedFullRewardZone;
  }
  m_current_block_cumul_sz_limit = median * 2;
  return true;
}

// ─── Miner transaction validation ────────────────────────────────────────────

bool Blockchain::prevalidate_miner_transaction(const Block& b, uint32_t height) {
  if (b.baseTransaction.version != TRANSACTION_VERSION_1) {
    logger(ERROR, BRIGHT_RED) << "Coinbase transaction must use transaction version "
      << static_cast<unsigned>(TRANSACTION_VERSION_1) << ", got "
      << static_cast<unsigned>(b.baseTransaction.version);
    return false;
  }
  if (b.baseTransaction.txType != TX_COINBASE) {
    logger(ERROR, BRIGHT_RED) << "Coinbase transaction must have txType TX_COINBASE, got "
      << static_cast<unsigned>(b.baseTransaction.txType);
    return false;
  }
  if (!(b.baseTransaction.inputs.size() == 1)) {
    logger(ERROR, BRIGHT_RED) << "Coinbase transaction in the block has no inputs";
    return false;
  }
  // Discrete: coinbase outputs are CoinbaseOutput (stripped — spendCommit only).
  // Normal blocks carry exactly one; genesis carries the Treasury Reserve allocation
  // as multiple staggered per-output-unlock CoinbaseOutputs.
  if (height == 0) {
    if (b.baseTransaction.outputs.empty()) {
      logger(ERROR, BRIGHT_RED) << "Genesis coinbase transaction must have at least one output";
      return false;
    }
  } else if (!(b.baseTransaction.outputs.size() == 1)) {
    logger(ERROR, BRIGHT_RED) << "Only 1 output in coinbase transaction allowed";
    return false;
  }
  for (const auto& o : b.baseTransaction.outputs) {
    if (!(o.target.type() == typeid(CoinbaseOutput))) {
      logger(ERROR, BRIGHT_RED) << "Coinbase transaction must have CoinbaseOutputs only";
      return false;
    }
  }
  if (!(b.baseTransaction.pqSignatures.empty())) {
    logger(ERROR, BRIGHT_RED) << "Coinbase transaction must not have pqSignatures";
    return false;
  }
  if (!(b.baseTransaction.inputs[0].type() == typeid(BaseInput))) {
    logger(ERROR, BRIGHT_RED) << "Coinbase transaction must have a BaseInput as first input";
    return false;
  }
  if (boost::get<BaseInput>(b.baseTransaction.inputs[0]).blockIndex != height) {
    logger(INFO, BRIGHT_RED) << "The miner transaction in block has invalid height: "
      << boost::get<BaseInput>(b.baseTransaction.inputs[0]).blockIndex
      << ", expected: " << height;
    return false;
  }
  // Genesis (height 0) uses per-output unlockHeights for the Treasury Reserve
  // batches, so the per-tx unlockHeight equality does not apply there.
  if (height != 0 &&
      !(b.baseTransaction.unlockHeight == height + m_currency.minedMoneyUnlockWindow())) {
    logger(ERROR, BRIGHT_RED) << "Coinbase transaction has wrong unlock time="
      << b.baseTransaction.unlockHeight
      << ", expected " << (height + m_currency.minedMoneyUnlockWindow());
    return false;
  }
  if (!check_outs_overflow(b.baseTransaction)) {
    logger(ERROR, BRIGHT_RED) << "The miner transaction has money overflow in block "
      << get_block_hash(b);
    return false;
  }
  uint64_t extraSize = (uint64_t)b.baseTransaction.extra.size();
  uint64_t maxExtra = CryptoNote::maxExtraSize(b.majorVersion);
  if (extraSize > maxExtra) {
    logger(ERROR, BRIGHT_RED) << "The miner transaction extra is too large in block "
      << get_block_hash(b) << ". Allowed: " << maxExtra
      << ", actual: " << extraSize;
    return false;
  }
  return true;
}

bool Blockchain::validate_miner_transaction(const Block& b, uint32_t height,
                                             size_t cumulativeBlockSize,
                                             uint64_t alreadyGeneratedCoins,
                                             uint64_t fee, uint64_t& reward,
                                             int64_t& emissionChange) {
  uint64_t minerReward = 0;
  for (auto& o : b.baseTransaction.outputs) {
    minerReward += o.amount;
  }

  // Genesis (height 0) carries the Treasury Reserve allocation in its coinbase.
  // There is no emission-curve "block reward" for it; the whole coinbase value is
  // the Treasury Reserve and becomes alreadyGeneratedCoins for the next block. Accept the
  // coinbase sum as-is (it is fixed forever by GENESIS_COINBASE_TX_HEX) and
  // report it as the emission change.
  if (height == 0) {
    reward = minerReward;
    emissionChange = static_cast<int64_t>(minerReward);
    return true;
  }

  std::vector<size_t> lastBlocksSizes;
  get_last_n_blocks_sizes(lastBlocksSizes, m_currency.rewardBlocksWindow());
  size_t blocksSizeMedian = Common::medianValue(lastBlocksSizes);

  auto blockMajorVersion = getBlockMajorVersionForHeight(height);
  if (!m_currency.getBlockReward(blockMajorVersion, blocksSizeMedian, cumulativeBlockSize,
                                  alreadyGeneratedCoins, fee, reward, emissionChange)) {
    logger(INFO, BRIGHT_WHITE) << "block size " << cumulativeBlockSize
      << " is bigger than allowed for this blockchain";
    return false;
  }
  if (minerReward > reward) {
    logger(ERROR, BRIGHT_RED) << "Coinbase transaction spend too much money: "
      << m_currency.formatAmount(minerReward)
      << ", block reward is " << m_currency.formatAmount(reward);
    return false;
  } else if (minerReward < reward) {
    logger(ERROR, BRIGHT_RED) << "Coinbase transaction doesn't use full amount of block reward: spent "
      << m_currency.formatAmount(minerReward)
      << ", block reward is " << m_currency.formatAmount(reward);
    return false;
  }
  return true;
}

bool Blockchain::validate_block_signature(const Block& b, const Crypto::Hash& id, uint32_t height) {
  // Genesis block is trusted by definition — no signature required.
  if (height == 0) return true;

  // DiscretePower reward binding (https://docs.discrete.cash/#/consensus/pow §8.3). The PoW
  // signature (b.signature) has ALREADY been verified against minerSpendPk by
  // checkProofOfWork, which every caller runs first and which enforces the spec's
  // verify-before-yespower ordering. There is no second reward signature: here we
  // only enforce that the single coinbase output commits to that same signer, so
  // the reward can only ever be spent by the key that signed the block.
  if (b.signature.size() != CryptoNote::PQ_SIGNATURE_SIZE) {
    logger(ERROR, BRIGHT_RED) << "Block " << id << " at height " << height
                               << " has wrong PoW signature size " << b.signature.size();
    return false;
  }
  if (b.baseTransaction.outputs.empty()) {
    logger(ERROR, BRIGHT_RED) << "Block " << id << " has no coinbase outputs";
    return false;
  }

  // Get miner spend pub from coinbase extra.
  std::array<uint8_t, CryptoNote::PQ_AUTH_PUB_SIZE> spendPubBytes;
  if (!getPqMinerSpendPubFromExtra(b.baseTransaction.extra, spendPubBytes)) {
    logger(ERROR, BRIGHT_RED) << "Block " << id << " coinbase extra missing PQ miner spend pub";
    return false;
  }
  CryptoPQ::DsaPublicKey spendPub;
  std::copy(spendPubBytes.begin(), spendPubBytes.end(), spendPub.begin());

  // Identity-bound mining: the coinbase reward recipient MUST be the block
  // signer. The single coinbase output's spendCommit must equal
  // spendCommit(signerSpendPub, coinbaseRho(signerSpendPub, height, 0)) — so the
  // reward can only ever be spent by the same ML-DSA key that signed the block.
  // This blocks unsigned reward redirection. A custodial operator can still
  // retain the key, sign candidate jobs, and pay workers off-chain. The coinbase
  // has a single, undivided output — enforced by prevalidate_miner_transaction.
  if (b.baseTransaction.outputs.size() != 1 ||
      b.baseTransaction.outputs[0].target.type() != typeid(CoinbaseOutput)) {
    logger(ERROR, BRIGHT_RED) << "Block " << id << " coinbase must be a single CoinbaseOutput";
    return false;
  }
  const CoinbaseOutput& cbOut = boost::get<CoinbaseOutput>(b.baseTransaction.outputs[0].target);
  CryptoPQ::Rho cbRho = CryptoPQ::coinbaseRho(spendPub, height, 0);
  CryptoPQ::Hash256 expectedCommit = CryptoPQ::spendCommit(spendPub, cbRho);
  if (std::memcmp(cbOut.spendCommit.data, expectedCommit.data(), 32) != 0) {
    logger(ERROR, BRIGHT_RED) << "Block " << id << " at height " << height
      << ": coinbase reward recipient is not the block signer";
    return false;
  }
  return true;
}

// ─── Rollback / chain switching ──────────────────────────────────────────────

bool Blockchain::rollback_blockchain_switching(std::list<Block>& original_chain,
                                                size_t rollback_height) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  flushBatch();  // ensure no pending batch before popping blocks
  while (m_db.getChainHeight() > rollback_height) {
    popBlock();
  }
  for (auto& bl : original_chain) {
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    bool r = pushBlock(bl, get_block_hash(bl), bvc);
    if (!(r && bvc.m_added_to_main_chain)) {
      logger(ERROR, BRIGHT_RED) << "PANIC!!! failed to add (again) block while chain switching during rollback!";
      return false;
    }
  }
  logger(INFO, BRIGHT_WHITE) << "Rollback success.";
  return true;
}

bool Blockchain::switch_to_alternative_blockchain(const std::list<Crypto::Hash>& alt_chain,
                                                   bool discard_disconnected_chain) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);

  // Flush any pending IBD batch before disconnecting blocks.
  // removeLastBlock() needs its own write txn for each block removal;
  // a stale batch txn would cause a nested-write-txn deadlock.
  flushBatch();

  if (alt_chain.empty()) {
    logger(ERROR, BRIGHT_RED) << "switch_to_alternative_blockchain: empty chain passed";
    return false;
  }

  size_t split_height = static_cast<size_t>(m_alternative_chains[alt_chain.front()].height);
  uint32_t chainHeight = m_db.getChainHeight();

  if (!(chainHeight > split_height)) {
    logger(ERROR, BRIGHT_RED) << "switch_to_alternative_blockchain: blockchain size is lower than split height";
    return false;
  }

  // Check block versions
  for (const auto& hash : alt_chain) {
    const Block& b = m_alternative_chains[hash].bl;
    if (!checkBlockVersion(b)) {
      logger(ERROR, BRIGHT_RED) << "switch_to_alternative_blockchain: wrong major version of block " << hash;
      return false;
    }
  }

  // Disconnect old chain
  std::list<Block> disconnected_chain;
  chainHeight = m_db.getChainHeight();
  for (int i = (int)chainHeight - 1; i >= (int)split_height; i--) {
    std::vector<uint8_t> bdata;
    m_db.getBlockData((uint32_t)i, bdata);
    Block b;
    fromBinaryArray(b, bdata);
    popBlock();
    disconnected_chain.push_front(b);
  }

  // Connect new alternative chain
  for (auto alt_ch_iter = alt_chain.begin(); alt_ch_iter != alt_chain.end(); alt_ch_iter++) {
    const auto& ch_ent_h = *alt_ch_iter;
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    const Block& b = m_alternative_chains[ch_ent_h].bl;
    bool r = pushBlock(b, get_block_hash(b), bvc);
    if (!r || !bvc.m_added_to_main_chain) {
      logger(INFO, BRIGHT_WHITE) << "Failed to switch to alternative blockchain";
      rollback_blockchain_switching(disconnected_chain, split_height);
      logger(INFO, BRIGHT_WHITE) << "The block was inserted as invalid while connecting new alternative chain, block_id: " << ch_ent_h;
      {
        auto range = m_orphanBlocksIndex.equal_range(get_block_height(b));
        for (auto it = range.first; it != range.second; ) {
          if (it->second == ch_ent_h) it = m_orphanBlocksIndex.erase(it);
          else ++it;
        }
      }
      m_alternative_chains.erase(ch_ent_h);
      try {
        for (auto it2 = ++alt_ch_iter; it2 != alt_chain.end(); it2++) {
          const auto& ch_ent_hh = *it2;
          const Block& bb = m_alternative_chains[ch_ent_hh].bl;
          uint32_t bbh = get_block_height(bb);
          auto range2 = m_orphanBlocksIndex.equal_range(bbh);
          for (auto it3 = range2.first; it3 != range2.second; ) {
            if (it3->second == ch_ent_hh) it3 = m_orphanBlocksIndex.erase(it3);
            else ++it3;
          }
          m_alternative_chains.erase(ch_ent_hh);
        }
      } catch (std::exception& e) {
        logger(ERROR) << "removing alt_chain entries while connecting new alternative chain failed: " << e.what();
      }
      return false;
    }
  }

  if (!discard_disconnected_chain) {
    for (const auto& old_ch_ent : disconnected_chain) {
      block_verification_context bvc = boost::value_initialized<block_verification_context>();
      bool r = handle_alternative_block(old_ch_ent, get_block_hash(old_ch_ent), bvc, false);
      if (!r) {
        logger(WARNING, BRIGHT_YELLOW) << "Failed to push ex-main chain blocks to alternative chain";
        break;
      }
    }
  }

  std::vector<Crypto::Hash> blocksFromCommonRoot;
  blocksFromCommonRoot.reserve(alt_chain.size() + 1);
  const Block& b_front = m_alternative_chains[alt_chain.front()].bl;
  blocksFromCommonRoot.push_back(b_front.previousBlockHash);

  try {
    for (const auto& ch_ent : alt_chain) {
      const Block& bl = m_alternative_chains[ch_ent].bl;
      blocksFromCommonRoot.push_back(get_block_hash(bl));
      uint32_t blh = get_block_height(bl);
      auto range = m_orphanBlocksIndex.equal_range(blh);
      for (auto it = range.first; it != range.second; ) {
        if (it->second == ch_ent) it = m_orphanBlocksIndex.erase(it);
        else ++it;
      }
      m_alternative_chains.erase(ch_ent);
    }
  } catch (std::exception& e) {
    logger(ERROR) << "removing alt_chain entries from alternative chain failed: " << e.what();
  }

  sendMessage(BlockchainMessage(ChainSwitchMessage(std::move(blocksFromCommonRoot))));

  // A successful reorg means we adopted a competing chain — any prior
  // finality-fork wedge is resolved. Clear the operator warning.
  m_finalityForkState = FinalityForkState{};

  logger(INFO, BRIGHT_GREEN) << "REORGANIZE SUCCESS! on height: " << split_height
    << ", new blockchain size: " << m_db.getChainHeight();
  return true;
}

// ─── handle_alternative_block ────────────────────────────────────────────────

bool Blockchain::handle_alternative_block(const Block& b, const Crypto::Hash& id,
                                           block_verification_context& bvc,
                                           bool sendNewAlternativeBlockMessage,
                                           const PrevalidatedBlockProof* prevalidatedProof) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);

  auto block_height = get_block_height(b);
  if (block_height == 0) {
    logger(ERROR, BRIGHT_RED) << "Block with id: " << Common::podToHex(id)
      << " (as alternative) have wrong miner transaction";
    bvc.m_verification_failed = true;
    return false;
  }

  const uint32_t chainLen = getCurrentBlockchainHeight();
  if (!m_checkpoints.is_alternative_block_allowed(chainLen, block_height)) {
    logger(TRACE) << "Block with id: " << id << "\n can't be accepted for alternative chain, "
      << "block height: " << block_height << "\n blockchain height: " << chainLen;
    // If the refusal was the node-local finality rule (not the below-last-
    // checkpoint rule), snapshot the fork for operator messaging/recovery. The
    // block is still refused — this only records why, it does not change the
    // decision. The peer-split hint and the WARNING with peer counts are added
    // by the protocol layer via bvc.m_finality_fork.
    if (m_checkpoints.is_finality_violation(chainLen, block_height)) {
      recordFinalityFork(chainLen, block_height, id);
      bvc.m_finality_fork = true;
    }
    bvc.m_verification_failed = true;
    return false;
  }

  if (!checkBlockVersion(b)) {
    bvc.m_verification_failed = true;
    return false;
  }

  if (!checkParentBlockSize(b, id)) {
    bvc.m_verification_failed = true;
    return false;
  }

  size_t cumulativeSize;
  if (!getBlockCumulativeSize(b, cumulativeSize)) {
    logger(TRACE) << "Block with id: " << id << " has at least one unknown transaction. "
      << "Cumulative size is calculated imprecisely";
  }

  if (!checkCumulativeBlockSize(id, cumulativeSize, block_height)) {
    bvc.m_verification_failed = true;
    return false;
  }

  uint32_t mainPrevHeight = 0;
  const bool mainPrev = m_db.getHashHeight(b.previousBlockHash, mainPrevHeight);
  const auto it_prev = m_alternative_chains.find(b.previousBlockHash);

  if (it_prev != m_alternative_chains.end() || mainPrev) {
    blocks_ext_by_hash::iterator alt_it = it_prev;
    std::list<Crypto::Hash> alt_chain;
    std::vector<uint64_t> timestamps;
    while (alt_it != m_alternative_chains.end()) {
      alt_chain.push_front(alt_it->first);
      timestamps.push_back(alt_it->second.bl.timestamp);
      alt_it = m_alternative_chains.find(alt_it->second.bl.previousBlockHash);
    }

    if (alt_chain.size()) {
      const BlockEntry& bei = m_alternative_chains[alt_chain.front()];
      if (!(m_db.getChainHeight() > bei.height)) {
        logger(ERROR, BRIGHT_RED) << "main blockchain wrong height";
        return false;
      }
      Crypto::Hash h = NULL_HASH;
      std::vector<uint8_t> bdata;
      m_db.getBlockData(bei.height - 1, bdata);
      Block prevBlk;
      fromBinaryArray(prevBlk, bdata);
      get_block_hash(prevBlk, h);
      if (!(h == bei.bl.previousBlockHash)) {
        logger(ERROR, BRIGHT_RED) << "alternative chain have wrong connection to main chain";
        return false;
      }
      complete_timestamps_vector(b.majorVersion, bei.height - 1, timestamps);
    } else {
      if (!mainPrev) {
        logger(ERROR, BRIGHT_RED) << "internal error: broken imperative condition "
          "it_main_prev != m_blocks_index.end()";
        return false;
      }
      complete_timestamps_vector(b.majorVersion, mainPrevHeight, timestamps);
    }

    if (!check_block_timestamp(timestamps, b)) {
      logger(INFO, BRIGHT_RED) << "Block with id: " << id << "\n"
        << " for alternative chain, have invalid timestamp: " << b.timestamp;
      bvc.m_verification_failed = true;
      return false;
    }

    BlockEntry bei = boost::value_initialized<BlockEntry>();
    bei.bl = b;
    bei.height = alt_chain.size() ? it_prev->second.height + 1 : mainPrevHeight + 1;

    bool is_a_checkpoint;
    if (!m_checkpoints.check_block(bei.height, id, is_a_checkpoint)) {
      logger(ERROR, BRIGHT_RED) << "CHECKPOINT VALIDATION FAILED";
      bvc.m_verification_failed = true;
      return false;
    }

    // Disable merged mining
    if (bei.bl.majorVersion >= CryptoNote::BLOCK_MAJOR_VERSION_5) {
      TransactionExtraMergeMiningTag mmTag;
      if (getMergeMiningTagFromExtra(bei.bl.baseTransaction.extra, mmTag)) {
        logger(ERROR, BRIGHT_RED) << "Merge mining tag was found in extra of miner transaction";
        return false;
      }
    }

    Difficulty current_diff = getDifficultyForNextBlock(bei.bl.previousBlockHash);
    if (!current_diff) {
      logger(ERROR, BRIGHT_RED) << "!!!!!!! DIFFICULTY OVERHEAD !!!!!!!";
      return false;
    }

    Crypto::Hash proof_of_work = NULL_HASH;
    const bool powValid = prevalidatedProof != nullptr
      ? (proof_of_work = prevalidatedProof->proofOfWork, check_hash(proof_of_work, current_diff))
      : checkProofOfWork(m_cn_context, bei.bl, current_diff, proof_of_work);
    if (!powValid) {
      logger(INFO, BRIGHT_RED) << "Block with id: " << Common::podToHex(id)
        << "\n for alternative chain, has not enough proof of work: " << proof_of_work
        << "\n expected difficulty: " << current_diff;
      bvc.m_verification_failed = true;
      return false;
    }

    if (!prevalidate_miner_transaction(b, bei.height)) {
      logger(INFO, BRIGHT_RED) << "Block with id: " << Common::podToHex(id)
        << " (as alternative) has wrong miner transaction.";
      bvc.m_verification_failed = true;
      return false;
    }

    if (!validate_block_signature(b, id, bei.height)) {
      logger(INFO, BRIGHT_RED) << "Block with id: " << Common::podToHex(id)
        << " (as alternative) has wrong miner signature.";
      bvc.m_verification_failed = true;
      return false;
    }

    if (alt_chain.size()) {
      bei.cumulative_difficulty = it_prev->second.cumulative_difficulty;
    } else {
      DbBlockMeta prevMeta{};
      m_db.getBlockMeta(mainPrevHeight, prevMeta);
      bei.cumulative_difficulty = prevMeta.cumulativeDifficulty;
    }
    bei.cumulative_difficulty += current_diff;

    auto i_res = m_alternative_chains.insert(blocks_ext_by_hash::value_type(id, bei));
    if (!i_res.second) {
      logger(ERROR, BRIGHT_RED) << "insertion of new alternative block returned as it already exist";
      return false;
    }

    m_orphanBlocksIndex.insert({bei.height, id});

    alt_chain.push_back(i_res.first->first);

    if (is_a_checkpoint) {
      logger(INFO, BRIGHT_GREEN)
        << "###### REORGANIZE on height: " << m_alternative_chains[alt_chain.front()].height
        << " of " << m_db.getChainHeight() - 1
        << ", checkpoint is found in alternative chain on height " << bei.height;
      bool r = switch_to_alternative_blockchain(alt_chain, true);
      if (r) {
        bvc.m_added_to_main_chain = true;
        bvc.m_switched_to_alt_chain = true;
      } else {
        bvc.m_verification_failed = true;
      }
      return r;
    } else {
      // Get last block meta for cumulative difficulty comparison
      uint32_t ch = m_db.getChainHeight();
      DbBlockMeta tailMeta{};
      m_db.getBlockMeta(ch - 1, tailMeta);

      if (tailMeta.cumulativeDifficulty < bei.cumulative_difficulty) {
        logger(INFO, BRIGHT_GREEN)
          << "###### REORGANIZE on height: " << m_alternative_chains[alt_chain.front()].height
          << " of " << ch - 1 << " with cumulative difficulty " << tailMeta.cumulativeDifficulty
          << "\n alternative blockchain size: " << alt_chain.size()
          << " with cumulative difficulty " << bei.cumulative_difficulty;
        bool r = switch_to_alternative_blockchain(alt_chain, false);
        if (r) {
          bvc.m_added_to_main_chain = true;
          bvc.m_switched_to_alt_chain = true;
        } else {
          bvc.m_verification_failed = true;
        }
        return r;
      } else {
        logger(INFO, BRIGHT_BLUE)
          << "----- BLOCK ADDED AS ALTERNATIVE ON HEIGHT " << bei.height
          << "\nid:         " << id
          << "\nPoW:        " << proof_of_work
          << "\ndifficulty: " << current_diff;
        if (sendNewAlternativeBlockMessage) {
          sendMessage(BlockchainMessage(NewAlternativeBlockMessage(id)));
        }
        return true;
      }
    }
  } else {
    bvc.m_marked_as_orphaned = true;
    logger(INFO, BRIGHT_RED) << "Block recognized as orphaned and rejected, id = " << id;
  }
  return true;
}

// ─── getBlocks ───────────────────────────────────────────────────────────────

bool Blockchain::getBlocks(uint32_t start_offset, uint32_t count,
                            std::list<Block>& blocks, std::list<Transaction>& txs) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t chainHeight = m_db.getChainHeight();
  if (start_offset >= chainHeight) return false;
  for (uint32_t i = start_offset; i < start_offset + count && i < chainHeight; i++) {
    std::vector<uint8_t> bdata;
    m_db.getBlockData(i, bdata);
    Block blk;
    fromBinaryArray(blk, bdata);
    blocks.push_back(blk);
    std::list<Crypto::Hash> missed_ids;
    getTransactions(blk.transactionHashes, txs, missed_ids);
    if (!missed_ids.empty()) {
      logger(ERROR, BRIGHT_RED) << "have missed transactions in own block in main blockchain";
      return false;
    }
  }
  return true;
}

bool Blockchain::getBlocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t chainHeight = m_db.getChainHeight();
  if (start_offset >= chainHeight) return false;
  for (uint32_t i = start_offset; i < start_offset + count && i < chainHeight; i++) {
    std::vector<uint8_t> bdata;
    m_db.getBlockData(i, bdata);
    Block blk;
    fromBinaryArray(blk, bdata);
    blocks.push_back(blk);
  }
  return true;
}

bool Blockchain::getTransactionsWithOutputGlobalIndexes(
    const std::vector<Crypto::Hash>& txs_ids,
    std::list<Crypto::Hash>& missed_txs,
    std::vector<std::pair<Transaction, std::vector<uint32_t>>>& txs) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  for (const auto& tx_id : txs_ids) {
    uint32_t block; uint16_t txSlot;
    if (!m_db.getTxIndex(tx_id, block, txSlot)) {
      missed_txs.push_back(tx_id);
    } else {
      TransactionEntry te = transactionByIndex({block, txSlot});
      // A transaction with no outputs (e.g. a free account registration that carries
      // only a tx_extra tag) legitimately has no global output indexes. Only an
      // output-bearing tx missing its indexes is an internal error.
      if (te.m_global_output_indexes.empty() && !te.tx.outputs.empty()) {
        logger(ERROR, BRIGHT_RED) << "internal error: global indexes for transaction "
          << tx_id << " is empty";
        return false;
      }
      txs.push_back({te.tx, te.m_global_output_indexes});
    }
  }
  return true;
}

bool Blockchain::handleGetObjects(NOTIFY_REQUEST_GET_OBJECTS::request& arg,
                                   NOTIFY_RESPONSE_GET_OBJECTS::request& rsp) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  rsp.current_blockchain_height = getCurrentBlockchainHeight();
  std::list<Block> blocks;
  getBlocks(arg.blocks, blocks, rsp.missed_ids);
  for (const auto& bl : blocks) {
    std::list<Crypto::Hash> missed_tx_id;
    std::list<Transaction> txs;
    getTransactions(bl.transactionHashes, txs, missed_tx_id);
    if (!missed_tx_id.empty()) {
      logger(ERROR, BRIGHT_RED) << "Internal error: have missed missed_tx_id.size()="
        << missed_tx_id.size() << "\nfor block id = " << get_block_hash(bl);
      logger(INFO) << "Probably some blockchain indexes or cache is corrupted. "
        "Perform rebuilding cache or just resync from scratch.";
      rsp.missed_ids.insert(rsp.missed_ids.end(), missed_tx_id.begin(), missed_tx_id.end());
      return false;
    }
    rsp.blocks.push_back(block_complete_entry());
    block_complete_entry& e = rsp.blocks.back();
    e.block = asString(toBinaryArray(bl));
    for (Transaction& tx : txs) {
      e.txs.push_back(asString(toBinaryArray(tx)));
    }
  }
  std::list<Transaction> txs;
  getTransactions(arg.txs, txs, rsp.missed_ids);
  for (const auto& tx : txs) {
    rsp.txs.push_back(asString(toBinaryArray(tx)));
  }
  return true;
}

bool Blockchain::getAlternativeBlocks(std::list<Block>& blocks) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  for (auto& alt_bl : m_alternative_chains) {
    blocks.push_back(alt_bl.second.bl);
  }
  return true;
}

uint32_t Blockchain::getAlternativeBlocksCount() {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  return static_cast<uint32_t>(m_alternative_chains.size());
}

// ─── Random outputs ──────────────────────────────────────────────────────────

// ─── findBlockchainSupplement ────────────────────────────────────────────────

uint32_t Blockchain::findBlockchainSupplement(const std::vector<Crypto::Hash>& qblock_ids) {
  assert(!qblock_ids.empty());
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  for (const auto& id : qblock_ids) {
    uint32_t height = 0;
    if (m_db.getHashHeight(id, height)) {
      return height;
    }
  }
  return 0;
}

std::vector<Crypto::Hash> Blockchain::findBlockchainSupplement(
    const std::vector<Crypto::Hash>& remoteBlockIds, size_t maxCount,
    uint32_t& totalBlockCount, uint32_t& startBlockIndex) {
  assert(!remoteBlockIds.empty());
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  totalBlockCount = getCurrentBlockchainHeight();
  startBlockIndex = findBlockchainSupplement(remoteBlockIds);
  return getBlockIds(startBlockIndex, static_cast<uint32_t>(maxCount));
}

std::vector<Crypto::Hash> Blockchain::buildSparseChain() {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t h = m_db.getChainHeight();
  assert(h != 0);
  DbBlockMeta meta{};
  m_db.getBlockMeta(h - 1, meta);
  Crypto::Hash tailHash;
  memcpy(tailHash.data, meta.hash, 32);
  return doBuildSparseChain(tailHash);
}

std::vector<Crypto::Hash> Blockchain::buildSparseChain(const Crypto::Hash& startBlockId) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  assert(haveBlock(startBlockId));
  return doBuildSparseChain(startBlockId);
}

std::vector<Crypto::Hash> Blockchain::doBuildSparseChain(const Crypto::Hash& startBlockId) const {
  uint32_t startBlockHeight = 0;
  bool isInMain = m_db.getHashHeight(startBlockId, startBlockHeight);

  if (isInMain) {
    std::vector<Crypto::Hash> result;
    size_t sparseChainEnd = static_cast<size_t>(startBlockHeight + 1);
    for (size_t i = 1; i <= sparseChainEnd; i *= 2) {
      DbBlockMeta meta{};
      m_db.getBlockMeta(static_cast<uint32_t>(sparseChainEnd - i), meta);
      Crypto::Hash h;
      memcpy(h.data, meta.hash, 32);
      result.emplace_back(h);
    }
    DbBlockMeta genMeta{};
    m_db.getBlockMeta(0, genMeta);
    Crypto::Hash genesisHash;
    memcpy(genesisHash.data, genMeta.hash, 32);
    if (result.back() != genesisHash) {
      result.emplace_back(genesisHash);
    }
    return result;
  } else {
    assert(m_alternative_chains.count(startBlockId) > 0);
    std::vector<Crypto::Hash> alternativeChain;
    Crypto::Hash blockchainAncestor;
    for (auto it = m_alternative_chains.find(startBlockId);
         it != m_alternative_chains.end();
         it = m_alternative_chains.find(blockchainAncestor)) {
      alternativeChain.emplace_back(it->first);
      blockchainAncestor = it->second.bl.previousBlockHash;
    }
    std::vector<Crypto::Hash> sparseChain;
    for (size_t i = 1; i <= alternativeChain.size(); i *= 2) {
      sparseChain.emplace_back(alternativeChain[i - 1]);
    }
    assert(!sparseChain.empty());
    std::vector<Crypto::Hash> sparseMainChain = doBuildSparseChain(blockchainAncestor);
    sparseChain.reserve(sparseChain.size() + sparseMainChain.size());
    std::copy(sparseMainChain.begin(), sparseMainChain.end(), std::back_inserter(sparseChain));
    return sparseChain;
  }
}

bool Blockchain::haveBlock(const Crypto::Hash& id) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t h = 0;
  if (m_db.getHashHeight(id, h)) return true;
  return m_alternative_chains.count(id) > 0;
}

size_t Blockchain::getTotalTransactions() {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t h = m_db.getChainHeight();
  if (h == 0) return 0;
  uint64_t count = 0;
  m_db.getGeneratedTxCount(h - 1, count);
  return static_cast<size_t>(count);
}

std::vector<Crypto::Hash> Blockchain::getBlockIds(uint32_t startHeight, uint32_t maxCount) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  std::vector<Crypto::Hash> result;
  uint32_t chainHeight = m_db.getChainHeight();
  for (uint32_t h = startHeight; h < chainHeight && result.size() < maxCount; ++h) {
    DbBlockMeta meta{};
    m_db.getBlockMeta(h, meta);
    Crypto::Hash hash;
    memcpy(hash.data, meta.hash, 32);
    result.push_back(hash);
  }
  return result;
}

bool Blockchain::getTransactionOutputGlobalIndexes(const Crypto::Hash& tx_id,
                                                    std::vector<uint32_t>& indexs) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t block; uint16_t txSlot;
  if (!m_db.getTxIndex(tx_id, block, txSlot)) {
    logger(WARNING, YELLOW) << "warning: get_tx_outputs_gindexs failed to find transaction with id = " << tx_id;
    return false;
  }
  TransactionEntry te = transactionByIndex({block, txSlot});
  // A transaction with no outputs (e.g. a free account registration that carries only
  // a tx_extra tag) legitimately has no global output indexes; return an empty list.
  // Only an output-bearing tx missing its indexes is an internal error.
  if (te.m_global_output_indexes.empty() && !te.tx.outputs.empty()) {
    logger(ERROR, BRIGHT_RED) << "internal error: global indexes for transaction " << tx_id << " is empty";
    return false;
  }
  indexs.resize(te.m_global_output_indexes.size());
  for (size_t i = 0; i < te.m_global_output_indexes.size(); ++i) {
    indexs[i] = te.m_global_output_indexes[i];
  }
  return true;
}

// ─── Transaction input validation ────────────────────────────────────────────

bool Blockchain::checkTransactionInputs(const Transaction& tx, uint32_t& max_used_block_height,
                                         Crypto::Hash& max_used_block_id, BlockInfo* tail) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  if (tail) tail->id = getTailId(tail->height);

  bool res = checkTransactionInputs(tx, &max_used_block_height);
  if (!res) return false;

  uint32_t chainHeight = m_db.getChainHeight();
  if (!(max_used_block_height < chainHeight)) {
    logger(ERROR, BRIGHT_RED) << "internal error: max used block index=" << max_used_block_height
      << " is not less than blockchain size = " << chainHeight;
    return false;
  }
  DbBlockMeta meta{};
  m_db.getBlockMeta(max_used_block_height, meta);
  memcpy(max_used_block_id.data, meta.hash, 32);
  return true;
}

bool Blockchain::haveTransactionKeyImagesAsSpent(const Transaction& tx) {
  for (const auto& in : tx.inputs) {
    if (in.type() == typeid(PqInput)) {
      const auto ki = pqInputNullifierAsKeyImage(boost::get<PqInput>(in));
      if (have_spend_tag_as_spent(ki)) {
        return true;
      }
    }
  }
  return false;
}

bool Blockchain::checkTransactionInputs(const Transaction& tx, uint32_t* pmax_used_block_height) {
  Crypto::Hash tx_prefix_hash = getObjectHash(*static_cast<const TransactionPrefix*>(&tx));
  return checkTransactionInputs(tx, tx_prefix_hash, pmax_used_block_height);
}

bool Blockchain::checkTransactionInputs(const Transaction& tx, const Crypto::Hash& tx_prefix_hash,
                                         uint32_t* pmax_used_block_height) {
  // Discrete: only PQ transactions are accepted. Legacy v1 (pre-PQ) txs are rejected.
  if (tx.version == TRANSACTION_VERSION_1) {
    // First-registration-wins is chain state, so a registration tx that was valid
    // when it was built (or when it entered the pool) goes stale the moment another
    // block registers the same account. pushTransaction rejects it and takes the
    // whole block down with it, so refuse it here instead: this is the check that
    // runs at pool admission and again when the block template is filled, before a
    // miner spends any work on it. Paid registrations ride on TX_PQ, free ones on
    // TX_FREE_REG — both are covered.
    if ((tx.txType == TX_PQ || tx.txType == TX_FREE_REG) && isPqAccountAlreadyRegistered(tx)) {
      logger(INFO, BRIGHT_WHITE) << "Account already registered, rejecting tx " << getObjectHash(tx);
      return false;
    }
    if (tx.txType == TX_PQ) {
      return checkPqInputs(tx, pmax_used_block_height);
    } else if (tx.txType == TX_FREE_REG) {
      return checkFreeRegInputs(tx, pmax_used_block_height);
    } else if (tx.txType == TX_COINBASE) {
      // Coinbase inputs are validated by block-level checks, not here.
      return true;
    } else {
      logger(ERROR, BRIGHT_RED) << "Unknown PQ tx type " << (int)tx.txType
                                 << " in tx " << getObjectHash(tx);
      return false;
    }
  }
  // All other versions (including ECC v1) are rejected.
  logger(ERROR, BRIGHT_RED) << "Non-PQ transaction version " << (int)tx.version
                             << " rejected in Discrete";
  return false;
}

bool Blockchain::checkPqInputs(const Transaction& tx, uint32_t* pmax_used_block_height) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  if (pmax_used_block_height) *pmax_used_block_height = 0;
  // Discrete: PQ is active from genesis — no height gate needed.

  // Resolve each PqInput's referenced output from the chain.
  std::vector<PqResolvedInput> resolved;
  resolved.reserve(tx.inputs.size());
  uint32_t maxRefHeight = 0;
  for (const auto& txin : tx.inputs) {
    if (txin.type() != typeid(PqInput)) {
      return false;  // semantic check already guarantees this; defensive
    }
    const PqInput& in = boost::get<PqInput>(txin);
    PqResolvedInput r;
    uint32_t block; uint16_t slot;
    if (m_db.getTxIndex(in.prevTxid, block, slot)) {
      try {
        TransactionEntry te = transactionByIndex(TransactionIndex{block, slot});
        if (in.prevOutIndex < te.tx.outputs.size()) {
          const TransactionOutput& o = te.tx.outputs[in.prevOutIndex];
          // Accept both PqOutput (regular TX) and CoinbaseOutput (coinbase TX).
          const bool isPq = (o.target.type() == typeid(PqOutput));
          const bool isCb = (o.target.type() == typeid(CoinbaseOutput));
          if (isPq || isCb) {
            // Maturity: outputs with a non-zero unlockHeight (coinbase reward,
            // genesis Treasury Reserve batch, or any timelock) can only be spent
            // once their PER-OUTPUT lock has elapsed. Unmatured → treat as
            // unresolved so checkPqTransactionInputs rejects.
            if (is_tx_spendheight_unlocked(o.unlockHeight)) {
              r.exists = true;
              r.isPqOutput = true;  // "spendable by a PQ input" — true for both types
              r.isCoinbase = (slot == 0);  // coinbase is always tx slot 0
              r.amount = o.amount;
              r.spendCommit = isPq ? boost::get<PqOutput>(o.target).spendCommit
                                   : boost::get<CoinbaseOutput>(o.target).spendCommit;
              if (block > maxRefHeight) maxRefHeight = block;
            }
          }
        }
      } catch (const std::exception&) {
        // leave r.exists == false; checkPqTransactionInputs rejects it
      }
    }
    resolved.push_back(r);
  }

  std::vector<Crypto::Hash> nullifiers;
  std::string err;
  if (!checkPqTransactionInputs(tx, resolved, parameters::MINIMUM_FEE, &nullifiers, &err)) {
    logger(INFO, BRIGHT_WHITE) << "PQ input check failed (" << err << ") for tx " << getObjectHash(tx);
    return false;
  }

  // On-chain double-spend: none of the nullifiers may already be recorded. A PQ
  // nullifier is a 32-byte spend tag; it shares the single type-agnostic
  // spent-key set with classical/CT key images (they cannot collide).
  for (const auto& nf : nullifiers) {
    Crypto::KeyImage img;
    std::memcpy(&img, &nf, sizeof(img));
    if (m_db.hasSpentKey(img)) {
      logger(DEBUGGING) << "PQ nullifier already spent in blockchain: " << Common::podToHex(nf);
      return false;
    }
  }

  if (pmax_used_block_height) *pmax_used_block_height = maxRefHeight;
  return true;
}

uint64_t Blockchain::pqReferencedInputAmount(const Transaction& tx) {
  uint64_t sum = 0;
  for (const auto& txin : tx.inputs) {
    if (txin.type() != typeid(PqInput)) continue;
    const PqInput& in = boost::get<PqInput>(txin);
    uint32_t block; uint16_t slot;
    if (!m_db.getTxIndex(in.prevTxid, block, slot)) continue;
    try {
      TransactionEntry te = transactionByIndex(TransactionIndex{block, slot});
      if (in.prevOutIndex < te.tx.outputs.size()) {
        const auto& tgt = te.tx.outputs[in.prevOutIndex].target;
        if (tgt.type() == typeid(PqOutput) || tgt.type() == typeid(CoinbaseOutput)) {
          sum += te.tx.outputs[in.prevOutIndex].amount;
        }
      }
    } catch (const std::exception&) {
      // unresolved (checkPqInputs already rejected such a tx); contributes 0
    }
  }
  return sum;
}

bool Blockchain::getPqTransactionFee(const Transaction& tx, uint64_t& fee) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  const uint64_t inAmount = pqReferencedInputAmount(tx);
  const uint64_t outAmount = getOutputAmount(tx);
  if (outAmount > inAmount) {
    return false;
  }
  fee = inAmount - outAmount;
  return true;
}

bool Blockchain::checkFreeRegInputs(const Transaction& tx, uint32_t* pmax_used_block_height) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  if (pmax_used_block_height) *pmax_used_block_height = 0;
  // Discrete: free-reg is active from genesis.

  TransactionExtraPqAccountRegistration reg;
  TransactionExtraPow pow;
  if (!getPqAccountRegistrationFromExtra(tx.extra, reg) ||
      !getPowTagFromExtra(tx.extra, pow)) {
    return false;  // semantic check should have caught this
  }

  // refBlockHash must be a main-chain block within the last FREE_REG_REF_WINDOW.
  const uint32_t curHeight = getCurrentBlockchainHeight();
  uint32_t refHeight = 0;
  if (!m_db.getHashHeight(pow.refBlockHash, refHeight)) {
    logger(INFO, BRIGHT_WHITE) << "free-reg refBlockHash not on the main chain, rejected";
    return false;
  }
  if (refHeight >= curHeight ||
      curHeight - refHeight > parameters::FREE_REG_REF_WINDOW) {
    logger(INFO, BRIGHT_WHITE) << "free-reg refBlockHash outside the reference window, rejected";
    return false;
  }

  // First-registration-wins: reject if the full PQ identity is already registered.
  // (checkTransactionInputs runs the same check for every registration-carrying tx
  // type; repeated here so this entry point stands on its own.)
  if (isPqAccountAlreadyRegistered(tx)) {
    logger(INFO, BRIGHT_WHITE) << "free-reg account already registered, rejected";
    return false;
  }

  if (pmax_used_block_height) *pmax_used_block_height = refHeight;
  return true;
}

bool Blockchain::isPqAccountAlreadyRegistered(const Transaction& tx) {
  TransactionExtraPqAccountRegistration reg;
  if (!getPqAccountRegistrationFromExtra(tx.extra, reg)) {
    return false;
  }
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  return m_db.hasPqAcctReg(getPqAccountIdentityHash(reg));
}

bool Blockchain::is_tx_spendheight_unlocked(uint64_t unlock_height) {
  if (unlock_height == 0) return true;
  if (unlock_height > m_currency.maxBlockHeight()) return false;
  const uint32_t currentHeight = getCurrentBlockchainHeight();
  return currentHeight - 1 + m_currency.lockedTxAllowedDeltaBlocks() >= unlock_height;
}

bool Blockchain::is_tx_spendheight_unlocked(uint64_t unlock_height, uint32_t height) {
  if (unlock_height == 0) return true;
  if (unlock_height > m_currency.maxBlockHeight()) return false;
  return height - 1 + m_currency.lockedTxAllowedDeltaBlocks() >= unlock_height;
}

// ─── addNewBlock / pushBlock / popBlock ──────────────────────────────────────

bool Blockchain::addNewBlock(const Block& bl, block_verification_context& bvc,
                             const PrevalidatedBlockProof* prevalidatedProof) {
  Crypto::Hash id;
  if (!get_block_hash(bl, id)) {
    logger(ERROR, BRIGHT_RED) << "Failed to get block hash, possible block has invalid format";
    bvc.m_verification_failed = true;
    return false;
  }

  if (prevalidatedProof != nullptr && prevalidatedProof->blockHash != id) {
    logger(ERROR, BRIGHT_RED) << "Prevalidated PoW block ID mismatch for " << id;
    bvc.m_verification_failed = true;
    return false;
  }

  bool add_result;
  {
    std::lock_guard<decltype(m_tx_pool)> poolLock(m_tx_pool);
    std::lock_guard<decltype(m_blockchain_lock)> bcLock(m_blockchain_lock);

    if (haveBlock(id)) {
      logger(TRACE) << "block with id = " << id << " already exists";
      bvc.m_already_exists = true;
      return false;
    }

    if (!(bl.previousBlockHash == getTailId())) {
      uint32_t blockHeight = 0;
      if (!bl.baseTransaction.inputs.empty()) {
        if (const BaseInput* baseInput = boost::get<BaseInput>(&bl.baseTransaction.inputs.front())) {
          blockHeight = baseInput->blockIndex;
        }
      }
      logger(DEBUGGING) << "handling alternative block " << Common::podToHex(id)
        << " at height " << blockHeight
        << " as it doesn't refer to chain tail " << Common::podToHex(getTailId())
        << ", its prev. block hash: " << Common::podToHex(bl.previousBlockHash);
      bvc.m_added_to_main_chain = false;
      add_result = handle_alternative_block(bl, id, bvc, true, prevalidatedProof);
    } else {
      add_result = pushBlock(bl, id, bvc, prevalidatedProof);
      if (add_result) {
        sendMessage(BlockchainMessage(NewBlockMessage(id)));
      }
    }
  }

  if (add_result && bvc.m_added_to_main_chain) {
    m_observerManager.notify(&IBlockchainStorageObserver::blockchainUpdated);
  }
  return add_result;
}

Blockchain::TransactionEntry Blockchain::transactionByIndex(TransactionIndex idx) {
  std::vector<uint8_t> raw;
  if (!m_db.getTxEntry(idx.block, idx.transaction, raw)) {
    throw std::runtime_error("transactionByIndex: entry not found at block=" +
                             std::to_string(idx.block) + " tx=" + std::to_string(idx.transaction));
  }
  if (raw.size() < sizeof(uint32_t))
    throw std::runtime_error("transactionByIndex: corrupt entry (too small for tx_size)");

  const uint8_t* p = raw.data();
  uint32_t txSize;
  memcpy(&txSize, p, sizeof(uint32_t)); p += sizeof(uint32_t);

  if (raw.size() < sizeof(uint32_t) + txSize + sizeof(uint32_t))
    throw std::runtime_error("transactionByIndex: corrupt entry (truncated)");

  TransactionEntry te;
  if (!fromBinaryArray(te.tx, BinaryArray(p, p + txSize)))
    throw std::runtime_error("transactionByIndex: tx deserialize failed");
  p += txSize;

  uint32_t numGidx;
  memcpy(&numGidx, p, sizeof(uint32_t)); p += sizeof(uint32_t);

  te.m_global_output_indexes.resize(numGidx);
  for (uint32_t i = 0; i < numGidx; ++i) {
    memcpy(&te.m_global_output_indexes[i], p, sizeof(uint32_t));
    p += sizeof(uint32_t);
  }
  return te;
}

bool Blockchain::pushBlock(const Block& blockData, const Crypto::Hash& id,
                            block_verification_context& bvc,
                            const PrevalidatedBlockProof* prevalidatedProof) {
  std::vector<Transaction> transactions;
  if (!loadTransactions(blockData, transactions)) {
    bvc.m_verification_failed = true;
    return false;
  }
  if (!pushBlock(blockData, transactions, id, bvc, prevalidatedProof)) {
    saveTransactions(transactions);
    return false;
  }
  return true;
}

bool Blockchain::pushBlock(const Block& blockData, const std::vector<Transaction>& transactions,
                            const Crypto::Hash& blockHash, block_verification_context& bvc,
                            const PrevalidatedBlockProof* prevalidatedProof) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);

  auto blockProcessingStart = std::chrono::steady_clock::now();

  {
    uint32_t h = 0;
    if (m_db.getHashHeight(blockHash, h)) {
      logger(ERROR, BRIGHT_RED) << "Block " << blockHash << " already exists in blockchain.";
      bvc.m_verification_failed = true;
      return false;
    }
  }

  if (!checkBlockVersion(blockData)) {
    bvc.m_verification_failed = true;
    return false;
  }
  if (!checkParentBlockSize(blockData, blockHash)) {
    bvc.m_verification_failed = true;
    return false;
  }
  if (blockData.majorVersion >= CryptoNote::BLOCK_MAJOR_VERSION_5) {
    TransactionExtraMergeMiningTag mmTag;
    if (getMergeMiningTagFromExtra(blockData.baseTransaction.extra, mmTag)) {
      logger(ERROR, BRIGHT_RED) << "Merge mining tag was found in extra of miner transaction";
      return false;
    }
  }
  if (blockData.previousBlockHash != getTailId()) {
    logger(INFO, BRIGHT_WHITE) << "Block " << blockHash << " has wrong previousBlockHash: "
      << blockData.previousBlockHash << ", expected: " << getTailId();
    bvc.m_verification_failed = true;
    return false;
  }
  if (!check_block_timestamp_main(blockData)) {
    logger(INFO, BRIGHT_WHITE) << "Block " << blockHash
      << " has invalid timestamp: " << blockData.timestamp;
    bvc.m_verification_failed = true;
    return false;
  }

  auto targetTimeStart = std::chrono::steady_clock::now();
  Difficulty currentDifficulty = getDifficultyForNextBlock(blockData.previousBlockHash);
  auto target_calculating_time = std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::steady_clock::now() - targetTimeStart).count();

  if (!currentDifficulty) {
    logger(ERROR, BRIGHT_RED) << "!!!!!!!!! difficulty overhead !!!!!!!!!";
    return false;
  }

  // getChainHeight() uses activeTxn() so it correctly accounts for any blocks
// already written into an open batch write txn from previous calls.
  uint32_t newHeight = m_db.getChainHeight();

  auto longhashTimeStart = std::chrono::steady_clock::now();
  Crypto::Hash proof_of_work = NULL_HASH;
  
  const bool inCheckpoint = m_checkpoints.is_in_checkpoint_zone(newHeight);
  if (newHeight == 0) {
    // Genesis is trusted by definition — its signature is an all-zero
    // placeholder that no key signs. Skip PoW/signature here exactly as
    // validate_block_signature skips the signature at height 0. (DiscretePower
    // verifies the ML-DSA signature inside checkProofOfWork, so genesis must be
    // exempted here rather than relying on a trivial difficulty pass.)
  }
  else if (inCheckpoint) {
    if (!m_checkpoints.check_block(newHeight, blockHash)) {
      logger(ERROR, BRIGHT_RED) << "CHECKPOINT VALIDATION FAILED";
      bvc.m_verification_failed = true;
      return false;
    }
  }
  else {
    const bool powValid = prevalidatedProof != nullptr
      ? (proof_of_work = prevalidatedProof->proofOfWork, check_hash(proof_of_work, currentDifficulty))
      : checkProofOfWork(m_cn_context, blockData, currentDifficulty, proof_of_work);
    if (!powValid) {
      logger(INFO, BRIGHT_WHITE) << "Block " << blockHash
        << ", has too weak proof of work: " << proof_of_work
        << ", expected difficulty: " << currentDifficulty;
      bvc.m_verification_failed = true;
      return false;
    }
  }

  auto longhash_calculating_time = std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::steady_clock::now() - longhashTimeStart).count();

  if (!prevalidate_miner_transaction(blockData, newHeight)) {
    logger(INFO, BRIGHT_WHITE) << "Block " << blockHash << " failed to pass prevalidation";
    bvc.m_verification_failed = true;
    return false;
  }
  if (!validate_block_signature(blockData, blockHash, newHeight)) {
    logger(INFO, BRIGHT_RED) << "Block with id: " << Common::podToHex(blockHash)
      << " has wrong miner signature.";
    bvc.m_verification_failed = true;
    return false;
  }

  // Pre-compute values that are stable across map-full retries.
  // These read from already-committed blocks so they work outside the write txn.
  const Crypto::Hash minerTransactionHash = getObjectHash(blockData.baseTransaction);
  const size_t coinbase_blob_size = getObjectBinarySize(blockData.baseTransaction);

  uint64_t already_generated_coins = 0;
  Difficulty prevCumulativeDifficulty = 0;
  if (newHeight > 0) {
    DbBlockMeta prevMeta{};
    m_db.getBlockMeta(newHeight - 1, prevMeta);
    already_generated_coins   = prevMeta.alreadyGeneratedCoins;
    prevCumulativeDifficulty  = prevMeta.cumulativeDifficulty;
  }

  // Outputs that must survive past the write-txn block for the log below.
  BlockEntry block;
  block.bl     = blockData;
  block.height = newHeight;
  size_t   cumulative_block_size = coinbase_blob_size;
  uint64_t fee_summary           = 0;
  int64_t  emissionChange        = 0;
  uint64_t reward                = 0;

  // ── Write section ────────────────────────────────────────────────────────
  // beginBatchIfNeeded() opens a new write txn (+ enables MDB_NOSYNC) only
  // when no batch is already in flight; otherwise the existing txn is reused.
  // commitBatchOrBlock() decides whether to commit immediately (normal live
  // operation) or to defer until BATCH_SIZE blocks have accumulated (sync).
  //
  // On map-full the whole batch is aborted and the chain reverts to the last
  // committed height; the protocol handler re-syncs from there.
  block.transactions.resize(1);
  block.transactions[0].tx = blockData.baseTransaction;
  TransactionIndex transactionIndex = {newHeight, 0};
  bool blockTxnActive = false;

  auto abortCurrentBlockTxn = [&]() {
    if (blockTxnActive && m_db.hasNestedTxn()) {
      m_db.abortNestedWriteTxn();
      blockTxnActive = false;
    } else if (m_db.hasActiveTxn() && m_batchCount == 0) {
      m_db.abortTxn();
    }
  };

  auto abortEntireBatchTxn = [&]() {
    if (blockTxnActive && m_db.hasNestedTxn()) {
      m_db.abortNestedWriteTxn();
      blockTxnActive = false;
    }
    m_db.abortTxn();
    m_batchCount = 0;
  };

  try {
    beginBatchIfNeeded();
    if (m_batchCount > 0) {
      m_db.beginNestedWriteTxn();
      blockTxnActive = true;
    }

    if (!pushTransaction(block, minerTransactionHash, transactionIndex)) {
      abortCurrentBlockTxn();
      bvc.m_verification_failed = true;
      return false;
    }

    size_t freeRegCount = 0;
    std::unordered_set<Crypto::Hash> pqRegistrationsInBlock;

    for (size_t i = 0; i < transactions.size(); ++i) {
      const Crypto::Hash& tx_id = blockData.transactionHashes[i];
      block.transactions.resize(block.transactions.size() + 1);
      block.transactions.back().tx = transactions[i];

      const Transaction& curTx = block.transactions.back().tx;
      size_t blob_size = toBinaryArray(curTx).size();
      if (curTx.version >= TRANSACTION_VERSION_1 && curTx.txType == TX_FREE_REG) {
        ++freeRegCount;
        if (freeRegCount > m_currency.freeRegPerBlock()) {
          logger(INFO, BRIGHT_WHITE) << "Block " << blockHash
            << " exceeds the free PQ registration limit";
          bvc.m_verification_failed = true;
          abortCurrentBlockTxn();
          return false;
        }
      }
      TransactionExtraPqAccountRegistration pqReg;
      if (getPqAccountRegistrationFromExtra(curTx.extra, pqReg)) {
        const Crypto::Hash accountId = getPqAccountIdentityHash(pqReg);
        if (!pqRegistrationsInBlock.insert(accountId).second) {
          logger(INFO, BRIGHT_WHITE) << "Block " << blockHash
            << " contains duplicate PQ account registrations";
          bvc.m_verification_failed = true;
          abortCurrentBlockTxn();
          return false;
        }
      }
      // TX_PQ inputs carry no amount (value lives in the referenced outputs), so
      // getInputAmount would read 0 and the fee would underflow. Resolve the
      // referenced amounts instead.
      const bool pqOnlyInputs = curTx.version >= TRANSACTION_VERSION_1 && curTx.txType == TX_PQ;
      uint64_t fee = 0;
      if (pqOnlyInputs) {
        if (!getPqTransactionFee(curTx, fee)) {
          logger(INFO, BRIGHT_WHITE) << "Block " << blockHash
            << " has TX_PQ with invalid value balance: " << tx_id;
          bvc.m_verification_failed = true;
          abortCurrentBlockTxn();
          return false;
        }
      } else {
        uint64_t inAmount = getInputAmount(curTx);
        uint64_t outAmount = getOutputAmount(curTx);
        if (outAmount > inAmount) {
          logger(INFO, BRIGHT_WHITE) << "Block " << blockHash
            << " has transaction spending more than its inputs: " << tx_id;
          bvc.m_verification_failed = true;
          abortCurrentBlockTxn();
          return false;
        }
        fee = inAmount - outAmount;
      }

      // Under a confirmed checkpoint the block hash has already been verified by
      // the network. Skip the expensive per-input validation (key-image domain
      // check, output-key LMDB scans) - pushTransaction still records everything.
      if (!inCheckpoint && !checkTransactionInputs(block.transactions.back().tx)) {
        logger(INFO, BRIGHT_WHITE) << "Block " << blockHash
          << " has at least one transaction with wrong inputs: " << tx_id;
        bvc.m_verification_failed = true;
        abortCurrentBlockTxn();
        return false;
      }

      ++transactionIndex.transaction;
      if (!pushTransaction(block, tx_id, transactionIndex)) {
        abortCurrentBlockTxn();
        bvc.m_verification_failed = true;
        return false;
      }

      cumulative_block_size += blob_size;
      fee_summary += fee;
    }

    if (!checkCumulativeBlockSize(blockHash, cumulative_block_size, newHeight)) {
      bvc.m_verification_failed = true;
      abortCurrentBlockTxn();
      return false;
    }

    if (!validate_miner_transaction(blockData, newHeight, cumulative_block_size,
                                     already_generated_coins, fee_summary, reward, emissionChange)) {
      logger(INFO, BRIGHT_WHITE) << "Block " << blockHash << " has invalid miner transaction";
      bvc.m_verification_failed = true;
      abortCurrentBlockTxn();
      return false;
    }

    block.block_cumulative_size   = cumulative_block_size;
    block.already_generated_coins = already_generated_coins + emissionChange;
    block.cumulative_difficulty   = currentDifficulty + prevCumulativeDifficulty;

    pushBlock(block, blockHash);  // writes block-level LMDB data
    if (blockTxnActive) {
      m_db.commitNestedWriteTxn();
      blockTxnActive = false;
    }

    commitBatchOrBlock(newHeight == 0);  // commits now if live, defers if syncing

  } catch (const LMDBMapFullException&) {
    // Batch (possibly spanning many blocks) is aborted.  Chain reverts to the
    // last committed height; the protocol handler will re-sync from there.
    abortEntireBatchTxn();
    if (m_batchFastMode) {
      m_db.setFastSyncMode(false);
      m_batchFastMode = false;
    }
    logger(WARNING, BRIGHT_YELLOW) << "LMDB map full at height " << newHeight
      << "; batch aborted. Re-syncing from height " << m_db.getChainHeight()
      << ". Map will be doubled on next block.";
    m_db.resizeMap();
    return false;
  } catch (const std::exception& e) {
    // Any other LMDB error (e.g. MDB_CORRUPTED): abort and clean up batch state.
    abortEntireBatchTxn();
    if (m_batchFastMode) {
      m_db.setFastSyncMode(false);
      m_batchFastMode = false;
    }
    logger(ERROR, BRIGHT_RED) << "Exception adding block " << blockHash << ": " << e.what();
    return false;
  }

  auto block_processing_time = std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::steady_clock::now() - blockProcessingStart).count();

  if (block.height % 1000 == 0) {
    logger(INFO) << "Blockchain loaded to height: " << block.height;
  }

  logger(DEBUGGING)
    << "+++++ BLOCK SUCCESSFULLY ADDED\nid:\t" << blockHash
    << "\nPoW:\t" << proof_of_work
    << "\nHEIGHT " << block.height << ", difficulty:\t" << currentDifficulty
    << "\nblock reward: " << m_currency.formatAmount(reward)
    << ", fee = " << m_currency.formatAmount(fee_summary)
    << ", coinbase_blob_size: " << coinbase_blob_size
    << ", cumulative size: " << cumulative_block_size
    << ", " << block_processing_time
    << "(" << target_calculating_time << "/" << longhash_calculating_time << ")ms";

  bvc.m_added_to_main_chain = true;

  m_upgradeDetectorV2.blockPushed();
  m_upgradeDetectorV3.blockPushed();
  m_upgradeDetectorV4.blockPushed();
  m_upgradeDetectorV5.blockPushed();
  m_upgradeDetectorV6.blockPushed();

  update_next_cumulative_size_limit();
  return true;
}

// Inner pushBlock - writes block-level data within the active write txn.
bool Blockchain::pushBlock(BlockEntry& block, const Crypto::Hash& blockHash) {
  uint32_t height = block.height;

  DbBlockMeta meta{};
  memcpy(meta.hash, blockHash.data, 32);
  if (height > 0) {
    memcpy(meta.prevHash, block.bl.previousBlockHash.data, 32);
  }
  meta.timestamp            = block.bl.timestamp;
  meta.cumulativeDifficulty = block.cumulative_difficulty;
  meta.alreadyGeneratedCoins = block.already_generated_coins;
  meta.blockCumulativeSize  = static_cast<uint32_t>(block.block_cumulative_size);
  meta.height               = height;
  meta.txCount              = static_cast<uint16_t>(block.transactions.size());
  meta.majorVersion         = block.bl.majorVersion;
  meta.minorVersion         = block.bl.minorVersion;

  m_db.putBlockMeta(height, meta);

  BinaryArray blockBlob = toBinaryArray(block.bl);
  m_db.putBlockData(height, blockBlob.data(), blockBlob.size());

  m_db.putHashHeight(blockHash, height);

  m_db.putTimestamp(block.bl.timestamp, blockHash);

  uint64_t prevGenTx = 0;
  if (height > 0) {
    m_db.getGeneratedTxCount(height - 1, prevGenTx);
  }
  uint64_t newGenTx = prevGenTx + block.bl.transactionHashes.size() + 1;
  m_db.putGeneratedTxCount(height, newGenTx);

  return true;
}

void Blockchain::popBlock() {
  uint32_t chainHeight = m_db.getChainHeight();
  if (chainHeight == 0) {
    logger(ERROR, BRIGHT_RED) << "Attempt to pop block from empty blockchain.";
    return;
  }
  uint32_t height = chainHeight - 1;

  DbBlockMeta meta{};
  m_db.getBlockMeta(height, meta);

  // Read non-coinbase transactions before removing
  std::vector<uint8_t> bdata;
  m_db.getBlockData(height, bdata);
  Block blk;
  fromBinaryArray(blk, bdata);

  std::vector<Transaction> transactions;
  for (uint16_t t = 1; t < meta.txCount; ++t) {
    TransactionEntry te = transactionByIndex({height, t});
    transactions.push_back(te.tx);
  }
  saveTransactions(transactions);

  removeLastBlock();

  m_upgradeDetectorV2.blockPopped();
  m_upgradeDetectorV3.blockPopped();
  m_upgradeDetectorV4.blockPopped();
  m_upgradeDetectorV5.blockPopped();
  m_upgradeDetectorV6.blockPopped();
}

// Recompute a PQ input's nullifier (= SHA3-256("discrete-pq-nullifier-v1" ||
// auth_pub || rho_reveal || prev_txid || LE32(prev_out_index))). Binding the
// outpoint makes the double-spend tag unique per output even if two outputs
// share (auth_pub, rho). Fields are fixed-size after serialization; a malformed
// input (wrong sizes) yields a zero hash, which validation rejects.
static Crypto::Hash pqInputNullifier(const PqInput& in) {
  Crypto::Hash h{};
  if (in.authPub.size() != CryptoNote::PQ_AUTH_PUB_SIZE ||
      in.rhoReveal.size() != CryptoNote::PQ_RHO_SIZE) {
    return h;
  }
  CryptoPQ::DsaPublicKey ap;
  CryptoPQ::Rho rho;
  std::memcpy(ap.data(), in.authPub.data(), ap.size());
  std::memcpy(rho.data(), in.rhoReveal.data(), rho.size());
  CryptoPQ::Hash256 prevTxid;
  std::memcpy(prevTxid.data(), in.prevTxid.data, 32);
  CryptoPQ::Hash256 n = CryptoPQ::nullifier(ap, rho, prevTxid, in.prevOutIndex);
  std::memcpy(h.data, n.data(), 32);
  return h;
}

// Map any spendable input to its 32-byte double-spend tag for the single
// type-agnostic spent-key set: a KeyInput's key image, or a PqInput's nullifier
// (reinterpreted as a key image — the two value spaces cannot collide). Returns
// false for inputs that carry no spend tag (e.g. BaseInput).
static bool spendImageForInput(const TransactionInput& in, Crypto::KeyImage& out) {
  if (in.type() == typeid(PqInput)) {
    out = pqInputNullifierAsKeyImage(boost::get<PqInput>(in));
    return true;
  }
  return false;
}

bool Blockchain::pushTransaction(BlockEntry& block, const Crypto::Hash& transactionHash,
                                  TransactionIndex transactionIndex) {
  // Check for duplicate
  {
    uint32_t existBlock; uint16_t existSlot;
    if (m_db.getTxIndex(transactionHash, existBlock, existSlot)) {
      logger(ERROR, BRIGHT_RED) << "Duplicate transaction was pushed to blockchain.";
      return false;
    }
  }

  Transaction& tx = block.transactions[transactionIndex.transaction].tx;

  // Record spent images for BOTH classical KeyInput key images and v2 PqInput
  // nullifiers in the one type-agnostic spent-key set (they are 32-byte spend
  // tags that cannot collide). Detect double-spends within this write txn; an
  // intra-tx duplicate is caught because a put is visible to the next has-check.
  for (size_t i = 0; i < tx.inputs.size(); ++i) {
    Crypto::KeyImage img;
    if (!spendImageForInput(tx.inputs[i], img)) {
      continue;
    }
    if (m_db.hasSpentKey(img)) {
      logger(ERROR, BRIGHT_RED) << "Double spending transaction was pushed to blockchain.";
      // Roll back images already written for this tx.
      for (size_t j = 0; j < i; ++j) {
        Crypto::KeyImage prev;
        if (spendImageForInput(tx.inputs[j], prev)) {
          m_db.removeSpentKey(prev);
        }
      }
      return false;
    }
    m_db.putSpentKey(img, block.height);
  }

  // Record key outputs and fill global output indexes
  // Discrete: all outputs are PqOutput; no KeyOutput global-index table is used.
  // PQ inputs reference outputs directly by (prevTxid, prevOutIndex), not by
  // amount + global index.
  auto& gidx = block.transactions[transactionIndex.transaction].m_global_output_indexes;
  gidx.resize(tx.outputs.size(), 0);

  // Record tx index
  m_db.putTxIndex(transactionHash, block.height, transactionIndex.transaction);

  // Record payment ID
  {
    Crypto::Hash paymentId;
    if (getPaymentIdFromTxExtra(tx.extra, paymentId)) {
      m_db.putPaymentId(paymentId, transactionHash);
    }
  }

  // ECC account registration (tag 0x04) is not used in Discrete; skip.

  // PQ account registration (tag 0x05) — FIRST-REGISTRATION-WINS. A registration
  // for an already-registered viewPub invalidates the tx (and the block). On a
  // failure return the whole block write txn is aborted by the caller, so no
  // manual rollback is needed here. (Non-coinbase only.)
  if (transactionIndex.transaction != 0) {
    TransactionExtraPqAccountRegistration pqReg;
    if (getPqAccountRegistrationFromExtra(tx.extra, pqReg)) {
      const Crypto::Hash accountId = getPqAccountIdentityHash(pqReg);
      if (m_db.hasPqAcctReg(accountId)) {
        logger(INFO, BRIGHT_WHITE) << "PQ account already registered, rejecting tx "
                                   << transactionHash;
        return false;
      }
      m_db.putPqAcctReg(accountId, block.height, transactionIndex.transaction);
    }
  }

  // Serialize and store tx entry: [u32 tx_size][tx_blob][u32 num_gidx][u32 gidx...]
  BinaryArray txBlob = toBinaryArray(tx);
  uint32_t txSize  = static_cast<uint32_t>(txBlob.size());
  uint32_t numGidx = static_cast<uint32_t>(gidx.size());

  std::vector<uint8_t> entry;
  entry.resize(sizeof(uint32_t) + txSize + sizeof(uint32_t) + numGidx * sizeof(uint32_t));
  uint8_t* p = entry.data();
  memcpy(p, &txSize, sizeof(uint32_t));   p += sizeof(uint32_t);
  memcpy(p, txBlob.data(), txSize);       p += txSize;
  memcpy(p, &numGidx, sizeof(uint32_t));  p += sizeof(uint32_t);
  for (uint32_t gi : gidx) {
    memcpy(p, &gi, sizeof(uint32_t));
    p += sizeof(uint32_t);
  }
  m_db.putTxEntry(block.height, transactionIndex.transaction, entry.data(), entry.size());

  return true;
}

void Blockchain::popTransaction(const Transaction& transaction,
                                 const Crypto::Hash& transactionHash,
                                 uint32_t blockHeight) {
  // Discrete: no KeyOutput global index to roll back — all outputs are PqOutput.
  // Remove spent tags (PQ nullifiers) from the single
  // spent-key set. After this a rolled-back KeyInput's key image or a PqInput's
  // (auth_pub, rho_reveal) pair may re-enter on the competing chain.
  for (const auto& input : transaction.inputs) {
    Crypto::KeyImage img;
    if (spendImageForInput(input, img)) {
      if (!m_db.removeSpentKey(img)) {
        logger(ERROR, BRIGHT_RED) << "Blockchain consistency broken - removeSpentKey failed";
      }
    }
  }

  // Remove payment ID
  {
    Crypto::Hash paymentId;
    if (getPaymentIdFromTxExtra(transaction.extra, paymentId)) {
      m_db.removePaymentId(paymentId, transactionHash);
    }
  }

  // Remove PQ account registration — mirrors first-reg-wins rollback: after the
  // orphaned block is popped, the same viewPub may re-register on the competing
  // chain.
  {
    TransactionExtraPqAccountRegistration pqReg;
    if (getPqAccountRegistrationFromExtra(transaction.extra, pqReg)) {
      m_db.removePqAcctReg(getPqAccountIdentityHash(pqReg));
    }
  }

  // Remove tx index
  if (!m_db.removeTxIndex(transactionHash)) {
    logger(ERROR, BRIGHT_RED) << "Blockchain consistency broken - removeTxIndex failed";
  }
}

void Blockchain::popTransactions(const BlockEntry& block, const Crypto::Hash& minerTransactionHash,
                                  uint32_t blockHeight) {
  for (size_t i = 0; i < block.transactions.size() - 1; ++i) {
    size_t ri = block.transactions.size() - 1 - i;
    popTransaction(block.transactions[ri].tx,
                   block.bl.transactionHashes[ri - 1],
                   blockHeight);
  }
  popTransaction(block.bl.baseTransaction, minerTransactionHash, blockHeight);
}

void Blockchain::removeLastBlock() {
  uint32_t chainHeight = m_db.getChainHeight();
  if (chainHeight == 0) {
    logger(ERROR, BRIGHT_RED) << "Attempt to pop block from empty blockchain.";
    return;
  }
  uint32_t height = chainHeight - 1;

  DbBlockMeta meta{};
  if (!m_db.getBlockMeta(height, meta)) {
    logger(ERROR, BRIGHT_RED) << "removeLastBlock: cannot read block meta at height " << height;
    return;
  }

  logger(DEBUGGING) << "Removing last block with height " << height;

  // Phase 1: Read all tx data (reads work through the active write txn if present)
  std::vector<uint8_t> bdata;
  if (!m_db.getBlockData(height, bdata)) {
    logger(ERROR, BRIGHT_RED) << "removeLastBlock: cannot read block data";
    return;
  }
  Block blk;
  if (!fromBinaryArray(blk, bdata)) {
    logger(ERROR, BRIGHT_RED) << "removeLastBlock: cannot deserialize block";
    return;
  }

  uint16_t txCount = meta.txCount;
  std::vector<std::pair<Crypto::Hash, Transaction>> txToRemove;
  txToRemove.reserve(txCount);

  for (uint16_t t = 0; t < txCount; ++t) {
    TransactionEntry te = transactionByIndex({height, t});
    Crypto::Hash txHash;
    if (t == 0) {
      txHash = getObjectHash(blk.baseTransaction);
    } else {
      txHash = blk.transactionHashes[t - 1];
    }
    txToRemove.push_back({txHash, te.tx});
  }

  Crypto::Hash blockHash;
  memcpy(blockHash.data, meta.hash, 32);

  // Phase 2: Atomic removal.
  // If a write txn is already active (caller manages it), reuse it;
  // otherwise open and commit our own.
  const bool ownTxn = !m_db.hasActiveTxn();
  if (ownTxn) {
    m_db.beginWriteTxn();
  }

  // Pop transactions in reverse (last non-coinbase first, coinbase last)
  for (int i = static_cast<int>(txToRemove.size()) - 1; i >= 0; --i) {
    popTransaction(txToRemove[i].second, txToRemove[i].first, height);
  }

  m_db.removeTxEntriesForBlock(height, txCount);
  m_db.removeBlockData(height);
  m_db.removeHashHeight(blockHash);
  m_db.removeGeneratedTxCount(height);

  m_db.removeTimestamp(meta.timestamp, blockHash);

  m_db.removeLastBlockMeta();

  if (ownTxn) {
    m_db.commitTxn();
  }
}

bool Blockchain::checkCheckpoints(uint32_t& lastValidCheckpointHeight) {
  std::vector<uint32_t> checkpointHeights = m_checkpoints.getCheckpointHeights();
  for (const auto& checkpointHeight : checkpointHeights) {
    if (m_db.getChainHeight() <= checkpointHeight) {
      return true;
    }
    if (m_checkpoints.check_block(checkpointHeight, getBlockIdByHeight(checkpointHeight))) {
      lastValidCheckpointHeight = checkpointHeight;
    } else {
      return false;
    }
  }
  return true;
}

void Blockchain::rollbackBlockchainTo(uint32_t height) {
  flushBatch();  // ensure no pending batch before removing blocks
  while (height + 1 < m_db.getChainHeight()) {
    try {
      removeLastBlock();
    } catch (const LMDBMapFullException&) {
      // Each removeLastBlock opens its own write txn; LMDB's copy-on-write
      // accumulates free pages inside the txn that aren't reclaimable until
      // commit, so deep rewinds can spill the map. Abort the partial txn,
      // double the map, and retry the same block — the push path uses the
      // same dance for IBD map-full.
      m_db.abortTxn();
      logger(WARNING, BRIGHT_YELLOW) << "LMDB map full during rollback at height "
                                     << (m_db.getChainHeight() - 1)
                                     << "; doubling map and retrying.";
      m_db.resizeMap();
      removeLastBlock();
    }
  }
}

// ─── first-seen finality: fork detection state + operator recovery ───────────

void Blockchain::recordFinalityFork(uint32_t chainLen, uint32_t altBlockHeight,
                                    const Crypto::Hash& altBlockId) {
  // Caller holds m_blockchain_lock and has established altBlockHeight >= 1.
  const uint32_t localTipHeight = chainLen - 1;
  const uint32_t divergence = altBlockHeight - 1; // last common ancestor
  if (m_finalityForkState.active) {
    // Keep the deepest divergence and the highest competing block seen while
    // the wedge persists (alt blocks arrive one at a time).
    m_finalityForkState.divergenceHeight = std::min(m_finalityForkState.divergenceHeight, divergence);
    if (altBlockHeight >= m_finalityForkState.competingTipHeight) {
      m_finalityForkState.competingTipHeight = altBlockHeight;
      m_finalityForkState.competingTipHash = altBlockId;
    }
  } else {
    m_finalityForkState.active = true;
    m_finalityForkState.divergenceHeight = divergence;
    m_finalityForkState.competingTipHeight = altBlockHeight;
    m_finalityForkState.competingTipHash = altBlockId;
  }
  m_finalityForkState.localTipHeight = localTipHeight;
  m_finalityForkState.localTipHash = getTailId();
  m_finalityForkState.refusedDepth = localTipHeight - m_finalityForkState.divergenceHeight;
}

FinalityForkState Blockchain::getFinalityForkState() {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  return m_finalityForkState;
}

bool Blockchain::resyncToMajority(std::string& message) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);

  // Refuse unless a finality fork is currently flagged. This is the safety rule
  // that keeps recovery from being repurposed to force an ordinary deep reorg by
  // hand — the very hole first-seen finality closes.
  if (!m_finalityForkState.active) {
    message = "no finality fork is currently flagged; refusing to roll back";
    return false;
  }

  const uint32_t target = m_finalityForkState.divergenceHeight; // last common ancestor
  const uint32_t tipBefore = m_db.getChainHeight() - 1;
  if (!(target < tipBefore)) {
    message = "divergence height is not below the current tip; nothing to roll back";
    return false;
  }

  logger(WARNING, BRIGHT_YELLOW)
    << "FINALITY RECOVERY: operator-confirmed resync_to_majority. Rolling back from tip "
    << tipBefore << ":" << getTailId() << " to divergence height " << target
    << " (" << (tipBefore - target) << " blocks popped), then resuming sync.";

  rollbackBlockchainTo(target);

  const uint32_t tipAfter = m_db.getChainHeight() - 1;
  logger(WARNING, BRIGHT_YELLOW)
    << "FINALITY RECOVERY: new tip " << tipAfter << ":" << getTailId()
    << ". Node will now sync the majority chain from its peers.";

  // Clear the warning; if we are still on a minority fork the next refused reorg
  // re-arms it, but after this rollback the majority chain no longer forks below
  // the finality depth so normal sync adopts it.
  m_finalityForkState = FinalityForkState{};

  message = "rolled back to height " + std::to_string(target)
    + "; resyncing to majority";
  return true;
}

bool Blockchain::checkUpgradeHeight(const UpgradeDetector& upgradeDetector) {
  uint32_t upgradeHeight = upgradeDetector.upgradeHeight();
  if (upgradeHeight != UpgradeDetectorBase::UNDEF_HEIGHT &&
      upgradeHeight + 1 < m_db.getChainHeight()) {
    DbBlockMeta meta{};
    if (!m_db.getBlockMeta(upgradeHeight + 1, meta)) return false;
    if (meta.majorVersion != upgradeDetector.targetVersion()) {
      return false;
    }
  }
  return true;
}

bool Blockchain::getLowerBound(uint64_t timestamp, uint64_t startOffset, uint32_t& height) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t chainHeight = m_db.getChainHeight();
  assert(startOffset < chainHeight);

  uint64_t threshold = timestamp > m_currency.blockFutureTimeLimit()
                         ? timestamp - m_currency.blockFutureTimeLimit()
                         : 0;
  DbBlockMeta meta{};
  for (uint32_t h = static_cast<uint32_t>(startOffset); h < chainHeight; ++h) {
    m_db.getBlockMeta(h, meta);
    if (meta.timestamp >= threshold) {
      height = h;
      return true;
    }
  }
  return false;
}

bool Blockchain::getBlockContainingTransaction(const Crypto::Hash& txId, Crypto::Hash& blockId,
                                                uint32_t& blockHeight) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t block; uint16_t txSlot;
  if (!m_db.getTxIndex(txId, block, txSlot)) return false;
  blockHeight = block;
  DbBlockMeta meta{};
  m_db.getBlockMeta(block, meta);
  memcpy(blockId.data, meta.hash, 32);
  return true;
}

bool Blockchain::getAlreadyGeneratedCoins(const Crypto::Hash& hash, uint64_t& generatedCoins) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t height = 0;
  if (m_db.getHashHeight(hash, height)) {
    DbBlockMeta meta{};
    m_db.getBlockMeta(height, meta);
    generatedCoins = meta.alreadyGeneratedCoins;
    return true;
  }
  auto it = m_alternative_chains.find(hash);
  if (it != m_alternative_chains.end()) {
    generatedCoins = it->second.already_generated_coins;
    return true;
  }
  logger(DEBUGGING) << "Can't find block with hash " << hash
    << " to get already generated coins.";
  return false;
}

bool Blockchain::getBlockSize(const Crypto::Hash& hash, size_t& size) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t height = 0;
  if (m_db.getHashHeight(hash, height)) {
    DbBlockMeta meta{};
    m_db.getBlockMeta(height, meta);
    size = meta.blockCumulativeSize;
    return true;
  }
  auto it = m_alternative_chains.find(hash);
  if (it != m_alternative_chains.end()) {
    size = it->second.block_cumulative_size;
    return true;
  }
  logger(DEBUGGING) << "Can't find block with hash " << hash << " to get block size.";
  return false;
}

bool Blockchain::getGeneratedTransactionsNumber(uint32_t height, uint64_t& generatedTransactions) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  return m_db.getGeneratedTxCount(height, generatedTransactions);
}

bool Blockchain::getOrphanBlockIdsByHeight(uint32_t height, std::vector<Crypto::Hash>& blockHashes) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  auto range = m_orphanBlocksIndex.equal_range(height);
  for (auto it = range.first; it != range.second; ++it) {
    blockHashes.push_back(it->second);
  }
  return true;
}

bool Blockchain::getBlockIdsByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd,
                                         uint32_t blocksNumberLimit,
                                         std::vector<Crypto::Hash>& hashes,
                                         uint32_t& blocksNumberWithinTimestamps) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  return m_db.getBlockHashesByTimestampRange(timestampBegin, timestampEnd,
                                              blocksNumberLimit, hashes, blocksNumberWithinTimestamps);
}

bool Blockchain::getTransactionIdsByPaymentId(const Crypto::Hash& paymentId,
                                               std::vector<Crypto::Hash>& transactionHashes) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  return m_db.getPaymentIdTxHashes(paymentId, transactionHashes);
}

bool Blockchain::isBlockInMainChain(const Crypto::Hash& blockId) {
  uint32_t h = 0;
  return m_db.getHashHeight(blockId, h);
}

bool Blockchain::isInCheckpointZone(const uint32_t height) {
  return m_checkpoints.is_in_checkpoint_zone(height);
}

// ─── Account number lookups ──────────────────────────────────────────────────

bool Blockchain::resolvePqAccountNumber(uint32_t blockHeight, uint32_t txIndex,
                                        std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE>& viewPub,
                                        std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE>& spendPub) {
  std::lock_guard<std::recursive_mutex> lk(m_blockchain_lock);
  const uint32_t chainHeight = m_db.getChainHeight();
  if (blockHeight >= chainHeight || txIndex > std::numeric_limits<uint16_t>::max()) {
    return false;
  }
  // Finality gate: an account number is only resolvable (payable) once its
  // registration is buried past first-seen finality (CRYPTONOTE_FINALITY_DEPTH).
  // Below that horizon a reorg could still repoint (blockHeight, txIndex) to a
  // different registration, so we refuse to hand out keys — the payer's wallet
  // treats it as "not yet resolvable". The owner can still display their own
  // number immediately (that path renders from the owner's keys, not this lookup).
  if (static_cast<uint64_t>(blockHeight) + parameters::CRYPTONOTE_FINALITY_DEPTH >= chainHeight) {
    return false;
  }
  try {
    TransactionEntry te = transactionByIndex({ blockHeight, static_cast<uint16_t>(txIndex) });
    TransactionExtraPqAccountRegistration reg;
    if (getPqAccountRegistrationFromExtra(te.tx.extra, reg)) {
      viewPub = reg.viewPub;
      spendPub = reg.spendPub;
      return true;
    }
  } catch (...) {
  }
  return false;
}

bool Blockchain::getPqAccountNumber(const Crypto::Hash& accountId,
                                    uint32_t& blockHeight, uint32_t& txIndex) {
  std::lock_guard<std::recursive_mutex> lk(m_blockchain_lock);
  return m_db.getPqAcctReg(accountId, blockHeight, txIndex);
}

bool Blockchain::getCanonicalAccountRegistrationsCount(uint64_t& count) {
  std::lock_guard<std::recursive_mutex> lk(m_blockchain_lock);
  return m_db.getPqAccountRegistrationsCount(count);
}

// ─── blockDifficulty / blockCumulativeDifficulty / getblockEntry ─────────────

uint64_t Blockchain::blockDifficulty(size_t i) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t chainHeight = m_db.getChainHeight();
  if (!(i < chainHeight)) {
    logger(ERROR, BRIGHT_RED) << "wrong block index i = " << i
      << " at Blockchain::block_difficulty()";
    return 0;
  }
  DbBlockMeta meta{};
  m_db.getBlockMeta(static_cast<uint32_t>(i), meta);
  if (i == 0) return meta.cumulativeDifficulty;
  DbBlockMeta prevMeta{};
  m_db.getBlockMeta(static_cast<uint32_t>(i) - 1, prevMeta);
  return meta.cumulativeDifficulty - prevMeta.cumulativeDifficulty;
}

uint64_t Blockchain::blockCumulativeDifficulty(size_t i) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  if (!(i < m_db.getChainHeight())) {
    logger(ERROR, BRIGHT_RED) << "wrong block index i = " << i
      << " at Blockchain::blockCumulativeDifficulty()";
    return 0;
  }
  DbBlockMeta meta{};
  m_db.getBlockMeta(static_cast<uint32_t>(i), meta);
  return meta.cumulativeDifficulty;
}

bool Blockchain::getblockEntry(size_t i, uint64_t& block_cumulative_size,
                                Difficulty& difficulty, uint64_t& already_generated_coins,
                                uint64_t& reward, uint64_t& transactions_count,
                                uint64_t& timestamp) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  if (!(i < m_db.getChainHeight())) {
    logger(ERROR, BRIGHT_RED) << "wrong block index i = " << i
      << " at Blockchain::get_block_entry()";
    return false;
  }
  DbBlockMeta meta{};
  m_db.getBlockMeta(static_cast<uint32_t>(i), meta);

  block_cumulative_size  = meta.blockCumulativeSize;
  already_generated_coins = meta.alreadyGeneratedCoins;
  timestamp              = meta.timestamp;
  transactions_count     = meta.txCount > 0 ? meta.txCount - 1 : 0; // exclude coinbase

  if (i == 0) {
    difficulty = meta.cumulativeDifficulty;
    reward     = meta.alreadyGeneratedCoins;
  } else {
    DbBlockMeta prevMeta{};
    m_db.getBlockMeta(static_cast<uint32_t>(i) - 1, prevMeta);
    difficulty = meta.cumulativeDifficulty - prevMeta.cumulativeDifficulty;
    reward     = meta.alreadyGeneratedCoins - prevMeta.alreadyGeneratedCoins;
  }
  return true;
}

bool Blockchain::getBlockStats(uint32_t startHeight, uint32_t endHeight, std::vector<BlockStatsEntry>& stats) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);

  const uint32_t chainHeight = m_db.getChainHeight();
  if (startHeight > endHeight || endHeight >= chainHeight) {
    logger(ERROR, BRIGHT_RED) << "wrong block range [" << startHeight << ", " << endHeight
      << "] at Blockchain::getBlockStats(), blockchain height = " << chainHeight;
    return false;
  }

  const uint32_t fromHeight = startHeight == 0 ? 0 : startHeight - 1;
  std::vector<DbBlockMeta> metas;
  if (!m_db.getBlockMetaRange(fromHeight, endHeight, metas)) {
    logger(ERROR, BRIGHT_RED) << "failed to read block meta range [" << fromHeight << ", " << endHeight
      << "] at Blockchain::getBlockStats()";
    return false;
  }

  const size_t expectedMetas = static_cast<size_t>(endHeight) - fromHeight + 1;
  if (metas.size() != expectedMetas) {
    logger(ERROR, BRIGHT_RED) << "incomplete block meta range [" << fromHeight << ", " << endHeight
      << "] at Blockchain::getBlockStats(): expected " << expectedMetas << ", got " << metas.size();
    return false;
  }

  stats.clear();
  stats.reserve(static_cast<size_t>(endHeight) - startHeight + 1);

  for (uint32_t height = startHeight; height <= endHeight; ++height) {
    const size_t metaIndex = static_cast<size_t>(height) - fromHeight;
    const DbBlockMeta& meta = metas[metaIndex];
    const DbBlockMeta* prevMeta = height == 0 ? nullptr : &metas[metaIndex - 1];
    stats.push_back(makeBlockStatsEntry(height, meta, prevMeta));
  }

  return true;
}

bool Blockchain::getBlockStats(const std::vector<uint32_t>& heights, std::vector<BlockStatsEntry>& stats) {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);

  stats.clear();
  if (heights.empty()) {
    return true;
  }

  const uint32_t chainHeight = m_db.getChainHeight();
  std::vector<uint32_t> metaHeights;
  metaHeights.reserve(heights.size() * 2);

  for (const uint32_t height : heights) {
    if (height >= chainHeight) {
      logger(ERROR, BRIGHT_RED) << "wrong block height " << height
        << " at Blockchain::getBlockStats(), blockchain height = " << chainHeight;
      return false;
    }

    if (height > 0) {
      metaHeights.push_back(height - 1);
    }
    metaHeights.push_back(height);
  }

  std::sort(metaHeights.begin(), metaHeights.end());
  metaHeights.erase(std::unique(metaHeights.begin(), metaHeights.end()), metaHeights.end());

  std::vector<DbBlockMeta> metas;
  if (!m_db.getBlockMetaForHeights(metaHeights, metas) || metas.size() != metaHeights.size()) {
    logger(ERROR, BRIGHT_RED) << "failed to read sparse block meta set at Blockchain::getBlockStats()";
    return false;
  }

  stats.reserve(heights.size());
  for (const uint32_t height : heights) {
    auto metaIt = std::lower_bound(metaHeights.begin(), metaHeights.end(), height);
    const size_t metaIndex = static_cast<size_t>(std::distance(metaHeights.begin(), metaIt));
    const DbBlockMeta& meta = metas[metaIndex];

    const DbBlockMeta* prevMeta = nullptr;
    if (height > 0) {
      auto prevMetaIt = std::lower_bound(metaHeights.begin(), metaHeights.end(), height - 1);
      const size_t prevMetaIndex = static_cast<size_t>(std::distance(metaHeights.begin(), prevMetaIt));
      prevMeta = &metas[prevMetaIndex];
    }

    stats.push_back(makeBlockStatsEntry(height, meta, prevMeta));
  }

  return true;
}

// ─── Transaction pool integration ────────────────────────────────────────────

bool Blockchain::loadTransactions(const Block& block, std::vector<Transaction>& transactions) {
  transactions.resize(block.transactionHashes.size());
  size_t transactionSize;
  uint64_t fee;
  for (size_t i = 0; i < block.transactionHashes.size(); ++i) {
    if (!m_tx_pool.take_tx(block.transactionHashes[i], transactions[i], transactionSize, fee)) {
      tx_verification_context context;
      for (size_t j = 0; j < i; ++j) {
        if (!m_tx_pool.add_tx(transactions[i - 1 - j], context, true)) {
          throw std::runtime_error("Blockchain::loadTransactions, failed to add transaction to pool");
        }
      }
      return false;
    }
  }
  return true;
}

void Blockchain::saveTransactions(const std::vector<Transaction>& transactions) {
  tx_verification_context context;
  for (size_t i = 0; i < transactions.size(); ++i) {
    if (!m_tx_pool.add_tx(transactions[transactions.size() - 1 - i], context, true)) {
      logger(WARNING, BRIGHT_YELLOW) << "Blockchain::saveTransactions, failed to add transaction to pool";
    }
  }
}

// ─── Message queue ───────────────────────────────────────────────────────────

bool Blockchain::addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) {
  return m_messageQueueList.insert(messageQueue);
}

bool Blockchain::removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) {
  return m_messageQueueList.remove(messageQueue);
}

void Blockchain::sendMessage(const BlockchainMessage& message) {
  for (auto iter = m_messageQueueList.begin(); iter != m_messageQueueList.end(); ++iter) {
    iter->push(message);
  }
}

// ─── Debug output ────────────────────────────────────────────────────────────

void Blockchain::print_blockchain(uint64_t start_index, uint64_t end_index) {
  std::stringstream ss;
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t chainHeight = m_db.getChainHeight();
  if (start_index >= chainHeight) {
    logger(INFO, BRIGHT_WHITE) << "Wrong starter index set: " << start_index
      << ", expected max index " << chainHeight - 1;
    return;
  }
  DbBlockMeta meta{}, prevMeta{};
  for (size_t i = start_index; i != chainHeight && i != end_index; i++) {
    m_db.getBlockMeta(static_cast<uint32_t>(i), meta);
    Crypto::Hash h;
    memcpy(h.data, meta.hash, 32);
    uint64_t diff = (i == 0) ? meta.cumulativeDifficulty
                              : (m_db.getBlockMeta(static_cast<uint32_t>(i) - 1, prevMeta),
                                 meta.cumulativeDifficulty - prevMeta.cumulativeDifficulty);
    ss << "height " << i
       << ", timestamp " << meta.timestamp
       << ", cumul_dif " << meta.cumulativeDifficulty
       << ", cumul_size " << meta.blockCumulativeSize
       << "\nid\t\t" << h
       << "\ndifficulty\t\t" << diff
       << ", tx_count " << meta.txCount << "\n";
  }
  logger(INFO, BRIGHT_WHITE) << "Current blockchain:\n" << ss.str();
  logger(INFO, BRIGHT_WHITE) << "Blockchain printed";
}

void Blockchain::print_blockchain_index() {
  std::lock_guard<decltype(m_blockchain_lock)> lk(m_blockchain_lock);
  uint32_t chainHeight = m_db.getChainHeight();
  logger(INFO, BRIGHT_WHITE) << "Current blockchain index:";
  DbBlockMeta meta{};
  for (uint32_t h = 0; h < chainHeight; ++h) {
    m_db.getBlockMeta(h, meta);
    Crypto::Hash hash;
    memcpy(hash.data, meta.hash, 32);
    logger(INFO, BRIGHT_WHITE) << "id\t\t" << hash << " height " << h;
  }
}

void Blockchain::print_blockchain_outs(const std::string& file) {
  // In LMDB mode, enumerating all outputs by amount is not straightforward.
  // Write a placeholder message.
  logger(INFO, BRIGHT_WHITE) << "print_blockchain_outs: not implemented for LMDB backend; "
    << "output file: " << file;
}

// ─── Migration from legacy SwappedVector ─────────────────────────────────────

bool Blockchain::migrateFromSwappedVector(const std::string& config_folder) {
  std::string blocksFile  = appendPath(config_folder, m_currency.blocksFileName());
  std::string indexFile   = appendPath(config_folder, m_currency.blockIndexesFileName());

  uint32_t totalBlocks = 0;
  uint32_t startBlock = 0;

  {
    SwappedVector<BlockEntry> oldBlocks;

    if (!oldBlocks.open(blocksFile, indexFile, 1024)) {
      logger(WARNING, BRIGHT_YELLOW) << "Migration: failed to open old block files";
      return false;
    }

    if (oldBlocks.empty()) {
      logger(INFO) << "Migration: old block files are empty, nothing to migrate";
      return true;
    }

    totalBlocks = static_cast<uint32_t>(oldBlocks.size());
    // Resume support: skip blocks already committed to LMDB.
    startBlock = m_db.getChainHeight();

    if (startBlock < totalBlocks) {
      if (startBlock > 0) {
        logger(INFO, BRIGHT_WHITE) << "Resuming migration from block " << startBlock
          << " of " << totalBlocks << " (" << (totalBlocks - startBlock) << " remaining).";
      }
      else {
        logger(INFO, BRIGHT_WHITE) << "Migrating " << totalBlocks << " blocks from legacy storage to LMDB...";
      }

      // Write BATCH_SIZE blocks per LMDB transaction.
      // Batching reduces commit overhead from O(totalBlocks) to O(totalBlocks/BATCH_SIZE)
      // and keeps B-tree pages hot in the mmap across multiple block writes within a batch,
      // which dramatically reduces B-tree fragmentation and page-split overhead.
      // On MDB_MAP_FULL the current batch is aborted, the map is doubled, and the same
      // batch is retried from its starting block (which is re-read from SwappedVector).
      static const uint32_t BATCH_SIZE = 1000;

      for (uint32_t batchStart = startBlock; batchStart < totalBlocks; ) {
        uint32_t batchEnd = std::min(batchStart + BATCH_SIZE, totalBlocks);

        for (;;) {  // map-full retry loop for this batch
          m_db.beginWriteTxn();
          bool ok = true;
          try {
            for (uint32_t b = batchStart; b < batchEnd && ok; ++b) {
              if (b % 10000 == 0) {
                logger(INFO, BRIGHT_WHITE) << "Migration: height " << b << " of " << totalBlocks;
              }

              // Fresh read from SwappedVector gives empty m_global_output_indexes,
              // which pushTransaction will fill in correctly.
              BlockEntry block = oldBlocks[b];
              Crypto::Hash blockHash = get_block_hash(block.bl);

              for (uint16_t t = 0; t < static_cast<uint16_t>(block.transactions.size()); ++t) {
                Crypto::Hash txHash = (t == 0)
                  ? getObjectHash(block.bl.baseTransaction)
                  : block.bl.transactionHashes[t - 1];
                if (!pushTransaction(block, txHash, { b, t })) {
                  logger(ERROR, BRIGHT_RED) << "Migration: pushTransaction failed at block " << b
                    << " tx " << t;
                  ok = false;
                  break;
                }
              }
              if (ok) pushBlock(block, blockHash);
            }

            if (ok) {
              m_db.commitTxn();
              batchStart = batchEnd;  // advance to next batch
              break;
            }
            else {
              m_db.abortTxn();
              return false;
            }

          }
          catch (const LMDBMapFullException&) {
            m_db.abortTxn();
            logger(DEBUGGING, BRIGHT_YELLOW) << "Migration: LMDB map full at block " << batchStart
              << ", resizing map and retrying batch...";
            m_db.resizeMap();
            // batchStart unchanged - retry same batch from the beginning
          }
          catch (const std::exception& e) {
            // Any non-map-full LMDB/storage error (e.g. EIO during commit):
            // abort the batch transaction and return a recoverable migration
            // failure instead of crashing daemon startup.
            m_db.abortTxn();
            logger(ERROR, BRIGHT_RED)
              << "Migration: batch [" << batchStart << ", " << (batchEnd - 1)
              << "] failed: " << e.what();
            return false;
          }
        }
      }

      logger(INFO, BRIGHT_WHITE) << "Migration complete! " << totalBlocks << " blocks migrated to LMDB.";
    } else {
      logger(INFO, BRIGHT_WHITE) << "Migration already complete (" << totalBlocks << " blocks in LMDB).";
    }
  } // oldBlocks goes out of scope and is closed here

  // Remove old SwappedVector files now that they are closed and no longer needed.
  try {
    if (std::filesystem::exists(blocksFile)) {
      std::filesystem::remove(blocksFile);
      logger(INFO) << "Migration: removed old blocks file: " << blocksFile;
    }

    if (std::filesystem::exists(indexFile)) {
      std::filesystem::remove(indexFile);
      logger(INFO) << "Migration: removed old index file: " << indexFile;
    }

    std::string cacheFile = appendPath(config_folder, m_currency.blocksCacheFileName());
    if (std::filesystem::exists(cacheFile)) {
      std::filesystem::remove(cacheFile);
      logger(INFO) << "Migration: removed old cache file: " << cacheFile;
    }

    std::string indicesFileName = appendPath(config_folder, m_currency.blockchainIndicesFileName());
    if (std::filesystem::exists(indicesFileName)) {
      std::filesystem::remove(indicesFileName);
      logger(INFO) << "Migration: removed old indices file: " << indicesFileName;
    }
  }
  catch (const std::exception& e) {
    logger(WARNING, BRIGHT_YELLOW) << "Migration: failed to remove old files: " << e.what();
  }

  return true;
}

} // namespace CryptoNote
