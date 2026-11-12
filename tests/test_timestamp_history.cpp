// Copyright (c) 2026, The Discrete developers
// Offline replay from an immutable, consistently copied mainnet LMDB snapshot.
// Never point this executable at a live database. No P2P endpoint is created.

#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/LMDBBlockchainDB.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"
#include "liblmdb/lmdb.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>

namespace {
using namespace CryptoNote;
namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}
void checked(int result, const char* operation) {
  if (result) throw std::runtime_error(std::string(operation) + ": " + mdb_strerror(result));
}

struct Snapshot {
  MDB_env* environment = nullptr;
  MDB_txn* transaction = nullptr;
  MDB_dbi metadata{}, blocks{}, transactions{};
  uint32_t height = 0;
  size_t transactionCount = 0;

  explicit Snapshot(const fs::path& path) {
    checked(mdb_env_create(&environment), "create snapshot environment");
    checked(mdb_env_set_maxdbs(environment, 20), "snapshot table limit");
    // NOLOCK is safe only because this is an immutable, detached copy.
    checked(mdb_env_open(environment, path.string().c_str(), MDB_RDONLY | MDB_NOLOCK, 0), "open immutable snapshot");
    checked(mdb_txn_begin(environment, nullptr, MDB_RDONLY, &transaction), "begin snapshot read");
    checked(mdb_dbi_open(transaction, "block_meta", 0, &metadata), "open metadata");
    checked(mdb_dbi_open(transaction, "block_data", 0, &blocks), "open blocks");
    checked(mdb_dbi_open(transaction, "tx_entries", 0, &transactions), "open transactions");
    MDB_stat statistics{};
    checked(mdb_stat(transaction, metadata, &statistics), "count snapshot blocks");
    require(statistics.ms_entries > 0 && statistics.ms_entries < UINT32_MAX, "bounded nonempty snapshot");
    height = static_cast<uint32_t>(statistics.ms_entries);
    checked(mdb_stat(transaction, transactions, &statistics), "count snapshot transactions");
    transactionCount = statistics.ms_entries;
  }
  ~Snapshot() {
    if (transaction) mdb_txn_abort(transaction);
    if (environment) mdb_env_close(environment);
  }
  MDB_val value(MDB_dbi table, uint32_t height, int index = -1) const {
    unsigned char keyBytes[6] = {
      static_cast<unsigned char>(height >> 24), static_cast<unsigned char>(height >> 16),
      static_cast<unsigned char>(height >> 8), static_cast<unsigned char>(height), 0, 0};
    if (index >= 0) {
      keyBytes[4] = static_cast<unsigned char>(index >> 8);
      keyBytes[5] = static_cast<unsigned char>(index);
    }
    MDB_val key{index < 0 ? size_t(4) : size_t(6), keyBytes}, result{};
    checked(mdb_get(transaction, table, &key, &result), "read snapshot record");
    return result;
  }
  DbBlockMeta meta(uint32_t height) const {
    const auto data = value(metadata, height);
    require(data.mv_size == sizeof(DbBlockMeta), "snapshot metadata schema");
    DbBlockMeta result{};
    std::memcpy(&result, data.mv_data, sizeof(result));
    require(result.height == height, "snapshot metadata height");
    return result;
  }
  BinaryArray block(uint32_t height) const {
    const auto data = value(blocks, height);
    const auto* bytes = static_cast<const uint8_t*>(data.mv_data);
    return BinaryArray(bytes, bytes + data.mv_size);
  }
  BinaryArray tx(uint32_t height, uint16_t index) const {
    const auto data = value(transactions, height, index);
    require(data.mv_size >= 8, "snapshot transaction entry bounds");
    uint32_t length = 0;
    std::memcpy(&length, data.mv_data, sizeof(length));
    require(length <= data.mv_size - 8, "snapshot transaction payload bounds");
    const auto* bytes = static_cast<const uint8_t*>(data.mv_data) + 4;
    return BinaryArray(bytes, bytes + length);
  }
};

void compareTip(Core& core, const Snapshot& source) {
  const uint32_t tip = core.getCurrentBlockchainHeight() - 1;
  const auto expected = source.meta(tip);
  const auto actual = core.get_tail_id();
  require(std::memcmp(actual.data, expected.hash, sizeof(expected.hash)) == 0, "exact replay tip hash");
  Difficulty work = 0;
  require(core.getBlockCumulativeDifficulty(tip, work) && work == expected.cumulativeDifficulty,
          "exact replay cumulative work");
  require(core.getTotalGeneratedAmount() == expected.alreadyGeneratedCoins, "exact replay emission");
}
} // namespace

int main(int argc, char** argv) {
  try {
    fs::path sourcePath, destination;
    bool resume = false;
    uint32_t stopAfter = UINT32_MAX;
    for (int i = 1; i < argc; ++i) {
      const std::string argument(argv[i]);
      if (argument == "--resume") resume = true;
      else if (argument == "--snapshot-dir" && i + 1 < argc) sourcePath = argv[++i];
      else if (argument == "--data-dir" && i + 1 < argc) destination = argv[++i];
      else if (argument == "--stop-after" && i + 1 < argc) {
        const auto count = std::stoull(argv[++i]);
        require(count > 0 && count < UINT32_MAX, "bounded replay stop height");
        stopAfter = static_cast<uint32_t>(count);
      } else throw std::runtime_error("Unknown or incomplete argument: " + argument);
    }
    require(sourcePath.is_absolute() && destination.is_absolute(), "absolute snapshot and data paths required");
    sourcePath = fs::weakly_canonical(sourcePath);
    destination = fs::weakly_canonical(destination);
    require(sourcePath != destination && sourcePath.parent_path() != destination,
            "snapshot and destination must be separate directories");
    require(fs::exists(sourcePath / "data.mdb"), "consistent immutable snapshot is required");
    require(resume ? fs::is_directory(destination) : !fs::exists(destination),
            "fresh destination required unless explicitly resuming");
    fs::create_directories(destination);
    Snapshot snapshot(sourcePath);
    Logging::ConsoleLogger logger(Logging::ERROR);
    // Mainnet history is replayed under unchanged rules; activation is disabled.
    const auto currency = CurrencyBuilder(logger).currency();
    System::Dispatcher dispatcher;
    CoreConfig configuration;
    configuration.configFolder = destination.string();
    auto core = std::make_unique<Core>(currency, nullptr, logger, dispatcher);
    require(core->init(configuration, MinerConfig{}, false), "initialize isolated replay Core");
    require(core->getCurrentBlockchainHeight() <= snapshot.height, "replay cannot exceed snapshot");
    const auto genesis = snapshot.meta(0);
    const auto expectedGenesis = currency.genesisBlockHash();
    require(std::memcmp(genesis.hash, expectedGenesis.data, sizeof(genesis.hash)) == 0,
            "snapshot matches mainnet genesis");
    compareTip(*core, snapshot);
    const uint32_t startHeight = core->getCurrentBlockchainHeight();
    const uint32_t endHeight = std::min(stopAfter, snapshot.height);
    require(startHeight <= endHeight, "resume point must not exceed selected stop height");
    uint64_t submittedTransactions = 0;
    const auto started = std::chrono::steady_clock::now();
    for (uint32_t height = startHeight; height < endHeight; ++height) {
      const auto metadata = snapshot.meta(height);
      const auto blob = snapshot.block(height);
      Block block;
      require(fromBinaryArray(block, blob), "deserialize historical block " + std::to_string(height));
      require(block.transactionHashes.size() + 1 == metadata.txCount, "historical transaction count");
      for (uint16_t index = 1; index < metadata.txCount; ++index) {
        const auto txBlob = snapshot.tx(height, index);
        Transaction transaction;
        require(fromBinaryArray(transaction, txBlob), "deserialize historical transaction");
        const auto id = getObjectHash(transaction);
        require(id == block.transactionHashes[index - 1], "historical transaction hash binding");
        tx_verification_context verification{};
        core->handleIncomingTransaction(transaction, id, txBlob.size(), verification, true, height);
        require(verification.m_added_to_pool && !verification.m_verification_failed,
                "historical transaction admission at " + std::to_string(height));
        ++submittedTransactions;
      }
      block_verification_context verification{};
      core->handle_incoming_block_blob(blob, verification, false, false);
      require(verification.m_added_to_main_chain && !verification.m_verification_failed,
              "historical block admission at " + std::to_string(height));
      require(core->getCurrentBlockchainHeight() == height + 1, "contiguous replay height");
      compareTip(*core, snapshot);
      if (height % 1000 == 0 || height + 1 == endHeight) {
        const auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        std::cout << "PROGRESS,height," << height << ",snapshot_blocks," << snapshot.height
                  << ",transactions_submitted," << submittedTransactions << ",elapsed_seconds," << seconds << std::endl;
      }
    }
    if (endHeight == snapshot.height) {
      require(core->getBlockchainTotalTransactions() == snapshot.transactionCount,
              "full replay transaction count equals snapshot");
    }
    require(core->deinit(), "clean replay shutdown");
    core.reset(new Core(currency, nullptr, logger, dispatcher));
    require(core->init(configuration, MinerConfig{}, false), "restart replay Core");
    require(core->getCurrentBlockchainHeight() == endHeight, "restart preserves replay height");
    compareTip(*core, snapshot);
    require(core->deinit(), "clean restarted replay shutdown");
    std::cout << "PASS,full_history," << (endHeight == snapshot.height)
              << ",snapshot_blocks," << snapshot.height << ",final_height," << endHeight - 1
              << ",start_height," << startHeight << ",restart_verified,1,activation_disabled,1\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "FAIL," << error.what() << '\n';
    return 1;
  }
}
