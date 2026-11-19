// Copyright (c) 2026, The Discrete developers
//
// Portable activation rehearsal through Core, LMDB and real DiscretePower.
// Uses historical synthetic timestamps and never changes the process/host clock.

#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/PqValidation.h"
#include "Checkpoints/Checkpoints.h"
#include "Common/StringTools.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"
#ifndef TIMESTAMP_LEGACY_BASELINE
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "InProcessNode/InProcessNode.h"
#include "System/Timer.h"
#include "Wallet/WalletGreen.h"
#include <future>
#endif
#include "TestGenerator/TestGenerator.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/WalletLedger.h"
#include "crypto_pq/PqOutputBuilder.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <list>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace CryptoNote;
namespace fs = std::filesystem;
constexpr uint64_t Fee = 50;
size_t assertions = 0, proofs = 0;
uint64_t proofAttempts = 0;

void require(bool condition, const std::string& message) {
  ++assertions;
  if (!condition) throw std::runtime_error(message);
}

uint64_t wallTime() { return static_cast<uint64_t>(std::time(nullptr)); }

Currency makeCurrency(Logging::ILogger& logger, uint32_t activation) {
  CurrencyBuilder builder(logger);
  builder.testnet(true);
#ifndef TIMESTAMP_LEGACY_BASELINE
  if (activation != UINT32_MAX) builder.monotonicTimestampHeight(activation);
#else
  require(activation == UINT32_MAX, "baseline executable supports disabled-policy replay only");
#endif
  return builder.currency();
}

struct Fixture {
  Logging::ConsoleLogger logger{Logging::ERROR};
  const Currency currency;
  System::Dispatcher dispatcher;
  std::unique_ptr<Core> core;
  test_generator generator;
  AccountBase miner, alternate;
  fs::path directory;
  std::vector<std::pair<uint32_t, Crypto::Hash>> checkpoints;
  bool initialized = false;

  Fixture(const fs::path& path, uint32_t activation = UINT32_MAX)
      : currency(makeCurrency(logger, activation)), generator(currency), directory(path) {
    require(!fs::exists(path) && fs::create_directories(path), "create fresh isolated Core directory");
    miner.generate(); alternate.generate(); open();
    std::vector<size_t> sizes;
    generator.addBlock(blockAt(0), 0, 0, sizes, 0);
  }
  ~Fixture() { if (initialized) core->deinit(); }

  void applyCheckpoints() {
    Checkpoints points(logger);
    for (const auto& item : checkpoints)
      require(points.add_checkpoint(item.first, Common::podToHex(item.second)), "add synthetic exact checkpoint");
    core->set_checkpoints(std::move(points));
  }
  void open() {
    core.reset(new Core(currency, nullptr, logger, dispatcher));
    CoreConfig config; config.configFolder = directory.string();
    require(core->init(config, MinerConfig{}, false), "initialize actual Core");
    initialized = true;
    generator.setBlockchain(&core->get_blockchain_storage());
    applyCheckpoints();
  }
  void checkpoint(uint32_t height, const Crypto::Hash& hash) {
    require(checkpoints.empty(), "checkpoint fixture installs one immutable checkpoint set");
    checkpoints.push_back({height, hash});
    applyCheckpoints();
  }
  void restart() {
    const auto tip = core->get_tail_id();
    const auto height = core->getCurrentBlockchainHeight();
    require(core->deinit(), "clean shutdown"); initialized = false;
    core.reset(); open();
    require(core->get_tail_id() == tip && core->getCurrentBlockchainHeight() == height,
            "restart preserves exact canonical tip and height");
  }
  Block blockAt(uint32_t height) {
    Block block;
    require(core->getBlockByHash(core->getBlockIdByHeight(height), block), "read canonical block");
    return block;
  }
  std::list<Transaction> transactions(const Block& block) {
    std::list<Transaction> result;
    std::list<Crypto::Hash> missing;
    core->getTransactions(block.transactionHashes, result, missing, false);
    require(missing.empty() && result.size() == block.transactionHashes.size(), "read exact canonical transactions");
    return result;
  }
  void prove(Block& block, const AccountBase& identity, Difficulty difficulty) {
    require(difficulty > 0 && difficulty <= 100000, "bounded actual branch difficulty");
    const auto start = std::chrono::steady_clock::now();
    for (uint32_t nonce = 0; nonce < 1000000; ++nonce) {
      if (nonce % 128 == 0)
        require(std::chrono::steady_clock::now() - start < std::chrono::seconds(120), "bounded real proof search");
      block.nonce = nonce;
      BinaryArray blob; Crypto::Hash hash;
      require(get_block_hashing_blob(block, blob) &&
              discrete_power_prove(blob, identity.pqSpendSk(), block.signature, hash), "compute real signed DiscretePower");
      ++proofAttempts;
      if (check_hash(hash, difficulty)) { ++proofs; return; }
    }
    throw std::runtime_error("real proof attempt bound exceeded");
  }
  void remember(const Block& block, const std::list<Transaction>& txs) {
    uint64_t generated = generator.getAlreadyGeneratedCoins(block.previousBlockHash);
    if (block.previousBlockHash == currency.genesisBlockHash())
      require(core->getAlreadyGeneratedCoins(block.previousBlockHash, generated), "read treasury genesis allocation");
    std::vector<size_t> sizes;
    generator.getLastNBlockSizes(sizes, block.previousBlockHash, currency.rewardBlocksWindow());
    size_t bytes = 0;
    for (const auto& tx : txs) bytes += getObjectBinarySize(tx);
    generator.addBlock(block, bytes, Fee * txs.size(), sizes, generated);
  }
  Block build(const Crypto::Hash& parent, uint32_t height, uint64_t timestamp,
              bool alternateMiner = false, const std::list<Transaction>& txs = {}, uint64_t timestampOffset = 0) {
    const auto& identity = alternateMiner ? alternate : miner;
    uint64_t generated = generator.getAlreadyGeneratedCoins(parent);
    if (parent == currency.genesisBlockHash())
      require(core->getAlreadyGeneratedCoins(parent, generated), "read actual genesis allocation");
    std::vector<size_t> sizes;
    generator.getLastNBlockSizes(sizes, parent, currency.rewardBlocksWindow());
    generator.defaultMajorVersion = core->getBlockMajorVersionForHeight(height);
    for (const auto& tx : txs) generator.setTxFee(getObjectHash(tx), Fee);
    Block block;
    require(generator.constructBlock(block, height, parent, identity, timestamp, generated, sizes, txs),
            "construct exact signed synthetic block");
#ifndef TIMESTAMP_LEGACY_BASELINE
    block.timestampOffset = timestampOffset;
#else
    require(timestampOffset == 0, "legacy test block has a single timestamp");
#endif
    prove(block, identity, core->get_blockchain_storage().getDifficultyForNextBlock(parent));
    remember(block, txs);
    return block;
  }
  Block buildNext(uint64_t timestamp, const std::list<Transaction>& txs = {}) {
    return build(core->get_tail_id(), core->getCurrentBlockchainHeight(), timestamp, false, txs);
  }
  block_verification_context submit(const Block& block, const std::list<Transaction>& txs = {}) {
    for (const auto& tx : txs) {
      const auto hash = getObjectHash(tx);
      if (!core->get_blockchain_storage().haveTransaction(hash)) {
        tx_verification_context result{};
        core->handleIncomingTransaction(tx, hash, toBinaryArray(tx).size(), result, false,
                                       core->getCurrentBlockchainHeight());
        require(!result.m_verification_failed, "submit exact transaction to ordinary pool validation");
      }
    }
    block_verification_context result{};
    core->handle_incoming_block(block, result, false, false);
    if (!result.m_verification_failed && !result.m_marked_as_orphaned && !result.m_already_exists)
      remember(block, txs);
    return result;
  }
  void accept(const Block& block, const std::list<Transaction>& txs = {}) {
    const auto result = submit(block, txs);
    require(result.m_added_to_main_chain && !result.m_verification_failed &&
            core->get_tail_id() == get_block_hash(block), "ordinary Core accepts exact canonical block");
  }
  Block append(uint64_t timestamp, const std::list<Transaction>& txs = {}) {
    const auto block = buildNext(timestamp, txs); accept(block, txs); return block;
  }
};

struct Snapshot {
  std::vector<Crypto::Hash> ids;
  std::vector<Difficulty> work;
  std::vector<BinaryArray> blocks;
  std::vector<std::vector<BinaryArray>> transactions;
  uint64_t emission, transactionCount;
  explicit Snapshot(Fixture& source)
      : emission(source.core->getTotalGeneratedAmount()),
        transactionCount(source.core->getBlockchainTotalTransactions()) {
    for (uint32_t h = 0; h < source.core->getCurrentBlockchainHeight(); ++h) {
      const auto block = source.blockAt(h);
      ids.push_back(get_block_hash(block)); blocks.push_back(toBinaryArray(block));
      Difficulty value;
      require(source.core->getBlockCumulativeDifficulty(h, value), "snapshot exact cumulative work");
      work.push_back(value);
      std::vector<BinaryArray> bytes;
      for (const auto& tx : source.transactions(block)) bytes.push_back(toBinaryArray(tx));
      transactions.push_back(bytes);
    }
  }
  void check(Fixture& target) const {
    require(target.core->getCurrentBlockchainHeight() == ids.size() &&
            target.core->getTotalGeneratedAmount() == emission &&
            target.core->getBlockchainTotalTransactions() == transactionCount,
            "exact height, emission and total transaction count match");
    for (uint32_t h = 0; h < ids.size(); ++h) {
      const auto block = target.blockAt(h);
      Difficulty value;
      require(get_block_hash(block) == ids[h] && toBinaryArray(block) == blocks[h] &&
              target.core->getBlockCumulativeDifficulty(h, value) && value == work[h],
              "every block ID, byte sequence and cumulative work value match");
      std::vector<BinaryArray> bytes;
      for (const auto& tx : target.transactions(block)) bytes.push_back(toBinaryArray(tx));
      require(bytes == transactions[h], "every canonical non-coinbase transaction byte sequence matches");
    }
  }
};

void replay(Fixture& source, Fixture& target) {
  require(source.core->getBlockIdByHeight(0) == target.core->getBlockIdByHeight(0), "exact genesis is shared");
  for (uint32_t h = 1; h < source.core->getCurrentBlockchainHeight(); ++h) {
    const auto block = source.blockAt(h);
    target.accept(block, source.transactions(block));
  }
}

void permanent(Fixture& fixture, const Block& block, const std::string& message) {
  const Snapshot before(fixture);
  const auto result = fixture.submit(block);
  require(result.m_verification_failed && !result.m_added_to_main_chain, message);
#ifndef TIMESTAMP_LEGACY_BASELINE
  require(!result.m_timestamp_too_far_in_future, "immutable timestamp rejection is not a future-time retry");
#endif
  before.check(fixture);
}

void lateUpgrade(const fs::path& root) {
  Fixture legacy(root / "late-upgrade");
  const uint64_t base = wallTime() - 1800;
  for (uint64_t delta : {60, 0, 59, 120, 120, 110, 180, 180}) legacy.append(base + delta);
  const Snapshot original(legacy);
  require(legacy.core->deinit(), "close legacy chain before changing policy");
  legacy.initialized = false;
  legacy.core.reset();

  const auto checkOpen = [&](uint32_t activation, bool expected, bool loadExisting) {
    const Currency currency = makeCurrency(legacy.logger, activation);
    Core reader(currency, nullptr, legacy.logger, legacy.dispatcher);
    CoreConfig config;
    config.configFolder = legacy.directory.string();
    const bool opened = reader.init(config, MinerConfig{}, loadExisting);
    require(opened == expected, "existing database under H=" + std::to_string(activation) +
                                (expected ? " must open" : " must refuse its incompatible stored suffix"));
    if (opened) {
      require(reader.get_tail_id() == original.ids.back(), "opening with a compatible rule preserves the tip");
      require(reader.deinit(), "close compatible reader");
    } else {
      // A refused startup must release the database while the failed Core object is still alive.
      legacy.open();
      original.check(legacy);
      require(legacy.core->deinit(), "release original chain after verifying refusal was nondestructive");
      legacy.initialized = false;
      legacy.core.reset();
    }
  };
  checkOpen(2, false, true);
  checkOpen(4, false, true);
  checkOpen(4, false, false);         // A second attempt preserves the same prefix.
  checkOpen(7, false, true);          // Ordered legacy time still lacks the V9 commitment.
  checkOpen(8, false, true);          // The version change applies at H itself.
  checkOpen(9, true, true);           // No database rewrite before the first V9 block.
  checkOpen(UINT32_MAX, true, true);

  const Currency currency = makeCurrency(legacy.logger, 9);
  Core reader(currency, nullptr, legacy.logger, legacy.dispatcher);
  Checkpoints points(legacy.logger);
  require(points.add_checkpoint(4, Common::podToHex(original.ids[4])) &&
          points.add_checkpoint(8, Common::podToHex(original.ids[7])), "set exact and mismatching checkpoints");
  reader.set_checkpoints(std::move(points));
  CoreConfig config;
  config.configFolder = legacy.directory.string();
  require(reader.init(config, MinerConfig{}, true) && reader.get_tail_id() == original.ids[4],
          "compatible stored timestamps preserve checkpoint rollback to the last matching checkpoint");
  require(reader.deinit(), "close after checkpoint rollback");
}

#ifndef TIMESTAMP_LEGACY_BASELINE
void storedMiningTime(const fs::path& root) {
  const uint64_t base = wallTime() - 1800;
  Fixture fixture(root / "stored-mining-time", 3);
  fixture.append(base);
  fixture.append(base + 100);
  auto held = fixture.buildNext(base + 100);
  held.timestampOffset = 40;
  fixture.prove(held, fixture.miner, fixture.core->get_blockchain_storage().getDifficultyForNextBlock(held.previousBlockHash));
  fixture.accept(held);
  fixture.append(base + 120);
  const Snapshot original(fixture);
  fixture.restart();
  original.check(fixture);
  require(fixture.core->deinit(), "close the committed two-clock fixture");
  fixture.initialized = false;
  fixture.core.reset();

  const auto refuses = [&](uint32_t activation) {
    const Currency currency = makeCurrency(fixture.logger, activation);
    Core reader(currency, nullptr, fixture.logger, fixture.dispatcher);
    CoreConfig config;
    config.configFolder = fixture.directory.string();
    require(!reader.init(config, MinerConfig{}, true), "refuse an incompatible V9 database on startup");
  };
  refuses(UINT32_MAX);
  refuses(2);
  refuses(4);
  refuses(20);

  const auto database = (fixture.directory / "blockchain.lmdb").string();
  DbBlockMeta valid{};
  {
    LMDBBlockchainDB db;
    require(db.open(database) && db.getBlockMeta(3, valid) && valid.timestampOffset == held.timestampOffset,
            "read the committed V9 offset");
  }
  const auto write = [&](const DbBlockMeta& metadata) {
    LMDBBlockchainDB db;
    require(db.open(database), "open closed fixture for metadata control");
    db.beginWriteTxn();
    require(db.putBlockMeta(3, metadata), "write controlled V9 metadata");
    db.commitTxn();
  };
  auto changed = valid;
  ++changed.cumulativeDifficulty;
  write(changed);
  refuses(3);
  changed = valid;
  --changed.timestampOffset; // Plausible raw time but different from the signed header.
  write(changed);
  refuses(3);
  write(valid);
  fixture.open();
  original.check(fixture);
}
#endif

// Write the original SwappedVector record layout for a coinbase-only history.
struct LegacyCoinbase {
  Transaction tx;
  std::vector<uint32_t> globalOutputIndexes;
  void serialize(ISerializer& serializer) {
    serializer(tx, "tx");
    serializer(globalOutputIndexes, "m_global_output_indexes");
  }
};
struct LegacyBlock {
  Block block;
  uint32_t height;
  uint64_t size, work, coins;
  std::vector<LegacyCoinbase> transactions;
  void serialize(ISerializer& serializer) {
    serializer(block, "block");
    serializer(height, "height");
    serializer(size, "block_cumulative_size");
    serializer(work, "cumulative_difficulty");
    serializer(coins, "already_generated_coins");
    serializer(transactions, "transactions");
  }
};

void migration(const fs::path& root) {
  Fixture source(root / "import-source"), prefix(root / "import-target");
  const uint64_t base = wallTime() - 1800;
  for (uint64_t delta : {0, 60, 0, 120, 120}) source.append(base + delta);
  prefix.accept(source.blockAt(1));
  const auto prefixTip = prefix.core->get_tail_id();
  require(prefix.core->deinit(), "close previously committed migration prefix");
  prefix.initialized = false;
  prefix.core.reset();

  const auto blocks = prefix.directory / prefix.currency.blocksFileName();
  const auto indexes = prefix.directory / prefix.currency.blockIndexesFileName();
  const Snapshot expected(source);
  {
    SwappedVector<LegacyBlock> records;
    require(records.open(blocks.string(), indexes.string(), 4), "create legacy files");
    std::vector<BlockStatsEntry> stats;
    require(source.core->getBlockStats(0, static_cast<uint32_t>(expected.ids.size() - 1), stats) &&
            stats.size() == expected.ids.size(), "read migration history metadata");
    for (const auto& stat : stats) {
      const auto block = source.blockAt(stat.height);
      records.push_back({block, stat.height, stat.blockSize, expected.work.at(stat.height),
                         stat.alreadyGeneratedCoins, {{block.baseTransaction, {}}}});
    }
  }
  const auto bytes = [](const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    require(bool(in), "retained migration file exists");
    return std::string(std::istreambuf_iterator<char>(in), {});
  };
  const auto originalBlocks = bytes(blocks), originalIndexes = bytes(indexes);
  const Currency active = makeCurrency(prefix.logger, 2);
  CoreConfig config;
  config.configFolder = prefix.directory.string();
  for (int attempt = 0; attempt < 2; ++attempt) {
    Core reader(active, nullptr, prefix.logger, prefix.dispatcher);
    require(!reader.init(config, MinerConfig{}, true), "refuse legacy import with an active inversion");
    require(bytes(blocks) == originalBlocks && bytes(indexes) == originalIndexes, "retain both original files exactly");
    LMDBBlockchainDB saved;
    require(saved.open((prefix.directory / "blockchain.lmdb").string()), "refused import releases database lock");
    DbBlockMeta tip{};
    require(saved.getChainHeight() == 2 && saved.getBlockMeta(1, tip) &&
            std::memcmp(tip.hash, prefixTip.data, sizeof(tip.hash)) == 0, "abort pending import and keep committed prefix");
  }
  const Currency compatible = makeCurrency(prefix.logger, 6);
  {
    Core reader(compatible, nullptr, prefix.logger, prefix.dispatcher);
    require(reader.init(config, MinerConfig{}, true) && reader.get_tail_id() == expected.ids.back(),
            "resume compatible migration using the retained original files");
    require(!fs::exists(blocks) && !fs::exists(indexes) && reader.deinit(), "complete normal legacy-file cleanup");
  }
  prefix.open();
  expected.check(prefix);
}

#ifndef TIMESTAMP_LEGACY_BASELINE
void checkWalletRestore(Fixture& fixture, const CryptoPQ::SeedMaster& seed,
                        const Transaction& transfer, uint32_t height) {
  const Block fundingBlock = fixture.blockAt(height);
  const auto tip = fixture.core->getCurrentBlockchainHeight() - 1;
  require(fundingBlock.timestampOffset > 0, "restore payment has different ordered and miner times");
  uint32_t start = 0, count = 0, fullOffset = 0;
  std::vector<BlockShortInfo> entries;
  require(fixture.core->queryBlocksLite({fixture.currency.genesisBlockHash()}, fundingBlock.timestamp,
          start, count, fullOffset, entries), "query wallet history at the payment's exact public timestamp");
  const auto payment = std::find_if(entries.begin(), entries.end(), [&](const BlockShortInfo& entry) {
    return entry.blockId == get_block_hash(fundingBlock);
  });
  require(payment != entries.end() && Common::asBinaryArray(payment->block) == toBinaryArray(fundingBlock) &&
          payment->txPrefixes.size() == 1 && payment->txPrefixes.front().txHash == getObjectHash(transfer),
          "birthday filter includes exact V9 bytes and payment despite the earlier miner time");
  std::vector<WalletSyncBlockInfo> batch;
  require(fixture.core->getWalletSyncBlocks(height, 1, count, batch) && batch.size() == 1 &&
          batch.front().height == height && batch.front().hash == get_block_hash(fundingBlock) &&
          toBinaryArray(batch.front().block) == toBinaryArray(fundingBlock) &&
          batch.front().transactions.size() == 1 && getObjectHash(batch.front().transactions.front()) == getObjectHash(transfer),
          "height-based wallet sync matches the same signed block and transfer");
  CryptoNoteProtocolHandler protocol(fixture.currency, fixture.dispatcher, *fixture.core, nullptr, fixture.logger);
  InProcessNode node(*fixture.core, protocol);
  std::promise<std::error_code> init;
  node.init([&](std::error_code error) { init.set_value(error); });
  require(!init.get_future().get(), "initialize local wallet's in-process Core connection");
  const auto path = (fixture.directory / "restored.wallet").string();
  require(!fs::exists(path), "seed restoration starts without a wallet cache");
  Crypto::SecretKey spend{};
  std::copy(seed.begin(), seed.end(), spend.data);
  const auto expectedAmount = transfer.outputs.at(0).amount;
  const auto check = [&](WalletGreen& wallet) {
    require(wallet.getActualBalance() == expectedAmount && wallet.getPendingBalance() == 0 &&
            wallet.getTransactionCount() == 1, "seed scan restores the exact available amount once");
    const auto tx = wallet.getTransaction(0);
    require(tx.hash == getObjectHash(transfer) && tx.blockHeight == height &&
            tx.timestamp == fundingBlock.timestamp, "wallet restores transaction hash, height and ordered time");
  };
  {
    WalletGreen wallet(fixture.dispatcher, fixture.currency, node, fixture.logger);
    wallet.initialize(path, "fixture");
    wallet.createAddress(spend, fundingBlock.timestamp - 1);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    System::Timer timer(fixture.dispatcher);
    while (wallet.pqSyncedHeight() < tip && std::chrono::steady_clock::now() < deadline)
      timer.sleep(std::chrono::milliseconds(20));
    require(wallet.pqSyncedHeight() == tip, "restored wallet synchronizes through the V9 tip");
    check(wallet);
    wallet.save();
    wallet.shutdown();
  }
  {
    WalletGreen reopened(fixture.dispatcher, fixture.currency, node, fixture.logger);
    reopened.load(path, "fixture");
    check(reopened);
    reopened.shutdown();
  }
  require(node.shutdown(), "close wallet node after restore and reopen");
  std::cout << "[METRIC] wallet_restore_height=" << height << " synced_tip=" << tip
            << " amount=" << expectedAmount << " tx_hash=" << Common::podToHex(getObjectHash(transfer))
            << " ordered_time=" << fundingBlock.timestamp
            << " raw_time=" << fundingBlock.timestamp - fundingBlock.timestampOffset << '\n';
}
#endif

void activation(const fs::path& root) {
  const uint64_t base = wallTime() - 1800;
  Fixture upgraded(root / "upgraded", 15), peer(root / "active-peer", 15), probe(root / "inactive-peer");
  for (uint32_t h = 1; h <= 14; ++h) {
    const uint64_t timestamp = h == 13 ? base + 60 : h == 14 ? base : base - (15 - h) * 90;
    const auto block = upgraded.append(timestamp);
    peer.accept(block); probe.accept(block);
  }
  Snapshot(upgraded).check(peer);
  require(upgraded.blockAt(14).timestamp < upgraded.blockAt(13).timestamp,
          "both upgraded peers accept the exact pre-activation inversion");
  upgraded.restart(); peer.restart();
  Snapshot(upgraded).check(peer);

  const auto forbidden = upgraded.buildNext(base + 59);
  permanent(upgraded, forbidden, "upgraded H rejects a timestamp below its legacy grandparent");
  permanent(probe, forbidden, "inactive peer rejects a V9 block at H");
  const auto oldFormat = probe.append(base + 59);
  permanent(upgraded, oldFormat, "active peer rejects a legacy block at H");
  require(probe.core->get_tail_id() == get_block_hash(oldFormat),
          "inactive peer follows its legacy proof-bearing block");

  const auto funding = upgraded.blockAt(1).baseTransaction;
  PqSpendInput input{};
  input.prevTxid = getObjectHash(funding); input.amount = funding.outputs.at(0).amount;
  input.rho = CryptoPQ::coinbaseRho(upgraded.miner.pqSpendPk(), 1, 0);
  CryptoPQ::SeedMaster seed{}; seed.fill(93);
  const auto recipient = derivePqWalletKeys(seed);
  const auto transfer = buildPqTransaction({input},
      {PqSendOutput{recipient.viewPub, recipient.spendPub, input.amount - Fee}},
      upgraded.miner.pqSpendPk(), upgraded.miner.pqSpendSk());
  const std::list<Transaction> txs{transfer};
  const auto h15 = upgraded.build(upgraded.core->get_tail_id(), 15, base + 60, false, txs, 50);
  upgraded.accept(h15, txs); peer.accept(h15, txs);
  permanent(upgraded, upgraded.buildNext(base + 59), "upgraded H+1 rejects a backward child");
  const auto h16 = upgraded.append(base + 60); peer.accept(h16);
  Snapshot(upgraded).check(peer);

  const auto common = upgraded.core->getBlockIdByHeight(13);
  auto parent = common;
  std::vector<Block> branch;
  for (uint32_t h = 14; h <= 17; ++h) {
    const uint64_t timestamp = h == 14 ? base + 30 : base + 60 + (h - 15);
    const auto block = upgraded.build(parent, h, timestamp, true, h == 15 ? txs : std::list<Transaction>{});
    const auto nextTxs = h == 15 ? txs : std::list<Transaction>{};
    const auto first = upgraded.submit(block, nextTxs);
    const auto second = peer.submit(block, nextTxs);
    require(!first.m_verification_failed && !second.m_verification_failed &&
            first.m_added_to_main_chain == (h == 17) && second.m_added_to_main_chain == (h == 17),
            "both upgraded peers apply the same valid branch across activation");
    if (h == 17) require(first.m_switched_to_alt_chain && second.m_switched_to_alt_chain,
                         "both actual Core instances execute the first reorg");
    parent = get_block_hash(block); branch.push_back(block);
  }
  Snapshot(upgraded).check(peer);
  for (uint32_t h = 17; h <= 18; ++h) {
    const auto back = upgraded.build(h == 17 ? get_block_hash(h16) : parent, h, base + 70 + (h - 17));
    const auto first = upgraded.submit(back), second = peer.submit(back);
    require(!first.m_verification_failed && !second.m_verification_failed &&
            first.m_added_to_main_chain == (h == 18) && second.m_added_to_main_chain == (h == 18),
            "both upgraded peers reorg back to the exact former branch");
    parent = get_block_hash(back);
  }
  const Snapshot expected(upgraded); expected.check(peer);
  upgraded.restart(); peer.restart(); expected.check(upgraded); expected.check(peer);
  Fixture upgradedReplay(root / "upgraded-full-replay", 15), peerReplay(root / "peer-full-replay", 15);
  replay(upgraded, upgradedReplay); replay(upgraded, peerReplay);
  expected.check(upgradedReplay); expected.check(peerReplay);
  upgradedReplay.restart(); peerReplay.restart(); expected.check(upgradedReplay); expected.check(peerReplay);
  Crypto::KeyImage spentTag{};
  const auto nullifier = pqNullifier(boost::get<PqInput>(transfer.inputs.at(0)));
  std::memcpy(spentTag.data, nullifier.data, sizeof(spentTag.data));
  for (Fixture* target : {&upgraded, &peer, &upgradedReplay, &peerReplay}) {
    Crypto::Hash containingBlock; uint32_t containingHeight = 0;
    require(target->core->is_key_image_spent(spentTag) &&
            target->core->getBlockContainingTx(getObjectHash(transfer), containingBlock, containingHeight) &&
            containingHeight == 15 && containingBlock == target->core->getBlockIdByHeight(15),
            "original, restarted and fully replayed peers retain the same spent nullifier and transaction index");
  }
#ifndef TIMESTAMP_LEGACY_BASELINE
  checkWalletRestore(upgradedReplay, seed, transfer, 15);
#endif
  WalletLedger receiver(recipient);
  require(receiver.processTransaction(transfer, getObjectHash(transfer), 15),
          "recipient recognizes the exact transfer after activation/reorg/full replay");
  std::cout << "[METRIC] activation height=15 peers=2,upgraded reorgs=2"
            << " synthetic_replay_from_genesis=1 final_tip=18 funded_pq_transfers=1"
            << " legacy_version_split_at_activation=1\n";
}

void checkpointPromotion(const fs::path& root) {
  const uint64_t now = wallTime(), base = now - 20000;
  Fixture canonical(root / "checkpoint-original", 105), alternative(root / "checkpoint-alternative", 105);
  for (uint32_t h = 1; h <= 90; ++h) {
    const auto block = canonical.append(base - (90 - h) * 90);
    alternative.accept(block);
  }
  for (uint32_t h = 91; h <= 114; ++h) canonical.append(base);
  std::vector<Block> branch;
  for (uint32_t h = 91; h <= 116; ++h) branch.push_back(alternative.append(base + (h - 90) * 90));
  Difficulty oldWork, checkpointWork;
  require(canonical.core->getBlockCumulativeDifficulty(114, oldWork) &&
          alternative.core->getBlockCumulativeDifficulty(116, checkpointWork) && checkpointWork < oldWork,
          "checkpoint branch has strictly less work despite its greater height");
  const auto oldTip = canonical.core->get_tail_id();
  Fixture future(root / "checkpoint-future", 105);
  replay(canonical, future);
  auto futureCheckpoint = branch.back(); futureCheckpoint.timestamp = now + 86400;
  alternative.prove(futureCheckpoint, alternative.miner,
      alternative.core->get_blockchain_storage().getDifficultyForNextBlock(futureCheckpoint.previousBlockHash));
  future.checkpoint(116, get_block_hash(futureCheckpoint));
  canonical.checkpoint(116, get_block_hash(branch.back()));
  const Snapshot original(future);
  for (size_t i = 0; i + 1 < branch.size(); ++i) {
    const auto normal = canonical.submit(branch[i]), pending = future.submit(branch[i]);
    require(!normal.m_verification_failed && !normal.m_added_to_main_chain &&
            !pending.m_verification_failed && !pending.m_added_to_main_chain,
            "lower-work checkpoint ancestors remain alternative until the actual checkpoint");
  }
  const auto rejected = future.submit(futureCheckpoint);
  require(rejected.m_verification_failed && !rejected.m_added_to_main_chain && !rejected.m_already_exists,
          "a checkpoint does not waive the local future-time cap");
#ifndef TIMESTAMP_LEGACY_BASELINE
  require(rejected.m_timestamp_too_far_in_future, "future checkpoint promotion is classified for retry");
#endif
  original.check(future);
  const auto repeated = future.submit(futureCheckpoint);
  require(repeated.m_verification_failed && !repeated.m_already_exists,
          "identical future checkpoint remains eligible for a later retry");
  original.check(future);
  const auto promoted = canonical.submit(branch.back());
  require(promoted.m_added_to_main_chain && promoted.m_switched_to_alt_chain && !promoted.m_verification_failed,
          "valid exact checkpoint forces promotion of a lower-work branch");
  require(!canonical.core->have_block(oldTip), "checkpoint promotion discards the disconnected original suffix");
  const Snapshot expected(alternative); expected.check(canonical);
  canonical.restart(); expected.check(canonical);
  std::cout << "[METRIC] checkpoint old_tip=114 checkpoint_tip=116 old_work=" << oldWork
            << " checkpoint_work=" << checkpointWork
            << " lower_work_promotion=1 future_checkpoint_rejected=1\n";
}

std::string hex(const BinaryArray& bytes) {
  static const char digits[] = "0123456789abcdef";
  std::string result; result.reserve(bytes.size() * 2);
  for (uint8_t value : bytes) { result.push_back(digits[value >> 4]); result.push_back(digits[value & 15]); }
  return result;
}
BinaryArray unhex(const std::string& text) {
  require(text.size() % 2 == 0, "valid compatibility byte encoding length");
  const auto digit = [](char c) -> uint8_t {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    throw std::runtime_error("invalid compatibility byte encoding");
  };
  BinaryArray result;
  for (size_t i = 0; i < text.size(); i += 2) result.push_back((digit(text[i]) << 4) | digit(text[i + 1]));
  return result;
}
unsigned flags(const block_verification_context& result) {
  return unsigned(result.m_verification_failed) | unsigned(result.m_added_to_main_chain) << 1 |
    unsigned(result.m_marked_as_orphaned) << 2 | unsigned(result.m_already_exists) << 3 |
    unsigned(result.m_switched_to_alt_chain) << 4 | unsigned(result.m_finality_fork) << 5;
}
std::string state(Fixture& fixture) {
  Difficulty work;
  require(fixture.core->getBlockCumulativeDifficulty(fixture.core->getCurrentBlockchainHeight() - 1, work),
          "read compatibility transcript work");
  std::ostringstream text;
  text << fixture.core->getCurrentBlockchainHeight() << ' ' << Common::podToHex(fixture.core->get_tail_id())
       << ' ' << work << ' ' << fixture.core->getTotalGeneratedAmount()
       << ' ' << fixture.core->getBlockchainTotalTransactions();
  return text.str();
}

void disabledCompatibility(const fs::path& root) {
  const uint64_t now = wallTime(), base = now - 1800, farFuture = now + 86400;
  Fixture fixture(root / "disabled-policy");
#ifndef TIMESTAMP_LEGACY_BASELINE
  require(fixture.currency.monotonicTimestampHeight() == UINT32_MAX, "production default activation is disabled");
#endif
  require(fixture.currency.blockFutureTimeLimit(BLOCK_MAJOR_VERSION_1) == 270,
          "versioned future-time cap remains three 90-second targets");
  const fs::path scriptPath = root / "disabled-compatibility.script";
  require(!fs::exists(scriptPath), "compatibility script must be new");
  std::ofstream script(scriptPath);
  require(bool(script), "open compatibility transcript");
  script << "timestamp-compatibility-v1 " << farFuture << '\n';
  size_t submissions = 0;
  const auto record = [&](const Block& block) {
    const auto result = fixture.submit(block);
#ifndef TIMESTAMP_LEGACY_BASELINE
    require(!result.m_timestamp_too_far_in_future, "disabled policy preserves legacy future-failure classification");
#endif
    script << "BLOCK " << hex(toBinaryArray(block)) << ' ' << flags(result) << ' ' << state(fixture) << '\n';
    ++submissions;
    return result;
  };
  for (uint32_t h = 1; h <= 14; ++h) {
    const uint64_t timestamp = h == 13 ? base + 60 : h == 14 ? base : base - (15 - h) * 90;
    require(record(fixture.buildNext(timestamp)).m_added_to_main_chain, "disabled policy accepts pre-fork history");
  }
  require(record(fixture.buildNext(base - 1)).m_added_to_main_chain,
          "disabled default still accepts timestamp inversion below both previous blocks");
  require(record(fixture.buildNext(base - 2000)).m_verification_failed, "legacy median bound remains enforced");
  const auto futureMain = fixture.buildNext(farFuture);
  require(record(futureMain).m_verification_failed, "default-disabled main admission enforces future cap");
  require(record(futureMain).m_verification_failed, "identical default-disabled future block remains rejected");
  const auto valid = fixture.buildNext(base + 1);
  require(record(valid).m_added_to_main_chain, "valid block still follows the legacy inversion");
  require(record(valid).m_already_exists, "accepted-block duplicate remains idempotent");
  auto parent = fixture.core->getBlockIdByHeight(13);
  std::vector<Block> branch;
  for (uint32_t h = 14; h <= 17; ++h) {
    branch.push_back(fixture.build(parent, h, farFuture, true));
    const auto result = record(branch.back());
    require(!result.m_added_to_main_chain && (h == 17 ? result.m_verification_failed : !result.m_verification_failed),
            "legacy alternatives retain future headers until winning replay enforces the cap");
    parent = get_block_hash(branch.back());
  }
  const auto tip = fixture.core->get_tail_id();
  const auto futureAfterRestart = fixture.buildNext(farFuture);
  fixture.restart(); script << "RESTART " << state(fixture) << '\n';
  require(fixture.core->get_tail_id() == tip, "disabled-policy restart preserves original chain after failed promotion");
  require(record(futureAfterRestart).m_verification_failed, "default-disabled future child remains rejected after restart");
  script.flush(); require(bool(script), "persist exact compatibility transcript");
  std::cout << "[METRIC] disabled-policy submissions=" << submissions
            << " exact_byte_transcript=" << scriptPath.filename().string() << " future_cap=270\n";
}

void replayCompatibility(const fs::path& root, const fs::path& path) {
  std::ifstream script(path);
  std::string version; uint64_t farFuture;
  require(bool(script >> version >> farFuture) && version == "timestamp-compatibility-v1", "read compatibility transcript header");
  require(wallTime() + 270 < farFuture, "future-test transcript has not expired under the actual clock");
  Fixture fixture(root / "compatibility-replay");
  std::string command, line;
  size_t submissions = 0;
  while (script >> command) {
    unsigned expectedFlags = 0;
    if (command == "BLOCK") {
      std::string bytes;
      require(bool(script >> bytes >> expectedFlags), "read exact block and expected admission flags");
      Block block;
      require(fromBinaryArray(block, unhex(bytes)), "decode exact original signed block");
      const auto result = fixture.submit(block);
      require(flags(result) == expectedFlags, "pristine/default-disabled admission flags match exact same block bytes");
#ifndef TIMESTAMP_LEGACY_BASELINE
      require(!result.m_timestamp_too_far_in_future, "disabled replay does not enable retry classification");
#endif
      ++submissions;
    } else if (command == "RESTART") fixture.restart();
    else throw std::runtime_error("unknown compatibility transcript command");
    std::getline(script, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    require(!line.empty() && line.substr(1) == state(fixture),
            "exact canonical height/hash/work/emission/transaction count matches reference transcript");
  }
  require(script.eof() && submissions != 0, "complete compatibility transcript consumed");
  std::cout << "[METRIC] compatibility-replay exact_signed_blocks=" << submissions
            << " all_admissions_and_canonical_states_matched=1\n";
}
} // namespace

int main(int argc, char** argv) {
  try {
    fs::path directory, replayScript;
    std::string selected = "all";
    for (int i = 1; i < argc; ++i) {
      const std::string option = argv[i];
      if (option == "--data-dir" && i + 1 < argc) directory = argv[++i];
      else if (option == "--case" && i + 1 < argc) selected = argv[++i];
      else if (option == "--replay-script" && i + 1 < argc) replayScript = argv[++i];
      else throw std::runtime_error("usage: timestamp_activation_tests --data-dir NEW_ABSOLUTE_PATH [--case all|activation|late-upgrade|stored-mining-time|migration|checkpoint|disabled] [--replay-script FILE]");
    }
    require(directory.is_absolute() && !fs::exists(directory) && fs::create_directories(directory),
            "new absolute isolated data directory is required");
    size_t completed = 0;
    if (!replayScript.empty()) { replayCompatibility(directory, replayScript); ++completed; }
    else {
      struct Case { const char* name; void (*run)(const fs::path&); };
      const std::vector<Case> cases = {{"activation", activation}, {"late-upgrade", lateUpgrade},
#ifndef TIMESTAMP_LEGACY_BASELINE
                                      {"stored-mining-time", storedMiningTime},
#endif
                                      {"migration", migration}, {"checkpoint", checkpointPromotion},
                                      {"disabled", disabledCompatibility}};
      for (const auto& item : cases) {
#ifdef TIMESTAMP_LEGACY_BASELINE
        if (std::string(item.name) != "disabled") continue;
#endif
        if (selected != "all" && selected != item.name) continue;
        std::cout << "[RUN] " << item.name << std::endl;
        item.run(directory); ++completed;
        std::cout << "[PASS] " << item.name << std::endl;
      }
    }
    require(completed != 0, "requested activation case exists in this build");
    std::cout << "{\"cases_passed\":" << completed << ",\"assertions\":" << assertions
              << ",\"real_pow_blocks\":" << proofs << ",\"real_pow_attempts\":" << proofAttempts << "}\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "[FAIL] " << error.what() << '\n';
    return 1;
  }
}
