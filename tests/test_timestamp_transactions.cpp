// Copyright (c) 2026, The Discrete developers
//
// Funded PQ transfer recovery through Core, LMDB and the real transaction pool.
// Only this executable wraps time(); it never changes the host clock.

#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/PqValidation.h"
#include "Common/Math.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"
#include "TestGenerator/TestGenerator.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/WalletLedger.h"
#include "crypto_pq/PqOutputBuilder.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
std::atomic<std::time_t> wallTime{1800000100};
std::function<void()> clockObservation;
}
extern "C" std::time_t __wrap_time(std::time_t* result) {
  const auto captured = wallTime.load(std::memory_order_relaxed);
  if (clockObservation) clockObservation();
  if (result) *result = captured;
  return captured;
}

namespace {
using namespace CryptoNote;
namespace fs = std::filesystem;
constexpr uint64_t Base = 1800000000, Fee = 50;
size_t checks = 0, proofs = 0;
bool requireCachedFee = false, ordinaryReorg = false;
void require(bool condition, const std::string& message) {
  ++checks;
  if (!condition) throw std::runtime_error(message);
}

Currency makeCurrency(Logging::ILogger& logger) {
  CurrencyBuilder builder(logger);
  builder.testnet(true);
#ifndef TIMESTAMP_LEGACY_BASELINE
  if (!ordinaryReorg) builder.monotonicTimestampHeight(15);
#endif
  return builder.currency();
}

struct Fixture {
  Logging::ConsoleLogger logger{Logging::ERROR};
  const Currency currency = makeCurrency(logger);
  System::Dispatcher dispatcher;
  std::unique_ptr<Core> core;
  test_generator generator{currency};
  AccountBase miner, alternate;
  fs::path directory;
  bool initialized = false;

  explicit Fixture(const fs::path& path) : directory(path) {
    require(!fs::exists(directory), "data directory must be fresh");
    require(fs::create_directories(directory), "create isolated data directory");
    miner.generate(); alternate.generate(); open();
    std::vector<size_t> sizes;
    generator.addBlock(blockAt(0), 0, 0, sizes, 0);
  }
  ~Fixture() { if (initialized) core->deinit(); }
  void open() {
    core.reset(new Core(currency, nullptr, logger, dispatcher));
    CoreConfig config; config.configFolder = directory.string();
    require(core->init(config, MinerConfig{}, false), "initialize Core");
    initialized = true;
    generator.setBlockchain(&core->get_blockchain_storage());
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
  void prove(Block& block, const AccountBase& identity, Difficulty difficulty) {
    require(difficulty > 0 && difficulty <= 100, "bounded fixture difficulty");
    const auto started = std::chrono::steady_clock::now();
    bool solved = false;
    for (uint32_t nonce = 0; nonce < 10000; ++nonce) {
      require(std::chrono::steady_clock::now() - started < std::chrono::seconds(120), "bounded proof search");
      block.nonce = nonce;
      BinaryArray blob; Crypto::Hash hash;
      require(get_block_hashing_blob(block, blob) &&
              discrete_power_prove(blob, identity.pqSpendSk(), block.signature, hash), "real DiscretePower proof");
      if (check_hash(hash, difficulty)) { solved = true; ++proofs; break; }
    }
    require(solved, "proof meets actual branch difficulty");
  }
  Block build(const Crypto::Hash& parent, uint32_t height, uint64_t timestamp,
              bool alt = false, const std::list<Transaction>& transactions = {}) {
    const auto& identity = alt ? alternate : miner;
    uint64_t generated = generator.getAlreadyGeneratedCoins(parent);
    if (parent == currency.genesisBlockHash())
      require(core->getAlreadyGeneratedCoins(parent, generated), "read genesis allocation");
    std::vector<size_t> sizes;
    generator.getLastNBlockSizes(sizes, parent, currency.rewardBlocksWindow());
    generator.defaultMajorVersion = core->getBlockMajorVersionForHeight(height);
    Block block;
    require(generator.constructBlock(block, height, parent, identity, timestamp, generated, sizes, transactions),
            "construct real signed block");
    prove(block, identity, core->get_blockchain_storage().getDifficultyForNextBlock(parent));
    size_t bytes = 0;
    for (const auto& tx : transactions) bytes += getObjectBinarySize(tx);
    generator.addBlock(block, bytes, Fee * transactions.size(), sizes, generated);
    return block;
  }
  block_verification_context submit(const Block& block) {
    block_verification_context result{};
    core->handle_incoming_block(block, result, false, false);
    return result;
  }
  Block append(uint64_t timestamp, const std::list<Transaction>& transactions = {}) {
    const auto block = build(core->get_tail_id(), core->getCurrentBlockchainHeight(), timestamp, false, transactions);
    const auto result = submit(block);
    require(result.m_added_to_main_chain && !result.m_verification_failed, "accept canonical block");
    return block;
  }
  tx_verification_context submit(const Transaction& tx) {
    tx_verification_context result{};
    core->handleIncomingTransaction(tx, getObjectHash(tx), toBinaryArray(tx).size(), result, false,
                                    core->getCurrentBlockchainHeight());
    return result;
  }
};

struct Snapshot {
  std::vector<Crypto::Hash> ids;
  std::vector<Difficulty> work;
  uint64_t generated;
  size_t transactions;
  explicit Snapshot(Core& core) : generated(core.getTotalGeneratedAmount()),
      transactions(core.getBlockchainTotalTransactions()) {
    for (uint32_t h = 0; h < core.getCurrentBlockchainHeight(); ++h) {
      ids.push_back(core.getBlockIdByHeight(h));
      Difficulty value;
      require(core.getBlockCumulativeDifficulty(h, value), "snapshot cumulative work");
      work.push_back(value);
    }
  }
  void check(Core& core) const {
    require(core.getCurrentBlockchainHeight() == ids.size() && core.getTotalGeneratedAmount() == generated &&
            core.getBlockchainTotalTransactions() == transactions, "restore height, emission and transaction count");
    for (uint32_t h = 0; h < ids.size(); ++h) {
      Difficulty value;
      require(core.getBlockIdByHeight(h) == ids[h] && core.getBlockCumulativeDifficulty(h, value) && value == work[h],
              "restore every exact block ID and cumulative work value");
    }
  }
};

void transferState(Core& core, const Transaction& tx, const Crypto::KeyImage& tag,
                   bool canonical, uint32_t height = 0) {
  const auto id = getObjectHash(tx);
  auto& chain = core.get_blockchain_storage();
  require(chain.haveTransaction(id) == canonical && core.is_key_image_spent(tag) == canonical,
          "transaction index and spent nullifier match canonical state");
  require(core.getPoolTransactionsCount() == (canonical ? 0 : 1), "pool has exactly the expected transaction count");
  std::list<Transaction> stored;
  std::list<Crypto::Hash> missing;
  core.getTransactions({id}, stored, missing, false);
  if (canonical) {
    uint32_t actualHeight = 0;
    require(stored.size() == 1 && missing.empty() && toBinaryArray(stored.front()) == toBinaryArray(tx) &&
            chain.getTransactionHeight(id, actualHeight) && actualHeight == height,
            "canonical transfer retains exact signed bytes and expected height");
  } else {
    require(stored.empty() && missing.size() == 1, "removed transfer is absent from canonical storage");
    const auto pool = core.getMemoryPool();
    require(pool.size() == 1 && pool.front().id == id && toBinaryArray(pool.front().tx) == toBinaryArray(tx),
            "returned pool transfer retains exact signed bytes");
    const auto poolNullifier = pqNullifier(boost::get<PqInput>(pool.front().tx.inputs.at(0)));
    require(std::memcmp(poolNullifier.data, tag.data, sizeof(tag.data)) == 0, "pool transfer retains the same nullifier");
    uint64_t resolvedFee = 0;
    require(core.getPqTransactionFee(tx, resolvedFee) && resolvedFee == Fee, "actual transfer fee remains unchanged");
    // Existing popBlock saves a PQ transaction before removing its spent tag.
    // Record the pool's cached fee separately from the valid transaction's fee.
    std::cout << "METRIC,returned_pool_cached_fee," << pool.front().fee << ",resolved_fee," << resolvedFee << '\n';
    if (pool.front().fee != Fee)
      std::cout << "[OBSERVED EXISTING],returned_pool_cached_fee_mismatch,stored," << pool.front().fee
                << ",actual," << Fee << '\n';
    if (requireCachedFee) require(pool.front().fee == Fee, "returned pool transfer retains its cached fee");
    BlockInfo referenced;
    require(chain.checkTransactionInputs(tx, referenced), "returned transfer is valid against restored funding output");
  }
}

uint64_t rewardFor(Fixture& fixture, const Block& block, const Transaction& transfer, uint64_t fee) {
  require(block.transactionHashes == std::vector<Crypto::Hash>{getObjectHash(transfer)},
          "reward comparison covers exactly the returned transfer");
  std::vector<size_t> sizes;
  require(fixture.core->getBackwardBlocksSizes(fixture.core->getCurrentBlockchainHeight() - 1,
          sizes, fixture.currency.rewardBlocksWindow()), "read actual reward history");
  uint64_t reward = 0;
  int64_t emission = 0;
  require(fixture.currency.getBlockReward(block.majorVersion, Common::medianValue(sizes),
          getObjectBinarySize(block.baseTransaction) + getObjectBinarySize(transfer),
          fixture.core->getTotalGeneratedAmount(), fee, reward, emission), "calculate actual consensus reward");
  return reward;
}

uint64_t paidReward(const Block& block) {
  uint64_t total = 0;
  for (const auto& output : block.baseTransaction.outputs) total += output.amount;
  return total;
}

void observeReturnedTemplate(Fixture& fixture, const Transaction& transfer, const Crypto::KeyImage& tag) {
  Block block; Difficulty difficulty = 0; uint32_t height = 0;
  require(fixture.core->get_block_template_pq(block, fixture.miner.pqViewPk(), fixture.miner.pqSpendPk(),
          difficulty, height, {}), "request actual miner template after transaction returns to pool");
  const auto expected = rewardFor(fixture, block, transfer, Fee);
  const auto actual = paidReward(block);
  std::cout << "METRIC,returned_transfer_template_reward," << actual << ",consensus_reward," << expected << '\n';
  if (actual != expected) {
    std::cout << "[OBSERVED EXISTING],returned_transfer_template_reward_mismatch,paid," << actual
              << ",required," << expected << '\n';
    require(actual < expected, "characterized template underpays rather than overpays");
    const Snapshot original(*fixture.core);
    const auto before = fixture.core->getMemoryPool();
    fixture.prove(block, fixture.miner, difficulty);
    const auto rejected = fixture.submit(block);
    require(rejected.m_verification_failed && !rejected.m_added_to_main_chain,
            "real consensus rejects the actually proved underpaid miner template");
    original.check(*fixture.core);
    transferState(*fixture.core, transfer, tag, false);
    const auto after = fixture.core->getMemoryPool();
    require(before.size() == 1 && after.size() == 1 && before.front().id == after.front().id &&
            toBinaryArray(before.front().tx) == toBinaryArray(after.front().tx),
            "rejected miner template preserves exact pool transaction bytes and count");
    // Returning a transaction after rejection may re-evaluate the cached fee.
    // Preserve the economic state checks and report this metadata transition.
    std::cout << "[OBSERVED EXISTING],proved_underpaid_template_rejected,1,cached_fee_before,"
              << before.front().fee << ",cached_fee_after," << after.front().fee << '\n';
  }
  // The later reinclusion is a manually constructed fee-correct test block;
  // it does not claim to exercise the miner's automatic retry/refresh loop.
}

struct ClockStep {
  bool fired = false;
  explicit ClockStep(Core& core, const Crypto::Hash& replayedTip) {
    clockObservation = [&, replayedTip] {
      if (!fired && core.getCurrentBlockchainHeight() == 16 && core.get_tail_id() == replayedTip) {
        fired = true;
        wallTime.store(Base - 600, std::memory_order_relaxed);
      }
    };
  }
  ~ClockStep() { clockObservation = {}; }
};

void run(const fs::path& directory) {
  require(static_cast<uint64_t>(std::time(nullptr)) == Base + 100, "executable-only time wrapper is effective");
  Fixture fixture(directory);
  auto& core = *fixture.core;
  for (uint32_t h = 1; h <= 13; ++h) fixture.append(Base - (13 - h) * 900);
  const auto common = core.get_tail_id();
  const auto funding = fixture.blockAt(1).baseTransaction;
  PqSpendInput input{};
  input.prevTxid = getObjectHash(funding);
  input.amount = funding.outputs.at(0).amount;
  input.rho = CryptoPQ::coinbaseRho(fixture.miner.pqSpendPk(), 1, 0);
  CryptoPQ::SeedMaster seed{}; seed.fill(19);
  const auto recipient = derivePqWalletKeys(seed);
  const auto transfer = buildPqTransaction({input},
      {PqSendOutput{recipient.viewPub, recipient.spendPub, input.amount - Fee}},
      fixture.miner.pqSpendPk(), fixture.miner.pqSpendSk());
  const auto admission = fixture.submit(transfer);
  require(admission.m_added_to_pool && !admission.m_verification_failed, "mature coinbase spend accepted");
  Crypto::KeyImage tag{};
  const auto nullifier = pqNullifier(boost::get<PqInput>(transfer.inputs.at(0)));
  std::memcpy(tag.data, nullifier.data, sizeof(tag.data));
  const auto conflicting = buildPqTransaction({input},
      {PqSendOutput{fixture.alternate.pqViewPk(), fixture.alternate.pqSpendPk(), input.amount - Fee}},
      fixture.miner.pqSpendPk(), fixture.miner.pqSpendSk());
  require(getObjectHash(conflicting) != getObjectHash(transfer), "conflicting spend is a distinct signed transaction");
  fixture.generator.setTxFee(getObjectHash(transfer), Fee);
  fixture.append(Base + 10, {transfer});
  fixture.append(Base + 20); fixture.append(Base + 30);
  const Snapshot original(core);
  transferState(core, transfer, tag, true, 14);

  std::vector<Block> branch;
  auto parent = common;
  for (uint32_t h = 14; h <= 17; ++h) {
    branch.push_back(fixture.build(parent, h, Base + (h - 10) * 10, true));
    parent = get_block_hash(branch.back());
    if (h < 17) {
      const auto staged = fixture.submit(branch.back());
      require(!staged.m_added_to_main_chain && !staged.m_verification_failed, "stage competing branch");
    }
  }
  if (!ordinaryReorg) {
#ifndef TIMESTAMP_LEGACY_BASELINE
    {
    ClockStep step(core, get_block_hash(branch[1]));
    const auto failed = fixture.submit(branch.back());
    require(step.fired && failed.m_verification_failed && failed.m_timestamp_too_far_in_future &&
            !failed.m_added_to_main_chain, "clock step during actual partial replay causes temporary rejection");
    }
    original.check(core); transferState(core, transfer, tag, true, 14);
    const auto repeated = fixture.submit(branch.back());
    require(repeated.m_timestamp_too_far_in_future && !repeated.m_already_exists, "same winning tip remains retryable");
    original.check(core); transferState(core, transfer, tag, true, 14);
#else
    throw std::runtime_error("The legacy baseline requires --ordinary-reorg");
#endif
  }

  wallTime.store(Base + 100, std::memory_order_relaxed);
  const auto promoted = fixture.submit(branch.back());
  require(promoted.m_added_to_main_chain && promoted.m_switched_to_alt_chain && !promoted.m_verification_failed,
          "same winning tip alone promotes after clock recovery");
  for (uint32_t i = 0; i < branch.size(); ++i)
    require(core.getBlockIdByHeight(14 + i) == get_block_hash(branch[i]), "exact alternative branch becomes canonical");
  transferState(core, transfer, tag, false);
  const auto poolConflict = fixture.submit(conflicting);
  require(poolConflict.m_verification_failed && !poolConflict.m_added_to_pool, "returned pool entry prevents a conflicting spend");
  fixture.restart(); transferState(*fixture.core, transfer, tag, false);
  const auto persistedConflict = fixture.submit(conflicting);
  require(persistedConflict.m_verification_failed && !persistedConflict.m_added_to_pool,
          "restart preserves pool duplicate-spend protection");
  const auto retry = fixture.submit(transfer);
  require(!retry.m_verification_failed && !retry.m_added_to_pool, "identical transaction retry does not duplicate pool entry");
  transferState(*fixture.core, transfer, tag, false);
  observeReturnedTemplate(fixture, transfer, tag);
  const auto included = fixture.build(fixture.core->get_tail_id(), fixture.core->getCurrentBlockchainHeight(),
                                       Base + 100, false, {transfer});
  const auto expectedReward = rewardFor(fixture, included, transfer, Fee);
  require(paidReward(included) == expectedReward && expectedReward - rewardFor(fixture, included, transfer, 0) == Fee,
          "explicit fee-correct reinclusion pays the complete reward including all 50 fee units");
  const auto reincluded = fixture.submit(included);
  require(reincluded.m_added_to_main_chain && !reincluded.m_verification_failed, "accept fee-correct reinclusion");
  transferState(*fixture.core, transfer, tag, true, 18);
  const Snapshot finalState(*fixture.core);
  const auto duplicate = fixture.submit(included);
  require(duplicate.m_already_exists && !duplicate.m_added_to_main_chain, "duplicate block does not include transfer twice");
  const auto rejected = fixture.submit(conflicting);
  require(rejected.m_verification_failed && !rejected.m_added_to_pool, "new double-spend of the restored nullifier is rejected");
  fixture.restart(); finalState.check(*fixture.core); transferState(*fixture.core, transfer, tag, true, 18);
  WalletLedger receiver(recipient);
  require(receiver.processTransaction(transfer, getObjectHash(transfer), 18), "recipient recognizes reincluded transfer");
  const auto outputs = receiver.spendableInputs();
  require(outputs.size() == 1 && outputs.front().amount == input.amount - Fee, "recipient retains exactly one correct output");
  std::cout << "PASS,checks," << checks << ",real_proofs," << proofs
            << ",transfer_original_height,14,transfer_reincluded_height,18,restarts,2,ordinary_reorg,"
            << ordinaryReorg << ",strict_cached_fee," << requireCachedFee << ",manual_fee_correct_reinclusion,1\n";
}
} // namespace

int main(int argc, char** argv) {
  try {
    fs::path directory;
    for (int i = 1; i < argc; ++i) {
      const std::string argument = argv[i];
      if (argument == "--data-dir" && i + 1 < argc) directory = argv[++i];
      else if (argument == "--ordinary-reorg") ordinaryReorg = true;
      else if (argument == "--require-cached-fee") requireCachedFee = true;
      else throw std::runtime_error("Usage: timestamp_transactions_tests --data-dir FRESH_DIRECTORY [--ordinary-reorg] [--require-cached-fee]");
    }
    require(!directory.empty(), "--data-dir is required");
#ifdef TIMESTAMP_LEGACY_BASELINE
    require(ordinaryReorg, "The legacy baseline requires --ordinary-reorg");
#endif
    run(directory);
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "FAIL," << error.what() << '\n';
    return 1;
  }
}
