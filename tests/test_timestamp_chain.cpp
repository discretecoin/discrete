// Copyright (c) 2026, The Discrete developers
//
// Timestamp qualification through Core, LMDB, and real DiscretePower proofs.
// The test executable alone links with --wrap=time. No host clock is changed.

#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"
#include "TestGenerator/TestGenerator.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
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
std::atomic<std::time_t> testWallTime{0};
std::function<void()> testClockObservation;
}

extern "C" std::time_t __real_time(std::time_t* result);
extern "C" std::time_t __wrap_time(std::time_t* result) {
  const std::time_t injected = testWallTime.load(std::memory_order_relaxed);
  if (injected == 0) return __real_time(result);
  // A scheduled step occurs immediately after this clock observation. The
  // current caller receives its captured value; later calls see the new time.
  if (testClockObservation) testClockObservation();
  if (result != nullptr) *result = injected;
  return injected;
}

namespace {
using namespace CryptoNote;
namespace fs = std::filesystem;
constexpr uint64_t Base = 1800000000;
size_t assertions = 0;
size_t proofs = 0;
uint64_t proofAttempts = 0;

void require(bool condition, const std::string& message) {
  ++assertions;
  if (!condition) throw std::runtime_error(message);
}

void setClock(uint64_t seconds) {
  testWallTime.store(static_cast<std::time_t>(seconds), std::memory_order_relaxed);
  require(static_cast<uint64_t>(std::time(nullptr)) == seconds,
          "test-only time wrapper is effective");
}

Currency makeCurrency(Logging::ILogger& logger, uint32_t activation) {
  CurrencyBuilder builder(logger);
  builder.testnet(true);
#ifndef TIMESTAMP_LEGACY_BASELINE
  builder.monotonicTimestampHeight(activation);
#else
  (void)activation;
#endif
  return builder.currency();
}

struct Fixture {
  Logging::ConsoleLogger logger{Logging::ERROR};
  const Currency currency;
  System::Dispatcher dispatcher;
  std::unique_ptr<Core> core;
  test_generator generator;
  AccountBase miner;
  AccountBase alternateMiner;
  fs::path directory;
  bool initialized = false;

  Fixture(const fs::path& path, uint32_t activation)
      : currency(makeCurrency(logger, activation)), generator(currency), directory(path) {
    require(!fs::exists(directory), "test data directory must not already exist: " + directory.string());
    fs::create_directories(directory);
    miner.generate();
    alternateMiner.generate();
    open();
    Block genesis;
    require(core->getBlockByHash(core->getBlockIdByHeight(0), genesis), "load genesis");
    std::vector<size_t> sizes;
    generator.addBlock(genesis, 0, 0, sizes, 0);
  }

  void open() {
    core.reset(new Core(currency, nullptr, logger, dispatcher));
    CoreConfig config;
    config.configFolder = directory.string();
    require(core->init(config, MinerConfig{}, false), "Core initialization");
    initialized = true;
    generator.setBlockchain(&core->get_blockchain_storage());
  }

  void close() {
    if (initialized) {
      require(core->deinit(), "Core clean shutdown");
      initialized = false;
    }
  }

  void restart() {
    const auto tip = core->get_tail_id();
    const auto height = core->getCurrentBlockchainHeight();
    close();
    core.reset();
    open();
    require(core->get_tail_id() == tip, "restart preserves exact canonical tip");
    require(core->getCurrentBlockchainHeight() == height, "restart preserves height");
  }

  ~Fixture() {
    if (initialized) core->deinit();
  }

  Block blockAt(uint32_t height) {
    Block block;
    require(core->getBlockByHash(core->getBlockIdByHeight(height), block), "load canonical block");
    return block;
  }

  void prove(Block& block, const AccountBase& identity, Difficulty difficulty) {
    require(difficulty != 0 && difficulty <= 100000,
            "bounded qualification difficulty: " + std::to_string(difficulty));
    const auto started = std::chrono::steady_clock::now();
    for (uint32_t nonce = 0; nonce < 1000000; ++nonce) {
      if (nonce % 128 == 0) {
        require(std::chrono::steady_clock::now() - started < std::chrono::seconds(120),
                "proof search exceeded 120 seconds");
      }
      block.nonce = nonce;
      BinaryArray blob;
      require(get_block_hashing_blob(block, blob), "serialize proof candidate");
      Crypto::Hash hash;
      require(discrete_power_prove(blob, identity.pqSpendSk(), block.signature, hash),
              "real DiscretePower proof computation");
      ++proofAttempts;
      if (check_hash(hash, difficulty)) {
        ++proofs;
        return;
      }
    }
    throw std::runtime_error("proof search attempt bound exceeded");
  }

  Block build(const Crypto::Hash& parent, uint32_t height, uint64_t timestamp,
              bool alternate = false) {
    const AccountBase& identity = alternate ? alternateMiner : miner;
    uint64_t generated = generator.getAlreadyGeneratedCoins(parent);
    // Genesis uses the Treasury Reserve allocation rather than ordinary emission.
    if (parent == currency.genesisBlockHash()) {
      require(core->getAlreadyGeneratedCoins(parent, generated), "read actual genesis allocation");
    }
    std::vector<size_t> sizes;
    generator.getLastNBlockSizes(sizes, parent, currency.rewardBlocksWindow());
    generator.defaultMajorVersion = core->getBlockMajorVersionForHeight(height);
    Block block;
    require(generator.constructBlock(block, height, parent, identity, timestamp,
                                     generated, sizes, std::list<Transaction>{}),
            "construct signed block at height " + std::to_string(height));
    const auto difficulty = core->get_blockchain_storage().getDifficultyForNextBlock(parent);
    prove(block, identity, difficulty);
    generator.addBlock(block, 0, 0, sizes, generated);
    return block;
  }

  Block buildNext(uint64_t timestamp, bool alternate = false) {
    return build(core->get_tail_id(), core->getCurrentBlockchainHeight(), timestamp, alternate);
  }

  block_verification_context submit(const Block& block) {
    block_verification_context context{};
    core->handle_incoming_block(block, context, false, false);
    return context;
  }

  Block append(uint64_t timestamp) {
    Block block = buildNext(timestamp);
    const auto context = submit(block);
    require(context.m_added_to_main_chain && !context.m_verification_failed,
            "canonical admission at timestamp " + std::to_string(timestamp));
    require(core->get_tail_id() == get_block_hash(block), "canonical exact block ID");
    return block;
  }

  void rejectPermanent(const Block& block, const std::string& label) {
    const auto tip = core->get_tail_id();
    const auto height = core->getCurrentBlockchainHeight();
    const auto context = submit(block);
    require(context.m_verification_failed && !context.m_added_to_main_chain, label);
#ifdef TIMESTAMP_RETRY_CANDIDATE
    require(!context.m_timestamp_too_far_in_future, label + ": permanent failure is not temporary");
#endif
    require(core->get_tail_id() == tip && core->getCurrentBlockchainHeight() == height,
            label + ": state unchanged");
  }

  void rejectTemporary(const Block& block, const std::string& label) {
    const auto tip = core->get_tail_id();
    const auto height = core->getCurrentBlockchainHeight();
    const auto context = submit(block);
    require(!context.m_added_to_main_chain && !context.m_already_exists, label);
#ifdef TIMESTAMP_RETRY_CANDIDATE
    require(context.m_verification_failed && context.m_timestamp_too_far_in_future,
            label + ": explicit future-time retry classification");
#endif
    require(core->get_tail_id() == tip && core->getCurrentBlockchainHeight() == height,
            label + ": state unchanged");
  }
};

struct ScheduledClockRollback {
  size_t observations = 0;
  bool fired = false;
  uint32_t observedHeight = 0;
  Crypto::Hash observedTip{};

  ScheduledClockRollback(Core& core, uint32_t height, const Crypto::Hash& tip,
                         uint64_t newTime) {
    require(!testClockObservation, "only one scheduled process-clock step is armed");
    testClockObservation = [&, height, tip, newTime]() {
      ++observations;
      if (fired || core.getCurrentBlockchainHeight() != height || core.get_tail_id() != tip) return;
      observedHeight = core.getCurrentBlockchainHeight();
      observedTip = core.get_tail_id();
      fired = true;
      testWallTime.store(static_cast<std::time_t>(newTime), std::memory_order_relaxed);
    };
  }

  ~ScheduledClockRollback() { testClockObservation = {}; }
};

struct CanonicalSnapshot {
  std::vector<Crypto::Hash> ids;
  std::vector<Difficulty> work;

  explicit CanonicalSnapshot(Fixture& fixture) {
    for (uint32_t h = 0; h < fixture.core->getCurrentBlockchainHeight(); ++h) {
      ids.push_back(fixture.core->getBlockIdByHeight(h));
      Difficulty cumulative;
      require(fixture.core->getBlockCumulativeDifficulty(h, cumulative), "snapshot canonical work");
      work.push_back(cumulative);
    }
  }

  void check(Fixture& fixture, const std::string& label) const {
    require(fixture.core->getCurrentBlockchainHeight() == ids.size(), label + ": exact height");
    for (uint32_t h = 0; h < ids.size(); ++h) {
      Difficulty cumulative;
      require(fixture.core->getBlockIdByHeight(h) == ids[h], label + ": exact block ID");
      require(fixture.core->getBlockCumulativeDifficulty(h, cumulative) && cumulative == work[h],
              label + ": exact cumulative work");
    }
  }
};

struct RecordingMinerHandler : IMinerHandler {
  Core& core;
  std::vector<Block> templates;
  std::vector<Difficulty> difficulties;
  std::vector<uint32_t> heights;
  size_t foundCalls = 0;
  size_t hashCalls = 0;

  explicit RecordingMinerHandler(Core& source) : core(source) {}

  bool handle_block_found(Block& block) override {
    ++foundCalls;
    return core.handle_block_found(block);
  }

  bool get_block_template_pq(Block& block, const CryptoPQ::KemPublicKey& viewPub,
      const CryptoPQ::DsaPublicKey& spendPub, Difficulty& difficulty, uint32_t& height,
      const BinaryArray& extraNonce) override {
    if (!core.get_block_template_pq(block, viewPub, spendPub, difficulty, height, extraNonce)) return false;
    templates.push_back(block);
    difficulties.push_back(difficulty);
    heights.push_back(height);
    return true;
  }

  bool getBlockLongHash(Crypto::cn_context& context, const Block& block, Crypto::Hash& result) override {
    ++hashCalls;
    return core.getBlockLongHash(context, block, result);
  }
};

void prepareBoundary(Fixture& fixture) {
  for (uint32_t height = 1; height <= 12; ++height) {
    fixture.append(Base - (15 - height) * 90);
  }
  fixture.append(Base + 60);
  fixture.append(Base);
  require(fixture.core->getCurrentBlockchainHeight() == 15, "prepared exact activation boundary");
}

void legacy(const fs::path& root) {
  setClock(Base);
  Fixture fixture(root / "legacy", UINT32_MAX);
  prepareBoundary(fixture);
  const auto lower = fixture.append(Base - 1);
  require(lower.timestamp < fixture.blockAt(14).timestamp &&
          lower.timestamp < fixture.blockAt(13).timestamp,
          "legacy consensus accepts a child below both immediate ancestors");
  fixture.restart();
}

void boundary(const fs::path& root) {
  setClock(Base);
  Fixture fixture(root / "boundary", 15);
  prepareBoundary(fixture);

  Block blockTemplate;
  Difficulty difficulty = 0;
  uint32_t height = 0;
  require(fixture.core->get_block_template_pq(blockTemplate, fixture.miner.pqViewPk(),
          fixture.miner.pqSpendPk(), difficulty, height, BinaryArray{}), "activation template");
  require(height == 15 && blockTemplate.timestamp == Base + 60,
          "activation template carries the legacy grandparent maximum");

  const auto invalid = fixture.buildNext(Base + 59);
  fixture.rejectPermanent(invalid, "H rejects timestamp between parent and grandparent");
  fixture.rejectPermanent(invalid, "H repeated invalid block remains rejected");
  fixture.append(Base + 60);
  fixture.rejectPermanent(fixture.buildNext(Base + 59), "H+1 rejects backward timestamp");
  fixture.append(Base + 60);
  fixture.append(Base + 61);
  fixture.restart();

  Fixture replay(root / "boundary-replay", 15);
  for (uint32_t h = 1; h < fixture.core->getCurrentBlockchainHeight(); ++h) {
    const Block block = fixture.blockAt(h);
    const auto context = replay.submit(block);
    require(context.m_added_to_main_chain && !context.m_verification_failed,
            "synthetic historical replay preserves activation at " + std::to_string(h));
  }
  require(replay.core->get_tail_id() == fixture.core->get_tail_id(),
          "replay reaches the same exact canonical tip");
}

void rapid(const fs::path& root) {
  setClock(Base);
  Fixture fixture(root / "rapid", 2);
  for (uint32_t height = 1; height <= 80; ++height) {
    fixture.append(Base - (80 - height) * 90);
  }
  for (uint32_t count = 0; count < 24; ++count) {
    const uint32_t height = fixture.core->getCurrentBlockchainHeight();
    std::vector<uint64_t> timestamps;
    std::vector<Difficulty> work;
    for (uint32_t h = height - 61; h < height; ++h) {
      uint64_t timestamp;
      Difficulty cumulative;
      require(fixture.core->getBlockTimestamp(h, timestamp), "read admitted LWMA timestamp");
      require(fixture.core->getBlockCumulativeDifficulty(h, cumulative), "read admitted cumulative work");
      timestamps.push_back(timestamp);
      work.push_back(cumulative);
    }
    const auto expected = fixture.currency.nextDifficulty(height,
        fixture.core->getBlockMajorVersionForHeight(height), timestamps, work);
    require(fixture.core->getNextBlockDifficulty() == expected,
            "actual next difficulty agrees with unchanged LWMA on admitted history");
    fixture.append(Base);
    Difficulty admitted;
    require(fixture.core->getBlockDifficulty(height, admitted) && admitted == expected,
            "stored block work equals actual required LWMA difficulty");
    std::cout << "[METRIC] rapid height=" << height << " timestamp=" << Base
              << " difficulty=" << admitted << '\n';
  }
  require(fixture.blockAt(104).timestamp == fixture.blockAt(80).timestamp,
          "24 real-PoW child blocks admitted with exactly the parent second");
  setClock(Base + 1);
  fixture.append(Base + 1);
}

void clockRollback(const fs::path& root) {
  setClock(Base);
  Fixture fixture(root / "clock", 2);
  for (uint32_t height = 1; height <= 20; ++height) {
    fixture.append(Base - (20 - height) * 90);
  }
  const auto same = fixture.buildNext(Base);
  setClock(Base - 300);
  fixture.rejectTemporary(same, "rollback -300: parent floor exceeds local future cap");
  fixture.rejectTemporary(same, "rollback: identical block can be submitted again before eligibility");
  setClock(Base - 271);
  fixture.rejectTemporary(same, "one second before eligibility remains rejected");
  setClock(Base - 270);
  const auto accepted = fixture.submit(same);
  require(accepted.m_added_to_main_chain && !accepted.m_verification_failed,
          "same proof and block ID accepted at the exact 30-second recovery boundary");
  const auto height = fixture.core->getCurrentBlockchainHeight();
  const auto duplicate = fixture.submit(same);
  require(duplicate.m_already_exists && !duplicate.m_added_to_main_chain &&
          fixture.core->getCurrentBlockchainHeight() == height,
          "accepted-block replay is idempotent");

  const auto next = fixture.buildNext(Base);
  setClock(Base - 600);
  fixture.restart();
  fixture.rejectTemporary(next, "restart behind persisted parent retains the future constraint");
  setClock(Base - 270);
  const auto afterRestart = fixture.submit(next);
  require(afterRestart.m_added_to_main_chain && !afterRestart.m_verification_failed,
          "identical pending block accepted after restart and clock recovery");
  setClock(Base);
  const auto futureParent = fixture.append(Base + 270);
  const auto equalFuture = fixture.buildNext(futureParent.timestamp);
  setClock(Base - 1);
  fixture.rejectTemporary(equalFuture, "one-second rollback after maximum future lead");
  setClock(Base);
  const auto equalAccepted = fixture.submit(equalFuture);
  require(equalAccepted.m_added_to_main_chain && !equalAccepted.m_verification_failed,
          "maximum-future parent allows equal child when the clock is restored");
}

void prepareFork(Fixture& fixture) {
  for (uint32_t height = 1; height <= 13; ++height) {
    fixture.append(Base - (13 - height) * 900);
  }
}

void reorg(const fs::path& root) {
  setClock(Base + 100);
  Fixture fixture(root / "reorg", 15);
  prepareFork(fixture);
  const auto common = fixture.core->get_tail_id();
  fixture.append(Base + 100);
  fixture.append(Base + 100);
  const auto originalTip = fixture.append(Base + 100);
  const auto alt14 = fixture.build(common, 14, Base - 100, true);
  auto context = fixture.submit(alt14);
  require(!context.m_verification_failed && !context.m_added_to_main_chain,
          "legacy alt block below its own parent is stored before activation");
  const auto wrong15 = fixture.build(get_block_hash(alt14), 15, Base - 50, true);
  fixture.rejectPermanent(wrong15, "alt activation uses its actual grandparent");
  const auto alt15 = fixture.build(get_block_hash(alt14), 15, Base, true);
  context = fixture.submit(alt15);
  require(!context.m_verification_failed && !context.m_added_to_main_chain,
          "valid alt timestamp below main tip is stored using branch ancestry");
  const auto alt16 = fixture.build(get_block_hash(alt15), 16, Base, true);
  context = fixture.submit(alt16);
  require(!context.m_verification_failed && !context.m_added_to_main_chain,
          "equal-work alternative branch does not replace the canonical branch");
  const auto alt17 = fixture.build(get_block_hash(alt16), 17, Base, true);
  context = fixture.submit(alt17);
  require(context.m_added_to_main_chain && context.m_switched_to_alt_chain &&
          !context.m_verification_failed, "higher-work branch promotes across activation");
  require(fixture.core->getBlockIdByHeight(14) == get_block_hash(alt14) &&
          fixture.core->getBlockIdByHeight(15) == get_block_hash(alt15) &&
          fixture.core->get_tail_id() == get_block_hash(alt17),
          "reorg installs the exact branch and grandfathered pre-activation inversion");
  require(fixture.blockAt(17).timestamp < originalTip.timestamp,
          "branch-local monotonicity does not pretend to prevent a tip-time decrease on reorg");

  const auto back17 = fixture.build(get_block_hash(originalTip), 17, Base + 100);
  context = fixture.submit(back17);
  require(!context.m_verification_failed && !context.m_added_to_main_chain,
          "former canonical branch can be extended as a valid equal-work alternative");
  const auto back18 = fixture.build(get_block_hash(back17), 18, Base + 100);
  context = fixture.submit(back18);
  require(context.m_added_to_main_chain && context.m_switched_to_alt_chain &&
          fixture.core->get_tail_id() == get_block_hash(back18),
          "second reorg back across activation follows the actual winning ancestry");
  require(!fixture.core->getFinalityForkState().active, "shallow valid reorg does not arm deep recovery");
  fixture.restart();
}

void futureReorgScenario(const fs::path& root, const char* name, bool rollbackClock) {
  setClock(Base + 30);
  Fixture fixture(root / name, 15);
  prepareFork(fixture);
  const auto common = fixture.core->get_tail_id();
  fixture.append(Base + 10);
  fixture.append(Base + 20);
  fixture.append(Base + 30);
  std::vector<Crypto::Hash> original;
  for (uint32_t h = 0; h < fixture.core->getCurrentBlockchainHeight(); ++h) {
    original.push_back(fixture.core->getBlockIdByHeight(h));
  }
  Difficulty originalWork;
  require(fixture.core->getBlockCumulativeDifficulty(16, originalWork), "read pre-switch cumulative work");
  if (rollbackClock) setClock(Base - 300);
  std::vector<Block> branch;
  auto parent = common;
  for (uint32_t h = 14; h <= 17; ++h) {
    auto block = fixture.build(parent, h, Base + 400, true);
    const auto context = fixture.submit(block);
    require(!context.m_added_to_main_chain, "future branch cannot become canonical before eligibility");
    if (h < 17) require(!context.m_verification_failed, "future alt storage retains legacy semantics");
#ifdef TIMESTAMP_RETRY_CANDIDATE
    if (h == 17) {
      require(context.m_verification_failed && context.m_timestamp_too_far_in_future,
              "temporarily ineligible winning branch is explicitly retryable");
    }
#endif
    parent = get_block_hash(block);
    branch.push_back(block);
  }
  require(fixture.core->getCurrentBlockchainHeight() == original.size(),
          "failed future promotion preserves canonical height");
  for (uint32_t h = 0; h < original.size(); ++h) {
    require(fixture.core->getBlockIdByHeight(h) == original[h],
            "failed future promotion restores every original block ID");
  }
  Difficulty afterWork;
  require(fixture.core->getBlockCumulativeDifficulty(16, afterWork) && afterWork == originalWork,
          "failed promotion preserves exact canonical cumulative work");
  setClock(Base + 130);
  for (const auto& block : branch) fixture.submit(block);
  require(fixture.core->get_tail_id() == get_block_hash(branch.back()),
          "resubmitted identical future branch promotes after clock eligibility");
  fixture.restart();
}

void futureReorg(const fs::path& root) {
  futureReorgScenario(root, "future-reorg", false);
}

void futureReorgClock(const fs::path& root) {
  futureReorgScenario(root, "future-reorg-clock", true);
}

void replayClockStep(const fs::path& root) {
  setClock(Base + 100);
  Fixture fixture(root / "replay-clock-step", 15);
  prepareFork(fixture);
  const auto common = fixture.core->get_tail_id();
  fixture.append(Base - 100);
  fixture.append(Base);
  fixture.append(Base + 10);
  const CanonicalSnapshot original(fixture);
  std::vector<Block> branch;
  auto parent = common;
  for (uint32_t h = 14; h <= 17; ++h) {
    branch.push_back(fixture.build(parent, h, Base + (h - 12) * 10, true));
    parent = get_block_hash(branch.back());
    if (h < 17) {
      const auto context = fixture.submit(branch.back());
      require(!context.m_verification_failed && !context.m_added_to_main_chain,
              "prepare equal-work branch for a step during replay");
    }
  }

  block_verification_context failed{};
  {
    // The trigger observes the actual replayed activation block in LMDB. It
    // therefore cannot fire during preflight or before the original disconnect.
    ScheduledClockRollback step(*fixture.core, 16, get_block_hash(branch[1]), Base - 600);
    failed = fixture.submit(branch.back());
    require(step.fired && step.observedHeight == 16 &&
            step.observedTip == get_block_hash(branch[1]),
            "clock step occurs after the alternative activation block was written");
    std::cout << "[METRIC] replay-step clock_observations=" << step.observations
              << " trigger_height=" << step.observedHeight << '\n';
  }
  require(failed.m_verification_failed && !failed.m_added_to_main_chain,
          "real replay fails after the scheduled backward clock step");
#ifdef TIMESTAMP_RETRY_CANDIDATE
  require(failed.m_timestamp_too_far_in_future, "mid-replay future failure remains retryable");
#endif
  original.check(fixture, "rollback after partial activation-crossing replay");
  require(fixture.blockAt(14).timestamp < fixture.blockAt(13).timestamp,
          "restoration preserves a legitimate pre-activation inversion");
  fixture.rejectTemporary(branch.back(), "identical winning tip remains retryable while clock is behind");
  fixture.rejectTemporary(branch.back(), "second identical winning-tip retry is idempotent");
  original.check(fixture, "repeated temporary winning-tip attempts");

  setClock(Base + 100);
  const auto accepted = fixture.submit(branch.back());
  require(accepted.m_added_to_main_chain && accepted.m_switched_to_alt_chain &&
          !accepted.m_verification_failed, "identical winning tip alone retries after clock recovery");
  for (size_t i = 0; i < branch.size(); ++i) {
    require(fixture.core->getBlockIdByHeight(static_cast<uint32_t>(14 + i)) == get_block_hash(branch[i]),
            "successful retry connects the original exact alternative blocks");
  }
  fixture.restart();
}

void permanentReplayClockStep(const fs::path& root) {
  setClock(Base + 100);
  Fixture fixture(root / "permanent-replay-clock-step", 15);
  prepareFork(fixture);
  const auto common = fixture.core->get_tail_id();
  fixture.append(Base - 100);
  fixture.append(Base);
  fixture.append(Base + 10);
  const CanonicalSnapshot original(fixture);
  std::vector<Block> branch;
  auto parent = common;
  for (uint32_t h = 14; h <= 17; ++h) {
    auto block = fixture.build(parent, h, Base + (h - 12) * 10, true);
    if (h == 14) {
      // Alternative admission checks the coinbase structure and real proof;
      // the exact reward is checked only when replaying onto the canonical DB.
      ++block.baseTransaction.outputs[0].amount;
      fixture.prove(block, fixture.alternateMiner,
                    fixture.core->get_blockchain_storage().getDifficultyForNextBlock(parent));
      std::vector<size_t> sizes;
      fixture.generator.getLastNBlockSizes(sizes, parent, fixture.currency.rewardBlocksWindow());
      fixture.generator.addBlock(block, 0, 0, sizes, fixture.generator.getAlreadyGeneratedCoins(parent));
    }
    branch.push_back(block);
    parent = get_block_hash(block);
    if (h < 17) {
      const auto context = fixture.submit(block);
      require(!context.m_verification_failed && !context.m_added_to_main_chain,
              "prepare proof-valid branch with a replay-only coinbase failure");
    }
  }

  block_verification_context failed{};
  {
    // At this height the old suffix has been removed. Return the last eligible
    // time to the first replay timestamp check, then roll back before the
    // reward check and restoration. No production fault-injection hook is used.
    ScheduledClockRollback step(*fixture.core, 14, common, Base - 600);
    failed = fixture.submit(branch.back());
    require(step.fired && step.observedHeight == 14 && step.observedTip == common,
            "permanent replay test steps the clock after the old suffix disconnect");
  }
  require(failed.m_verification_failed && !failed.m_added_to_main_chain,
          "overpaid coinbase fails real canonical replay");
#ifdef TIMESTAMP_RETRY_CANDIDATE
  require(!failed.m_timestamp_too_far_in_future, "permanent reward failure is not classified as temporary");
#endif
  original.check(fixture, "permanent replay failure under clock rollback");
  setClock(Base + 100);
  block_verification_context rejected{};
  for (const auto& block : branch) {
    rejected = fixture.submit(block);
    require(!rejected.m_added_to_main_chain,
            "identical permanently invalid branch cannot become canonical after recovery");
  }
  require(rejected.m_verification_failed, "repeat winning-tip replay still rejects the wrong coinbase reward");
#ifdef TIMESTAMP_RETRY_CANDIDATE
  require(!rejected.m_timestamp_too_far_in_future, "repeat coinbase failure is still permanent after clock recovery");
#endif
  original.check(fixture, "permanent failure retains canonical chain after clock recovery");
  fixture.restart();
}

void shorterHeavierReorg(const fs::path& root) {
  constexpr uint32_t activation = 115;
  constexpr uint32_t commonHeight = 90;
  constexpr uint32_t originalHeight = 116;
  const uint64_t commonTimestamp = Base - (originalHeight - commonHeight) * 90;
  setClock(Base);
  Fixture fixture(root / "shorter-heavier-reorg", activation);
  for (uint32_t h = 1; h <= commonHeight; ++h) {
    fixture.append(Base - (originalHeight - h) * 90);
  }
  auto parent = fixture.core->get_tail_id();
  Difficulty branchWork;
  require(fixture.core->getBlockCumulativeDifficulty(commonHeight, branchWork),
          "read common-ancestor work for shorter/heavier branch");
  std::vector<Block> branch;
  uint32_t winningHeight = 0;
  Difficulty canonicalWork = 0;
  for (uint32_t h = commonHeight + 1; h < activation; ++h) {
    // Store early alternative ancestors while they are still within the
    // existing first-seen finality window; then grow both branches normally.
    const uint32_t desiredMainHeight = std::min(originalHeight, h + 8);
    while (fixture.core->getCurrentBlockchainHeight() <= desiredMainHeight) {
      const uint32_t next = fixture.core->getCurrentBlockchainHeight();
      fixture.append(Base - (originalHeight - next) * 90);
    }
    require(fixture.core->getBlockCumulativeDifficulty(
              fixture.core->getCurrentBlockchainHeight() - 1, canonicalWork),
            "read actual canonical work during branch preparation");
    const auto difficulty = fixture.core->get_blockchain_storage().getDifficultyForNextBlock(parent);
    branch.push_back(fixture.build(parent, h, commonTimestamp, true));
    branchWork += difficulty;
    parent = get_block_hash(branch.back());
    std::cout << "[METRIC] shorter-heavier height=" << h << " difficulty=" << difficulty
              << " branch_work=" << branchWork << " canonical_work=" << canonicalWork << '\n';
    if (branchWork > canonicalWork) {
      winningHeight = h;
      break;
    }
    const auto stored = fixture.submit(branch.back());
    require(!stored.m_verification_failed && !stored.m_added_to_main_chain,
            "real-PoW alternative stays stored until it has greater work");
    require(!fixture.core->getFinalityForkState().active,
            "interleaved branch preparation does not bypass the finality gate");
  }
  require(winningHeight != 0 && winningHeight < activation &&
          fixture.core->getCurrentBlockchainHeight() == originalHeight + 1 && branch.size() >= 2,
          "bounded real LWMA branch wins below H against a canonical tip above H");
  const CanonicalSnapshot original(fixture);
  block_verification_context failed{};
  {
    ScheduledClockRollback step(*fixture.core, commonHeight + 2,
                                get_block_hash(branch.front()), commonTimestamp - 600);
    failed = fixture.submit(branch.back());
    require(step.fired && step.observedTip == get_block_hash(branch.front()),
            "shorter winner clock step occurs during actual pre-activation replay");
  }
  require(failed.m_verification_failed && !failed.m_added_to_main_chain,
          "shorter/heavier replay fails when its next block becomes temporarily future");
#ifdef TIMESTAMP_RETRY_CANDIDATE
  require(failed.m_timestamp_too_far_in_future,
          "old post-activation tip supplies recovery context for a pre-activation winner");
#endif
  original.check(fixture, "shorter/heavier failed replay restores old post-activation suffix");
  fixture.rejectTemporary(branch.back(), "same shorter/heavier winner remains retryable before recovery");
  original.check(fixture, "shorter/heavier repeated attempt preserves original chain");
  setClock(Base);
  const auto accepted = fixture.submit(branch.back());
  require(accepted.m_added_to_main_chain && accepted.m_switched_to_alt_chain &&
          !accepted.m_verification_failed && fixture.core->get_tail_id() == get_block_hash(branch.back()),
          "identical shorter/heavier winning tip alone promotes after clock recovery");
  require(fixture.core->getCurrentBlockchainHeight() == winningHeight + 1 && winningHeight < activation,
          "successful reorg legitimately moves the canonical tip back below activation");
  Difficulty admittedWork;
  require(fixture.core->getBlockCumulativeDifficulty(winningHeight, admittedWork) &&
          admittedWork == branchWork && admittedWork > canonicalWork,
          "shorter winning branch has the exact measured greater cumulative work");
  fixture.restart();
}

void stagedFinality(const fs::path& root) {
  constexpr uint32_t commonHeight = 90;
  constexpr uint32_t originalHeight = 116;
  const uint64_t commonTimestamp = Base - (originalHeight - commonHeight) * 90;
  setClock(Base);
  // This case intentionally disables the proposed timestamp fork and performs
  // no clock step or operator recovery. It also compiles against the baseline.
  Fixture fixture(root / "staged-finality", UINT32_MAX);
  for (uint32_t h = 1; h <= commonHeight; ++h) {
    fixture.append(Base - (originalHeight - h) * 90);
  }
  const auto common = fixture.core->get_tail_id();
  auto parent = common;
  Difficulty branchWork;
  require(fixture.core->getBlockCumulativeDifficulty(commonHeight, branchWork),
          "staged finality reads actual common-ancestor work");
  Difficulty originalWork = 0;
  std::vector<Block> branch;
  uint32_t winningHeight = 0;
  for (uint32_t h = commonHeight + 1; h < 115; ++h) {
    const uint32_t desiredMainHeight = std::min(originalHeight, h + 8);
    while (fixture.core->getCurrentBlockchainHeight() <= desiredMainHeight) {
      const uint32_t next = fixture.core->getCurrentBlockchainHeight();
      fixture.append(Base - (originalHeight - next) * 90);
    }
    require(fixture.core->getBlockCumulativeDifficulty(
              fixture.core->getCurrentBlockchainHeight() - 1, originalWork),
            "staged finality reads actual canonical work");
    const auto difficulty = fixture.core->get_blockchain_storage().getDifficultyForNextBlock(parent);
    branch.push_back(fixture.build(parent, h, commonTimestamp, true));
    parent = get_block_hash(branch.back());
    branchWork += difficulty;
    const bool expectedWinner = branchWork > originalWork;
    if (expectedWinner) {
      require(fixture.core->getCurrentBlockchainHeight() == originalHeight + 1,
              "staged finality retains original tip 116 until the winning submission");
    }
    const auto context = fixture.submit(branch.back());
    if (expectedWinner) {
      require(context.m_added_to_main_chain && context.m_switched_to_alt_chain &&
              !context.m_verification_failed,
              "ordinary staged higher-work branch automatically promotes without operator recovery");
      winningHeight = h;
      break;
    }
    require(!context.m_verification_failed && !context.m_added_to_main_chain &&
            !fixture.core->getFinalityForkState().active,
            "each staged alternative block is admitted while within the incoming-height finality window");
  }
  require(winningHeight != 0 && winningHeight < originalHeight &&
          fixture.core->getCurrentBlockchainHeight() == winningHeight + 1,
          "bounded staged fork replaces a taller chain with the shorter higher-work branch");
  require(fixture.core->getBlockIdByHeight(commonHeight) == common,
          "staged promotion preserves the exact common ancestor at height 90");
  for (size_t i = 0; i < branch.size(); ++i) {
    require(fixture.core->getBlockIdByHeight(static_cast<uint32_t>(commonHeight + 1 + i)) ==
              get_block_hash(branch[i]),
            "staged promotion replaces the original suffix with exact alternative block IDs");
  }
  Difficulty admittedWork;
  require(fixture.core->getBlockCumulativeDifficulty(winningHeight, admittedWork) &&
          admittedWork == branchWork && admittedWork > originalWork,
          "staged promotion uses the exact greater cumulative work");
  require(!fixture.core->getFinalityForkState().active,
          "ordinary staged promotion completes without an active manual-recovery warning");
  require(testWallTime.load(std::memory_order_relaxed) == static_cast<std::time_t>(Base),
          "staged finality reproduction never steps the process clock");
  std::cout << "[METRIC] staged-finality common_height=" << commonHeight
            << " old_tip=" << originalHeight << " new_tip=" << winningHeight
            << " disconnected_original_blocks=" << originalHeight - commonHeight
            << " old_work=" << originalWork << " new_work=" << admittedWork
            << " timestamp_activation=disabled operator_recovery_calls=0\n";
  fixture.restart();
}

void minerRefresh(const fs::path& root) {
  setClock(Base);
  Fixture fixture(root / "miner-refresh", 15);
  prepareBoundary(fixture);
  RecordingMinerHandler handler(*fixture.core);
  CryptoNote::miner templateMiner(fixture.currency, handler, fixture.logger);
  require(templateMiner.startPq(fixture.miner.pqViewPk(), fixture.miner.pqSpendPk(),
                               fixture.miner.pqSpendSk(), 0),
          "initialize actual miner template path with zero worker threads");
  require(templateMiner.is_mining() && handler.templates.size() == 1,
          "zero-worker miner requested its initial real Core template");
  require(handler.heights.back() == 15 && handler.templates.back().timestamp == Base + 60,
          "initial miner template includes the activation grandparent floor");
  require(templateMiner.on_idle() && handler.templates.size() == 2,
          "first real idle callback refreshes the template");

  setClock(Base - 300);
  require(templateMiner.on_idle() && handler.templates.size() == 2,
          "backward wall clock delays the existing periodic template timer");
  require(templateMiner.on_block_chain_update() && handler.templates.size() == 3,
          "chain-update callback bypasses the delayed periodic timer");
  require(handler.templates.back().timestamp == Base + 60,
          "clock rollback cannot lower the actual activation template floor");
  auto pending = handler.templates.back();
  fixture.prove(pending, fixture.miner, handler.difficulties.back());
  fixture.rejectTemporary(pending, "real miner template is temporarily outside the observer future cap");
  setClock(Base);
  auto accepted = fixture.submit(pending);
  require(accepted.m_added_to_main_chain && !accepted.m_verification_failed,
          "identical signed miner template is accepted after clock recovery");

  for (uint32_t i = 0; i < 4; ++i) {
    const size_t before = handler.templates.size();
    require(templateMiner.on_block_chain_update() && handler.templates.size() == before + 1,
            "every same-second chain update requests a fresh actual template");
    require(handler.heights.back() == 16 + i && handler.templates.back().timestamp == Base + 60 &&
            handler.templates.back().previousBlockHash == fixture.core->get_tail_id(),
            "fast template uses new parent and equal timestamp without a one-second ratchet");
    auto block = handler.templates.back();
    fixture.prove(block, fixture.miner, handler.difficulties.back());
    accepted = fixture.submit(block);
    require(accepted.m_added_to_main_chain && !accepted.m_verification_failed,
            "same-second real template and proof are admitted");
  }

  const size_t beforeTimer = handler.templates.size();
  setClock(Base + 5);
  require(templateMiner.on_idle() && handler.templates.size() == beforeTimer,
          "existing five-second timer remains strict at the boundary");
  setClock(Base + 6);
  require(templateMiner.on_idle() && handler.templates.size() == beforeTimer + 1,
          "periodic template refresh resumes six seconds after its previous wall time");
  require(handler.foundCalls == 0 && handler.hashCalls == 0,
          "template qualification created no mining workers or asynchronous submissions");
  templateMiner.send_stop_signal();
  templateMiner.stop();
  require(!templateMiner.is_mining() && templateMiner.pqSpendSecretCleared(),
          "zero-worker template fixture stops and clears its test credentials");
  std::cout << "[METRIC] miner-refresh rollback_seconds=300 periodic_recovery_seconds=306"
            << " same_second_templates=4 worker_threads=0\n";
}

void finality(const fs::path& root) {
  setClock(Base);
  Fixture fixture(root / "finality", 3);
  for (uint32_t height = 1; height <= 20; ++height) {
    fixture.append(Base - (20 - height) * 900);
  }
  const CanonicalSnapshot original(fixture);
  std::string recoveryMessage;
  require(!fixture.core->resyncToMajority(recoveryMessage),
          "manual recovery refuses to cut the chain without an active finality warning");
  original.check(fixture, "refused unarmed manual recovery");
  const auto parent = fixture.blockAt(2);
  const auto invalid = fixture.build(get_block_hash(parent), 3, parent.timestamp - 1, true);
  fixture.rejectPermanent(invalid, "deep competing block with backward time is refused");
  require(!fixture.core->getFinalityForkState().active,
          "proof-bearing but permanently timestamp-invalid competitor cannot arm recovery");
  require(!fixture.core->resyncToMajority(recoveryMessage),
          "permanently invalid timestamp evidence cannot authorize manual recovery");
  original.check(fixture, "manual recovery remains refused after invalid competing timestamp");
  const auto valid = fixture.build(get_block_hash(parent), 3, parent.timestamp + 1, true);
  const auto context = fixture.submit(valid);
  require(!context.m_added_to_main_chain && fixture.core->getFinalityForkState().active,
          "otherwise valid deep competing block retains existing recovery evidence behavior");
  require(fixture.core->getFinalityForkState().divergenceHeight == 2,
          "valid warning identifies the actual common ancestor below activation");
  require(fixture.core->resyncToMajority(recoveryMessage) &&
          fixture.core->getCurrentBlockchainHeight() == 3 &&
          fixture.core->get_tail_id() == get_block_hash(parent) &&
          !fixture.core->getFinalityForkState().active,
          "explicit Core recovery cuts to the recorded ancestor and clears the warning");
  fixture.rejectPermanent(invalid, "manual cut below H does not disable the activation timestamp floor");
  const auto accepted = fixture.submit(valid);
  require(accepted.m_added_to_main_chain && !accepted.m_verification_failed &&
          fixture.core->get_tail_id() == get_block_hash(valid),
          "identical valid competing block is admitted through ordinary validation after manual cut");
  fixture.rejectPermanent(fixture.buildNext(valid.timestamp - 1),
                          "post-recovery H+1 still rejects a backward timestamp");
  fixture.append(valid.timestamp);
  const CanonicalSnapshot recovered(fixture);
  require(!fixture.core->resyncToMajority(recoveryMessage),
          "completed manual recovery cannot be repeated without new validated evidence");
  recovered.check(fixture, "repeated manual recovery is refused without changing recovered state");
  std::cout << "[METRIC] manual-finality old_tip=20 cut_tip=2 activation=3"
            << " valid_competitor_retried=1 post_cut_floor_enforced=1\n";
  fixture.restart();
}

}  // namespace

int main(int argc, char** argv) {
  try {
    fs::path directory;
    std::string selected = "all";
    for (int i = 1; i < argc; ++i) {
      const std::string option = argv[i];
      if (option == "--data-dir" && i + 1 < argc) directory = argv[++i];
      else if (option == "--case" && i + 1 < argc) selected = argv[++i];
      else throw std::runtime_error("usage: timestamp_chain_tests --data-dir NEW_ABSOLUTE_PATH [--case NAME]");
    }
    require(!directory.empty() && directory.is_absolute() && !fs::exists(directory),
            "a new absolute test data directory is required");
    fs::create_directories(directory);
    struct Case { const char* name; void (*run)(const fs::path&); };
    const std::vector<Case> cases = {
      {"legacy", legacy}, {"boundary", boundary}, {"rapid", rapid},
      {"clock", clockRollback}, {"reorg", reorg},
      {"future-reorg", futureReorg}, {"future-reorg-clock", futureReorgClock},
      {"replay-clock-step", replayClockStep},
      {"permanent-replay-clock-step", permanentReplayClockStep},
      {"shorter-heavier-reorg", shorterHeavierReorg},
      {"staged-finality", stagedFinality},
      {"miner-refresh", minerRefresh},
      {"finality", finality}
    };
    size_t completed = 0;
    for (const auto& item : cases) {
#ifdef TIMESTAMP_LEGACY_BASELINE
      if (std::string(item.name) != "legacy" &&
          std::string(item.name) != "future-reorg-clock" &&
          std::string(item.name) != "staged-finality") continue;
#endif
      if (selected != "all" && selected != item.name) continue;
      std::cout << "[RUN] " << item.name << std::endl;
      item.run(directory);
      ++completed;
      std::cout << "[PASS] " << item.name << std::endl;
    }
    require(completed != 0, "unknown or unavailable test case");
    testWallTime.store(0, std::memory_order_relaxed);
    std::cout << "{\"cases_passed\":" << completed << ",\"assertions\":" << assertions
              << ",\"real_pow_blocks_constructed\":" << proofs
              << ",\"real_pow_attempts\":" << proofAttempts << "}" << std::endl;
    return 0;
  } catch (const std::exception& error) {
    testWallTime.store(0, std::memory_order_relaxed);
    std::cerr << "[FAIL] " << error.what() << std::endl;
    return 1;
  }
}
