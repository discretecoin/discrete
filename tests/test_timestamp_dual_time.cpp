// Copyright (c) 2026, The Discrete developers
// Offline consensus fixture. Only this executable supplies a virtual wall clock.
#include "Common/StringTools.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr std::time_t Epoch = 1800000000;
std::atomic<std::time_t> virtualNow{Epoch};
std::time_t fixtureTime(std::time_t* dest) {
  const auto now = virtualNow.load();
  if (dest) *dest = now;
  return now;
}
}

// Windows x64 time() uses _time64. MinGW can call the UCRT through import pointers.
#if defined(_MSC_VER)
extern "C" __time64_t __cdecl _time64(__time64_t* dest) { return fixtureTime(dest); }
#elif defined(__MINGW32__)
extern "C" {
std::time_t __wrap_time(std::time_t* dest) { return fixtureTime(dest); }
std::time_t __wrap__time64(std::time_t* dest) { return fixtureTime(dest); }
std::time_t (*__wrap___imp_time)(std::time_t*) = fixtureTime;
std::time_t (*__wrap___imp__time64)(std::time_t*) = fixtureTime;
}
#else
constexpr bool timeIsNoexcept = noexcept(std::time(nullptr));
extern "C" std::time_t time(std::time_t* dest) noexcept(timeIsNoexcept) { return fixtureTime(dest); }
#endif

namespace {
using namespace CryptoNote;
namespace fs = std::filesystem;
constexpr uint32_t H = 15;
constexpr uint32_t Disabled = UINT32_MAX;

void check(bool value, const std::string& message) {
  if (!value) throw std::runtime_error(message);
}

struct Node {
  Logging::ConsoleLogger logger{Logging::ERROR};
  Currency currency;
  System::Dispatcher dispatcher;
  Core core;
  AccountBase miner;
  bool opened;

  Node(const fs::path& directory, uint32_t activation, bool expectOpen = true)
      : currency(CurrencyBuilder(logger).testnet(true).monotonicTimestampHeight(activation).currency()),
        core(currency, nullptr, logger, dispatcher), opened(false) {
    fs::create_directories(directory);
    CoreConfig config;
    config.configFolder = directory.string();
    opened = core.init(config, MinerConfig{}, true);
    check(opened == expectOpen, "stored history opens only with its compatible activation height");
    if (opened) miner.generate();
  }
  ~Node() { if (opened) core.deinit(); }

  Block prepare() {
    Block block;
    Difficulty diff;
    uint32_t height;
    check(core.get_block_template_pq(block, miner.pqViewPk(), miner.pqSpendPk(), diff, height, {}),
          "request actual miner template");
    check(height == core.getCurrentBlockchainHeight() && block.previousBlockHash == core.get_tail_id() &&
          diff == core.getNextBlockDifficulty(), "template parent, height and work");
    return block;
  }

  Block prove(Block block) {
    const auto diff = core.getNextBlockDifficulty();
    check(diff != 0, "nonzero required work");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
    for (uint32_t nonce = 0; nonce < 1000000; ++nonce) {
      if (!(nonce % 64)) check(std::chrono::steady_clock::now() < deadline, "fixture proof search deadline");
      block.nonce = nonce;
      BinaryArray blob;
      Crypto::Hash hash;
      check(get_block_hashing_blob(block, blob) &&
            discrete_power_prove(blob, miner.pqSpendSk(), block.signature, hash), "sign actual proof input");
      if (check_hash(hash, diff)) return block;
    }
    throw std::runtime_error("fixture proof search limit");
  }

  block_verification_context submit(const Block& block) {
    block_verification_context result{};
    core.handle_incoming_block(block, result, false, false);
    return result;
  }

  std::string state() {
    const auto height = core.getCurrentBlockchainHeight() - 1;
    const auto hash = core.get_tail_id();
    Difficulty work, diff;
    Block tip;
    check(core.getBlockDifficulty(height, diff) && core.getBlockCumulativeDifficulty(height, work) &&
          core.getBlockByHash(hash, tip), "read canonical work, difficulty and header");
    std::ostringstream out;
    out << height << ' ' << Common::podToHex(hash) << ' ' << diff << ' ' << work << ' '
        << core.getNextBlockDifficulty() << ' ' << tip.timestamp << ' ' << tip.timestampOffset << ' '
        << core.getTotalGeneratedAmount() << ' ' << core.getBlockchainTotalTransactions();
    return out.str();
  }
};

unsigned flags(const block_verification_context& v) {
  return unsigned(v.m_added_to_main_chain) | (unsigned(v.m_verification_failed) << 1) |
    (unsigned(v.m_marked_as_orphaned) << 2) | (unsigned(v.m_already_exists) << 3) |
    (unsigned(v.m_switched_to_alt_chain) << 4) | (unsigned(v.m_finality_fork) << 5) |
    (unsigned(v.m_timestamp_too_far_in_future) << 6);
}

void accepted(Node& node, const Block& block) {
  check(flags(node.submit(block)) == 1 && node.core.get_tail_id() == get_block_hash(block),
        "accept signed block as canonical");
}

void expectTuple(const Block& block, uint64_t order, uint64_t raw) {
  check(block.majorVersion == 9 && order >= raw && block.timestamp == order && block.timestampOffset == order - raw,
        "expected version, nondecreasing header and raw sample");
}

void generate(const fs::path& directory, const fs::path& path) {
  check(!fs::exists(path), "refuse to replace an existing transcript");
  std::ofstream script(path, std::ios::binary);
  check(bool(script), "create signed transcript");
  script << "discrete-dual-time-v1\n";
  const auto mainPath = directory / "main";
  auto main = std::make_unique<Node>(mainPath, Disabled);
  Node side(directory / "side", H);

  const auto record = [&](const Block& block) {
    const auto bytes = toBinaryArray(block);
    Block decoded;
    check(fromBinaryArray(decoded, bytes) && toBinaryArray(decoded) == bytes, "canonical serialized block round trip");
    const auto result = main->submit(decoded);
    script << "B " << virtualNow.load() << ' ' << Common::toHex(bytes) << ' ' << flags(result) << ' '
           << main->state() << '\n';
    return result;
  };
  const auto reopen = [&](bool checkConflictingPolicies) {
    const auto before = main->state();
    main.reset();
    if (checkConflictingPolicies) {
      for (uint32_t wrong : {Disabled, H + 1, H - 1}) {
        Node incompatible(mainPath, wrong, false);
        script << "F " << wrong << '\n';
      }
    }
    main = std::make_unique<Node>(mainPath, H);
    check(main->state() == before, "reopen identical stored height, work, times and tip");
    script << "R " << H << ' ' << main->state() << '\n';
  };

  // Below H an external producer may undercut the previous stamp under the legacy median.
  for (uint32_t height = 1; height < H; ++height) {
    virtualNow = Epoch;
    auto block = main->prepare();
    check(block.majorVersion == 1 && block.timestampOffset == 0, "legacy wire rule below H");
    block.timestamp = height == H-2 ? Epoch+270 : height == H-1 ? Epoch-10 : Epoch-(H-height)*90;
    block = main->prove(block);
    check(flags(record(block)) == 1, "record signed old-policy prefix");
    if (height <= H-3) accepted(side, block);
  }
  reopen(false);
  // The old grandparent was accepted at +270. Correcting the local clock by
  // one second leaves the ordinary raw sample admissible on the same branch.
  virtualNow = Epoch-1;
  auto boundary = main->prepare();
  expectTuple(boundary, Epoch+270, Epoch-1);
  auto invalid = boundary;
  invalid.timestamp = Epoch-10;
  invalid.timestampOffset = 0;
  check(flags(record(main->prove(invalid))) == 2, "activation requires the legacy grandparent floor");

  boundary = main->prove(boundary);
  invalid = boundary;
  ++invalid.timestampOffset;
  BinaryArray originalBlob, changedBlob;
  check(get_block_hashing_blob(boundary, originalBlob) && get_block_hashing_blob(invalid, changedBlob) &&
        originalBlob != changedBlob && get_block_hash(boundary) != get_block_hash(invalid),
        "raw offset changes the signed input and block ID");
  check(flags(record(invalid)) == 2, "a different valid-domain raw sample cannot reuse the original proof");
  check(flags(record(boundary)) == 1 && flags(record(boundary)) == 8,
        "accept and deduplicate the exact signed boundary");

  virtualNow = Epoch-5;
  auto child = main->prepare();
  expectTuple(child, Epoch+270, Epoch-5);
  check(flags(record(main->prove(child))) == 1, "accept decreasing raw time under a flat header");
  virtualNow = Epoch+271;
  auto future = main->prepare();
  expectTuple(future, Epoch+271, Epoch+271);
  future = main->prove(future);
  virtualNow = Epoch;
  check(flags(record(future)) == (2|64), "refuse only the genuinely future raw sample");
  virtualNow = Epoch+1;
  check(flags(record(future)) == 1, "retry unchanged proof at the inclusive future cap");
  const auto oldTip = main->core.get_tail_id();
  reopen(true);

  // The side fork begins below H with a different stored grandparent at H.
  bool staged = false, switched = false;
  for (uint32_t height = H-2; height <= H+4; ++height) {
    virtualNow = Epoch-20 + static_cast<int>(height)-static_cast<int>(H);
    auto other = side.prepare();
    if (height < H) {
      other.timestamp = height == H-2 ? Epoch+30 : Epoch-5;
    } else {
      expectTuple(other, Epoch+30, static_cast<uint64_t>(virtualNow.load()));
    }
    if (height == H) {
      auto wrongFloor = other;
      ++wrongFloor.timestamp;
      ++wrongFloor.timestampOffset;
      check(flags(record(side.prove(wrongFloor))) == 2, "require the exact branch-local maximum on the side fork");
    }
    other = side.prove(other);
    accepted(side, other);
    const auto result = record(other);
    check(!result.m_verification_failed && !result.m_marked_as_orphaned && !result.m_finality_fork,
          "store valid fork block");
    staged |= !result.m_added_to_main_chain;
    switched |= result.m_switched_to_alt_chain;
  }
  check(staged && switched && oldTip != main->core.get_tail_id() && main->state() == side.state(),
        "heavier fork crosses H and converges to independently validated signed branch");
  reopen(false);
  // An independent synthetic chain distinguishes raw and ordered LWMA inputs
  // at actual testnet difficulty. The oracle reads signed headers and actual
  // cumulative work and does not use the database's timestamp metadata.
  main.reset();
  main = std::make_unique<Node>(directory / "difficulty", H);
  Node workFork(directory / "difficulty-fork", H);
  script << "N " << H << ' ' << main->state() << '\n';
  std::vector<uint64_t> rawHistory, orderedHistory;
  std::vector<Difficulty> workHistory;
  std::vector<Difficulty> rawOracle, orderedOracle;
  unsigned different = 0;
  Difficulty highest = 0;
  std::time_t observed = Epoch;
  for (uint32_t height = 1; height <= 138; ++height) {
    observed += height >= 29 && height <= 79 ? 15 : 90;
    const auto sample = observed + (height == 73 ? 270 : 0);
    virtualNow = sample;
    auto job = main->prepare();
    check(job.timestamp >= job.timestampOffset && job.timestamp - job.timestampOffset == static_cast<uint64_t>(sample),
          "raw sample in actual miner template follows the specified observations");
    const size_t window = std::min(rawHistory.size(), main->currency.difficultyBlocksCountByBlockVersion(job.majorVersion));
    const std::vector<Difficulty> work(workHistory.end() - window, workHistory.end());
    const auto expected = main->currency.nextDifficulty(height, job.majorVersion,
        {rawHistory.end() - window, rawHistory.end()}, work);
    const auto ordered = main->currency.nextDifficulty(height, job.majorVersion,
        {orderedHistory.end() - window, orderedHistory.end()}, work);
    rawOracle.push_back(expected);
    orderedOracle.push_back(ordered);
    check(main->core.getNextBlockDifficulty() == expected, "actual miner difficulty equals the raw-header oracle");
    if (expected != ordered) ++different;
    highest = std::max(highest, expected);
    const auto block = main->prove(job);
    virtualNow = observed;
    check(flags(record(block)) == 1, "accept real signed block at raw-oracle difficulty");
    if (height <= 132) accepted(workFork, block);
    Difficulty actual, cumulative;
    check(main->core.getBlockDifficulty(height, actual) && actual == expected &&
          main->core.getBlockCumulativeDifficulty(height, cumulative), "stored block work equals the raw oracle");
    rawHistory.push_back(block.timestamp - block.timestampOffset);
    orderedHistory.push_back(block.timestamp);
    workHistory.push_back(cumulative);
  }
  check(different > 1 && highest > 1, "workload distinguishes the raw and ordered LWMA difficulty oracles");
  // Check the same observations through the separate alternative-parent lookup.
  // The fork is short enough to remain within the existing finality window.
  unsigned differentOnFork = 0;
  bool promoted = false;
  for (uint32_t height = 133; height <= 139; ++height) {
    virtualNow = observed + (static_cast<int>(height) - 138) * 90;
    auto job = workFork.prepare();
    const auto branchWork = workFork.core.getNextBlockDifficulty();
    const auto stagedWork = main->core.get_blockchain_storage().getDifficultyForNextBlock(job.previousBlockHash);
    check(stagedWork == branchWork, "alternative parent yields the reference branch's required work");
    if (height <= 138) {
      check(stagedWork == rawOracle.at(height - 1), "alternative-parent difficulty matches the raw oracle");
      if (height > 133 && stagedWork != orderedOracle.at(height - 1)) ++differentOnFork;
    }
    const auto block = workFork.prove(job);
    accepted(workFork, block);
    const auto added = record(block);
    check(!added.m_verification_failed && !added.m_finality_fork &&
          added.m_added_to_main_chain == (height == 139), "stage the signed alternative until it has more work");
    promoted |= added.m_switched_to_alt_chain;
  }
  check(differentOnFork != 0 && promoted && main->state() == workFork.state(),
        "actual alternative-parent path distinguishes raw timestamps and promotes exact heavier tip");
  std::cout << "[METRIC] raw_lwma heights=138 different_ordered_oracle=" << different
            << " different_on_fork=" << differentOnFork << " maximum_difficulty=" << highest << '\n';
  script << "END " << main->state() << '\n';
  script.close();
  check(bool(script), "flush signed transcript");
}

void replay(const fs::path& directory, const fs::path& path) {
  std::ifstream script(path);
  std::string line;
  check(bool(std::getline(script,line)), "read transcript header");
  if (!line.empty() && line.back()=='\r') line.pop_back();
  check(line=="discrete-dual-time-v1", "recognized signed transcript");
  auto node = std::make_unique<Node>(directory, Disabled);
  unsigned blocks = 0, restarts = 0, refused = 0, newChains = 0;
  bool ended = false;
  while (std::getline(script,line)) {
    if (!line.empty() && line.back()=='\r') line.pop_back();
    check(!ended, "no trailing data after end marker");
    std::istringstream fields(line);
    std::string action;
    check(bool(fields >> action), "read transcript operation");
    if (action == "B") {
      std::time_t clock{};
      std::string bytes;
      unsigned expected{};
      check(bool(node) && bool(fields >> clock >> bytes >> expected), "read signed block, observer time and disposition");
      virtualNow = clock;
      Block block;
      auto encoded = Common::fromHex(bytes);
      check(fromBinaryArray(block,encoded) && toBinaryArray(block)==encoded, "replay exact serialized bytes");
      check(flags(node->submit(block)) == expected, "reproduce block, fork, future and proof decisions");
      ++blocks;
    } else if (action == "R") {
      uint32_t activation;
      check(bool(fields >> activation) && activation == H, "read configured restart height");
      node.reset();
      node = std::make_unique<Node>(directory,activation);
      ++restarts;
    } else if (action == "N") {
      uint32_t activation;
      check(bool(fields >> activation) && activation == H && newChains == 0, "start the independent difficulty chain");
      node.reset();
      node = std::make_unique<Node>(directory / "difficulty", activation);
      ++newChains;
    } else if (action == "F") {
      uint32_t wrong;
      check(bool(fields >> wrong) && (wrong == Disabled || wrong == H+1 || wrong == H-1),
            "read incompatible policy");
      node.reset();
      Node incompatible(directory, wrong, false);
      ++refused;
      continue;
    } else {
      check(action == "END" && bool(node), "recognized transcript termination");
      ended = true;
    }
    std::string expectedState;
    std::getline(fields, expectedState);
    check(expectedState == " "+node->state(),
          "same tip, height, per-block difficulty, cumulative work, next difficulty, timestamps and emission");
  }
  check(script.eof() && ended && blocks >= 138 && restarts == 3 && refused == 3 && newChains == 1,
        "complete signed branch and difficulty transcripts");
  std::cout << "[PASS] dual-time signed submissions=" << blocks << " restarts=" << restarts
            << " incompatible_opens_refused=" << refused << " final_state=" << node->state() << '\n';
}
}

int main(int argc, char** argv) {
  try {
    fs::path directory, exportPath, replayPath;
    for (int i=1; i<argc; ++i) {
      const std::string opt=argv[i];
      check(i+1 < argc, "each option takes a path");
      const fs::path value(argv[++i]);
      if (opt == "--data-dir") directory=value;
      else if (opt == "--export-script") exportPath=value;
      else if (opt == "--replay-script") replayPath=value;
      else throw std::runtime_error("unknown option: "+opt);
    }
    check(directory.is_absolute() && !fs::exists(directory) && fs::create_directories(directory),
          "a new absolute isolated data directory is required");
    check(exportPath.empty() || replayPath.empty(), "choose export or replay");
    virtualNow = Epoch-1;
    check(std::time(nullptr) == Epoch-1, "test executable's virtual clock is effective");
    virtualNow = Epoch;
    if (replayPath.empty()) {
      replayPath = exportPath.empty() ? directory/"dual-time.script" : exportPath;
      generate(directory,replayPath);
    }
    replay(directory/"replay",replayPath);
    return 0;
  } catch (const std::exception& err) {
    std::cerr << "[FAIL] " << err.what() << '\n';
    return 1;
  }
}
