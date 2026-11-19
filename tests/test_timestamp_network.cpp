// Copyright (c) 2026, The Discrete developers
//
// Actual loopback TCP, Core/LMDB, protocol and NodeServer qualification. Run only
// in a fresh Linux network namespace with loopback enabled. Both nodes share the
// test-only process clock; the source accepts the block before the rollback.
// After the first rejection, recovery uses NodeServer's own reconnect and sync.

#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "Common/StringTools.h"
#include "Logging/StreamLogger.h"
#include "P2p/NetNode.h"
#include "System/Context.h"
#include "System/Dispatcher.h"
#include "System/Timer.h"
#include "TestGenerator/TestGenerator.h"

#include <atomic>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <list>
#include <memory>
#include <net/if.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace CryptoNote {

// The existing test friend provides read-only observations and a qualified call
// to the unchanged real endpoint implementation. No connection policy is faked.
class NodeServerTestAccess {
public:
  static void realDrop(NodeServer& node, CryptoNoteConnectionContext& context, bool addFail) {
    node.NodeServer::drop_connection(context, addFail);
  }

  static uint64_t failureScore(const NodeServer& node, uint32_t address) {
    const auto found = node.m_host_fails_score.find(address);
    return found == node.m_host_fails_score.end() ? 0 : found->second;
  }

  static bool hasConnection(const NodeServer& node, const boost::uuids::uuid& id) {
    return node.m_connections.find(id) != node.m_connections.end();
  }
};

} // namespace CryptoNote

namespace {

using namespace CryptoNote;
using Clock = std::chrono::steady_clock;
std::atomic<time_t> clockOffset{0};
size_t assertions = 0;

void require(bool condition, const std::string& description) {
  ++assertions;
  if (!condition) throw std::runtime_error(description);
}

template<class Condition>
void until(System::Dispatcher& dispatcher, Condition condition,
           const std::string& description, unsigned seconds = 30) {
  const auto deadline = Clock::now() + std::chrono::seconds(seconds);
  while (!condition()) {
    require(Clock::now() < deadline, description);
    System::Timer(dispatcher).sleep(std::chrono::milliseconds(5));
  }
}

void requireIsolatedNetwork() {
  require(std::filesystem::read_symlink("/proc/self/ns/net") !=
              std::filesystem::read_symlink("/proc/1/ns/net"),
          "Must run in a network namespace separate from PID 1");
  struct if_nameindex* interfaces = if_nameindex();
  require(interfaces != nullptr, "Read network interfaces");
  bool onlyLoopback = true;
  bool sawLoopback = false;
  for (auto* current = interfaces; current->if_index != 0; ++current) {
    const std::string name(current->if_name);
    if (name == "lo") sawLoopback = true;
    else onlyLoopback = false;
  }
  if_freenameindex(interfaces);
  require(onlyLoopback && sawLoopback, "Isolated namespace must contain only loopback");
}

struct Drop {
  boost::uuids::uuid connection;
  bool penalty;
  uint32_t height;
  Crypto::Hash tip;
};

class ObservedNodeServer : public NodeServer {
public:
  ObservedNodeServer(System::Dispatcher& dispatcher, CryptoNoteProtocolHandler& protocol,
                     Logging::ILogger& logger, Core& core)
      : NodeServer(dispatcher, protocol, logger), core(core) {}

  void drop_connection(CryptoNoteConnectionContext& connection, bool addFail) override {
    drops.push_back(Drop{connection.m_connection_id, addFail,
                         core.getCurrentBlockchainHeight(), core.get_tail_id()});
    NodeServerTestAccess::realDrop(*this, connection, addFail);
  }

  std::vector<Drop> drops;
  Core& core;
};

struct Node {
  System::Dispatcher& dispatcher;
  Core core;
  CryptoNoteProtocolHandler protocol;
  ObservedNodeServer p2p;
  std::unique_ptr<System::Context<>> service;
  bool initialized = false;

  Node(System::Dispatcher& dispatcher, const Currency& currency, Logging::ILogger& logger,
       const std::filesystem::path& directory, uint16_t port, uint16_t peerPort)
      : dispatcher(dispatcher), core(currency, nullptr, logger, dispatcher),
        protocol(currency, dispatcher, core, nullptr, logger, 1),
        p2p(dispatcher, protocol, logger, core) {
    require(!std::filesystem::exists(directory), "Node directory must be fresh");
    std::filesystem::create_directories(directory);
    protocol.set_p2p_endpoint(&p2p);
    core.set_cryptonote_protocol(&protocol);
    NetNodeConfig config;
    config.setTestnet(true);
    // Standard testnet configuration works without optional lab APIs. The
    // process first requires a private loopback-only network namespace; seeds
    // are empty, the source has no outbound peers, and the receiver exclusively
    // dials the local source. The namespace also contains any UPnP discovery.
    config.setBindIp("127.0.0.1");
    config.setBindPort(port);
    config.setExternalPort(0);
    config.setAllowLocalIp(true);
    config.setConnectionsCount(peerPort == 0 ? 0 : 1);
    config.setConfigFolder(directory.string());
    config.setP2pStateFilename("p2pstate.bin");
    config.setSeedNodes({});
    config.setSeedNodeStrings({});
    if (peerPort != 0) {
      config.setExclusiveNodes({NetworkAddress{Common::stringToIpAddress("127.0.0.1"), peerPort}});
    }
    require(p2p.init(config), "Real NodeServer initialization");
    CoreConfig coreConfig;
    coreConfig.configFolder = directory.string();
    require(core.init(coreConfig, MinerConfig{}, false), "Real Core initialization");
    initialized = true;
  }

  void start() {
    service.reset(new System::Context<>(dispatcher, [&] {
      require(p2p.run(), "Real NodeServer service");
    }));
  }

  void stop() {
    if (service) {
      p2p.sendStopSignal();
      service->get();
      service.reset();
    }
    if (initialized) {
      require(p2p.deinit(), "Persist synthetic peer state");
      require(core.deinit(), "Close synthetic LMDB");
      initialized = false;
    }
  }

  ~Node() {
    try { stop(); } catch (...) {}
  }
};

Block mine(Node& node, const Currency& currency, test_generator& generator,
           const AccountBase& miner, uint64_t timestamp) {
  const uint32_t height = node.core.getCurrentBlockchainHeight();
  uint64_t generated = 0;
  require(node.core.getAlreadyGeneratedCoins(node.core.get_tail_id(), generated), "Read emission");
  std::vector<size_t> sizes;
  require(node.core.getBackwardBlocksSizes(height - 1, sizes, currency.rewardBlocksWindow()),
          "Read reward window");
  generator.defaultMajorVersion = node.core.getBlockMajorVersionForHeight(height);
  Block block;
  require(generator.constructBlock(block, height, node.core.get_tail_id(), miner,
                                   timestamp, generated, sizes, std::list<Transaction>{}),
          "Construct signed block using real DiscretePower");
  const auto difficulty = node.core.getNextBlockDifficulty();
  if (difficulty > 1) {
    fillNonce(block, difficulty, &node.core.get_blockchain_storage(), miner);
    generator.addBlock(block, 0, 0, sizes, generated);
  }
  block_verification_context verification{};
  node.core.handle_incoming_block(block, verification, false, false);
  require(verification.m_added_to_main_chain && !verification.m_verification_failed,
          "Source accepted its block before clock rollback");
  return block;
}

} // namespace

extern "C" time_t __real_time(time_t* destination);
extern "C" time_t __wrap_time(time_t* destination) {
  const time_t value = __real_time(nullptr) + clockOffset.load();
  if (destination) *destination = value;
  return value;
}

int main(int argc, char** argv) {
  try {
    require(argc == 3 && std::string(argv[1]) == "--data-dir",
            "Usage: TimestampNetworkTests --data-dir FRESH_DIRECTORY");
    requireIsolatedNetwork();
    const std::filesystem::path root(argv[2]);
    require(!std::filesystem::exists(root), "Evidence directory must be fresh");
    std::filesystem::create_directories(root);
    std::ofstream log(root / "nodes.log");
    require(log.good(), "Open network evidence log");
    Logging::StreamLogger logger(log, Logging::DEBUGGING);
    System::Dispatcher dispatcher;
    const auto currency = CurrencyBuilder(logger).testnet(true)
        .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
        .upgradeHeightV5(11).upgradeHeightV6(12)
        .monotonicTimestampHeight(14).currency();
    Node source(dispatcher, currency, logger, root / "source", 39480, 0);
    Node receiver(dispatcher, currency, logger, root / "receiver", 39481, 39480);
    test_generator generator(currency);
    generator.setBlockchain(&source.core.get_blockchain_storage());
    AccountBase miner;
    miner.generate();
    Block genesis;
    require(source.core.getBlockByHash(source.core.getBlockIdByHeight(0), genesis), "Load genesis");
    std::vector<size_t> sizes;
    generator.addBlock(genesis, 0, 0, sizes, 0);
    const uint64_t base = static_cast<uint64_t>(std::time(nullptr));
    for (uint32_t height = 1; height <= 13; ++height) {
      mine(source, currency, generator, miner, base - (14 - height) * 90);
    }
    const auto initialTip = source.core.get_tail_id();
    source.start();
    receiver.start();
    until(dispatcher, [&] { return receiver.core.get_tail_id() == initialTip; },
          "Initial sync through actual TCP");
    require(receiver.core.getCurrentBlockchainHeight() == 14, "Receiver initially ends at height 13");
    until(dispatcher, [&] {
      return source.protocol.getPeerCount() != 0 && receiver.protocol.getPeerCount() != 0 &&
             receiver.protocol.isSynchronized();
    }, "Application handshake and initial sync complete");
    require(receiver.p2p.drops.empty(), "No disconnects during initial sync");

    const auto pending = mine(source, currency, generator, miner,
                              static_cast<uint64_t>(std::time(nullptr)));
    const auto raw = toBinaryArray(pending);
    const auto pendingHash = get_block_hash(pending);
    require(get_block_height(pending) == 14, "Pending block activates timestamp floor");
    require(receiver.core.get_tail_id() == initialTip, "Source-only block has not been manually delivered");
    {
      std::ofstream frozen(root / "pending-block.bin", std::ios::binary);
      frozen.write(reinterpret_cast<const char*>(raw.data()), raw.size());
      require(frozen.good(), "Persist exact pending wire block");
    }

    clockOffset.store(-300);
    require(__real_time(nullptr) - std::time(nullptr) == 300, "Only the process clock rolls back 300 seconds");
    require(pending.timestamp > static_cast<uint64_t>(std::time(nullptr)) + 270,
            "Pending block exceeds receiver future-time limit");
    NOTIFY_NEW_BLOCK::request announcement{};
    announcement.b.block = Common::asString(raw);
    announcement.current_blockchain_height = 15;
    // This is the single initial announcement. All subsequent delivery is
    // performed autonomously by NodeServer reconnect and chain synchronization.
    source.core.get_protocol()->relay_block(announcement);
    until(dispatcher, [&] { return !receiver.p2p.drops.empty(); },
          "Future block rejected and actual TCP connection dropped");
    const auto rejected = receiver.p2p.drops.front();
    require(!rejected.penalty, "Temporary future rejection does not add a host failure");
    require(rejected.height == 14 && rejected.tip == initialTip,
            "Rejected block did not advance receiver LMDB");
    require(!receiver.core.have_block(pendingHash), "Future block has not been accepted");
    const uint32_t localhost = Common::stringToIpAddress("127.0.0.1");
    require(NodeServerTestAccess::failureScore(receiver.p2p, localhost) == 0,
            "Actual receiver host-failure score remains zero");
    require(receiver.p2p.get_blocked_hosts().empty(), "Receiver did not ban local peer");

    const auto recoveryStart = Clock::now();
    clockOffset.store(0);
    // The production reconnect scheduler also uses wall time. Full restoration
    // avoids claiming that a runtime rollback necessarily retries at the earlier
    // 30-second consensus boundary; that boundary is tested in the handler suite.
    until(dispatcher, [&] { return receiver.core.get_tail_id() == pendingHash; },
          "Autonomous reconnect and get-objects sync after full clock restoration");
    const auto recoveryMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - recoveryStart).count();
    require(!NodeServerTestAccess::hasConnection(receiver.p2p, rejected.connection),
            "Recovery uses a new TCP connection after the rejected connection closed");
    require(receiver.p2p.get_connections_count() != 0, "Real TCP connection is established after recovery");
    require(receiver.core.getCurrentBlockchainHeight() == 15 &&
                receiver.core.get_tail_id() == source.core.get_tail_id(),
            "Both real LMDB chains agree after automatic retry");
    Block recovered;
    require(receiver.core.getBlockByHash(pendingHash, recovered), "Read recovered block from receiver LMDB");
    require(toBinaryArray(recovered) == raw, "Recovered block is byte-identical to originally rejected block");
    require(NodeServerTestAccess::failureScore(receiver.p2p, localhost) == 0 &&
                receiver.p2p.get_blocked_hosts().empty(),
            "Reconnect leaves host score and ban list unchanged");
    for (const auto& dropped : receiver.p2p.drops) {
      require(!dropped.penalty, "No retry penalizes the source peer");
    }
    receiver.stop();
    source.stop();
    std::cout << "[PASS] actual_tcp=1 initial_sync=1 future_rejected=1 host_failure_score=0"
              << " autonomous_reconnect=1 same_blob_sync=1 global_process_clock=1"
              << " clock_restored_fully=1 receiver_height=15 recovery_ms=" << recoveryMs
              << " block_hash=" << Common::podToHex(pendingHash)
              << " assertions=" << assertions << '\n';
    return 0;
  } catch (const std::exception& error) {
    clockOffset.store(0);
    std::cerr << "[FAIL] " << error.what() << " assertions=" << assertions << '\n';
    return 1;
  }
}
