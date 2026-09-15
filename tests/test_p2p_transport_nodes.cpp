// Real Core, LMDB, protocol handler and NodeServer over loopback TCP.
// Run in an isolated network namespace; the fixture never uses public seeds.
#include <CryptoNoteCore/Account.h>
#include <CryptoNoteCore/Core.h>
#include <CryptoNoteCore/CoreConfig.h>
#include <CryptoNoteCore/Currency.h>
#include <CryptoNoteCore/MinerConfig.h>
#include <CryptoNoteCore/CryptoNoteTools.h>
#include <CryptoNoteCore/CryptoNoteFormatUtils.h>
#include <CryptoNoteProtocol/CryptoNoteProtocolHandler.h>
#include <P2p/NetNode.h>
#include <Common/StringTools.h>
#include <Logging/StreamLogger.h>
#include <System/Context.h>
#include <System/Timer.h>
#include "TestGenerator/TestGenerator.h"
#include <Wallet/PqTransactionBuilder.h>
#include <crypto_pq/PqOutputBuilder.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <list>

using namespace CryptoNote;

namespace CryptoNote {
class NodeServerTestAccess {
public:
  static bool grayPeerlistHousekeeping(NodeServer& node) { return node.gray_peerlist_housekeeping(); }
  static bool isAddressConnected(const NodeServer& node, const NetworkAddress& address) { return node.is_addr_connected(address); }
};
}

namespace {
using Clock = std::chrono::steady_clock;
void check(bool ok, const std::string& message) { if (!ok) throw std::runtime_error(message); }
double elapsed(Clock::time_point start) { return std::chrono::duration<double, std::milli>(Clock::now() - start).count(); }

template<class Condition>
void until(System::Dispatcher& dispatcher, Condition condition, const std::string& message, int seconds = 30) {
  const auto start = Clock::now();
  while (!condition()) {
    check(elapsed(start) < seconds * 1000, message);
    System::Timer(dispatcher).sleep(std::chrono::milliseconds(2));
  }
}

struct Node {
  System::Dispatcher& dispatcher;
  Core core;
  CryptoNoteProtocolHandler protocol;
  NodeServer p2p;
  std::unique_ptr<System::Context<>> service;
  bool initialized = false;

  Node(System::Dispatcher& d, const Currency& currency, Logging::ILogger& log,
       const std::string& directory, uint16_t port, uint16_t peerPort, const std::string& mode,
       const std::string& route = "exclusive", uint32_t connections = 1)
    : dispatcher(d), core(currency, nullptr, log, d), protocol(currency, d, core, nullptr, log, 1), p2p(d, protocol, log) {
    std::filesystem::create_directories(directory);
    protocol.set_p2p_endpoint(&p2p); core.set_cryptonote_protocol(&protocol);
    NetNodeConfig config;
    config.setTestnet(true); config.setBindIp("192.0.2.1"); config.setBindPort(port);
    config.setConfigFolder(directory); config.setP2pStateFilename("p2pstate.bin");
    config.setAllowLocalIp(true); config.setConnectionsCount(connections);
    const NetworkAddress peer{Common::stringToIpAddress("192.0.2.1"), peerPort};
    if (route == "priority") config.setPriorityNodes({peer});
    else if (route == "seed") config.setSeedNodes({peer});
    else if (route == "peer") {
      PeerlistEntry entry{}; entry.adr = peer; entry.id = peerPort;
      entry.last_seen = static_cast<uint64_t>(std::time(nullptr));
      config.setPeers({entry});
    } else if (route == "exclusive") config.setExclusiveNodes({peer});
    else check(route == "none", "Invalid peer route");
#ifndef P2P_TRANSPORT_BASELINE
    P2pTransportConfig transport; transport.mode = P2pTransportConfig::parseMode(mode);
    config.setTransportConfig(transport);
#else
    check(mode == "off", "Baseline only supports off");
#endif
    check(p2p.init(config), "NodeServer initialization");
    CoreConfig coreConfig; coreConfig.configFolder = directory;
    check(core.init(coreConfig, MinerConfig{}, false), "Core initialization");
    initialized = true;
  }
  void start() { service.reset(new System::Context<>(dispatcher, [&] { check(p2p.run(), "NodeServer run"); })); }
  void stop() {
    if (service) { p2p.sendStopSignal(); service->get(); service.reset(); }
    if (initialized) { check(p2p.deinit(), "Peer state persistence"); check(core.deinit(), "Core shutdown"); initialized = false; }
  }
  ~Node() { try { stop(); } catch (...) {} }
};

int connectionCapFixture(const std::filesystem::path& base, const std::string& mode) {
  check(!std::filesystem::exists(base), "Connection-cap fixture directory must not already exist");
  std::filesystem::create_directories(base);
  std::ofstream logFile(base / "nodes.log");
  Logging::StreamLogger logger(logFile, Logging::DEBUGGING);
  System::Dispatcher dispatcher;
  const auto currency = CurrencyBuilder(logger).testnet(true)
    .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1).upgradeHeightV5(11).upgradeHeightV6(12).currency();

  Node first(dispatcher, currency, logger, (base / "first").string(), 39300, 1, mode, "none", 0);
  Node promoted(dispatcher, currency, logger, (base / "promoted").string(), 39301, 1, mode, "none", 0);
  Node client(dispatcher, currency, logger, (base / "client").string(), 39302, 39300, mode, "peer", 1);
  first.start(); promoted.start(); client.start();
  until(dispatcher, [&] { return client.p2p.get_outgoing_connections_count() == 1; }, "Initial ordinary outgoing connection");
  const NetworkAddress firstAddress{Common::stringToIpAddress("192.0.2.1"), 39300};
  check(NodeServerTestAccess::isAddressConnected(client.p2p, firstAddress), "Initial ordinary peer is connected");

  std::list<AnchorPeerlistEntry> anchors;
  std::vector<PeerlistEntry> gray;
  std::vector<PeerlistEntry> white;
  check(client.p2p.getPeerlistManager().get_peerlist_full(anchors, gray, white), "Read initial peer lists");
  for (auto entry : gray) check(client.p2p.getPeerlistManager().remove_from_peer_gray(entry), "Clear handshake-discovered gray peer");

  PeerlistEntry candidate{};
  candidate.adr = NetworkAddress{Common::stringToIpAddress("192.0.2.1"), 39301};
  candidate.id = 39301; candidate.last_seen = static_cast<uint64_t>(std::time(nullptr));
  check(client.p2p.getPeerlistManager().append_with_peer_gray(candidate), "Add gray housekeeping candidate");
  check(client.p2p.getPeerlistManager().get_gray_peers_count() == 1, "Gray candidate retained before housekeeping");
  check(NodeServerTestAccess::grayPeerlistHousekeeping(client.p2p), "Successful gray housekeeping");
  const auto afterHousekeeping = client.p2p.get_outgoing_connections_count();
  check(afterHousekeeping == 1, "Housekeeping exceeded configured outgoing count: expected 1, got " + std::to_string(afterHousekeeping));
  check(client.protocol.getPeerCount() == 1, "Transient housekeeping leaked the protocol peer count");

  anchors.clear(); gray.clear(); white.clear();
  check(client.p2p.getPeerlistManager().get_peerlist_full(anchors, gray, white), "Read promoted peer lists");
  const auto hasAddress = [&](const auto& entries, const NetworkAddress& address) {
    return std::any_of(entries.begin(), entries.end(), [&](const auto& entry) { return entry.adr == address; });
  };
  check(!hasAddress(gray, candidate.adr), "Successful housekeeping removes candidate from gray list");
  check(hasAddress(white, candidate.adr), "Successful housekeeping promotes candidate to white list");
  check(hasAddress(anchors, candidate.adr), "Successful housekeeping preserves anchor promotion");

  anchors.clear(); gray.clear(); white.clear();
  check(client.p2p.getPeerlistManager().get_peerlist_full(anchors, gray, white), "Read post-housekeeping peer lists");
  for (auto entry : gray) check(client.p2p.getPeerlistManager().remove_from_peer_gray(entry), "Clear handshake-discovered gray peer before retry test");

  PeerlistEntry retry{};
  retry.adr = NetworkAddress{Common::stringToIpAddress("192.0.2.1"), 39303};
  retry.id = 39303; retry.last_seen = static_cast<uint64_t>(std::time(nullptr));
  check(client.p2p.getPeerlistManager().append_with_peer_gray(retry), "Add retry candidate");
  check(client.p2p.getPeerlistManager().get_gray_peers_count() == 1, "Retry candidate is the sole gray peer");
  check(NodeServerTestAccess::grayPeerlistHousekeeping(client.p2p), "Failed recent gray housekeeping attempt");
  check(client.p2p.getPeerlistManager().get_gray_peers_count() == 1, "Recent failed gray peer remains retryable");
  check(client.p2p.get_outgoing_connections_count() == 1, "Failed housekeeping changed outgoing count");

  check(client.p2p.getPeerlistManager().get_gray_peer_by_index(retry, 0), "Read retry candidate");
  check(client.p2p.getPeerlistManager().remove_from_peer_gray(retry), "Remove retry candidate for aging");
  retry.last_seen = static_cast<uint64_t>(std::time(nullptr) - 11 * 24 * 60 * 60);
  check(client.p2p.getPeerlistManager().append_with_peer_gray(retry), "Age retry candidate");
  check(NodeServerTestAccess::grayPeerlistHousekeeping(client.p2p), "Failed stale gray housekeeping attempt");
  check(client.p2p.getPeerlistManager().get_gray_peers_count() == 0, "Stale failed gray peer evicted");

  first.stop();
  until(dispatcher, [&] { return NodeServerTestAccess::isAddressConnected(client.p2p, candidate.adr); }, "Promoted peer replaces closed ordinary connection");
  check(!NodeServerTestAccess::isAddressConnected(client.p2p, firstAddress), "Closed ordinary peer is no longer connected");
  check(client.p2p.get_outgoing_connections_count() == 1, "Connection churn preserves configured outgoing count");
  client.stop(); promoted.stop();
  std::cout << "{\"configured\":1,\"after_housekeeping\":" << afterHousekeeping
    << ",\"promotion\":true,\"retry\":true,\"eviction\":true,\"churn\":true,\"passed\":true}\n";
  return 0;
}

void mine(Node& node, const Currency& currency, test_generator& generator, const AccountBase& miner,
          uint64_t timestamp, const std::list<Transaction>& txs = {}, bool relay = false) {
  auto& core = node.core;
  const auto height = core.getCurrentBlockchainHeight();
  const auto tail = core.get_tail_id();
  uint64_t generated = 0;
  check(core.getAlreadyGeneratedCoins(tail, generated), "generated coins");
  std::vector<size_t> sizes;
  check(core.getBackwardBlocksSizes(height - 1, sizes, currency.rewardBlocksWindow()), "block sizes");
  generator.defaultMajorVersion = core.getBlockMajorVersionForHeight(height);
  Block block;
  check(generator.constructBlock(block, height, tail, miner, timestamp, generated, sizes, txs), "construct block");
  if (core.getNextBlockDifficulty() > 1) fillNonce(block, core.getNextBlockDifficulty(), &core.get_blockchain_storage(), miner);
  generator.addBlock(block, 0, 0, sizes, generated);
  block_verification_context result{};
  core.handle_incoming_block(block, result, false, relay);
  check(result.m_added_to_main_chain && !result.m_verification_failed, "block accepted by source Core");
}

bool inPool(Core& core, const Crypto::Hash& hash) {
  for (const auto& entry : core.getMemoryPool()) if (entry.id == hash) return true;
  return false;
}
}

// Separate processes let the same fixture pair an unchanged baseline P2P stack
// with the candidate, in both directions. Coordination files contain only public
// synthetic block/transaction hashes and never replace P2P delivery.
int processFixture(int argc, char** argv) {
  check(argc >= 6, "Usage: --process shared-directory server|client mode frozen-chain [route]");
  const std::filesystem::path base(argv[2]);
  const bool serving = std::string(argv[3]) == "server";
  check(serving || std::string(argv[3]) == "client", "Invalid fixture role");
  std::filesystem::create_directories(base);
  std::ofstream logFile(base / (serving ? "server.log" : "client.log"));
  Logging::StreamLogger logger(logFile, Logging::DEBUGGING);
  System::Dispatcher dispatcher;
  const auto currency = CurrencyBuilder(logger).testnet(true)
    .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1).upgradeHeightV5(11).upgradeHeightV6(12).currency();
  auto publish = [&](const std::string& name, const std::string& value = "ok") {
    const auto temp = base / (name + ".tmp");
    { std::ofstream output(temp); output << value << '\n'; check(static_cast<bool>(output), "Write fixture signal"); }
    std::filesystem::rename(temp, base / name);
  };
  auto receive = [&](const std::string& name) {
    until(dispatcher, [&] { return std::filesystem::exists(base / name); }, "Missing signal: " + name);
    std::ifstream input(base / name); std::string value;
    check(static_cast<bool>(std::getline(input, value)), "Read fixture signal"); return value;
  };
  auto readHash = [&](const std::string& name) { Crypto::Hash hash{}; check(Common::podFromHex(receive(name), hash), "Signal hash"); return hash; };
  if (serving) {
    Node source(dispatcher, currency, logger, (base / "server").string(), 39280, 1, argv[4]);
    test_generator generator(currency); generator.setBlockchain(&source.core.get_blockchain_storage());
    Block genesis; check(source.core.getBlockByHash(source.core.getBlockIdByHeight(0), genesis), "genesis");
    std::vector<size_t> genesisSizes;
    generator.addBlock(genesis, 0, 0, genesisSizes, 0);
    std::ifstream snapshot(argv[5]); std::string line;
    check(static_cast<bool>(std::getline(snapshot, line)), "Frozen timestamp");
    uint64_t timestamp = std::stoull(line);
    for (int i = 0; i < 13; ++i) {
      check(static_cast<bool>(std::getline(snapshot, line)), "Frozen block");
      block_verification_context result{};
      source.core.handle_incoming_block_blob(Common::fromHex(line), result, false, false);
      check(result.m_added_to_main_chain && !result.m_verification_failed, "Frozen block accepted");
    }
    // A seed advertises a distinct usable peer. An empty two-node seed topology
    // cannot discover anybody: the legacy seed path only requests a peerlist.
    Node seed(dispatcher, currency, logger, (base / "seed").string(), 39279, 1, argv[4]);
    PeerlistEntry advertised{};
    advertised.adr = NetworkAddress{Common::stringToIpAddress("192.0.2.1"), 39280};
    advertised.id = 42; advertised.last_seen = static_cast<uint64_t>(std::time(nullptr));
    check(seed.p2p.getPeerlistManager().append_with_peer_white(advertised), "Seed advertises the local source");
    source.start(); seed.start(); publish("ready", Common::podToHex(source.core.get_tail_id())); receive("synced");
    check(source.p2p.getPeerlistManager().get_white_peers_count() != 0, "Cross-version reverse ping promotion");
    AccountBase miner; AccountKeys fixtureKeys{};
    for (size_t i = 0; i < sizeof(fixtureKeys.spendSecretKey.data); ++i) fixtureKeys.spendSecretKey.data[i] = static_cast<uint8_t>(17 + i * 3);
    miner.setAccountKeys(fixtureKeys);
    Block coinbase; check(source.core.getBlockByHash(source.core.getBlockIdByHeight(1), coinbase), "Funded coinbase");
    PqSpendInput input; input.prevTxid = getObjectHash(coinbase.baseTransaction); input.prevOutIndex = 0;
    input.amount = coinbase.baseTransaction.outputs.at(0).amount; input.rho = CryptoPQ::coinbaseRho(miner.pqSpendPk(), 1, 0);
    AccountBase recipient; recipient.generate();
    const auto tx = buildPqTransaction({input}, {PqSendOutput{recipient.pqViewPk(), recipient.pqSpendPk(), input.amount - 50}}, miner.pqSpendPk(), miner.pqSpendSk());
    const auto hash = getObjectHash(tx); const auto blob = toBinaryArray(tx);
    tx_verification_context tvc{};
    source.core.handleIncomingTransaction(tx, hash, blob.size(), tvc, false, source.core.getCurrentBlockchainHeight());
    check(tvc.m_added_to_pool && !tvc.m_verification_failed, "Funded transaction accepted");
    publish("transaction", Common::podToHex(hash));
    NOTIFY_NEW_TRANSACTIONS::request relay; relay.txs.push_back(Common::asString(blob)); relay.stem = false;
    source.core.get_protocol()->relay_transactions(relay); receive("tx-seen");
    generator.setTxFee(hash, 50); mine(source, currency, generator, miner, timestamp, {tx}, true);
    publish("block", Common::podToHex(source.core.get_tail_id())); receive("block-seen"); receive("client-stopped");
    timestamp += currency.difficultyTarget() * 10; mine(source, currency, generator, miner, timestamp);
    publish("reconnect", Common::podToHex(source.core.get_tail_id())); receive("done"); seed.stop(); source.stop();
  } else {
    const auto initial = readHash("ready");
    const std::string route = argc > 6 ? argv[6] : "exclusive";
    auto node = std::make_unique<Node>(dispatcher, currency, logger, (base / "client").string(), 39281, route == "seed" ? 39279 : 39280, argv[4], route);
    node->start(); until(dispatcher, [&] { return node->core.get_tail_id() == initial; }, "Cross-version initial sync"); publish("synced");
    const auto tx = readHash("transaction");
    until(dispatcher, [&] { return inPool(node->core, tx); }, "Cross-version transaction relay"); publish("tx-seen");
    const auto block = readHash("block");
    until(dispatcher, [&] { return node->core.get_tail_id() == block; }, "Cross-version block relay");
    check(!inPool(node->core, tx), "Confirmed transaction left pool"); publish("block-seen");
    node->stop(); node.reset(); publish("client-stopped");
    const auto tail = readHash("reconnect");
    node = std::make_unique<Node>(dispatcher, currency, logger, (base / "client").string(), 39281, 39279, argv[4], "seed");
    node->start(); until(dispatcher, [&] { return node->core.get_tail_id() == tail; }, "Persisted peer reconnect and sync");
    check(node->core.getCurrentBlockchainHeight() == 16, "Cross-version height");
    node->stop(); node.reset(); publish("done");
  }
  std::cout << "{\"role\":\"" << argv[3] << "\",\"mode\":\"" << argv[4] << "\",\"height\":16,\"passed\":true}\n";
  return 0;
}
int main(int argc, char** argv) {
  try {
    if (argc > 1 && std::string(argv[1]) == "--process") return processFixture(argc, argv);
    if (argc > 1 && std::string(argv[1]) == "--connection-cap") {
      check(argc == 4, "Usage: P2pTransportNodeTests --connection-cap directory mode");
      return connectionCapFixture(argv[2], argv[3]);
    }
    check(argc >= 4, "Usage: P2pTransportNodeTests new-directory source-mode sink-mode [exclusive|priority]");
    const std::filesystem::path base(argv[1]);
    check(!std::filesystem::exists(base), "Fixture directory must not already exist");
    std::filesystem::create_directories(base);
    std::ofstream logFile(base / "nodes.log");
    Logging::StreamLogger logger(logFile, Logging::DEBUGGING);
    System::Dispatcher dispatcher;
    const auto currency = CurrencyBuilder(logger).testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1).upgradeHeightV5(11).upgradeHeightV6(12).currency();
    Node source(dispatcher, currency, logger, (base / "source").string(), 39280, 1, argv[2]);
    test_generator generator(currency); generator.setBlockchain(&source.core.get_blockchain_storage());
    // Public deterministic fixture seed; never use this account outside tests.
    AccountBase miner;
    AccountKeys fixtureKeys{};
    for (size_t i = 0; i < sizeof(fixtureKeys.spendSecretKey.data); ++i) fixtureKeys.spendSecretKey.data[i] = static_cast<uint8_t>(17 + i * 3);
    miner.setAccountKeys(fixtureKeys);
    Block genesis;
    check(source.core.getBlockByHash(source.core.getBlockIdByHeight(0), genesis), "load genesis");
    std::vector<size_t> genesisSizes;
    generator.addBlock(genesis, 0, 0, genesisSizes, 0);
    uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr)) - 86400;
    const std::string snapshotPath = argc > 5 ? argv[5] : "";
    if (!snapshotPath.empty() && std::filesystem::exists(snapshotPath)) {
      check(std::filesystem::file_size(snapshotPath) < 4 * 1024 * 1024, "Fixture snapshot too large");
      std::ifstream snapshot(snapshotPath);
      std::string line;
      check(static_cast<bool>(std::getline(snapshot, line)), "Fixture timestamp missing");
      timestamp = std::stoull(line);
      for (int i = 0; i < 13; ++i) {
        check(static_cast<bool>(std::getline(snapshot, line)), "Fixture block missing");
        block_verification_context bvc{};
        source.core.handle_incoming_block_blob(Common::fromHex(line), bvc, false, false);
        check(bvc.m_added_to_main_chain && !bvc.m_verification_failed, "Frozen fixture block rejected");
      }
      check(!std::getline(snapshot, line), "Unexpected fixture data");
    } else {
      for (int i = 0; i < 13; ++i) { mine(source, currency, generator, miner, timestamp); timestamp += currency.difficultyTarget() * 10; }
      if (!snapshotPath.empty()) {
        std::ofstream snapshot(snapshotPath);
        snapshot << timestamp << '\n';
        for (uint32_t height = 1; height <= 13; ++height) {
          Block block; check(source.core.getBlockByHash(source.core.getBlockIdByHeight(height), block), "Export fixture block");
          snapshot << Common::toHex(toBinaryArray(block)) << '\n';
        }
        check(static_cast<bool>(snapshot), "Persist fixture snapshot");
      }
    }
    const auto initialTail = source.core.get_tail_id();
    source.start();
    auto sink = std::make_unique<Node>(dispatcher, currency, logger, (base / "sink").string(), 39281, 39280, argv[3], argc > 4 ? argv[4] : "exclusive");
    const auto syncStart = Clock::now(); sink->start();
    until(dispatcher, [&] { return sink->core.get_tail_id() == initialTail; }, "Initial sync failed");
    const auto syncMs = elapsed(syncStart);
    until(dispatcher, [&] { return source.protocol.getPeerCount() != 0 && sink->protocol.getPeerCount() != 0; }, "Application handshake incomplete");
    check(source.p2p.getPeerlistManager().get_white_peers_count() != 0, "Reverse ping did not promote the reachable peer");

    Block coinbase;
    check(source.core.getBlockByHash(source.core.getBlockIdByHeight(1), coinbase), "load funded coinbase");
    PqSpendInput input;
    input.prevTxid = getObjectHash(coinbase.baseTransaction); input.prevOutIndex = 0;
    input.amount = coinbase.baseTransaction.outputs.at(0).amount;
    input.rho = CryptoPQ::coinbaseRho(miner.pqSpendPk(), 1, 0);
    AccountBase recipient; recipient.generate();
    const auto tx = buildPqTransaction({input}, {PqSendOutput{recipient.pqViewPk(), recipient.pqSpendPk(), input.amount - 50}}, miner.pqSpendPk(), miner.pqSpendSk());
    const auto hash = getObjectHash(tx); const auto blob = toBinaryArray(tx);
    tx_verification_context tvc{};
    source.core.handleIncomingTransaction(tx, hash, blob.size(), tvc, false, source.core.getCurrentBlockchainHeight());
    check(tvc.m_added_to_pool && !tvc.m_verification_failed, "Funded PQ transaction acceptance");
    NOTIFY_NEW_TRANSACTIONS::request relay;
    relay.txs.push_back(Common::asString(blob)); relay.stem = false;
    const auto relayStart = Clock::now();
    source.core.get_protocol()->relay_transactions(relay);
    until(dispatcher, [&] { return inPool(sink->core, hash); }, "PQ transaction relay failed");
    const auto txMs = elapsed(relayStart);
    const auto blockStart = Clock::now();
    generator.setTxFee(hash, 50);
    mine(source, currency, generator, miner, timestamp, {tx}, true); timestamp += currency.difficultyTarget() * 10;
    until(dispatcher, [&] { return sink->core.get_tail_id() == source.core.get_tail_id(); }, "Block relay failed");
    const auto blockMs = elapsed(blockStart);
    check(!inPool(sink->core, hash), "Confirmed transaction removed from pool");
    sink->stop(); sink.reset();
    mine(source, currency, generator, miner, timestamp, {}, false);
    sink = std::make_unique<Node>(dispatcher, currency, logger, (base / "sink").string(), 39281, 39280, argv[3]);
    const auto reconnectStart = Clock::now(); sink->start();
    until(dispatcher, [&] { return sink->core.get_tail_id() == source.core.get_tail_id(); }, "Reconnect and catch-up failed");
    const auto reconnectMs = elapsed(reconnectStart);
    check(sink->core.getCurrentBlockchainHeight() == 16, "Final height mismatch");
    sink->stop(); sink.reset(); source.stop();
    std::cout << "{\"initial_sync_ms\":" << syncMs << ",\"transaction_relay_ms\":" << txMs
      << ",\"block_relay_ms\":" << blockMs << ",\"reconnect_ms\":" << reconnectMs
      << ",\"initial_tail\":\"" << Common::podToHex(initialTail) << "\",\"height\":16,\"source_mode\":\"" << argv[2] << "\",\"sink_mode\":\"" << argv[3] << "\",\"passed\":true}\n";
    return 0;
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
