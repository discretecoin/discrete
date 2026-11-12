// Copyright (c) 2026, The Discrete developers
//
// Serialized protocol-handler qualification with real Core, LMDB, ML-DSA and
// DiscretePower. The endpoint records disconnect policy; no sockets are opened.
// Build with --wrap=time. TIMESTAMP_LEGACY_BASELINE permits the same harness to
// compile against the pristine source without the activation-height API.

#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "Logging/StreamLogger.h"
#include "P2p/LevinProtocol.h"
#include "P2p/NetNodeCommon.h"
#include "System/Dispatcher.h"
#include "TestGenerator/TestGenerator.h"

#include <atomic>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <list>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr uint64_t BASE = 1800000000;
constexpr uint32_t ACTIVATION = 14;
std::atomic<time_t> wallTime{static_cast<time_t>(BASE)};
size_t assertions = 0;

void require(bool condition, const std::string& description) {
  ++assertions;
  if (!condition) throw std::runtime_error(description);
}

void setClock(uint64_t timestamp) {
  wallTime.store(static_cast<time_t>(timestamp));
  require(static_cast<uint64_t>(std::time(nullptr)) == timestamp,
          "Test-only time wrapper controls the process clock");
}

enum class Channel { Full, Lite, Objects };

const char* name(Channel channel) {
  switch (channel) {
    case Channel::Full: return "new_block";
    case Channel::Lite: return "new_lite_block";
    case Channel::Objects: return "response_get_objects";
  }
  throw std::runtime_error("Unknown channel");
}

struct RecordingEndpoint : CryptoNote::p2p_endpoint_stub {
  std::vector<bool> penalties;
  std::vector<int> outboundCommands;

  void drop_connection(CryptoNote::CryptoNoteConnectionContext& context,
                       bool addFail) override {
    penalties.push_back(addFail);
    context.m_state = CryptoNote::CryptoNoteConnectionContext::state_shutdown;
  }

  bool invoke_notify_to_peer(int command, const CryptoNote::BinaryArray&,
      const CryptoNote::CryptoNoteConnectionContext&) override {
    outboundCommands.push_back(command);
    return true;
  }

  void reset() {
    penalties.clear();
    outboundCommands.clear();
  }
};

CryptoNote::Currency makeCurrency(Logging::ILogger& logger, bool baseline) {
  CryptoNote::CurrencyBuilder builder(logger);
  builder.testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(11).upgradeHeightV6(12);
#ifndef TIMESTAMP_LEGACY_BASELINE
  if (!baseline) builder.monotonicTimestampHeight(ACTIVATION);
#else
  require(baseline, "Pristine build requires --baseline");
#endif
  return builder.currency();
}

struct Message {
  CryptoNote::BinaryArray encoded;
  Crypto::Hash hash;
  std::vector<Crypto::Hash> requestedHashes;
  uint32_t height;
  int command;
};

class Fixture {
public:
  Fixture(const std::filesystem::path& dataDirectory, Logging::ILogger& logger,
          bool baseline)
      : currency(makeCurrency(logger, baseline)),
        core(currency, nullptr, logger, dispatcher),
        protocol(currency, dispatcher, core, &endpoint, logger, 2),
        generator(currency) {
    require(!std::filesystem::exists(dataDirectory), "Fixture directory must be fresh");
    std::filesystem::create_directories(dataDirectory);
    setClock(BASE);
    CryptoNote::CoreConfig config;
    config.configFolder = dataDirectory.string();
    CryptoNote::MinerConfig minerConfig;
    require(core.init(config, minerConfig, false), "Core initialization");
    initialized = true;
    core.set_cryptonote_protocol(&protocol);
    generator.setBlockchain(&core.get_blockchain_storage());
    miner.generate();
    CryptoNote::Block genesis;
    require(core.getBlockByHash(core.getBlockIdByHeight(0), genesis), "Read genesis");
    std::vector<size_t> emptySizes;
    generator.addBlock(genesis, 0, 0, emptySizes, 0);
    require(core.getCurrentBlockchainHeight() == 1, "Fresh LMDB contains only genesis");
    require(currency.blockFutureTimeLimit(1) == 270, "Fixture future limit is 270 seconds");
  }

  ~Fixture() {
    protocol.stop();
    core.set_cryptonote_protocol(nullptr);
    if (initialized) core.deinit();
  }

  CryptoNote::Block block(uint64_t timestamp) {
    const uint32_t height = core.getCurrentBlockchainHeight();
    const Crypto::Hash parent = core.get_tail_id();
    uint64_t generated = 0;
    require(core.getAlreadyGeneratedCoins(parent, generated), "Read emission state");
    std::vector<size_t> sizes;
    require(core.getBackwardBlocksSizes(height - 1, sizes, currency.rewardBlocksWindow()),
            "Read reward window");
    generator.defaultMajorVersion = core.getBlockMajorVersionForHeight(height);
    CryptoNote::Block result;
    require(generator.constructBlock(result, height, parent, miner, timestamp,
                                     generated, sizes, std::list<CryptoNote::Transaction>{}),
            "Build signed block with real proof of work");
    const CryptoNote::Difficulty difficulty = core.getNextBlockDifficulty();
    if (difficulty > 1) {
      fillNonce(result, difficulty, &core.get_blockchain_storage(), miner);
      generator.addBlock(result, 0, 0, sizes, generated);
    }
    require(result.timestamp == timestamp, "Nonce search preserved requested timestamp");
    return result;
  }

  void append(uint64_t timestamp) {
    CryptoNote::Block next = block(timestamp);
    const uint32_t before = core.getCurrentBlockchainHeight();
    CryptoNote::block_verification_context verification{};
    core.handle_incoming_block(next, verification, false, false);
    require(verification.m_added_to_main_chain && !verification.m_verification_failed,
            "Warm-up block accepted by real Core");
    require(core.getCurrentBlockchainHeight() == before + 1, "Warm-up height advanced once");
  }

  Message encode(Channel channel, const CryptoNote::Block& block) {
    const auto blob = CryptoNote::toBinaryArray(block);
    const std::string binary(reinterpret_cast<const char*>(blob.data()), blob.size());
    Message message{};
    message.hash = CryptoNote::get_block_hash(block);
    message.requestedHashes.push_back(message.hash);
    message.height = CryptoNote::get_block_height(block);
    switch (channel) {
      case Channel::Full: {
        CryptoNote::NOTIFY_NEW_BLOCK::request request{};
        request.b.block = binary;
        request.current_blockchain_height = message.height + 1;
        message.command = CryptoNote::NOTIFY_NEW_BLOCK::ID;
        message.encoded = CryptoNote::LevinProtocol::encode(request);
        break;
      }
      case Channel::Lite: {
        CryptoNote::NOTIFY_NEW_LITE_BLOCK::request request{};
        request.block = binary;
        request.current_blockchain_height = message.height + 1;
        message.command = CryptoNote::NOTIFY_NEW_LITE_BLOCK::ID;
        message.encoded = CryptoNote::LevinProtocol::encode(request);
        break;
      }
      case Channel::Objects: {
        CryptoNote::NOTIFY_RESPONSE_GET_OBJECTS::request request{};
        CryptoNote::block_complete_entry entry;
        entry.block = binary;
        request.blocks.push_back(entry);
        request.current_blockchain_height = message.height + 1;
        message.command = CryptoNote::NOTIFY_RESPONSE_GET_OBJECTS::ID;
        message.encoded = CryptoNote::LevinProtocol::encode(request);
        break;
      }
    }
    require(!message.encoded.empty(), "Levin notification encoded");
    return message;
  }

  Message encodeProofFailureBatch(const CryptoNote::Block& badProof,
                                  const CryptoNote::Block& otherBlock) {
    Message message = encode(Channel::Objects, badProof);
    const auto otherHash = CryptoNote::get_block_hash(otherBlock);
    require(otherHash != message.hash, "Parallel proof fixture has two distinct requested objects");
    CryptoNote::NOTIFY_RESPONSE_GET_OBJECTS::request request{};
    require(CryptoNote::LevinProtocol::decode(message.encoded, request), "Decode batch fixture");
    const auto blob = CryptoNote::toBinaryArray(otherBlock);
    CryptoNote::block_complete_entry entry;
    entry.block.assign(reinterpret_cast<const char*>(blob.data()), blob.size());
    request.blocks.push_back(entry);
    message.requestedHashes.push_back(otherHash);
    message.encoded = CryptoNote::LevinProtocol::encode(request);
    return message;
  }

  CryptoNote::CryptoNoteConnectionContext send(Channel channel, const Message& message,
                                               bool requested = true) {
    endpoint.reset();
    CryptoNote::CryptoNoteConnectionContext connection{};
    connection.m_connection_id.data[15] = ++connectionNumber;
    connection.m_remote_ip = 0x0100007f;
    connection.m_remote_port = 18080 + connectionNumber;
    connection.m_remote_blockchain_height = message.height + 1;
    connection.m_last_response_height = message.height;
    connection.m_state = channel == Channel::Objects
        ? CryptoNote::CryptoNoteConnectionContext::state_synchronizing
        : CryptoNote::CryptoNoteConnectionContext::state_normal;
    if (channel == Channel::Objects && requested) {
      connection.m_requested_objects.insert(message.requestedHashes.begin(), message.requestedHashes.end());
    }
    CryptoNote::BinaryArray output;
    bool handled = false;
    require(protocol.handleCommand(true, message.command, message.encoded,
                                   output, connection, handled) == 1,
            "Real protocol handler returned notification success code");
    require(handled, "Notification was decoded and dispatched");
    return connection;
  }

  void rejected(Channel channel, const Message& message, bool penalty,
                const std::string& label) {
    const auto beforeHeight = core.getCurrentBlockchainHeight();
    const auto beforeTip = core.get_tail_id();
    const auto connection = send(channel, message);
    require(endpoint.penalties.size() == 1, label + ": exactly one endpoint drop");
    require(endpoint.penalties.front() == penalty, label + ": expected add_fail policy");
    require(connection.m_state == CryptoNote::CryptoNoteConnectionContext::state_shutdown,
            label + ": dropped connection shut down");
    require(core.getCurrentBlockchainHeight() == beforeHeight && core.get_tail_id() == beforeTip,
            label + ": chain unchanged");
    require(!core.have_block(message.hash), label + ": rejected block not stored as accepted");
  }

  void accepted(Channel channel, const Message& message, bool duplicate = false) {
    const auto before = core.getCurrentBlockchainHeight();
    send(channel, message);
    require(endpoint.penalties.empty(), "Accepted block must not disconnect peer");
    require(core.getCurrentBlockchainHeight() == before + (duplicate ? 0 : 1),
            "Accepted block advances height exactly once; duplicate is idempotent");
    require(core.get_tail_id() == message.hash && core.have_block(message.hash),
            "Accepted hash is the actual stored tip");
  }

  CryptoNote::Currency currency;
  System::Dispatcher dispatcher;
  CryptoNote::Core core;
  RecordingEndpoint endpoint;
  CryptoNote::CryptoNoteProtocolHandler protocol;
  test_generator generator;
  CryptoNote::AccountBase miner;
  bool initialized = false;
  uint8_t connectionNumber = 0;
};

void runChannel(const std::filesystem::path& root, Logging::ILogger& logger,
                Channel channel, bool baseline, bool expectFuturePenalty) {
  Fixture fixture(root / name(channel), logger, baseline);
  // Height 12 is BASE-90, height 13 is BASE. Height 14 activates the rule.
  for (uint32_t height = 1; height <= 12; ++height) {
    fixture.append(BASE - (13 - height) * 90);
  }

  const auto beforeActivation = fixture.encode(channel, fixture.block(BASE));
  setClock(BASE - 300);
  fixture.rejected(channel, beforeActivation, true, "Pre-activation future timestamp");
  setClock(BASE);
  fixture.accepted(channel, beforeActivation);

  const auto child = fixture.block(BASE);
  const auto future = fixture.encode(channel, child);
  if (!baseline) {
    const auto badFloor = fixture.encode(channel, fixture.block(BASE - 1));
    fixture.rejected(channel, badFloor, true, "Permanent floor violation after clock restoration");
    setClock(BASE - 300);
    fixture.rejected(channel, badFloor, true, "Future timestamp does not mask permanent floor violation");
    setClock(BASE);
  }

  CryptoNote::Block badProof = child;
  require(!badProof.signature.empty(), "Candidate has ML-DSA proof signature");
  badProof.signature[0] ^= 1;
  const auto badProofMessage = fixture.encode(channel, badProof);
  setClock(BASE - 300);
  // A single-block path checks the timestamp before the signature. This flag
  // means rejection at the local future gate, not proof of full block validity.
  fixture.rejected(channel, badProofMessage, expectFuturePenalty,
                   "Future gate defers later malformed-signature rejection");
  if (channel == Channel::Objects) {
    // A two-object response enables the real parallel proof pipeline. Its first
    // malformed proof fails before Core reaches the timestamp gate. The second
    // competing object only engages that pipeline; neither may be appended.
    fixture.rejected(channel, fixture.encodeProofFailureBatch(badProof, child), true,
                     "Parallel sync rejects malformed signature before the future gate");
  }
  setClock(BASE);
  fixture.rejected(channel, badProofMessage, true,
                   "Permanent malformed proof at valid wall time");

  if (channel == Channel::Objects) {
    const auto oldHeight = fixture.core.getCurrentBlockchainHeight();
    const auto oldTip = fixture.core.get_tail_id();
    const auto unsolicited = fixture.send(channel, future, false);
    require(unsolicited.m_state == CryptoNote::CryptoNoteConnectionContext::state_shutdown,
            "Unrequested object remains a protocol violation");
    require(fixture.core.getCurrentBlockchainHeight() == oldHeight && fixture.core.get_tail_id() == oldTip,
            "Unrequested object does not enter Core");
  }

  setClock(BASE - 300);
  fixture.rejected(channel, future, expectFuturePenalty, "Post-activation future-only rejection");
  setClock(BASE);
  // The exact serialized bytes are reused. send() models a new connection and
  // requested-object state, not a new block or an in-memory acceptance shortcut.
  fixture.accepted(channel, future);
  fixture.accepted(channel, future, true);

  const auto equalTimeChild = fixture.encode(channel, fixture.block(BASE));
  setClock(BASE - 300);
  fixture.rejected(channel, equalTimeChild, expectFuturePenalty, "Equal-time child after 300-second rollback");
  setClock(BASE - 271);
  fixture.rejected(channel, equalTimeChild, expectFuturePenalty, "Still future-only at 29-second recovery");
  setClock(BASE - 270);
  fixture.accepted(channel, equalTimeChild);
  fixture.accepted(channel, equalTimeChild, true);
  setClock(BASE);

  std::cout << (baseline ? "[OBSERVED LEGACY] " : expectFuturePenalty ? "[OBSERVED FLOOR ONLY] " : "[PASS] ")
            << name(channel)
            << " preactivation_add_fail=1 future_add_fail=" << (expectFuturePenalty ? 1 : 0)
            << " permanent_signature_add_fail=1"
            << " future_signature_add_fail=" << (expectFuturePenalty ? 1 : 0)
            << " parallel_signature_checked=" << (channel == Channel::Objects ? 1 : 0)
            << " permanent_floor_checked=" << (baseline ? 0 : 1)
            << " same_blob_retry=accepted duplicate=idempotent"
            << " rollback_seconds=300 wait_boundary_seconds=30"
            << " final_height=" << fixture.core.getCurrentBlockchainHeight() << '\n';
}

} // namespace

extern "C" time_t __wrap_time(time_t* destination) {
  const time_t now = wallTime.load();
  if (destination) *destination = now;
  return now;
}

int main(int argc, char** argv) {
  try {
    bool baseline = false;
    bool expectFuturePenalty = false;
    std::filesystem::path dataRoot;
    for (int i = 1; i < argc; ++i) {
      const std::string argument = argv[i];
      if (argument == "--baseline") baseline = true;
      else if (argument == "--expect-future-penalty") expectFuturePenalty = true;
      else if (argument == "--data-dir" && i + 1 < argc) dataRoot = argv[++i];
      else throw std::runtime_error("Usage: TimestampProtocolTests --data-dir FRESH_DIRECTORY [--baseline] [--expect-future-penalty]");
    }
    require(!dataRoot.empty(), "Explicit --data-dir is required");
    require(!std::filesystem::exists(dataRoot), "Data root must not exist; no prior evidence is deleted");
    std::filesystem::create_directories(dataRoot);
    std::ofstream log(dataRoot / "protocol.log");
    require(log.good(), "Open protocol evidence log");
    Logging::StreamLogger logger(log, Logging::DEBUGGING);
    expectFuturePenalty = expectFuturePenalty || baseline;
    for (const auto channel : {Channel::Full, Channel::Lite, Channel::Objects}) {
      runChannel(dataRoot, logger, channel, baseline, expectFuturePenalty);
    }
    std::cout << "[PASS] assertions=" << assertions
              << " mode=" << (baseline ? "legacy_observation" : expectFuturePenalty ? "floor_only_observation" : "candidate")
              << " transport=serialized_handler_with_recording_endpoint no_tcp=1\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "[FAIL] " << error.what() << " assertions=" << assertions << '\n';
    return 1;
  }
}
