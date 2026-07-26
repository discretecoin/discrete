// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Discrete is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Discrete is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Discrete.  If not, see <http://www.gnu.org/licenses/>.

#include "CheckpointsDnsFetch.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "CheckpointDownloader.h"
#include "DnsCheckpoint.h"
#include "Common/DnsTools.h"
#include "Common/StringTools.h"
#include "CryptoNoteConfig.h"
#include "Logging/LoggerRef.h"
#include "PqAddress.h"
#include "System/Dispatcher.h"

// <windows.h> (pulled in transitively by the TLS/socket stack) defines ERROR as
// a macro, which collides with Logging::ERROR.
#undef ERROR

namespace CryptoNote {

namespace {

// Overall wall-clock budget for DNS + TLS + download + verify. Neither the DNS
// resolver nor the TLS/HTTP stack enforces a deadline of its own, so without
// this a silent web server (one that completes the TCP handshake and then never
// speaks) would stall node startup indefinitely.
constexpr std::chrono::seconds kDnsCheckpointDeadline{5};

// The worker runs on a thread that may outlive this call, so it must never touch
// `checkpoints` or `log` directly — it reports back through this shared state
// and the caller does all logging and mutation on its own thread.
struct DnsFetchState {
  std::mutex mutex;
  std::condition_variable cv;
  bool done = false;
  std::vector<std::pair<Logging::Level, std::string>> messages;
  std::vector<CheckpointRecord> accepted;
};

}  // namespace

bool fetchDnsCheckpoints(Checkpoints& checkpoints, Logging::ILogger& log,
                         const Crypto::Hash& genesisBlockHash, bool testnet) {
#if defined(__ANDROID__)
  return false;
#else
  Logging::LoggerRef logger(log, "checkpoints-dns");
  const std::string domain(CryptoNote::DNS_CHECKPOINTS_HOST);

  if (CryptoNote::DNS_CHECKPOINT_SIGNERS_COUNT == 0) {
    logger(Logging::WARNING) << "No DNS_CHECKPOINT_SIGNERS configured in this build; "
                                "skipping DNS checkpoint discovery.";
    return true;
  }

  // Parse the approved signers up front: cheap, and a misconfigured build should
  // say so without doing any network I/O.
  std::vector<CryptoPQ::DsaPublicKey> signerSpendPubs;
  signerSpendPubs.reserve(CryptoNote::DNS_CHECKPOINT_SIGNERS_COUNT);
  for (size_t i = 0; i < CryptoNote::DNS_CHECKPOINT_SIGNERS_COUNT; ++i) {
    const std::string entry(CryptoNote::DNS_CHECKPOINT_SIGNERS[i]);
    CryptoNote::PqAddress addr;
    if (CryptoNote::decodePqAddress(entry, addr)) {
      signerSpendPubs.push_back(addr.spendPub);
    } else {
      logger(Logging::ERROR, Logging::BRIGHT_RED)
          << "DNS_CHECKPOINT_SIGNERS[" << i << "]='" << entry
          << "' is not a valid Discrete PQ address; skipping.";
    }
  }

  if (signerSpendPubs.empty()) {
    logger(Logging::WARNING) << "No usable DNS checkpoint signers after parsing; "
                                "ignoring DNS checkpoints.";
    return true;
  }

  const std::string expectedNetwork = testnet ? "testnet" : "mainnet";
  logger(Logging::INFO) << "Fetching DNS checkpoint pointer from " << domain;
  const auto start = std::chrono::steady_clock::now();

  auto state = std::make_shared<DnsFetchState>();

  // Detached rather than joined: std::async's future blocks in its destructor,
  // which would silently defeat the deadline. The worker co-owns `state`, so
  // abandoning it here is safe.
  std::thread([state, domain, signerSpendPubs, genesisBlockHash, expectedNetwork]() {
    std::vector<std::pair<Logging::Level, std::string>> messages;
    std::vector<CheckpointRecord> accepted;

    try {
      std::vector<std::string> records;
      if (!Common::fetch_dns_txt(domain, records)) {
        messages.emplace_back(Logging::WARNING, "DNS checkpoint lookup failed for " + domain);
      } else if (records.empty()) {
        messages.emplace_back(Logging::WARNING, "No DNS checkpoint pointer found at " + domain);
      } else {
        System::Dispatcher dispatcher;
        for (const auto& record : records) {
          CheckpointPointer pointer;
          std::string reject;
          if (!parseCheckpointPointer(record, pointer, reject)) {
            messages.emplace_back(Logging::WARNING,
                "Malformed DNS checkpoint pointer (" + reject + "): " + record);
            continue;
          }

          messages.emplace_back(Logging::INFO,
              "Downloading checkpoint " + std::to_string(pointer.height) + " from " + pointer.url);

          std::string fileBytes;
          if (!downloadCheckpointFile(dispatcher, pointer, fileBytes, reject)) {
            messages.emplace_back(Logging::WARNING,
                "Failed to download DNS checkpoint " + std::to_string(pointer.height) + ": " + reject);
            continue;
          }

          CheckpointRecord checkpoint;
          switch (verifyCheckpointFile(fileBytes, pointer, signerSpendPubs,
                                       genesisBlockHash, expectedNetwork,
                                       checkpoint, reject)) {
            case CheckpointStatus::Malformed:
              messages.emplace_back(Logging::WARNING,
                  "Malformed DNS checkpoint file at height " +
                  std::to_string(pointer.height) + ": " + reject);
              continue;
            case CheckpointStatus::BadSignature:
              messages.emplace_back(Logging::ERROR,
                  "Invalid DNS checkpoint signature at height " +
                  std::to_string(pointer.height) + ": " + reject);
              continue;
            case CheckpointStatus::Accepted:
              accepted.push_back(checkpoint);
              break;
          }
        }
      }
    }
    catch (const std::exception& e) {
      messages.emplace_back(Logging::WARNING,
          std::string("DNS checkpoint discovery failed: ") + e.what());
    }
    catch (...) {
      messages.emplace_back(Logging::WARNING, "DNS checkpoint discovery failed");
    }

    {
      std::lock_guard<std::mutex> guard(state->mutex);
      state->messages = std::move(messages);
      state->accepted = std::move(accepted);
      state->done = true;
    }
    state->cv.notify_one();
  }).detach();

  std::vector<std::pair<Logging::Level, std::string>> messages;
  std::vector<CheckpointRecord> accepted;
  {
    std::unique_lock<std::mutex> guard(state->mutex);
    if (!state->cv.wait_for(guard, kDnsCheckpointDeadline, [&] { return state->done; })) {
      guard.unlock();
      logger(Logging::WARNING)
          << "DNS checkpoint discovery timed out after " << kDnsCheckpointDeadline.count()
          << "s; continuing with the checkpoints already loaded.";
      return false;
    }
    messages = std::move(state->messages);
    accepted = std::move(state->accepted);
  }

  const auto dur = std::chrono::steady_clock::now() - start;
  logger(Logging::DEBUGGING) << "DNS checkpoint discovery took "
      << std::chrono::duration_cast<std::chrono::milliseconds>(dur).count() << " ms";

  for (const auto& message : messages) {
    if (message.first == Logging::ERROR) {
      logger(Logging::ERROR, Logging::BRIGHT_RED) << message.second;
    } else {
      logger(message.first) << message.second;
    }
  }

  for (const auto& checkpoint : accepted) {
    Crypto::Hash existingHash{};
    if (checkpoints.tryGetCheckpoint(checkpoint.height, existingHash)) {
      if (existingHash != checkpoint.blockHash) {
        logger(Logging::ERROR, Logging::BRIGHT_RED)
            << "DNS checkpoint conflicts with an existing checkpoint at height "
            << checkpoint.height;
      } else {
        logger(Logging::INFO) << "Verified DNS checkpoint already present at height "
                              << checkpoint.height;
      }
      continue;
    }

    if (!checkpoints.add_checkpoint(checkpoint.height, Common::podToHex(checkpoint.blockHash))) {
      logger(Logging::WARNING) << "Failed to add verified DNS checkpoint at height "
                               << checkpoint.height;
      continue;
    }

    logger(Logging::INFO, Logging::GREEN) << "Accepted signed DNS checkpoint at height "
                                          << checkpoint.height << " (" << checkpoint.keyId << ")";
  }

  if (accepted.empty()) {
    logger(Logging::WARNING) << "No DNS checkpoints were verified.";
  }

  return true;
#endif
}

}  // namespace CryptoNote
