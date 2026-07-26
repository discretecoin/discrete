// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, The TurtleCoin developers
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

#include <cstdlib>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <cstring>
#include <string>
#include <string.h>
#include <sstream>
#include <vector>
#include <iterator>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#include "Checkpoints.h"
#include "CheckpointDownloader.h"
#include "DnsCheckpoint.h"
#include "../CryptoNoteConfig.h"
#include "Common/StringTools.h"
#include "Common/DnsTools.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "PqAddress.h"
#include "System/Dispatcher.h"

using namespace Logging;
#undef ERROR

namespace CryptoNote {
//---------------------------------------------------------------------------
Checkpoints::Checkpoints(Logging::ILogger &log) : logger(log, "checkpoints") {

}
//---------------------------------------------------------------------------
bool Checkpoints::add_checkpoint(uint32_t height, const std::string &hash_str) {
  Crypto::Hash h = NULL_HASH;

  if (!Common::podFromHex(hash_str, h)) {
    logger(WARNING) << "Wrong hash in checkpoint for height " << height;
    return false;
  }

  if (!m_points.insert({ height, h }).second) {
    logger(WARNING) << "Checkpoint already exists.";
    return false;
  }

  return true;
}
//---------------------------------------------------------------------------
bool Checkpoints::load_checkpoints_from_file(const std::string& fileName) {
  std::ifstream file(fileName);
  if (!file) {
    logger(Logging::ERROR, BRIGHT_RED) << "Could not load checkpoints file: " << fileName;
    return false;
  }
  std::string indexString;
  std::string hash;
  uint32_t height;
  while (std::getline(file, indexString, ','), std::getline(file, hash)) {
    try {
      height = std::stoi(indexString);
    } catch (const std::invalid_argument &) {
      logger(Logging::ERROR, BRIGHT_RED) << "Invalid checkpoint file format - "
        << "could not parse height as a number";
      return false;
    }
    if (!add_checkpoint(height, hash)) {
      return false;
    }
  }
  logger(Logging::INFO) << "Loaded " << m_points.size() << " checkpoints from "	<< fileName;
  return true;
}

//---------------------------------------------------------------------------
bool Checkpoints::is_in_checkpoint_zone(uint32_t  height) const {
  return !m_points.empty() && (height <= (--m_points.end())->first);
}
//---------------------------------------------------------------------------
bool Checkpoints::check_block(uint32_t  height, const Crypto::Hash &h,
                              bool &is_a_checkpoint) const {
  auto it = m_points.find(height);
  is_a_checkpoint = it != m_points.end();
  if (!is_a_checkpoint)
    return true;

  if (it->second == h) {
    logger(Logging::DEBUGGING, Logging::GREEN)
      << "CHECKPOINT PASSED FOR HEIGHT " << height << " " << h;
    return true;
  } else {
    logger(Logging::ERROR) << "CHECKPOINT FAILED FOR HEIGHT " << height
                           << ". EXPECTED HASH: " << it->second
                           << ", FETCHED HASH: " << h;
    return false;
  }
}
//---------------------------------------------------------------------------
bool Checkpoints::check_block(uint32_t  height, const Crypto::Hash &h) const {
  bool ignored;
  return check_block(height, h, ignored);
}
//---------------------------------------------------------------------------
// Network-wide first-seen finality rule. blockchain_height is the current chain
// length (tip height + 1); block_height is the height of the alternative block.
// The additive comparison (block_height + depth < blockchain_height) is the
// underflow-safe form of "the fork is more than CRYPTONOTE_FINALITY_DEPTH blocks
// below the tip" — the subtractive form would wrap on a chain younger than the
// finality depth (the first ~10 blocks) and wrongly reject normal shallow reorgs.
// Enforced from genesis on every node; the checkpoint zone stays exempt.
bool Checkpoints::is_finality_violation(uint32_t blockchain_height,
                                        uint32_t block_height) const {
  return static_cast<uint64_t>(block_height) + CryptoNote::parameters::CRYPTONOTE_FINALITY_DEPTH < blockchain_height
    && !is_in_checkpoint_zone(block_height);
}
//---------------------------------------------------------------------------
bool Checkpoints::is_alternative_block_allowed(uint32_t  blockchain_height,
                                               uint32_t  block_height) const {
  if (0 == block_height)
    return false;

  if (is_finality_violation(blockchain_height, block_height)) {
    logger(Logging::WARNING, Logging::WHITE) << "An attempt of too deep reorganization: "
      << blockchain_height - block_height << ", BLOCK REJECTED";

    return false;
  }

  auto it = m_points.upper_bound(blockchain_height);
  // Is blockchain_height before the first checkpoint?
  if (it == m_points.begin())
    return true;

  --it;
  uint32_t  checkpoint_height = it->first;
  return checkpoint_height < block_height;
}

std::vector<uint32_t> Checkpoints::getCheckpointHeights() const {
  std::vector<uint32_t> checkpointHeights;
  checkpointHeights.reserve(m_points.size());
  for (const auto& it : m_points) {
    checkpointHeights.push_back(it.first);
  }

  return checkpointHeights;
}

namespace {

// Overall wall-clock budget for DNS + TLS + download + verify. Neither the DNS
// resolver nor the TLS/HTTP stack enforces a deadline of its own, so without
// this a silent web server (one that completes the TCP handshake and then never
// speaks) would stall node startup indefinitely.
constexpr std::chrono::seconds kDnsCheckpointDeadline{5};

// The worker runs on a thread that may outlive this call, so it must never touch
// the Checkpoints object — not even its logger. It reports back through this
// shared state and the caller does all logging and mutation.
struct DnsFetchState {
  std::mutex mutex;
  std::condition_variable cv;
  bool done = false;
  std::vector<std::pair<Logging::Level, std::string>> messages;
  std::vector<CryptoNote::CheckpointRecord> accepted;
};

}  // namespace

//---------------------------------------------------------------------------
bool Checkpoints::load_checkpoints_from_dns(const Crypto::Hash& genesisBlockHash,
                                            bool testnet)
{
#if defined(__ANDROID__)
  return false;
#else
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
      logger(Logging::ERROR, BRIGHT_RED)
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
  // which would silently defeat the deadline (the previous implementation's
  // 200 ms DNS timeout did exactly that). The worker co-owns `state`, so
  // abandoning it here is safe.
  std::thread([state, domain, signerSpendPubs, genesisBlockHash, expectedNetwork]() {
    std::vector<std::pair<Logging::Level, std::string>> messages;
    std::vector<CryptoNote::CheckpointRecord> accepted;

    try {
      std::vector<std::string> records;
      if (!Common::fetch_dns_txt(domain, records)) {
        messages.emplace_back(Logging::WARNING, "DNS checkpoint lookup failed for " + domain);
      } else if (records.empty()) {
        messages.emplace_back(Logging::WARNING, "No DNS checkpoint pointer found at " + domain);
      } else {
        System::Dispatcher dispatcher;
        for (const auto& record : records) {
          CryptoNote::CheckpointPointer pointer;
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

          CryptoNote::CheckpointRecord checkpoint;
          switch (verifyCheckpointFile(fileBytes, pointer, signerSpendPubs,
                                       genesisBlockHash, expectedNetwork,
                                       checkpoint, reject)) {
            case CryptoNote::CheckpointStatus::Malformed:
              messages.emplace_back(Logging::WARNING,
                  "Malformed DNS checkpoint file at height " +
                  std::to_string(pointer.height) + ": " + reject);
              continue;
            case CryptoNote::CheckpointStatus::BadSignature:
              messages.emplace_back(Logging::ERROR,
                  "Invalid DNS checkpoint signature at height " +
                  std::to_string(pointer.height) + ": " + reject);
              continue;
            case CryptoNote::CheckpointStatus::Accepted:
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
  std::vector<CryptoNote::CheckpointRecord> accepted;
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
      logger(Logging::ERROR, BRIGHT_RED) << message.second;
    } else {
      logger(message.first) << message.second;
    }
  }

  for (const auto& checkpoint : accepted) {
    const auto existing = m_points.find(checkpoint.height);
    if (existing != m_points.end()) {
      if (existing->second != checkpoint.blockHash) {
        logger(Logging::ERROR, BRIGHT_RED)
            << "DNS checkpoint conflicts with an existing checkpoint at height "
            << checkpoint.height;
      } else {
        logger(Logging::INFO) << "Verified DNS checkpoint already present at height "
                              << checkpoint.height;
      }
      continue;
    }

    if (!add_checkpoint(checkpoint.height, Common::podToHex(checkpoint.blockHash))) {
      logger(Logging::WARNING) << "Failed to add verified DNS checkpoint at height "
                               << checkpoint.height;
      continue;
    }

    logger(Logging::INFO, GREEN) << "Accepted signed DNS checkpoint at height "
                                 << checkpoint.height << " (" << checkpoint.keyId << ")";
  }

  if (accepted.empty()) {
    logger(Logging::WARNING) << "No DNS checkpoints were verified.";
  }

  return true;
#endif
}

}
