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
#include <thread>
#include <future>

#include "Checkpoints.h"
#include "../CryptoNoteConfig.h"
#include "Common/StringTools.h"
#include "Common/DnsTools.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "PqAddress.h"

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

//---------------------------------------------------------------------------
bool Checkpoints::load_checkpoints_from_dns()
{
#if defined(__ANDROID__)
  return false;
#else
  std::string domain(CryptoNote::DNS_CHECKPOINTS_HOST);
  std::vector<std::string>records;
  bool res = true;
  auto start = std::chrono::steady_clock::now();
  logger(Logging::DEBUGGING) << "Fetching DNS checkpoint records from " << domain;

  try {
    auto future = std::async(std::launch::async, [this, &res, &domain, &records]() {
      res = Common::fetch_dns_txt(domain, records);
    });

    std::future_status status;

    status = future.wait_for(std::chrono::milliseconds(200));

    if (status == std::future_status::timeout) {
      logger(Logging::DEBUGGING) << "Timeout lookup DNS checkpoint records from " << domain;
      return false;
    }
    else if (status == std::future_status::ready) {
      future.get();
    }
  }
  catch (std::runtime_error& e) {
    logger(Logging::DEBUGGING) << e.what();
    return false;
  }

  auto dur = std::chrono::steady_clock::now() - start;
  logger(Logging::DEBUGGING) << "DNS query time: " << std::chrono::duration_cast<std::chrono::milliseconds>(dur).count() << " ms";

  // Fail-closed: if no signer addresses are baked into this build, every DNS
  // record is dropped without trying to verify it. Tampered DNS or an
  // accidentally-misconfigured release can't sneak past the signature gate
  // by simply omitting the signature field. The one-shot warning makes the
  // misconfiguration visible to operators reading the log.
  if (CryptoNote::DNS_CHECKPOINT_SIGNERS_COUNT == 0) {
    logger(Logging::WARNING) << "DNS checkpoints fetched but no DNS_CHECKPOINT_SIGNERS "
                                "configured in this build; ignoring " << records.size()
                             << " record(s). Set DNS_CHECKPOINT_SIGNERS in CryptoNoteConfig.h "
                                "to enable.";
    return true;
  }

  // Pre-parse the approved PQ signer addresses once per DNS fetch. Each signer is
  // a Discrete PQ address; we keep its ML-DSA-65 spend public key, which
  // verifyMessagePq checks the record signature against. A mistyped/invalid PQ
  // address is logged and dropped (it can't open the verifier — decodePqAddress
  // rejects it — but the diagnostic points at the bad entry).
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
                                "ignoring all DNS records.";
    return true;
  }

  for (const auto& record : records) {
    // Required wire format: "<height>:<block_hash_64hex>:<signature>"
    // The legacy 2-field "<height>:<hash>" format is rejected — it has no
    // signature and so cannot be trusted to add even an anchor.
    const size_t del1 = record.find(':');
    if (del1 == std::string::npos) {
      logger(Logging::WARNING) << "Malformed DNS checkpoint (no field delimiter): " << record;
      continue;
    }
    const size_t del2 = record.find(':', del1 + 1);
    if (del2 == std::string::npos) {
      logger(Logging::WARNING) << "Malformed DNS checkpoint (legacy unsigned format, rejected): " << record;
      continue;
    }

    const std::string height_str = record.substr(0, del1);
    const std::string hash_str   = record.substr(del1 + 1, del2 - del1 - 1);
    const std::string sig_str    = record.substr(del2 + 1);

    if (hash_str.size() != 64) {
      logger(Logging::WARNING) << "Malformed DNS checkpoint (hash length " << hash_str.size()
                               << " != 64): " << record;
      continue;
    }

    uint32_t height = 0;
    {
      std::stringstream ss(height_str);
      char trailing;
      ss >> height;
      if (ss.fail() || ss.get(trailing)) {
        logger(Logging::WARNING) << "Malformed DNS checkpoint (height not a clean number): " << record;
        continue;
      }
    }

    Crypto::Hash hash{};
    if (!Common::podFromHex(hash_str, hash)) {
      logger(Logging::WARNING) << "Malformed DNS checkpoint (hash not hex): " << record;
      continue;
    }

    // Verify the ML-DSA signature against any one of the approved signers. The
    // signed payload is the literal "<height>:<hash>" string — what the
    // maintainer types into simplewallet's sign_message prompt (which signs with
    // the wallet's ML-DSA spend key; see CryptoNoteFormatUtils::signMessagePq).
    const std::string signed_payload = height_str + ":" + hash_str;
    bool verified = false;
    for (const auto& spendPub : signerSpendPubs) {
      if (CryptoNote::verifyMessagePq(signed_payload, spendPub, sig_str)) {
        verified = true;
        break;
      }
    }
    if (!verified) {
      logger(Logging::ERROR, BRIGHT_RED)
          << "DNS checkpoint signature did not match any approved signer; "
             "rejecting record: " << record;
      continue;
    }

    if (m_points.count(height) != 0) {
      logger(Logging::DEBUGGING) << "Checkpoint already exists for height: " << height
                                 << ". Ignoring DNS checkpoint.";
      continue;
    }
    add_checkpoint(height, hash_str);
    logger(Logging::DEBUGGING) << "Added signed DNS checkpoint: " << height_str << ":" << hash_str;
  }

  return true;
#endif
}

}
