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

#pragma once

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <CryptoNoteCore/CryptoNoteBasicImpl.h>
#include <Logging/LoggerRef.h>
#include "crypto_pq/PqDsa.h"

namespace CryptoNote
{
  class Checkpoints
  {
  public:
    Checkpoints(Logging::ILogger& log);

    Checkpoints& operator=(Checkpoints const& other)
    {
      if (&other != this)
      {
        // lock both objects
        std::unique_lock<std::mutex> lock_this(m_mutex, std::defer_lock);
        std::unique_lock<std::mutex> lock_other(other.m_mutex, std::defer_lock);
        std::lock(lock_this, lock_other); // ensure no deadlock
        m_points = other.m_points;
        logger = other.logger;
      }

      return *this;
    }

    // Outcome of verifying one DNS TXT checkpoint record. Malformed and
    // BadSignature are kept distinct so operators can tell a broken record
    // (typo, stale format) from a forged one (attack signal).
    enum class DnsRecordStatus { Accepted, Malformed, BadSignature };

    // Parse one DNS TXT record "<height>:<block_hash_64hex>:<signature>" and
    // verify its ML-DSA signature against any of the approved signer spend keys.
    // The signed payload is genesis-bound — "<genesis_hex>:<height>:<hash_hex>"
    // — so a record signed for any other deployment (testnet, a fork reusing
    // this code and signer key) can never be replayed onto this chain via the
    // shared DNS host. On Accepted, height/hash_str carry the parsed values;
    // otherwise reject_reason says why. Pure function; no DNS, no logging.
    static DnsRecordStatus verify_signed_dns_record(
        const std::string& record,
        const std::vector<CryptoPQ::DsaPublicKey>& signerSpendPubs,
        const Crypto::Hash& genesisBlockHash,
        uint32_t& height, std::string& hash_str, std::string& reject_reason);

    bool add_checkpoint(uint32_t height, const std::string& hash_str);
    bool load_checkpoints_from_file(const std::string& fileName);
    bool load_checkpoints_from_dns(const Crypto::Hash& genesisBlockHash);
    bool is_in_checkpoint_zone(uint32_t height) const;
    bool check_block(uint32_t height, const Crypto::Hash& h) const;
    bool check_block(uint32_t height, const Crypto::Hash& h, bool& is_a_checkpoint) const;
    bool is_alternative_block_allowed(uint32_t blockchain_height, uint32_t block_height) const;
    // Pure predicate: would an alt block at block_height be refused by the
    // node-local first-seen finality rule (forks deeper than
    // CRYPTONOTE_FINALITY_DEPTH below the tip, outside a hardcoded checkpoint
    // zone)? Deterministic function of heights + checkpoints only.
    bool is_finality_violation(uint32_t blockchain_height, uint32_t block_height) const;
    std::vector<uint32_t> getCheckpointHeights() const;

  private:
    std::map<uint32_t, Crypto::Hash> m_points;
    Logging::LoggerRef logger;
    mutable std::mutex m_mutex;
  };
}
