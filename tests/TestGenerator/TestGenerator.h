// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

#include <cstdint>
#include <list>
#include <vector>
#include <unordered_map>

#include "crypto/hash.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/Difficulty.h"

// Forward declaration so test_generator can hold a Blockchain pointer without
// pulling in the heavy Blockchain.h transitively through TestGenerator.h.
namespace CryptoNote { class Blockchain; }


class test_generator
{
public:
  struct BlockInfo {
    BlockInfo()
      : previousBlockHash()
      , alreadyGeneratedCoins(0)
      , blockSize(0) {
    }

    BlockInfo(Crypto::Hash aPrevId, uint64_t anAlreadyGeneratedCoins, size_t aBlockSize)
      : previousBlockHash(aPrevId)
      , alreadyGeneratedCoins(anAlreadyGeneratedCoins)
      , blockSize(aBlockSize) {
    }

    Crypto::Hash previousBlockHash;
    uint64_t alreadyGeneratedCoins;
    size_t blockSize;
  };

  enum BlockFields {
    bf_none      = 0,
    bf_major_ver = 1 << 0,
    bf_minor_ver = 1 << 1,
    bf_timestamp = 1 << 2,
    bf_prev_id   = 1 << 3,
    bf_miner_tx  = 1 << 4,
    bf_tx_hashes = 1 << 5,
    bf_diffic    = 1 << 6
  };

  test_generator(const CryptoNote::Currency& currency, uint8_t majorVersion = CryptoNote::BLOCK_MAJOR_VERSION_1,
                 uint8_t minorVersion = CryptoNote::BLOCK_MINOR_VERSION_0)
    : m_currency(currency), defaultMajorVersion(majorVersion), defaultMinorVersion(minorVersion) {
  }

  // Optional sink for V5+ PoW evaluation. Production V5+ blocks are hashed via
  // Blockchain::getBlockLongHash (DiscretePower); the standalone get_block_longhash
  // returns false for V5+. Without setBlockchain(), the PoW search loop for a
  // V5+ block would spin forever. Wire it once if the test mines past V5:
  //   test_generator gen(currency);
  //   gen.setBlockchain(&core.get_blockchain_storage());
  // For V1–V4 blocks the field is ignored; nullptr is fine.
  void setBlockchain(CryptoNote::Blockchain* blockchain) { m_blockchain = blockchain; }

  uint8_t defaultMajorVersion;
  uint8_t defaultMinorVersion;

  // Fee override by tx hash. A TX_PQ carries no inline input amounts, so the
  // generic get_tx_fee cannot price it; a test that builds a TX_PQ knows its fee
  // and registers it here so the block can be constructed (coinbase reward = base
  // + these fees, which must match what consensus computes).
  std::unordered_map<Crypto::Hash, uint64_t> knownTxFees;
  void setTxFee(const Crypto::Hash& txHash, uint64_t fee) { knownTxFees[txHash] = fee; }

  const CryptoNote::Currency& currency() const { return m_currency; }

  void getBlockchain(std::vector<BlockInfo>& blockchain, const Crypto::Hash& head, size_t n) const;
  void getLastNBlockSizes(std::vector<size_t>& blockSizes, const Crypto::Hash& head, size_t n) const;
  uint64_t getAlreadyGeneratedCoins(const Crypto::Hash& blockId) const;
  uint64_t getAlreadyGeneratedCoins(const CryptoNote::Block& blk) const;

  void addBlock(const CryptoNote::Block& blk, size_t tsxSize, uint64_t fee, std::vector<size_t>& blockSizes,
    uint64_t alreadyGeneratedCoins);
  bool constructBlock(CryptoNote::Block& blk, uint32_t height, const Crypto::Hash& previousBlockHash,
    const CryptoNote::AccountBase& minerAcc, uint64_t timestamp, uint64_t alreadyGeneratedCoins,
    std::vector<size_t>& blockSizes, const std::list<CryptoNote::Transaction>& txList);
  bool constructBlock(CryptoNote::Block& blk, const CryptoNote::AccountBase& minerAcc, uint64_t timestamp);
  bool constructBlock(CryptoNote::Block& blk, const CryptoNote::Block& blkPrev, const CryptoNote::AccountBase& minerAcc,
    const std::list<CryptoNote::Transaction>& txList = std::list<CryptoNote::Transaction>());

  bool constructBlockManually(CryptoNote::Block& blk, const CryptoNote::Block& prevBlock,
    const CryptoNote::AccountBase& minerAcc, int actualParams = bf_none, uint8_t majorVer = 0,
    uint8_t minorVer = 0, uint64_t timestamp = 0, const Crypto::Hash& previousBlockHash = Crypto::Hash(),
    const CryptoNote::Difficulty& diffic = 1, const CryptoNote::Transaction& baseTransaction = CryptoNote::Transaction(),
    const std::vector<Crypto::Hash>& transactionHashes = std::vector<Crypto::Hash>(), size_t txsSizes = 0, uint64_t fee = 0);
  bool constructBlockManuallyTx(CryptoNote::Block& blk, const CryptoNote::Block& prevBlock,
    const CryptoNote::AccountBase& minerAcc, const std::vector<Crypto::Hash>& transactionHashes, size_t txsSize);

private:
  const CryptoNote::Currency& m_currency;
  CryptoNote::Blockchain* m_blockchain = nullptr;
  std::unordered_map<Crypto::Hash, BlockInfo> m_blocksInfo;
};

inline CryptoNote::Difficulty getTestDifficulty() { return 1; }
// PoW search (difficulty=1 shortcut — no signing needed for single-attempt fills).
void fillNonce(CryptoNote::Block& blk, const CryptoNote::Difficulty& diffic);

// PoW search delegating to Blockchain::getBlockLongHash (DiscretePower).
// `blockchain` may be null — blocks fail to mine (logged once).
void fillNonce(CryptoNote::Block& blk, const CryptoNote::Difficulty& diffic,
               CryptoNote::Blockchain* blockchain);

// PoW search with ML-DSA re-signing on every nonce attempt (required because
// DiscretePower injects the candidate signature into the memory-hard PoW).
void fillNonce(CryptoNote::Block& blk, const CryptoNote::Difficulty& diffic,
               CryptoNote::Blockchain* blockchain,
               const CryptoNote::AccountBase& minerAcc);

