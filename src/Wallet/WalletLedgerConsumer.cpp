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

#include "WalletLedgerConsumer.h"

#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "Common/StringTools.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Transfers/CommonTypes.h"

namespace CryptoNote {

WalletLedgerConsumer::WalletLedgerConsumer(const PqWalletKeys& keys, const SynchronizationStart& syncStart,
                       Logging::ILogger& logger)
    : m_state(keys), m_syncStart(syncStart), m_logger(logger, "WalletLedgerConsumer") {}

WalletLedgerConsumer::WalletLedgerConsumer(const PqTrackingKeys& keys, const SynchronizationStart& syncStart,
                       Logging::ILogger& logger)
    : m_state(keys), m_syncStart(syncStart), m_logger(logger, "WalletLedgerConsumer") {}

SynchronizationStart WalletLedgerConsumer::getSyncStart() {
  return m_syncStart;
}

bool WalletLedgerConsumer::scanReader(const ITransactionReader& reader, uint32_t height, uint64_t timestamp) {
  // The synchronizer hands us prefix-only readers; getTransactionData() returns
  // the serialized TransactionPrefix. That carries everything PQ scanning needs
  // (PQ input signatures live inside the inputs). Non-PQ transactions are
  // rejected cheaply inside WalletLedger (version gate).
  BinaryArray blob = reader.getTransactionData();
  TransactionPrefix prefix;
  if (!fromBinaryArray(prefix, blob)) {
    m_logger(Logging::TRACE) << "skipping transaction that failed to parse";
    return false;
  }
  if (prefix.version < TRANSACTION_VERSION_1) {
    return false;
  }
  Crypto::Hash txid = reader.getTransactionHash();
  bool affected = m_state.processTransaction(prefix, txid, height, timestamp);
  if (affected) {
    const PqWalletTransaction* row = m_state.historyByTxid(txid);
    m_logger(Logging::INFO) << "Ledger transaction " << Common::podToHex(txid)
        << ", state " << (height == WalletLedger::UNCONFIRMED_HEIGHT ? "pool" : "confirmed")
        << (height == WalletLedger::UNCONFIRMED_HEIGHT ? std::string() :
            std::string(", height ") + std::to_string(height))
        << (row ? (row->outgoing ? ", direction outgoing" : ", direction incoming") : "")
        << (row ? std::string(", net atomic units ") + std::to_string(row->netAmount) : "")
        << (row && row->fee != 0 ? std::string(", fee atomic units ") + std::to_string(row->fee) : "")
        << ", owned outputs " << m_state.ownedCount()
        << ", unspent " << m_state.unspentCount()
        << ", spendable inputs " << m_state.spendableInputs().size()
        << ", balance atomic units " << m_state.balance()
        << ", spendable atomic units " << m_state.spendableBalance()
        << ", history rows " << m_state.historyCount();
  }
  return affected;
}

uint32_t WalletLedgerConsumer::onNewBlocks(const CompleteBlock* blocks, uint32_t startHeight, uint32_t count) {
  if (count == 0) {
    return 0;
  }

  uint32_t processed = 0;
  std::size_t affectedTransactions = 0;
  std::vector<Crypto::Hash> blockHashes;
  blockHashes.reserve(count);
  try {
    for (uint32_t i = 0; i < count; ++i) {
      const CompleteBlock& cb = blocks[i];
      uint32_t height = startHeight + i;
      if (cb.block.is_initialized()) {
        uint64_t timestamp = cb.block->timestamp;
        for (const auto& tx : cb.transactions) {
          if (tx) {
            if (scanReader(*tx, height, timestamp)) {
              ++affectedTransactions;
            }
          }
        }
      }
      blockHashes.push_back(cb.blockHash);
      ++processed;
      m_state.setLastScannedHeight(height);
    }
  } catch (const std::exception& e) {
    m_logger(Logging::ERROR, Logging::BRIGHT_RED)
        << "PQ scan failed at block " << (startHeight + processed) << ": " << e.what();
  }

  // Feed the wallet's block-hash list (the front-end's m_blockchain). Previously
  // this came from the classical TransfersConsumer's onBlocksAdded; the PQ consumer
  // is now the sole sync driver, so it must emit the block hashes it processed.
  if (!blockHashes.empty()) {
    m_observerManager.notify(&IBlockchainConsumerObserver::onBlocksAdded, this, blockHashes);
  }
  if (processed != 0) {
    m_logger(Logging::DEBUGGING) << "Ledger scan batch: blocks " << startHeight << "-"
        << (startHeight + processed - 1) << ", processed " << processed
        << ", affected transactions " << affectedTransactions
        << ", cursor " << m_state.lastScannedHeight();
  }
  return processed;
}

void WalletLedgerConsumer::onBlockchainDetach(uint32_t height) {
  const std::size_t outputsBefore = m_state.ownedCount();
  const std::size_t unspentBefore = m_state.unspentCount();
  const std::size_t historyBefore = m_state.historyCount();
  const uint64_t balanceBefore = m_state.balance();
  m_observerManager.notify(&IBlockchainConsumerObserver::onBlockchainDetach, this, height);
  m_state.rollbackToHeight(height);
  m_logger(Logging::WARNING, Logging::BRIGHT_YELLOW) << "Ledger rollback to height " << height
      << ": outputs " << outputsBefore << " -> " << m_state.ownedCount()
      << ", unspent " << unspentBefore << " -> " << m_state.unspentCount()
      << ", history " << historyBefore << " -> " << m_state.historyCount()
      << ", balance atomic units " << balanceBefore << " -> " << m_state.balance()
      << ", cursor " << m_state.lastScannedHeight();
}

std::error_code WalletLedgerConsumer::onPoolUpdated(
    const std::vector<std::unique_ptr<ITransactionReader>>& addedTransactions,
    const std::vector<Crypto::Hash>& deletedTransactions) {
  for (const auto& tx : addedTransactions) {
    if (!tx) continue;
    Crypto::Hash h = tx->getTransactionHash();
    if (scanReader(*tx, WalletLedger::UNCONFIRMED_HEIGHT, 0)) {
      m_poolTxs.insert(h);
    }
  }
  for (const auto& h : deletedTransactions) {
    m_poolTxs.erase(h);
    // A tx that left the pool without being mined: undo its unconfirmed effects.
    // (If it was mined, its outputs/spends already carry a real height and are kept.)
    removeUnconfirmedFromState(h);
  }
  if (!addedTransactions.empty() || !deletedTransactions.empty()) {
    m_logger(Logging::DEBUGGING) << "Ledger pool update: added " << addedTransactions.size()
        << ", removed " << deletedTransactions.size()
        << ", tracked wallet transactions " << m_poolTxs.size();
  }
  return std::error_code();
}

const std::unordered_set<Crypto::Hash>& WalletLedgerConsumer::getKnownPoolTxIds() const {
  return m_poolTxs;
}

std::error_code WalletLedgerConsumer::addUnconfirmedTransaction(const ITransactionReader& transaction) {
  if (scanReader(transaction, WalletLedger::UNCONFIRMED_HEIGHT, 0)) {
    m_poolTxs.insert(transaction.getTransactionHash());
  }
  return std::error_code();
}

void WalletLedgerConsumer::removeUnconfirmedTransaction(const Crypto::Hash& transactionHash) {
  m_poolTxs.erase(transactionHash);
  removeUnconfirmedFromState(transactionHash);
}

void WalletLedgerConsumer::removeUnconfirmedFromState(const Crypto::Hash& transactionHash) {
  const std::size_t outputsBefore = m_state.ownedCount();
  const std::size_t unspentBefore = m_state.unspentCount();
  const std::size_t historyBefore = m_state.historyCount();
  const uint64_t balanceBefore = m_state.balance();
  m_state.removeUnconfirmedTransaction(transactionHash);
  if (outputsBefore != m_state.ownedCount() || unspentBefore != m_state.unspentCount() ||
      historyBefore != m_state.historyCount()) {
    m_logger(Logging::INFO) << "Removed unconfirmed ledger transaction "
        << Common::podToHex(transactionHash)
        << ": outputs " << outputsBefore << " -> " << m_state.ownedCount()
        << ", unspent " << unspentBefore << " -> " << m_state.unspentCount()
        << ", history " << historyBefore << " -> " << m_state.historyCount()
        << ", balance atomic units " << balanceBefore << " -> " << m_state.balance();
  }
}

}  // namespace CryptoNote
