// Copyright (c) 2026, The Karbo developers
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

#include "PqConsumer.h"

#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Transfers/CommonTypes.h"

namespace CryptoNote {

PqConsumer::PqConsumer(const PqWalletKeys& keys, const SynchronizationStart& syncStart,
                       Logging::ILogger& logger)
    : m_state(keys), m_syncStart(syncStart), m_logger(logger, "PqConsumer") {}

SynchronizationStart PqConsumer::getSyncStart() {
  return m_syncStart;
}

bool PqConsumer::scanReader(const ITransactionReader& reader, uint32_t height) {
  // The synchronizer hands us prefix-only readers; getTransactionData() returns
  // the serialized TransactionPrefix. That carries everything PQ scanning needs
  // (PQ input signatures live inside the inputs). Non-PQ transactions are
  // rejected cheaply inside PqWalletState (version gate).
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
  return m_state.processTransaction(prefix, txid, height);
}

uint32_t PqConsumer::onNewBlocks(const CompleteBlock* blocks, uint32_t startHeight, uint32_t count) {
  if (count == 0) {
    return 0;
  }

  uint32_t processed = 0;
  try {
    for (uint32_t i = 0; i < count; ++i) {
      const CompleteBlock& cb = blocks[i];
      uint32_t height = startHeight + i;
      if (cb.block.is_initialized()) {
        for (const auto& tx : cb.transactions) {
          if (tx) {
            scanReader(*tx, height);
          }
        }
      }
      ++processed;
      m_state.setLastScannedHeight(height);
    }
  } catch (const std::exception& e) {
    m_logger(Logging::ERROR, Logging::BRIGHT_RED)
        << "PQ scan failed at block " << (startHeight + processed) << ": " << e.what();
  }
  return processed;
}

void PqConsumer::onBlockchainDetach(uint32_t height) {
  m_observerManager.notify(&IBlockchainConsumerObserver::onBlockchainDetach, this, height);
  m_state.rollbackToHeight(height);
}

std::error_code PqConsumer::onPoolUpdated(
    const std::vector<std::unique_ptr<ITransactionReader>>& addedTransactions,
    const std::vector<Crypto::Hash>& deletedTransactions) {
  for (const auto& tx : addedTransactions) {
    if (!tx) continue;
    Crypto::Hash h = tx->getTransactionHash();
    if (scanReader(*tx, PqWalletState::UNCONFIRMED_HEIGHT)) {
      m_poolTxs.insert(h);
    }
  }
  for (const auto& h : deletedTransactions) {
    m_poolTxs.erase(h);
  }
  return std::error_code();
}

const std::unordered_set<Crypto::Hash>& PqConsumer::getKnownPoolTxIds() const {
  return m_poolTxs;
}

std::error_code PqConsumer::addUnconfirmedTransaction(const ITransactionReader& transaction) {
  if (scanReader(transaction, PqWalletState::UNCONFIRMED_HEIGHT)) {
    m_poolTxs.insert(transaction.getTransactionHash());
  }
  return std::error_code();
}

void PqConsumer::removeUnconfirmedTransaction(const Crypto::Hash& transactionHash) {
  m_poolTxs.erase(transactionHash);
}

}  // namespace CryptoNote
