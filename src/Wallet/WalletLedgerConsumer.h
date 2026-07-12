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

#pragma once

#include <unordered_set>

#include "Transfers/IBlockchainSynchronizer.h"
#include "Transfers/IObservableImpl.h"
#include "ITransfersSynchronizer.h"   // SynchronizationStart
#include "Logging/LoggerRef.h"
#include "PqWallet.h"
#include "WalletLedger.h"

// A BlockchainSynchronizer consumer that scans the chain for this wallet's PQ
// outputs and maintains its WalletLedger. It runs alongside the classical
// TransfersConsumer under the same synchronizer: the classical consumer ignores
// PQ transactions (they carry no transaction public key), and this consumer
// ignores everything but the PQ family.
//
// The synchronizer owns this consumer's block cursor (a SynchronizationState);
// WalletLegacy persists that cursor plus the WalletLedger across restarts so
// the wallet does not rescan from genesis each load.

namespace CryptoNote {

class WalletLedgerConsumer : public IObservableImpl<IBlockchainConsumerObserver, IBlockchainConsumer> {
public:
  WalletLedgerConsumer(const PqWalletKeys& keys, const SynchronizationStart& syncStart,
             Logging::ILogger& logger);
  WalletLedgerConsumer(const PqTrackingKeys& keys, const SynchronizationStart& syncStart,
             Logging::ILogger& logger);

  WalletLedger& state() { return m_state; }
  const WalletLedger& state() const { return m_state; }

  // IBlockchainConsumer
  SynchronizationStart getSyncStart() override;
  void onBlockchainDetach(uint32_t height) override;
  uint32_t onNewBlocks(const CompleteBlock* blocks, uint32_t startHeight, uint32_t count) override;
  std::error_code onPoolUpdated(const std::vector<std::unique_ptr<ITransactionReader>>& addedTransactions,
                                const std::vector<Crypto::Hash>& deletedTransactions) override;
  const std::unordered_set<Crypto::Hash>& getKnownPoolTxIds() const override;
  std::error_code addUnconfirmedTransaction(const ITransactionReader& transaction) override;
  void removeUnconfirmedTransaction(const Crypto::Hash& transactionHash) override;

private:
  // Scan one transaction (given its reader) at a height + block timestamp; returns
  // true if owned. timestamp is 0 for mempool transactions.
  bool scanReader(const ITransactionReader& reader, uint32_t height, uint64_t timestamp);
  void removeUnconfirmedFromState(const Crypto::Hash& transactionHash);

  WalletLedger        m_state;
  SynchronizationStart m_syncStart;
  std::unordered_set<Crypto::Hash> m_poolTxs;
  Logging::LoggerRef   m_logger;
};

}  // namespace CryptoNote
