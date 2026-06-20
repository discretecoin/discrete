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

#include <cstdint>
#include <iosfwd>
#include <map>
#include <unordered_map>
#include <vector>

#include "CryptoNote.h"
#include "PqWallet.h"
#include "PqTransactionBuilder.h"
#include "crypto/hash.h"
#include "crypto_pq/PqDsa.h"

// Self-contained PQ wallet state: scans raw transactions for owned PQ outputs,
// tracks a SEPARATE PQ balance, detects when owned outputs are spent, and hands
// spendable inputs to the PQ transaction builders.
//
// This deliberately lives outside the classical Transfers/BlockchainSynchronizer
// pipeline, which is built around stealth KeyOutputs and even filters out PQ
// transactions (they carry no transaction public key). PQ recognition is a
// different mechanism (ML-KEM decaps + AEAD), so it gets its own state, mirroring
// the consensus-side isolation of the PQ family.
//
// A caller (front-end / sync driver) feeds confirmed transactions in chain order
// via processTransaction(); on a reorg it calls rollbackToHeight().

namespace CryptoNote {

// Sentinel depositIndex meaning "the wallet's own primary address" — i.e. NOT a
// deposit issued under a deposit-wallet scheme. Distinct from any real index.
constexpr uint32_t PQ_PRIMARY_DEPOSIT = 0xFFFFFFFFu;

// One PQ output this wallet owns. Holds no secret key: the spend secret is
// re-derived from the seed on demand at spend time.
struct PqWalletOutput {
  Crypto::Hash  txid{};
  uint32_t      outputIndex = 0;
  uint64_t      amount = 0;
  CryptoPQ::Rho rho{};
  Crypto::Hash  nullifier{};      // SHA3(spendPub || rho) — watched to detect spends
  uint32_t      height = 0;       // block height the output was received at
  uint64_t      unlockHeight = 0; // per-output spend lock (0 = none); consensus
                                  // rejects spends before this height
  bool          spent = false;
  uint32_t      spentHeight = 0;  // height the spend was seen at (when spent)
  // Which deposit this output was attributed to. PQ_PRIMARY_DEPOSIT = the
  // wallet's own primary address. For AggregatedMultikey it is the deposit
  // spend-key index; for SingleKeyIndex it is the subaddress index T.
  uint32_t      depositIndex = PQ_PRIMARY_DEPOSIT;
};

// One transaction that touched this wallet, derived as the scanner processes it.
// This is the PQ ledger's transaction-history view (the native IWallet history is
// built from these rows). Counterparties are NOT recoverable from owned-output
// scanning, so only the wallet's own net effect is recorded.
struct PqWalletTransaction {
  Crypto::Hash txid{};
  uint32_t     height = 0;       // UNCONFIRMED_HEIGHT while still in the mempool
  uint64_t     timestamp = 0;    // block timestamp (0 if unknown / unconfirmed)
  int64_t      netAmount = 0;    // + for net incoming; -(amount+fee) for our sends
  uint64_t     fee = 0;          // our outgoing txs only (0 for incoming)
  bool         outgoing = false; // true if this tx spends any owned output
};

class WalletLedger {
public:
  explicit WalletLedger(const PqWalletKeys& keys);
  explicit WalletLedger(const PqTrackingKeys& keys);

  // Scan one transaction seen at `height` (use UNCONFIRMED_HEIGHT for mempool).
  // Credits owned PQ outputs and marks owned outputs spent when their nullifier
  // appears among the tx's PQ inputs. Returns true if the wallet was affected.
  // Takes a TransactionPrefix: the scanner only has the prefix (PQ input
  // signatures live inside the inputs, so the prefix carries all PQ data).
  bool processTransaction(const TransactionPrefix& tx, const Crypto::Hash& txid, uint32_t height,
                          uint64_t timestamp = 0);

  // Deposit-wallet configuration. Set once after construction (and again after
  // load) by the owning WalletGreen, which persists scheme + count separately.
  // For AggregatedMultikey this (re)derives the deposit spend-key set so the
  // scanner can route deposits by spend key; for SingleKeyIndex it only records
  // how many subaddress indices T to try. Idempotent and cheap to re-call as the
  // deposit count grows.
  void setDepositConfig(PqDepositScheme scheme, uint32_t depositCount);

  // Total of unspent owned outputs (all deposits + primary; confirmed + pending).
  uint64_t balance() const;

  // Unspent balance still in the mempool (received at UNCONFIRMED_HEIGHT).
  uint64_t pendingBalance() const;

  // Unspent balance attributed to one deposit index (for walletd attribution).
  uint64_t depositBalance(uint32_t depositIndex) const;

  // Unspent balance per deposit index, excluding the primary address.
  std::map<uint32_t, uint64_t> depositBalances() const;

  // All unspent outputs as builder inputs (for buildPqTransaction).
  std::vector<PqSpendInput> spendableInputs() const;

  const std::vector<PqWalletOutput>& outputs() const { return m_outputs; }
  std::size_t ownedCount() const { return m_outputs.size(); }
  std::size_t unspentCount() const;

  // Transaction-history view (native IWallet history is built from these).
  const std::vector<PqWalletTransaction>& history() const { return m_history; }
  std::size_t historyCount() const { return m_history.size(); }
  // The history row for `txid`, or nullptr if this tx never touched the wallet.
  const PqWalletTransaction* historyByTxid(const Crypto::Hash& txid) const;

  // Reorg support: drop outputs received at height >= h, and un-spend outputs
  // whose spend was seen at height >= h.
  void rollbackToHeight(uint32_t h);

  uint32_t lastScannedHeight() const { return m_lastScannedHeight; }
  void setLastScannedHeight(uint32_t h) { m_lastScannedHeight = h; }

  // Binary persistence of the owned-output set + scan cursor. The keys are NOT
  // stored (they are re-supplied at construction from the wallet seed).
  void save(std::ostream& os) const;
  void load(std::istream& is);

  static constexpr uint32_t UNCONFIRMED_HEIGHT = 0xFFFFFFFFu;

private:
  // Grow m_depositSpendPubs to cover [0, count) deposit keys (AggregatedMultikey
  // only). Incremental: derives only the keys not yet cached.
  void ensureDepositKeys(uint32_t count);

  CryptoPQ::PqScanKeys   m_scanKeys;
  CryptoPQ::DsaPublicKey m_spendPub;
  CryptoPQ::SeedMaster   m_seedMaster;  // to derive deposit spend keys on demand
  bool                   m_hasSeedMaster = false;

  PqDepositScheme m_depositScheme = PqDepositScheme::AggregatedMultikey;
  uint32_t        m_depositCount = 0;
  // Cached deposit spend pubs (AggregatedMultikey); index == deposit index.
  std::vector<CryptoPQ::DsaPublicKey> m_depositSpendPubs;

  std::vector<PqWalletOutput> m_outputs;
  // nullifier -> index into m_outputs, for O(1) spend detection.
  std::unordered_map<Crypto::Hash, std::size_t> m_byNullifier;

  // Transaction-history view + txid -> index, for O(1) upsert (pool -> confirmed).
  std::vector<PqWalletTransaction> m_history;
  std::unordered_map<Crypto::Hash, std::size_t> m_historyByTxid;

  uint32_t m_lastScannedHeight = 0;
};

}  // namespace CryptoNote
