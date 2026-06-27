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

#include "WalletLedger.h"

#include <algorithm>
#include <cstring>
#include <istream>
#include <ostream>

#include "CryptoNoteConfig.h"
#include "PqTxType.h"
#include "crypto_pq/PqScan.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqSeed.h"

namespace CryptoNote {

namespace {

Crypto::Hash toHash(const CryptoPQ::Hash256& h) {
  Crypto::Hash out;
  std::memcpy(out.data, h.data(), 32);
  return out;
}

template <typename T>
void writePod(std::ostream& os, const T& v) {
  os.write(reinterpret_cast<const char*>(&v), sizeof(T));
}
template <typename T>
void readPod(std::istream& is, T& v) {
  is.read(reinterpret_cast<char*>(&v), sizeof(T));
}

// v2 added PqWalletOutput::unlockHeight. v3 added PqWalletOutput::depositIndex.
// v4 appended the PqWalletTransaction history. v5 appended PqWalletOutput::spentTxid
// (the tx that spent each output, so a dropped/rejected spend can be undone). Older
// blobs load with the missing fields defaulted (history empty / depositIndex primary
// / spentTxid zero) and repopulate on the next rescan.
constexpr uint8_t kPqStateFormatVersion = 5;

}  // namespace

WalletLedger::WalletLedger(const PqWalletKeys& keys)
    : m_scanKeys(pqScanKeys(keys)), m_spendPub(keys.spendPub), m_seedMaster(keys.seedMaster),
      m_hasSeedMaster(true) {}

WalletLedger::WalletLedger(const PqTrackingKeys& keys)
    : m_scanKeys(pqScanKeys(keys)), m_spendPub(keys.spendPub), m_seedMaster{},
      m_hasSeedMaster(false) {}

void WalletLedger::ensureDepositKeys(uint32_t count) {
  if (m_depositScheme != PqDepositScheme::AggregatedMultikey) {
    return;
  }
  if (!m_hasSeedMaster) {
    m_depositSpendPubs.clear();
    return;
  }
  for (uint32_t i = static_cast<uint32_t>(m_depositSpendPubs.size()); i < count; ++i) {
    m_depositSpendPubs.push_back(CryptoPQ::deriveDepositSpendKeys(m_seedMaster, i).first);
  }
}

void WalletLedger::setDepositConfig(PqDepositScheme scheme, uint32_t depositCount) {
  if (scheme != m_depositScheme) {
    m_depositSpendPubs.clear();  // scheme changed: any cached keys are stale
  }
  m_depositScheme = scheme;
  m_depositCount = depositCount;
  ensureDepositKeys(depositCount);
}

bool WalletLedger::processTransaction(const TransactionPrefix& tx, const Crypto::Hash& txid,
                                       uint32_t height, uint64_t timestamp) {
  // PQ outputs only ever appear in v2 (PQ-family) transactions.
  if (tx.version < TRANSACTION_VERSION_1) {
    return false;
  }

  bool affected = false;
  // Per-tx accounting for the history row (computed on first sight only).
  uint64_t debited = 0;       // owned outputs this tx spends (= our input total)
  uint64_t credited = 0;      // owned outputs this tx creates (incl. our change)
  uint64_t allOutputsSum = 0; // total of every PqOutput amount (for fee)

  // 1. Spend detection: a PqInput whose nullifier matches one of our owned
  //    outputs means that output is now spent.
  for (const auto& input : tx.inputs) {
    if (input.type() != typeid(PqInput)) {
      continue;  // only PqInputs spend PQ outputs (coinbase BaseInput etc. do not)
    }
    const PqInput& in = boost::get<PqInput>(input);
    if (in.authPub.size() != PQ_AUTH_PUB_SIZE || in.rhoReveal.size() != PQ_RHO_SIZE) {
      continue;
    }
    CryptoPQ::DsaPublicKey authPub;
    std::memcpy(authPub.data(), in.authPub.data(), authPub.size());
    CryptoPQ::Rho rho;
    std::memcpy(rho.data(), in.rhoReveal.data(), rho.size());
    CryptoPQ::Hash256 inPrevTxid;
    std::memcpy(inPrevTxid.data(), in.prevTxid.data, 32);
    Crypto::Hash nf = toHash(CryptoPQ::nullifier(authPub, rho, inPrevTxid, in.prevOutIndex));

    auto it = m_byNullifier.find(nf);
    if (it != m_byNullifier.end()) {
      PqWalletOutput& o = m_outputs[it->second];
      if (!o.spent) {
        o.spent = true;
        o.spentHeight = height;
        o.spentTxid = txid;       // remember which tx spent it (to undo on drop/reorg)
        debited += o.amount;
        affected = true;
      } else if (o.spentHeight == UNCONFIRMED_HEIGHT && height != UNCONFIRMED_HEIGHT &&
                 o.spentTxid == txid) {
        // Same spend, first seen in the mempool, now confirmed: promote its height
        // so reorg accounting (rollbackToHeight) treats it correctly. Do not touch
        // `debited` here — the history row already exists and is upserted below.
        o.spentHeight = height;
        affected = true;
      }
    }
  }

  // 2. Output recognition. inputsHash seeds every output's out_context; the
  //    wallet-side helper derives it from the tx's PqInputs.
  CryptoPQ::Hash256 ih = pqTransactionInputsHash(tx);
  for (uint32_t i = 0; i < tx.outputs.size(); ++i) {
    const TransactionOutput& out = tx.outputs[i];
    if (out.target.type() != typeid(PqOutput)) {
      continue;
    }
    const PqOutput& po = boost::get<PqOutput>(out.target);
    if (po.kemCt.size() != PQ_KEM_CIPHERTEXT_SIZE ||
        po.encPayload.size() != PQ_ENC_PAYLOAD_SIZE) {
      continue;
    }
    allOutputsSum += out.amount;  // every PQ output (for the fee of our own sends)

    CryptoPQ::PqScanOutput so;
    so.outputIndex = i;
    so.amount = out.amount;
    std::memcpy(so.kemCt.data(), po.kemCt.data(), so.kemCt.size());
    so.encPayload = po.encPayload;
    std::memcpy(so.spendCommit.data(), po.spendCommit.data, 32);

    // Recognize the output and attribute it to the right address/deposit.
    // ownerSpendPub is the spend public key the output commits to — it MUST be
    // used for the nullifier, because the future spending input will reveal that
    // same key (for a Spec-1 deposit that is the deposit key, not the primary).
    std::optional<CryptoPQ::PqOwnedOutput> owned;
    CryptoPQ::DsaPublicKey ownerSpendPub = m_spendPub;
    uint32_t depositIndex = PQ_PRIMARY_DEPOSIT;

    if (m_depositScheme == PqDepositScheme::SingleKeyIndex) {
      // One key pair; deposits are distinguished by the subaddress index T.
      // T=0 is the wallet's own address (and deposit #0); try every reserved T.
      uint32_t maxT = std::max(m_depositCount, 1u);
      for (uint32_t t = 0; t < maxT; ++t) {
        owned = CryptoPQ::scanPqOutput(m_scanKeys, ih, so, t);
        if (owned) {
          depositIndex = t;
          break;
        }
      }
    } else {
      // AggregatedMultikey: the wallet's own primary address (T=0), then the
      // shared-view-key deposit family routed by deposit spend key.
      owned = CryptoPQ::scanPqOutput(m_scanKeys, ih, so, 0);
      if (!owned && m_depositCount > 0) {
        ensureDepositKeys(m_depositCount);
        auto agg = m_depositSpendPubs.empty()
            ? std::optional<CryptoPQ::PqAggregateOwned>{}
            : CryptoPQ::scanPqOutputAggregate(m_scanKeys.viewSk, m_depositSpendPubs, ih, so);
        if (agg) {
          owned = agg->record;
          depositIndex = static_cast<uint32_t>(agg->spendPubIndex);
          ownerSpendPub = m_depositSpendPubs[agg->spendPubIndex];
        }
      }
    }

    if (!owned) {
      continue;  // not ours (or tampered) — silent, by design
    }

    // Skip if already recorded (idempotent re-scan of the same tx/output). The
    // watched nullifier binds this output's outpoint (txid, i) — the same value
    // the future spending input will produce.
    CryptoPQ::Hash256 ownTxid;
    std::memcpy(ownTxid.data(), txid.data, 32);
    Crypto::Hash nf = toHash(CryptoPQ::nullifier(ownerSpendPub, owned->rho, ownTxid, i));
    auto existing = m_byNullifier.find(nf);
    if (existing != m_byNullifier.end()) {
      // Already recorded (idempotent re-scan). If we first saw this output in the
      // mempool and now see its transaction confirmed, promote its height so it
      // moves out of the pending balance into the confirmed (spendable) balance.
      PqWalletOutput& o = m_outputs[existing->second];
      if (o.height == UNCONFIRMED_HEIGHT && height != UNCONFIRMED_HEIGHT) {
        o.height = height;
        o.unlockHeight = out.unlockHeight;
        affected = true;
      }
      continue;
    }

    PqWalletOutput rec;
    rec.txid = txid;
    rec.outputIndex = i;
    rec.amount = owned->amount;
    rec.rho = owned->rho;
    rec.nullifier = nf;
    rec.height = height;
    rec.unlockHeight = out.unlockHeight;  // per-output spend lock
    rec.spent = false;
    rec.depositIndex = depositIndex;
    m_byNullifier.emplace(nf, m_outputs.size());
    m_outputs.push_back(rec);
    credited += rec.amount;
    affected = true;
  }

  // 3. Transaction-history row. Upsert by txid so a pool sighting that later
  //    confirms updates in place rather than double-counting.
  auto hit = m_historyByTxid.find(txid);
  if (hit != m_historyByTxid.end()) {
    PqWalletTransaction& h = m_history[hit->second];
    if (h.height == UNCONFIRMED_HEIGHT && height != UNCONFIRMED_HEIGHT) {
      h.height = height;        // pool -> confirmed
      h.timestamp = timestamp;
      affected = true;
    }
  } else if (debited > 0 || credited > 0) {
    PqWalletTransaction h;
    h.txid = txid;
    h.height = height;
    h.timestamp = timestamp;
    h.outgoing = debited > 0;  // we spent at least one owned output
    if (h.outgoing) {
      // All inputs of a TX_PQ we sign are ours, so our input total == debited.
      // fee = inputs - outputs; net = what came back (change) minus what we spent.
      h.fee = debited >= allOutputsSum ? debited - allOutputsSum : 0;
      h.netAmount = static_cast<int64_t>(credited) - static_cast<int64_t>(debited);
    } else {
      h.fee = 0;
      h.netAmount = static_cast<int64_t>(credited);
    }
    m_historyByTxid.emplace(txid, m_history.size());
    m_history.push_back(h);
    affected = true;
  }

  return affected;
}

uint64_t WalletLedger::balance() const {
  uint64_t total = 0;
  for (const auto& o : m_outputs) {
    if (!o.spent) {
      total += o.amount;
    }
  }
  return total;
}

uint64_t WalletLedger::pendingBalance() const {
  uint64_t total = 0;
  for (const auto& o : m_outputs) {
    if (!o.spent && o.height == UNCONFIRMED_HEIGHT) {
      total += o.amount;
    }
  }
  return total;
}

uint64_t WalletLedger::spendableBalance() const {
  // Mirror the spendableInputs() filter exactly: an unspent output is offerable to
  // the spend path once it is confirmed (out of the mempool) and its unlockHeight
  // (0 = none) is reached at the scan tip.
  uint64_t total = 0;
  for (const auto& o : m_outputs) {
    if (o.spent) {
      continue;
    }
    if (o.height == UNCONFIRMED_HEIGHT) {
      continue;
    }
    if (o.unlockHeight != 0 && o.unlockHeight > m_lastScannedHeight) {
      continue;
    }
    total += o.amount;
  }
  return total;
}

const PqWalletTransaction* WalletLedger::historyByTxid(const Crypto::Hash& txid) const {
  auto it = m_historyByTxid.find(txid);
  return it == m_historyByTxid.end() ? nullptr : &m_history[it->second];
}

uint64_t WalletLedger::depositBalance(uint32_t depositIndex) const {
  uint64_t total = 0;
  for (const auto& o : m_outputs) {
    if (!o.spent && o.depositIndex == depositIndex) {
      total += o.amount;
    }
  }
  return total;
}

uint64_t WalletLedger::depositPendingBalance(uint32_t depositIndex) const {
  uint64_t total = 0;
  for (const auto& o : m_outputs) {
    if (!o.spent && o.depositIndex == depositIndex && o.height == UNCONFIRMED_HEIGHT) {
      total += o.amount;
    }
  }
  return total;
}

std::map<uint32_t, uint64_t> WalletLedger::depositBalances() const {
  std::map<uint32_t, uint64_t> out;
  for (const auto& o : m_outputs) {
    if (!o.spent && o.depositIndex != PQ_PRIMARY_DEPOSIT) {
      out[o.depositIndex] += o.amount;
    }
  }
  return out;
}

std::map<uint32_t, int64_t> WalletLedger::transfersByDeposit(const Crypto::Hash& txid) const {
  std::map<uint32_t, int64_t> out;
  for (const auto& o : m_outputs) {
    if (o.txid == txid) {
      out[o.depositIndex] += static_cast<int64_t>(o.amount);   // received into this bucket
    }
    if (o.spent && o.spentTxid == txid) {
      out[o.depositIndex] -= static_cast<int64_t>(o.amount);   // spent out of this bucket
    }
  }
  return out;
}

std::vector<PqSpendInput> WalletLedger::spendableInputs() const {
  std::vector<PqSpendInput> out;
  for (const auto& o : m_outputs) {
    if (o.spent) {
      continue;
    }
    // Still in the mempool (its tx not yet mined): not spendable. The network has no
    // confirmed outpoint to reference, so a tx spending it would be rejected at relay.
    // This is what makes rapid back-to-back sends (which would otherwise grab the
    // previous send's unconfirmed change) report "insufficient unlocked balance"
    // cleanly instead of building a doomed tx the daemon bounces.
    if (o.height == UNCONFIRMED_HEIGHT) {
      continue;
    }
    // Every owned output is spendable; the spend path picks the matching ML-DSA key
    // per input from its bucket (the primary key for primary outputs; under
    // AggregatedMultikey the per-deposit key for deposit outputs; under SingleKeyIndex
    // the one key for all). depositIndex carries the bucket so buildPqSend can do that.
    //
    // Per-output spend lock: do not offer an output the network would reject as
    // still locked. m_lastScannedHeight approximates the chain tip; an output
    // unlocks once the tip reaches its unlockHeight (0 = no lock). Conservative
    // by design — better to wait than to build a tx that fails consensus.
    if (o.unlockHeight != 0 && o.unlockHeight > m_lastScannedHeight) {
      continue;
    }
    PqSpendInput si;
    si.prevTxid = o.txid;
    si.prevOutIndex = o.outputIndex;
    si.amount = o.amount;
    si.rho = o.rho;
    si.depositIndex = o.depositIndex;
    out.push_back(si);
  }
  return out;
}

std::size_t WalletLedger::unspentCount() const {
  std::size_t n = 0;
  for (const auto& o : m_outputs) {
    if (!o.spent) ++n;
  }
  return n;
}

void WalletLedger::rollbackToHeight(uint32_t h) {
  // Un-spend outputs whose spend was seen at or above the rollback height.
  for (auto& o : m_outputs) {
    if (o.spent && o.spentHeight >= h) {
      o.spent = false;
      o.spentHeight = 0;
      o.spentTxid = Crypto::Hash{};
    }
  }
  // Drop confirmed outputs received at or above the rollback height, rebuilding
  // the index. Unconfirmed (mempool) outputs are not tied to an orphaned height,
  // so they survive — the driver re-feeds the pool anyway.
  std::vector<PqWalletOutput> kept;
  kept.reserve(m_outputs.size());
  for (auto& o : m_outputs) {
    if (o.height >= h && o.height != UNCONFIRMED_HEIGHT) {
      continue;  // orphaned
    }
    kept.push_back(o);
  }
  m_outputs = std::move(kept);
  m_byNullifier.clear();
  for (std::size_t i = 0; i < m_outputs.size(); ++i) {
    m_byNullifier.emplace(m_outputs[i].nullifier, i);
  }
  // Drop orphaned history rows the same way (confirmed at/above h); unconfirmed
  // rows survive (the driver re-feeds the pool), then rebuild the txid index.
  std::vector<PqWalletTransaction> keptH;
  keptH.reserve(m_history.size());
  for (auto& t : m_history) {
    if (t.height >= h && t.height != UNCONFIRMED_HEIGHT) {
      continue;  // orphaned
    }
    keptH.push_back(t);
  }
  m_history = std::move(keptH);
  m_historyByTxid.clear();
  for (std::size_t i = 0; i < m_history.size(); ++i) {
    m_historyByTxid.emplace(m_history[i].txid, i);
  }
  if (m_lastScannedHeight >= h && h > 0) {
    m_lastScannedHeight = h - 1;
  }
}

void WalletLedger::removeUnconfirmedTransaction(const Crypto::Hash& txid) {
  // A transaction that left the mempool WITHOUT being mined (evicted, rejected,
  // replaced, double-spent) must have its still-UNCONFIRMED effects undone.
  // Confirmed effects are permanent and untouched: a mined tx is also removed from
  // the pool, but by then its outputs/spends carry a real height, so the guards
  // below (== UNCONFIRMED_HEIGHT) skip them. Mirrors the classical
  // TransfersContainer::deleteUnconfirmedTransaction.

  // 1. Un-spend any owned outputs this tx spent while it was unconfirmed.
  for (auto& o : m_outputs) {
    if (o.spent && o.spentHeight == UNCONFIRMED_HEIGHT && o.spentTxid == txid) {
      o.spent = false;
      o.spentHeight = 0;
      o.spentTxid = Crypto::Hash{};
    }
  }

  // 2. Drop unconfirmed received outputs this tx created (e.g. an incoming payment
  //    still in the pool, or the change of our own now-dropped send).
  std::vector<PqWalletOutput> kept;
  kept.reserve(m_outputs.size());
  for (auto& o : m_outputs) {
    if (o.height == UNCONFIRMED_HEIGHT && o.txid == txid) {
      continue;  // orphaned mempool receive
    }
    kept.push_back(o);
  }
  if (kept.size() != m_outputs.size()) {
    m_outputs = std::move(kept);
    m_byNullifier.clear();
    for (std::size_t i = 0; i < m_outputs.size(); ++i) {
      m_byNullifier.emplace(m_outputs[i].nullifier, i);
    }
  }

  // 3. Drop the history row only if it is still unconfirmed.
  auto hit = m_historyByTxid.find(txid);
  if (hit != m_historyByTxid.end() && m_history[hit->second].height == UNCONFIRMED_HEIGHT) {
    m_history.erase(m_history.begin() + static_cast<std::ptrdiff_t>(hit->second));
    m_historyByTxid.clear();
    for (std::size_t i = 0; i < m_history.size(); ++i) {
      m_historyByTxid.emplace(m_history[i].txid, i);
    }
  }
}

void WalletLedger::save(std::ostream& os) const {
  writePod(os, kPqStateFormatVersion);
  writePod(os, m_lastScannedHeight);
  uint64_t count = m_outputs.size();
  writePod(os, count);
  for (const auto& o : m_outputs) {
    os.write(reinterpret_cast<const char*>(o.txid.data), 32);
    writePod(os, o.outputIndex);
    writePod(os, o.amount);
    os.write(reinterpret_cast<const char*>(o.rho.data()), 32);
    os.write(reinterpret_cast<const char*>(o.nullifier.data), 32);
    writePod(os, o.height);
    writePod(os, o.unlockHeight);
    uint8_t spent = o.spent ? 1 : 0;
    writePod(os, spent);
    writePod(os, o.spentHeight);
    writePod(os, o.depositIndex);
    os.write(reinterpret_cast<const char*>(o.spentTxid.data), 32);  // v5
  }
  // v4: transaction history.
  uint64_t hcount = m_history.size();
  writePod(os, hcount);
  for (const auto& t : m_history) {
    os.write(reinterpret_cast<const char*>(t.txid.data), 32);
    writePod(os, t.height);
    writePod(os, t.timestamp);
    writePod(os, t.netAmount);
    writePod(os, t.fee);
    uint8_t outgoing = t.outgoing ? 1 : 0;
    writePod(os, outgoing);
  }
}

void WalletLedger::load(std::istream& is) {
  m_outputs.clear();
  m_byNullifier.clear();
  m_history.clear();
  m_historyByTxid.clear();
  m_lastScannedHeight = 0;

  uint8_t version = 0;
  readPod(is, version);
  // Accept v2 (no depositIndex), v3 (no history), v4 (no spentTxid), and the current
  // v5. Missing fields default (depositIndex = PQ_PRIMARY_DEPOSIT, empty history,
  // spentTxid = zero) and repopulate on rescan. Anything older/unknown -> start empty.
  if (!is || (version != 2 && version != 3 && version != 4 && version != kPqStateFormatVersion)) {
    m_outputs.clear();
    m_byNullifier.clear();
    m_history.clear();
    m_historyByTxid.clear();
    m_lastScannedHeight = 0;
    return;
  }
  readPod(is, m_lastScannedHeight);
  uint64_t count = 0;
  readPod(is, count);
  for (uint64_t i = 0; i < count && is; ++i) {
    PqWalletOutput o;
    is.read(reinterpret_cast<char*>(o.txid.data), 32);
    readPod(is, o.outputIndex);
    readPod(is, o.amount);
    is.read(reinterpret_cast<char*>(o.rho.data()), 32);
    is.read(reinterpret_cast<char*>(o.nullifier.data), 32);
    readPod(is, o.height);
    readPod(is, o.unlockHeight);
    uint8_t spent = 0;
    readPod(is, spent);
    o.spent = spent != 0;
    readPod(is, o.spentHeight);
    if (version >= 3) {
      readPod(is, o.depositIndex);
    } else {
      o.depositIndex = PQ_PRIMARY_DEPOSIT;  // v2 had no deposits
    }
    if (version >= 5) {
      is.read(reinterpret_cast<char*>(o.spentTxid.data), 32);
    } else {
      o.spentTxid = Crypto::Hash{};  // pre-v5 did not record the spending tx
    }
    if (!is) break;
    m_byNullifier.emplace(o.nullifier, m_outputs.size());
    m_outputs.push_back(o);
  }

  // v4: transaction history (absent in v2/v3 -> leave empty).
  if (version >= 4) {
    uint64_t hcount = 0;
    readPod(is, hcount);
    for (uint64_t i = 0; i < hcount && is; ++i) {
      PqWalletTransaction t;
      is.read(reinterpret_cast<char*>(t.txid.data), 32);
      readPod(is, t.height);
      readPod(is, t.timestamp);
      readPod(is, t.netAmount);
      readPod(is, t.fee);
      uint8_t outgoing = 0;
      readPod(is, outgoing);
      t.outgoing = outgoing != 0;
      if (!is) break;
      m_historyByTxid.emplace(t.txid, m_history.size());
      m_history.push_back(t);
    }
  }
}

}  // namespace CryptoNote
