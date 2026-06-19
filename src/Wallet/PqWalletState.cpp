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

#include "PqWalletState.h"

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
// Older blobs load with depositIndex = PQ_PRIMARY_DEPOSIT (their only address).
constexpr uint8_t kPqStateFormatVersion = 3;

}  // namespace

PqWalletState::PqWalletState(const PqWalletKeys& keys)
    : m_scanKeys(pqScanKeys(keys)), m_spendPub(keys.spendPub), m_seedMaster(keys.seedMaster) {}

void PqWalletState::ensureDepositKeys(uint32_t count) {
  if (m_depositScheme != PqDepositScheme::AggregatedMultikey) {
    return;
  }
  for (uint32_t i = static_cast<uint32_t>(m_depositSpendPubs.size()); i < count; ++i) {
    m_depositSpendPubs.push_back(CryptoPQ::deriveDepositSpendKeys(m_seedMaster, i).first);
  }
}

void PqWalletState::setDepositConfig(PqDepositScheme scheme, uint32_t depositCount) {
  if (scheme != m_depositScheme) {
    m_depositSpendPubs.clear();  // scheme changed: any cached keys are stale
  }
  m_depositScheme = scheme;
  m_depositCount = depositCount;
  ensureDepositKeys(depositCount);
}

bool PqWalletState::processTransaction(const TransactionPrefix& tx, const Crypto::Hash& txid,
                                       uint32_t height) {
  // PQ outputs only ever appear in v2 (PQ-family) transactions.
  if (tx.version < TRANSACTION_VERSION_1) {
    return false;
  }

  bool affected = false;

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
        auto agg = CryptoPQ::scanPqOutputAggregate(m_scanKeys.viewSk, m_depositSpendPubs, ih, so);
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
    if (m_byNullifier.count(nf)) {
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
    affected = true;
  }

  return affected;
}

uint64_t PqWalletState::balance() const {
  uint64_t total = 0;
  for (const auto& o : m_outputs) {
    if (!o.spent) {
      total += o.amount;
    }
  }
  return total;
}

uint64_t PqWalletState::depositBalance(uint32_t depositIndex) const {
  uint64_t total = 0;
  for (const auto& o : m_outputs) {
    if (!o.spent && o.depositIndex == depositIndex) {
      total += o.amount;
    }
  }
  return total;
}

std::map<uint32_t, uint64_t> PqWalletState::depositBalances() const {
  std::map<uint32_t, uint64_t> out;
  for (const auto& o : m_outputs) {
    if (!o.spent && o.depositIndex != PQ_PRIMARY_DEPOSIT) {
      out[o.depositIndex] += o.amount;
    }
  }
  return out;
}

std::vector<PqSpendInput> PqWalletState::spendableInputs() const {
  std::vector<PqSpendInput> out;
  for (const auto& o : m_outputs) {
    if (o.spent) {
      continue;
    }
    // Spend-authority filter: this list is signed with the wallet's PRIMARY
    // ML-DSA spend key. Under AggregatedMultikey a deposit output commits to a
    // distinct per-deposit spend key, so it cannot be signed here — exclude it
    // (it is swept via its own deposit key). Under SingleKeyIndex every output,
    // including deposits, is spendable by the one key, so all are offered.
    if (m_depositScheme == PqDepositScheme::AggregatedMultikey &&
        o.depositIndex != PQ_PRIMARY_DEPOSIT) {
      continue;
    }
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
    out.push_back(si);
  }
  return out;
}

std::size_t PqWalletState::unspentCount() const {
  std::size_t n = 0;
  for (const auto& o : m_outputs) {
    if (!o.spent) ++n;
  }
  return n;
}

void PqWalletState::rollbackToHeight(uint32_t h) {
  // Un-spend outputs whose spend was seen at or above the rollback height.
  for (auto& o : m_outputs) {
    if (o.spent && o.spentHeight >= h) {
      o.spent = false;
      o.spentHeight = 0;
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
  if (m_lastScannedHeight >= h && h > 0) {
    m_lastScannedHeight = h - 1;
  }
}

void PqWalletState::save(std::ostream& os) const {
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
  }
}

void PqWalletState::load(std::istream& is) {
  m_outputs.clear();
  m_byNullifier.clear();
  m_lastScannedHeight = 0;

  uint8_t version = 0;
  readPod(is, version);
  // v2 lacked PqWalletOutput::depositIndex (single-address wallets only); load it
  // with depositIndex = PQ_PRIMARY_DEPOSIT. Anything older/unknown -> start empty.
  if (!is || (version != kPqStateFormatVersion && version != 2)) {
    m_outputs.clear();
    m_byNullifier.clear();
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
    if (!is) break;
    m_byNullifier.emplace(o.nullifier, m_outputs.size());
    m_outputs.push_back(o);
  }
}

}  // namespace CryptoNote
