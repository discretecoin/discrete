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

#include <cstring>
#include <istream>
#include <ostream>

#include "CryptoNoteConfig.h"
#include "PqTxType.h"
#include "crypto_pq/PqScan.h"
#include "crypto_pq/PqDerive.h"

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

constexpr uint8_t kPqStateFormatVersion = 1;

}  // namespace

PqWalletState::PqWalletState(const PqWalletKeys& keys)
    : m_scanKeys(pqScanKeys(keys)), m_spendPub(keys.spendPub) {}

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
      continue;  // bridge KeyInputs never spend PQ outputs
    }
    const PqInput& in = boost::get<PqInput>(input);
    if (in.authPub.size() != PQ_AUTH_PUB_SIZE || in.rhoReveal.size() != PQ_RHO_SIZE) {
      continue;
    }
    CryptoPQ::DsaPublicKey authPub;
    std::memcpy(authPub.data(), in.authPub.data(), authPub.size());
    CryptoPQ::Rho rho;
    std::memcpy(rho.data(), in.rhoReveal.data(), rho.size());
    Crypto::Hash nf = toHash(CryptoPQ::nullifier(authPub, rho));

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
  //    wallet-side helper handles both TX_PQ (PqInput) and TX_BRIDGE (KeyInput).
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

    auto owned = CryptoPQ::scanPqOutput(m_scanKeys, ih, so);
    if (!owned) {
      continue;  // not ours (or tampered) — silent, by design
    }

    // Skip if already recorded (idempotent re-scan of the same tx/output).
    Crypto::Hash nf = toHash(CryptoPQ::nullifier(m_spendPub, owned->rho));
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
    rec.spent = false;
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

std::vector<PqSpendInput> PqWalletState::spendableInputs() const {
  std::vector<PqSpendInput> out;
  for (const auto& o : m_outputs) {
    if (o.spent) {
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
    uint8_t spent = o.spent ? 1 : 0;
    writePod(os, spent);
    writePod(os, o.spentHeight);
  }
}

void PqWalletState::load(std::istream& is) {
  m_outputs.clear();
  m_byNullifier.clear();
  m_lastScannedHeight = 0;

  uint8_t version = 0;
  readPod(is, version);
  if (!is || version != kPqStateFormatVersion) {
    // Unknown/absent format -> start empty; the consumer will rescan.
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
    uint8_t spent = 0;
    readPod(is, spent);
    o.spent = spent != 0;
    readPod(is, o.spentHeight);
    if (!is) break;
    m_byNullifier.emplace(o.nullifier, m_outputs.size());
    m_outputs.push_back(o);
  }
}

}  // namespace CryptoNote
