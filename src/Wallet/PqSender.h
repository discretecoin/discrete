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

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "PqWallet.h"               // PqWalletKeys
#include "PqTransactionBuilder.h"   // PqSpendInput, PqSendOutput
#include "crypto_pq/PqPaymentProof.h"

// The single, engine-agnostic PQ spend path shared by BOTH wallet engines
// (WalletLegacy/simplewallet and WalletGreen/greenwallet/walletd). All deterministic
// policy — input selection order, canonical denomination decomposition, two-pass fee
// rounding, change handling, signing — lives here so the front-ends can never drift.
// It performs NO I/O and touches no node: the caller relays the returned transaction.

namespace CryptoNote {

// One recipient with the lump amount to pay. buildPqSend decomposes the amount into
// canonical denominations (Denominations.h) and may emit several outputs per recipient.
struct PqSendRequest {
  std::vector<PqSendOutput> recipients;  // each .amount is the lump to that recipient
  uint64_t explicitFee = 0;              // 0 = auto (two-pass measured fee)
  uint64_t unlockHeight = 0;             // legacy API tx-level lock; TX_PQ requires 0
  std::vector<uint8_t> extra;            // tx.extra (e.g. a PQ account registration tag)
  CryptoPQ::Hash256 genesisId{};         // network binding embedded in every proof

  // Deposit scheme: decides each input's signing key. Under SingleKeyIndex the one
  // ML-DSA key authorizes every input; under AggregatedMultikey a deposit input is
  // signed with deriveDepositSpendKeys(seedMaster, depositIndex). `keys` must carry a
  // usable seedMaster for AggregatedMultikey deposit spends.
  PqDepositScheme scheme = PqDepositScheme::AggregatedMultikey;

  // Restrict the spend to these source buckets (depositIndex values; PQ_PRIMARY_DEPOSIT
  // = primary). Empty = spend from any bucket. Lets a caller spend only from a specific
  // deposit / address index.
  std::vector<uint32_t> sourceBuckets;

  // Where change (if any) is sent. When hasChangeDest is false (default) change returns
  // to the primary identity (`keys`) — correct for a single-address wallet. The
  // front-end sets it to route change to a specific address/deposit per the
  // change-destination rule (CryptoNote getChangeDestination). `changeDest.amount` is
  // ignored (filled per denomination slot).
  bool hasChangeDest = false;
  PqSendOutput changeDest;
};

struct PqSendResult {
  Transaction               tx;
  uint64_t                  fee = 0;
  uint64_t                  sent = 0;     // sum of recipient amounts (excl. fee/change)
  uint64_t                  change = 0;
  std::vector<PqSpendInput> selected;     // inputs actually spent
  std::vector<PqPaymentProof> proofs;     // exactly one per request recipient row
};

enum class PqSendErrorCode {
  NoRecipients,
  ZeroAmount,
  InsufficientFunds,
  TooLarge,
  UnsupportedUnlockHeight
};

struct PqSendError : std::runtime_error {
  PqSendErrorCode code;
  PqSendError(PqSendErrorCode c, const std::string& msg) : std::runtime_error(msg), code(c) {}
};

// Build (and sign) a TX_PQ paying `req.recipients` from `available`, owned by `keys`.
// Deterministic; throws PqSendError on no/zero recipients, unsupported tx-level
// unlockHeight, insufficient funds, or a transaction that cannot be made to fit
// the consensus caps. Use PqSendOutput::unlockHeight for per-output locks.
// Change returns to the wallet's own primary address. The caller relays result.tx.
PqSendResult buildPqSend(const std::vector<PqSpendInput>& available,
                         const PqWalletKeys& keys,
                         const PqSendRequest& req);

}  // namespace CryptoNote
