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

#include "PqSender.h"

#include <algorithm>

#include "Denominations.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"  // toBinaryArray

namespace CryptoNote {

namespace {

namespace P = CryptoNote::parameters;

// A payee plus the canonical denominations that make up its amount. Coarsening
// merges denominations within a group (never across payees).
struct OutputGroup {
  PqSendOutput          tmpl;    // recipient keys/T/unlockHeight; amount overwritten per slot
  std::vector<uint64_t> denoms;  // canonical pieces, sum == the payee's amount
};

// Greedily append inputs (already sorted descending by amount) until the running
// sum covers `target` or MAX_PQ_INPUTS_PER_TX is reached. `selected` is always a
// prefix of `sortedDesc`, so resumption just continues from its current length.
uint64_t growSelection(const std::vector<PqSpendInput>& sortedDesc,
                       std::vector<PqSpendInput>& selected, uint64_t sumIn, uint64_t target) {
  for (std::size_t i = selected.size();
       sumIn < target && selected.size() < P::MAX_PQ_INPUTS_PER_TX && i < sortedDesc.size();
       ++i) {
    selected.push_back(sortedDesc[i]);
    sumIn += sortedDesc[i].amount;
  }
  return sumIn;
}

// Build the payee groups (recipients + optional change to own primary), then coarsen
// by merging the two smallest denominations of the largest group until the total
// output count fits `maxOut`. Throws TooLarge if it cannot (every group already a
// single output, yet still over the cap). Returns the flattened PqSendOutput list.
std::vector<PqSendOutput> decomposeOutputs(const std::vector<PqSendOutput>& recipients,
                                           uint64_t change, const PqWalletKeys& keys,
                                           std::size_t maxOut) {
  std::vector<OutputGroup> groups;
  groups.reserve(recipients.size() + 1);
  for (const auto& r : recipients) {
    OutputGroup g;
    g.tmpl = r;
    g.denoms = decomposeToDenominations(r.amount);
    groups.push_back(std::move(g));
  }
  if (change > 0) {
    OutputGroup g;
    g.tmpl = PqSendOutput{keys.viewPub, keys.spendPub, 0 /*amount per slot*/, 0 /*T*/, 0 /*unlock*/};
    g.denoms = decomposeToDenominations(change);
    groups.push_back(std::move(g));
  }

  const std::size_t numDest = groups.size();
  if (maxOut < numDest) {
    throw PqSendError(PqSendErrorCode::TooLarge,
                      "too many outputs for one PQ transaction; split into smaller transfers");
  }

  auto total = [&groups]() {
    std::size_t n = 0;
    for (const auto& g : groups) n += g.denoms.size();
    return n;
  };
  while (total() > maxOut) {
    // Merge the two smallest denominations of the group with the most pieces.
    std::size_t best = 0;
    for (std::size_t i = 1; i < groups.size(); ++i) {
      if (groups[i].denoms.size() > groups[best].denoms.size()) best = i;
    }
    auto& d = groups[best].denoms;
    if (d.size() < 2) {
      // Should not happen (numDest <= maxOut guarantees a mergeable group exists).
      throw PqSendError(PqSendErrorCode::TooLarge, "cannot coarsen PQ outputs to fit");
    }
    std::sort(d.begin(), d.end());
    uint64_t merged = d[0] + d[1];  // may be non-canonical; consensus accepts any non-zero amount
    d.erase(d.begin(), d.begin() + 2);
    d.push_back(merged);
  }

  std::vector<PqSendOutput> outs;
  for (const auto& g : groups) {
    for (uint64_t v : g.denoms) {
      PqSendOutput o = g.tmpl;
      o.amount = v;
      outs.push_back(o);
    }
  }
  return outs;
}

// Build (and sign) a draft for the given change, shrinking the output cap until the
// serialized size is within MAX_PQ_TX_SIZE. Returns the signed transaction.
Transaction buildFitting(const std::vector<PqSpendInput>& selected,
                         const std::vector<PqSendOutput>& recipients, uint64_t change,
                         const PqWalletKeys& keys, uint64_t unlockHeight,
                         const std::vector<uint8_t>& extra) {
  std::size_t numDest = recipients.size() + (change > 0 ? 1 : 0);
  std::size_t maxOut = P::MAX_PQ_OUTPUTS_PER_TX;
  for (;;) {
    std::vector<PqSendOutput> outs = decomposeOutputs(recipients, change, keys, maxOut);
    Transaction tx = buildPqTransaction(selected, outs, keys.spendPub, keys.spendSk, unlockHeight, extra);
    if (toBinaryArray(tx).size() <= P::MAX_PQ_TX_SIZE) {
      return tx;
    }
    if (maxOut <= numDest) {
      throw PqSendError(PqSendErrorCode::TooLarge,
                        "PQ transaction exceeds the size limit; split into smaller transfers");
    }
    --maxOut;
  }
}

}  // namespace

PqSendResult buildPqSend(const std::vector<PqSpendInput>& available,
                         const PqWalletKeys& keys,
                         const PqSendRequest& req) {
  if (req.recipients.empty()) {
    throw PqSendError(PqSendErrorCode::NoRecipients, "no recipients");
  }
  uint64_t sent = 0;
  for (const auto& r : req.recipients) {
    if (r.amount == 0) {
      throw PqSendError(PqSendErrorCode::ZeroAmount, "zero-amount recipient");
    }
    if (sent + r.amount < sent) {
      throw PqSendError(PqSendErrorCode::TooLarge, "recipient amount overflow");
    }
    sent += r.amount;
  }

  // Deterministic input selection: largest first.
  std::vector<PqSpendInput> sorted = available;
  std::sort(sorted.begin(), sorted.end(),
            [](const PqSpendInput& a, const PqSpendInput& b) { return a.amount > b.amount; });

  std::vector<PqSpendInput> selected;
  uint64_t sumIn = growSelection(sorted, selected, 0, sent);
  if (sumIn < sent) {
    throw PqSendError(PqSendErrorCode::InsufficientFunds, "insufficient PQ balance");
  }

  // Two-pass fee with a fixed point: raising the fee shrinks the change (never grows
  // the tx), so the measured floor is monotonically non-increasing and converges.
  uint64_t fee = req.explicitFee;
  Transaction tx;
  for (int iter = 0; iter < 8; ++iter) {
    if (sumIn < sent + fee) {
      sumIn = growSelection(sorted, selected, sumIn, sent + fee);
      if (sumIn < sent + fee) {
        throw PqSendError(PqSendErrorCode::InsufficientFunds,
                          "insufficient PQ balance to cover the fee");
      }
    }
    uint64_t change = sumIn - sent - fee;
    tx = buildFitting(selected, req.recipients, change, keys, req.unlockHeight, req.extra);
    if (req.explicitFee != 0) {
      break;  // caller fixed the fee
    }
    uint64_t size = toBinaryArray(tx).size();
    uint64_t floor = (size * P::MIN_PQ_FEE_PER_1000_BYTES + 999) / 1000 + 1;
    if (fee >= floor) {
      break;  // fee covers the floor for the final size
    }
    fee = floor;
  }
  if (sumIn < sent + fee) {
    throw PqSendError(PqSendErrorCode::InsufficientFunds, "insufficient PQ balance to cover the fee");
  }

  PqSendResult result;
  result.tx = std::move(tx);
  result.fee = fee;
  result.sent = sent;
  result.change = sumIn - sent - fee;
  result.selected = std::move(selected);
  return result;
}

}  // namespace CryptoNote
