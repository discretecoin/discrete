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

#include "PqSender.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <unordered_set>

#include "Common/SecureMemory.h"
#include "Denominations.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"  // toBinaryArray
#include "crypto_pq/PqSeed.h"                 // deriveDepositSpendKeys

namespace CryptoNote {

namespace {

namespace P = CryptoNote::parameters;

// A payee plus the canonical denominations that make up its amount. Coarsening
// merges denominations within a group (never across payees).
struct OutputGroup {
  PqSendOutput          tmpl;    // recipient keys/T/unlockHeight; amount overwritten per slot
  std::vector<uint64_t> denoms;  // canonical pieces, sum == the payee's amount
  std::optional<std::size_t> recipientIndex;  // absent only for change
};

struct ProvenancedOutput {
  PqSendOutput output;
  std::optional<std::size_t> recipientIndex;
};

struct FittingBuild {
  PqTransactionBuildResult transaction;
  std::vector<std::optional<std::size_t>> recipientIndexes;
};

// Greedily append inputs (already sorted descending by amount) until the running
// sum covers `target` or MAX_PQ_INPUTS_PER_TX is reached. `selected` is always a
// prefix of `sortedDesc`, so resumption just continues from its current length.
uint64_t growSelection(const std::vector<PqSpendInput>& sortedDesc,
                       std::vector<PqSpendInput>& selected, uint64_t sumIn, uint64_t target) {
  for (std::size_t i = selected.size();
       sumIn < target && selected.size() < P::MAX_PQ_INPUTS_PER_TX && i < sortedDesc.size();
       ++i) {
    if (sumIn > std::numeric_limits<uint64_t>::max() - sortedDesc[i].amount) {
      throw PqSendError(PqSendErrorCode::TooLarge, "input amount overflow");
    }
    selected.push_back(sortedDesc[i]);
    sumIn += sortedDesc[i].amount;
  }
  return sumIn;
}

// Build the payee groups (recipients + optional change to own primary), then coarsen
// by merging the two smallest denominations of the largest group until the total
// output count fits `maxOut`. Throws TooLarge if it cannot (every group already a
// single output, yet still over the cap). Returns the flattened PqSendOutput list.
std::vector<ProvenancedOutput> decomposeOutputs(
    const std::vector<PqSendOutput>& recipients,
    uint64_t change, const PqSendOutput& changeTmpl,
    std::size_t maxOut) {
  std::vector<OutputGroup> groups;
  groups.reserve(recipients.size() + 1);
  for (std::size_t recipientIndex = 0; recipientIndex < recipients.size(); ++recipientIndex) {
    const auto& r = recipients[recipientIndex];
    OutputGroup g;
    g.tmpl = r;
    g.denoms = decomposeToDenominations(r.amount);
    g.recipientIndex = recipientIndex;
    groups.push_back(std::move(g));
  }
  if (change > 0) {
    OutputGroup g;
    g.tmpl = changeTmpl;
    g.tmpl.amount = 0;  // filled per denomination slot
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

  std::vector<ProvenancedOutput> outs;
  for (const auto& g : groups) {
    for (uint64_t v : g.denoms) {
      PqSendOutput o = g.tmpl;
      o.amount = v;
      outs.push_back({std::move(o), g.recipientIndex});
    }
  }
  return outs;
}

// Build (and sign) a draft for the given change, shrinking the output cap until the
// serialized size is within MAX_PQ_TX_SIZE. Returns the signed transaction.
FittingBuild buildFitting(const std::vector<PqSpendInput>& selected,
                          const std::vector<PqInputAuth>& inputAuth,
                          const std::vector<PqSendOutput>& recipients, uint64_t change,
                          const PqSendOutput& changeTmpl,
                          const std::vector<uint8_t>& extra) {
  std::size_t numDest = recipients.size() + (change > 0 ? 1 : 0);
  std::size_t maxOut = P::MAX_PQ_OUTPUTS_PER_TX;
  for (;;) {
    std::vector<ProvenancedOutput> provenanced =
        decomposeOutputs(recipients, change, changeTmpl, maxOut);
    std::vector<PqSendOutput> outputs;
    std::vector<std::optional<std::size_t>> recipientIndexes;
    outputs.reserve(provenanced.size());
    recipientIndexes.reserve(provenanced.size());
    for (auto& output : provenanced) {
      outputs.push_back(std::move(output.output));
      recipientIndexes.push_back(output.recipientIndex);
    }
    PqTransactionBuildResult draft =
        buildPqTransactionWithProof(selected, outputs, inputAuth, 0, extra);
    if (toBinaryArray(draft.tx).size() <= P::MAX_PQ_TX_SIZE) {
      FittingBuild accepted;
      accepted.transaction = std::move(draft);
      accepted.recipientIndexes = std::move(recipientIndexes);
      return accepted;
    }
    // The draft and its rho openings are one owner. Wipe before rebuilding with a
    // smaller output cap; no stale rho can survive into the accepted transaction.
    draft.clearWitnesses();
    if (maxOut <= numDest) {
      throw PqSendError(PqSendErrorCode::TooLarge,
                        "transaction exceeds the size limit; split into smaller transfers");
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
  if (req.unlockHeight != 0) {
    throw PqSendError(PqSendErrorCode::UnsupportedUnlockHeight,
                      "TX_PQ does not support tx-level unlockHeight; use per-output unlockHeight");
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

  // Optional source filter: keep only inputs from the requested buckets (deposit
  // indices / PQ_PRIMARY_DEPOSIT). Empty = spend from any bucket.
  std::vector<PqSpendInput> sorted;
  if (req.sourceBuckets.empty()) {
    sorted = available;
  } else {
    std::unordered_set<uint32_t> want(req.sourceBuckets.begin(), req.sourceBuckets.end());
    for (const auto& si : available) {
      if (want.count(si.depositIndex) != 0) {
        sorted.push_back(si);
      }
    }
  }
  // Deterministic input selection: largest first.
  std::sort(sorted.begin(), sorted.end(),
            [](const PqSpendInput& a, const PqSpendInput& b) { return a.amount > b.amount; });

  // Per-input signing key, by bucket. Keep all copies in one contiguous,
  // page-locked vector and scrub it after the transaction has been signed.
  // PqInputAuth also scrubs individual temporaries and reallocated elements.
  auto authForSelection = [&keys, &req](const std::vector<PqSpendInput>& sel) {
    std::vector<PqInputAuth> auth;
    auth.reserve(sel.size());
    for (const auto& si : sel) {
      auth.emplace_back();
      PqInputAuth& entry = auth.back();
      if (req.scheme == PqDepositScheme::SingleKeyIndex ||
          si.depositIndex == PQ_PRIMARY_DEPOSIT) {
        entry.spendPub = keys.spendPub;
        entry.spendSk = keys.spendSk;
      } else {
        auto derived = CryptoPQ::deriveDepositSpendKeys(keys.seedMaster, si.depositIndex);
        Tools::SecretLock scrubDerived(derived.second.data(), derived.second.size());
        entry.spendPub = derived.first;
        entry.spendSk = derived.second;
      }
    }
    return auth;
  };

  // Change destination: the caller's choice, else the primary identity (single-address
  // default). The amount is filled per slot in decomposeOutputs.
  PqSendOutput changeTmpl = req.hasChangeDest
                                ? req.changeDest
                                : PqSendOutput{keys.viewPub, keys.spendPub, 0, 0, 0};

  // Total spendable funds across all unlocked inputs. growSelection can only take up
  // to MAX_PQ_INPUTS_PER_TX of them, so distinguish "no funds" from "funds exist but
  // need more inputs than one tx allows" — the latter is not an insufficient balance.
  uint64_t totalAvail = 0;
  for (const auto& si : sorted) {
    if (totalAvail > std::numeric_limits<uint64_t>::max() - si.amount) {
      totalAvail = std::numeric_limits<uint64_t>::max();
      break;
    }
    totalAvail += si.amount;
  }
  auto shortfall = [&totalAvail](uint64_t need) -> PqSendError {
    if (totalAvail >= need) {
      return PqSendError(PqSendErrorCode::TooLarge,
        "amount is too large to send in one transaction (it would need more than " +
        std::to_string(P::MAX_PQ_INPUTS_PER_TX) +
        " inputs); send a smaller amount, or consolidate your outputs first");
    }
    // `sorted` holds only spendable (unlocked) inputs, so a true shortfall means the
    // unlocked balance is too small — typically coinbase still maturing.
    return PqSendError(PqSendErrorCode::InsufficientFunds, "insufficient unlocked balance");
  };

  std::vector<PqSpendInput> selected;
  uint64_t sumIn = growSelection(sorted, selected, 0, sent);
  if (sumIn < sent) {
    throw shortfall(sent);
  }

  // Flat fee: MINIMUM_FEE plus the tx_extra surcharge. It is exact up front,
  // so coin selection needs no size-measurement fixed point.
  uint64_t fee = req.explicitFee != 0
                     ? req.explicitFee
                     : P::pqTxFeeFloor(P::MINIMUM_FEE, req.extra.size());
  if (sent > std::numeric_limits<uint64_t>::max() - fee) {
    throw PqSendError(PqSendErrorCode::TooLarge, "payment plus fee overflow");
  }
  const uint64_t required = sent + fee;
  if (sumIn < required) {
    sumIn = growSelection(sorted, selected, sumIn, required);
    if (sumIn < required) {
      throw shortfall(required);
    }
  }
  uint64_t change = sumIn - sent - fee;
  std::vector<PqInputAuth> inputAuth = authForSelection(selected);
  Tools::SecretLock scrubAuth(
      inputAuth.data(), inputAuth.size() * sizeof(PqInputAuth));
  FittingBuild finalBuild = buildFitting(
      selected, inputAuth, req.recipients, change,
      changeTmpl, req.extra);

  if (finalBuild.recipientIndexes.size() != finalBuild.transaction.tx.outputs.size() ||
      finalBuild.transaction.outputRhos.size() != finalBuild.transaction.tx.outputs.size()) {
    throw std::runtime_error("buildPqSend: output provenance/opening mismatch");
  }

  const PqPaymentProofTransaction proofTx =
      makePqPaymentProofTransaction(finalBuild.transaction.tx);
  std::vector<std::vector<PqPaymentProofEntry>> proofEntries(req.recipients.size());
  std::vector<uint64_t> proofAmounts(req.recipients.size(), 0);
  for (std::size_t outputIndex = 0;
       outputIndex < finalBuild.transaction.tx.outputs.size(); ++outputIndex) {
    const auto recipientIndex = finalBuild.recipientIndexes[outputIndex];
    if (!recipientIndex) continue;  // change is intentionally never proven
    if (*recipientIndex >= req.recipients.size()) {
      throw std::runtime_error("buildPqSend: invalid recipient provenance");
    }
    proofEntries[*recipientIndex].push_back({
        static_cast<uint32_t>(outputIndex),
        finalBuild.transaction.outputRhos[outputIndex]});
    const uint64_t amount = finalBuild.transaction.tx.outputs[outputIndex].amount;
    if (proofAmounts[*recipientIndex] + amount < proofAmounts[*recipientIndex]) {
      throw std::runtime_error("buildPqSend: proof amount overflow");
    }
    proofAmounts[*recipientIndex] += amount;
  }

  std::vector<PqPaymentProof> proofs;
  proofs.reserve(req.recipients.size());
  for (std::size_t recipientIndex = 0;
       recipientIndex < req.recipients.size(); ++recipientIndex) {
    if (proofEntries[recipientIndex].empty() ||
        proofAmounts[recipientIndex] != req.recipients[recipientIndex].amount) {
      throw std::runtime_error("buildPqSend: incomplete recipient proof");
    }
    const PqSendOutput& requested = req.recipients[recipientIndex];
    ResolvedRecipient recipient{
        requested.recipientViewPub,
        requested.recipientSpendPub,
        requested.subaddrIndexT};
    PqPaymentProof proof = makePqPaymentProof(
        req.genesisId, proofTx.txid, recipient,
        std::move(proofEntries[recipientIndex]));
    const uint64_t verified = verifyPqPaymentProof(
        proof, req.genesisId, proofTx, recipient);
    if (verified != requested.amount) {
      throw std::runtime_error("buildPqSend: final payment proof total mismatch");
    }
    proofs.push_back(std::move(proof));
  }

  PqSendResult result;
  result.tx = std::move(finalBuild.transaction.tx);
  result.fee = fee;
  result.sent = sent;
  result.change = sumIn - sent - fee;
  result.selected = std::move(selected);
  result.proofs = std::move(proofs);
  finalBuild.transaction.clearWitnesses();
  return result;
}

}  // namespace CryptoNote
