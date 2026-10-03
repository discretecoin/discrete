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
#include <cstring>
#include <limits>
#include <set>
#include <unordered_set>

#include "Common/SecureMemory.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"  // toBinaryArray
#include "crypto_pq/PqSeed.h"                 // deriveDepositSpendKeys

namespace CryptoNote {

namespace {

namespace P = CryptoNote::parameters;

// Which spend key authorizes an input, as an opaque group id: inputs in one group
// are signed by the same ML-DSA key. Under SingleKeyIndex every output commits to
// the one wallet key; under AggregatedMultikey each deposit bucket has its own
// derived key, while primary and unattributed outputs share the wallet key. This
// mirrors the key choice in authForSelection below.
uint32_t keyGroupOf(const PqSpendInput& in, PqDepositScheme scheme) {
  if (scheme == PqDepositScheme::SingleKeyIndex || in.depositIndex == PQ_UNATTRIBUTED_DEPOSIT) {
    return PQ_PRIMARY_DEPOSIT;
  }
  return in.depositIndex;
}

// Consensus caps a transaction's inputs. The key cap bounds how many DISTINCT
// spend keys (and so ML-DSA signatures) one transaction may carry; the total cap
// bounds the inputs. Until grouped authorization activates
// (parameters::PQ_GROUPED_AUTH_HEIGHT) every input carries its own key, so the
// two are the same number and the key cap never binds first.
struct InputCaps {
  std::size_t totalInputs;
  std::size_t keyInputs;
};

InputCaps capsFor(const PqSigningContext& signing) {
  // Under grouped authorization only the first input of each key carries a key
  // and a signature; the rest are ~70-byte key references, so far more inputs fit.
  const std::size_t total = signing.groupedAuth
                                ? static_cast<std::size_t>(P::MAX_PQ_GROUPED_INPUTS_PER_TX)
                                : static_cast<std::size_t>(P::MAX_PQ_INPUTS_PER_TX);
  return {total, static_cast<std::size_t>(P::MAX_PQ_INPUTS_PER_TX)};
}

// A growing input selection that respects both caps.
struct Selection {
  std::vector<PqSpendInput> inputs;
  std::set<uint32_t> keys;
  uint64_t sum = 0;
  PqDepositScheme scheme;
  InputCaps caps;

  bool canTake(const PqSpendInput& in) const {
    if (inputs.size() >= caps.totalInputs) return false;
    if (keys.count(keyGroupOf(in, scheme)) == 0 && keys.size() >= caps.keyInputs) return false;
    return sum <= std::numeric_limits<uint64_t>::max() - in.amount;
  }

  void take(const PqSpendInput& in) {
    inputs.push_back(in);
    keys.insert(keyGroupOf(in, scheme));
    sum += in.amount;
  }

  void drop() {
    const PqSpendInput& in = inputs.back();
    sum -= in.amount;
    inputs.pop_back();
    keys.clear();
    for (const auto& kept : inputs) keys.insert(keyGroupOf(kept, scheme));
  }
};

bool sameOutpoint(const PqSpendInput& a, const PqSpendInput& b) {
  return a.prevOutIndex == b.prevOutIndex &&
         std::memcmp(a.prevTxid.data, b.prevTxid.data, sizeof(a.prevTxid.data)) == 0;
}

// Deterministic total order for consolidation: smallest amount first, ties by
// outpoint so two wallets holding the same set build the same transaction.
bool smallestFirst(const PqSpendInput& lhs, const PqSpendInput& rhs) {
  if (lhs.amount != rhs.amount) return lhs.amount < rhs.amount;
  const int hashOrder = std::memcmp(lhs.prevTxid.data, rhs.prevTxid.data,
                                    sizeof(lhs.prevTxid.data));
  if (hashOrder != 0) return hashOrder < 0;
  return lhs.prevOutIndex < rhs.prevOutIndex;
}

std::vector<PqSpendInput> filterBuckets(const std::vector<PqSpendInput>& available,
                                        const std::vector<uint32_t>& sourceBuckets) {
  if (sourceBuckets.empty()) return available;
  std::unordered_set<uint32_t> want(sourceBuckets.begin(), sourceBuckets.end());
  std::vector<PqSpendInput> out;
  for (const auto& si : available) {
    if (want.count(si.depositIndex) != 0) out.push_back(si);
  }
  return out;
}

struct ConsolidationSelection {
  PqConsolidationPlan plan;
  std::vector<PqSpendInput> inputs;
};

ConsolidationSelection selectConsolidationInputs(
    const std::vector<PqSpendInput>& available, const PqConsolidationRequest& req) {
  ConsolidationSelection selection;
  selection.plan.fee = req.explicitFee != 0 ? req.explicitFee
                                            : P::pqTxFeeFloor(P::MINIMUM_FEE, 0);

  std::vector<PqSpendInput> sorted = filterBuckets(available, req.sourceBuckets);
  selection.plan.availableInputs = sorted.size();
  if (sorted.size() < 2) return selection;
  std::sort(sorted.begin(), sorted.end(), smallestFirst);

  const PqSigningContext signing = pqSigningContextForHeight(req.signingHeight, req.genesisId);
  Selection picked{{}, {}, 0, req.scheme, capsFor(signing)};
  for (const auto& in : sorted) {
    if (picked.inputs.size() >= picked.caps.totalInputs) break;
    if (picked.canTake(in)) picked.take(in);
  }
  // Every merged input raises the total, so the largest batch that fits is also
  // the one that clears the fee if any does.
  if (picked.inputs.size() < 2 || picked.sum <= selection.plan.fee) return selection;

  selection.plan.selectedInputs = picked.inputs.size();
  selection.plan.resultingOutputs = 1;
  selection.plan.amount = picked.sum - selection.plan.fee;
  selection.inputs = std::move(picked.inputs);
  return selection;
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
  // One output per recipient row plus change: the cap is on the recipient count,
  // not on how the amounts decompose.
  if (req.recipients.size() + 1 > P::MAX_PQ_OUTPUTS_PER_TX) {
    throw PqSendError(PqSendErrorCode::TooLarge,
                      "too many recipients for one PQ transaction; split into smaller transfers");
  }

  // Flat fee: MINIMUM_FEE plus the tx_extra surcharge. It is exact up front, so
  // coin selection needs no size-measurement fixed point.
  const uint64_t fee = req.explicitFee != 0
                           ? req.explicitFee
                           : P::pqTxFeeFloor(P::MINIMUM_FEE, req.extra.size());
  if (sent > std::numeric_limits<uint64_t>::max() - fee) {
    throw PqSendError(PqSendErrorCode::TooLarge, "payment plus fee overflow");
  }
  const uint64_t required = sent + fee;

  // One context for the whole transaction, derived once through the shared
  // consensus helper, so every input of this transaction signs under the same
  // transcript and under the same rule the verifier will apply.
  const PqSigningContext signing = [&] {
    PqSigningContext ctx = pqSigningContextForHeight(req.signingHeight, req.genesisId);
    ctx.txType = pqTransferTypeForHeight(req.signingHeight, req.deliveryV2Height);
    return ctx;
  }();

  // Optional source filter, then deterministic largest-first order.
  std::vector<PqSpendInput> sorted = filterBuckets(available, req.sourceBuckets);
  std::sort(sorted.begin(), sorted.end(),
            [](const PqSpendInput& a, const PqSpendInput& b) { return a.amount > b.amount; });

  // Total spendable funds. The selection can only take so many inputs, so
  // distinguish "no funds" from "funds exist but need more inputs than one tx
  // allows" — the latter is not an insufficient balance.
  uint64_t totalAvail = 0;
  for (const auto& si : sorted) {
    if (totalAvail > std::numeric_limits<uint64_t>::max() - si.amount) {
      totalAvail = std::numeric_limits<uint64_t>::max();
      break;
    }
    totalAvail += si.amount;
  }

  Selection selected{{}, {}, 0, req.scheme, capsFor(signing)};
  std::vector<PqSpendInput> skipped;  // candidates the caps refused or the cover did not need
  for (const auto& si : sorted) {
    if (selected.sum >= required) {
      skipped.push_back(si);
      continue;
    }
    if (selected.canTake(si)) {
      selected.take(si);
    } else {
      skipped.push_back(si);
    }
  }
  if (selected.sum < required) {
    if (totalAvail >= required) {
      throw PqSendError(PqSendErrorCode::TooLarge,
        "amount is too large to send in one transaction (it would need more than " +
        std::to_string(selected.caps.totalInputs) +
        " inputs); send a smaller amount, or consolidate your outputs first");
    }
    // `sorted` holds only spendable (unlocked) inputs, so a true shortfall means the
    // unlocked balance is too small — typically coinbase still maturing.
    throw PqSendError(PqSendErrorCode::InsufficientFunds, "insufficient unlocked balance");
  }
  const std::size_t coverCount = selected.inputs.size();

  // Sweep: fold the smallest leftover inputs in while the wallet keeps a few
  // outputs free. `skipped` is in descending order, so walk it from the back.
  //
  // Only outputs under keys this payment already reveals are swept. Spending an
  // output publishes its key, so sweeping a different deposit's output in would
  // publicly link that deposit to the others, which is exactly what per-deposit
  // keys exist to prevent. For a single-key wallet that is every output.
  //
  // An extra input normally costs ~5.3 KB of key and signature, so only a few are
  // folded in. Under grouped authorization an input under a key the transaction
  // already carries is a ~70-byte key reference, so many more fit.
  if (req.sweepSmallInputs) {
    const std::size_t limit = signing.groupedAuth ? PQ_SWEEP_MAX_EXTRA_KEY_REFERENCES
                                                  : PQ_SWEEP_MAX_EXTRA_INPUTS;
    std::size_t remaining = skipped.size();
    std::size_t swept = 0;
    for (auto it = skipped.rbegin(); it != skipped.rend() && swept < limit; ++it) {
      if (remaining <= PQ_SWEEP_KEEP_OUTPUTS) break;
      if (selected.keys.count(keyGroupOf(*it, req.scheme)) == 0) continue;
      if (!selected.canTake(*it)) continue;
      selected.take(*it);
      ++swept;
      --remaining;
    }
  }

  // Per-input signing key, by bucket. Keep all copies in one contiguous,
  // page-locked vector and scrub it after the transaction has been signed.
  // PqInputAuth also scrubs individual temporaries and reallocated elements.
  auto authForSelection = [&keys, &req](const std::vector<PqSpendInput>& sel) {
    std::vector<PqInputAuth> auth;
    auth.reserve(sel.size());
    for (const auto& si : sel) {
      auth.emplace_back();
      PqInputAuth& entry = auth.back();
      // An unattributed output is ours but has no deposit; like the primary
      // bucket it is authorized by the wallet's own spend key, never by a
      // per-deposit key derived from the sentinel value.
      if (req.scheme == PqDepositScheme::SingleKeyIndex ||
          si.depositIndex == PQ_PRIMARY_DEPOSIT ||
          si.depositIndex == PQ_UNATTRIBUTED_DEPOSIT) {
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
  // default).
  PqSendOutput changeTmpl = req.hasChangeDest
                                ? req.changeDest
                                : PqSendOutput{keys.viewPub, keys.spendPub, 0, 0, 0};

  // Build, shedding swept inputs if the serialized size is over the cap. The
  // covering inputs are never shed: without them the payment cannot be made.
  PqTransactionBuildResult draft;
  for (;;) {
    std::vector<PqSendOutput> outputs(req.recipients.begin(), req.recipients.end());
    const uint64_t change = selected.sum - required;
    if (change > 0) {
      PqSendOutput c = changeTmpl;
      c.amount = change;
      outputs.push_back(c);
    }

    std::vector<PqInputAuth> inputAuth = authForSelection(selected.inputs);
    Tools::SecretLock scrubAuth(inputAuth.data(), inputAuth.size() * sizeof(PqInputAuth));
    // Every rebuild signs under the SAME context: the loop varies only the input
    // set, so re-deriving the transcript here would let a resized draft be signed
    // under different rules from the one the caller asked for.
    draft = buildPqTransactionWithProof(selected.inputs, outputs, inputAuth, 0, req.extra, signing);
    if (toBinaryArray(draft.tx).size() <= P::MAX_PQ_TX_SIZE) {
      break;
    }
    // The draft and its rho openings are one owner. Wipe before rebuilding with a
    // smaller input set; no stale rho can survive into the accepted transaction.
    draft.clearWitnesses();
    if (selected.inputs.size() <= coverCount) {
      throw PqSendError(PqSendErrorCode::TooLarge,
                        "transaction exceeds the size limit; split into smaller transfers");
    }
    selected.drop();
  }

  // Payment proofs: output i < recipients.size() belongs to recipient row i; the
  // change output (if any) is last and is intentionally never proven.
  if (draft.outputRhos.size() != draft.tx.outputs.size() ||
      draft.tx.outputs.size() < req.recipients.size()) {
    throw std::runtime_error("buildPqSend: output provenance/opening mismatch");
  }
  const PqPaymentProofTransaction proofTx = makePqPaymentProofTransaction(draft.tx);
  std::vector<PqPaymentProof> proofs;
  proofs.reserve(req.recipients.size());
  for (std::size_t i = 0; i < req.recipients.size(); ++i) {
    const PqSendOutput& requested = req.recipients[i];
    if (draft.tx.outputs[i].amount != requested.amount) {
      throw std::runtime_error("buildPqSend: incomplete recipient proof");
    }
    ResolvedRecipient recipient{
        requested.recipientViewPub,
        requested.recipientSpendPub,
        requested.subaddrIndexT};
    std::vector<PqPaymentProofEntry> entries;
    entries.push_back({static_cast<uint32_t>(i), draft.outputRhos[i]});
    PqPaymentProof proof = makePqPaymentProof(
        req.genesisId, proofTx.txid, recipient, std::move(entries));
    const uint64_t verified = verifyPqPaymentProof(proof, req.genesisId, proofTx, recipient);
    if (verified != requested.amount) {
      throw std::runtime_error("buildPqSend: final payment proof total mismatch");
    }
    proofs.push_back(std::move(proof));
  }

  PqSendResult result;
  result.tx = std::move(draft.tx);
  result.fee = fee;
  result.sent = sent;
  result.change = selected.sum - required;
  result.selected = std::move(selected.inputs);
  result.proofs = std::move(proofs);
  draft.clearWitnesses();
  return result;
}

PqConsolidationPlan planPqConsolidation(
    const std::vector<PqSpendInput>& available, uint64_t explicitFee) {
  PqConsolidationRequest req;
  req.explicitFee = explicitFee;
  return selectConsolidationInputs(available, req).plan;
}

PqConsolidationPlan planPqConsolidation(
    const std::vector<PqSpendInput>& available, const PqConsolidationRequest& req) {
  return selectConsolidationInputs(available, req).plan;
}

PqConsolidationResult buildPqConsolidation(
    const std::vector<PqSpendInput>& available,
    const PqWalletKeys& keys,
    const PqConsolidationRequest& req) {
  ConsolidationSelection selection = selectConsolidationInputs(available, req);
  if (!selection.plan.useful()) {
    throw PqSendError(
        PqSendErrorCode::TooLarge,
        "no useful consolidation batch (fewer than two spendable inputs, or the fee would consume them)");
  }

  PqSendRequest send;
  PqSendOutput destination = req.hasDestination
                                 ? req.destination
                                 : PqSendOutput{keys.viewPub, keys.spendPub, 0, 0, 0};
  destination.amount = selection.plan.amount;
  send.recipients.push_back(destination);
  send.explicitFee = selection.plan.fee;
  send.genesisId = req.genesisId;
  send.signingHeight = req.signingHeight;
  send.deliveryV2Height = req.deliveryV2Height;
  send.scheme = req.scheme;
  send.sweepSmallInputs = false;  // the plan IS the input set

  // The plan's inputs sum to exactly amount + fee, so the send must take all of
  // them and leave no change.
  PqSendResult transaction = buildPqSend(selection.inputs, keys, send);
  if (transaction.selected.size() != selection.plan.selectedInputs ||
      transaction.tx.outputs.size() != selection.plan.resultingOutputs ||
      transaction.change != 0 || transaction.sent != selection.plan.amount ||
      transaction.fee != selection.plan.fee ||
      transaction.tx.outputs.size() >= transaction.tx.inputs.size()) {
    throw std::runtime_error("buildPqConsolidation: final transaction does not match its plan");
  }
  for (const auto& picked : selection.inputs) {
    const bool present = std::any_of(
        transaction.selected.begin(), transaction.selected.end(),
        [&picked](const PqSpendInput& used) { return sameOutpoint(used, picked); });
    if (!present) {
      throw std::runtime_error("buildPqConsolidation: planned input was not spent");
    }
  }

  return PqConsolidationResult{selection.plan, std::move(transaction)};
}

}  // namespace CryptoNote
