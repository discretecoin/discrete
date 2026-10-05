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
// policy — input selection, output shape, the flat fee, change handling, signing —
// lives here so the front-ends can never drift. It performs NO I/O and touches no
// node: the caller relays the returned transaction.
//
// Output policy: ONE output per recipient row plus one change output. Consensus
// accepts any non-zero amount, so there is no decomposition into denominations
// (the former canonical denomination table was wallet policy only and multiplied
// the output count of every payment, which later cost a ~5.3 KB input each).
//
// Input policy: the fewest largest inputs that cover the payment, then — because
// the fee is flat and does not grow with the input count — the wallet's SMALLEST
// spendable inputs are folded into the same transaction (the sweep). This keeps
// the unspent-output set small as a side effect of ordinary sends, so large
// payments keep fitting the consensus input caps without a separate consolidation
// step. Every input is spent exactly once over its life, so the sweep is
// byte-neutral for the chain; it only moves the cost earlier.
//
// What a send holds back until it confirms is the covering inputs (as before)
// plus the swept ones, and the sweep is bounded so it cannot eat into liquidity:
//   * it only runs while more than PQ_SWEEP_KEEP_OUTPUTS spendable outputs would
//     remain, so a wallet that is not fragmented is never swept;
//   * the swept value is at most 1/PQ_SWEEP_VALUE_DIVISOR of the spendable value,
//     so a second payment can be built before the first confirms;
//   * at most PQ_SWEEP_MAX_EXTRA_INPUTS inputs per send;
//   * only inputs under spend keys the payment already uses, so it never links a
//     deposit key the payment did not need.
// Explicit consolidation (buildPqConsolidation) has none of these bounds: it
// merges whatever it selects and holds all of it until it confirms.

namespace CryptoNote {

// Sweep policy (wallet policy, not consensus); see the input policy above. 32 is
// today's per-transaction input cap: a wallet holding no more outputs than that
// can always pay from one transaction, so it has nothing worth sweeping.
constexpr std::size_t PQ_SWEEP_KEEP_OUTPUTS = 32;
constexpr std::size_t PQ_SWEEP_MAX_EXTRA_INPUTS = 8;
constexpr uint64_t PQ_SWEEP_VALUE_DIVISOR = 10;

// One recipient with the lump amount to pay. buildPqSend emits exactly one output
// per recipient row.
struct PqSendRequest {
  std::vector<PqSendOutput> recipients;  // each .amount is the lump to that recipient
  uint64_t explicitFee = 0;              // 0 = auto (flat consensus floor for the extra size)
  uint64_t unlockHeight = 0;             // legacy API tx-level lock; TX_PQ requires 0
  std::vector<uint8_t> extra;            // tx.extra (e.g. a PQ account registration tag)
  CryptoPQ::Hash256 genesisId{};         // network binding embedded in every proof

  // The block index this transaction is expected to be validated at, which is the
  // NEXT block index (the chain height), not the current tip: consensus judges a
  // transaction at the height of the block carrying it. It selects the signing
  // transcript via pqSigningContextForHeight — the same helper consensus uses.
  //
  // Left at 0 the transaction signs under transcript v1, which is what consensus
  // requires until parameters::PQ_TRANSCRIPT_V2_HEIGHT activates. Every wallet
  // front-end sets it; the default keeps direct callers (tests, tools) on the
  // pre-activation transcript rather than silently signing for height 0 of a
  // chain they did not mean.
  uint32_t signingHeight = 0;
  // Activation height of the mandatory outContext-v2 delivery declaration, taken
  // from the Currency. signingHeight is compared against it to pick the declared
  // transfer subtype, so a wallet never has to know the schedule itself.
  uint32_t deliveryV2Height = 0xFFFFFFFFu;

  // Deposit scheme: decides each input's signing key. Under SingleKeyIndex the one
  // ML-DSA key authorizes every input; under AggregatedMultikey a deposit input is
  // signed with deriveDepositSpendKeys(seedMaster, depositIndex). `keys` must carry a
  // usable seedMaster for AggregatedMultikey deposit spends.
  PqDepositScheme scheme = PqDepositScheme::AggregatedMultikey;

  // Restrict the spend to these source buckets (depositIndex values; PQ_PRIMARY_DEPOSIT
  // = primary). Empty = spend from any bucket. Lets a caller spend only from a specific
  // deposit / address index. The sweep draws from the same restricted set.
  std::vector<uint32_t> sourceBuckets;

  // Where change (if any) is sent. When hasChangeDest is false (default) change returns
  // to the primary identity (`keys`) — correct for a single-address wallet. The
  // front-end sets it to route change to a specific address/deposit per the
  // change-destination rule (CryptoNote getChangeDestination). `changeDest.amount` is
  // ignored (filled with the change).
  bool hasChangeDest = false;
  PqSendOutput changeDest;

  // Fold the smallest spendable inputs into this send (see the policy above).
  // Front-ends leave it on; a caller that must spend an exact input set turns it off.
  bool sweepSmallInputs = true;
};

struct PqSendResult {
  Transaction               tx;
  uint64_t                  fee = 0;
  uint64_t                  sent = 0;     // sum of recipient amounts (excl. fee/change)
  uint64_t                  change = 0;
  std::vector<PqSpendInput> selected;     // inputs actually spent
  std::vector<PqPaymentProof> proofs;     // exactly one per request recipient row
};

// A dry-run description of one maintenance transaction: the smallest spendable
// inputs merged into ONE output back to the wallet. Consolidation is useful only
// when it consumes at least two inputs and the fee leaves something to return;
// callers must never pay a fee for a useless transaction.
struct PqConsolidationPlan {
  std::size_t availableInputs = 0;
  std::size_t selectedInputs = 0;
  std::size_t resultingOutputs = 0;  // 1 when the plan is useful
  uint64_t amount = 0;  // value returned to the wallet, after the fee
  uint64_t fee = 0;

  bool useful() const noexcept {
    return selectedInputs >= 2 && resultingOutputs < selectedInputs && amount > 0;
  }
};

struct PqConsolidationRequest {
  uint64_t explicitFee = 0;       // 0 = current TX_PQ fee floor
  CryptoPQ::Hash256 genesisId{};
  uint32_t signingHeight = 0;
  // Same meaning as PqSendRequest::deliveryV2Height: the consolidation is an
  // ordinary transfer and must declare the subtype consensus expects at
  // signingHeight, or it is rejected once TX_PQ_V2 activates.
  uint32_t deliveryV2Height = 0xFFFFFFFFu;
  PqDepositScheme scheme = PqDepositScheme::AggregatedMultikey;
  // Only merge inputs from these buckets (empty = any bucket), and send the merged
  // output to `destination` (default: the wallet's primary identity). A service
  // wallet uses these to sweep deposit buckets into its hot address, or to merge a
  // bucket back into itself so per-address attribution is preserved.
  std::vector<uint32_t> sourceBuckets;
  bool hasDestination = false;
  PqSendOutput destination;
};

struct PqConsolidationResult {
  PqConsolidationPlan plan;
  PqSendResult transaction;
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

// Selects the smallest spendable inputs, as many as one transaction may carry,
// and describes merging them into one output. Read-only; does not sign.
PqConsolidationPlan planPqConsolidation(
    const std::vector<PqSpendInput>& available,
    uint64_t explicitFee = 0);
PqConsolidationPlan planPqConsolidation(
    const std::vector<PqSpendInput>& available,
    const PqConsolidationRequest& req);

// Builds a self-transfer from the exact inputs selected by planPqConsolidation.
// The transaction has no tx_extra, no change, and one output to the destination
// (default: the wallet's primary PQ identity). Throws TooLarge when no useful plan
// exists.
PqConsolidationResult buildPqConsolidation(
    const std::vector<PqSpendInput>& available,
    const PqWalletKeys& keys,
    const PqConsolidationRequest& req = {});

}  // namespace CryptoNote
