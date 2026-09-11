// Copyright (c) 2026, The Discrete developers. LGPL-3.0-or-later.
#pragma once
#include <functional>
#include "PqTransactionBuilder.h"
#include "CryptoNoteCore/SwapValidation.h"

namespace CryptoNote {
using SwapFundingDraftSink = std::function<void(const Transaction&, const std::vector<SwapResolvedInput>&, uint32_t)>;
// Input descriptors and resolved outputs must come from the same validated chain snapshot.
Transaction buildSwapFunding(const std::vector<PqSpendInput>& inputs,
                             const std::vector<PqInputAuth>& authorities,
                             const std::vector<SwapResolvedInput>& resolved,
                             const TransactionOutput& contract,
                             const std::vector<PqSendOutput>& change,
                             const Crypto::Hash& chain, uint32_t candidateHeight);
Transaction buildSwapFundingWithDraftSink(const std::vector<PqSpendInput>& inputs,
                             const std::vector<PqInputAuth>& authorities,
                             const std::vector<SwapResolvedInput>& resolved,
                             const TransactionOutput& contract,
                             const std::vector<PqSendOutput>& change,
                             const Crypto::Hash& chain, uint32_t candidateHeight,
                             const SwapFundingDraftSink& sink);
// Signs only a previously fixed, unsigned funding prefix; does not select inputs
// or generate any new output. The caller owns persistence and source freshness.
Transaction finishSwapFundingDraft(Transaction draft, const std::vector<SwapResolvedInput>& resolved,
                             const std::vector<PqInputAuth>& authorities,
                             const Crypto::Hash& chain, uint32_t candidateHeight);
Transaction buildSwapSpend(const SwapInput& input, const TransactionOutput& contract,
                           const PqInputAuth& authority, const std::vector<PqSendOutput>& payouts,
                           const Crypto::Hash& chain, uint32_t candidateHeight);
}
