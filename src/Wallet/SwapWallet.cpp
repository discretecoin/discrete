#include "SwapWallet.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteConfig.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <stdexcept>

namespace CryptoNote {
namespace {
constexpr uint64_t fee = parameters::MINIMUM_FEE;
void require(bool yes, const char* message) { if (!yes) throw std::invalid_argument(message); }
Crypto::Hash ordinaryTag(const PqSpendInput& input, const PqWalletKeys& keys) {
  CryptoPQ::Hash256 id{}; std::memcpy(id.data(), input.prevTxid.data, 32);
  const auto value = CryptoPQ::nullifier(keys.spendPub, input.rho, id, input.prevOutIndex);
  Crypto::Hash result{}; std::memcpy(result.data, value.data(), 32); return result;
}
const TransactionOutput& checkedOutput(const SwapOutpointInfo& state,
    const Crypto::Hash& txid, uint32_t index, const Crypto::Hash& genesis) {
  require(state.genesis == genesis, "swap node network mismatch");
  require(state.found && state.inChain && !state.inPool && state.height > state.blockHeight,
          "swap outpoint is not confirmed");
  require(state.confirmations == uint64_t(state.height) - state.blockHeight,
          "swap confirmation snapshot mismatch");
  require(state.spentKnown && !state.spent && !state.spentInPool, "swap outpoint is spent or unknown");
  require(getObjectHash(state.transaction) == txid && index < state.transaction.outputs.size(),
          "swap outpoint transaction mismatch");
  const auto& output = state.transaction.outputs[index];
  require(output.amount == state.amount, "swap outpoint amount mismatch");
  return output;
}
SwapWalletPrepared result(Transaction tx, uint64_t principal, std::vector<PqSpendInput> inputs = {}) {
  SwapWalletPrepared value; value.wire = toBinaryArray(tx); value.txid = getObjectHash(tx);
  value.tx = std::move(tx); value.fee = fee; value.principal = principal; value.selectedInputs = std::move(inputs);
  return value;
}
PqInputAuth auth(const PqWalletKeys& keys) { PqInputAuth a; a.spendPub = keys.spendPub; a.spendSk = keys.spendSk; return a; }
}

SwapWalletPrepared prepareSwapWalletFunding(const SwapWalletFundingRequest& request,
    const std::vector<PqSpendInput>& available, const PqWalletKeys& keys,
    const Crypto::Hash& genesis, uint32_t scannedHeight, const SwapWalletReadOutpoint& read) {
  return prepareSwapWalletFundingWithDraftSink(request,available,keys,genesis,scannedHeight,read,{});
}
SwapWalletPrepared prepareSwapWalletFundingWithDraftSink(const SwapWalletFundingRequest& request,
    const std::vector<PqSpendInput>& available, const PqWalletKeys& keys,
    const Crypto::Hash& genesis, uint32_t scannedHeight, const SwapWalletReadOutpoint& read,
    const SwapFundingDraftSink& sink) {
  require(request.genesis == genesis, "swap request network mismatch");
  require(request.principal > fee && request.principal <= UINT64_MAX - fee, "swap principal/fee");
  const auto refund = CryptoPQ::spendCommit(keys.spendPub, request.refundRho);
  require(std::memcmp(refund.data(), request.contract.refundCommit.data, 32) == 0,
          "swap refund authority is not this wallet");
  auto sorted = available;
  std::sort(sorted.begin(), sorted.end(), [](const PqSpendInput& a, const PqSpendInput& b) {
    if (a.amount != b.amount) return a.amount > b.amount;
    const int order = std::memcmp(a.prevTxid.data, b.prevTxid.data, 32);
    return order ? order < 0 : a.prevOutIndex < b.prevOutIndex;
  });
  uint64_t total = 0; uint32_t height = 0; Crypto::Hash tip{};
  std::vector<PqSpendInput> selected; std::vector<PqInputAuth> authorities;
  authorities.reserve(8);
  std::vector<SwapResolvedInput> resolved;
  for (const auto& input : sorted) {
    if (total >= request.principal + fee || selected.size() == 8) break;
    auto state = read(input.prevTxid, input.prevOutIndex, ordinaryTag(input, keys));
    const auto& output = checkedOutput(state, input.prevTxid, input.prevOutIndex, genesis);
    require(output.target.type() == typeid(PqOutput) || output.target.type() == typeid(CoinbaseOutput),
            "swap funding must spend an ordinary wallet output");
    // WalletLegacy is SingleKeyIndex. A nonzero routing T does not authorize
    // deriving another key; bind the actual output before preparing any signature.
    const auto ownedCommit = CryptoPQ::spendCommit(keys.spendPub, input.rho);
    const auto& outputCommit = output.target.type() == typeid(PqOutput)
        ? boost::get<PqOutput>(output.target).spendCommit : boost::get<CoinbaseOutput>(output.target).spendCommit;
    require(std::memcmp(ownedCommit.data(), outputCommit.data, 32) == 0,
            "swap funding input requires this SingleKeyIndex wallet authority");
    require(output.amount == input.amount && output.amount <= UINT64_MAX - total, "swap selected amount mismatch");
    require(output.unlockHeight == 0 || output.unlockHeight <= scannedHeight, "swap funding input immature");
    require(uint64_t(scannedHeight) + 1 >= state.height, "swap wallet scan is behind daemon");
    if (selected.empty()) { height = state.height; tip = state.tipHash; }
    else require(state.height == height && state.tipHash == tip, "swap chain moved during preparation; retry");
    total += input.amount; selected.push_back(input); authorities.push_back(auth(keys)); resolved.push_back({true, output});
  }
  require(total >= request.principal + fee, "insufficient swap funds within eight inputs");
  TransactionOutput contract{}; contract.amount = request.principal; contract.target = request.contract;
  std::vector<PqSendOutput> change;
  if (total > request.principal + fee) change.push_back({keys.viewPub, keys.spendPub, total - request.principal - fee});
  auto tx = buildSwapFundingWithDraftSink(selected, authorities, resolved, contract, change, genesis, height,sink);
  return result(std::move(tx), request.principal, std::move(selected));
}

SwapWalletPrepared prepareSwapWalletSpend(const SwapWalletSpendRequest& request,
    const PqWalletKeys& keys, const Crypto::Hash& genesis, const SwapWalletReadOutpoint& read) {
  require(request.genesis == genesis, "swap request network mismatch");
  require(request.branch == 1 || request.branch == 2, "swap role");
  auto state = read(request.fundingTxid, request.outputIndex, Crypto::Hash{});
  const auto& output = checkedOutput(state, request.fundingTxid, request.outputIndex, genesis);
  require(output.target.type() == typeid(SwapOutput) && output.amount > fee, "swap contract output required");
  const auto& contract = boost::get<SwapOutput>(output.target);
  const auto commitment = CryptoPQ::spendCommit(keys.spendPub, request.rho);
  const auto& expected = request.branch == 1 ? contract.claimCommit : contract.refundCommit;
  require(std::memcmp(commitment.data(), expected.data, 32) == 0, "swap role is not owned by this wallet");
  SwapInput input; input.prevTxid = request.fundingTxid; input.prevOutIndex = request.outputIndex;
  input.branch = request.branch; input.rhoReveal.assign(request.rho.begin(), request.rho.end()); input.secret = request.secret;
  auto tx = buildSwapSpend(input, output, auth(keys), {{keys.viewPub, keys.spendPub, output.amount - fee}}, genesis, state.height);
  return result(std::move(tx), output.amount);
}
}
