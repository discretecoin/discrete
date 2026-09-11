#include "SwapTransactionBuilder.h"
#include "crypto_pq/PqOutputBuilder.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace CryptoNote {
namespace {
void payout(Transaction& tx,const PqSendOutput& recipient) {
  if(recipient.amount==0 || recipient.unlockHeight!=0)throw std::invalid_argument("swap payout amount/lock");
  auto built=CryptoPQ::buildPqOutput(recipient.recipientViewPub,recipient.recipientSpendPub,
                                   pqTransactionInputsHash(tx),static_cast<uint32_t>(tx.outputs.size()),
                                   recipient.amount,recipient.subaddrIndexT);
  PqOutput po;po.kemCt.assign(built.kemCt.begin(),built.kemCt.end());po.encPayload=std::move(built.encPayload);
  std::memcpy(po.spendCommit.data,built.spendCommit.data(),32);
  TransactionOutput output{};output.amount=recipient.amount;output.target=std::move(po);tx.outputs.push_back(std::move(output));
}
void finish(Transaction& tx,const std::vector<SwapResolvedInput>& resolved,const std::vector<PqInputAuth>& auth,
            const Crypto::Hash& chain,uint32_t height,const SwapFundingDraftSink& sink = {}) {
  if(auth.size()!=tx.inputs.size())throw std::invalid_argument("swap authority count");
  tx.pqSignatures.resize(tx.inputs.size());std::string error;
  if(!checkSwapTransactionSemantic(tx,&error))throw std::invalid_argument(error);
  if(sink)sink(tx,resolved,height);
  for(size_t i=0;i<auth.size();++i) {
    auto digest=swapSigningDigest(tx,resolved,chain,static_cast<uint32_t>(i));
    tx.pqSignatures[i]=CryptoPQ::dsa_sign(auth[i].spendSk,digest.data(),digest.size());
  }
  if(!checkSwapTransactionInputs(tx,resolved,chain,height,nullptr,nullptr,&error))throw std::invalid_argument(error);
}
}
Transaction buildSwapFunding(const std::vector<PqSpendInput>& inputs,const std::vector<PqInputAuth>& auth,
                             const std::vector<SwapResolvedInput>& resolved,const TransactionOutput& contract,
                             const std::vector<PqSendOutput>& change,const Crypto::Hash& chain,uint32_t height) {
  return buildSwapFundingWithDraftSink(inputs,auth,resolved,contract,change,chain,height,{});
}
Transaction buildSwapFundingWithDraftSink(const std::vector<PqSpendInput>& inputs,const std::vector<PqInputAuth>& auth,
                             const std::vector<SwapResolvedInput>& resolved,const TransactionOutput& contract,
                             const std::vector<PqSendOutput>& change,const Crypto::Hash& chain,uint32_t height,
                             const SwapFundingDraftSink& sink) {
  if(inputs.empty() || inputs.size()>8 || inputs.size()!=auth.size() || inputs.size()!=resolved.size() ||
     change.size()>1 || contract.target.type()!=typeid(SwapOutput))throw std::invalid_argument("swap funding shape");
  Transaction tx{};tx.version=TRANSACTION_VERSION_1;tx.txType=TX_SWAP_FUND;
  for(size_t i=0;i<inputs.size();++i) {
    if(inputs[i].amount!=resolved[i].output.amount)throw std::invalid_argument("swap descriptor amount mismatch");
    PqInput in;in.prevTxid=inputs[i].prevTxid;in.prevOutIndex=inputs[i].prevOutIndex;
    in.authPub.assign(auth[i].spendPub.begin(),auth[i].spendPub.end());in.rhoReveal.assign(inputs[i].rho.begin(),inputs[i].rho.end());tx.inputs.push_back(std::move(in));
  }
  tx.outputs.push_back(contract);for(const auto& out:change)payout(tx,out);
  finish(tx,resolved,auth,chain,height,sink);return tx;
}
Transaction finishSwapFundingDraft(Transaction draft,const std::vector<SwapResolvedInput>& resolved,
                             const std::vector<PqInputAuth>& auth,const Crypto::Hash& chain,uint32_t height) {
  if(draft.txType!=TX_SWAP_FUND || draft.pqSignatures.size()!=draft.inputs.size())
    throw std::invalid_argument("unsigned swap funding draft required");
  for(const auto& signature:draft.pqSignatures)
    if(!std::all_of(signature.begin(),signature.end(),[](uint8_t v){return v==0;}))
      throw std::invalid_argument("draft already contains a signature");
  finish(draft,resolved,auth,chain,height);return draft;
}
Transaction buildSwapSpend(const SwapInput& input,const TransactionOutput& contract,const PqInputAuth& authority,
                           const std::vector<PqSendOutput>& payouts,const Crypto::Hash& chain,uint32_t height) {
  if(payouts.empty() || payouts.size()>2)throw std::invalid_argument("swap payout count");
  Transaction tx{};tx.version=TRANSACTION_VERSION_1;tx.txType=TX_SWAP_SPEND;
  auto in=input;in.authPub.assign(authority.spendPub.begin(),authority.spendPub.end());tx.inputs.push_back(std::move(in));
  for(const auto& out:payouts)payout(tx,out);
  finish(tx,{SwapResolvedInput{true,contract}},{authority},chain,height);return tx;
}
}
