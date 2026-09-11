// Copyright (c) 2026, The Discrete developers. LGPL-3.0-or-later.
#include "SwapWallet.h"
#include "SwapFundingStore.h"
#include "Common/SecureMemory.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteConfig.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace CryptoNote {
namespace {
constexpr uint64_t fee = parameters::MINIMUM_FEE;
void require(bool value,const char* message) { if(!value)throw std::invalid_argument(message); }
void put32(BinaryArray& out,uint32_t value) { for(int i=0;i<4;++i)out.push_back(uint8_t(value>>(8*i))); }
void put64(BinaryArray& out,uint64_t value) { for(int i=0;i<8;++i)out.push_back(uint8_t(value>>(8*i))); }
void putHash(BinaryArray& out,const Crypto::Hash& value) { out.insert(out.end(),value.data,value.data+32); }
void putBytes(BinaryArray& out,const BinaryArray& value) {
  require(value.size()<=SwapFundingStore::MAX_WIRE_BYTES,"swap record wire bound");
  put32(out,uint32_t(value.size()));out.insert(out.end(),value.begin(),value.end());
}
class Reader {
public:
  explicit Reader(const BinaryArray& bytes):bytes(bytes){}
  uint32_t number() { require(bytes.size()-at>=4,"truncated swap record");uint32_t value=0;for(int i=0;i<4;++i)value|=uint32_t(bytes[at++])<<(8*i);return value; }
  Crypto::Hash hash() { require(bytes.size()-at>=32,"truncated swap record hash");Crypto::Hash value{};std::memcpy(value.data,bytes.data()+at,32);at+=32;return value; }
  BinaryArray blob() { const auto n=number();require(n<=SwapFundingStore::MAX_WIRE_BYTES&&bytes.size()-at>=n,"swap record blob bound");BinaryArray value(bytes.begin()+at,bytes.begin()+at+n);at+=n;return value; }
  void end() { require(at==bytes.size(),"trailing swap record bytes"); }
private:
  const BinaryArray& bytes;size_t at=0;
};
Crypto::Hash hashBytes(const BinaryArray& bytes) {
  const auto hash=CryptoPQ::sha3_256(bytes.data(),bytes.size());Crypto::Hash value{};std::memcpy(value.data,hash.data(),32);return value;
}
struct StoreIdentity {
  Crypto::Hash wallet{};CryptoPQ::Hash256 key{};
  StoreIdentity(const PqWalletKeys& keys,const Crypto::Hash& genesis) {
    auto identity=CryptoPQ::sha3_256(keys.spendPub.data(),keys.spendPub.size());std::memcpy(wallet.data,identity.data(),32);
    constexpr char domain[]="discrete-swap-funding-store-key-v1";
    BinaryArray info(domain,domain+sizeof(domain));putHash(info,genesis);putHash(info,wallet);
    key=CryptoPQ::hkdf_sha3_256(keys.seedMaster.data(),keys.seedMaster.size(),info.data(),info.size());
  }
  ~StoreIdentity() { sodium_memzero(key.data(),key.size()); }
};
struct SavedDraft {
  Crypto::Hash request{};uint32_t height=0;Transaction tx{};BinaryArray wire;
  std::vector<SwapResolvedInput> resolved;
};
BinaryArray encodeDraft(const SavedDraft& draft) {
  BinaryArray out;put32(out,1);putHash(out,draft.request);put32(out,draft.height);putBytes(out,draft.wire);
  put32(out,uint32_t(draft.resolved.size()));
  for(const auto& input:draft.resolved) { require(input.exists,"resolved swap source absent");putBytes(out,toBinaryArray(input.output)); }
  return out;
}
SavedDraft decodeDraft(const BinaryArray& bytes) {
  Reader reader(bytes);require(reader.number()==1,"unsupported swap draft version");SavedDraft draft;
  draft.request=reader.hash();draft.height=reader.number();draft.wire=reader.blob();
  require(fromBinaryArray(draft.tx,draft.wire)&&toBinaryArray(draft.tx)==draft.wire,"noncanonical swap draft");
  const auto count=reader.number();require(count>0&&count<=8&&count==draft.tx.inputs.size(),"swap draft input count");
  for(uint32_t i=0;i<count;++i) { SwapResolvedInput value;value.exists=true;auto wire=reader.blob();
    require(fromBinaryArray(value.output,wire)&&toBinaryArray(value.output)==wire,"invalid resolved swap output");draft.resolved.push_back(value); }
  reader.end();std::string error;
  require(draft.tx.txType==TX_SWAP_FUND&&checkSwapTransactionSemantic(draft.tx,&error),"invalid swap draft semantics");
  for(const auto& signature:draft.tx.pqSignatures)
    require(std::all_of(signature.begin(),signature.end(),[](uint8_t v){return v==0;}),"unsigned swap draft required");
  uint64_t actualFee=0;require(swapResolvedFee(draft.tx,draft.resolved,actualFee,&error)&&actualFee==fee,"swap draft fixed fee mismatch");
  return draft;
}
Crypto::Hash draftHash(const BinaryArray& bytes) {
  constexpr char domain[]="discrete-swap-funding-draft-v1";BinaryArray input(domain,domain+sizeof(domain));
  input.insert(input.end(),bytes.begin(),bytes.end());return hashBytes(input);
}
SwapWalletPrepared preparedResult(Transaction tx,const SavedDraft& draft) {
  SwapWalletPrepared result;result.tx=std::move(tx);result.wire=toBinaryArray(result.tx);result.txid=getObjectHash(result.tx);
  result.fee=fee;result.principal=result.tx.outputs.at(0).amount;
  for(size_t i=0;i<result.tx.inputs.size();++i) {
    const auto& input=boost::get<PqInput>(result.tx.inputs[i]);PqSpendInput value;
    value.prevTxid=input.prevTxid;value.prevOutIndex=input.prevOutIndex;value.amount=draft.resolved[i].output.amount;
    require(input.rhoReveal.size()==value.rho.size(),"swap draft rho shape");
    std::copy(input.rhoReveal.begin(),input.rhoReveal.end(),value.rho.begin());result.selectedInputs.push_back(value);
  }
  return result;
}
void validatePrepared(const Transaction& tx,const SavedDraft& draft,const Crypto::Hash& genesis) {
  require(tx.txType==TX_SWAP_FUND&&tx.pqSignatures.size()==draft.tx.pqSignatures.size(),"prepared swap shape mismatch");
  Transaction unsignedTx=tx;for(auto& signature:unsignedTx.pqSignatures)signature.fill(0);
  require(toBinaryArray(unsignedTx)==draft.wire,"prepared swap changed its fixed draft");
  std::string error;uint64_t actualFee=0;
  require(checkSwapTransactionInputs(tx,draft.resolved,genesis,draft.height,nullptr,&actualFee,&error)&&actualFee==fee,
      "stored swap funding signature or fee rejected");
}
SwapFundingPreparation load(SwapFundingStore& store,const Crypto::Hash& operation,const Crypto::Hash& genesis) {
  SwapFundingPreparation result;result.operation=operation;
  auto draftBytes=store.read(operation,SwapFundingStore::Draft);
  auto preparedBytes=store.read(operation,SwapFundingStore::Prepared);
  if(!draftBytes) { require(!preparedBytes,"prepared swap is missing its draft");return result; }
  Tools::SecretLock scrubDraft(draftBytes->data(),draftBytes->size());
  const auto draft=decodeDraft(*draftBytes);result.status=SwapFundingPreparation::Draft;
  result.requestHash=draft.request;result.draftHash=draftHash(*draftBytes);
  result.prepared.principal=draft.tx.outputs.at(0).amount;result.prepared.fee=fee;
  if(!preparedBytes)return result;
  Tools::SecretLock scrubPrepared(preparedBytes->data(),preparedBytes->size());
  Reader reader(*preparedBytes);require(reader.number()==1,"unsupported prepared swap version");
  require(reader.hash()==result.requestHash&&reader.hash()==result.draftHash,"prepared swap draft binding mismatch");
  const auto wire=reader.blob();reader.end();Transaction tx;
  require(fromBinaryArray(tx,wire)&&toBinaryArray(tx)==wire,"invalid stored signed swap wire");
  validatePrepared(tx,draft,genesis);result.status=SwapFundingPreparation::Prepared;
  result.prepared=preparedResult(std::move(tx),draft);return result;
}
uint32_t currentSources(const SavedDraft& draft,const PqWalletKeys& keys,const Crypto::Hash& genesis,
                        uint32_t scannedHeight,const SwapWalletReadOutpoint& read) {
  uint32_t height=0;Crypto::Hash tip{};
  for(size_t i=0;i<draft.tx.inputs.size();++i) {
    const auto& input=boost::get<PqInput>(draft.tx.inputs[i]);
    require(input.authPub.size()==keys.spendPub.size()&&std::equal(input.authPub.begin(),input.authPub.end(),keys.spendPub.begin()),
            "stored swap input is not this wallet authority");
    Crypto::KeyImage tag{};require(transactionSpendTag(draft.tx.inputs[i],genesis,tag),"swap source tag unavailable");
    Crypto::Hash hashTag{};std::memcpy(hashTag.data,tag.data,32);const auto state=read(input.prevTxid,input.prevOutIndex,hashTag);
    require(state.genesis==genesis&&state.found&&state.inChain&&!state.inPool&&state.height>state.blockHeight&&
            state.confirmations==uint64_t(state.height)-state.blockHeight,"swap source inclusion changed");
    require(state.spentKnown&&!state.spent&&!state.spentInPool,"swap source interfered; no replacement inputs permitted");
    require(getObjectHash(state.transaction)==input.prevTxid&&input.prevOutIndex<state.transaction.outputs.size(),"swap source transaction mismatch");
    const auto& output=state.transaction.outputs[input.prevOutIndex];
    require(state.amount==output.amount&&toBinaryArray(output)==toBinaryArray(draft.resolved[i].output),"swap source output changed");
    require(output.target.type()==typeid(PqOutput)||output.target.type()==typeid(CoinbaseOutput),"ordinary swap source required");
    require((output.unlockHeight==0||output.unlockHeight<=scannedHeight)&&uint64_t(scannedHeight)+1>=state.height,"swap wallet scan is behind source");
    CryptoPQ::Rho rho{};require(input.rhoReveal.size()==rho.size(),"swap source rho shape");std::copy(input.rhoReveal.begin(),input.rhoReveal.end(),rho.begin());
    const auto expected=CryptoPQ::spendCommit(keys.spendPub,rho);
    const auto& commit=output.target.type()==typeid(PqOutput)?boost::get<PqOutput>(output.target).spendCommit:boost::get<CoinbaseOutput>(output.target).spendCommit;
    require(std::memcmp(expected.data(),commit.data,32)==0,"swap source owner mismatch");
    if(i==0){height=state.height;tip=state.tipHash;}else require(height==state.height&&tip==state.tipHash,"swap sources changed tip");
  }
  require(boost::get<SwapOutput>(draft.tx.outputs.at(0).target).refundHeight>height,"stored funding deadline already eligible");
  return height;
}
}

Crypto::Hash swapFundingRequestHash(const Crypto::Hash& operation,const SwapWalletFundingRequest& request) {
  require(operation!=Crypto::Hash{},"zero swap operation id");
  constexpr char domain[]="discrete-swap-funding-operation-v1";BinaryArray bytes(domain,domain+sizeof(domain));
  putHash(bytes,request.genesis);putHash(bytes,operation);put64(bytes,request.principal);put32(bytes,request.contract.refundHeight);
  putHash(bytes,request.contract.hashlock);putHash(bytes,request.contract.nonce);putHash(bytes,request.contract.claimCommit);
  bytes.insert(bytes.end(),request.refundRho.begin(),request.refundRho.end());return hashBytes(bytes);
}
SwapFundingPreparation lookupSwapWalletFunding(const std::string& path,const Crypto::Hash& operation,
    const PqWalletKeys& keys,const Crypto::Hash& genesis) {
  require(operation!=Crypto::Hash{},"zero swap operation id");StoreIdentity identity(keys,genesis);
  SwapFundingStore store(path,identity.key,identity.wallet,genesis,false);return load(store,operation,genesis);
}
SwapFundingPreparation prepareSwapWalletFundingOnce(const std::string& path,const Crypto::Hash& operation,
    const SwapWalletFundingRequest& request,const std::vector<PqSpendInput>& available,const PqWalletKeys& keys,
    const Crypto::Hash& genesis,uint32_t scannedHeight,const SwapWalletReadOutpoint& read) {
  require(request.genesis==genesis&&request.principal>fee&&request.principal<=UINT64_MAX-fee,"invalid durable swap network or amount");
  const auto refund=CryptoPQ::spendCommit(keys.spendPub,request.refundRho);
  require(std::memcmp(refund.data(),request.contract.refundCommit.data,32)==0,"durable swap refund owner mismatch");
  const auto requestHash=swapFundingRequestHash(operation,request);StoreIdentity identity(keys,genesis);
  SwapFundingStore store(path,identity.key,identity.wallet,genesis,true);
  auto previous=load(store,operation,genesis);
  if(previous.status!=SwapFundingPreparation::Absent)require(previous.requestHash==requestHash,"swap operation id reused for different terms");
  if(previous.status==SwapFundingPreparation::Prepared)return previous;
  Transaction signedTx;SavedDraft draft;BinaryArray draftBytes;
  if(previous.status==SwapFundingPreparation::Absent) {
    const auto result=prepareSwapWalletFundingWithDraftSink(request,available,keys,genesis,scannedHeight,read,
      [&](const Transaction& fixed,const std::vector<SwapResolvedInput>& resolved,uint32_t height) {
        draft.request=requestHash;draft.height=height;draft.tx=fixed;draft.wire=toBinaryArray(fixed);draft.resolved=resolved;
        draftBytes=encodeDraft(draft);store.publish(operation,SwapFundingStore::Draft,draftBytes);
      });
    signedTx=result.tx;
  } else {
    const auto bytes=store.read(operation,SwapFundingStore::Draft);require(bool(bytes),"stored swap draft disappeared");
    draftBytes=*bytes;draft=decodeDraft(draftBytes);
    TransactionOutput expected{};expected.amount=request.principal;expected.target=request.contract;
    require(toBinaryArray(expected)==toBinaryArray(draft.tx.outputs.at(0)),"stored funding contract differs from request");
    const auto height=currentSources(draft,keys,genesis,scannedHeight,read);
    std::vector<PqInputAuth> authorities(draft.tx.inputs.size());
    for(auto& authority:authorities){authority.spendPub=keys.spendPub;authority.spendSk=keys.spendSk;}
    signedTx=finishSwapFundingDraft(draft.tx,draft.resolved,authorities,genesis,height);
  }
  Tools::SecretLock scrubDraft(draftBytes.data(),draftBytes.size());
  // Ordinary wallet APIs retain their existing behavior. Any competing spend or
  // changed source is rejected here; replay never selects replacement coins.
  currentSources(draft,keys,genesis,scannedHeight,read);validatePrepared(signedTx,draft,genesis);
  BinaryArray prepared;put32(prepared,1);putHash(prepared,requestHash);putHash(prepared,draftHash(draftBytes));putBytes(prepared,toBinaryArray(signedTx));
  Tools::SecretLock scrubPrepared(prepared.data(),prepared.size());
  store.publish(operation,SwapFundingStore::Prepared,prepared);
  return load(store,operation,genesis);
}
}
