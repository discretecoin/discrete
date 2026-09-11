#include "SwapValidation.h"
#include "CryptoNoteTools.h"
#include "CryptoNoteSerialization.h"
#include <cstring>
#include <limits>
#include <set>
#include <stdexcept>
extern "C" {
#include <oqs/sha2.h>
}

namespace CryptoNote {
namespace {
bool fail(std::string* error, const char* text) { if(error) *error=text; return false; }
bool add(uint64_t& sum,uint64_t value) {
  if(value>std::numeric_limits<uint64_t>::max()-sum) return false;
  sum+=value; return true;
}
void le(std::vector<uint8_t>& b,uint64_t v,size_t n) { for(size_t i=0;i<n;++i)b.push_back(static_cast<uint8_t>(v>>(i*8))); }
template<size_t N> void domain(std::vector<uint8_t>& b,const char (&d)[N]) { b.insert(b.end(),d,d+N); }
void hash(std::vector<uint8_t>& b,const Crypto::Hash& h) { b.insert(b.end(),h.data,h.data+32); }
bool policy(const SwapOutput& c) {
  return c.version==1 && c.hashScheme==1 && c.authScheme==1 && c.amountScheme==1 && c.refundHeight!=0;
}
bool fields(const std::vector<uint8_t>& pub,const std::vector<uint8_t>& rho) {
  return pub.size()==PQ_AUTH_PUB_SIZE && rho.size()==PQ_RHO_SIZE;
}
}
bool swapInputReference(const TransactionInput& input,Crypto::Hash& txid,uint32_t& index) {
  if(input.type()==typeid(PqInput)) { const auto& in=boost::get<PqInput>(input);txid=in.prevTxid;index=in.prevOutIndex;return true; }
  if(input.type()==typeid(SwapInput)) { const auto& in=boost::get<SwapInput>(input);txid=in.prevTxid;index=in.prevOutIndex;return true; }
  return false;
}
Crypto::KeyImage swapSpendTag(const SwapInput& input,const Crypto::Hash& chain) {
  std::vector<uint8_t> b; domain(b,"XDS/SwapSpent/v1");hash(b,chain);hash(b,input.prevTxid);le(b,input.prevOutIndex,4);
  auto h=CryptoPQ::sha3_256(b.data(),b.size()); Crypto::KeyImage tag{};std::memcpy(tag.data,h.data(),32);return tag;
}
bool transactionSpendTag(const TransactionInput& input,const Crypto::Hash& chain,Crypto::KeyImage& tag) {
  if(input.type()==typeid(PqInput)) {tag=pqInputNullifierAsKeyImage(boost::get<PqInput>(input));return true;}
  if(input.type()==typeid(SwapInput)) {tag=swapSpendTag(boost::get<SwapInput>(input),chain);return true;}
  return false;
}
Crypto::Hash swapHashlock(const std::vector<uint8_t>& secret) {
  Crypto::Hash h{};OQS_SHA2_sha256(h.data,secret.data(),secret.size());return h;
}
bool checkSwapTransactionSemantic(const Transaction& tx,std::string* error) {
  if(tx.version!=TRANSACTION_VERSION_1 || !isSwapTransaction(tx)) return fail(error,"swap family/version");
  if(tx.unlockHeight!=0 || !tx.extra.empty()) return fail(error,"swap outer lock/extra");
  const bool funding=tx.txType==TX_SWAP_FUND;
  if(tx.inputs.empty() || tx.inputs.size()>(funding?8u:1u) || tx.outputs.empty() || tx.outputs.size()>2 ||
     tx.pqSignatures.size()!=tx.inputs.size()) return fail(error,"swap counts");
  for(const auto& in:tx.inputs) {
    if(funding) {
      if(in.type()!=typeid(PqInput))return fail(error,"swap funding requires ordinary input");
      const auto& p=boost::get<PqInput>(in); if(!fields(p.authPub,p.rhoReveal))return fail(error,"swap auth length");
    } else {
      if(in.type()!=typeid(SwapInput))return fail(error,"swap spending requires conditional input");
      const auto& p=boost::get<SwapInput>(in);
      if(!fields(p.authPub,p.rhoReveal) || (p.branch!=1 && p.branch!=2) ||
         p.secret.size()!=(p.branch==1?32u:0u))return fail(error,"swap witness");
    }
  }
  size_t contracts=0;
  for(const auto& out:tx.outputs) {
    if(out.amount==0 || out.unlockHeight!=0)return fail(error,"swap output amount/lock");
    if(out.target.type()==typeid(SwapOutput)) {
      if(!funding || !policy(boost::get<SwapOutput>(out.target)))return fail(error,"swap policy/output family");
      // A conditional spend cannot add fee inputs or create a zero-value payout.
      if(out.amount<=parameters::MINIMUM_FEE)return fail(error,"swap principal cannot pay exit fee");
      ++contracts;
    } else if(out.target.type()==typeid(PqOutput)) {
      const auto& p=boost::get<PqOutput>(out.target);
      if(p.kemCt.size()!=PQ_KEM_CIPHERTEXT_SIZE || p.encPayload.size()!=PQ_ENC_PAYLOAD_SIZE)return fail(error,"swap payout length");
    } else return fail(error,"swap output type");
  }
  if(contracts!=(funding?1u:0u))return fail(error,"exactly one funded contract; no chaining");
  if(toBinaryArray(tx).size()>65536)return fail(error,"swap bytes");
  return true;
}
bool swapResolvedFee(const Transaction& tx,const std::vector<SwapResolvedInput>& resolved,uint64_t& fee,std::string* error) {
  if(resolved.size()!=tx.inputs.size())return fail(error,"swap resolution count");
  uint64_t inputs=0,outputs=0;
  for(size_t i=0;i<resolved.size();++i) {
    const auto& r=resolved[i];if(!r.exists)return fail(error,"swap missing/unmatured input");
    const auto& type=r.output.target.type();
    if(tx.inputs[i].type()==typeid(PqInput)) {
      if(type!=typeid(PqOutput) && type!=typeid(CoinbaseOutput))return fail(error,"ordinary input cannot spend swap");
    } else if(tx.inputs[i].type()==typeid(SwapInput)) {
      if(type!=typeid(SwapOutput) || r.output.unlockHeight!=0)return fail(error,"swap input cannot spend ordinary output");
    } else return fail(error,"unsupported swap input");
    if(!add(inputs,r.output.amount))return fail(error,"swap input overflow");
  }
  for(const auto& out:tx.outputs)if(!add(outputs,out.amount))return fail(error,"swap output overflow");
  if(outputs>inputs)return fail(error,"swap inflation");
  const uint64_t result=inputs-outputs;
  if(result!=parameters::MINIMUM_FEE)return fail(error,"experimental swap fee must be 0.01 XDS");
  fee=result;return true;
}
CryptoPQ::Hash256 swapSigningDigest(const Transaction& tx,const std::vector<SwapResolvedInput>& resolved,
                                   const Crypto::Hash& chain,uint32_t index) {
  uint64_t fee=0;std::string error;
  if(index>=tx.inputs.size() || !swapResolvedFee(tx,resolved,fee,&error))throw std::invalid_argument("swap digest resolution: "+error);
  std::vector<uint8_t> b;domain(b,"discrete-swap-tx-sign-v1");hash(b,chain);le(b,index,4);
  const auto prefix=toBinaryArray(static_cast<const TransactionPrefix&>(tx));le(b,prefix.size(),4);b.insert(b.end(),prefix.begin(),prefix.end());
  le(b,resolved.size(),4);
  for(const auto& r:resolved) {auto bytes=toBinaryArray(r.output);le(b,bytes.size(),4);b.insert(b.end(),bytes.begin(),bytes.end());}
  le(b,fee,8);return CryptoPQ::sha3_256(b.data(),b.size());
}
bool checkSwapTransactionInputs(const Transaction& tx,const std::vector<SwapResolvedInput>& resolved,
                               const Crypto::Hash& chain,uint32_t height,std::vector<Crypto::KeyImage>* tags,
                               uint64_t* outFee,std::string* error) {
  if(!checkSwapTransactionSemantic(tx,error))return false;
  uint64_t fee=0;if(!swapResolvedFee(tx,resolved,fee,error))return false;
  for(const auto& out:tx.outputs) if(out.target.type()==typeid(SwapOutput) &&
      boost::get<SwapOutput>(out.target).refundHeight<=height)return fail(error,"funding refund already eligible");
  std::set<CryptoPQ::Hash256> unique;std::vector<Crypto::KeyImage> result;
  for(size_t i=0;i<tx.inputs.size();++i) {
    const auto& input=tx.inputs[i];const auto& output=resolved[i].output;
    const std::vector<uint8_t>* pub; const std::vector<uint8_t>* rho; Crypto::Hash expected{};
    if(input.type()==typeid(PqInput)) {
      const auto& p=boost::get<PqInput>(input);pub=&p.authPub;rho=&p.rhoReveal;
      expected=output.target.type()==typeid(PqOutput)?boost::get<PqOutput>(output.target).spendCommit:boost::get<CoinbaseOutput>(output.target).spendCommit;
    } else {
      const auto& p=boost::get<SwapInput>(input);const auto& c=boost::get<SwapOutput>(output.target);
      if(!policy(c))return fail(error,"resolved swap policy");pub=&p.authPub;rho=&p.rhoReveal;
      expected=p.branch==1?c.claimCommit:c.refundCommit;
      if(p.branch==1 && swapHashlock(p.secret)!=c.hashlock)return fail(error,"swap hashlock");
      if(p.branch==2 && height<c.refundHeight)return fail(error,"swap refund immature");
    }
    CryptoPQ::DsaPublicKey pk{};CryptoPQ::Rho r{};std::memcpy(pk.data(),pub->data(),pk.size());std::memcpy(r.data(),rho->data(),r.size());
    const auto commit=CryptoPQ::spendCommit(pk,r);
    if(std::memcmp(commit.data(),expected.data,32)!=0)return fail(error,"swap ownership");
    Crypto::KeyImage tag{};if(!transactionSpendTag(input,chain,tag))return fail(error,"swap spent identity");
    CryptoPQ::Hash256 key{};std::memcpy(key.data(),tag.data,32);
    if(!unique.insert(key).second)return fail(error,"swap duplicate input");result.push_back(tag);
  }
  // All shape, value, role, time and conflict checks precede expensive signatures.
  for(size_t i=0;i<tx.inputs.size();++i) {
    const auto& bytes=tx.inputs[i].type()==typeid(PqInput)?boost::get<PqInput>(tx.inputs[i]).authPub:boost::get<SwapInput>(tx.inputs[i]).authPub;
    CryptoPQ::DsaPublicKey pk{};std::memcpy(pk.data(),bytes.data(),pk.size());
    auto digest=swapSigningDigest(tx,resolved,chain,static_cast<uint32_t>(i));
    if(!CryptoPQ::dsa_verify(pk,digest.data(),digest.size(),tx.pqSignatures[i]))return fail(error,"swap signature");
  }
  if(tags)*tags=std::move(result);if(outFee)*outFee=fee;return true;
}
}
