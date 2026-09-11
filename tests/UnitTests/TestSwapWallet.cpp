// Wallet engine tests use the existing refresh stub, not a consensus oracle.
// Real daemon/RPC integration is qualified separately by the localnet driver.
#include "gtest/gtest.h"
#include "INodeStubs.h"
#include "TestBlockchainGenerator.h"
#include "WalletLegacy/WalletLegacy.h"
#include "WalletLegacy/WalletHelper.h"
#include "Wallet/SwapWallet.h"
#include "Wallet/SwapFundingStore.h"
#include "Common/StringTools.h"
#include <boost/filesystem.hpp>
#include "Wallet/PqWallet.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Logging/ConsoleLogger.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <sstream>
#include <thread>

using namespace CryptoNote;
namespace {
template<size_t N> std::array<uint8_t,N> swapPattern(uint8_t seed) {
  std::array<uint8_t,N> value{}; for (size_t i=0;i<N;++i) value[i]=uint8_t(seed+i); return value;
}
Crypto::Hash swapCommit(const CryptoPQ::DsaPublicKey& pub, const CryptoPQ::Rho& rho) {
  const auto bytes=CryptoPQ::spendCommit(pub,rho); Crypto::Hash result{};
  std::memcpy(result.data,bytes.data(),32); return result;
}
class WalletSwapNode : public INodeTrivialRefreshStub {
public:
  WalletSwapNode(TestBlockchainGenerator& generator,const Currency& currency)
    : INodeTrivialRefreshStub(generator), chain(generator),currency(currency) {}
  void getSwapOutpoint(const Crypto::Hash& txid,uint32_t index,const Crypto::Hash& tag,
      SwapOutpointInfo& result,const Callback& callback) override {
    ++queries; result={}; result.genesis=currency.genesisBlockHash();
    const auto blocks=chain.getBlockchainCopy(); result.height=uint32_t(blocks.size());
    result.tipHash=getObjectHash(blocks.back());
    result.found=chain.getTransactionByHash(txid,result.transaction,true) && index<result.transaction.outputs.size();
    if(result.found) {
      for(uint32_t h=0;h<blocks.size();++h) {
        if(getObjectHash(blocks[h].baseTransaction)==txid ||
            std::find(blocks[h].transactionHashes.begin(),blocks[h].transactionHashes.end(),txid)!=blocks[h].transactionHashes.end()) {
          result.inChain=true;result.blockHeight=h;result.blockHash=getObjectHash(blocks[h]);result.confirmations=result.height-h;break;
        }
      }
      result.inPool=!result.inChain;result.amount=result.transaction.outputs[index].amount;
      Crypto::Hash expected=tag;
      if(result.transaction.outputs[index].target.type()==typeid(SwapOutput)) {
        SwapInput input;input.prevTxid=txid;input.prevOutIndex=index;
        const auto spent=swapSpendTag(input,currency.genesisBlockHash());std::memcpy(expected.data,spent.data,32);
      }
      result.spentKnown=expected!=Crypto::Hash{};
      for(const auto& block:blocks) for(const auto& hash:block.transactionHashes) {
        Transaction spender;if(!chain.getTransactionByHash(hash,spender))continue;
        for(const auto& input:spender.inputs) {
          Crypto::KeyImage actual{};
          if(transactionSpendTag(input,currency.genesisBlockHash(),actual) && std::memcmp(actual.data,expected.data,32)==0)
            result.spent=true;
        }
      }
    }
    if(mutate)mutate(result);callback({});
  }
  void relayTransaction(const Transaction&,const Callback& callback) override {++relays;callback({});}
  TestBlockchainGenerator& chain;const Currency& currency;
  size_t queries=0,relays=0;std::function<void(SwapOutpointInfo&)> mutate;
};
struct WalletSwapFixture {
  Logging::ConsoleLogger logger{Logging::ERROR};
  Currency currency=CurrencyBuilder(logger).testnet(true).swapLab(true).swapTestActivation(0).currency();
  TestBlockchainGenerator chain{currency};WalletSwapNode node{chain,currency};
  std::unique_ptr<WalletLegacy> wallet;
  AccountKeys account{};PqWalletKeys keys{},other=derivePqWalletKeys(swapPattern<32>(98));
  CryptoPQ::Rho refundRho=swapPattern<32>(7),claimRho=swapPattern<32>(8);
  std::vector<uint8_t> secret=std::vector<uint8_t>(32,73);
  WalletSwapFixture() {
    wallet.reset(new WalletLegacy(currency,node,logger));wallet->initAndGenerate("pass");wallet->getAccountKeys(account);
    keys=derivePqWalletKeys(account.spendSecretKey);
    PqSpendInput fake;fake.prevTxid.data[0]=12;fake.prevOutIndex=0;fake.amount=10001;fake.rho=swapPattern<32>(4);
    auto received=buildPqTransaction({fake},{{keys.viewPub,keys.spendPub,10000}},other.spendPub,other.spendSk);
    chain.setTxFee(getObjectHash(received),1);chain.addTxToBlockchain(received);node.updateObservers();
    wait([this] {return wallet->actualBalance()==10000;});
  }
  ~WalletSwapFixture(){if(wallet)wallet->shutdown();}
  void wait(const std::function<bool()>& ready) {
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    while(!ready() && std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if(!ready())throw std::runtime_error("wallet scanner timeout");
  }
  SwapWalletFundingRequest request() {
    SwapWalletFundingRequest r;r.genesis=currency.genesisBlockHash();r.principal=1001;r.refundRho=refundRho;
    r.contract.nonce.data[0]=39;r.contract.hashlock=swapHashlock(secret);
    r.contract.claimCommit=swapCommit(keys.spendPub,claimRho);r.contract.refundCommit=swapCommit(keys.spendPub,refundRho);
    r.contract.refundHeight=node.getLocalBlockCount()+5;return r;
  }
  SwapWalletPrepared fund() {
    auto prepared=wallet->prepareSwapFunding(request());chain.setTxFee(prepared.txid,prepared.fee);
    chain.addTxToBlockchain(prepared.tx);node.updateObservers();wait([this]{return wallet->actualBalance()==8998;});
    return prepared;
  }
  SwapWalletSpendRequest spend(const SwapWalletPrepared& funding,bool refund=false) {
    SwapWalletSpendRequest r;r.genesis=currency.genesisBlockHash();r.fundingTxid=funding.txid;r.outputIndex=0;
    r.branch=refund?2:1;r.rho=refund?refundRho:claimRho;if(!refund)r.secret=secret;return r;
  }
};
}

TEST(SwapWalletRuntime, FundingUsesScannedOwnedInputsWithoutRelayOrReservation) {
  WalletSwapFixture f;const auto before=f.wallet->pqSpendableInputs();auto prepared=f.wallet->prepareSwapFunding(f.request());
  ASSERT_EQ(prepared.fee,1u);ASSERT_EQ(prepared.principal,1001u);ASSERT_EQ(prepared.selectedInputs.size(),1u);
  EXPECT_EQ(prepared.selectedInputs[0].prevTxid,before[0].prevTxid);EXPECT_EQ(prepared.wire,toBinaryArray(prepared.tx));
  EXPECT_EQ(prepared.txid,getObjectHash(prepared.tx));EXPECT_EQ(f.node.relays,0u);EXPECT_EQ(f.wallet->actualBalance(),10000u);
  EXPECT_EQ(f.wallet->pqSpendableInputs().size(),before.size());
  EXPECT_EQ(boost::get<SwapOutput>(prepared.tx.outputs[0].target).refundCommit,f.request().contract.refundCommit);
}

TEST(SwapWalletRuntime, FundingRejectsNetworkRoleAmountAndSpentSnapshot) {
  WalletSwapFixture f;auto request=f.request();request.genesis.data[0]^=1;
  EXPECT_THROW(f.wallet->prepareSwapFunding(request),std::invalid_argument);
  request=f.request();request.refundRho[0]^=1;EXPECT_THROW(f.wallet->prepareSwapFunding(request),std::invalid_argument);
  request=f.request();request.principal=1;EXPECT_THROW(f.wallet->prepareSwapFunding(request),std::invalid_argument);
  for(unsigned mode=0;mode<7;++mode) {
    f.node.mutate=[mode](SwapOutpointInfo& x) {
      if(mode==0)x.spent=true;if(mode==1)x.spentInPool=true;if(mode==2)x.spentKnown=false;
      if(mode==3)x.amount++;if(mode==4)x.genesis.data[0]^=1;if(mode==5)x.inChain=false;
      if(mode==6){x.height++;x.confirmations++;}
    };
    EXPECT_THROW(f.wallet->prepareSwapFunding(f.request()),std::invalid_argument)<<mode;
  }
  f.node.mutate={};EXPECT_NO_THROW(f.wallet->prepareSwapFunding(f.request()));EXPECT_EQ(f.node.relays,0u);
}

TEST(SwapWalletRuntime, ClaimPayoutScansAndNextOrdinaryPrepareStillWorks) {
  WalletSwapFixture f;auto funding=f.fund();auto claim=f.wallet->prepareSwapSpend(f.spend(funding));
  EXPECT_EQ(claim.fee,1u);EXPECT_EQ(claim.principal,1001u);EXPECT_EQ(claim.tx.outputs[0].amount,1000u);
  EXPECT_EQ(f.wallet->actualBalance(),8998u);EXPECT_EQ(f.node.relays,0u);
  f.chain.setTxFee(claim.txid,1);f.chain.addTxToBlockchain(claim.tx);f.node.updateObservers();
  f.wait([&]{return f.wallet->actualBalance()==9998;});
  EXPECT_THROW(f.wallet->prepareSwapSpend(f.spend(funding)),std::invalid_argument);
  EXPECT_NO_THROW(f.wallet->preparePqTransfer({{f.other.viewPub,f.other.spendPub,100}}));
}

TEST(SwapWalletRuntime, FundingRejectsWrongOwnershipAndInconsistentMultiInputSnapshot) {
  WalletSwapFixture f;auto available=f.wallet->pqSpendableInputs();available[0].rho[0]^=1;
  const auto read=[&](const Crypto::Hash& id,uint32_t index,const Crypto::Hash& tag) {
    SwapOutpointInfo result;f.node.getSwapOutpoint(id,index,tag,result,[](std::error_code){});return result;
  };
  EXPECT_THROW(prepareSwapWalletFunding(f.request(),available,f.keys,f.currency.genesisBlockHash(),
      f.wallet->pqSyncedHeight(),read),std::invalid_argument);
  PqSpendInput fake;fake.prevTxid.data[0]=13;fake.prevOutIndex=0;fake.amount=5001;fake.rho=swapPattern<32>(14);
  auto received=buildPqTransaction({fake},{{f.keys.viewPub,f.keys.spendPub,5000}},f.other.spendPub,f.other.spendSk);
  f.chain.setTxFee(getObjectHash(received),1);f.chain.addTxToBlockchain(received);f.node.updateObservers();
  f.wait([&]{return f.wallet->actualBalance()==15000;});
  auto request=f.request();request.principal=12001;size_t queries=0;
  f.node.mutate=[&](SwapOutpointInfo& result){if(++queries==2)result.tipHash.data[0]^=1;};
  EXPECT_THROW(f.wallet->prepareSwapFunding(request),std::invalid_argument);EXPECT_EQ(queries,2u);
  f.node.mutate={};auto retry=f.wallet->prepareSwapFunding(request);
  EXPECT_EQ(retry.selectedInputs.size(),2u);EXPECT_EQ(retry.tx.outputs[1].amount,2998u);
  EXPECT_EQ(f.node.relays,0u);
}

TEST(SwapWalletRuntime, MixedPrimaryAndRoutedDepositFundingPreservesSingleKeyIndex) {
  WalletSwapFixture f;
  PqSpendInput fake;fake.prevTxid.data[0]=21;fake.prevOutIndex=0;fake.amount=5001;fake.rho=swapPattern<32>(24);
  auto received=buildPqTransaction({fake},{{f.keys.viewPub,f.keys.spendPub,5000,7}},f.other.spendPub,f.other.spendSk);
  f.chain.setTxFee(getObjectHash(received),1);f.chain.addTxToBlockchain(received);f.node.updateObservers();
  f.wait([&]{return f.wallet->actualBalance()==15000;});
  const auto owned=f.wallet->pqSpendableInputs();ASSERT_EQ(owned.size(),2u);
  const auto routedCount=std::count_if(owned.begin(),owned.end(),[](const PqSpendInput& in){return in.depositIndex==7;});
  const auto primaryCount=std::count_if(owned.begin(),owned.end(),[](const PqSpendInput& in){return in.depositIndex==PQ_PRIMARY_DEPOSIT;});
  EXPECT_EQ(routedCount,1);EXPECT_EQ(primaryCount,1);
  auto request=f.request();request.principal=12001;
  auto prepared=f.wallet->prepareSwapFunding(request);ASSERT_EQ(prepared.tx.inputs.size(),2u);
  ASSERT_EQ(prepared.selectedInputs.size(),2u);EXPECT_EQ(prepared.selectedInputs[1].depositIndex,7u);
  for(const auto& input:prepared.tx.inputs) {
    const auto& pub=boost::get<PqInput>(input).authPub;
    ASSERT_EQ(pub.size(),f.keys.spendPub.size());EXPECT_EQ(std::memcmp(pub.data(),f.keys.spendPub.data(),pub.size()),0);
  }
  // A routing bucket is not a derivation index. Altering only this local label
  // cannot switch the on-chain authority to a different ML-DSA key.
  auto relabeled=owned;for(auto& input:relabeled)if(input.depositIndex==7)input.depositIndex=8;
  const auto read=[&](const Crypto::Hash& id,uint32_t index,const Crypto::Hash& tag) {
    SwapOutpointInfo result;f.node.getSwapOutpoint(id,index,tag,result,[](std::error_code){});return result;
  };
  auto sameAuthority=prepareSwapWalletFunding(request,relabeled,f.keys,f.currency.genesisBlockHash(),f.wallet->pqSyncedHeight(),read);
  EXPECT_EQ(boost::get<PqInput>(sameAuthority.tx.inputs[1]).authPub,boost::get<PqInput>(prepared.tx.inputs[1]).authPub);
  f.chain.setTxFee(prepared.txid,1);f.chain.addTxToBlockchain(prepared.tx);f.node.updateObservers();
  f.wait([&]{return f.wallet->actualBalance()==2998;});
  EXPECT_NO_THROW(f.wallet->preparePqTransfer({{f.other.viewPub,f.other.spendPub,100}}));EXPECT_EQ(f.node.relays,0u);
}

TEST(SwapWalletRuntime, AggregatedDepositAuthorityFailsClosedWithoutChangingOwnedBalance) {
  WalletSwapFixture f;auto derived=CryptoPQ::deriveDepositSpendKeys(f.keys.seedMaster,7);
  PqSpendInput fake;fake.prevTxid.data[0]=22;fake.prevOutIndex=0;fake.amount=5001;fake.rho=swapPattern<32>(25);
  auto received=buildPqTransactionWithProof({fake},{{f.keys.viewPub,derived.first,5000}},f.other.spendPub,f.other.spendSk);
  const auto id=getObjectHash(received.tx);f.chain.setTxFee(id,1);f.chain.addTxToBlockchain(received.tx);f.node.updateObservers();
  f.wait([&]{return uint64_t(f.wallet->pqSyncedHeight())+1==f.node.getLocalBlockCount();});
  EXPECT_EQ(f.wallet->actualBalance(),10000u);EXPECT_EQ(f.wallet->pqSpendableInputs().size(),1u);
  PqSpendInput aggregate;aggregate.prevTxid=id;aggregate.prevOutIndex=0;aggregate.amount=5000;aggregate.rho=received.outputRhos[0];
  auto request=f.request();request.principal=12001;
  const auto read=[&](const Crypto::Hash& txid,uint32_t index,const Crypto::Hash& tag) {
    SwapOutpointInfo result;f.node.getSwapOutpoint(txid,index,tag,result,[](std::error_code){});return result;
  };
  for(uint32_t label:{7u,8u,PQ_PRIMARY_DEPOSIT}) {
    aggregate.depositIndex=label;auto supplied=f.wallet->pqSpendableInputs();supplied.push_back(aggregate);
    try {
      prepareSwapWalletFunding(request,supplied,f.keys,f.currency.genesisBlockHash(),f.wallet->pqSyncedHeight(),read);
      FAIL()<<"a different wallet scheme must not be inferred from a deposit label";
    } catch(const std::invalid_argument& error) {
      EXPECT_STREQ(error.what(),"swap funding input requires this SingleKeyIndex wallet authority");
    }
  }
  EXPECT_NO_THROW(f.wallet->prepareSwapFunding(f.request()));EXPECT_EQ(f.node.relays,0u);
}

TEST(SwapWalletRuntime, RefundMaturityAndRoleChecksThenPayoutScans) {
  WalletSwapFixture f;auto funding=f.fund();auto refund=f.spend(funding,true);
  EXPECT_THROW(f.wallet->prepareSwapSpend(refund),std::invalid_argument);
  auto claim=f.spend(funding);claim.rho[0]^=1;EXPECT_THROW(f.wallet->prepareSwapSpend(claim),std::invalid_argument);
  claim=f.spend(funding);claim.secret[0]^=1;EXPECT_THROW(f.wallet->prepareSwapSpend(claim),std::invalid_argument);
  const auto height=boost::get<SwapOutput>(funding.tx.outputs[0].target).refundHeight;
  while(f.node.getLocalBlockCount()<height)f.chain.generateEmptyBlocks(1);
  auto prepared=f.wallet->prepareSwapSpend(refund);EXPECT_EQ(prepared.tx.outputs[0].amount,1000u);
  EXPECT_TRUE(boost::get<SwapInput>(prepared.tx.inputs[0]).secret.empty());
  EXPECT_NO_THROW(f.wallet->prepareSwapSpend(f.spend(funding)));EXPECT_EQ(f.node.relays,0u);
  f.chain.setTxFee(prepared.txid,1);f.chain.addTxToBlockchain(prepared.tx);f.node.updateObservers();
  f.wait([&]{return f.wallet->actualBalance()==9998;});
  EXPECT_THROW(f.wallet->prepareSwapSpend(f.spend(funding)),std::invalid_argument);
}

TEST(SwapWalletRuntime, EncryptedWalletReloadAndSeedRestoreKeepRoleAuthority) {
  WalletSwapFixture f;auto funding=f.fund();std::stringstream saved;
  WalletHelper::SaveWalletResultObserver observer;
  { WalletHelper::IWalletRemoveObserverGuard guard(*f.wallet,observer);auto done=observer.saveResult.get_future();
    f.wallet->save(saved,true,true);ASSERT_FALSE(done.get()); }
  f.wallet->shutdown();f.wallet.reset(new WalletLegacy(f.currency,f.node,f.logger));saved.seekg(0);
  WalletHelper::InitWalletResultObserver init;
  { WalletHelper::IWalletRemoveObserverGuard guard(*f.wallet,init);auto done=init.initResult.get_future();
    f.wallet->initAndLoad(saved,"pass");ASSERT_FALSE(done.get()); }
  EXPECT_NO_THROW(f.wallet->prepareSwapSpend(f.spend(funding)));
  // Only role authority is seed-derived. The request/rho comes from the separate
  // recovery record; this does NOT claim mnemonic-only recovery of swap secrets.
  f.wallet->shutdown();f.wallet.reset(new WalletLegacy(f.currency,f.node,f.logger));
  f.wallet->initWithKeys(f.account,"pass");EXPECT_NO_THROW(f.wallet->prepareSwapSpend(f.spend(funding)));
  EXPECT_EQ(f.node.relays,0u);
}

TEST(SwapWalletRuntime, TrackingAndNonLabWalletsRejectPreparation) {
  WalletSwapFixture f;const auto request=f.request();auto tracking=pqTrackingKeys(f.keys);
  WalletLegacy tracked(f.currency,f.node,f.logger);AccountKeys empty{};
  tracked.initWithPqTrackingKeys(empty,tracking,"pass");
  EXPECT_THROW(tracked.prepareSwapFunding(request),std::invalid_argument);tracked.shutdown();
  Currency ordinary=CurrencyBuilder(f.logger).testnet(true).currency();
  WalletLegacy disabled(ordinary,f.node,f.logger);disabled.initWithKeys(f.account,"pass");
  EXPECT_THROW(disabled.prepareSwapFunding(request),std::invalid_argument);disabled.shutdown();
}

namespace {
struct SwapStoreDirectory {
  boost::filesystem::path root=boost::filesystem::temp_directory_path()/boost::filesystem::unique_path("xds-funding-%%%%-%%%%-%%%%");
  SwapStoreDirectory() { boost::filesystem::create_directory(root); }
  ~SwapStoreDirectory() { boost::system::error_code ignored;boost::filesystem::remove_all(root,ignored); }
  std::string path() const { return (root/"funding").string(); }
};
Crypto::Hash swapOperation(uint8_t seed=5) { Crypto::Hash value{};value.data[0]=seed;return value; }
}

TEST(SwapFundingRuntime, CanonicalRequestCommitmentMatchesIndependentClientVector) {
  SwapWalletFundingRequest request;Crypto::Hash operation{};
  for(size_t i=0;i<32;++i) {
    request.genesis.data[i]=uint8_t(i);operation.data[i]=uint8_t(i+32);
    request.contract.hashlock.data[i]=uint8_t(i+64);request.contract.nonce.data[i]=uint8_t(i+96);
    request.contract.claimCommit.data[i]=uint8_t(i+128);request.refundRho[i]=uint8_t(i+160);
  }
  request.principal=1001;request.contract.refundHeight=80;
  EXPECT_EQ(Common::podToHex(swapFundingRequestHash(operation,request)),
      "7cee2f192755bd52e0398c04294253fbc8761d78a0f9f28b5018a746be44502a");
}

TEST(SwapFundingRuntime, PreparedResponseIsExactAcrossLookupReplayAndWalletReopen) {
  WalletSwapFixture f;SwapStoreDirectory directory;const auto op=swapOperation();const auto request=f.request();
  auto first=f.wallet->prepareSwapFundingOnce(directory.path(),op,request);
  ASSERT_EQ(first.status,SwapFundingPreparation::Prepared);ASSERT_FALSE(first.prepared.wire.empty());
  EXPECT_EQ(first.requestHash,swapFundingRequestHash(op,request));EXPECT_NE(first.draftHash,Crypto::Hash{});
  EXPECT_EQ(first.prepared.fee,1u);EXPECT_EQ(first.prepared.principal,1001u);EXPECT_EQ(f.node.relays,0u);
  const auto queries=f.node.queries;
  auto lookup=f.wallet->getSwapFundingPreparation(directory.path(),op);
  auto replay=f.wallet->prepareSwapFundingOnce(directory.path(),op,request);
  EXPECT_EQ(lookup.prepared.wire,first.prepared.wire);EXPECT_EQ(replay.prepared.txid,first.prepared.txid);
  EXPECT_EQ(replay.prepared.wire,first.prepared.wire);EXPECT_EQ(f.node.queries,queries);
  std::stringstream saved;WalletHelper::SaveWalletResultObserver observer;
  { WalletHelper::IWalletRemoveObserverGuard guard(*f.wallet,observer);auto done=observer.saveResult.get_future();
    f.wallet->save(saved,true,true);ASSERT_FALSE(done.get()); }
  f.wallet->shutdown();f.wallet.reset(new WalletLegacy(f.currency,f.node,f.logger));saved.seekg(0);
  WalletHelper::InitWalletResultObserver init;
  { WalletHelper::IWalletRemoveObserverGuard guard(*f.wallet,init);auto done=init.initResult.get_future();
    f.wallet->initAndLoad(saved,"pass");ASSERT_FALSE(done.get()); }
  auto reopened=f.wallet->getSwapFundingPreparation(directory.path(),op);
  EXPECT_EQ(reopened.prepared.wire,first.prepared.wire);EXPECT_EQ(reopened.draftHash,first.draftHash);
  EXPECT_EQ(f.wallet->actualBalance(),10000u);EXPECT_NO_THROW(f.wallet->preparePqTransfer({{f.other.viewPub,f.other.spendPub,100}}));
}

TEST(SwapFundingRuntime, ChangedTermsRejectWithoutReplacingPreparedBytes) {
  WalletSwapFixture f;SwapStoreDirectory directory;const auto op=swapOperation();const auto request=f.request();
  auto first=f.wallet->prepareSwapFundingOnce(directory.path(),op,request);
  for(unsigned mode=0;mode<6;++mode) {
    auto changed=request;
    if(mode==0)++changed.principal;if(mode==1)++changed.contract.refundHeight;
    if(mode==2)changed.contract.hashlock.data[0]^=1;if(mode==3)changed.contract.nonce.data[0]^=1;
    if(mode==4)changed.contract.claimCommit.data[0]^=1;
    if(mode==5) {changed.refundRho[0]^=1;changed.contract.refundCommit=swapCommit(f.keys.spendPub,changed.refundRho);}
    EXPECT_THROW(f.wallet->prepareSwapFundingOnce(directory.path(),op,changed),std::invalid_argument)<<mode;
  }
  EXPECT_EQ(f.wallet->getSwapFundingPreparation(directory.path(),op).prepared.wire,first.prepared.wire);
}

TEST(SwapFundingRuntime, InterruptedDraftResumesFixedInputsAfterAdditionalCoinsArrive) {
  WalletSwapFixture f;SwapStoreDirectory directory;const auto op=swapOperation();auto request=f.request();request.contract.refundHeight+=100;
  const auto original=f.wallet->pqSpendableInputs();size_t reads=0;
  f.node.mutate=[&](SwapOutpointInfo& state){if(++reads>1)state.spentInPool=true;};
  EXPECT_THROW(f.wallet->prepareSwapFundingOnce(directory.path(),op,request),std::invalid_argument);
  auto pending=f.wallet->getSwapFundingPreparation(directory.path(),op);
  ASSERT_EQ(pending.status,SwapFundingPreparation::Draft);EXPECT_TRUE(pending.prepared.wire.empty());
  // A competing ordinary payment is not reserved away. The pending operation
  // must refuse interference; after it clears only the stored prefix can sign.
  EXPECT_THROW(f.wallet->prepareSwapFundingOnce(directory.path(),op,request),std::invalid_argument);
  EXPECT_EQ(f.wallet->getSwapFundingPreparation(directory.path(),op).draftHash,pending.draftHash);
  f.node.mutate={};PqSpendInput fake;fake.prevTxid.data[0]=141;fake.amount=50001;fake.rho=swapPattern<32>(114);
  auto incoming=buildPqTransaction({fake},{{f.keys.viewPub,f.keys.spendPub,50000}},f.other.spendPub,f.other.spendSk);
  f.chain.setTxFee(getObjectHash(incoming),1);f.chain.addTxToBlockchain(incoming);f.node.updateObservers();
  f.wait([&]{return f.wallet->actualBalance()==60000;});
  auto resumed=f.wallet->prepareSwapFundingOnce(directory.path(),op,request);
  ASSERT_EQ(resumed.status,SwapFundingPreparation::Prepared);ASSERT_EQ(resumed.prepared.selectedInputs.size(),1u);
  EXPECT_EQ(resumed.draftHash,pending.draftHash);EXPECT_EQ(resumed.prepared.selectedInputs[0].prevTxid,original[0].prevTxid);
  EXPECT_EQ(resumed.prepared.tx.outputs.at(1).amount,8998u);EXPECT_EQ(f.node.relays,0u);
  EXPECT_NO_THROW(f.wallet->preparePqTransfer({{f.other.viewPub,f.other.spendPub,100}}));
}

TEST(SwapFundingRuntime, PublishedBytesRemainRecoverableAfterSourcesSpentOrRpcUnavailable) {
  WalletSwapFixture f;SwapStoreDirectory directory;const auto op=swapOperation();const auto request=f.request();
  auto first=f.wallet->prepareSwapFundingOnce(directory.path(),op,request);
  f.chain.setTxFee(first.prepared.txid,1);f.chain.addTxToBlockchain(first.prepared.tx);f.node.updateObservers();
  f.wait([&]{return f.wallet->actualBalance()==8998;});
  f.node.mutate=[](SwapOutpointInfo&){throw std::runtime_error("read must not be needed for immutable lookup");};
  EXPECT_EQ(f.wallet->getSwapFundingPreparation(directory.path(),op).prepared.wire,first.prepared.wire);
  EXPECT_EQ(f.wallet->prepareSwapFundingOnce(directory.path(),op,request).prepared.wire,first.prepared.wire);
  EXPECT_EQ(f.node.relays,0u);
}

TEST(SwapFundingRuntime, AbsentLookupDoesNotCreateStoreAndDifferentWalletCannotReadIt) {
  WalletSwapFixture f;SwapStoreDirectory directory;const auto op=swapOperation();
  EXPECT_EQ(f.wallet->getSwapFundingPreparation(directory.path(),op).status,SwapFundingPreparation::Absent);
  EXPECT_FALSE(boost::filesystem::exists(directory.path()));
  auto first=f.wallet->prepareSwapFundingOnce(directory.path(),op,f.request());
  EXPECT_THROW(lookupSwapWalletFunding(directory.path(),op,f.other,f.currency.genesisBlockHash()),std::runtime_error);
  auto wrongGenesis=f.currency.genesisBlockHash();wrongGenesis.data[0]^=1;
  EXPECT_THROW(lookupSwapWalletFunding(directory.path(),op,f.keys,wrongGenesis),std::runtime_error);
  EXPECT_EQ(f.wallet->getSwapFundingPreparation(directory.path(),op).prepared.wire,first.prepared.wire);
}

TEST(SwapFundingRuntime, DraftCannotBeResignedAfterRefundDeadline) {
  WalletSwapFixture f;SwapStoreDirectory directory;const auto op=swapOperation();const auto request=f.request();size_t reads=0;
  f.node.mutate=[&](SwapOutpointInfo& state){if(++reads>1)state.spentInPool=true;};
  EXPECT_THROW(f.wallet->prepareSwapFundingOnce(directory.path(),op,request),std::invalid_argument);f.node.mutate={};
  const auto before=f.wallet->getSwapFundingPreparation(directory.path(),op);
  while(f.node.getLocalBlockCount()<=request.contract.refundHeight)f.chain.generateEmptyBlocks(1);
  f.node.updateObservers();f.wait([&]{return uint64_t(f.wallet->pqSyncedHeight())+1==f.node.getLocalBlockCount();});
  EXPECT_THROW(f.wallet->prepareSwapFundingOnce(directory.path(),op,request),std::invalid_argument);
  EXPECT_EQ(f.wallet->getSwapFundingPreparation(directory.path(),op).draftHash,before.draftHash);EXPECT_EQ(f.node.relays,0u);
}
