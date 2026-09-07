// Copyright (c) 2026, The Discrete developers. LGPL-3.0-or-later.
#include "gtest/gtest.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/SwapValidation.h"
#include "Wallet/SwapTransactionBuilder.h"
#include "Wallet/WalletLedger.h"
#include "Wallet/PqWallet.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"
#include "TestGenerator/TestGenerator.h"
#include "Common/StringTools.h"
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <memory>
#include <stdexcept>

using namespace CryptoNote;
namespace {
template<size_t N> std::array<uint8_t,N> pattern(uint8_t x) {
  std::array<uint8_t,N> r{};for(size_t i=0;i<N;++i)r[i]=static_cast<uint8_t>(x+i);return r;
}
Crypto::Hash toHash(const CryptoPQ::Hash256& h) {Crypto::Hash x{};std::memcpy(x.data,h.data(),32);return x;}
void require(bool condition,const char* text) {if(!condition)throw std::runtime_error(text);}
PqInputAuth authority(const PqWalletKeys& k) {PqInputAuth a;a.spendPub=k.spendPub;a.spendSk=k.spendSk;return a;}
struct Harness {
  Logging::ConsoleLogger logger{Logging::ERROR};
  Currency currency;
  System::Dispatcher dispatcher;
  std::unique_ptr<Core> core;
  AccountBase miner;
  std::filesystem::path dir;
  CoreConfig config;MinerConfig minerConfig;
  PqWalletKeys minerKeys{},claimant=derivePqWalletKeys(pattern<32>(41)),owner=derivePqWalletKeys(pattern<32>(77));
  std::vector<uint8_t> secret=std::vector<uint8_t>(32,0x73);
  CryptoPQ::Rho claimRho=pattern<32>(4),refundRho=pattern<32>(5);
  Transaction coinbase{};
  Transaction funding{};
  uint32_t fundingHeight=0;
  explicit Harness(uint32_t activation=14) : currency(CurrencyBuilder(logger).testnet(true).swapTestActivation(activation).currency()) {
    static unsigned serial=0;
    dir=std::filesystem::absolute(std::filesystem::path("swap_chain_") +=
      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())+"_"+std::to_string(++serial));
    require(dir.parent_path()==std::filesystem::current_path(),"test directory parent");
    require(std::filesystem::create_directory(dir),"new test directory required");
    config.configFolder=dir.string();miner.generate();
    minerKeys.viewPub=miner.pqViewPk();minerKeys.viewSk=miner.pqViewSk();minerKeys.spendPub=miner.pqSpendPk();minerKeys.spendSk=miner.pqSpendSk();
    reopen();for(int i=0;i<13;++i)require(mine(),"bootstrap block");
    Block one;require(core->getBlockByHash(core->getBlockIdByHeight(1),one),"load coinbase");coinbase=one.baseTransaction;
  }
  ~Harness() {
    if(core)core->deinit();core.reset();
    if(!::testing::Test::HasFailure()) {std::error_code ec;std::filesystem::remove_all(dir,ec);}
  }
  void reopen() {
    if(core)core->deinit();core.reset(new Core(currency,nullptr,logger,dispatcher));
    require(core->init(config,minerConfig,false),"Core init/reopen");
  }
  tx_verification_context submit(const Transaction& tx,bool kept=false) {
    tx_verification_context v{};auto bytes=toBinaryArray(tx);
    core->handleIncomingTransaction(tx,getObjectHash(tx),bytes.size(),v,kept,core->getCurrentBlockchainHeight());return v;
  }
  Block blockTemplate() {
    Block b;Difficulty difficulty;uint32_t height;
    require(core->get_block_template_pq(b,miner.pqViewPk(),miner.pqSpendPk(),difficulty,height,{}),"block template");return b;
  }
  bool mine(const std::vector<Transaction>* forced=nullptr) {
    auto b=blockTemplate();
    if(forced) {
      uint64_t oldFees=0,newFees=0;
      for(const auto& id:b.transactionHashes) {Transaction t;uint64_t f=0;require(core->getTransaction(id,t,true),"template tx");require(core->getPqTransactionFee(t,f),"template fee");oldFees+=f;}
      b.transactionHashes.clear();
      for(const auto& t:*forced) {uint64_t f=0;require(core->getPqTransactionFee(t,f),"forced fee");newFees+=f;b.transactionHashes.push_back(getObjectHash(t));}
      b.baseTransaction.outputs[0].amount=b.baseTransaction.outputs[0].amount-oldFees+newFees;
    }
    b.timestamp=static_cast<uint64_t>(std::time(nullptr))-86400+uint64_t(core->getCurrentBlockchainHeight())*currency.difficultyTarget()*10;
    std::array<uint8_t,64> header{};require(get_block_pow_header_hash(b,header),"block header");
    auto message=discrete_power_sign_message(header);auto sig=CryptoPQ::dsa_sign(miner.pqSpendSk(),message.data(),message.size());b.signature.assign(sig.begin(),sig.end());
    auto difficulty=core->getNextBlockDifficulty();if(difficulty>1)fillNonce(b,difficulty,&core->get_blockchain_storage(),miner);
    block_verification_context v{};core->handle_incoming_block(b,v,false,false);
    return v.m_added_to_main_chain && !v.m_verification_failed;
  }
  Transaction makeFunding(uint32_t refundHeight=20,const Crypto::Hash* externalHash=nullptr) {
    PqSpendInput in;in.prevTxid=getObjectHash(coinbase);in.prevOutIndex=0;in.amount=coinbase.outputs[0].amount;
    in.rho=CryptoPQ::coinbaseRho(miner.pqSpendPk(),1,0);
    SwapOutput c;c.nonce=toHash(pattern<32>(11));c.hashlock=externalHash?*externalHash:swapHashlock(secret);c.refundHeight=refundHeight;
    c.claimCommit=toHash(CryptoPQ::spendCommit(claimant.spendPub,claimRho));
    c.refundCommit=toHash(CryptoPQ::spendCommit(owner.spendPub,refundRho));
    TransactionOutput out{};out.amount=1001;out.target=c;
    return buildSwapFunding({in},{authority(minerKeys)},{SwapResolvedInput{true,coinbase.outputs[0]}},out,
      {PqSendOutput{miner.pqViewPk(),miner.pqSpendPk(),in.amount-1002}},currency.genesisBlockHash(),core->getCurrentBlockchainHeight());
  }
  void fund(uint32_t refundHeight=20,const Crypto::Hash* externalHash=nullptr) {
    funding=makeFunding(refundHeight,externalHash);auto v=submit(funding);require(v.m_added_to_pool&&!v.m_verification_failed,"fund admission");
    fundingHeight=core->getCurrentBlockchainHeight();require(mine(),"fund block");
    Transaction loaded;require(core->getTransaction(getObjectHash(funding),loaded,false),"fund persisted");require(toBinaryArray(loaded)==toBinaryArray(funding),"fund roundtrip");
  }
  Transaction spend(bool refund=false) {
    SwapInput in;in.prevTxid=getObjectHash(funding);in.prevOutIndex=0;in.branch=refund?2:1;
    auto rho=refund?refundRho:claimRho;in.rhoReveal.assign(rho.begin(),rho.end());if(!refund)in.secret=secret;
    const auto& k=refund?owner:claimant;uint32_t h=refund?boost::get<SwapOutput>(funding.outputs[0].target).refundHeight:core->getCurrentBlockchainHeight();
    return buildSwapSpend(in,funding.outputs[0],authority(k),{PqSendOutput{k.viewPub,k.spendPub,1000}},currency.genesisBlockHash(),h);
  }
  void until(uint32_t nextHeight) {while(core->getCurrentBlockchainHeight()<nextHeight)require(mine(),"advance");}
};
}

TEST(SwapActivation, MainnetAndDefaultTestnetStayDisabled) {
  Logging::ConsoleLogger logger(Logging::ERROR);
  auto main=CurrencyBuilder(logger).swapTestActivation(0).currency();
  auto test=CurrencyBuilder(logger).testnet(true).currency();
  for(uint32_t h:{0u,1u,14u,UINT32_MAX}) {EXPECT_FALSE(main.swapsEnabledAt(h));EXPECT_FALSE(test.swapsEnabledAt(h));}
}
TEST(SwapChain, ActualFundingClaimWalletAndNextOrdinarySpend) {
  Harness h;WalletLedger sender(h.minerKeys),recipient(h.claimant),observer(h.owner);
  ASSERT_TRUE(sender.processTransaction(h.coinbase,getObjectHash(h.coinbase),1));h.fund();
  ASSERT_TRUE(sender.processTransaction(h.funding,getObjectHash(h.funding),h.fundingHeight));
  auto row=sender.historyByTxid(getObjectHash(h.funding));ASSERT_NE(row,nullptr);EXPECT_EQ(row->fee,1u);
  auto claim=h.spend();auto v=h.submit(claim);ASSERT_TRUE(v.m_added_to_pool);ASSERT_FALSE(v.m_verification_failed);
  auto t=h.blockTemplate();ASSERT_EQ(t.transactionHashes.size(),1u);EXPECT_EQ(t.transactionHashes[0],getObjectHash(claim));
  uint64_t fee=0;ASSERT_TRUE(h.core->getPqTransactionFee(claim,fee));EXPECT_EQ(fee,1u);
  auto claimHeight=h.core->getCurrentBlockchainHeight();ASSERT_TRUE(h.mine());
  ASSERT_TRUE(recipient.processTransaction(claim,getObjectHash(claim),claimHeight));
  EXPECT_FALSE(observer.processTransaction(claim,getObjectHash(claim),claimHeight));
  auto inputs=recipient.spendableInputs();ASSERT_EQ(inputs.size(),1u);EXPECT_EQ(inputs[0].amount,1000u);
  auto ordinary=buildPqTransaction(inputs,{PqSendOutput{h.owner.viewPub,h.owner.spendPub,999}},h.claimant.spendPub,h.claimant.spendSk);
  ASSERT_TRUE(h.submit(ordinary).m_added_to_pool);ASSERT_TRUE(h.mine());
  EXPECT_TRUE(observer.processTransaction(ordinary,getObjectHash(ordinary),claimHeight+1));
  EXPECT_TRUE(h.core->get_blockchain_storage().haveSpentKeyImages(claim));
}
TEST(SwapChain, RefundBoundaryNegativeCacheRetryAndRestart) {
  Harness h;h.fund(17);auto refund=h.spend(true);
  BlockInfo used,failed;
  EXPECT_FALSE(h.core->get_blockchain_storage().checkTransactionInputs(refund,used,failed));
  EXPECT_FALSE(h.submit(refund).m_added_to_pool);h.until(17);
  ASSERT_TRUE(h.core->get_blockchain_storage().checkTransactionInputs(refund,used,failed));
  ASSERT_TRUE(h.submit(refund).m_added_to_pool);ASSERT_TRUE(h.mine());h.reopen();
  Transaction stored;ASSERT_TRUE(h.core->getTransaction(getObjectHash(refund),stored,false));
  EXPECT_EQ(toBinaryArray(stored),toBinaryArray(refund));EXPECT_TRUE(h.core->get_blockchain_storage().haveSpentKeyImages(refund));
  EXPECT_FALSE(h.submit(h.spend()).m_added_to_pool);
  WalletLedger restored(h.owner);ASSERT_TRUE(restored.processTransaction(stored,getObjectHash(stored),17));
  EXPECT_EQ(restored.spendableInputs().size(),1u);
}
TEST(SwapChain, ActivationBoundaryRejectThenAcceptSameSignedFunding) {
  Harness h(16);auto fund=h.makeFunding(22);EXPECT_FALSE(h.submit(fund).m_added_to_pool);h.until(16);
  ASSERT_TRUE(h.submit(fund).m_added_to_pool);ASSERT_TRUE(h.mine());
}
TEST(SwapChain, BothClaimRefundOrdersConflictInPoolAndChain) {
  for(bool firstRefund:{false,true}) {
    Harness h;h.fund(16);h.until(16);auto first=h.spend(firstRefund),other=h.spend(!firstRefund);
    ASSERT_TRUE(h.submit(first).m_added_to_pool);EXPECT_FALSE(h.submit(other).m_added_to_pool);
    ASSERT_TRUE(h.mine());EXPECT_FALSE(h.submit(other).m_added_to_pool);
  }
}
TEST(SwapChain, BlockDoubleSpendAbortsAllWritesAndRetryWorks) {
  Harness h;h.fund(16);h.until(16);auto claim=h.spend(),refund=h.spend(true);
  ASSERT_TRUE(h.submit(claim,true).m_added_to_pool);ASSERT_TRUE(h.submit(refund,true).m_added_to_pool);
  auto height=h.core->getCurrentBlockchainHeight();std::vector<Transaction> both{claim,refund};
  EXPECT_FALSE(h.mine(&both));EXPECT_EQ(h.core->getCurrentBlockchainHeight(),height);
  EXPECT_FALSE(h.core->get_blockchain_storage().haveSpentKeyImages(claim));
  Transaction absent;EXPECT_FALSE(h.core->getTransaction(getObjectHash(claim),absent,false));
  // Failed block validation may return taken transactions to the pool; restore missing intents only.
  if(!h.core->getTransaction(getObjectHash(refund),absent,true))ASSERT_TRUE(h.submit(refund,true).m_added_to_pool);
  std::vector<Transaction> one{refund};ASSERT_TRUE(h.mine(&one));
  EXPECT_TRUE(h.core->get_blockchain_storage().haveSpentKeyImages(claim));
}
TEST(SwapChain, ActualRollbackRemovesSpendAndRestoresAlternativeRight) {
  Harness h;h.fund(17);h.until(17);auto claim=h.spend();ASSERT_TRUE(h.submit(claim).m_added_to_pool);ASSERT_TRUE(h.mine());
  h.core->get_blockchain_storage().rollbackBlockchainTo(16);
  EXPECT_EQ(h.core->getCurrentBlockchainHeight(),17u);EXPECT_FALSE(h.core->get_blockchain_storage().haveSpentKeyImages(claim));
  auto refund=h.spend(true);BlockInfo used;ASSERT_TRUE(h.core->get_blockchain_storage().checkTransactionInputs(refund,used));
  Transaction t;if(!h.core->getTransaction(getObjectHash(refund),t,true))ASSERT_TRUE(h.submit(refund,true).m_added_to_pool);
  std::vector<Transaction> one{refund};ASSERT_TRUE(h.mine(&one));h.reopen();EXPECT_TRUE(h.core->get_blockchain_storage().haveSpentKeyImages(claim));
}
TEST(SwapChain, CheckpointCannotBypassBadSwapSignature) {
  Harness h;h.fund();auto bad=h.spend();bad.pqSignatures[0][0]^=1;
  ASSERT_TRUE(h.submit(bad,true).m_added_to_pool);
  Checkpoints checkpoints(h.logger);ASSERT_TRUE(checkpoints.add_checkpoint(100,std::string(64,'1')));h.core->set_checkpoints(std::move(checkpoints));
  ASSERT_TRUE(h.core->isInCheckpointZone(h.core->getCurrentBlockchainHeight()));
  auto height=h.core->getCurrentBlockchainHeight();std::vector<Transaction> one{bad};EXPECT_FALSE(h.mine(&one));
  EXPECT_EQ(h.core->getCurrentBlockchainHeight(),height);EXPECT_FALSE(h.core->get_blockchain_storage().haveSpentKeyImages(bad));
}
TEST(SwapChain, OrdinaryInputCannotStealEitherSwapRole) {
  Harness h;h.fund();PqSpendInput input;input.prevTxid=getObjectHash(h.funding);input.prevOutIndex=0;input.amount=1001;input.rho=h.claimRho;
  auto forged=buildPqTransaction({input},{PqSendOutput{h.claimant.viewPub,h.claimant.spendPub,1000}},h.claimant.spendPub,h.claimant.spendSk);
  EXPECT_FALSE(h.submit(forged).m_added_to_pool);auto good=h.spend();ASSERT_TRUE(h.submit(good).m_added_to_pool);ASSERT_TRUE(h.mine());
}
TEST(SwapWire, RealFundingAndSpendRoundTripTruncationAndCanonicalGate) {
  Harness h;h.fund();for(const auto& tx:{h.funding,h.spend(),h.spend(true)}) {
    auto bytes=toBinaryArray(tx);Transaction parsed;Crypto::Hash id{},prefix{};
    ASSERT_TRUE(parseAndValidateTransactionFromBinaryArray(bytes,parsed,id,prefix));EXPECT_EQ(toBinaryArray(parsed),bytes);
    for(size_t n=0;n<bytes.size();++n) {BinaryArray cut(bytes.begin(),bytes.begin()+n);ASSERT_FALSE(fromBinaryArray(parsed,cut))<<n;}
    bytes.push_back(0);EXPECT_FALSE(parseAndValidateTransactionFromBinaryArray(bytes,parsed,id,prefix));
  }
}
TEST(SwapChain, FundingInputsConflictWithOrdinaryPaymentsAndMatureBeforeUse) {
  Harness h;auto fund=h.makeFunding();ASSERT_TRUE(h.submit(fund).m_added_to_pool);
  auto input=boost::get<PqInput>(fund.inputs[0]);PqSpendInput desc;desc.prevTxid=input.prevTxid;desc.prevOutIndex=input.prevOutIndex;
  desc.amount=h.coinbase.outputs[0].amount;std::copy(input.rhoReveal.begin(),input.rhoReveal.end(),desc.rho.begin());
  auto ordinary=buildPqTransaction({desc},{PqSendOutput{h.owner.viewPub,h.owner.spendPub,desc.amount-1}},h.miner.pqSpendPk(),h.miner.pqSpendSk());
  EXPECT_FALSE(h.submit(ordinary).m_added_to_pool);ASSERT_TRUE(h.mine());EXPECT_FALSE(h.submit(ordinary).m_added_to_pool);
}
TEST(SwapChain, HostilePolicyWitnessAmountsAndSignatureCannotConsumeRealOutput) {
  Harness h;h.fund();const auto original=h.spend();
  for(unsigned mode=0;mode<10;mode++) {
    auto bad=original;auto& in=boost::get<SwapInput>(bad.inputs[0]);
    switch(mode) {
      case 0:in.branch=3;break;case 1:in.secret[0]^=1;break;case 2:in.rhoReveal[0]^=1;break;
      case 3:in.prevOutIndex=999;break;case 4:bad.pqSignatures[0][0]^=1;break;
      case 5:bad.outputs[0].amount=UINT64_MAX;break;case 6:bad.outputs[0].amount=0;break;
      case 7:bad.outputs[0].amount=1001;break;case 8:bad.outputs[0].amount=999;break;
      case 9:bad.unlockHeight=1;break;
    }
    EXPECT_FALSE(h.submit(bad).m_added_to_pool)<<mode;
    EXPECT_FALSE(h.core->get_blockchain_storage().haveSpentKeyImages(original));
  }
  ASSERT_TRUE(h.submit(original).m_added_to_pool);ASSERT_TRUE(h.mine());
}
TEST(SwapWire, DeterministicMutationCorpusPreservesCanonicalBytesOrRejects) {
  Harness h;h.fund();std::mt19937_64 random(0x584453);
  const auto seed=toBinaryArray(h.spend());
  for(unsigned i=0;i<20000;i++) {
    auto bytes=seed;
    for(unsigned j=0;j<1+(i%8);j++)bytes[random()%bytes.size()]^=uint8_t(1u<<(random()%8));
    if(i%7==0)bytes.resize(random()%bytes.size());
    Transaction tx;Crypto::Hash id{},prefix{};
    if(parseAndValidateTransactionFromBinaryArray(bytes,tx,id,prefix))EXPECT_EQ(toBinaryArray(tx),bytes)<<i;
  }
}
TEST(SwapChain, MaximumFundingShapeAndOrdinaryPaymentShareTemplateAtBaseFee) {
  Harness h;h.until(23);auto sample=h.makeFunding(80);std::vector<PqSpendInput> inputs;
  std::vector<PqInputAuth> auth;std::vector<SwapResolvedInput> resolved;uint64_t total=0;
  for(uint32_t height=1;height<=8;height++) {
    Block b;ASSERT_TRUE(h.core->getBlockByHash(h.core->getBlockIdByHeight(height),b));
    PqSpendInput in;in.prevTxid=getObjectHash(b.baseTransaction);in.prevOutIndex=0;in.amount=b.baseTransaction.outputs[0].amount;
    in.rho=CryptoPQ::coinbaseRho(h.miner.pqSpendPk(),height,0);total+=in.amount;inputs.push_back(in);
    auth.push_back(authority(h.minerKeys));resolved.push_back({true,b.baseTransaction.outputs[0]});
  }
  auto funding=buildSwapFunding(inputs,auth,resolved,sample.outputs[0],
    {PqSendOutput{h.miner.pqViewPk(),h.miner.pqSpendPk(),total-1002}},h.currency.genesisBlockHash(),23);
  EXPECT_LE(toBinaryArray(funding).size(),65536u);RecordProperty("fund8_wire_bytes",static_cast<int>(toBinaryArray(funding).size()));
  std::string error;auto started=std::chrono::steady_clock::now();
  for(int i=0;i<1000;i++)ASSERT_TRUE(checkSwapTransactionInputs(funding,resolved,h.currency.genesisBlockHash(),23,nullptr,nullptr,&error));
  RecordProperty("fund8_1000_verifications_ms",static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count()));
  Block b;ASSERT_TRUE(h.core->getBlockByHash(h.core->getBlockIdByHeight(9),b));PqSpendInput ordinaryInput;
  ordinaryInput.prevTxid=getObjectHash(b.baseTransaction);ordinaryInput.prevOutIndex=0;ordinaryInput.amount=b.baseTransaction.outputs[0].amount;
  ordinaryInput.rho=CryptoPQ::coinbaseRho(h.miner.pqSpendPk(),9,0);
  auto ordinary=buildPqTransaction({ordinaryInput},{PqSendOutput{h.owner.viewPub,h.owner.spendPub,ordinaryInput.amount-1}},h.miner.pqSpendPk(),h.miner.pqSpendSk());
  ASSERT_TRUE(h.submit(funding).m_added_to_pool);ASSERT_TRUE(h.submit(ordinary).m_added_to_pool);
  auto block=h.blockTemplate();EXPECT_EQ(block.transactionHashes.size(),2u);ASSERT_TRUE(h.mine());
  Transaction stored;EXPECT_TRUE(h.core->getTransaction(getObjectHash(funding),stored,false));EXPECT_TRUE(h.core->getTransaction(getObjectHash(ordinary),stored,false));
  inputs.push_back(inputs[0]);auth.push_back(auth[0]);resolved.push_back(resolved[0]);
  EXPECT_THROW(buildSwapFunding(inputs,auth,resolved,sample.outputs[0],{},h.currency.genesisBlockHash(),24),std::invalid_argument);
}
int main(int argc,char** argv) {
  // Local pair-harness entry, no P2P/RPC node and no real wallet. Foreign funding is driven externally first.
  if(argc==3 && std::string(argv[1])=="--pair-session") {
    try {
      auto decode=[](const std::string& s,uint8_t* p){require(s.size()==64,"32-byte hex");for(size_t i=0;i<32;i++){
        auto digit=[](char c)->unsigned{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;throw std::runtime_error("hex");};
        p[i]=static_cast<uint8_t>((digit(s[2*i])<<4)|digit(s[2*i+1]));}};
      const auto prefix=std::filesystem::absolute(argv[2]);require(prefix.parent_path()==std::filesystem::current_path(),"pair output directory");
      std::string wire;require(bool(std::getline(std::cin,wire)),"pair public hash");Crypto::Hash externalHash{};decode(wire,externalHash.data);
      Harness h;h.fund(32,&externalHash);h.until(h.fundingHeight+11);
      const uint32_t confirmations=h.core->getCurrentBlockchainHeight()-h.fundingHeight;
      require(confirmations>=11,"pair confirmation floor");
      {std::ofstream ready(prefix.string()+".funded.tmp");ready<<"{\"confirmations\":"<<confirmations<<",\"next_height\":"<<h.core->getCurrentBlockchainHeight()<<",\"refund_height\":32,\"txid\":\""<<Common::podToHex(getObjectHash(h.funding))<<"\",\"vout\":0,\"hashlock\":\""<<Common::podToHex(externalHash)<<"\"}\n";ready.close();require(bool(ready),"fund receipt");}
      std::filesystem::rename(prefix.string()+".funded.tmp",prefix.string()+".funded.json");
      // No preimage enters this process until the external coordinator observes the funding receipt.
      require(bool(std::getline(std::cin,wire)),"pair settlement command");const bool refund=wire=="REFUND";
      if(refund)h.until(32);else decode(wire,h.secret.data());
      auto spend=h.spend(refund);const auto preparedId=Common::podToHex(getObjectHash(spend));
      {std::ofstream prepared(prefix.string()+".prepared.tmp");prepared<<"{\"txid\":\""<<preparedId<<"\",\"wire\":\""<<Common::toHex(toBinaryArray(spend))<<"\"}\n";prepared.close();require(bool(prepared),"prepared receipt");}
      std::filesystem::rename(prefix.string()+".prepared.tmp",prefix.string()+".prepared.json");
      require(bool(std::getline(std::cin,wire)) && wire=="COMMIT "+preparedId,"durable signed-transaction acknowledgement");
      require(h.submit(spend).m_added_to_pool,"pair settlement admission");require(h.mine(),"pair settlement mined");h.reopen();
      Transaction stored;require(h.core->getTransaction(getObjectHash(spend),stored,false),"pair persisted spend");
      require(h.core->get_blockchain_storage().haveSpentKeyImages(stored),"pair spend tag durable");
      WalletLedger ledger(refund?h.owner:h.claimant);require(ledger.processTransaction(stored,getObjectHash(stored),h.core->getCurrentBlockchainHeight()-1),"pair wallet scan");
      require(ledger.spendableInputs().size()==1 && ledger.spendableInputs()[0].amount==1000,"pair net amount");
      std::ofstream output(prefix.string()+".settled.json");require(bool(output),"pair receipt open");
      auto hex=[&](const uint8_t* b,size_t n){for(size_t i=0;i<n;i++)output<<std::hex<<std::setfill('0')<<std::setw(2)<<unsigned(b[i]);output<<std::dec;};
      output<<"{\"mode\":\""<<(refund?"refund":"claim")<<"\",\"funding_confirmations\":"<<confirmations<<",\"fee_atoms\":1,\"net_atoms\":1000,\"txid\":\"";
      auto id=getObjectHash(stored);hex(id.data,32);output<<"\",\"hashlock\":\"";hex(externalHash.data,32);
      output<<"\",\"observed_preimage\":\"";const auto& revealed=boost::get<SwapInput>(stored.inputs[0]).secret;hex(revealed.data(),revealed.size());output<<"\"}\n";
      output.flush();require(bool(output),"pair receipt write");return 0;
    } catch(const std::exception& e) {std::cerr<<e.what()<<std::endl;return 1;}
  }
  ::testing::InitGoogleTest(&argc,argv);return RUN_ALL_TESTS();
}
