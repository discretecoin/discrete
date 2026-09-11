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
#include "PqTxType.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"
#include "TestGenerator/TestGenerator.h"
#include "Common/StringTools.h"
#include "BlockchainExplorer/BlockchainExplorerDataBuilder.h"
#include "Serialization/BlockchainExplorerDataSerialization.h"
#include "Serialization/SerializationTools.h"
#include <chrono>
#include <algorithm>
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
struct ExplorerProtocolQuery final : ICryptoNoteProtocolQuery {
  bool addObserver(ICryptoNoteProtocolObserver*) override { return true; }
  bool removeObserver(ICryptoNoteProtocolObserver*) override { return true; }
  uint32_t getObservedHeight() const override { return 0; }
  size_t getPeerCount() const override { return 0; }
  bool isSynchronized() const override { return true; }
  bool getConnections(std::vector<CryptoNoteConnectionContext>&) const override { return true; }
  void printDandelions() const override {}
};
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
  explicit Harness(uint32_t activation=14,
      uint32_t delivery=parameters::PQ_DELIVERY_V2_HEIGHT_TESTNET)
      : currency(CurrencyBuilder(logger).testnet(true).swapTestActivation(activation).pqDeliveryV2Height(delivery).currency()) {
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

Transaction ordinaryCoinbaseSpend(Harness& h, uint32_t coinbaseHeight, uint8_t type,
    const PqWalletKeys& recipient, uint64_t amount, uint64_t route=0) {
  Block block;
  require(h.core->getBlockByHash(h.core->getBlockIdByHeight(coinbaseHeight),block),"ordinary coinbase source");
  const auto& source=block.baseTransaction;
  PqSpendInput input;
  input.prevTxid=getObjectHash(source);input.prevOutIndex=0;input.amount=source.outputs.at(0).amount;
  input.rho=CryptoPQ::coinbaseRho(h.miner.pqSpendPk(),coinbaseHeight,0);
  require(input.amount>amount+parameters::MINIMUM_FEE,"ordinary source covers fee");
  auto signing=pqSigningContextForHeight(h.core->getCurrentBlockchainHeight(),h.currency.genesisBlockHash());
  signing.txType=type;
  return buildPqTransaction({input},{PqSendOutput{recipient.viewPub,recipient.spendPub,amount,route},
      PqSendOutput{h.miner.pqViewPk(),h.miner.pqSpendPk(),input.amount-amount-parameters::MINIMUM_FEE}},
      h.miner.pqSpendPk(),h.miner.pqSpendSk(),0,{},signing);
}

}

TEST(SwapActivation, MainnetAndDefaultTestnetStayDisabled) {
  Logging::ConsoleLogger logger(Logging::ERROR);
  auto main=CurrencyBuilder(logger).swapTestActivation(0).currency();
  auto test=CurrencyBuilder(logger).testnet(true).currency();
  for(uint32_t h:{0u,1u,14u,UINT32_MAX}) {EXPECT_FALSE(main.swapsEnabledAt(h));EXPECT_FALSE(test.swapsEnabledAt(h));}
}

TEST(SwapCoexistence, CanonicalPqV2AndSwapWireFamiliesRemainDistinct) {
  // Literal assignments guard against another collision with a canonical type.
  EXPECT_EQ(TX_PQ_V2,0x04);EXPECT_EQ(TX_SWAP_SPEND,0x05);EXPECT_EQ(TX_SWAP_FUND,0x06);
  EXPECT_TRUE(isPqTransfer(TX_PQ_V2));EXPECT_FALSE(isPqTransfer(TX_SWAP_FUND));
  EXPECT_FALSE(isPqTransfer(TX_SWAP_SPEND));
  Harness h(14,14);
  const auto ordinary=ordinaryCoinbaseSpend(h,2,TX_PQ_V2,h.owner,2000);
  const auto funding=h.makeFunding(20);
  for(const auto& tx:{ordinary,funding}) {
    Transaction decoded;
    const auto wire=toBinaryArray(tx);
    ASSERT_TRUE(fromBinaryArray(decoded,wire));
    EXPECT_EQ(toBinaryArray(decoded),wire);EXPECT_EQ(decoded.txType,tx.txType);
  }
  std::string error;
  EXPECT_TRUE(checkPqTransactionSemantic(ordinary,&error));
  EXPECT_FALSE(checkSwapTransactionSemantic(ordinary,&error));
  EXPECT_TRUE(checkSwapTransactionSemantic(funding,&error));
  EXPECT_FALSE(checkPqTransactionSemantic(funding,&error));
  // A type label cannot reinterpret one family's output shape as the other.
  auto mislabeledFunding=funding;mislabeledFunding.txType=TX_PQ_V2;
  auto mislabeledOrdinary=ordinary;mislabeledOrdinary.txType=TX_SWAP_FUND;
  EXPECT_FALSE(checkPqTransactionSemantic(mislabeledFunding,&error));
  EXPECT_FALSE(checkSwapTransactionSemantic(mislabeledOrdinary,&error));
}

TEST(SwapCoexistence, DeliveryBoundaryKeepsMixedFeesWalletsAndRestart) {
  Harness h(14,15);
  ASSERT_EQ(h.core->getCurrentBlockchainHeight(),14u);
  const auto legacy=ordinaryCoinbaseSpend(h,2,TX_PQ,h.owner,2000);
  const auto future=ordinaryCoinbaseSpend(h,3,TX_PQ_V2,h.claimant,3000,9000);
  const auto early=h.submit(future);
  EXPECT_FALSE(early.m_added_to_pool);EXPECT_TRUE(early.m_verification_failed);
  h.funding=h.makeFunding(20);
  ASSERT_TRUE(h.submit(h.funding).m_added_to_pool);
  ASSERT_TRUE(h.submit(legacy).m_added_to_pool);
  auto first=h.blockTemplate();ASSERT_EQ(first.transactionHashes.size(),2u);
  ASSERT_TRUE(h.mine());
  ExplorerProtocolQuery protocol;BlockchainExplorerDataBuilder explorer(*h.core,protocol);
  Block firstBlock;ASSERT_TRUE(h.core->getBlockByHash(h.core->getBlockIdByHeight(14),firstBlock));
  BlockDetails firstDetails{};ASSERT_TRUE(explorer.fillBlockDetails(firstBlock,firstDetails));
  EXPECT_EQ(firstDetails.totalFeeAmount,2u);

  WalletLedger miner(h.minerKeys);
  ASSERT_TRUE(miner.processTransaction(h.coinbase,getObjectHash(h.coinbase),1));
  ASSERT_TRUE(miner.processTransaction(h.funding,getObjectHash(h.funding),14));
  const auto* outgoing=miner.historyByTxid(getObjectHash(h.funding));ASSERT_NE(outgoing,nullptr);
  EXPECT_EQ(outgoing->fee,1u);EXPECT_EQ(outgoing->netAmount,-1002);
  EXPECT_EQ(miner.balance(),h.coinbase.outputs[0].amount-1002);

  ASSERT_EQ(h.core->getCurrentBlockchainHeight(),15u);
  const auto past=ordinaryCoinbaseSpend(h,4,TX_PQ,h.owner,2000);
  EXPECT_FALSE(h.submit(past).m_added_to_pool);
  const auto claim=h.spend();
  ASSERT_TRUE(h.submit(future).m_added_to_pool);ASSERT_TRUE(h.submit(claim).m_added_to_pool);
  auto mixed=h.blockTemplate();ASSERT_EQ(mixed.transactionHashes.size(),2u);
  for(const auto& tx:{future,claim}) {
    uint64_t fee=0;ASSERT_TRUE(h.core->getPqTransactionFee(tx,fee));EXPECT_EQ(fee,1u);
    EXPECT_NE(std::find(mixed.transactionHashes.begin(),mixed.transactionHashes.end(),getObjectHash(tx)),mixed.transactionHashes.end());
  }
  ASSERT_TRUE(h.mine());
  Block mixedBlock;ASSERT_TRUE(h.core->getBlockByHash(h.core->getBlockIdByHeight(15),mixedBlock));
  BlockDetails mixedDetails{};ASSERT_TRUE(explorer.fillBlockDetails(mixedBlock,mixedDetails));
  EXPECT_EQ(mixedDetails.totalFeeAmount,2u);

  WalletLedger claimant(h.claimant);
  claimant.setDepositConfig(PqDepositScheme::SingleKeyIndex,3);
  claimant.setLegacyTWindowRescan(64);
  ASSERT_TRUE(claimant.processTransaction(future,getObjectHash(future),15));
  ASSERT_TRUE(claimant.processTransaction(claim,getObjectHash(claim),15));
  EXPECT_EQ(claimant.depositBalance(9000),3000u);EXPECT_EQ(claimant.balance(),4000u);
  EXPECT_FALSE(claimant.processTransaction(future,getObjectHash(future),15));
  claimant.rollbackToHeight(15);EXPECT_EQ(claimant.balance(),0u);
  ASSERT_TRUE(claimant.processTransaction(future,getObjectHash(future),15));
  ASSERT_TRUE(claimant.processTransaction(claim,getObjectHash(claim),15));
  EXPECT_EQ(claimant.balance(),4000u);
  h.reopen();
  for(const auto& tx:{legacy,h.funding,future,claim}) {
    Transaction stored;ASSERT_TRUE(h.core->getTransaction(getObjectHash(tx),stored,false));
    EXPECT_EQ(toBinaryArray(stored),toBinaryArray(tx));
  }
  auto signing=pqSigningContextForHeight(h.core->getCurrentBlockchainHeight(),h.currency.genesisBlockHash());
  signing.txType=TX_PQ_V2;
  const auto ordinary=buildPqTransaction(claimant.spendableInputs(),
      {PqSendOutput{h.owner.viewPub,h.owner.spendPub,3999}},h.claimant.spendPub,h.claimant.spendSk,0,{},signing);
  ASSERT_TRUE(h.submit(ordinary).m_added_to_pool);ASSERT_TRUE(h.mine());
  WalletLedger recipient(h.owner);
  ASSERT_TRUE(recipient.processTransaction(ordinary,getObjectHash(ordinary),16));
  EXPECT_EQ(recipient.balance(),3999u);
}

TEST(SwapChain, ExplorerDetailsResolveSwapFeesAndStoredBranchWitness) {
  for(bool refund:{false,true}) {
    Harness h;ExplorerProtocolQuery protocol;BlockchainExplorerDataBuilder builder(*h.core,protocol);
    h.fund(17);Transaction loaded;ASSERT_TRUE(h.core->getTransaction(getObjectHash(h.funding),loaded,false));
    TransactionDetails funded{};ASSERT_TRUE(builder.fillTransactionDetails(loaded,funded));
    EXPECT_TRUE(funded.inBlockchain);EXPECT_EQ(funded.fee,1u);
    EXPECT_EQ(funded.totalInputsAmount,h.coinbase.outputs[0].amount);
    EXPECT_EQ(funded.totalInputsAmount,funded.totalOutputsAmount+1);
    ASSERT_EQ(funded.inputs.size(),1u);EXPECT_TRUE(funded.inputs[0].type()==typeid(PqInputDetails));
    ASSERT_EQ(funded.outputs.size(),2u);EXPECT_TRUE(funded.outputs[0].output.target.type()==typeid(SwapOutput));
    if(refund)h.until(17);auto spend=h.spend(refund);ASSERT_TRUE(h.submit(spend).m_added_to_pool);
    TransactionDetails pending{};ASSERT_TRUE(builder.fillTransactionDetails(spend,pending));EXPECT_FALSE(pending.inBlockchain);
    ASSERT_TRUE(h.mine());ASSERT_TRUE(h.core->getTransaction(getObjectHash(spend),loaded,false));
    TransactionDetails details{};ASSERT_TRUE(builder.fillTransactionDetails(loaded,details));
    EXPECT_TRUE(details.inBlockchain);EXPECT_EQ(details.fee,1u);EXPECT_EQ(details.totalInputsAmount,1001u);EXPECT_EQ(details.totalOutputsAmount,1000u);
    ASSERT_EQ(details.inputs.size(),1u);ASSERT_TRUE(details.inputs[0].type()==typeid(SwapInputDetails));
    const auto& input=boost::get<SwapInputDetails>(details.inputs[0]);
    EXPECT_EQ(input.amount,1001u);EXPECT_EQ(input.input.branch,refund?2:1);
    EXPECT_EQ(input.input.secret,boost::get<SwapInput>(loaded.inputs[0]).secret);
    EXPECT_EQ(input.output.transactionHash,getObjectHash(h.funding));EXPECT_EQ(input.output.number,0u);
    const auto expected=swapSpendTag(input.input,h.currency.genesisBlockHash());
    EXPECT_EQ(std::memcmp(input.spendTag.data,expected.data,32),0);
    const auto json=storeToJson(details);TransactionDetails decoded{};ASSERT_TRUE(loadFromJson(decoded,json));
    ASSERT_TRUE(decoded.inputs[0].type()==typeid(SwapInputDetails));
    EXPECT_EQ(boost::get<SwapInputDetails>(decoded.inputs[0]).input.secret,input.input.secret);
    EXPECT_EQ(storeToJson(decoded),json);
    Block block;ASSERT_TRUE(h.core->getBlockByHash(details.blockHash,block));BlockDetails blockDetails{};
    ASSERT_TRUE(builder.fillBlockDetails(block,blockDetails));EXPECT_EQ(blockDetails.totalFeeAmount,1u);
    EXPECT_EQ(blockDetails.transactions.size(),2u);
    const auto& recipient=refund?h.owner:h.claimant;WalletLedger ledger(recipient);
    ASSERT_TRUE(ledger.processTransaction(loaded,getObjectHash(loaded),details.blockHeight));
    auto ordinary=buildPqTransaction(ledger.spendableInputs(),{PqSendOutput{h.owner.viewPub,h.owner.spendPub,999}},recipient.spendPub,recipient.spendSk);
    ASSERT_TRUE(h.submit(ordinary).m_added_to_pool);ASSERT_TRUE(h.mine());TransactionDetails adjacent{};
    ASSERT_TRUE(builder.fillTransactionDetails(ordinary,adjacent));EXPECT_EQ(adjacent.fee,1u);
    EXPECT_TRUE(adjacent.inputs[0].type()==typeid(PqInputDetails));EXPECT_TRUE(adjacent.inBlockchain);
  }
}
TEST(SwapChain, ContractPrincipalMustExceedExitFee) {
  Harness h;
  for(uint64_t principal:{0u,1u}) {
    auto tx=h.makeFunding();tx.outputs[0].amount=principal;
    auto& change=tx.outputs[1];change.amount=h.coinbase.outputs[0].amount-principal-parameters::MINIMUM_FEE;
    auto built=CryptoPQ::buildPqOutput(h.miner.pqViewPk(),h.miner.pqSpendPk(),pqTransactionInputsHash(tx),1,change.amount,0);
    PqOutput out;out.kemCt.assign(built.kemCt.begin(),built.kemCt.end());out.encPayload=std::move(built.encPayload);
    std::memcpy(out.spendCommit.data,built.spendCommit.data(),32);change.target=std::move(out);
    const std::vector<SwapResolvedInput> resolved{{true,h.coinbase.outputs[0]}};
    const auto digest=swapSigningDigest(tx,resolved,h.currency.genesisBlockHash(),0);
    tx.pqSignatures[0]=CryptoPQ::dsa_sign(h.miner.pqSpendSk(),digest.data(),digest.size());
    ASSERT_TRUE(CryptoPQ::dsa_verify(h.miner.pqSpendPk(),digest.data(),digest.size(),tx.pqSignatures[0]));
    // These are correctly signed amounts, not mutations masked by an invalid signature.
    const auto result=h.submit(tx);
    EXPECT_FALSE(result.m_added_to_pool)<<principal;
    EXPECT_TRUE(result.m_verification_failed)<<principal;
  }
}
TEST(SwapChain, ImmatureKeptRefundGetsCorrectFeeWhenTemplateBecomesReady) {
  Harness h;h.fund(17);auto refund=h.spend(true);
  const auto early=h.submit(refund,true);
  ASSERT_TRUE(early.m_added_to_pool);ASSERT_TRUE(early.m_verifivation_impossible);
  h.until(17);
  auto block=h.blockTemplate();ASSERT_EQ(block.transactionHashes.size(),1u);
  EXPECT_EQ(block.transactionHashes[0],getObjectHash(refund));
  // Use the actual template without the forced-block helper's coinbase adjustment.
  ASSERT_TRUE(h.mine());
  Transaction stored;ASSERT_TRUE(h.core->getTransaction(getObjectHash(refund),stored,false));
  h.reopen();EXPECT_TRUE(h.core->get_blockchain_storage().haveSpentKeyImages(refund));
}
TEST(SwapChain, MinimumSpendablePrincipalSupportsBothExitBranchesAtBaseFee) {
  for(bool refund:{false,true}) {
    Harness h;auto sample=h.makeFunding(17);sample.outputs[0].amount=2;
    const auto& source=boost::get<PqInput>(sample.inputs[0]);
    PqSpendInput input;input.prevTxid=source.prevTxid;input.prevOutIndex=source.prevOutIndex;
    input.amount=h.coinbase.outputs[0].amount;std::copy(source.rhoReveal.begin(),source.rhoReveal.end(),input.rho.begin());
    const std::vector<SwapResolvedInput> resolved{{true,h.coinbase.outputs[0]}};
    auto unspendable=sample.outputs[0];unspendable.amount=1;
    EXPECT_THROW(buildSwapFunding({input},{authority(h.minerKeys)},resolved,unspendable,
      {PqSendOutput{h.miner.pqViewPk(),h.miner.pqSpendPk(),input.amount-2}},h.currency.genesisBlockHash(),14),std::invalid_argument);
    h.funding=buildSwapFunding({input},{authority(h.minerKeys)},resolved,sample.outputs[0],
      {PqSendOutput{h.miner.pqViewPk(),h.miner.pqSpendPk(),input.amount-3}},h.currency.genesisBlockHash(),14);
    ASSERT_TRUE(h.submit(h.funding).m_added_to_pool);ASSERT_TRUE(h.mine());if(refund)h.until(17);
    SwapInput spend;spend.prevTxid=getObjectHash(h.funding);spend.prevOutIndex=0;spend.branch=refund?2:1;
    const auto rho=refund?h.refundRho:h.claimRho;spend.rhoReveal.assign(rho.begin(),rho.end());if(!refund)spend.secret=h.secret;
    const auto& recipient=refund?h.owner:h.claimant;
    auto tx=buildSwapSpend(spend,h.funding.outputs[0],authority(recipient),
      {PqSendOutput{recipient.viewPub,recipient.spendPub,1}},h.currency.genesisBlockHash(),h.core->getCurrentBlockchainHeight());
    uint64_t fee=0;ASSERT_TRUE(h.core->getPqTransactionFee(tx,fee));EXPECT_EQ(fee,parameters::MINIMUM_FEE);
    ASSERT_TRUE(h.submit(tx).m_added_to_pool);ASSERT_TRUE(h.mine());
  }
}
TEST(SwapChain, ResignedUnsupportedPoliciesAndExpiredFundingCannotEnterPool) {
  Harness h;const auto original=h.makeFunding();
  for(unsigned mode=0;mode<6;++mode) {
    auto tx=original;auto& contract=boost::get<SwapOutput>(tx.outputs[0].target);
    switch(mode) {
      case 0:contract.version=2;break;case 1:contract.hashScheme=2;break;
      case 2:contract.authScheme=2;break;case 3:contract.amountScheme=2;break;
      case 4:contract.refundHeight=0;break;case 5:contract.refundHeight=h.core->getCurrentBlockchainHeight();break;
    }
    const auto digest=swapSigningDigest(tx,{{true,h.coinbase.outputs[0]}},h.currency.genesisBlockHash(),0);
    tx.pqSignatures[0]=CryptoPQ::dsa_sign(h.miner.pqSpendSk(),digest.data(),digest.size());
    ASSERT_TRUE(CryptoPQ::dsa_verify(h.miner.pqSpendPk(),digest.data(),digest.size(),tx.pqSignatures[0]));
    EXPECT_FALSE(h.submit(tx).m_added_to_pool)<<mode;
  }
  ASSERT_TRUE(h.submit(original).m_added_to_pool);ASSERT_TRUE(h.mine());
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
TEST(SwapChain, IndexedPoolSpendTagTracksBothBranchesMiningAndRestart) {
  for (bool refund : {false, true}) {
    Harness h; h.fund(16); h.until(16);
    auto spend = h.spend(refund);
    Crypto::KeyImage tag{};
    ASSERT_TRUE(transactionSpendTag(spend.inputs[0], h.currency.genesisBlockHash(), tag));
    EXPECT_FALSE(h.core->poolHasSpendTag(tag));
    EXPECT_FALSE(h.core->poolHasSpendTag(Crypto::KeyImage{}));
    ASSERT_TRUE(h.submit(spend).m_added_to_pool);
    EXPECT_TRUE(h.core->poolHasSpendTag(tag));
    EXPECT_FALSE(h.submit(h.spend(!refund)).m_added_to_pool);
    EXPECT_TRUE(h.core->poolHasSpendTag(tag));
    h.reopen();
    EXPECT_TRUE(h.core->poolHasSpendTag(tag));
    ASSERT_TRUE(h.mine());
    EXPECT_FALSE(h.core->poolHasSpendTag(tag));
    EXPECT_TRUE(h.core->get_blockchain_storage().have_spend_tag_as_spent(tag));
    h.reopen();
    EXPECT_FALSE(h.core->poolHasSpendTag(tag));
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
      {std::ofstream ready(prefix.string()+".funded.tmp");ready<<"{\"confirmations\":"<<confirmations<<",\"next_height\":"<<h.core->getCurrentBlockchainHeight()<<",\"refund_height\":32,\"txid\":\""<<Common::podToHex(getObjectHash(h.funding))<<"\",\"vout\":0,\"hashlock\":\""<<Common::podToHex(externalHash)<<"\",\"wire\":\""<<Common::toHex(toBinaryArray(h.funding))<<"\"}\n";ready.close();require(bool(ready),"fund receipt");}
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
