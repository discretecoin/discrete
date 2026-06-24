// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#include "gtest/gtest.h"
#include <numeric>

#include <System/Timer.h>
#include <Common/StringTools.h>
#include <Logging/ConsoleLogger.h>

#include "PaymentGate/WalletService.h"
#include "Wallet/WalletGreen.h"
#include "AccountNumber.h"
#include "PqAddress.h"
#include "CryptoNoteCore/Account.h"
#include "Wallet/WalletErrors.h"

// test helpers
#include "INodeStubs.h"
#include "TestBlockchainGenerator.h"

using namespace PaymentService;
using namespace CryptoNote;

class PaymentGateTest : public testing::Test {
public:

  PaymentGateTest() :
    logger(Logging::ERROR),
    currency(CryptoNote::CurrencyBuilder(logger).currency()),
    generator(currency),
    nodeStub(generator) 
  {}

  WalletConfiguration createWalletConfiguration(const std::string& walletFile = "pgwalleg.bin") const {
    return WalletConfiguration{ walletFile, "pass" };
  }

  std::unique_ptr<WalletService> createWalletService(const WalletConfiguration& cfg) {
    WalletGreen* walletGreen = new CryptoNote::WalletGreen(dispatcher, currency, nodeStub, logger);
    wallet.reset(walletGreen);
    std::unique_ptr<WalletService> service(new WalletService(currency, dispatcher, nodeStub, *walletGreen, cfg, logger));
    service->init();
    return service;
  }

  void generateWallet(const WalletConfiguration& conf) {
    unlink(conf.walletFile.c_str());
    generateNewWallet(currency, conf, logger, dispatcher, nodeStub);
  }

protected:  
  Logging::ConsoleLogger logger;
  CryptoNote::Currency currency;
  TestBlockchainGenerator generator;
  INodeTrivialRefreshStub nodeStub;
  System::Dispatcher dispatcher;

  std::unique_ptr<CryptoNote::IWallet> wallet;
};


TEST_F(PaymentGateTest, createWallet) {
  auto cfg = createWalletConfiguration();
  generateWallet(cfg);
  auto service = createWalletService(cfg);
}

// DISABLED: this is a classical-era test. On the PQ-only chain createAddress()
// returns a PQ address (not a classical one parseAccountAddressString accepts),
// and getBlockRewardForAddress mines classical coinbases the PQ ledger never
// credits. The wallet-side balance flow is covered by PqWalletSyncE2E
// (TestWallet.cpp PqWalletIntegration), which drives a real WalletGreen sync.
TEST_F(PaymentGateTest, DISABLED_addTransaction) {
  auto cfg = createWalletConfiguration();
  generateWallet(cfg);
  auto service = createWalletService(cfg);

  std::string addressStr;
  ASSERT_TRUE(!service->createAddress(addressStr));

  AccountPublicAddress address;
  ASSERT_TRUE(currency.parseAccountAddressString(addressStr, address));

  generator.getBlockRewardForAddress(address);
  generator.getBlockRewardForAddress(address);
  generator.generateEmptyBlocks(11);
  generator.getBlockRewardForAddress(address);

  nodeStub.updateObservers();

  System::Timer(dispatcher).sleep(std::chrono::seconds(2));

  uint64_t pending = 0, actual = 0;

  service->getBalance(actual, pending);

  ASSERT_NE(0, pending);
  ASSERT_NE(0, actual);

  ASSERT_EQ(pending * 2, actual);
}

// Regression: once the PQ ledger is live (which happens as soon as the primary
// address exists), getAddresses() hands back the wallet's PQ address -- a
// non-classical encoding. getSpendKeys must accept that exact address and
// return the underlying classical spend keypair, instead of rejecting it as a
// "Bad address" because parseAddress() only decodes classical addresses.
TEST_F(PaymentGateTest, getSpendKeysAcceptsOwnAddress) {
  auto cfg = createWalletConfiguration();
  generateWallet(cfg);
  auto service = createWalletService(cfg);

  std::vector<std::string> addresses;
  ASSERT_FALSE(service->getAddresses(addresses));
  ASSERT_FALSE(addresses.empty());

  // The address getAddresses() advertises is exactly what an RPC client feeds
  // back into getSpendKeys, so this round-trip must succeed.
  std::string spendPublicKey;
  std::string spendSecretKey;
  std::error_code ec = service->getSpendkeys(addresses[0], spendPublicKey, spendSecretKey);
  ASSERT_FALSE(ec) << "getSpendkeys rejected its own address: " << ec.message();

  // A full (non-tracking) wallet must surface the classical spend secret that
  // mining keys are derived from.
  ASSERT_EQ(64u, spendPublicKey.size());
  ASSERT_EQ(64u, spendSecretKey.size());
  ASSERT_NE(spendSecretKey, std::string(64, '0'));
}

// Every address-taking RPC accepts the same selector forms: a numeric address index
// (0 = primary, 1.. = deposit in issue order), the raw PQ address, and (for the
// validation gate) an H-I-C / H-I-T-C account number. Index and address must resolve
// to the same bucket.
TEST_F(PaymentGateTest, addressIndexAndAccountNumberSelectors) {
  auto cfg = createWalletConfiguration();
  generateWallet(cfg);
  auto service = createWalletService(cfg);

  std::vector<std::string> addresses;
  ASSERT_FALSE(service->getAddresses(addresses));
  ASSERT_EQ(1u, addresses.size());
  const std::string primary = addresses[0];

  // AggregatedMultikey (the default scheme) derives a deposit address with no
  // on-chain registration, so index 1 becomes addressable.
  std::string depositAddr;
  uint32_t depositIndex = 99;
  ASSERT_FALSE(service->createPqDepositAddress(depositAddr, depositIndex));
  ASSERT_EQ(0u, depositIndex);
  ASSERT_FALSE(depositAddr.empty());

  // getBalance: index "0"/"1" resolve to the same buckets as the address strings.
  uint64_t a = 1, l = 1, b = 2, m = 2;
  ASSERT_FALSE(service->getBalance("0", a, l));
  ASSERT_FALSE(service->getBalance(primary, b, m));
  EXPECT_EQ(a, b);
  EXPECT_EQ(l, m);
  ASSERT_FALSE(service->getBalance("1", a, l));
  ASSERT_FALSE(service->getBalance(depositAddr, b, m));
  EXPECT_EQ(a, b);
  EXPECT_EQ(l, m);

  // hasAddress by index.
  bool ours = false;
  ASSERT_FALSE(service->hasAddress("1", ours));
  EXPECT_TRUE(ours);

  // validateAddress: a numeric index normalizes to the deposit address; the raw PQ
  // address is recognized as valid.
  bool valid = false;
  std::string norm, spk, vpk;
  ASSERT_FALSE(service->validateAddress("1", valid, norm, spk, vpk));
  EXPECT_TRUE(valid);
  EXPECT_EQ(norm, depositAddr);
  valid = false;
  ASSERT_FALSE(service->validateAddress(depositAddr, valid, norm, spk, vpk));
  EXPECT_TRUE(valid);

  // A filter-gated RPC accepts index, raw address, and a syntactic H-I-T-C account
  // number (empty wallet -> empty result, but crucially no BAD_ADDRESS rejection).
  std::vector<std::string> hashes;
  ASSERT_FALSE(service->getUnconfirmedTransactionHashes(std::vector<std::string>{ "1" }, hashes));
  ASSERT_FALSE(service->getUnconfirmedTransactionHashes(std::vector<std::string>{ depositAddr }, hashes));
  const std::string hitc = CryptoNote::AccountNumber{ 10, 2 }.toStringWithIndex(3);
  ASSERT_FALSE(service->getUnconfirmedTransactionHashes(std::vector<std::string>{ hitc }, hashes));

  // An out-of-range index is rejected.
  ASSERT_TRUE(service->getBalance("5", a, l));
}

// The change-destination defaulting must match the original CryptoNote rule
// (getChangeDestination / validateChangeDestination): explicit changeAddress (ours),
// else the wallet's sole address, else the sole source; otherwise CHANGE_ADDRESS_REQUIRED.
// Asserted on an unfunded wallet — the rule is enforced before coin selection, so a
// rule PASS surfaces as some non-change error (insufficient funds), never as a change
// error.
TEST_F(PaymentGateTest, ChangeDestinationRuleMatchesCryptoNote) {
  auto cfg = createWalletConfiguration();
  generateWallet(cfg);
  auto service = createWalletService(cfg);

  std::vector<std::string> addrs;
  ASSERT_FALSE(service->getAddresses(addrs));
  ASSERT_EQ(1u, addrs.size());
  const std::string primary = addrs[0];

  auto trySend = [&](const std::string& change, const std::vector<std::string>& sources) {
    SendTransaction::Request req;
    req.transfers.push_back(WalletRpcOrder{ primary, 100 });  // recipient = our primary PQ addr
    req.fee = 100;
    req.changeAddress = change;
    req.sourceAddresses = sources;
    std::string hash, txkey;
    return service->sendTransaction(req, hash, txkey);
  };
  const auto required = make_error_code(CryptoNote::error::CHANGE_ADDRESS_REQUIRED);
  const auto notFound = make_error_code(CryptoNote::error::CHANGE_ADDRESS_NOT_FOUND);

  // Single-address wallet, no change address -> defaults to the sole address (rule
  // passes); the failure is insufficient funds, not a change error.
  {
    auto ec = trySend("", {});
    EXPECT_NE(ec, required);
    EXPECT_NE(ec, notFound);
  }

  // Give the wallet a second address (a deposit).
  std::string dep;
  uint32_t depIdx = 0;
  ASSERT_FALSE(service->createPqDepositAddress(dep, depIdx));

  // Multi-address, no change, no source -> ambiguous -> CHANGE_ADDRESS_REQUIRED.
  EXPECT_EQ(trySend("", {}), required);

  // Multi-address, exactly one source -> change defaults to that source (rule passes).
  {
    auto ec = trySend("", { dep });
    EXPECT_NE(ec, required);
    EXPECT_NE(ec, notFound);
  }

  // Explicit change to our own deposit, addressed by index -> rule passes.
  {
    auto ec = trySend("1", {});
    EXPECT_NE(ec, required);
    EXPECT_NE(ec, notFound);
  }

  // Change to a valid address that is not ours -> CHANGE_ADDRESS_NOT_FOUND.
  {
    CryptoNote::AccountBase other;
    other.generate();
    const std::string foreign = CryptoNote::encodePqAddress(
        CryptoNote::makePqAddress(currency.publicAddressBase58Prefix(),
                                  other.pqViewPk(), other.pqSpendPk()));
    EXPECT_EQ(trySend(foreign, {}), notFound);
  }
}

/*
TEST_F(PaymentGateTest, DISABLED_sendTransaction) {

  auto cfg = createWalletConfiguration();
  generateWallet(cfg);
  auto service = createWalletService(cfg);

  std::string addressStr;
  ASSERT_TRUE(!service->createAddress(addressStr));

  AccountPublicAddress address;
  ASSERT_TRUE(currency.parseAccountAddressString(addressStr, address));

  generator.getBlockRewardForAddress(address);
  generator.generateEmptyBlocks(11);

  nodeStub.updateObservers();

  System::Timer(dispatcher).sleep(std::chrono::seconds(5));

  auto cfg2 = createWalletConfiguration("pgwallet2.bin");
  generateWallet(cfg2);
  auto serviceRecv = createWalletService(cfg2);

  std::string recvAddress;
  serviceRecv->createAddress(recvAddress);

  uint64_t TEST_AMOUNT = 0;
  currency.parseAmount("100000.0", TEST_AMOUNT);

  Crypto::Hash paymentId;
  std::iota(reinterpret_cast<char*>(&paymentId), reinterpret_cast<char*>(&paymentId) + sizeof(paymentId), 0);
  std::string paymentIdStr = Common::podToHex(paymentId);

  uint64_t txId = 0;

  {
    SendTransaction::Request req;
    SendTransaction::Response res;

    req.transfers.push_back(WalletRpcOrder{ TEST_AMOUNT, recvAddress });
    req.fee = currency.minimumFee();
    req.anonymity = 1;
    req.unlockHeight = 0;
    req.paymentId = paymentIdStr;

    ASSERT_TRUE(!service->sendTransaction(req, res.transactionHash));

    txId = res.transactionId;
  }

  generator.generateEmptyBlocks(11);

  nodeStub.updateObservers();

  System::Timer(dispatcher).sleep(std::chrono::seconds(5));

  TransactionRpcInfo txInfo;
  bool found = false;

  ASSERT_TRUE(!service->getTransaction(txId, found, txInfo));
  ASSERT_TRUE(found);

  uint64_t recvTxCount = 0;
  ASSERT_TRUE(!serviceRecv->getTransactionsCount(recvTxCount));
  ASSERT_EQ(1, recvTxCount);

  uint64_t sendTxCount = 0;
  ASSERT_TRUE(!service->getTransactionsCount(sendTxCount));
  ASSERT_EQ(2, sendTxCount); // 1 from mining, 1 transfer

  TransactionRpcInfo recvTxInfo;
  ASSERT_TRUE(!serviceRecv->getTransaction(0, found, recvTxInfo));
  ASSERT_TRUE(found);

  ASSERT_EQ(txInfo.hash, recvTxInfo.hash);
  ASSERT_EQ(txInfo.extra, recvTxInfo.extra);
  ASSERT_EQ(-txInfo.totalAmount - currency.minimumFee(), recvTxInfo.totalAmount);
  ASSERT_EQ(txInfo.blockHeight, recvTxInfo.blockHeight);

  {
    // check payments
    WalletService::IncomingPayments payments;
    ASSERT_TRUE(!serviceRecv->getIncomingPayments({ paymentIdStr }, payments));

    ASSERT_EQ(1, payments.size());

    ASSERT_EQ(paymentIdStr, payments.begin()->first);

    const auto& recvPayment = payments.begin()->second;

    ASSERT_EQ(1, recvPayment.size());

    ASSERT_EQ(txInfo.hash, recvPayment[0].txHash);
    ASSERT_EQ(TEST_AMOUNT, recvPayment[0].amount);
    ASSERT_EQ(txInfo.blockHeight, recvPayment[0].blockHeight);
  }

  // reload services

  service->saveWallet();
  serviceRecv->saveWallet();

  service.reset();
  serviceRecv.reset();

  service = createWalletService(cfg);
  serviceRecv = createWalletService(cfg2);

  recvTxInfo = boost::value_initialized<TransactionRpcInfo>();
  ASSERT_TRUE(!serviceRecv->getTransaction(0, found, recvTxInfo));
  ASSERT_TRUE(found);

  ASSERT_EQ(txInfo.hash, recvTxInfo.hash);
  ASSERT_EQ(txInfo.extra, recvTxInfo.extra);
  ASSERT_EQ(-txInfo.totalAmount - currency.minimumFee(), recvTxInfo.totalAmount);
  ASSERT_EQ(txInfo.blockHeight, recvTxInfo.blockHeight);

  // send some money back
  std::reverse(paymentIdStr.begin(), paymentIdStr.end());

  {
    std::string recvAddress;
    service->createAddress(recvAddress);

    SendTransactionRequest req;
    SendTransactionResponse res;

    req.destinations.push_back(TransferDestination{ TEST_AMOUNT/2, recvAddress });
    req.fee = currency.minimumFee();
    req.mixin = 1;
    req.unlockHeight = 0;
    req.paymentId = paymentIdStr;

    ASSERT_TRUE(!serviceRecv->sendTransaction(req, res));

    txId = res.transactionId;
  }

  generator.generateEmptyBlocks(11);
  nodeStub.updateObservers();

  System::Timer(dispatcher).sleep(std::chrono::seconds(5));

  ASSERT_TRUE(!service->getTransactionsCount(recvTxCount));
  ASSERT_EQ(3, recvTxCount);

  {
    WalletService::IncomingPayments payments;
    ASSERT_TRUE(!service->getIncomingPayments({ paymentIdStr }, payments));
    ASSERT_EQ(1, payments.size());
    ASSERT_EQ(paymentIdStr, payments.begin()->first);

    const auto& recvPayment = payments.begin()->second;

    ASSERT_EQ(1, recvPayment.size());
    ASSERT_EQ(TEST_AMOUNT / 2, recvPayment[0].amount);
  }
} */
