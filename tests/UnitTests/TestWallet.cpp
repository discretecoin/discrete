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

#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <numeric>
#include <set>
#include <sstream>
#include <system_error>
#include <thread>
#include <tuple>

#include "Common/StringTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/TransactionApi.h"
#include "CryptoNoteCore/TransactionApiExtra.h"
#include "INodeStubs.h"
#include "TestBlockchainGenerator.h"
#include <Logging/ConsoleLogger.h>
#include "Wallet/MiningKeyLoader.h"
#include "Wallet/WalletErrors.h"
#include "Wallet/WalletGreen.h"
#include "Wallet/WalletIndices.h"
#include "Wallet/PqWallet.h"
#include "Wallet/PqTransactionBuilder.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqSeed.h"   // deriveDepositSpendKeys
#include "Wallet/WalletSerializationV2.h"
#include "Wallet/WalletUtils.h"
#include "WalletLegacy/WalletLegacy.h"  // simplewallet engine smoke test
#include "WalletLegacy/WalletHelper.h"
#include "PqAddress.h"
#include "AccountNumber.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"  // verifyMessagePq
#include "CryptoNoteCore/TransactionExtra.h"  // createTxExtraWithPaymentId / getPaymentIdFromTxExtra
#include "CryptoNoteCore/CryptoNoteTools.h"  // getObjectHash
#include "WalletLegacy/WalletUserTransactionsCache.h"
#include "WalletLegacy/WalletLegacySerializer.h"
#include <System/Dispatcher.h>
#include <System/Timer.h>
#include <System/Context.h>

#ifdef ERROR
#undef ERROR
#endif

using namespace Crypto;
using namespace Common;
using namespace CryptoNote;

namespace CryptoNote {

    std::ostream& operator<<(std::ostream& o, const WalletTransaction& tx) {
      o << "WalletTransaction{state=" << tx.state << ", timestamp=" << tx.timestamp
        << ", blockHeight=" << tx.blockHeight << ", hash=" << tx.hash
        << ", totalAmount=" << tx.totalAmount << ", fee=" << tx.fee
        << ", creationTime=" << tx.creationTime << ", unlockHeight=" << tx.unlockHeight
        << ", extra=" << tx.extra  << ", isBase=" << tx.isBase << "}";
      return o;
    }

    bool operator==(const WalletTransaction& lhs, const WalletTransaction& rhs) {
      if (lhs.state != rhs.state) {
        return false;
      }

      if (lhs.timestamp != rhs.timestamp) {
        return false;
      }

      if (lhs.blockHeight != rhs.blockHeight) {
        return false;
      }

      if (lhs.hash != rhs.hash) {
        return false;
      }

      if (lhs.totalAmount != rhs.totalAmount) {
        return false;
      }

      if (lhs.fee != rhs.fee) {
        return false;
      }

      if (lhs.creationTime != rhs.creationTime) {
        return false;
      }

      if (lhs.unlockHeight != rhs.unlockHeight) {
        return false;
      }

      if (lhs.extra != rhs.extra) {
        return false;
      }

      if (lhs.isBase != rhs.isBase) {
        return false;
      }

      return true;
    }

    bool operator!=(const WalletTransaction& lhs, const WalletTransaction& rhs) {
      return !(lhs == rhs);
    }

    bool operator==(const WalletTransfer& lhs, const WalletTransfer& rhs) {
      if (lhs.address != rhs.address) {
        return false;
      }

      if (lhs.amount != rhs.amount) {
        return false;
      }

      if (lhs.type != rhs.type) {
        return false;
      }

      return true;
    }

    bool operator!=(const WalletTransfer& lhs, const WalletTransfer& rhs) {
      return !(lhs == rhs);
    }

    bool operator<(const WalletTransfer& lhs, const WalletTransfer& rhs) {
      return std::make_tuple(lhs.amount, lhs.address) < std::make_tuple(rhs.amount, rhs.address);
    }
}

namespace {
CryptoNote::Transaction makePqPayTo(const CryptoNote::PqWalletKeys& from,
                                    const CryptoNote::PqWalletKeys& to,
                                    uint64_t inAmount, uint64_t payAmount, uint8_t seed,
                                    uint64_t subaddrT = 0, uint64_t outUnlockHeight = 0,
                                    const std::vector<uint8_t>& extra = {}) {
  std::vector<CryptoPQ::InputRef> refs(1);
  for (auto& b : refs[0].prevTxid) b = seed;
  refs[0].prevOutIndex = 1;
  CryptoPQ::Hash256 fih = CryptoPQ::inputsHash(refs);
  CryptoPQ::PqBuiltOutput src =
      CryptoPQ::buildPqOutput(from.viewPub, from.spendPub, fih, 0, inAmount);
  CryptoNote::PqSpendInput in;
  for (std::size_t i = 0; i < 32; ++i) in.prevTxid.data[i] = static_cast<uint8_t>(seed + i);
  in.prevOutIndex = 0;
  in.amount = inAmount;
  in.rho = src.rho;
  CryptoNote::PqSendOutput out{to.viewPub, to.spendPub, payAmount};
  out.subaddrIndexT = subaddrT;       // SingleKeyIndex deposit routing (0 = base address)
  out.unlockHeight = outUnlockHeight;  // per-output spend lock (0 = none); 0 != coinbase maturity
  return CryptoNote::buildPqTransaction({in}, {out}, from.spendPub, from.spendSk,
                                        /*unlockHeight=*/0, extra);
}
// Pump wallet events until `pred` holds or the timeout elapses.
void pumpUntil(System::Dispatcher& dispatcher, CryptoNote::WalletGreen& wallet,
               std::function<bool()> pred,
               std::chrono::nanoseconds timeout = std::chrono::seconds(30)) {
  System::Context<> waitContext(dispatcher, [&wallet, &pred]() {
    while (!pred()) { wallet.getEvent(); }
  });
  System::Context<> timeoutContext(dispatcher, [&dispatcher, &waitContext, timeout]() {
    System::Timer(dispatcher).sleep(timeout);
    waitContext.interrupt();
  });
  try { waitContext.get(); } catch (System::InterruptedException&) {}
}
}  // namespace

// End-to-end gate for the PQ-as-native-engine convergence: drives a real WalletGreen
// (INodeTrivialRefreshStub -> BlockchainSynchronizer -> WalletLedgerConsumer) and
// asserts the NATIVE IWallet getters reflect the PQ ledger.
//
// The in-memory TestBlockchainGenerator builds V1 blocks whose PoW comes from the
// standalone long-hash (the wallet never validates PoW — it trusts its node), so no
// real Core sink is needed here. This test also guards the F1 fix: the classical
// TransfersConsumer must count PQ-only blocks as empty instead of stalling PQ sync.

// getAddressSpendKey(0).secretKey returns the wallet's 32-byte PQ master seed. The
// wallet derives its identity from the seed directly (no HKDF), so a test that mines
// to the wallet must derive the same way.
static CryptoNote::PqWalletKeys pqKeysFromWalletSeed(const Crypto::SecretKey& seed) {
  CryptoPQ::SeedMaster sm{};
  std::memcpy(sm.data(), seed.data, sm.size());
  return CryptoNote::derivePqWalletKeys(sm);
}

// --- Failed loads leave nothing behind -------------------------------------
//
// Once the container has opened, the container key and the master seeds are
// resident. Everything after that point can still fail, and until load() reaches
// its end the wallet is NOT_INITIALIZED, so no later shutdown would ever clean it
// up. These assert the post-failure invariant directly rather than merely that
// nothing crashed.

namespace {

struct LoadFixture {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger{Logging::ERROR};
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator{currency};
  INodeTrivialRefreshStub node{generator};
};

// Create a real container at `path` and close it.
void makeWallet(LoadFixture& f, const std::string& path, const std::string& password) {
  boost::filesystem::remove(path);
  CryptoNote::WalletGreen wallet(f.dispatcher, f.currency, f.node, f.logger);
  wallet.initialize(path, password);
  wallet.createAddress();
  wallet.save(CryptoNote::WalletSaveLevel::SAVE_ALL);
  wallet.shutdown();
}

// Clears any injected fault however the test leaves.
struct FaultInjectorGuard {
  ~FaultInjectorGuard() { CryptoNote::WalletGreen::loadFaultInjector() = nullptr; }
};

}  // namespace

TEST(PqWalletLoadFailure, WrongPasswordLeavesNoResidentSecrets) {
  LoadFixture f;
  const std::string path = "pq_loadfail_password.wallet";
  makeWallet(f, path, "right");

  CryptoNote::WalletGreen wallet(f.dispatcher, f.currency, f.node, f.logger);
  EXPECT_ANY_THROW(wallet.load(path, "wrong"));
  EXPECT_FALSE(wallet.hasResidentSecrets());

  boost::filesystem::remove(path);
}

TEST(PqWalletLoadFailure, CorruptedRecordLeavesNoResidentSecrets) {
  LoadFixture f;
  const std::string path = "pq_loadfail_corrupt.wallet";
  makeWallet(f, path, "pass");

  // Flip a byte inside the first encrypted seed record, past the header, so the
  // password is right but the authentication tag is not.
  {
    // Rewrite the file at exactly its original length, so the failure is the
    // record's authentication tag and not a size or structural check.
    std::vector<char> bytes;
    {
      std::ifstream in(path, std::ios::binary);
      ASSERT_TRUE(in.is_open());
      bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    // FileMappedVector lays the file out as: prefix, capacity(u64), size(u64),
    // then the records. Land inside the first record's ciphertext, past its
    // nonce, so the tag is what rejects this and not a structural check.
    const std::size_t offset = sizeof(CryptoNote::ContainerStoragePrefix) +
                               2 * sizeof(uint64_t) + CryptoPQ::kAeadNonceBytes + 4;
    ASSERT_GT(bytes.size(), offset);
    const std::size_t original = bytes.size();
    bytes[offset] = static_cast<char>(bytes[offset] ^ 0x5A);
    {
      std::ofstream out(path, std::ios::binary | std::ios::trunc);
      ASSERT_TRUE(out.is_open());
      out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    ASSERT_EQ(original, static_cast<std::size_t>(boost::filesystem::file_size(path)));
  }

  CryptoNote::WalletGreen wallet(f.dispatcher, f.currency, f.node, f.logger);
  EXPECT_ANY_THROW(wallet.load(path, "pass"));
  EXPECT_FALSE(wallet.hasResidentSecrets());

  boost::filesystem::remove(path);
}

// The gap this covers: the container opened, the records authenticated, the key
// and the seeds are resident — and then a later initialization step throws.
TEST(PqWalletLoadFailure, FailureAfterRecordsLoadLeavesNoResidentSecrets) {
  LoadFixture f;
  const std::string path = "pq_loadfail_late.wallet";
  makeWallet(f, path, "pass");

  FaultInjectorGuard restore;
  CryptoNote::WalletGreen wallet(f.dispatcher, f.currency, f.node, f.logger);

  bool secretsWereResident = false;
  CryptoNote::WalletGreen::loadFaultInjector() = [&wallet, &secretsWereResident] {
    // Establishes that this fires in the window that matters: had the load
    // succeeded to here and then thrown, these secrets would have stayed.
    secretsWereResident = wallet.hasResidentSecrets();
    throw std::runtime_error("injected post-container load failure");
  };

  EXPECT_ANY_THROW(wallet.load(path, "pass"));
  EXPECT_TRUE(secretsWereResident) << "fault injected too early to be meaningful";
  EXPECT_FALSE(wallet.hasResidentSecrets());

  boost::filesystem::remove(path);
}

// After the cleanup the object must be genuinely reusable, not merely scrubbed:
// the synchronizer detached, the consumer dropped, the state reset.
TEST(PqWalletLoadFailure, ObjectIsReusableAfterAFailedLoad) {
  LoadFixture f;
  const std::string path = "pq_loadfail_reuse.wallet";
  makeWallet(f, path, "pass");

  CryptoNote::WalletGreen wallet(f.dispatcher, f.currency, f.node, f.logger);
  {
    FaultInjectorGuard restore;
    CryptoNote::WalletGreen::loadFaultInjector() = [] {
      throw std::runtime_error("injected post-container load failure");
    };
    EXPECT_ANY_THROW(wallet.load(path, "pass"));
  }
  ASSERT_FALSE(wallet.hasResidentSecrets());

  // The same object now loads the same file normally.
  ASSERT_NO_THROW(wallet.load(path, "pass"));
  EXPECT_TRUE(wallet.hasResidentSecrets());
  EXPECT_GE(wallet.getAddressCount(), 1u);

  wallet.shutdown();
  EXPECT_FALSE(wallet.hasResidentSecrets());

  boost::filesystem::remove(path);
}

TEST(PqWalletLoadFailure, ShutdownAfterFailedLoadIsSafe) {
  LoadFixture f;
  const std::string path = "pq_loadfail_shutdown.wallet";
  makeWallet(f, path, "pass");

  CryptoNote::WalletGreen wallet(f.dispatcher, f.currency, f.node, f.logger);
  EXPECT_ANY_THROW(wallet.load(path, "wrong"));

  // The wallet never reached INITIALIZED, so shutdown() is expected to refuse
  // rather than tear down a second time. Either way it must not leave secrets.
  try {
    wallet.shutdown();
  } catch (const std::exception&) {
  }
  EXPECT_FALSE(wallet.hasResidentSecrets());

  boost::filesystem::remove(path);
}

TEST(PqWalletLoadFailure, SuccessfulLoadStillRetainsItsSecrets) {
  LoadFixture f;
  const std::string path = "pq_loadfail_success.wallet";
  makeWallet(f, path, "pass");

  CryptoNote::WalletGreen wallet(f.dispatcher, f.currency, f.node, f.logger);
  ASSERT_NO_THROW(wallet.load(path, "pass"));
  // The guard must be dismissed on success, not merely not fire.
  EXPECT_TRUE(wallet.hasResidentSecrets());
  EXPECT_GE(wallet.getAddressCount(), 1u);

  wallet.shutdown();
  EXPECT_FALSE(wallet.hasResidentSecrets());

  boost::filesystem::remove(path);
}

TEST(PqWalletIntegration, IncomingTransactionCreditsNativeBalance) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_integration.wallet";
  boost::filesystem::remove(path);
  wallet.initialize(path, "pass");
  wallet.createAddress();

  // The wallet's PQ identity derives from its primary spend secret.
  Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
  CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(spend);

  // Some other wallet pays us 800000 via a TX_PQ placed on-chain.
  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 7 + 3);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

  CryptoNote::Transaction pqTx = makePqPayTo(them, mine, 1000000, 800000, 0x55);
  // TX_PQ has no inline input amounts; register its fee (in − out) so the block
  // constructor doesn't try to value it via the classical get_tx_fee path.
  generator.setTxFee(CryptoNote::getObjectHash(pqTx), 1000000 - 800000);
  generator.addTxToBlockchain(pqTx);
  node.updateObservers();

  // The native IWallet getters must reflect the PQ ledger once the block syncs.
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 800000u; });

  EXPECT_EQ(wallet.getActualBalance(), 800000u);
  EXPECT_EQ(wallet.getPendingBalance(), 0u);
  ASSERT_EQ(wallet.getTransactionCount(), 1u);

  CryptoNote::WalletTransaction tx0 = wallet.getTransaction(0);
  EXPECT_EQ(tx0.totalAmount, 800000);
  EXPECT_EQ(tx0.hash, CryptoNote::getObjectHash(pqTx));

  wallet.shutdown();
  boost::filesystem::remove(path);
}

// Persistence/resume: after a save + shutdown, a fresh WalletGreen that loads the
// file must report the balance and history straight from the persisted PQ ledger
// (the WalletLedgerConsumer cursor + WalletLedger blob), without rescanning.
TEST(PqWalletIntegration, BalanceSurvivesSaveAndReload) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  const std::string path = "pq_reload.wallet";
  boost::filesystem::remove(path);

  Crypto::Hash txHash;
  {
    CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);
    wallet.initialize(path, "pass");
    wallet.createAddress();
    Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
    CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(spend);

    Crypto::SecretKey otherSecret;
    for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
      otherSecret.data[i] = static_cast<uint8_t>(i * 7 + 3);
    CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

    CryptoNote::Transaction pqTx = makePqPayTo(them, mine, 1000000, 800000, 0x55);
    txHash = CryptoNote::getObjectHash(pqTx);
    generator.setTxFee(txHash, 1000000 - 800000);
    generator.addTxToBlockchain(pqTx);
    node.updateObservers();

    pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 800000u; });
    wallet.save();
    wallet.shutdown();
  }

  {
    CryptoNote::WalletGreen reloaded(dispatcher, currency, node, logger);
    ASSERT_NO_THROW(reloaded.load(path, "pass"));
    // Comes straight from the restored ledger, before any fresh sync work.
    EXPECT_EQ(reloaded.getActualBalance(), 800000u);
    ASSERT_EQ(reloaded.getTransactionCount(), 1u);
    EXPECT_EQ(reloaded.getTransaction(0).hash, txHash);
    reloaded.shutdown();
  }

  boost::filesystem::remove(path);
}

// Classic payment ids are RETAINED alongside H-I-A-T-C for exchange integrations
// (kept out of the Qt GUI deliberately; simplewallet `transfer -p` and walletd
// sendTransaction.paymentId are the entry points). This is the PQ round trip: a
// TX_PQ whose tx_extra carries the classic payment-id nonce must (1) embed it on
// the wire, (2) surface it in the receiving wallet's history row — WalletLedger
// captures it at scan time and WalletGreen re-encodes it as the classic extra
// nonce — and (3) keep it across save/reload (ledger v6+ persists the field).
TEST(PqWalletIntegration, PaymentIdRoundTrip) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  const std::string path = "pq_payment_id.wallet";
  boost::filesystem::remove(path);

  const std::string paymentIdHex =
      "f00dfaceb00c00010203040506070809f00dfaceb00c00010203040506070809";
  Crypto::Hash txHash;
  {
    CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);
    wallet.initialize(path, "pass");
    wallet.createAddress();
    Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
    CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(spend);

    Crypto::SecretKey otherSecret;
    for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
      otherSecret.data[i] = static_cast<uint8_t>(i * 7 + 3);
    CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

    // Sender side: the same helper simplewallet -p / walletd paymentId use.
    std::vector<uint8_t> extra;
    ASSERT_TRUE(CryptoNote::createTxExtraWithPaymentId(paymentIdHex, extra));

    CryptoNote::Transaction pqTx =
        makePqPayTo(them, mine, 1000000, 800000, 0x66, 0, 0, extra);

    // (1) The id is embedded in the signed wire transaction.
    Crypto::Hash embedded;
    ASSERT_TRUE(CryptoNote::getPaymentIdFromTxExtra(pqTx.extra, embedded));
    EXPECT_EQ(Common::podToHex(embedded), paymentIdHex);

    txHash = CryptoNote::getObjectHash(pqTx);
    generator.setTxFee(txHash, 1000000 - 800000);
    generator.addTxToBlockchain(pqTx);
    node.updateObservers();

    pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 800000u; });

    // (2) The receiving wallet's history row carries the id, re-encoded as the
    // classic extra nonce (what walletd listings/filters parse).
    ASSERT_EQ(wallet.getTransactionCount(), 1u);
    CryptoNote::WalletTransaction tx0 = wallet.getTransaction(0);
    EXPECT_EQ(tx0.hash, txHash);
    Crypto::Hash received;
    ASSERT_TRUE(CryptoNote::getPaymentIdFromTxExtra(
        Common::asBinaryArray(tx0.extra), received));
    EXPECT_EQ(Common::podToHex(received), paymentIdHex);

    wallet.save();
    wallet.shutdown();
  }

  // (3) Persistence: the id survives save/reload straight from the ledger blob.
  {
    CryptoNote::WalletGreen reloaded(dispatcher, currency, node, logger);
    ASSERT_NO_THROW(reloaded.load(path, "pass"));
    ASSERT_EQ(reloaded.getTransactionCount(), 1u);
    CryptoNote::WalletTransaction tx0 = reloaded.getTransaction(0);
    EXPECT_EQ(tx0.hash, txHash);
    Crypto::Hash persisted;
    ASSERT_TRUE(CryptoNote::getPaymentIdFromTxExtra(
        Common::asBinaryArray(tx0.extra), persisted));
    EXPECT_EQ(Common::podToHex(persisted), paymentIdHex);
    reloaded.shutdown();
  }

  boost::filesystem::remove(path);
}

// Reorg/rollback through the real BlockchainSynchronizer: a credited transaction
// whose block is orphaned must be rolled back (onBlockchainDetach ->
// WalletLedger::rollbackToHeight), reversing the balance and history.
TEST(PqWalletIntegration, ReorgDetachReversesCredit) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_reorg.wallet";
  boost::filesystem::remove(path);
  wallet.initialize(path, "pass");
  wallet.createAddress();
  Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
  CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(spend);

  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 7 + 3);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

  CryptoNote::Transaction pqTx = makePqPayTo(them, mine, 1000000, 800000, 0x55);
  generator.setTxFee(CryptoNote::getObjectHash(pqTx), 1000000 - 800000);
  generator.addTxToBlockchain(pqTx);  // tx lands in block at height 1
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 800000u; });
  ASSERT_EQ(wallet.getActualBalance(), 800000u);

  // Orphan the block that carried the payment: reorg from height 1 (keep only
  // genesis) and let a longer, payment-free chain win.
  node.startAlternativeChain(1);
  generator.generateEmptyBlocks(3);
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 0u; },
            std::chrono::seconds(20));

  EXPECT_EQ(wallet.getActualBalance(), 0u);
  EXPECT_EQ(wallet.getTransactionCount(), 0u);

  wallet.shutdown();
  boost::filesystem::remove(path);
}

// AggregatedMultikey deposit lifecycle end-to-end through a real WalletGreen: receive a
// payment to a DEPOSIT address, confirm it's attributed to the deposit bucket (not the
// primary), then SPEND it restricted to that deposit (which must sign with the derived
// per-deposit key) and confirm the deposit empties while change lands on the primary.
TEST(PqWalletIntegration, AggregatedDepositReceivesAndSpends) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_deposit.wallet";
  boost::filesystem::remove(path);
  wallet.initialize(path, "pass");
  wallet.createAddress();  // primary = index 0

  Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
  CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(spend);

  // Reserve deposit 0 (AggregatedMultikey is the default). This configures the ledger
  // to attribute deposit-0 outputs. getAddress(1) is the deposit address.
  const uint32_t depIdx = wallet.reservePqDepositIndex();
  ASSERT_EQ(depIdx, 0u);
  const std::string primaryAddr = wallet.getAddress(0);
  const std::string depositAddr = wallet.getAddress(1);
  ASSERT_NE(primaryAddr, depositAddr);

  // Some other wallet pays 800000 to OUR deposit: shared view key + the per-deposit
  // spend key (subaddress T = 0 under AggregatedMultikey).
  CryptoNote::PqWalletKeys depositRecipient = mine;
  depositRecipient.spendPub = CryptoPQ::deriveDepositSpendKeys(mine.seedMaster, 0).first;

  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 11 + 5);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

  CryptoNote::Transaction pqTx = makePqPayTo(them, depositRecipient, 1000000, 800000, 0x33);
  generator.setTxFee(CryptoNote::getObjectHash(pqTx), 1000000 - 800000);
  generator.addTxToBlockchain(pqTx);
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 800000u; });

  // Attribution: the credit is the DEPOSIT's, not the primary's.
  EXPECT_EQ(wallet.getActualBalance(), 800000u);
  EXPECT_EQ(wallet.getActualBalance(depositAddr), 800000u);
  EXPECT_EQ(wallet.getActualBalance(primaryAddr), 0u);

  // Spend, restricted to the deposit source: buildPqSend must sign the deposit input
  // with deriveDepositSpendKeys(seed, 0). Pay an external recipient; change (no explicit
  // changeAddress) returns to the primary. Relay to the pool first so we can register
  // the TX_PQ fee (no inline input amounts) before the generator mines it.
  node.setNextTransactionToPool();
  CryptoNote::PqSendResult r = wallet.sendPqTransfer(
      { CryptoNote::PqSendOutput{ them.viewPub, them.spendPub, 300000 } },
      /*fee*/ 0, /*unlockHeight*/ 0, /*extra*/ {}, /*sourceAddresses*/ { depositAddr });
  ASSERT_EQ(r.selected.size(), 1u);
  EXPECT_EQ(r.selected[0].depositIndex, 0u);  // spent the deposit's output, not primary's
  generator.setTxFee(CryptoNote::getObjectHash(r.tx), r.fee);
  generator.putTxPoolToBlockchain();
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet, &primaryAddr]() {
    return wallet.getActualBalance(primaryAddr) > 0u;  // change confirmed to primary
  });

  // The deposit output is spent; the change landed on the primary; nothing stranded.
  EXPECT_EQ(wallet.getActualBalance(depositAddr), 0u);
  EXPECT_GT(wallet.getActualBalance(primaryAddr), 0u);
  EXPECT_EQ(wallet.getActualBalance(), wallet.getActualBalance(primaryAddr));
  EXPECT_LT(wallet.getActualBalance(), 800000u - 300000u);  // < change ceiling (fee paid)

  wallet.shutdown();
  boost::filesystem::remove(path);
}

// Seed-only restore of an AggregatedMultikey wallet must be told the deposit COUNT
// (restore-address-count) to recover deposit funds: each deposit output commits to a
// distinct derived spend key, so the scanner only recognizes it after that deposit is
// re-reserved. Without it the deposit funds are invisible; with it they are recovered.
TEST(PqWalletIntegration, RestoreFromSeedNeedsDepositCountToRecoverDepositFunds) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  // A known wallet seed and its derived deposit-0 identity (shared view + deposit key).
  Crypto::SecretKey seed;
  for (std::size_t i = 0; i < sizeof(seed.data); ++i) seed.data[i] = static_cast<uint8_t>(i * 3 + 1);
  CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(seed);
  CryptoNote::PqWalletKeys deposit0 = mine;
  deposit0.spendPub = CryptoPQ::deriveDepositSpendKeys(mine.seedMaster, 0).first;

  // Put an 800000 payment to deposit 0 on-chain (funded by some other wallet).
  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 11 + 5);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);
  CryptoNote::Transaction pqTx = makePqPayTo(them, deposit0, 1000000, 800000, 0x44);
  generator.setTxFee(CryptoNote::getObjectHash(pqTx), 1000000 - 800000);
  generator.addTxToBlockchain(pqTx);
  const uint32_t tipHeight = static_cast<uint32_t>(generator.getBlockchain().size() - 1);

  // Restore the primary from the seed, optionally re-reserving `deposits` deposits
  // (what restore-address-count does), sync fully, and report the recovered balance.
  auto restoreAndSync = [&](const std::string& path, uint32_t deposits) -> uint64_t {
    boost::filesystem::remove(path);
    CryptoNote::WalletGreen w(dispatcher, currency, node, logger);
    w.initialize(path, "pass");
    w.createAddress(seed);  // restore the primary identity from the seed
    for (uint32_t i = 0; i < deposits; ++i) {
      w.reservePqDepositIndex();
    }
    node.updateObservers();
    pumpUntil(dispatcher, w, [&w, tipHeight]() { return w.pqSyncedHeight() >= tipHeight; });
    uint64_t bal = w.getActualBalance();
    w.shutdown();
    boost::filesystem::remove(path);
    return bal;
  };

  // Seed only, no deposits restored -> the deposit output is unrecognized (the bug
  // restore-address-count fixes).
  EXPECT_EQ(restoreAndSync("pq_restore_nodep.wallet", 0), 0u);
  // Seed + deposit count 1 -> the deposit funds are recovered.
  EXPECT_EQ(restoreAndSync("pq_restore_dep.wallet", 1), 800000u);
}

// SingleKeyIndex (H-I-A-T-C) differentiator: every deposit shares the ONE spend key and is
// distinguished only by the subaddress index T carried in the output. The scanner must
// attribute each output to the bucket whose T it scans under, and T=0 — which is what a
// payment to the primary address / base H-I-A-C number produces — must stay OFF the
// deposit buckets entirely. (The H-I-A-T-C address string + registration are a separate
// concern needing node-side account resolution.)
TEST(PqWalletIntegration, SingleKeyIndexAttributesDepositsByT) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_ski.wallet";
  boost::filesystem::remove(path);
  wallet.initialize(path, "pass");
  wallet.createAddress();  // primary
  wallet.setPqDepositScheme(CryptoNote::PqDepositScheme::SingleKeyIndex);
  // Deposits start at T=1: T=0 is the primary address itself.
  ASSERT_EQ(wallet.reservePqDepositIndex(), 1u);
  ASSERT_EQ(wallet.reservePqDepositIndex(), 2u);
  EXPECT_EQ(wallet.getPqDepositCount(), 2u);

  Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
  CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(spend);  // the one keypair

  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 11 + 5);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

  // Three payments to the ONE key: T=0 is an ordinary payment to the primary address,
  // T=1 and T=2 are the two issued deposits. Each must land in its own bucket, and the
  // primary payment must not be attributable to any deposit.
  CryptoNote::Transaction t0 = makePqPayTo(them, mine, 1000000, 500000, 0x61, /*T*/ 0);
  CryptoNote::Transaction t1 = makePqPayTo(them, mine, 1000000, 300000, 0x62, /*T*/ 1);
  CryptoNote::Transaction t2 = makePqPayTo(them, mine, 1000000, 200000, 0x63, /*T*/ 2);
  generator.setTxFee(CryptoNote::getObjectHash(t0), 1000000 - 500000);
  generator.setTxFee(CryptoNote::getObjectHash(t1), 1000000 - 300000);
  generator.setTxFee(CryptoNote::getObjectHash(t2), 1000000 - 200000);
  generator.addTxToBlockchain(t0);
  generator.addTxToBlockchain(t1);
  generator.addTxToBlockchain(t2);
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 1000000u; });

  EXPECT_EQ(wallet.getActualBalance(), 1000000u);
  EXPECT_EQ(wallet.pqDepositBalance(1), 300000u);  // T=1 output -> deposit 1
  EXPECT_EQ(wallet.pqDepositBalance(2), 200000u);  // T=2 output -> deposit 2
  // The primary payment is NOT deposit #0 — no deposit owns it.
  EXPECT_EQ(wallet.pqDepositBalance(0), 0u);
  EXPECT_EQ(wallet.pqDepositBalance(CryptoNote::PQ_PRIMARY_DEPOSIT), 500000u);
  auto buckets = wallet.pqDepositBalances();
  EXPECT_EQ(buckets.size(), 2u);
  EXPECT_EQ(buckets.count(0), 0u);

  wallet.shutdown();
  boost::filesystem::remove(path);
}

// Crash durability of the deposit registry. WalletService::createPqDepositAddress now
// persists (wallet.save(SAVE_ALL)) right after reservePqDepositIndex(), because the
// reserved count lives only in the PQ state blob until a save. A process that dies
// after that create-time save — before any graceful shutdown save — must still report
// the reserved deposits on reopen; otherwise a single-key-index (exchange) scanner
// falls back to maxT=1 and funds received at deposit indices T>=1 go invisible until a
// full rescan. Model the crash exactly: ONE create-time save(), then shutdown() (which
// does not save), then a fresh load() with no further save.
TEST(PqWalletIntegration, DepositRegistrySurvivesCrashAfterCreateTimeSave) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  const std::string path = "pq_deposit_durable.wallet";
  boost::filesystem::remove(path);

  {
    CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);
    wallet.initialize(path, "pass");
    wallet.createAddress();  // primary (spend wallet: deposits allowed)
    wallet.setPqDepositScheme(CryptoNote::PqDepositScheme::SingleKeyIndex);
    ASSERT_EQ(wallet.reservePqDepositIndex(), 1u);
    ASSERT_EQ(wallet.reservePqDepositIndex(), 2u);
    wallet.save();      // the single create-time save createPqDepositAddress now performs
    wallet.shutdown();  // no save here: anything not already on disk is lost (== crash)
  }

  {
    CryptoNote::WalletGreen reloaded(dispatcher, currency, node, logger);
    ASSERT_NO_THROW(reloaded.load(path, "pass"));
    // Scheme + cursor come straight off disk, so the issued deposits keep their numbers
    // and the next reservation continues past them instead of reissuing T=1.
    EXPECT_EQ(reloaded.getPqDepositScheme(), CryptoNote::PqDepositScheme::SingleKeyIndex);
    EXPECT_EQ(reloaded.getPqDepositCount(), 2u);
    EXPECT_EQ(reloaded.getPqDepositIndexAt(0), 1u);
    EXPECT_EQ(reloaded.reservePqDepositIndex(), 3u);
    reloaded.shutdown();
  }

  boost::filesystem::remove(path);
}

// A SingleKeyIndex container that has issued NOTHING still persists cursor 1 (the
// first issuable T), which is byte-identical to what <=v0.9.6 wrote after issuing
// deposit T=0. The two must not be confused — one has no deposits, the other has an
// unattributable one — so a fresh container must round-trip as "zero deposits issued"
// and must keep handing out T=1 next.
TEST(PqWalletIntegration, SingleKeyIndexContainerWithNoDepositsRoundTrips) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  const std::string path = "pq_ski_nodeposits.wallet";
  boost::filesystem::remove(path);
  {
    CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);
    wallet.initialize(path, "pass");
    wallet.createAddress();
    wallet.setPqDepositScheme(CryptoNote::PqDepositScheme::SingleKeyIndex);
    EXPECT_EQ(wallet.getPqDepositCount(), 0u);
    EXPECT_EQ(wallet.getAddressCount(), 1u);  // primary only
    wallet.save(CryptoNote::WalletSaveLevel::SAVE_ALL);
    wallet.shutdown();
  }
  {
    CryptoNote::WalletGreen reloaded(dispatcher, currency, node, logger);
    ASSERT_NO_THROW(reloaded.load(path, "pass"));
    EXPECT_EQ(reloaded.getPqDepositScheme(), CryptoNote::PqDepositScheme::SingleKeyIndex);
    EXPECT_EQ(reloaded.getPqDepositCount(), 0u);   // NOT "one deposit at T=0"
    EXPECT_EQ(reloaded.getAddressCount(), 1u);
    EXPECT_EQ(reloaded.reservePqDepositIndex(), 1u);
    reloaded.shutdown();
  }

  boost::filesystem::remove(path);
}

// A failed relay must roll the spend back: inputs are reserved before relay (so a
// second send can't reuse them), and on relay failure the reservation is undone and the
// balance fully restored — no funds stranded.
TEST(PqWalletIntegration, RelayFailureRollsBackReservation) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_relayfail.wallet";
  boost::filesystem::remove(path);
  wallet.initialize(path, "pass");
  wallet.createAddress();

  Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
  CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(spend);
  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 7 + 3);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

  CryptoNote::Transaction pqTx = makePqPayTo(them, mine, 1000000, 800000, 0x55);
  generator.setTxFee(CryptoNote::getObjectHash(pqTx), 1000000 - 800000);
  generator.addTxToBlockchain(pqTx);
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 800000u; });
  ASSERT_EQ(wallet.getActualBalance(), 800000u);

  // Force the next relay to fail; the spend must throw and undo its reservation.
  node.setNextTransactionError();
  EXPECT_THROW(wallet.sendPqTransfer({ CryptoNote::PqSendOutput{ them.viewPub, them.spendPub, 300000 } }),
               std::exception);

  // Fully restored: nothing reserved, nothing pending.
  EXPECT_EQ(wallet.getActualBalance(), 800000u);
  EXPECT_EQ(wallet.getPendingBalance(), 0u);

  // And the wallet is still usable: a subsequent (successful) spend goes through.
  node.setNextTransactionToPool();
  CryptoNote::PqSendResult r =
      wallet.sendPqTransfer({ CryptoNote::PqSendOutput{ them.viewPub, them.spendPub, 300000 } });
  EXPECT_EQ(r.sent, 300000u);
  const Crypto::Hash successfulTxid = CryptoNote::getObjectHash(r.tx);

  // Payment proofs are wallet-cache metadata: they survive a reload once saved.
  wallet.save();
  wallet.shutdown();
  {
    CryptoNote::WalletGreen reloaded(dispatcher, currency, node, logger);
    ASSERT_NO_THROW(reloaded.load(path, "pass"));
    CryptoNote::SentPaymentRecord saved;
    ASSERT_TRUE(reloaded.copyPaymentProofs(successfulTxid, saved));
    ASSERT_EQ(saved.recipients.size(), 1u);
    EXPECT_EQ(saved.recipients[0].amount, 300000u);
    EXPECT_FALSE(saved.recipients[0].proof.empty());
    reloaded.shutdown();
  }
  boost::filesystem::remove(path);
}

// A deposit credit is rolled back when its block is orphaned, the same as a primary
// credit (onBlockchainDetach -> WalletLedger::rollbackToHeight), per bucket.
TEST(PqWalletIntegration, DepositCreditReversedOnReorg) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_depreorg.wallet";
  boost::filesystem::remove(path);
  wallet.initialize(path, "pass");
  wallet.createAddress();
  ASSERT_EQ(wallet.reservePqDepositIndex(), 0u);

  Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
  CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(spend);
  CryptoNote::PqWalletKeys depositRecipient = mine;
  depositRecipient.spendPub = CryptoPQ::deriveDepositSpendKeys(mine.seedMaster, 0).first;

  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 11 + 5);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

  CryptoNote::Transaction pqTx = makePqPayTo(them, depositRecipient, 1000000, 800000, 0x33);
  generator.setTxFee(CryptoNote::getObjectHash(pqTx), 1000000 - 800000);
  generator.addTxToBlockchain(pqTx);  // credits deposit 0 at height 1
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 800000u; });
  ASSERT_EQ(wallet.pqDepositBalance(0), 800000u);

  // Orphan the crediting block; a longer payment-free chain wins.
  node.startAlternativeChain(1);
  generator.generateEmptyBlocks(3);
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 0u; },
            std::chrono::seconds(20));

  EXPECT_EQ(wallet.getActualBalance(), 0u);
  EXPECT_EQ(wallet.pqDepositBalance(0), 0u);  // the deposit credit was rolled back
  EXPECT_EQ(wallet.getTransactionCount(), 0u);

  wallet.shutdown();
  boost::filesystem::remove(path);
}

// A tracking (view-only) wallet — built from a tracking credential, with no spend
// secret — must scan/report but REFUSE to spend.
TEST(PqWalletIntegration, TrackingWalletCannotSpend) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  // A full wallet to source a tracking credential.
  CryptoNote::PqTrackingKeys tk;
  const std::string fullPath = "pq_full.wallet";
  {
    boost::filesystem::remove(fullPath);
    CryptoNote::WalletGreen full(dispatcher, currency, node, logger);
    full.initialize(fullPath, "pass");
    full.createAddress();
    ASSERT_TRUE(full.getPqTrackingKeys(tk));
    full.shutdown();
    boost::filesystem::remove(fullPath);
  }

  // The view-only wallet built from that credential.
  const std::string trackPath = "pq_tracking.wallet";
  boost::filesystem::remove(trackPath);
  CryptoNote::WalletGreen tracking(dispatcher, currency, node, logger);
  tracking.initializeWithPqTrackingKey(trackPath, "pass", tk);

  // No spend authority...
  EXPECT_EQ(tracking.getAddressSpendKey(0).secretKey, CryptoNote::NULL_SECRET_KEY);
  // ...so spending is refused (not attempted and failed on funds — refused outright).
  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 7 + 3);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);
  EXPECT_THROW(tracking.sendPqTransfer({ CryptoNote::PqSendOutput{ them.viewPub, them.spendPub, 1000 } }),
               std::exception);

  tracking.shutdown();
  boost::filesystem::remove(trackPath);
}

// A view-only container asked to scan from a point in the past (walletd's
// --view-key --scan-height) hits doCreateAddressList's internal
// save(SAVE_KEYS_AND_TRANSACTIONS)/shutdown()/load() reset, because its creation
// timestamp is older than "now". That save level omits the PQ state blob, which is
// where the tracking credential lives — so the reload came back with a key record
// and no scanning consumer, and starting the synchronizer failed with "no
// consumers". The credential is identity, not cache: it must survive the reset, and
// the container must reopen with the same public identity.
TEST(PqWalletIntegration, TrackingContainerFromPastScanHeightKeepsIdentity) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  CryptoNote::PqTrackingKeys tk;
  uint32_t fullFingerprint = 0;
  std::string fullAddress;
  const std::string fullPath = "pq_scanheight_full.wallet";
  {
    boost::filesystem::remove(fullPath);
    CryptoNote::WalletGreen full(dispatcher, currency, node, logger);
    full.initialize(fullPath, "pass");
    full.createAddress();
    ASSERT_TRUE(full.getPqTrackingKeys(tk));
    fullFingerprint = full.pqAccountFingerprint();
    fullAddress = full.getAddress(0);
    full.shutdown();
    boost::filesystem::remove(fullPath);
  }

  // An explicitly old creation timestamp is what a past --scan-height resolves to,
  // and it is what triggers the reset (a live scan height would depend on the node's
  // block timestamps).
  const uint64_t pastTimestamp = 1000000;
  const std::string trackPath = "pq_scanheight_tracking.wallet";
  boost::filesystem::remove(trackPath);
  {
    CryptoNote::WalletGreen tracking(dispatcher, currency, node, logger);
    ASSERT_NO_THROW(tracking.initializeWithPqTrackingKey(trackPath, "pass", tk, pastTimestamp));
    tracking.setPqDepositScheme(CryptoNote::PqDepositScheme::SingleKeyIndex);

    // The credential came through the reset intact: same public identity as the
    // spending wallet, and a live consumer behind it.
    CryptoNote::PqTrackingKeys roundTripped;
    ASSERT_TRUE(tracking.getPqTrackingKeys(roundTripped));
    EXPECT_EQ(CryptoNote::encodePqTrackingKey(roundTripped), CryptoNote::encodePqTrackingKey(tk));
    EXPECT_EQ(tracking.pqAccountFingerprint(), fullFingerprint);
    EXPECT_EQ(tracking.getAddress(0), fullAddress);
    EXPECT_EQ(tracking.getAddressCount(), 1u);

    tracking.save(CryptoNote::WalletSaveLevel::SAVE_ALL);
    tracking.shutdown();
  }

  // ...and it is durable: reopening the container yields the same identity again.
  {
    CryptoNote::WalletGreen reopened(dispatcher, currency, node, logger);
    ASSERT_NO_THROW(reopened.load(trackPath, "pass"));
    EXPECT_EQ(reopened.pqAccountFingerprint(), fullFingerprint);
    EXPECT_EQ(reopened.getAddress(0), fullAddress);
    EXPECT_EQ(reopened.getPqDepositScheme(), CryptoNote::PqDepositScheme::SingleKeyIndex);
    reopened.shutdown();
  }
  boost::filesystem::remove(trackPath);
}

// walletd's --generate-container is a one-shot "write the container and exit". It has
// no reason to sync, and starting the synchronizer anyway means teardown must join a
// worker that can be parked in a node call with no timeout — which is what kept the
// process alive after the container was already on disk. Offline mode must suppress
// the start on EVERY path that reaches it, including the internal save/shutdown/load
// reset a past scan height triggers, and must leave nothing to join.
TEST(PqWalletIntegration, OfflineModeNeverStartsSynchronization) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  CryptoNote::PqTrackingKeys tk;
  const std::string genPath = "pq_offline_gen.wallet";
  {
    boost::filesystem::remove(genPath);
    CryptoNote::WalletGreen gen(dispatcher, currency, node, logger);
    gen.setOfflineMode(true);
    gen.initialize(genPath, "pass");
    gen.createAddress();
    ASSERT_TRUE(gen.getPqTrackingKeys(tk));
    gen.save(CryptoNote::WalletSaveLevel::SAVE_ALL);   // save() would otherwise restart it
    EXPECT_FALSE(gen.synchronizationStarted());
    gen.shutdown();
  }

  // The same for a view-only container generated at a past scan height, whose old
  // creation timestamp forces the reset path (save -> shutdown -> load), and whose
  // load() would otherwise start synchronization on the way back.
  const std::string trackPath = "pq_offline_track.wallet";
  {
    boost::filesystem::remove(trackPath);
    CryptoNote::WalletGreen tracking(dispatcher, currency, node, logger);
    tracking.setOfflineMode(true);
    const uint64_t pastTimestamp = 1000000;
    ASSERT_NO_THROW(tracking.initializeWithPqTrackingKey(trackPath, "pass", tk, pastTimestamp));
    tracking.save(CryptoNote::WalletSaveLevel::SAVE_ALL);
    EXPECT_FALSE(tracking.synchronizationStarted());
    tracking.shutdown();
  }

  // Offline mode describes the PROCESS, not the container: an ordinary open of the
  // container written above synchronizes as usual.
  {
    CryptoNote::WalletGreen reopened(dispatcher, currency, node, logger);
    ASSERT_NO_THROW(reopened.load(genPath, "pass"));
    EXPECT_TRUE(reopened.synchronizationStarted());
    reopened.shutdown();
  }

  boost::filesystem::remove(genPath);
  boost::filesystem::remove(trackPath);
}

// A container that has never completed a sync still has to report a block. Its
// consumer knows no block hashes, and initBlockchain() used to leave the block list
// empty in that case — so getBlockCount() returned 0 (its assert is compiled out in
// Release) and every "last block" lookup computed count - 1, underflowed to
// 0xFFFFFFFF, and indexed an empty result. walletd's getStatus did exactly that and
// died with an access violation. The block list must always hold at least genesis.
TEST(PqWalletIntegration, NeverSyncedContainerStillKnowsGenesis) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  const std::string path = "pq_neversynced.wallet";
  boost::filesystem::remove(path);
  {
    // Offline mode is exactly the state a wallet is in when the daemon never answers:
    // a container with keys whose consumer has never seen a block.
    CryptoNote::WalletGreen gen(dispatcher, currency, node, logger);
    gen.setOfflineMode(true);
    gen.initialize(path, "pass");
    gen.createAddress();
    gen.save(CryptoNote::WalletSaveLevel::SAVE_ALL);
    gen.shutdown();
  }

  CryptoNote::WalletGreen reopened(dispatcher, currency, node, logger);
  reopened.setOfflineMode(true);
  ASSERT_NO_THROW(reopened.load(path, "pass"));

  const uint32_t blockCount = reopened.getBlockCount();
  ASSERT_GE(blockCount, 1u);  // never 0: "count - 1" must not underflow
  auto lastHashes = reopened.getBlockHashes(blockCount - 1, 1);
  ASSERT_FALSE(lastHashes.empty());
  EXPECT_EQ(lastHashes.back(), currency.genesisBlockHash());

  reopened.shutdown();
  boost::filesystem::remove(path);
}

// The exchange deposit surface: the spending wallet registers the account number ONCE and
// exports a tracking credential; the view-only container then issues further H-I-A-T-C
// sub-numbers under that same account number. Everything a sub-number is made of is
// public — the fingerprint A hashes the two PUBLIC keys, T is an integer, and (H, I) come
// from a node lookup keyed by those public keys — so the view-only wallet must render
// byte-identical numbers, and must still scan deposits received at those T.
TEST(PqWalletIntegration, TrackingWalletIssuesSingleKeyIndexSubNumbers) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  // The registration coords (H, I) the spending wallet already obtained on-chain.
  const uint32_t regH = 4242, regI = 3;

  CryptoNote::PqTrackingKeys tk;
  Crypto::SecretKey seed;
  uint32_t fullFingerprint = 0;
  std::vector<std::string> fullNumbers;
  const std::string fullPath = "pq_ski_full.wallet";
  {
    boost::filesystem::remove(fullPath);
    CryptoNote::WalletGreen full(dispatcher, currency, node, logger);
    full.initialize(fullPath, "pass");
    full.createAddress();
    full.setPqDepositScheme(CryptoNote::PqDepositScheme::SingleKeyIndex);
    ASSERT_TRUE(full.getPqTrackingKeys(tk));
    seed = full.getAddressSpendKey(0).secretKey;
    fullFingerprint = full.pqAccountFingerprint();
    for (uint32_t t = 1; t <= 4; ++t) {  // deposits are T>=1; T=0 is the primary address
      fullNumbers.push_back(full.pqDepositAddress(t, regH, regI));
      ASSERT_FALSE(fullNumbers.back().empty());
    }
    full.shutdown();
    boost::filesystem::remove(fullPath);
  }

  const std::string trackPath = "pq_ski_tracking.wallet";
  boost::filesystem::remove(trackPath);
  CryptoNote::WalletGreen tracking(dispatcher, currency, node, logger);
  tracking.initializeWithPqTrackingKey(trackPath, "pass", tk);
  tracking.setPqDepositScheme(CryptoNote::PqDepositScheme::SingleKeyIndex);

  // No spend authority whatsoever...
  ASSERT_EQ(tracking.getAddressSpendKey(0).secretKey, CryptoNote::NULL_SECRET_KEY);
  // ...yet the public account identity is fully reconstructible: same fingerprint A, and
  // the key pair walletd needs to resolve (H, I) against the node.
  EXPECT_EQ(tracking.pqAccountFingerprint(), fullFingerprint);
  std::string viewHex, spendHex;
  EXPECT_TRUE(tracking.getPqRegistrationKeysHex(viewHex, spendHex));

  // Issuing sub-numbers works view-only and matches the spending wallet exactly.
  for (uint32_t t = 1; t <= 4; ++t) {
    ASSERT_EQ(tracking.reservePqDepositIndex(), t);
    EXPECT_EQ(tracking.pqDepositAddress(t, regH, regI), fullNumbers[t - 1]);
  }
  EXPECT_EQ(tracking.getPqDepositCount(), 4u);

  // A deposit paid to one of those sub-numbers is still scanned and attributed to it.
  CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(seed);
  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 13 + 2);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

  CryptoNote::Transaction pqTx = makePqPayTo(them, mine, 1000000, 700000, 0x71, /*T*/ 2);
  generator.setTxFee(CryptoNote::getObjectHash(pqTx), 1000000 - 700000);
  generator.addTxToBlockchain(pqTx);
  node.updateObservers();
  pumpUntil(dispatcher, tracking, [&tracking]() { return tracking.getActualBalance() == 700000u; });

  EXPECT_EQ(tracking.getActualBalance(), 700000u);
  EXPECT_EQ(tracking.pqDepositBalance(2), 700000u);

  tracking.shutdown();
  boost::filesystem::remove(trackPath);
}

// AggregatedMultikey is the one deposit scheme a view-only wallet genuinely cannot serve:
// each deposit gets its own ML-DSA spend key derived from the master seed, which a
// tracking credential does not carry. That refusal must survive the SingleKeyIndex fix.
TEST(PqWalletIntegration, TrackingWalletRefusesAggregatedMultikeyDeposits) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  CryptoNote::PqTrackingKeys tk;
  const std::string fullPath = "pq_agg_full.wallet";
  {
    boost::filesystem::remove(fullPath);
    CryptoNote::WalletGreen full(dispatcher, currency, node, logger);
    full.initialize(fullPath, "pass");
    full.createAddress();
    ASSERT_TRUE(full.getPqTrackingKeys(tk));
    full.shutdown();
    boost::filesystem::remove(fullPath);
  }

  const std::string trackPath = "pq_agg_tracking.wallet";
  boost::filesystem::remove(trackPath);
  CryptoNote::WalletGreen tracking(dispatcher, currency, node, logger);
  tracking.initializeWithPqTrackingKey(trackPath, "pass", tk);
  tracking.setPqDepositScheme(CryptoNote::PqDepositScheme::AggregatedMultikey);

  EXPECT_THROW(tracking.reservePqDepositIndex(), std::exception);
  EXPECT_TRUE(tracking.pqDepositAddress(0, 0, 0).empty());

  tracking.shutdown();
  boost::filesystem::remove(trackPath);
}

// A spend-locked output (per-output unlockHeight — the same mechanism coinbase maturity
// uses) is counted in the balance but NOT spendable until the chain reaches its unlock
// height; once it does, it becomes spendable.
TEST(PqWalletIntegration, LockedOutputNotSpendableUntilUnlockHeight) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_locked.wallet";
  boost::filesystem::remove(path);
  wallet.initialize(path, "pass");
  wallet.createAddress();

  Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
  CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(spend);
  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 7 + 3);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

  // Receive an output locked until a height a few blocks ahead of the current tip.
  const uint64_t unlockAt = generator.getBlockchain().size() + 5;
  CryptoNote::Transaction pqTx = makePqPayTo(them, mine, 1000000, 800000, 0x55, /*T*/ 0, unlockAt);
  generator.setTxFee(CryptoNote::getObjectHash(pqTx), 1000000 - 800000);
  generator.addTxToBlockchain(pqTx);
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getPendingBalance() == 800000u; });

  // Counted in total ownership, but locked: the public Available/Locked split must
  // agree with the send path rather than advertising funds it cannot select.
  EXPECT_EQ(wallet.pqActualBalance(), 800000u);
  EXPECT_EQ(wallet.getActualBalance(), 0u);
  EXPECT_EQ(wallet.getPendingBalance(), 800000u);
  EXPECT_THROW(wallet.sendPqTransfer({ CryptoNote::PqSendOutput{ them.viewPub, them.spendPub, 300000 } }),
               std::exception);

  // Advance the chain past the unlock height.
  generator.generateEmptyBlocks(8);
  const uint32_t tip = static_cast<uint32_t>(generator.getBlockchain().size() - 1);
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet, tip]() { return wallet.pqSyncedHeight() >= tip; });

  // Now spendable and reported as available rather than locked.
  EXPECT_EQ(wallet.getActualBalance(), 800000u);
  EXPECT_EQ(wallet.getPendingBalance(), 0u);
  node.setNextTransactionToPool();
  CryptoNote::PqSendResult r =
      wallet.sendPqTransfer({ CryptoNote::PqSendOutput{ them.viewPub, them.spendPub, 300000 } });
  EXPECT_EQ(r.sent, 300000u);

  wallet.shutdown();
  boost::filesystem::remove(path);
}

// reset(scanHeight) drops the PQ ledger and re-derives it by rescanning the chain; the
// balance and history come back identical.
TEST(PqWalletIntegration, ResetRescansLedger) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_reset.wallet";
  boost::filesystem::remove(path);
  wallet.initialize(path, "pass");
  wallet.createAddress();

  Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
  CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(spend);
  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 7 + 3);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

  CryptoNote::Transaction pqTx = makePqPayTo(them, mine, 1000000, 800000, 0x55);
  generator.setTxFee(CryptoNote::getObjectHash(pqTx), 1000000 - 800000);
  generator.addTxToBlockchain(pqTx);
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 800000u; });
  ASSERT_EQ(wallet.getActualBalance(), 800000u);
  ASSERT_EQ(wallet.getTransactionCount(), 1u);

  // Rescan from genesis: the ledger is rebuilt from the chain to the same state.
  wallet.reset(0);
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 800000u; },
            std::chrono::seconds(20));
  EXPECT_EQ(wallet.getActualBalance(), 800000u);
  EXPECT_EQ(wallet.getTransactionCount(), 1u);

  wallet.shutdown();
  boost::filesystem::remove(path);
}

// simplewallet engine (WalletLegacy) smoke test: it has a working PQ identity — a valid
// PQ address and message signing that verifies against that address's spend key.
TEST(WalletLegacySmoke, PqIdentityAndSigning) {
  System::Dispatcher dispatcher;
  (void)dispatcher;  // WalletLegacy manages its own threads
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  CryptoNote::WalletLegacy wallet(currency, node, logger);
  wallet.initAndGenerate("pass");

  // A valid PQ address.
  const std::string address = wallet.getAddress();
  CryptoNote::PqAddress pq;
  ASSERT_TRUE(CryptoNote::decodePqAddress(address, pq));

  // Message signing verifies against the address's published spend key.
  const std::string msg = "discrete simplewallet";
  const std::string sig = wallet.sign_message(msg);
  ASSERT_FALSE(sig.empty());
  EXPECT_TRUE(CryptoNote::verifyMessagePq(msg, pq.spendPub, sig));
  EXPECT_FALSE(CryptoNote::verifyMessagePq("tampered", pq.spendPub, sig));

  // Deterministic backup: a non-empty mnemonic.
  std::string words;
  EXPECT_TRUE(wallet.getSeed(words));
  EXPECT_FALSE(words.empty());

  wallet.shutdown();
}

TEST(WalletLegacySmoke, DetachedSeedNeverReturnsToSavedTrackingWallet) {
  System::Dispatcher dispatcher;
  (void)dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  CryptoNote::WalletLegacy wallet(currency, node, logger);
  wallet.initAndGenerate("pass");
  EXPECT_FALSE(wallet.pqScannerHasSpendSeed());
  EXPECT_FALSE(wallet.setPqProtectedSpendMetadata("must-not-enter-a-full-wallet"));
  const std::string address = wallet.getAddress();

  CryptoNote::AccountKeys before;
  wallet.getAccountKeys(before);
  const CryptoPQ::SeedMaster expected = CryptoNote::pqSeedMasterFromSpendSecret(before.spendSecretKey);
  CryptoPQ::SeedMaster detached{};
  ASSERT_TRUE(wallet.detachPqSpendSeed(detached));
  EXPECT_EQ(detached, expected);
  EXPECT_TRUE(wallet.isTrackingWallet());
  EXPECT_FALSE(wallet.pqScannerHasSpendSeed());

  CryptoNote::AccountKeys after;
  wallet.getAccountKeys(after);
  EXPECT_EQ(after.spendSecretKey, CryptoNote::NULL_SECRET_KEY);
  std::string words;
  EXPECT_FALSE(wallet.getSeed(words));
  EXPECT_THROW(wallet.sign_message("must not sign from resident state"), std::runtime_error);

  const std::string message = "one-operation external seed";
  const std::string signature = wallet.signMessageWithSeed(detached, message);
  CryptoNote::PqAddress decoded;
  ASSERT_TRUE(CryptoNote::decodePqAddress(address, decoded));
  EXPECT_TRUE(CryptoNote::verifyMessagePq(message, decoded.spendPub, signature));
  CryptoPQ::SeedMaster wrong = detached;
  wrong[0] ^= 1;
  EXPECT_THROW(wallet.signMessageWithSeed(wrong, message), std::runtime_error);

  const std::string protectedSpendMetadata =
      R"({"version":2,"algorithm":"test-envelope","keys":["primary","backup"]})";
  ASSERT_TRUE(wallet.setPqProtectedSpendMetadata(protectedSpendMetadata));
  std::string storedMetadata;
  ASSERT_TRUE(wallet.getPqProtectedSpendMetadata(storedMetadata));
  EXPECT_EQ(storedMetadata, protectedSpendMetadata);

  std::stringstream serialized;
  CryptoNote::WalletHelper::SaveWalletResultObserver saveObserver;
  {
    CryptoNote::WalletHelper::IWalletRemoveObserverGuard guard(wallet, saveObserver);
    std::future<std::error_code> saved = saveObserver.saveResult.get_future();
    wallet.save(serialized, true, true);
    ASSERT_FALSE(saved.get());
  }
  const std::string protectedWalletBytes = serialized.str();
  ASSERT_FALSE(protectedWalletBytes.empty());
  // The first byte is the envelope marker now, not the content version: the
  // content version moved inside the authenticated payload so it cannot be edited
  // on disk. inspectWalletSnapshot below reads it back out and is what pins that
  // this is still a protected-spend wallet.
  EXPECT_EQ(static_cast<unsigned char>(protectedWalletBytes.front()),
            CryptoNote::WalletLegacySerializer::AUTHENTICATED_ENVELOPE);

  CryptoNote::WalletSnapshotInfo snapshotInfo;
  std::string snapshotError;
  std::stringstream snapshotStream(protectedWalletBytes);
  ASSERT_TRUE(CryptoNote::WalletLegacy::inspectWalletSnapshot(
      snapshotStream, "pass", snapshotInfo, snapshotError)) << snapshotError;
  EXPECT_EQ(snapshotInfo.serializationVersion,
            CryptoNote::WalletLegacySerializer::PROTECTED_SPEND_VERSION);
  EXPECT_TRUE(snapshotInfo.isTracking);
  EXPECT_TRUE(snapshotInfo.hasPqTrackingKeys);
  EXPECT_EQ(CryptoNote::encodePqTrackingKey(snapshotInfo.pqTrackingKeys),
            CryptoNote::encodePqTrackingKey(
                CryptoNote::pqTrackingKeys(
                    CryptoNote::derivePqWalletKeys(detached))));
  EXPECT_EQ(snapshotInfo.protectedSpendMetadata, protectedSpendMetadata);

  std::stringstream wrongPasswordSnapshot(protectedWalletBytes);
  EXPECT_FALSE(CryptoNote::WalletLegacy::inspectWalletSnapshot(
      wrongPasswordSnapshot, "wrong", snapshotInfo, snapshotError));

  // The old v2 reader ignored unknown top-level versions. Re-label the v3 file
  // as v2 to make the current parser follow that exact legacy path: it must see
  // the compatibility guard as keys and reject the file instead of opening it.
  std::string legacyReaderBytes = protectedWalletBytes;
  legacyReaderBytes[0] =
      static_cast<char>(CryptoNote::WalletLegacySerializer::STANDARD_VERSION);
  std::stringstream legacyReaderStream(legacyReaderBytes);
  CryptoNote::AccountBase legacyReaderAccount;
  CryptoNote::WalletLegacySerializer legacyReader(legacyReaderAccount);
  EXPECT_FALSE(legacyReader.deserialize(legacyReaderStream, "pass"));
  wallet.shutdown();

  serialized.seekg(0);
  CryptoNote::WalletLegacy reloaded(currency, node, logger);
  CryptoNote::WalletHelper::InitWalletResultObserver initObserver;
  {
    CryptoNote::WalletHelper::IWalletRemoveObserverGuard guard(reloaded, initObserver);
    std::future<std::error_code> loaded = initObserver.initResult.get_future();
    reloaded.initAndLoad(serialized, "pass");
    ASSERT_FALSE(loaded.get());
  }

  EXPECT_TRUE(reloaded.isTrackingWallet());
  EXPECT_FALSE(reloaded.pqScannerHasSpendSeed());
  EXPECT_EQ(reloaded.getAddress(), address);
  CryptoNote::AccountKeys reloadedKeys;
  reloaded.getAccountKeys(reloadedKeys);
  EXPECT_EQ(reloadedKeys.spendSecretKey, CryptoNote::NULL_SECRET_KEY);
  EXPECT_FALSE(reloaded.getSeed(words));
  EXPECT_NO_THROW(reloaded.signMessageWithSeed(detached, message));
  storedMetadata.clear();
  ASSERT_TRUE(reloaded.getPqProtectedSpendMetadata(storedMetadata));
  EXPECT_EQ(storedMetadata, protectedSpendMetadata);

  // reset() deliberately saves without the normal cache. Protected-spend
  // recovery metadata is authority, not disposable sync state, and must remain.
  reloaded.reset();
  storedMetadata.clear();
  ASSERT_TRUE(reloaded.getPqProtectedSpendMetadata(storedMetadata));
  EXPECT_EQ(storedMetadata, protectedSpendMetadata);
  EXPECT_TRUE(reloaded.isTrackingWallet());
  reloaded.shutdown();
}

TEST(WalletLegacySmoke, FailedProtectedMigrationCanRestoreDetachedSeed) {
  System::Dispatcher dispatcher;
  (void)dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  CryptoNote::WalletLegacy wallet(currency, node, logger);
  wallet.initAndGenerate("pass");
  const std::string address = wallet.getAddress();

  CryptoPQ::SeedMaster detached{};
  ASSERT_TRUE(wallet.detachPqSpendSeed(detached));
  ASSERT_TRUE(wallet.setPqProtectedSpendMetadata("staged-but-not-committed"));
  ASSERT_TRUE(wallet.restorePqSpendSeed(detached));
  EXPECT_FALSE(wallet.isTrackingWallet());
  EXPECT_EQ(wallet.getAddress(), address);

  std::string metadata;
  EXPECT_FALSE(wallet.getPqProtectedSpendMetadata(metadata));
  std::string mnemonic;
  EXPECT_TRUE(wallet.getSeed(mnemonic));
  EXPECT_FALSE(mnemonic.empty());
  EXPECT_NO_THROW(wallet.sign_message("rollback restored spending"));

  CryptoPQ::SeedMaster wrong = detached;
  wrong[0] ^= 1;
  CryptoPQ::SeedMaster detachedAgain{};
  ASSERT_TRUE(wallet.detachPqSpendSeed(detachedAgain));
  EXPECT_FALSE(wallet.restorePqSpendSeed(wrong));
  EXPECT_TRUE(wallet.isTrackingWallet());
  ASSERT_TRUE(wallet.restorePqSpendSeed(detachedAgain));
  EXPECT_FALSE(wallet.isTrackingWallet());
  wallet.shutdown();
}

// DiscreteWallet uses WalletLegacy rather than WalletGreen. Exercise the exact
// GUI send/history backend and prove that its original recipient label and
// payment proof survive a full cache-backed wallet save, reload, and safe rescan,
// while an explicitly destructive reset removes only that local payer evidence.
TEST(WalletLegacySmoke, RescanPreservesAndResetDiscardsStoredRecipientAndPaymentProof) {
  System::Dispatcher dispatcher;
  (void)dispatcher;  // WalletLegacy manages its own threads
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  CryptoNote::WalletLegacy wallet(currency, node, logger);
  wallet.initAndGenerate("pass");

  CryptoNote::AccountKeys accountKeys;
  wallet.getAccountKeys(accountKeys);
  CryptoNote::PqWalletKeys mine = CryptoNote::derivePqWalletKeys(accountKeys.spendSecretKey);

  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 7 + 3);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);

  CryptoNote::Transaction funding = makePqPayTo(them, mine, 1000000, 800000, 0x55);
  generator.setTxFee(CryptoNote::getObjectHash(funding), 200000);
  generator.addTxToBlockchain(funding);
  node.updateObservers();

  const auto syncDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (wallet.actualBalance() != 800000u && std::chrono::steady_clock::now() < syncDeadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  ASSERT_EQ(wallet.actualBalance(), 800000u);

  const std::string recipient = CryptoNote::encodePqAddress(
      CryptoNote::makePqAddress(currency.publicAddressBase58Prefix(), them.viewPub, them.spendPub),
      CryptoNote::pqBech32Hrp(currency.isTestnet()));
  node.setNextTransactionToPool();
  const CryptoNote::TransactionId transactionId = wallet.sendTransaction(
      CryptoNote::WalletLegacyTransfer{recipient, 300000}, 0, "", 0, 0);
  ASSERT_NE(transactionId, CryptoNote::WALLET_LEGACY_INVALID_TRANSACTION_ID);

  CryptoNote::WalletLegacyTransaction transaction;
  ASSERT_TRUE(wallet.getTransaction(transactionId, transaction));
  ASSERT_EQ(transaction.transferCount, 1u);

  CryptoNote::SentPaymentRecord stored;
  ASSERT_TRUE(wallet.copyPaymentProofs(transaction.hash, stored));
  ASSERT_EQ(stored.recipients.size(), 1u);
  EXPECT_EQ(stored.recipients[0].address, recipient);
  EXPECT_EQ(stored.recipients[0].amount, 300000u);
  ASSERT_FALSE(stored.recipients[0].proof.empty());

  std::stringstream serialized;
  CryptoNote::WalletHelper::SaveWalletResultObserver saveObserver;
  {
    CryptoNote::WalletHelper::IWalletRemoveObserverGuard guard(wallet, saveObserver);
    std::future<std::error_code> saved = saveObserver.saveResult.get_future();
    wallet.save(serialized, true, true);
    ASSERT_FALSE(saved.get());
  }
  wallet.shutdown();

  // Corrupt only the recoverable scan cursor while leaving the later payer
  // evidence section valid. Loading must fall back to rescan without skipping
  // recipient/proof metadata that the blockchain cannot reconstruct.
  CryptoNote::AccountBase serializedAccount;
  CryptoNote::WalletLegacySerializer cacheReader(serializedAccount);
  std::string cache;
  {
    std::stringstream encoded(serialized.str());
    ASSERT_NO_THROW(cacheReader.deserialize(encoded, "pass", cache));
  }
  ASSERT_GE(cache.size(), 8u);
  std::array<std::string, 6> cacheSections;
  std::size_t cacheOffset = 8;
  for (std::string& section : cacheSections) {
    ASSERT_LE(sizeof(uint64_t), cache.size() - cacheOffset);
    uint64_t length = 0;
    std::memcpy(&length, cache.data() + cacheOffset, sizeof(length));
    cacheOffset += sizeof(length);
    ASSERT_LE(length, static_cast<uint64_t>(cache.size() - cacheOffset));
    section.assign(cache.data() + cacheOffset, static_cast<std::size_t>(length));
    cacheOffset += static_cast<std::size_t>(length);
  }
  ASSERT_EQ(cacheOffset, cache.size());
  ASSERT_FALSE(cacheSections[4].empty());

  cacheSections[1].assign(1, static_cast<char>(0x80));  // unterminated varint
  {
    CryptoNote::SynchronizationState invalidState(currency.genesisBlockHash());
    std::stringstream invalidConsumerState(cacheSections[1]);
    EXPECT_ANY_THROW(invalidState.load(invalidConsumerState));
  }

  std::stringstream corruptedCache;
  corruptedCache.write(cache.data(), 8);
  for (const std::string& section : cacheSections) {
    const uint64_t length = section.size();
    corruptedCache.write(reinterpret_cast<const char*>(&length), sizeof(length));
    corruptedCache.write(section.data(), static_cast<std::streamsize>(section.size()));
  }
  std::stringstream corruptedWallet;
  CryptoNote::WalletLegacySerializer cacheWriter(
      serializedAccount, cacheReader.loadedVersion());
  ASSERT_NO_THROW(cacheWriter.serialize(
      corruptedWallet, "pass", true, corruptedCache.str()));

  corruptedWallet.seekg(0);
  CryptoNote::WalletLegacy recoveredFromBadScanCache(currency, node, logger);
  CryptoNote::WalletHelper::InitWalletResultObserver badCacheInitObserver;
  {
    CryptoNote::WalletHelper::IWalletRemoveObserverGuard guard(
        recoveredFromBadScanCache, badCacheInitObserver);
    std::future<std::error_code> loaded =
        badCacheInitObserver.initResult.get_future();
    recoveredFromBadScanCache.initAndLoad(corruptedWallet, "pass");
    ASSERT_FALSE(loaded.get());
  }
  CryptoNote::SentPaymentRecord recoveredEvidence;
  ASSERT_TRUE(recoveredFromBadScanCache.copyPaymentProofs(
      transaction.hash, recoveredEvidence));
  ASSERT_EQ(recoveredEvidence.recipients.size(), 1u);
  EXPECT_EQ(recoveredEvidence.recipients[0].address, recipient);
  EXPECT_EQ(recoveredEvidence.recipients[0].amount, 300000u);
  EXPECT_EQ(recoveredEvidence.recipients[0].proof,
            stored.recipients[0].proof);
  recoveredFromBadScanCache.shutdown();

  serialized.seekg(0);
  CryptoNote::WalletLegacy reloaded(currency, node, logger);
  CryptoNote::WalletHelper::InitWalletResultObserver initObserver;
  {
    CryptoNote::WalletHelper::IWalletRemoveObserverGuard guard(reloaded, initObserver);
    std::future<std::error_code> loaded = initObserver.initResult.get_future();
    reloaded.initAndLoad(serialized, "pass");
    ASSERT_FALSE(loaded.get());
  }

  CryptoNote::SentPaymentRecord restored;
  ASSERT_TRUE(reloaded.copyPaymentProofs(transaction.hash, restored));
  ASSERT_EQ(restored.recipients.size(), 1u);
  EXPECT_EQ(restored.recipients[0].address, recipient);
  EXPECT_EQ(restored.recipients[0].amount, 300000u);
  EXPECT_EQ(restored.recipients[0].proof, stored.recipients[0].proof);

  CryptoNote::WalletLegacyTransaction restoredTransaction;
  ASSERT_TRUE(reloaded.getTransaction(transactionId, restoredTransaction));
  ASSERT_EQ(restoredTransaction.transferCount, 1u);
  CryptoNote::WalletLegacyTransfer restoredTransfer;
  ASSERT_TRUE(reloaded.getTransfer(restoredTransaction.firstTransferId, restoredTransfer));
  EXPECT_EQ(restoredTransfer.address, recipient);
  EXPECT_EQ(restoredTransfer.amount, 300000);

  reloaded.rescan();
  CryptoNote::SentPaymentRecord rescanned;
  ASSERT_TRUE(reloaded.copyPaymentProofs(transaction.hash, rescanned));
  ASSERT_EQ(rescanned.recipients.size(), 1u);
  EXPECT_EQ(rescanned.recipients[0].address, recipient);
  EXPECT_EQ(rescanned.recipients[0].amount, 300000u);
  EXPECT_EQ(rescanned.recipients[0].proof, stored.recipients[0].proof);

  CryptoNote::AccountKeys rescannedKeys;
  reloaded.getAccountKeys(rescannedKeys);
  EXPECT_EQ(rescannedKeys.viewSecretKey, accountKeys.viewSecretKey);
  EXPECT_EQ(rescannedKeys.spendSecretKey, accountKeys.spendSecretKey);

  reloaded.reset();
  CryptoNote::SentPaymentRecord discarded;
  EXPECT_FALSE(reloaded.copyPaymentProofs(transaction.hash, discarded));

  CryptoNote::AccountKeys resetKeys;
  reloaded.getAccountKeys(resetKeys);
  EXPECT_EQ(resetKeys.viewSecretKey, accountKeys.viewSecretKey);
  EXPECT_EQ(resetKeys.spendSecretKey, accountKeys.spendSecretKey);

  std::stringstream afterReset;
  CryptoNote::WalletHelper::SaveWalletResultObserver afterResetSaveObserver;
  {
    CryptoNote::WalletHelper::IWalletRemoveObserverGuard guard(reloaded, afterResetSaveObserver);
    std::future<std::error_code> saved = afterResetSaveObserver.saveResult.get_future();
    reloaded.save(afterReset, true, true);
    ASSERT_FALSE(saved.get());
  }
  reloaded.shutdown();

  afterReset.seekg(0);
  CryptoNote::WalletLegacy reopenedAfterReset(currency, node, logger);
  CryptoNote::WalletHelper::InitWalletResultObserver afterResetInitObserver;
  {
    CryptoNote::WalletHelper::IWalletRemoveObserverGuard guard(reopenedAfterReset, afterResetInitObserver);
    std::future<std::error_code> loaded = afterResetInitObserver.initResult.get_future();
    reopenedAfterReset.initAndLoad(afterReset, "pass");
    ASSERT_FALSE(loaded.get());
  }
  EXPECT_FALSE(reopenedAfterReset.copyPaymentProofs(transaction.hash, discarded));
  CryptoNote::AccountKeys reopenedKeys;
  reopenedAfterReset.getAccountKeys(reopenedKeys);
  EXPECT_EQ(reopenedKeys.viewSecretKey, accountKeys.viewSecretKey);
  EXPECT_EQ(reopenedKeys.spendSecretKey, accountKeys.spendSecretKey);
  reopenedAfterReset.shutdown();
}

// Full Index (H-I-A-T-C) receive + spend addressed by the account-number STRING: register,
// issue an H-I-A-T-C deposit, receive to it, read its balance by the H-I-A-T-C string, and
// spend restricted to it by that same string.
TEST(PqWalletIntegration, IndexHITCReceiveAndSpendByAddressString) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_hitc_spend.wallet";
  boost::filesystem::remove(path);
  wallet.initialize(path, "pass");
  wallet.createAddress();
  wallet.setPqDepositScheme(CryptoNote::PqDepositScheme::SingleKeyIndex);

  Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
  CryptoNote::PqWalletKeys mine = pqKeysFromWalletSeed(spend);

  // Register the base account on-chain so H-I-A-T-C addresses can be formed.
  Crypto::Hash refHash = node.getLastLocalBlockHeaderInfo().hash;
  CryptoNote::Transaction regTx = wallet.buildPqFreeRegTransaction(refHash);
  generator.addTxToBlockchain(regTx);

  // Reserve two deposits and address the first (T=1) by its H-I-A-T-C string.
  // SingleKeyIndex issuance starts at 1 — T=0 is the primary address.
  ASSERT_EQ(wallet.reservePqDepositIndex(), 1u);
  ASSERT_EQ(wallet.reservePqDepositIndex(), 2u);
  const std::string hitc = wallet.getAddress(1);  // first issued deposit -> T=1
  CryptoNote::AccountNumber acct;
  uint32_t t = 99;
  ASSERT_TRUE(CryptoNote::AccountNumber::fromStringWithIndex(hitc, acct, t));
  ASSERT_EQ(t, 1u);

  // Pay 800000 to the deposit (one key, subaddress T=1).
  Crypto::SecretKey otherSecret;
  for (std::size_t i = 0; i < sizeof(otherSecret.data); ++i)
    otherSecret.data[i] = static_cast<uint8_t>(i * 11 + 5);
  CryptoNote::PqWalletKeys them = CryptoNote::derivePqWalletKeys(otherSecret);
  CryptoNote::Transaction pqTx = makePqPayTo(them, mine, 1000000, 800000, 0x71, /*T*/ 1);
  generator.setTxFee(CryptoNote::getObjectHash(pqTx), 1000000 - 800000);
  generator.addTxToBlockchain(pqTx);
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet]() { return wallet.getActualBalance() == 800000u; });

  // Balance read BY THE H-I-A-T-C STRING resolves to that deposit bucket.
  EXPECT_EQ(wallet.getActualBalance(hitc), 800000u);

  // Spend restricted to that deposit BY THE H-I-A-T-C STRING (SingleKeyIndex -> one key).
  node.setNextTransactionToPool();
  CryptoNote::PqSendResult r = wallet.sendPqTransfer(
      { CryptoNote::PqSendOutput{ them.viewPub, them.spendPub, 300000 } },
      /*fee*/ 0, /*unlockHeight*/ 0, /*extra*/ {}, /*sourceAddresses*/ { hitc });
  ASSERT_EQ(r.selected.size(), 1u);
  EXPECT_EQ(r.selected[0].depositIndex, 1u);  // drew from deposit #1
  generator.setTxFee(CryptoNote::getObjectHash(r.tx), r.fee);
  generator.putTxPoolToBlockchain();
  node.updateObservers();
  pumpUntil(dispatcher, wallet, [&wallet, &hitc]() { return wallet.getActualBalance(hitc) == 0u; });

  EXPECT_EQ(wallet.getActualBalance(hitc), 0u);  // the deposit was spent

  wallet.shutdown();
  boost::filesystem::remove(path);
}

// AggregatedMultikey per-subaddress message signing: each deposit has its OWN spend key,
// so signing FOR a deposit address produces a signature that verifies against THAT
// address and no other.
TEST(PqWalletIntegration, AggregatedPerSubaddressMessageSigning) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_subsign.wallet";
  boost::filesystem::remove(path);
  wallet.initialize(path, "pass");
  wallet.createAddress();                 // primary (AggregatedMultikey is default)
  ASSERT_EQ(wallet.reservePqDepositIndex(), 0u);
  ASSERT_EQ(wallet.reservePqDepositIndex(), 1u);

  const std::string primary = wallet.getAddress(0);
  const std::string dep0 = wallet.getAddress(1);
  const std::string dep1 = wallet.getAddress(2);
  ASSERT_NE(dep0, dep1);

  const std::string msg = "prove control of deposit 1";

  // Sign FOR deposit 1 with its own key: verifies against deposit 1 only.
  const std::string sig1 = wallet.signMessage(msg, dep1);
  EXPECT_TRUE(wallet.verifyMessage(msg, dep1, sig1));
  EXPECT_FALSE(wallet.verifyMessage(msg, dep0, sig1));     // different deposit key
  EXPECT_FALSE(wallet.verifyMessage(msg, primary, sig1));  // not the primary key

  // Sign FOR deposit 0: verifies against deposit 0 only.
  const std::string sig0 = wallet.signMessage(msg, dep0);
  EXPECT_TRUE(wallet.verifyMessage(msg, dep0, sig0));
  EXPECT_FALSE(wallet.verifyMessage(msg, dep1, sig0));

  // Primary (and the empty selector) sign as the primary identity.
  const std::string sigP = wallet.signMessage(msg, primary);
  EXPECT_TRUE(wallet.verifyMessage(msg, primary, sigP));
  EXPECT_FALSE(wallet.verifyMessage(msg, dep1, sigP));
  const std::string sigEmpty = wallet.signMessage(msg, "");
  EXPECT_TRUE(wallet.verifyMessage(msg, primary, sigEmpty));

  wallet.shutdown();
  boost::filesystem::remove(path);
}

// Every ciphertext in the container must carry its own nonce. Reusing one
// (key, nonce) pair across two plaintexts leaks their XOR, and the wallet cache
// is largely predictable, so a collision between a seed record and the cache
// blob exposes the master seed. reset() is the path that rewrites every seed
// record and then immediately rewrites the cache, so it is where a shared
// counter shows up.
namespace {
// Collect every IV the container file holds: one per live seed record, plus the
// one that prefixes the encrypted cache blob. Read straight off disk (the file
// layout is prefix | size | capacity | records | suffix) because the wallet keeps
// an exclusive mapping open while it is loaded.
std::vector<std::string> collectContainerNonces(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

  const size_t prefixSize = sizeof(CryptoNote::ContainerStoragePrefix);
  const size_t recordSize = sizeof(CryptoNote::EncryptedWalletRecord);
  const size_t nonceSize = CryptoPQ::kAeadNonceBytes;

  uint64_t capacity = 0, count = 0;
  std::memcpy(&capacity, bytes.data() + prefixSize, sizeof(capacity));
  std::memcpy(&count, bytes.data() + prefixSize + sizeof(capacity), sizeof(count));

  std::vector<std::string> ivs;
  const size_t recordsAt = prefixSize + 2 * sizeof(uint64_t);
  for (uint64_t i = 0; i < count; ++i) {
    ivs.emplace_back(bytes.data() + recordsAt + i * recordSize, nonceSize);
  }

  // The cache blob is nonce || ciphertext || tag, so its nonce is at the front.
  const size_t suffixAt = recordsAt + static_cast<size_t>(capacity) * recordSize;
  if (bytes.size() >= suffixAt + nonceSize) {
    ivs.emplace_back(bytes.data() + suffixAt, nonceSize);
  }
  return ivs;
}
}  // namespace

TEST(PqWalletIntegration, ResetNeverReusesAnIv) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_reset_iv.wallet";
  boost::filesystem::remove(path);
  wallet.initialize(path, "pass");
  wallet.createAddress();
  wallet.save(CryptoNote::WalletSaveLevel::SAVE_ALL);
  wallet.shutdown();

  std::vector<std::string> before = collectContainerNonces(path);
  ASSERT_GE(before.size(), 2u) << "expected at least one seed record plus a cache blob";
  EXPECT_EQ(before.size(), std::set<std::string>(before.begin(), before.end()).size());

  // reset() re-encrypts every seed record and then saves the cache.
  wallet.load(path, "pass");
  wallet.reset(0);
  wallet.save(CryptoNote::WalletSaveLevel::SAVE_ALL);
  wallet.shutdown();

  std::vector<std::string> after = collectContainerNonces(path);
  ASSERT_EQ(before.size(), after.size());
  EXPECT_EQ(after.size(), std::set<std::string>(after.begin(), after.end()).size())
      << "an IV was reused inside the container after reset";

  // The rewrite must also not reuse the IVs the previous ciphertexts were under.
  std::set<std::string> seen(before.begin(), before.end());
  for (const std::string& iv : after) {
    EXPECT_EQ(0u, seen.count(iv)) << "reset reused a pre-reset IV";
  }

  boost::filesystem::remove(path);
}

// A wallet written in the pre-upgrade format must still open, and opening it
// must convert it: unlock with the old unsalted key, rewrite under a fresh salt
// with authenticated records, and come back with the same identity and the same
// balance. The original file is kept alongside as a backup.
namespace {

// The version-9 writer, kept here rather than in production code: nothing ships
// that writes this format any more, but the reader has to keep working.
CryptoNote::EncryptedWalletRecordV1 encryptSeedRecordLegacy(
    const CryptoPQ::SeedMaster& seedMaster, uint64_t creationTimestamp,
    const Crypto::chacha8_key& key) {
  CryptoNote::EncryptedWalletRecordV1 result{};
  unsigned char buffer[sizeof(result.data)];
  std::memcpy(buffer, CryptoNote::SEED_RECORD_MAGIC_V1, sizeof(CryptoNote::SEED_RECORD_MAGIC_V1));
  std::memcpy(buffer + sizeof(CryptoNote::SEED_RECORD_MAGIC_V1), seedMaster.data(),
              seedMaster.size());
  std::memcpy(buffer + sizeof(CryptoNote::SEED_RECORD_MAGIC_V1) + seedMaster.size(),
              &creationTimestamp, sizeof(uint64_t));
  result.iv = Crypto::randomChachaIV();
  Crypto::chacha8(buffer, sizeof(buffer), key, result.iv, reinterpret_cast<char*>(result.data));
  return result;
}

// Write a minimal but genuine version-9 container holding one seed record.
void writeLegacyWallet(const std::string& path, const std::string& password,
                       const CryptoPQ::SeedMaster& seed, uint64_t creationTimestamp) {
  Crypto::chacha8_key key;
  Crypto::cn_context context;
  ASSERT_TRUE(Crypto::generate_chacha8_key(context, password, key));

  CryptoNote::ContainerStorageV1 storage(path, Common::FileMappedVectorOpenMode::CREATE,
                                         sizeof(CryptoNote::ContainerStoragePrefixV1));
  auto* prefix = reinterpret_cast<CryptoNote::ContainerStoragePrefixV1*>(storage.prefix());
  prefix->version = CryptoNote::WALLET_CONTAINER_VERSION_LEGACY;
  prefix->nextIv = Crypto::randomChachaIV();

  storage.push_back(encryptSeedRecordLegacy(seed, creationTimestamp, key));
  storage.flush();
  storage.close();
}

uint8_t walletFileVersion(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  return static_cast<uint8_t>(in.peek());
}

}  // namespace

TEST(PqWalletIntegration, LegacyContainerIsUpgradedOnOpen) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  const std::string path = "pq_legacy_upgrade.wallet";
  const std::string backup = path + ".v9";
  boost::filesystem::remove(path);
  boost::filesystem::remove(backup);

  CryptoPQ::SeedMaster seed{};
  for (std::size_t i = 0; i < seed.size(); ++i) {
    seed[i] = static_cast<uint8_t>(i * 3 + 7);
  }
  writeLegacyWallet(path, "pass", seed, 1700000000);
  ASSERT_EQ(CryptoNote::WALLET_CONTAINER_VERSION_LEGACY, walletFileVersion(path));

  const std::string expectedAddress = [&]() {
    CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);
    wallet.load(path, "pass");

    // The identity survives the rewrite untouched.
    EXPECT_EQ(1u, wallet.getAddressCount());
    Crypto::SecretKey spend = wallet.getAddressSpendKey(0).secretKey;
    EXPECT_EQ(0, std::memcmp(spend.data, seed.data(), sizeof(spend.data)));

    std::string address = wallet.getAddress(0);
    wallet.shutdown();
    return address;
  }();

  // The file on disk is now the current format, and the original is kept.
  EXPECT_EQ(CryptoNote::WALLET_CONTAINER_VERSION, walletFileVersion(path));
  EXPECT_TRUE(boost::filesystem::exists(backup));
  EXPECT_EQ(CryptoNote::WALLET_CONTAINER_VERSION_LEGACY, walletFileVersion(backup));

  // Reopening the upgraded file gives the same wallet back, and the old password
  // still opens it (the password did not change, only the salt it is used with).
  {
    CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);
    wallet.load(path, "pass");
    EXPECT_EQ(expectedAddress, wallet.getAddress(0));
    wallet.shutdown();
  }

  // A wrong password is still refused after the upgrade.
  {
    CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);
    EXPECT_ANY_THROW(wallet.load(path, "not the password"));
  }

  boost::filesystem::remove(path);
  boost::filesystem::remove(backup);
}

TEST(PqWalletIntegration, LegacyContainerWithAWrongPasswordIsLeftAlone) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  const std::string path = "pq_legacy_badpass.wallet";
  boost::filesystem::remove(path);
  boost::filesystem::remove(path + ".v9");

  CryptoPQ::SeedMaster seed{};
  for (std::size_t i = 0; i < seed.size(); ++i) {
    seed[i] = static_cast<uint8_t>(i + 1);
  }
  writeLegacyWallet(path, "pass", seed, 1700000000);

  {
    CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);
    EXPECT_ANY_THROW(wallet.load(path, "wrong"));
  }

  // Nothing was rewritten: a failed unlock must never touch the wallet file.
  EXPECT_EQ(CryptoNote::WALLET_CONTAINER_VERSION_LEGACY, walletFileVersion(path));
  EXPECT_FALSE(boost::filesystem::exists(path + ".v9"));

  // And the right password still works afterwards.
  {
    CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);
    wallet.load(path, "pass");
    EXPECT_EQ(1u, wallet.getAddressCount());
    wallet.shutdown();
  }

  boost::filesystem::remove(path);
  boost::filesystem::remove(path + ".v9");
}

// Secrets must not outlive the wallet that holds them. Closing a wallet, and
// failing to open one, both have to leave the container key, the password and
// the master seeds zeroed rather than sitting in freed heap (and in swap) until
// the process ends.
TEST(PqWalletIntegration, ClosingAWalletScrubsItsSecrets) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_scrub.wallet";
  boost::filesystem::remove(path);

  wallet.initialize(path, "pass");
  wallet.createAddress();
  EXPECT_TRUE(wallet.hasResidentSecrets());

  wallet.shutdown();
  EXPECT_FALSE(wallet.hasResidentSecrets())
      << "a closed wallet is still holding its key, password or master seed";

  // Reopening and closing again behaves the same way.
  wallet.load(path, "pass");
  EXPECT_TRUE(wallet.hasResidentSecrets());
  wallet.shutdown();
  EXPECT_FALSE(wallet.hasResidentSecrets());

  boost::filesystem::remove(path);
}

TEST(PqWalletIntegration, AFailedOpenLeavesNoSecretsBehind) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);

  const std::string path = "pq_scrub_badpass.wallet";
  boost::filesystem::remove(path);

  {
    CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);
    wallet.initialize(path, "pass");
    wallet.createAddress();
    wallet.save(CryptoNote::WalletSaveLevel::SAVE_ALL);
    wallet.shutdown();
  }

  // A wrong password still derives a key before it fails. That key must not
  // survive the failure.
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);
  EXPECT_ANY_THROW(wallet.load(path, "wrong"));
  EXPECT_FALSE(wallet.hasResidentSecrets())
      << "a failed open left the derived container key resident";

  boost::filesystem::remove(path);
}

TEST(PqWalletIntegration, ChangingThePasswordDoesNotStrandTheOldKey) {
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger(Logging::ERROR);
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger)
      .testnet(true)
      .upgradeHeightV2(1).upgradeHeightV3(1).upgradeHeightV4(1)
      .upgradeHeightV5(1000000).upgradeHeightV6(1000000)
      .currency();
  TestBlockchainGenerator generator(currency);
  INodeTrivialRefreshStub node(generator);
  CryptoNote::WalletGreen wallet(dispatcher, currency, node, logger);

  const std::string path = "pq_scrub_chpass.wallet";
  boost::filesystem::remove(path);

  wallet.initialize(path, "old pass");
  wallet.createAddress();
  const std::string address = wallet.getAddress(0);

  wallet.changePassword("old pass", "new pass");
  wallet.save(CryptoNote::WalletSaveLevel::SAVE_ALL);
  wallet.shutdown();
  EXPECT_FALSE(wallet.hasResidentSecrets());

  // The new password opens it and the old one does not.
  wallet.load(path, "new pass");
  EXPECT_EQ(address, wallet.getAddress(0));
  wallet.shutdown();

  CryptoNote::WalletGreen stale(dispatcher, currency, node, logger);
  EXPECT_ANY_THROW(stale.load(path, "old pass"));

  boost::filesystem::remove(path);
}
