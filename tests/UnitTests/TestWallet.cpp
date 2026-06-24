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
#include <chrono>
#include <fstream>
#include <numeric>
#include <system_error>
#include <tuple>

#include "Common/StringTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/TransactionApi.h"
#include "CryptoNoteCore/TransactionApiExtra.h"
#include "INodeStubs.h"
#include "TestBlockchainGenerator.h"
#include "TransactionApiHelpers.h"
#include <Logging/ConsoleLogger.h>
#include "Wallet/MiningKeyLoader.h"
#include "Wallet/WalletErrors.h"
#include "Wallet/WalletGreen.h"
#include "Wallet/PqWallet.h"
#include "Wallet/PqTransactionBuilder.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqDerive.h"
#include "Wallet/WalletSerializationV2.h"
#include "Wallet/WalletUtils.h"
#include "WalletLegacy/WalletUserTransactionsCache.h"
#include "WalletLegacy/WalletLegacySerializer.h"
#include <System/Dispatcher.h>
#include <System/Timer.h>
#include <System/Context.h>

#include "TransactionApiHelpers.h"

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
                                    uint64_t inAmount, uint64_t payAmount, uint8_t seed) {
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
  return CryptoNote::buildPqTransaction({in}, {out}, from.spendPub, from.spendSk);
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
// to the wallet must derive the same way (the SeedMaster overload, not the SecretKey
// overload which applies the legacy HKDF step).
static CryptoNote::PqWalletKeys pqKeysFromWalletSeed(const Crypto::SecretKey& seed) {
  CryptoPQ::SeedMaster sm{};
  std::memcpy(sm.data(), seed.data, sm.size());
  return CryptoNote::derivePqWalletKeys(sm);
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
