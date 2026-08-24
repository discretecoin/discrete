// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete — a post-quantum-only cryptocurrency.
//
// Pins the frozen genesis: the deterministic 21-batch Treasury Reserve coinbase,
// its per-output unlock schedule, the total reserve, reproducibility, that the
// frozen GENESIS_COINBASE_TX_HEX matches the builder, and the genesis block hash.

#include <gtest/gtest.h>

#include <cstdint>

#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/GenesisTreasuryReserve.h"
#include "Common/StringTools.h"
#include "Logging/ConsoleLogger.h"
#include "PqTxType.h"

using namespace CryptoNote;

namespace {
Currency makeCurrency(Logging::ILogger& logger) {
  // Mainnet (testnet=false): pins the canonical mainnet genesis.
  return CurrencyBuilder(logger).currency();
}
}  // namespace

// Treasury Reserve economics: 21 batches of 50,000 XDS (5,000,000 atoms), staggered
// unlock at 0, 87600, ... 1,752,000 (quarterly over 5 years); total 1,050,000 XDS
// (5% of the 21,000,000 XDS ceiling).
TEST(PqGenesis, TreasuryReserveStructure) {
  Logging::ConsoleLogger logger;
  Currency currency = makeCurrency(logger);
  const Transaction& cb = currency.genesisBlock().baseTransaction;

  EXPECT_EQ(cb.version, TRANSACTION_VERSION_1);
  EXPECT_EQ(cb.txType, static_cast<uint8_t>(TX_COINBASE));
  ASSERT_EQ(cb.inputs.size(), 1u);
  EXPECT_EQ(cb.inputs[0].type(), typeid(BaseInput));
  EXPECT_EQ(boost::get<BaseInput>(cb.inputs[0]).blockIndex, 0u);
  EXPECT_TRUE(cb.pqSignatures.empty());

  ASSERT_EQ(cb.outputs.size(), GENESIS_TREASURY_RESERVE_BATCHES);
  uint64_t total = 0;
  for (size_t i = 0; i < cb.outputs.size(); ++i) {
    EXPECT_EQ(cb.outputs[i].amount, GENESIS_TREASURY_RESERVE_BATCH_ATOMS) << "batch " << i;
    EXPECT_EQ(cb.outputs[i].unlockHeight,
              static_cast<uint64_t>(i) * GENESIS_TREASURY_RESERVE_UNLOCK_STEP) << "batch " << i;
    EXPECT_EQ(cb.outputs[i].target.type(), typeid(CoinbaseOutput)) << "batch " << i;
    total += cb.outputs[i].amount;
  }
  EXPECT_EQ(total, GENESIS_TREASURY_RESERVE_TOTAL_ATOMS);
  EXPECT_EQ(total, UINT64_C(105000000));  // 1,050,000 XDS at 2 decimals
}

// Building the Treasury Reserve coinbase twice yields byte-identical output (deterministic
// ML-KEM encaps + seed-derived rho) — this is what makes --print-genesis-tx
// reproducible across runs/hosts.
TEST(PqGenesis, BuilderIsDeterministic) {
  BinaryArray a = toBinaryArray(buildGenesisTreasuryReserveCoinbase());
  BinaryArray b = toBinaryArray(buildGenesisTreasuryReserveCoinbase());
  EXPECT_EQ(a, b);
  EXPECT_FALSE(a.empty());
}

// The frozen GENESIS_COINBASE_TX_HEX constant must equal the builder output, so
// the constant on disk and a regenerating node agree byte-for-byte.
TEST(PqGenesis, FrozenHexMatchesBuilder) {
  BinaryArray fromConst;
  ASSERT_TRUE(Common::fromHex(std::string(GENESIS_COINBASE_TX_HEX), fromConst));
  BinaryArray fromBuilder = toBinaryArray(buildGenesisTreasuryReserveCoinbase());
  EXPECT_EQ(fromConst, fromBuilder);
}

// Pin the mainnet genesis block hash. If this changes, the network forks — only
// update deliberately (and never after launch).
TEST(PqGenesis, GenesisBlockHashPinned) {
  Logging::ConsoleLogger logger;
  Currency currency = makeCurrency(logger);
  EXPECT_EQ(currency.genesisBlock().timestamp, GENESIS_BLOCK_TIMESTAMP);
  ASSERT_EQ(currency.genesisBlock().signature.size(), PQ_SIGNATURE_SIZE);
  for (uint8_t byte : currency.genesisBlock().signature) {
    EXPECT_EQ(byte, 0u);  // trusted wire-shape placeholder; genesis is not mined
  }
  // Regenerated 2026-07-15 (fresh GENESIS_BLOCK_TIMESTAMP) under the
  // witness-commitment block ID (get_block_hash now folds a 32-byte witness over
  // the block signature). Genesis carries an all-zero placeholder signature.
  EXPECT_EQ(Common::podToHex(currency.genesisBlockHash()),
            "06c4df2cd46045b9fbc1664a10f1bdf0355f672c8349bbd29d671bf48e83d7bd");
}


// Mainnet and testnet must not share a genesis transaction.
//
// A TX_PQ spend signature covers the transaction body, which names the outpoints
// being spent but not the chain they belong to. If both networks started from the
// same genesis transaction they would have the same genesis transaction id and
// the same genesis outpoints, and a signature spending one of them would verify
// on either chain. Differing block nonces do not help: the nonce is in the block,
// and the outpoint comes from the transaction.
//
// This pins the mitigation. The complete fix is to bind chain identity into the
// signing transcript, which is a consensus change scheduled for the next upgrade.
TEST(PqGenesis, NetworksDoNotShareAGenesisTransaction) {
  Logging::ConsoleLogger logger;
  Currency mainnet = CurrencyBuilder(logger).testnet(false).currency();
  Currency testnet = CurrencyBuilder(logger).testnet(true).currency();

  const Transaction& mainCb = mainnet.genesisBlock().baseTransaction;
  const Transaction& testCb = testnet.genesisBlock().baseTransaction;

  const Crypto::Hash mainTxid = getObjectHash(mainCb);
  const Crypto::Hash testTxid = getObjectHash(testCb);
  EXPECT_NE(Common::podToHex(mainTxid), Common::podToHex(testTxid))
      << "the two networks share a genesis transaction id, so they share genesis "
         "outpoints and a spend signed for one verifies on the other";

  // Every genesis outpoint is (txid, index), so distinct txids make every
  // outpoint distinct. Assert the transactions really do differ on the wire too.
  EXPECT_NE(toBinaryArray(mainCb), toBinaryArray(testCb));

  // And the block hashes differ, as they already did.
  EXPECT_NE(Common::podToHex(mainnet.genesisBlockHash()),
            Common::podToHex(testnet.genesisBlockHash()));
}

// The testnet marker changes only the coinbase extra: the reserve outputs, the
// amounts, and the unlock schedule are the same on both networks.
TEST(PqGenesis, TestnetKeepsTheSameReserveStructure) {
  Logging::ConsoleLogger logger;
  Currency testnet = CurrencyBuilder(logger).testnet(true).currency();
  const Transaction& cb = testnet.genesisBlock().baseTransaction;

  ASSERT_EQ(GENESIS_TREASURY_RESERVE_BATCHES, cb.outputs.size());
  uint64_t total = 0;
  for (size_t i = 0; i < cb.outputs.size(); ++i) {
    EXPECT_EQ(GENESIS_TREASURY_RESERVE_BATCH_ATOMS, cb.outputs[i].amount);
    EXPECT_EQ(static_cast<uint64_t>(i) * GENESIS_TREASURY_RESERVE_UNLOCK_STEP,
              cb.outputs[i].unlockHeight);
    total += cb.outputs[i].amount;
  }
  EXPECT_EQ(GENESIS_TREASURY_RESERVE_TOTAL_ATOMS, total);
}

// The mainnet artifact is frozen and must not move because testnet changed.
TEST(PqGenesis, TestnetMarkerDoesNotTouchMainnet) {
  BinaryArray fromConst;
  ASSERT_TRUE(Common::fromHex(std::string(GENESIS_COINBASE_TX_HEX), fromConst));
  EXPECT_EQ(fromConst, toBinaryArray(buildGenesisTreasuryReserveCoinbase(false)));
  EXPECT_NE(fromConst, toBinaryArray(buildGenesisTreasuryReserveCoinbase(true)));
}

TEST(PqGenesis, TestnetBuilderIsDeterministic) {
  EXPECT_EQ(toBinaryArray(buildGenesisTreasuryReserveCoinbase(true)),
            toBinaryArray(buildGenesisTreasuryReserveCoinbase(true)));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
