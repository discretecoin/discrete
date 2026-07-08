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
    EXPECT_EQ(cb.outputs[i].target.type(), typeid(PqOutput)) << "batch " << i;
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
  EXPECT_EQ(Common::podToHex(currency.genesisBlockHash()),
            "b1df0152bb41d12bef471f322ac8fef52889cdb4128759a41877d26d08edace8");
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
