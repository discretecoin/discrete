// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete — a post-quantum-only cryptocurrency.
//
// Pins the frozen genesis: the deterministic 14-tranche premine coinbase, its
// per-output unlock schedule, the total premine, reproducibility, that the
// frozen GENESIS_COINBASE_TX_HEX matches the builder, and the genesis block hash.

#include <gtest/gtest.h>

#include <cstdint>

#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/GenesisPremine.h"
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

// Premine economics: 14 tranches of 500,000 XDS (50,000,000 atoms), staggered
// unlock at 0, 80000, ... 1,040,000; total 7,000,000 XDS.
TEST(PqGenesis, PremineStructure) {
  Logging::ConsoleLogger logger;
  Currency currency = makeCurrency(logger);
  const Transaction& cb = currency.genesisBlock().baseTransaction;

  EXPECT_EQ(cb.version, TRANSACTION_VERSION_1);
  EXPECT_EQ(cb.txType, static_cast<uint8_t>(TX_COINBASE));
  ASSERT_EQ(cb.inputs.size(), 1u);
  EXPECT_EQ(cb.inputs[0].type(), typeid(BaseInput));
  EXPECT_EQ(boost::get<BaseInput>(cb.inputs[0]).blockIndex, 0u);
  EXPECT_TRUE(cb.pqSignatures.empty());

  ASSERT_EQ(cb.outputs.size(), GENESIS_PREMINE_TRANCHES);
  uint64_t total = 0;
  for (size_t i = 0; i < cb.outputs.size(); ++i) {
    EXPECT_EQ(cb.outputs[i].amount, GENESIS_PREMINE_TRANCHE_ATOMS) << "tranche " << i;
    EXPECT_EQ(cb.outputs[i].unlockHeight,
              static_cast<uint64_t>(i) * GENESIS_PREMINE_UNLOCK_STEP) << "tranche " << i;
    EXPECT_EQ(cb.outputs[i].target.type(), typeid(PqOutput)) << "tranche " << i;
    total += cb.outputs[i].amount;
  }
  EXPECT_EQ(total, GENESIS_PREMINE_TOTAL_ATOMS);
  EXPECT_EQ(total, UINT64_C(700000000));  // 7,000,000 XDS at 2 decimals
}

// Building the premine coinbase twice yields byte-identical output (deterministic
// ML-KEM encaps + seed-derived rho) — this is what makes --print-genesis-tx
// reproducible across runs/hosts.
TEST(PqGenesis, BuilderIsDeterministic) {
  BinaryArray a = toBinaryArray(buildGenesisPremineCoinbase());
  BinaryArray b = toBinaryArray(buildGenesisPremineCoinbase());
  EXPECT_EQ(a, b);
  EXPECT_FALSE(a.empty());
}

// The frozen GENESIS_COINBASE_TX_HEX constant must equal the builder output, so
// the constant on disk and a regenerating node agree byte-for-byte.
TEST(PqGenesis, FrozenHexMatchesBuilder) {
  BinaryArray fromConst;
  ASSERT_TRUE(Common::fromHex(std::string(GENESIS_COINBASE_TX_HEX), fromConst));
  BinaryArray fromBuilder = toBinaryArray(buildGenesisPremineCoinbase());
  EXPECT_EQ(fromConst, fromBuilder);
}

// Pin the mainnet genesis block hash. If this changes, the network forks — only
// update deliberately (and never after launch).
TEST(PqGenesis, GenesisBlockHashPinned) {
  Logging::ConsoleLogger logger;
  Currency currency = makeCurrency(logger);
  EXPECT_EQ(Common::podToHex(currency.genesisBlockHash()),
            "69462d0732edab6182c8872315dc0ea7a0d6a8695971c405894f4e17014b1de8");
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
