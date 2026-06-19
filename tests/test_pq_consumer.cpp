// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Tests for WalletLedgerConsumer: the BlockchainSynchronizer consumer that scans blocks
// for PQ outputs. Drives it with synthetic CompleteBlocks built from real PQ
// transactions (via the builders) wrapped in prefix readers — exercising the
// same prefix-blob path the live synchronizer uses.

#include "gtest/gtest.h"

#include "Wallet/WalletLedgerConsumer.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/PqWallet.h"
#include "Transfers/CommonTypes.h"
#include "CryptoNoteCore/TransactionApi.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqDerive.h"
#include "Logging/ConsoleLogger.h"
#include "CryptoNote.h"

#include <cstring>
#include <memory>

using namespace CryptoNote;

namespace {

Crypto::SecretKey spendSecret(uint8_t a, uint8_t b) {
    Crypto::SecretKey k;
    for (std::size_t i = 0; i < sizeof(k.data); ++i)
        k.data[i] = static_cast<uint8_t>(i * a + b);
    return k;
}

// A TX_PQ from `from` paying `payAmount` to `to`.
Transaction payTo(const PqWalletKeys& from, const PqWalletKeys& to, uint64_t inAmount,
                  uint64_t payAmount, uint8_t seed) {
    std::vector<CryptoPQ::InputRef> refs(1);
    for (auto& b : refs[0].prevTxid) b = seed;
    refs[0].prevOutIndex = 1;
    CryptoPQ::Hash256 fih = CryptoPQ::inputsHash(refs);
    CryptoPQ::PqBuiltOutput src =
        CryptoPQ::buildPqOutput(from.viewPub, from.spendPub, fih, 0, inAmount);

    PqSpendInput in;
    for (std::size_t i = 0; i < 32; ++i) in.prevTxid.data[i] = static_cast<uint8_t>(seed + i);
    in.prevOutIndex = 0;
    in.amount = inAmount;
    in.rho = src.rho;

    PqSendOutput out{to.viewPub, to.spendPub, payAmount};
    return buildPqTransaction({in}, {out}, from.spendPub, from.spendSk);
}

// Wrap a transaction as a one-tx CompleteBlock at the given (dummy) block.
CompleteBlock makeBlock(const Transaction& tx) {
    CompleteBlock cb;
    cb.block = Block();  // initialized so the consumer processes it
    cb.transactions.push_back(std::shared_ptr<ITransactionReader>(createTransactionPrefix(tx).release()));
    cb.blockHash = getObjectHash(tx);  // arbitrary but unique-ish
    return cb;
}

}  // namespace

TEST(WalletLedgerConsumer, ScansOwnedOutputFromBlock) {
    Logging::ConsoleLogger logger(Logging::ERROR);
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedgerConsumer consumer(me, SynchronizationStart{0, 0}, logger);

    Transaction tx = payTo(them, me, 1000000, 800000, 0x10);
    CompleteBlock cb = makeBlock(tx);

    uint32_t processed = consumer.onNewBlocks(&cb, 50, 1);
    EXPECT_EQ(processed, 1u);
    EXPECT_EQ(consumer.state().balance(), 800000u);
    EXPECT_EQ(consumer.state().lastScannedHeight(), 50u);
}

TEST(WalletLedgerConsumer, IgnoresOtherWalletsOutputs) {
    Logging::ConsoleLogger logger(Logging::ERROR);
    PqWalletKeys me    = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them  = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys other = derivePqWalletKeys(spendSecret(2, 2));

    WalletLedgerConsumer consumer(me, SynchronizationStart{0, 0}, logger);
    Transaction tx = payTo(them, other, 1000000, 800000, 0x20);
    CompleteBlock cb = makeBlock(tx);

    EXPECT_EQ(consumer.onNewBlocks(&cb, 10, 1), 1u);
    EXPECT_EQ(consumer.state().balance(), 0u);
}

TEST(WalletLedgerConsumer, MultipleBlocksAndDetach) {
    Logging::ConsoleLogger logger(Logging::ERROR);
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedgerConsumer consumer(me, SynchronizationStart{0, 0}, logger);

    Transaction a = payTo(them, me, 1000000, 500000, 0x30);
    Transaction b = payTo(them, me, 1000000, 300000, 0x40);
    CompleteBlock blocks[2] = { makeBlock(a), makeBlock(b) };

    EXPECT_EQ(consumer.onNewBlocks(blocks, 100, 2), 2u);
    EXPECT_EQ(consumer.state().balance(), 800000u);  // received at 100 and 101

    // Reorg detach at 101 drops the second output (received at 101), keeps first.
    consumer.onBlockchainDetach(101);
    EXPECT_EQ(consumer.state().balance(), 500000u);
    EXPECT_EQ(consumer.state().unspentCount(), 1u);
}

TEST(WalletLedgerConsumer, EmptyBlocksCountButCreditNothing) {
    Logging::ConsoleLogger logger(Logging::ERROR);
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    WalletLedgerConsumer consumer(me, SynchronizationStart{0, 0}, logger);

    CompleteBlock empty;  // block not initialized
    EXPECT_EQ(consumer.onNewBlocks(&empty, 5, 1), 1u);
    EXPECT_EQ(consumer.state().balance(), 0u);
    EXPECT_EQ(consumer.state().lastScannedHeight(), 5u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
