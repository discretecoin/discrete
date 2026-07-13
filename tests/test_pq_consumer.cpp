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
#include "Transfers/SynchronizationState.h"
#include "CryptoNoteCore/TransactionApi.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqDerive.h"
#include "Logging/ConsoleLogger.h"
#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "PqTxType.h"

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

// Regression for the live walletd reorg bug (testnet run 2026-06-27): a confirmed
// receive whose block is orphaned by a reorg, and whose still-valid tx returns to the
// mempool, must end up PENDING — counted in the total balance but NOT spendable. The
// aggregate getBalance was reporting the raw total as "available", so it advertised 700
// while the per-deposit balance and the spend path (which exclude pending) saw 0, and a
// send then failed with "insufficient unlocked balance". This test pins the ledger split
// the fix relies on: balance() includes pending, spendableBalance()/spendableInputs() do not.
TEST(WalletLedgerConsumer, ReorgReturnsReceiveToPoolAsPendingNotSpendable) {
    Logging::ConsoleLogger logger(Logging::ERROR);
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedgerConsumer consumer(me, SynchronizationStart{0, 0}, logger);

    Transaction tx = payTo(them, me, 1000000, 700, 0x55);  // 700 au = the live "deposit" amount
    Crypto::Hash txid = getObjectHash(tx);
    CompleteBlock cb = makeBlock(tx);

    // Confirmed in block 14: fully available, and present in history as confirmed.
    ASSERT_EQ(consumer.onNewBlocks(&cb, 14, 1), 1u);
    EXPECT_EQ(consumer.state().balance(), 700u);
    EXPECT_EQ(consumer.state().spendableBalance(), 700u);
    EXPECT_EQ(consumer.state().spendableInputs().size(), 1u);
    ASSERT_NE(consumer.state().historyByTxid(txid), nullptr);
    EXPECT_NE(consumer.state().historyByTxid(txid)->height, WalletLedger::UNCONFIRMED_HEIGHT);

    // The reorg detaches block 14: the orphaned output (and its history row) are dropped.
    consumer.onBlockchainDetach(14);
    EXPECT_EQ(consumer.state().balance(), 0u);
    EXPECT_EQ(consumer.state().spendableBalance(), 0u);
    EXPECT_EQ(consumer.state().historyByTxid(txid), nullptr);

    // The orphaned tx is still valid, so the daemon returns it to the mempool. It is
    // re-credited — but PENDING: the total counts it, the spendable amount does not.
    std::vector<std::unique_ptr<ITransactionReader>> added;
    added.push_back(createTransactionPrefix(tx));
    std::vector<Crypto::Hash> noDeletes;
    ASSERT_FALSE(consumer.onPoolUpdated(added, noDeletes));

    EXPECT_EQ(consumer.state().balance(), 700u);          // raw total (the old "available")
    EXPECT_EQ(consumer.state().pendingBalance(), 700u);   // ...is entirely in the mempool
    EXPECT_EQ(consumer.state().spendableBalance(), 0u);   // ...so nothing is actually available
    EXPECT_TRUE(consumer.state().spendableInputs().empty());
    ASSERT_NE(consumer.state().historyByTxid(txid), nullptr);
    EXPECT_EQ(consumer.state().historyByTxid(txid)->height, WalletLedger::UNCONFIRMED_HEIGHT);

    // If the tx never comes back (e.g. it lost to a double-spend on the new chain) the
    // daemon drops it from the pool, and the pending effect is reconciled away.
    std::vector<std::unique_ptr<ITransactionReader>> noAdds;
    std::vector<Crypto::Hash> deleted{ txid };
    ASSERT_FALSE(consumer.onPoolUpdated(noAdds, deleted));
    EXPECT_EQ(consumer.state().balance(), 0u);
    EXPECT_EQ(consumer.state().pendingBalance(), 0u);
    EXPECT_EQ(consumer.state().historyByTxid(txid), nullptr);
}

// SynchronizationState::checkInterval with empty m_blockchain sets newBlockHeight=0
// so the synchronizer delivers block 0. This pins the core mechanism of the fix:
// a fresh consumer (never synced, m_blockchain empty) sees genesis as the first
// new block, not as already-processed.
TEST(SynchronizationState, FreshConsumerDeliversGenesisAtHeightZero) {
    Crypto::Hash genesisHash{};
    genesisHash.data[0] = 0x11;
    Crypto::Hash block1Hash{};
    block1Hash.data[0] = 0x22;

    SynchronizationState state(genesisHash);

    // m_blockchain is empty → getHeight() == 0, getShortHistory returns genesis anchor.
    EXPECT_EQ(state.getHeight(), 0u);
    auto history = state.getShortHistory(1000);
    ASSERT_EQ(history.size(), 1u);
    EXPECT_EQ(history[0], genesisHash);

    // checkInterval starting at height 0 with [genesis, block1] → deliver from 0.
    BlockchainInterval interval;
    interval.startHeight = 0;
    interval.blocks = {genesisHash, block1Hash};
    auto result = state.checkInterval(interval);
    EXPECT_FALSE(result.detachRequired);
    EXPECT_TRUE(result.hasNewBlocks);
    EXPECT_EQ(result.newBlockHeight, 0u);  // block 0 is new

    // After addBlocks at height 0, genesis is now recorded.
    Crypto::Hash hashes[] = {genesisHash, block1Hash};
    state.addBlocks(hashes, 0, 2);
    EXPECT_EQ(state.getHeight(), 2u);

    // Second sync: nothing new.
    auto result2 = state.checkInterval(interval);
    EXPECT_FALSE(result2.hasNewBlocks);
}

// Genesis treasury flows through the normal onNewBlocks path (block 0 delivered
// by the synchronizer). Previously required a scanGenesisBlock crutch because
// SynchronizationState pre-seeded genesis as already-known; the fix starts
// m_blockchain empty so checkInterval sets newBlockHeight=0 and block 0 arrives.
//
// Models the real genesis shape: TX_COINBASE, BaseInput at height 0,
// CoinbaseOutput per batch (stripped: only spendCommit, no kemCt/encPayload).
// Tests that:
// - owned batches credit at height 0, non-owned are ignored
// - far-future batch stays locked until setLastScannedHeight clears it
// - re-delivering block 0 (nullifier already known) is idempotent (no double-credit)
TEST(WalletLedgerConsumer, GenesisBlockCreditsTreasuryViaOnNewBlocks) {
    Logging::ConsoleLogger logger(Logging::ERROR);
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    Transaction tx;
    tx.version = TRANSACTION_VERSION_1;
    tx.txType = TX_COINBASE;
    tx.unlockHeight = 0;
    BaseInput coinbaseIn;
    coinbaseIn.blockIndex = 0;
    tx.inputs.push_back(coinbaseIn);

    struct Batch { const PqWalletKeys* to; uint64_t unlock; };
    const Batch batches[] = {
        { &me,   0 },      // ours, spendable from genesis
        { &me,   87600 },  // ours, locked ~one quarter out
        { &them, 0 },      // someone else's
    };
    for (uint32_t i = 0; i < 3; ++i) {
        CryptoPQ::Rho cbRho = CryptoPQ::coinbaseRho(batches[i].to->spendPub, 0, i);
        CryptoPQ::Hash256 sc = CryptoPQ::spendCommit(batches[i].to->spendPub, cbRho);
        CoinbaseOutput co;
        std::memcpy(co.spendCommit.data, sc.data(), 32);
        TransactionOutput out;
        out.amount = 5000000;
        out.unlockHeight = batches[i].unlock;
        out.target = std::move(co);
        tx.outputs.push_back(std::move(out));
    }

    // Wrap in a CompleteBlock at height 0, the way BlockchainSynchronizer does.
    Block genesisBlock;
    genesisBlock.timestamp = GENESIS_BLOCK_TIMESTAMP;
    genesisBlock.baseTransaction = tx;

    CompleteBlock cb;
    cb.blockHash = Crypto::Hash{};  // sentinel; WalletLedger doesn't use it
    cb.block = boost::make_optional(genesisBlock);
    cb.transactions.push_back(createTransactionPrefix(tx));

    WalletLedgerConsumer consumer(me, SynchronizationStart{0, 0}, logger);
    EXPECT_EQ(consumer.onNewBlocks(&cb, 0, 1), 1u);

    // Both owned batches credited (balance includes locked funds); theirs ignored.
    EXPECT_EQ(consumer.state().balance(), 10000000u);
    EXPECT_EQ(consumer.state().unspentCount(), 2u);

    // The credited row is flagged as a mined (coinbase) transaction: both owned
    // batches share the one base tx, so there is a single history row and the GUI
    // (History "MINED" label, Mining tab found-block stats) reads coinbase off it.
    ASSERT_EQ(consumer.state().history().size(), 1u);
    EXPECT_TRUE(consumer.state().history()[0].coinbase);

    // Past coinbase maturity only the unlockHeight-0 batch is spendable.
    consumer.state().setLastScannedHeight(20);
    EXPECT_EQ(consumer.state().spendableBalance(), 5000000u);

    // Re-delivering block 0 must be idempotent: nullifiers already known.
    EXPECT_EQ(consumer.onNewBlocks(&cb, 0, 1), 1u);
    EXPECT_EQ(consumer.state().balance(), 10000000u);
    EXPECT_EQ(consumer.state().unspentCount(), 2u);
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
