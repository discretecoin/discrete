// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Tests for PqWalletState: scanning raw transactions for owned PQ outputs,
// separate balance accounting, spend detection via nullifiers, and reorg
// rollback. Uses the real PQ builders to produce the transactions it scans.

#include "gtest/gtest.h"

#include "Wallet/PqWalletState.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/PqWallet.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqDerive.h"
#include "CryptoNote.h"

#include <cstring>
#include <sstream>
#include <vector>

using namespace CryptoNote;

namespace {

Crypto::SecretKey spendSecret(uint8_t a, uint8_t b) {
    Crypto::SecretKey k;
    for (std::size_t i = 0; i < sizeof(k.data); ++i)
        k.data[i] = static_cast<uint8_t>(i * a + b);
    return k;
}

// A funded PQ output owned by `owner`, as both a spend input and the on-chain
// transaction that created it (a TX_PQ paying `owner`, from some other wallet).
struct Funded {
    Transaction tx;
    Crypto::Hash txid;
};

// Build a TX_PQ from `from` paying `amount` to `to`; returns the tx + txid.
Funded payTo(const PqWalletKeys& from, const PqWalletKeys& to, uint64_t inAmount,
             uint64_t payAmount, uint8_t seed) {
    // Give `from` a synthetic owned output to spend.
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

    Funded f;
    f.tx = buildPqTransaction({in}, {out}, from.spendPub, from.spendSk);
    f.txid = getObjectHash(f.tx);
    return f;
}

}  // namespace

TEST(PqWalletState, CreditsOwnedOutput) {
    PqWalletKeys me  = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    PqWalletState st(me);
    Funded f = payTo(them, me, 1000000, 800000, 0x10);

    EXPECT_TRUE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 800000u);
    EXPECT_EQ(st.unspentCount(), 1u);

    // Re-scanning the same tx is idempotent.
    EXPECT_FALSE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 800000u);
}

TEST(PqWalletState, IgnoresOutputsForOtherWallets) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys other = derivePqWalletKeys(spendSecret(2, 2));

    PqWalletState st(me);
    Funded f = payTo(them, other, 1000000, 800000, 0x22);  // pays `other`, not me
    EXPECT_FALSE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 0u);
}

TEST(PqWalletState, DetectsSpendOfOwnedOutput) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys dest = derivePqWalletKeys(spendSecret(4, 4));

    PqWalletState st(me);
    Funded recv = payTo(them, me, 1000000, 900000, 0x30);
    ASSERT_TRUE(st.processTransaction(recv.tx, recv.txid, 100));
    ASSERT_EQ(st.balance(), 900000u);

    // Now `me` spends that output to `dest`.
    std::vector<PqSpendInput> ins = st.spendableInputs();
    ASSERT_EQ(ins.size(), 1u);
    PqSendOutput pay{dest.viewPub, dest.spendPub, 850000};
    Transaction spend = buildPqTransaction(ins, {pay}, me.spendPub, me.spendSk);
    Crypto::Hash spendId = getObjectHash(spend);

    EXPECT_TRUE(st.processTransaction(spend, spendId, 105));
    EXPECT_EQ(st.balance(), 0u);          // the owned output is now spent
    EXPECT_EQ(st.unspentCount(), 0u);
}

TEST(PqWalletState, ReorgRestoresSpentAndDropsOrphanedOutputs) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys dest = derivePqWalletKeys(spendSecret(4, 4));

    PqWalletState st(me);
    Funded a = payTo(them, me, 1000000, 500000, 0x40);  // received at height 100
    Funded b = payTo(them, me, 1000000, 300000, 0x50);  // received at height 110
    ASSERT_TRUE(st.processTransaction(a.tx, a.txid, 100));
    ASSERT_TRUE(st.processTransaction(b.tx, b.txid, 110));
    EXPECT_EQ(st.balance(), 800000u);

    // Spend output `a` at height 112.
    std::vector<PqSpendInput> ins;
    for (const auto& o : st.outputs()) {
        if (o.amount == 500000) { ins.push_back(PqSpendInput{o.txid, o.outputIndex, o.amount, o.rho}); }
    }
    ASSERT_EQ(ins.size(), 1u);
    Transaction spend = buildPqTransaction(ins, {PqSendOutput{dest.viewPub, dest.spendPub, 450000}},
                                           me.spendPub, me.spendSk);
    ASSERT_TRUE(st.processTransaction(spend, getObjectHash(spend), 112));
    EXPECT_EQ(st.balance(), 300000u);  // only `b` left unspent

    // Reorg back to height 111: undoes the spend (seen at 112) and drops `b`
    // (received at 110 < 111 survives; received at >=111 dropped). `b` was at
    // 110 so it SURVIVES; the spend at 112 is undone -> `a` spendable again.
    st.rollbackToHeight(111);
    EXPECT_EQ(st.balance(), 800000u);
    EXPECT_EQ(st.unspentCount(), 2u);

    // Deeper reorg to 105 drops `b` (110) too, keeps `a` (100).
    st.rollbackToHeight(105);
    EXPECT_EQ(st.balance(), 500000u);
    EXPECT_EQ(st.unspentCount(), 1u);
}

TEST(PqWalletState, SpendableInputsCarryRho) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletState st(me);
    Funded f = payTo(them, me, 1000000, 700000, 0x60);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100));

    auto ins = st.spendableInputs();
    ASSERT_EQ(ins.size(), 1u);
    EXPECT_EQ(ins[0].amount, 700000u);
    // rho must be non-zero (it was recovered from the AEAD payload).
    bool nonZero = false;
    for (auto x : ins[0].rho) if (x) { nonZero = true; break; }
    EXPECT_TRUE(nonZero);
}

TEST(PqWalletState, RespectsPerOutputUnlockHeight) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    // `them` pays `me` 800000, with the output locked until height 1000.
    std::vector<CryptoPQ::InputRef> refs(1);
    for (auto& b : refs[0].prevTxid) b = 0xAB;
    refs[0].prevOutIndex = 1;
    CryptoPQ::Hash256 fih = CryptoPQ::inputsHash(refs);
    CryptoPQ::PqBuiltOutput src =
        CryptoPQ::buildPqOutput(them.viewPub, them.spendPub, fih, 0, 1000000);
    PqSpendInput in;
    for (std::size_t i = 0; i < 32; ++i) in.prevTxid.data[i] = static_cast<uint8_t>(0xAB + i);
    in.prevOutIndex = 0;
    in.amount = 1000000;
    in.rho = src.rho;
    PqSendOutput out{me.viewPub, me.spendPub, 800000};
    out.unlockHeight = 1000;
    Transaction tx = buildPqTransaction({in}, {out}, them.spendPub, them.spendSk);
    Crypto::Hash txid = getObjectHash(tx);

    PqWalletState st(me);
    ASSERT_TRUE(st.processTransaction(tx, txid, 100));
    ASSERT_EQ(st.outputs().size(), 1u);
    EXPECT_EQ(st.outputs()[0].unlockHeight, 1000u);  // per-output lock recovered on scan
    EXPECT_EQ(st.balance(), 800000u);                // owned regardless of lock

    // Tip below the unlock height: the wallet must NOT offer it (consensus would
    // reject the spend).
    st.setLastScannedHeight(999);
    EXPECT_TRUE(st.spendableInputs().empty());

    // Tip at/after the unlock height: now spendable.
    st.setLastScannedHeight(1000);
    ASSERT_EQ(st.spendableInputs().size(), 1u);
    EXPECT_EQ(st.spendableInputs()[0].amount, 800000u);
}

TEST(PqWalletState, SaveLoadRoundTrip) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys dest = derivePqWalletKeys(spendSecret(4, 4));

    PqWalletState st(me);
    Funded a = payTo(them, me, 1000000, 500000, 0x70);  // received @100
    Funded b = payTo(them, me, 1000000, 300000, 0x80);  // received @110
    ASSERT_TRUE(st.processTransaction(a.tx, a.txid, 100));
    ASSERT_TRUE(st.processTransaction(b.tx, b.txid, 110));

    // Spend output `a`.
    std::vector<PqSpendInput> ins;
    for (const auto& o : st.outputs())
        if (o.amount == 500000) ins.push_back(PqSpendInput{o.txid, o.outputIndex, o.amount, o.rho});
    Transaction spend = buildPqTransaction(ins, {PqSendOutput{dest.viewPub, dest.spendPub, 450000}},
                                           me.spendPub, me.spendSk);
    ASSERT_TRUE(st.processTransaction(spend, getObjectHash(spend), 112));
    st.setLastScannedHeight(120);
    ASSERT_EQ(st.balance(), 300000u);

    std::stringstream ss;
    st.save(ss);

    PqWalletState restored(me);
    restored.load(ss);

    EXPECT_EQ(restored.balance(), 300000u);
    EXPECT_EQ(restored.ownedCount(), 2u);
    EXPECT_EQ(restored.unspentCount(), 1u);
    EXPECT_EQ(restored.lastScannedHeight(), 120u);

    // The spend-tracking index survives: re-feeding the spend is idempotent and
    // the spent output stays spent.
    EXPECT_FALSE(restored.processTransaction(spend, getObjectHash(spend), 112));
    EXPECT_EQ(restored.balance(), 300000u);

    // And a fresh receive is still recognized after a reload.
    Funded c = payTo(them, me, 1000000, 200000, 0x90);
    EXPECT_TRUE(restored.processTransaction(c.tx, c.txid, 130));
    EXPECT_EQ(restored.balance(), 500000u);
}

TEST(PqWalletState, LoadGarbageYieldsEmpty) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletState st(me);
    std::stringstream ss;
    ss << "not a valid pq state blob";
    st.load(ss);
    EXPECT_EQ(st.balance(), 0u);
    EXPECT_EQ(st.ownedCount(), 0u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
