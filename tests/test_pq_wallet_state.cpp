// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Tests for WalletLedger: scanning raw transactions for owned PQ outputs,
// separate balance accounting, spend detection via nullifiers, and reorg
// rollback. Uses the real PQ builders to produce the transactions it scans.

#include "gtest/gtest.h"

#include "Wallet/WalletLedger.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/PqWallet.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/PqValidation.h"
#include "crypto_pq/PqAead.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqSeed.h"
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

// Pay `payAmount` to an explicit (viewPub, spendPub) at subaddress index T.
// Used to forge deposits: Spec-1 pays a deposit spend key at T=0; Spec-2 pays the
// wallet's own key at T=index.
Funded payToPub(const PqWalletKeys& from, const CryptoPQ::KemPublicKey& toViewPub,
                const CryptoPQ::DsaPublicKey& toSpendPub, uint64_t inAmount,
                uint64_t payAmount, uint8_t seed, uint64_t T) {
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

    PqSendOutput out{toViewPub, toSpendPub, payAmount};
    out.subaddrIndexT = T;

    Funded f;
    f.tx = buildPqTransaction({in}, {out}, from.spendPub, from.spendSk);
    f.txid = getObjectHash(f.tx);
    return f;
}

// Build the same SingleKeyIndex payment format emitted before outContext-v2:
// the legacy AEAD key derivation included T in outContext. Released senders
// through v0.9.4 can still create these outputs for any nonzero deposit T.
Funded payToPubLegacyV1(const PqWalletKeys& from, const CryptoPQ::KemPublicKey& toViewPub,
                        const CryptoPQ::DsaPublicKey& toSpendPub, uint64_t inAmount,
                        uint64_t payAmount, uint8_t seed, uint64_t T) {
    Funded f = payToPub(from, toViewPub, toSpendPub, inAmount, payAmount, seed, T);
    CryptoPQ::Hash256 ih = pqTransactionInputsHash(f.tx);

    auto encapsulation = CryptoPQ::kem_encaps(toViewPub);
    CryptoPQ::Rho rho{};
    for (std::size_t i = 0; i < rho.size(); ++i) {
        rho[i] = static_cast<uint8_t>(seed + i);
    }
    CryptoPQ::Hash256 oc = CryptoPQ::legacyOutContextV1(ih, encapsulation.first, 0, T);
    CryptoPQ::Hash256 aeadKey = CryptoPQ::deriveAeadKey(encapsulation.second, oc);
    CryptoPQ::AeadNonce nonce{};
    std::array<uint8_t, 40> aad{};
    std::memcpy(aad.data(), oc.data(), 32);
    for (int i = 0; i < 8; ++i) {
        aad[32 + i] = static_cast<uint8_t>((payAmount >> (8 * i)) & 0xFF);
    }
    std::array<uint8_t, 40> plaintext{};
    std::memcpy(plaintext.data(), rho.data(), 32);
    for (int i = 0; i < 8; ++i) {
        plaintext[32 + i] = static_cast<uint8_t>((T >> (8 * i)) & 0xFF);
    }

    PqOutput legacy;
    legacy.kemCt.assign(encapsulation.first.begin(), encapsulation.first.end());
    legacy.encPayload = CryptoPQ::aead_encrypt(
        aeadKey, nonce, aad.data(), aad.size(), plaintext.data(), plaintext.size());
    CryptoPQ::Hash256 commitment = CryptoPQ::spendCommit(toSpendPub, rho);
    std::memcpy(legacy.spendCommit.data, commitment.data(), commitment.size());
    f.tx.outputs[0].target = std::move(legacy);

    // Re-sign because the output is part of the TX_PQ signing digest. This
    // keeps the legacy fixture wire-valid, not just recognizable by the ledger.
    CryptoPQ::Hash256 digest = pqSigningDigest(f.tx, inAmount - payAmount);
    f.tx.pqSignatures[0] = CryptoPQ::dsa_sign(
        from.spendSk, digest.data(), digest.size());
    f.txid = getObjectHash(f.tx);
    return f;
}

}  // namespace

TEST(WalletLedger, CreditsOwnedOutput) {
    PqWalletKeys me  = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    Funded f = payTo(them, me, 1000000, 800000, 0x10);

    EXPECT_TRUE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 800000u);
    EXPECT_EQ(st.unspentCount(), 1u);

    // Re-scanning the same tx is idempotent.
    EXPECT_FALSE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 800000u);
}

TEST(WalletLedger, PoolThenConfirmPromotesOutputToConfirmed) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    Funded f = payTo(them, me, 1000000, 800000, 0x11);

    // First seen in the mempool: the output is pending, not yet confirmed.
    EXPECT_TRUE(st.processTransaction(f.tx, f.txid, WalletLedger::UNCONFIRMED_HEIGHT));
    EXPECT_EQ(st.balance(), 800000u);
    EXPECT_EQ(st.pendingBalance(), 800000u);

    // Its transaction is then mined: the same output must move from pending to
    // confirmed, otherwise received funds would never become available to spend.
    EXPECT_TRUE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 800000u);     // total unchanged
    EXPECT_EQ(st.pendingBalance(), 0u);   // no longer pending
    EXPECT_EQ(st.unspentCount(), 1u);     // exactly one output, not duplicated
}

TEST(WalletLedger, IgnoresOutputsForOtherWallets) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys other = derivePqWalletKeys(spendSecret(2, 2));

    WalletLedger st(me);
    Funded f = payTo(them, other, 1000000, 800000, 0x22);  // pays `other`, not me
    EXPECT_FALSE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 0u);
}

TEST(WalletLedger, DetectsSpendOfOwnedOutput) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys dest = derivePqWalletKeys(spendSecret(4, 4));

    WalletLedger st(me);
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

// A receive seen only in the mempool, then evicted (never mined), must be dropped.
TEST(WalletLedger, RemoveUnconfirmedDropsEvictedReceive) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    Funded f = payTo(them, me, 1000000, 800000, 0x12);

    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, WalletLedger::UNCONFIRMED_HEIGHT));
    ASSERT_EQ(st.pendingBalance(), 800000u);
    ASSERT_EQ(st.historyCount(), 1u);

    st.removeUnconfirmedTransaction(f.txid);
    EXPECT_EQ(st.balance(), 0u);
    EXPECT_EQ(st.pendingBalance(), 0u);
    EXPECT_EQ(st.unspentCount(), 0u);
    EXPECT_EQ(st.historyCount(), 0u);
}

// Our own send, seen unconfirmed (marks our input spent), then rejected/dropped:
// the input must return to the spendable set.
TEST(WalletLedger, RemoveUnconfirmedRestoresDroppedSendInputs) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys dest = derivePqWalletKeys(spendSecret(4, 4));

    WalletLedger st(me);
    Funded recv = payTo(them, me, 1000000, 900000, 0x31);
    ASSERT_TRUE(st.processTransaction(recv.tx, recv.txid, 100));
    ASSERT_EQ(st.balance(), 900000u);

    std::vector<PqSpendInput> ins = st.spendableInputs();
    ASSERT_EQ(ins.size(), 1u);
    PqSendOutput pay{dest.viewPub, dest.spendPub, 850000};
    Transaction spend = buildPqTransaction(ins, {pay}, me.spendPub, me.spendSk);
    Crypto::Hash spendId = getObjectHash(spend);

    ASSERT_TRUE(st.processTransaction(spend, spendId, WalletLedger::UNCONFIRMED_HEIGHT));
    ASSERT_EQ(st.balance(), 0u);                  // input now (unconfirmed) spent
    ASSERT_EQ(st.spendableInputs().size(), 0u);

    st.removeUnconfirmedTransaction(spendId);
    EXPECT_EQ(st.balance(), 900000u);             // input restored
    EXPECT_EQ(st.spendableInputs().size(), 1u);
}

// An output still in the mempool (received unconfirmed) is owned but NOT spendable:
// the network has no confirmed outpoint for it yet, so a tx spending it would be
// rejected at relay. It becomes spendable once its tx is mined. This is what makes
// rapid back-to-back sends fail cleanly (insufficient funds) instead of grabbing the
// previous send's unconfirmed change and bouncing off the daemon.
TEST(WalletLedger, UnconfirmedReceiveIsNotSpendableUntilMined) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    Funded recv = payTo(them, me, 1000000, 900000, 0x33);

    // Seen first in the mempool.
    ASSERT_TRUE(st.processTransaction(recv.tx, recv.txid, WalletLedger::UNCONFIRMED_HEIGHT));
    EXPECT_EQ(st.balance(), 900000u);          // owned...
    EXPECT_EQ(st.pendingBalance(), 900000u);   // ...but still pending (in the pool)
    EXPECT_EQ(st.spendableBalance(), 0u);      // not spendable yet
    EXPECT_TRUE(st.spendableInputs().empty());

    // Same tx mined: promotes to confirmed, now spendable.
    ASSERT_TRUE(st.processTransaction(recv.tx, recv.txid, 100));
    EXPECT_EQ(st.pendingBalance(), 0u);
    EXPECT_EQ(st.spendableBalance(), 900000u);
    ASSERT_EQ(st.spendableInputs().size(), 1u);
}

// A spend first seen in the pool then mined must record its real height, so a
// reorg ABOVE the spend does not wrongly un-spend it.
TEST(WalletLedger, ConfirmedSpendSurvivesReorgAboveIt) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys dest = derivePqWalletKeys(spendSecret(4, 4));

    WalletLedger st(me);
    Funded recv = payTo(them, me, 1000000, 900000, 0x32);
    ASSERT_TRUE(st.processTransaction(recv.tx, recv.txid, 100));

    std::vector<PqSpendInput> ins = st.spendableInputs();
    PqSendOutput pay{dest.viewPub, dest.spendPub, 850000};
    Transaction spend = buildPqTransaction(ins, {pay}, me.spendPub, me.spendSk);
    Crypto::Hash spendId = getObjectHash(spend);

    ASSERT_TRUE(st.processTransaction(spend, spendId, WalletLedger::UNCONFIRMED_HEIGHT));
    ASSERT_TRUE(st.processTransaction(spend, spendId, 105));  // mined
    ASSERT_EQ(st.balance(), 0u);

    st.rollbackToHeight(106);          // detach blocks above the spend
    EXPECT_EQ(st.balance(), 0u);       // spend at 105 must survive

    st.rollbackToHeight(105);          // detach the spend's own block
    EXPECT_EQ(st.balance(), 900000u);  // input restored
}

TEST(WalletLedger, ReorgRestoresSpentAndDropsOrphanedOutputs) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys dest = derivePqWalletKeys(spendSecret(4, 4));

    WalletLedger st(me);
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

// Finding A regression: an output is spent UNCONFIRMED by one tx, then a DIFFERENT
// tx (a fee-bumped/replacement spend, or a sibling process sharing the seed) spends
// the same output and is the one that gets MINED. Both carry the same nullifier but
// different txids. The confirmed spend must supersede the unconfirmed one, so a later
// pool-drop of the original does NOT restore an output that is already spent on-chain
// (which would inflate the balance and then build consensus-invalid transactions).
TEST(WalletLedger, ConfirmedReplacementSupersedesUnconfirmedSpend) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys dest = derivePqWalletKeys(spendSecret(4, 4));

    WalletLedger st(me);
    Funded recv = payTo(them, me, 1000000, 900000, 0x70);
    ASSERT_TRUE(st.processTransaction(recv.tx, recv.txid, 100));
    ASSERT_EQ(st.balance(), 900000u);

    std::vector<PqSpendInput> ins = st.spendableInputs();
    ASSERT_EQ(ins.size(), 1u);

    // Two distinct transactions spending the SAME owned output. Output kemCt/rho are
    // randomized per build, so the txids differ while the input nullifier is identical.
    Transaction spendA = buildPqTransaction(ins, {PqSendOutput{dest.viewPub, dest.spendPub, 850000}},
                                            me.spendPub, me.spendSk);
    Transaction spendB = buildPqTransaction(ins, {PqSendOutput{dest.viewPub, dest.spendPub, 840000}},
                                            me.spendPub, me.spendSk);
    Crypto::Hash idA = getObjectHash(spendA);
    Crypto::Hash idB = getObjectHash(spendB);
    ASSERT_NE(idA, idB);

    // spendA is seen first in the mempool (marks the owned output spent by A).
    ASSERT_TRUE(st.processTransaction(spendA, idA, WalletLedger::UNCONFIRMED_HEIGHT));
    ASSERT_EQ(st.balance(), 0u);

    // spendB is the replacement that actually gets MINED.
    ASSERT_TRUE(st.processTransaction(spendB, idB, 105));
    EXPECT_EQ(st.balance(), 0u);

    // spendA is dropped from the pool. The output stays spent (spent on-chain by B);
    // the balance must NOT be restored.
    st.removeUnconfirmedTransaction(idA);
    EXPECT_EQ(st.balance(), 0u);
    EXPECT_TRUE(st.spendableInputs().empty());

    // The confirmed spend (B at 105) survives a reorg above it, and is undone only
    // when its own block detaches.
    st.rollbackToHeight(106);
    EXPECT_EQ(st.balance(), 0u);
    st.rollbackToHeight(105);
    EXPECT_EQ(st.balance(), 900000u);
}

// Finding B regression: a reorg of CONFIRMED blocks must not clear a spend that is
// still only in the mempool. UNCONFIRMED_HEIGHT (0xFFFFFFFF) satisfies `>= h` for
// every h, so the rollback guard must explicitly exclude it — the mempool spend is
// unaffected by a reorg of mined blocks and is owned by removeUnconfirmedTransaction.
TEST(WalletLedger, ReorgLeavesUnconfirmedSpendInPlace) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys dest = derivePqWalletKeys(spendSecret(4, 4));

    WalletLedger st(me);
    Funded recv = payTo(them, me, 1000000, 900000, 0x71);
    ASSERT_TRUE(st.processTransaction(recv.tx, recv.txid, 100));

    std::vector<PqSpendInput> ins = st.spendableInputs();
    Transaction spend = buildPqTransaction(ins, {PqSendOutput{dest.viewPub, dest.spendPub, 850000}},
                                           me.spendPub, me.spendSk);
    Crypto::Hash spendId = getObjectHash(spend);

    // Spend seen only in the mempool.
    ASSERT_TRUE(st.processTransaction(spend, spendId, WalletLedger::UNCONFIRMED_HEIGHT));
    ASSERT_EQ(st.balance(), 0u);

    // A reorg detaching confirmed blocks must NOT un-spend the still-pending spend.
    st.rollbackToHeight(105);
    EXPECT_EQ(st.balance(), 0u);
    EXPECT_TRUE(st.spendableInputs().empty());

    // The pending spend is still owned by the mempool path, which can drop it.
    st.removeUnconfirmedTransaction(spendId);
    EXPECT_EQ(st.balance(), 900000u);
}

TEST(WalletLedger, SpendableInputsCarryRho) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    WalletLedger st(me);
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

TEST(WalletLedger, RespectsPerOutputUnlockHeight) {
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

    WalletLedger st(me);
    ASSERT_TRUE(st.processTransaction(tx, txid, 100));
    ASSERT_EQ(st.outputs().size(), 1u);
    EXPECT_EQ(st.outputs()[0].unlockHeight, 1000u);  // per-output lock recovered on scan
    EXPECT_EQ(st.balance(), 800000u);                // owned regardless of lock

    // Tip below the unlock height: the wallet must NOT offer it (consensus would
    // reject the spend).
    st.setLastScannedHeight(999);
    EXPECT_EQ(st.spendableBalance(), 0u);
    EXPECT_EQ(st.depositSpendableBalance(PQ_PRIMARY_DEPOSIT), 0u);
    EXPECT_TRUE(st.spendableInputs().empty());

    // Tip at/after the unlock height: now spendable.
    st.setLastScannedHeight(1000);
    EXPECT_EQ(st.spendableBalance(), 800000u);
    EXPECT_EQ(st.depositSpendableBalance(PQ_PRIMARY_DEPOSIT), 800000u);
    ASSERT_EQ(st.spendableInputs().size(), 1u);
    EXPECT_EQ(st.spendableInputs()[0].amount, 800000u);
}

TEST(WalletLedger, SaveLoadRoundTrip) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys dest = derivePqWalletKeys(spendSecret(4, 4));

    WalletLedger st(me);
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

    WalletLedger restored(me);
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

// --- Deposit-scan attribution ----------------------------------------------

TEST(WalletLedger, AggregatedMultikeyAttributesDeposit) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    st.setDepositConfig(PqDepositScheme::AggregatedMultikey, 3);  // 3 deposit keys

    // `them` pays deposit #2: shared view key + deposit spend key #2, at T=0.
    auto dep2 = CryptoPQ::deriveDepositSpendKeys(me.seedMaster, 2);
    Funded f = payToPub(them, me.viewPub, dep2.first, 1000000, 800000, 0xA0, 0);

    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 800000u);
    EXPECT_EQ(st.depositBalance(2), 800000u);
    EXPECT_EQ(st.depositBalance(0), 0u);
    auto bals = st.depositBalances();
    ASSERT_EQ(bals.size(), 1u);
    EXPECT_EQ(bals[2], 800000u);
    ASSERT_EQ(st.outputs().size(), 1u);
    EXPECT_EQ(st.outputs()[0].depositIndex, 2u);

    // A Spec-1 deposit output commits to its own deposit spend key. It IS spendable —
    // the spend path signs each input with the matching derived deposit key — so it is
    // offered for spending, tagged with its bucket so the right key can be selected.
    auto inputs = st.spendableInputs();
    ASSERT_EQ(inputs.size(), 1u);
    EXPECT_EQ(inputs[0].depositIndex, 2u);
    EXPECT_EQ(inputs[0].amount, 800000u);
}

TEST(WalletLedger, AggregatedMultikeyKeepsPrimaryAddressSpendable) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    st.setDepositConfig(PqDepositScheme::AggregatedMultikey, 2);

    // Pay the wallet's OWN primary address (not a deposit key).
    Funded f = payToPub(them, me.viewPub, me.spendPub, 1000000, 700000, 0xA8, 0);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 700000u);
    ASSERT_EQ(st.outputs().size(), 1u);
    EXPECT_EQ(st.outputs()[0].depositIndex, PQ_PRIMARY_DEPOSIT);
    EXPECT_TRUE(st.depositBalances().empty());     // not attributed to any deposit
    EXPECT_EQ(st.spendableInputs().size(), 1u);    // primary funds are spendable
}

TEST(WalletLedger, SingleKeyIndexAttributesDepositByT) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    st.setDepositConfig(PqDepositScheme::SingleKeyIndex, 3);

    // Same key pair, subaddress index T=2.
    Funded f = payToPub(them, me.viewPub, me.spendPub, 1000000, 750000, 0xB0, 2);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 750000u);
    EXPECT_EQ(st.depositBalance(2), 750000u);
    ASSERT_EQ(st.outputs().size(), 1u);
    EXPECT_EQ(st.outputs()[0].depositIndex, 2u);
    // Single key: every output, deposits included, is spendable by the one key.
    EXPECT_EQ(st.spendableInputs().size(), 1u);
}

TEST(WalletLedger, SingleKeyIndexAutomaticallyCreditsCurrentV2NonzeroT) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    st.setDepositConfig(PqDepositScheme::SingleKeyIndex, 45);

    Funded f = payToPub(them, me.viewPub, me.spendPub, 1000000, 50000, 0xB3, 44);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 50000u);
    EXPECT_EQ(st.depositBalance(44), 50000u);
    ASSERT_EQ(st.outputs().size(), 1u);
    EXPECT_EQ(st.outputs()[0].depositIndex, 44u);
}

TEST(WalletLedger, SingleKeyIndexAutomaticallyCreditsLegacyNonzeroT) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    // This is the next-index cursor, so [0, 45) includes the issued T=44.
    st.setDepositConfig(PqDepositScheme::SingleKeyIndex, 45);

    Funded f = payToPubLegacyV1(
        them, me.viewPub, me.spendPub, 1000000, 50000, 0xB4, 44);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 50000u);
    EXPECT_EQ(st.depositBalance(44), 50000u);
    ASSERT_EQ(st.outputs().size(), 1u);
    EXPECT_EQ(st.outputs()[0].depositIndex, 44u);
}

// T is 64 bits on the wire; the ledger's deposit buckets are 32. The SENDER
// picks T, so narrowing it with a cast would let a payer choose which of our
// deposits their payment is credited to — T = 2^32 + n would land on bucket n,
// and T = 0xFFFFFFFF would land on the primary-address sentinel. Out-of-range
// values must be recorded as unattributed instead, with the funds still owned.
TEST(WalletLedger, HugeRoutingIndexDoesNotAliasADepositBucket) {
    // The pure mapping, over the boundary cases.
    EXPECT_EQ(PQ_PRIMARY_DEPOSIT, pqDepositIndexForRoute(0));
    EXPECT_EQ(1u, pqDepositIndexForRoute(1));
    EXPECT_EQ(7u, pqDepositIndexForRoute(7));

    EXPECT_EQ(PQ_UNATTRIBUTED_DEPOSIT, pqDepositIndexForRoute(1ull << 32));
    EXPECT_NE(0u, pqDepositIndexForRoute(1ull << 32));

    EXPECT_EQ(PQ_UNATTRIBUTED_DEPOSIT, pqDepositIndexForRoute((1ull << 32) + 5));
    EXPECT_NE(5u, pqDepositIndexForRoute((1ull << 32) + 5));

    EXPECT_EQ(PQ_UNATTRIBUTED_DEPOSIT, pqDepositIndexForRoute(0xFFFFFFFFull));
    EXPECT_NE(PQ_PRIMARY_DEPOSIT, pqDepositIndexForRoute(0xFFFFFFFFull));

    EXPECT_EQ(PQ_UNATTRIBUTED_DEPOSIT, pqDepositIndexForRoute(0xFFFFFFFFFFFFFFFFull));

    // The last attributable index still maps to itself.
    EXPECT_EQ(static_cast<uint32_t>(PQ_MAX_DEPOSIT_ROUTE),
              pqDepositIndexForRoute(PQ_MAX_DEPOSIT_ROUTE));
}

TEST(WalletLedger, OutOfRangeRoutingIndexIsOwnedButUnattributed) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    st.setDepositConfig(PqDepositScheme::SingleKeyIndex, 8);

    // A payer aiming at deposit 3 by way of 2^32 + 3.
    Funded f = payToPub(them, me.viewPub, me.spendPub, 1000000, 750000, 0xB8,
                        (1ull << 32) + 3);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100));

    // The money is ours and spendable...
    EXPECT_EQ(750000u, st.balance());
    ASSERT_EQ(1u, st.outputs().size());
    EXPECT_EQ(1u, st.spendableInputs().size());

    // ...but it did not land in deposit 3, nor on the primary address.
    EXPECT_EQ(PQ_UNATTRIBUTED_DEPOSIT, st.outputs()[0].depositIndex);
    EXPECT_EQ(0u, st.depositBalance(3));
    EXPECT_EQ(0u, st.depositBalance(PQ_PRIMARY_DEPOSIT));
}

TEST(WalletLedger, RoutingIndexAtTheSentinelDoesNotBecomeThePrimaryAddress) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    st.setDepositConfig(PqDepositScheme::SingleKeyIndex, 8);

    Funded f = payToPub(them, me.viewPub, me.spendPub, 1000000, 750000, 0xB9,
                        0xFFFFFFFFull);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100));

    ASSERT_EQ(1u, st.outputs().size());
    EXPECT_EQ(PQ_UNATTRIBUTED_DEPOSIT, st.outputs()[0].depositIndex);
    EXPECT_EQ(0u, st.depositBalance(PQ_PRIMARY_DEPOSIT));
}

TEST(WalletLedger, SingleKeyIndexDoesNotCreditLegacyTOutsideIssuedWindow) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    // [0, 45) is issued; T=45 is deliberately just outside the cursor.
    st.setDepositConfig(PqDepositScheme::SingleKeyIndex, 45);

    Funded f = payToPubLegacyV1(
        them, me.viewPub, me.spendPub, 1000000, 50000, 0xB5, 45);
    EXPECT_FALSE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 0u);
    EXPECT_EQ(st.depositBalance(45), 0u);
    EXPECT_TRUE(st.outputs().empty());
}

TEST(WalletLedger, SingleKeyIndexManualWindowExtendsIssuedRange) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    st.setDepositConfig(PqDepositScheme::SingleKeyIndex, 45);
    st.setLegacyTWindowRescan(46);

    Funded f = payToPubLegacyV1(
        them, me.viewPub, me.spendPub, 1000000, 50000, 0xB6, 45);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 50000u);
    EXPECT_EQ(st.depositBalance(45), 50000u);
    ASSERT_EQ(st.outputs().size(), 1u);
    EXPECT_EQ(st.outputs()[0].depositIndex, 45u);
}

// T=0 is the primary address, not deposit #0. A plain Bech32m PQ address and a base
// H-I-A-C account number both send at T=0, so an output there can never be pinned to
// a deposit; SingleKeyIndex issuance starts at T=1 to keep that unambiguous.
TEST(WalletLedger, SingleKeyIndexTZeroIsPrimaryNotDepositZero) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    st.setDepositConfig(PqDepositScheme::SingleKeyIndex, 3);

    // An ordinary payment to the wallet's own primary address: same key pair, T=0.
    Funded f = payToPub(them, me.viewPub, me.spendPub, 1000000, 900000, 0xB8, 0);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100));
    EXPECT_EQ(st.balance(), 900000u);
    ASSERT_EQ(st.outputs().size(), 1u);
    EXPECT_EQ(st.outputs()[0].depositIndex, PQ_PRIMARY_DEPOSIT);
    EXPECT_EQ(st.depositBalance(0), 0u);          // deposit #0 does not exist here
    EXPECT_TRUE(st.depositBalances().empty());    // attributed to no deposit at all
    EXPECT_EQ(st.spendableInputs().size(), 1u);   // still the wallet's money

    auto byBucket = st.transfersByDeposit(f.txid);
    ASSERT_EQ(byBucket.size(), 1u);
    EXPECT_EQ(byBucket.begin()->first, PQ_PRIMARY_DEPOSIT);
}

// <=v0.9.6 (state blob v7) recorded SingleKeyIndex T=0 receipts in deposit bucket 0.
// Those are primary-address receipts; loading such a blob must move them off the
// deposit bucket, and must NOT touch AggregatedMultikey, where deposit 0 is real.
TEST(WalletLedger, LegacyBucketZeroMigratesToPrimaryOnlyForSingleKeyIndex) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    // Produce a blob holding one output in bucket 0, then stamp it as v7. The v7 and
    // v8 layouts are byte-identical — v8 only changes what bucket 0 MEANS — so the
    // version byte is the whole difference.
    auto dep0 = CryptoPQ::deriveDepositSpendKeys(me.seedMaster, 0);
    Funded f = payToPub(them, me.viewPub, dep0.first, 1000000, 500000, 0xB9, 0);
    WalletLedger legacy(me);
    legacy.setDepositConfig(PqDepositScheme::AggregatedMultikey, 1);
    ASSERT_TRUE(legacy.processTransaction(f.tx, f.txid, 100));
    ASSERT_EQ(legacy.outputs()[0].depositIndex, 0u);

    std::stringstream saved;
    legacy.save(saved);
    std::string blob = saved.str();
    ASSERT_FALSE(blob.empty());
    blob[0] = 7;  // pretend it was written by v0.9.6

    {
        WalletLedger migrated(me);
        std::stringstream in(blob);
        migrated.load(in);
        // Scheme arrives only after load (WalletGreen parses it from a later section).
        migrated.setDepositConfig(PqDepositScheme::SingleKeyIndex, 1);
        ASSERT_EQ(migrated.outputs().size(), 1u);
        EXPECT_EQ(migrated.outputs()[0].depositIndex, PQ_PRIMARY_DEPOSIT);
        EXPECT_EQ(migrated.depositBalance(0), 0u);
    }
    {
        WalletLedger kept(me);
        std::stringstream in(blob);
        kept.load(in);
        kept.setDepositConfig(PqDepositScheme::AggregatedMultikey, 1);
        ASSERT_EQ(kept.outputs().size(), 1u);
        EXPECT_EQ(kept.outputs()[0].depositIndex, 0u);  // a genuine deposit key
        EXPECT_EQ(kept.depositBalance(0), 500000u);
    }
}

TEST(WalletLedger, DepositIndexSurvivesSaveLoad) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));

    WalletLedger st(me);
    st.setDepositConfig(PqDepositScheme::SingleKeyIndex, 3);
    Funded f = payToPub(them, me.viewPub, me.spendPub, 1000000, 600000, 0xC0, 1);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100));
    ASSERT_EQ(st.depositBalance(1), 600000u);

    std::stringstream ss;
    st.save(ss);

    WalletLedger restored(me);
    restored.setDepositConfig(PqDepositScheme::SingleKeyIndex, 3);
    restored.load(ss);
    EXPECT_EQ(restored.depositBalance(1), 600000u);
    ASSERT_EQ(restored.outputs().size(), 1u);
    EXPECT_EQ(restored.outputs()[0].depositIndex, 1u);
}

// --- Transaction history (Phase B) -----------------------------------------

TEST(WalletLedger, HistoryRecordsIncoming) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    WalletLedger st(me);

    Funded f = payTo(them, me, 1000000, 800000, 0xD0);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100, 1700000000ull));
    ASSERT_EQ(st.historyCount(), 1u);
    const auto& h = st.history()[0];
    EXPECT_EQ(h.txid, f.txid);
    EXPECT_FALSE(h.outgoing);
    EXPECT_EQ(h.netAmount, 800000);     // received
    EXPECT_EQ(h.fee, 0u);               // counterparty's fee is not ours
    EXPECT_EQ(h.height, 100u);
    EXPECT_EQ(h.timestamp, 1700000000ull);

    // Idempotent re-scan does not add a second row.
    EXPECT_FALSE(st.processTransaction(f.tx, f.txid, 100, 1700000000ull));
    EXPECT_EQ(st.historyCount(), 1u);
}

TEST(WalletLedger, HistoryRecordsOutgoingWithFeeAndChange) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys dest = derivePqWalletKeys(spendSecret(4, 4));
    WalletLedger st(me);

    Funded recv = payTo(them, me, 1000000, 1000000, 0xD1);
    ASSERT_TRUE(st.processTransaction(recv.tx, recv.txid, 100, 111));

    // Spend 300000 to dest with 690000 change back to me (fee 10000).
    std::vector<PqSpendInput> ins = st.spendableInputs();
    ASSERT_EQ(ins.size(), 1u);
    Transaction spend = buildPqTransaction(
        ins, {PqSendOutput{dest.viewPub, dest.spendPub, 300000}, PqSendOutput{me.viewPub, me.spendPub, 690000}},
        me.spendPub, me.spendSk);
    Crypto::Hash spendId = getObjectHash(spend);
    ASSERT_TRUE(st.processTransaction(spend, spendId, 105, 222));

    ASSERT_EQ(st.historyCount(), 2u);
    const auto* h = st.historyByTxid(spendId);
    ASSERT_NE(h, nullptr);
    EXPECT_TRUE(h->outgoing);
    EXPECT_EQ(h->fee, 10000u);             // 1,000,000 in - 990,000 out
    EXPECT_EQ(h->netAmount, -310000);      // -(300,000 sent + 10,000 fee); change returns
    EXPECT_EQ(st.balance(), 690000u);      // only the change remains unspent
}

TEST(WalletLedger, HistoryUpsertsPoolThenConfirm) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    WalletLedger st(me);

    Funded f = payTo(them, me, 1000000, 500000, 0xD2);
    // Seen in the mempool first.
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, WalletLedger::UNCONFIRMED_HEIGHT, 0));
    ASSERT_EQ(st.historyCount(), 1u);
    EXPECT_EQ(st.history()[0].height, WalletLedger::UNCONFIRMED_HEIGHT);

    // Then confirmed: the same row is updated, not duplicated.
    EXPECT_TRUE(st.processTransaction(f.tx, f.txid, 120, 333));
    ASSERT_EQ(st.historyCount(), 1u);
    EXPECT_EQ(st.history()[0].height, 120u);
    EXPECT_EQ(st.history()[0].timestamp, 333u);
}

TEST(WalletLedger, HistoryReorgDropsOrphanedRows) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    WalletLedger st(me);

    Funded a = payTo(them, me, 1000000, 500000, 0xD3);  // height 100
    Funded b = payTo(them, me, 1000000, 300000, 0xD4);  // height 110
    ASSERT_TRUE(st.processTransaction(a.tx, a.txid, 100, 1));
    ASSERT_TRUE(st.processTransaction(b.tx, b.txid, 110, 2));
    ASSERT_EQ(st.historyCount(), 2u);

    st.rollbackToHeight(105);  // drops the height-110 tx, keeps height-100
    ASSERT_EQ(st.historyCount(), 1u);
    EXPECT_EQ(st.history()[0].txid, a.txid);
    EXPECT_EQ(st.historyByTxid(b.txid), nullptr);
}

TEST(WalletLedger, HistorySurvivesSaveLoad) {
    PqWalletKeys me   = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys them = derivePqWalletKeys(spendSecret(7, 3));
    WalletLedger st(me);

    Funded f = payTo(them, me, 1000000, 700000, 0xD5);
    ASSERT_TRUE(st.processTransaction(f.tx, f.txid, 100, 444));

    std::stringstream ss;
    st.save(ss);
    WalletLedger restored(me);
    restored.load(ss);

    ASSERT_EQ(restored.historyCount(), 1u);
    const auto& h = restored.history()[0];
    EXPECT_EQ(h.txid, f.txid);
    EXPECT_FALSE(h.outgoing);
    EXPECT_FALSE(h.coinbase);  // a received transfer is not a mined output
    EXPECT_EQ(h.netAmount, 700000);
    EXPECT_EQ(h.height, 100u);
    EXPECT_EQ(h.timestamp, 444u);
}

TEST(WalletLedger, LoadGarbageYieldsEmpty) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    WalletLedger st(me);
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
