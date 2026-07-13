// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Tests for the high-level TX_PQ builder (src/Wallet/PqTransactionBuilder).
// A transaction built here must satisfy the SAME consensus checks the node runs
// (checkPqTransactionSemantic + checkPqTransactionInputs), including ML-DSA
// signature verification and the spend_commit / fee accounting.

#include "gtest/gtest.h"

#include "Wallet/PqTransactionBuilder.h"
#include "Wallet/PqWallet.h"
#include "CryptoNoteCore/PqValidation.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqSeed.h"   // deriveDepositSpendKeys
#include "crypto/crypto.h"
#include "CryptoNote.h"
#include "PqTxType.h"
#include "CryptoNoteConfig.h"

#include <cstring>
#include <vector>

using namespace CryptoNote;

namespace {

Crypto::SecretKey spendSecret(uint8_t a, uint8_t b) {
    Crypto::SecretKey k;
    for (std::size_t i = 0; i < sizeof(k.data); ++i)
        k.data[i] = static_cast<uint8_t>(i * a + b);
    return k;
}

// Fund an identity: build a PqOutput TO it and return the spend input that
// references that (pretend on-chain) output plus the resolved view the node
// would reconstruct. prevTxid/prevOutIndex are arbitrary stand-ins.
PqSpendInput fund(const PqWalletKeys& owner, uint64_t amount, uint8_t txidSeed,
                  uint32_t outIndex, PqResolvedInput& resolvedOut) {
    // The funding tx's own inputsHash is irrelevant to the spender; only the
    // output's rho + spend_commit matter for the later spend.
    std::vector<CryptoPQ::InputRef> fakeRefs(1);
    for (auto& b : fakeRefs[0].prevTxid) b = txidSeed;
    fakeRefs[0].prevOutIndex = 7;
    CryptoPQ::Hash256 fih = CryptoPQ::inputsHash(fakeRefs);

    CryptoPQ::PqBuiltOutput built =
        CryptoPQ::buildPqOutput(owner.viewPub, owner.spendPub, fih, outIndex, amount);

    PqSpendInput si;
    for (std::size_t i = 0; i < 32; ++i) si.prevTxid.data[i] = static_cast<uint8_t>(txidSeed + i);
    si.prevOutIndex = outIndex;
    si.amount = amount;
    si.rho = built.rho;

    resolvedOut = PqResolvedInput{};
    std::memcpy(resolvedOut.spendCommit.data, built.spendCommit.data(), 32);
    resolvedOut.amount = amount;
    resolvedOut.exists = true;
    resolvedOut.isPqOutput = true;
    resolvedOut.isCoinbase = false;
    return si;
}

}  // namespace

TEST(PqTxBuilder, FundedSpendPassesConsensus) {
    PqWalletKeys sender = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys recip  = derivePqWalletKeys(spendSecret(9, 1));

    PqResolvedInput resolved;
    PqSpendInput in = fund(sender, 1000000, 0x11, 0, resolved);

    PqSendOutput out;
    out.recipientViewPub = recip.viewPub;
    out.recipientSpendPub = recip.spendPub;
    out.amount = 900000;  // leaves a 100000 fee

    Transaction tx = buildPqTransaction({in}, {out}, sender.spendPub, sender.spendSk);

    EXPECT_EQ(tx.version, TRANSACTION_VERSION_1);
    EXPECT_EQ(tx.txType, TX_PQ);
    EXPECT_EQ(tx.pqSignatures.size(), 1u);

    std::string err;
    ASSERT_TRUE(checkPqTransactionSemantic(tx, &err)) << err;

    std::vector<Crypto::Hash> nullifiers;
    ASSERT_TRUE(checkPqTransactionInputs(tx, {resolved}, /*minFeePerByte*/0, &nullifiers, &err)) << err;
    EXPECT_EQ(nullifiers.size(), 1u);
}

TEST(PqTxBuilder, MultiInputMultiOutput) {
    PqWalletKeys sender = derivePqWalletKeys(spendSecret(4, 8));
    PqWalletKeys r1 = derivePqWalletKeys(spendSecret(2, 2));
    PqWalletKeys r2 = derivePqWalletKeys(spendSecret(3, 3));

    PqResolvedInput res0, res1;
    PqSpendInput in0 = fund(sender, 500000, 0x20, 0, res0);
    PqSpendInput in1 = fund(sender, 700000, 0x40, 1, res1);

    PqSendOutput o0{r1.viewPub, r1.spendPub, 400000};
    PqSendOutput o1{r2.viewPub, r2.spendPub, 750000};  // sum out 1,150,000; in 1,200,000 -> fee 50,000

    Transaction tx = buildPqTransaction({in0, in1}, {o0, o1}, sender.spendPub, sender.spendSk);

    std::string err;
    ASSERT_TRUE(checkPqTransactionSemantic(tx, &err)) << err;
    std::vector<Crypto::Hash> nf;
    ASSERT_TRUE(checkPqTransactionInputs(tx, {res0, res1}, 0, &nf, &err)) << err;
    EXPECT_EQ(nf.size(), 2u);
    EXPECT_NE(0, std::memcmp(nf[0].data, nf[1].data, 32));  // distinct outputs -> distinct nullifiers
}

TEST(PqTxBuilder, PerInputDepositKeysPassConsensus) {
    // AggregatedMultikey: a deposit output commits to a per-deposit spend key, while a
    // primary output commits to the primary key. A single TX_PQ spends BOTH, signing
    // each input with its own key (the per-input authority overload).
    PqWalletKeys base = derivePqWalletKeys(spendSecret(7, 3));   // primary identity
    PqWalletKeys recip = derivePqWalletKeys(spendSecret(9, 1));

    // Deposit identity (index 2) = shared view key + derived per-deposit spend key.
    auto dep = CryptoPQ::deriveDepositSpendKeys(base.seedMaster, 2);
    PqWalletKeys depKeys = base;
    depKeys.spendPub = dep.first;
    depKeys.spendSk = dep.second;

    PqResolvedInput resPrimary, resDeposit;
    PqSpendInput inPrimary = fund(base, 500000, 0x20, 0, resPrimary);
    inPrimary.depositIndex = PQ_PRIMARY_DEPOSIT;
    PqSpendInput inDeposit = fund(depKeys, 700000, 0x40, 1, resDeposit);
    inDeposit.depositIndex = 2;

    PqSendOutput out{recip.viewPub, recip.spendPub, 1100000};  // in 1,200,000 -> fee 100,000

    std::vector<PqInputAuth> auth(2);
    auth[0].spendPub = base.spendPub; auth[0].spendSk = base.spendSk;     // primary input
    auth[1].spendPub = dep.first;     auth[1].spendSk = dep.second;       // deposit input

    Transaction tx = buildPqTransaction({inPrimary, inDeposit}, {out}, auth);
    ASSERT_EQ(tx.pqSignatures.size(), 2u);

    std::string err;
    ASSERT_TRUE(checkPqTransactionSemantic(tx, &err)) << err;
    std::vector<Crypto::Hash> nf;
    ASSERT_TRUE(checkPqTransactionInputs(tx, {resPrimary, resDeposit}, 0, &nf, &err)) << err;
    EXPECT_EQ(nf.size(), 2u);

    // Sanity: signing BOTH with the primary key (the old single-key path) must fail —
    // the deposit input's spend_commit won't match the primary pubkey.
    Transaction wrong = buildPqTransaction({inPrimary, inDeposit}, {out}, base.spendPub, base.spendSk);
    std::vector<Crypto::Hash> nf2;
    EXPECT_FALSE(checkPqTransactionInputs(wrong, {resPrimary, resDeposit}, 0, &nf2, &err));
}

TEST(PqTxBuilder, RecipientCanScanTheOutput) {
    // The receiver must recognize the output the builder created for them.
    PqWalletKeys sender = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys recip  = derivePqWalletKeys(spendSecret(9, 1));

    PqResolvedInput resolved;
    PqSpendInput in = fund(sender, 1000000, 0x11, 0, resolved);
    PqSendOutput out{recip.viewPub, recip.spendPub, 900000};

    Transaction tx = buildPqTransaction({in}, {out}, sender.spendPub, sender.spendSk);

    // Recompute the tx's inputsHash (same the builder used) for scanning.
    std::vector<CryptoPQ::InputRef> refs(tx.inputs.size());
    for (std::size_t i = 0; i < tx.inputs.size(); ++i) {
        const PqInput& pin = boost::get<PqInput>(tx.inputs[i]);
        std::memcpy(refs[i].prevTxid.data(), pin.prevTxid.data, 32);
        refs[i].prevOutIndex = pin.prevOutIndex;
    }
    CryptoPQ::Hash256 ih = CryptoPQ::inputsHash(refs);

    const PqOutput& po = boost::get<PqOutput>(tx.outputs[0].target);
    CryptoPQ::PqScanOutput so;
    so.outputIndex = 0;
    so.amount = tx.outputs[0].amount;
    std::memcpy(so.kemCt.data(), po.kemCt.data(), so.kemCt.size());
    so.encPayload = po.encPayload;
    std::memcpy(so.spendCommit.data(), po.spendCommit.data, 32);

    auto owned = CryptoPQ::scanPqOutput(pqScanKeys(recip), ih, so);
    ASSERT_TRUE(owned.has_value());
    EXPECT_EQ(owned->amount, 900000u);

    // The sender (wrong identity) must NOT recognize it.
    EXPECT_FALSE(CryptoPQ::scanPqOutput(pqScanKeys(sender), ih, so).has_value());
}

TEST(PqTxBuilder, ProofBuildOwnsOneMatchingRhoPerOutput) {
    PqWalletKeys sender = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys r1 = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys r2 = derivePqWalletKeys(spendSecret(5, 4));
    PqResolvedInput resolved;
    PqSpendInput in = fund(sender, 1000000, 0x51, 0, resolved);
    std::vector<PqSendOutput> outputs = {
        {r1.viewPub, r1.spendPub, 400000},
        {r2.viewPub, r2.spendPub, 500000}};

    PqTransactionBuildResult built = buildPqTransactionWithProof(
        {in}, outputs, sender.spendPub, sender.spendSk);
    ASSERT_EQ(built.outputRhos.size(), built.tx.outputs.size());
    ASSERT_EQ(built.outputRhos.size(), 2u);
    PqPaymentProofTransaction proofTx = makePqPaymentProofTransaction(built.tx);
    CryptoPQ::Hash256 genesis{};
    genesis[0] = 0x99;
    for (std::size_t i = 0; i < outputs.size(); ++i) {
        ResolvedRecipient recipient{
            outputs[i].recipientViewPub,
            outputs[i].recipientSpendPub,
            outputs[i].subaddrIndexT};
        PqPaymentProof proof = makePqPaymentProof(
            genesis, proofTx.txid, recipient,
            {{static_cast<uint32_t>(i), built.outputRhos[i]}});
        EXPECT_EQ(verifyPqPaymentProof(proof, genesis, proofTx, recipient),
                  outputs[i].amount);
    }
}

TEST(PqTxBuilder, TamperedSignatureRejected) {
    PqWalletKeys sender = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys recip  = derivePqWalletKeys(spendSecret(9, 1));
    PqResolvedInput resolved;
    PqSpendInput in = fund(sender, 1000000, 0x11, 0, resolved);
    PqSendOutput out{recip.viewPub, recip.spendPub, 900000};

    Transaction tx = buildPqTransaction({in}, {out}, sender.spendPub, sender.spendSk);
    tx.pqSignatures[0][0] ^= 0xFF;

    std::string err;
    std::vector<Crypto::Hash> nf;
    EXPECT_FALSE(checkPqTransactionInputs(tx, {resolved}, 0, &nf, &err));
}

TEST(PqTxBuilder, WrongSpenderFailsSpendCommit) {
    // A different wallet's spend key cannot spend the output: spend_commit won't
    // match (and the signature wouldn't verify either).
    PqWalletKeys owner   = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys thief   = derivePqWalletKeys(spendSecret(1, 1));
    PqWalletKeys recip   = derivePqWalletKeys(spendSecret(9, 1));

    PqResolvedInput resolved;
    PqSpendInput in = fund(owner, 1000000, 0x11, 0, resolved);  // owned by `owner`
    PqSendOutput out{recip.viewPub, recip.spendPub, 900000};

    // Thief signs with their own key/pub.
    Transaction tx = buildPqTransaction({in}, {out}, thief.spendPub, thief.spendSk);

    std::string err;
    std::vector<Crypto::Hash> nf;
    EXPECT_FALSE(checkPqTransactionInputs(tx, {resolved}, 0, &nf, &err));
}

TEST(PqTxBuilder, RejectsOverspend) {
    PqWalletKeys sender = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys recip  = derivePqWalletKeys(spendSecret(9, 1));
    PqResolvedInput resolved;
    PqSpendInput in = fund(sender, 100000, 0x11, 0, resolved);
    PqSendOutput out{recip.viewPub, recip.spendPub, 200000};  // exceeds input

    EXPECT_THROW(buildPqTransaction({in}, {out}, sender.spendPub, sender.spendSk),
                 std::runtime_error);
}

TEST(PqTxBuilder, RejectsTxLevelUnlockHeight) {
    PqWalletKeys sender = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys recip  = derivePqWalletKeys(spendSecret(9, 1));
    PqResolvedInput resolved;
    PqSpendInput in = fund(sender, 1000000, 0x12, 0, resolved);
    PqSendOutput out{recip.viewPub, recip.spendPub, 900000};

    EXPECT_THROW(buildPqTransaction({in}, {out}, sender.spendPub, sender.spendSk, 5),
                 std::runtime_error);
}

// --- TX_FREE_REG (zero-fee account registration) ---------------------------

TEST(PqFreeReg, BuildsValidRegistration) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(5, 5));
    Crypto::Hash ref;
    for (int i = 0; i < 32; ++i) ref.data[i] = static_cast<uint8_t>(i + 1);

    // Grind the anti-spam PoW via the shared helper (the same one simplewallet
    // and walletd call). Use a lenient test target so grinding stays instant —
    // the production parameters::FREE_REG_POW_TARGET is deliberately strong.
    constexpr uint64_t kTestFreeRegPowTarget = UINT64_C(0x0FFFFFFFFFFFFFFF);
    uint64_t nonce = CryptoNote::grindFreeRegPow(me.viewPub, me.spendPub, ref,
                                                 kTestFreeRegPowTarget);
    // The helper must return a nonce that actually satisfies the predicate.
    EXPECT_TRUE(CryptoNote::checkFreeRegPow(me.viewPub, me.spendPub, ref, nonce,
                                            kTestFreeRegPowTarget));

    Transaction tx = buildFreeRegTransaction(me.viewPub, me.spendPub, ref, nonce);
    EXPECT_EQ(tx.version, TRANSACTION_VERSION_1);
    EXPECT_EQ(tx.txType, TX_FREE_REG);
    EXPECT_TRUE(tx.inputs.empty());
    EXPECT_TRUE(tx.outputs.empty());
    EXPECT_TRUE(tx.pqSignatures.empty());

    std::string err;
    EXPECT_TRUE(checkFreeRegTransactionSemantic(tx, &err, kTestFreeRegPowTarget)) << err;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
