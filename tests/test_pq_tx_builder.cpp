// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
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
#include <limits>
#include <new>
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

TEST(PqTxBuilder, InputAuthScrubsSecretOnDestroy) {
    alignas(PqInputAuth) unsigned char storage[sizeof(PqInputAuth)];
    auto* auth = new (storage) PqInputAuth;
    auth->spendSk.fill(0xA5);
    const std::size_t secretOffset =
        reinterpret_cast<unsigned char*>(auth->spendSk.data()) - storage;
    const std::size_t secretSize = auth->spendSk.size();

    auth->~PqInputAuth();

    for (std::size_t i = 0; i < secretSize; ++i) {
        EXPECT_EQ(storage[secretOffset + i], 0);
    }
}

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


namespace {

CryptoPQ::SeedMaster seedBytes(uint8_t a, uint8_t b) {
    CryptoPQ::SeedMaster out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(i * a + b);
    }
    return out;
}

CryptoPQ::Rho rhoBytes(uint8_t a, uint8_t b) {
    CryptoPQ::Rho out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(i * a + b);
    }
    return out;
}

}  // namespace

// --- Version-2 signing transcript ------------------------------------------
//
// Transcript v1 has two properties a signature ought not to have.
//
// It says nothing about which chain the transaction belongs to. The outpoints it
// names are just (txid, index), so a signature made for one network verifies on
// another that happens to hold the same live outpoint.
//
// And it gives every input the same digest, so two inputs spending under one key
// carry interchangeable signatures. Swapping them leaves the transaction valid
// but changes its id, which lets a third party mutate an unconfirmed payment's
// identity without touching what it pays.
//
// v2 folds the chain identity and the input's index into the message. These
// tests pin both halves, and pin that v1 still behaves exactly as it did (it is
// what consensus requires until the change is activated).

namespace {

CryptoPQ::Hash256 chainIdOf(const char* label) {
    return CryptoPQ::sha3_256(label, std::strlen(label));
}

// A transaction spending TWO outputs owned by the SAME key -- the shape in which
// v1's shared digest makes the two signatures interchangeable.
struct TwoInputTx {
    Transaction tx;
    std::vector<PqResolvedInput> resolved;
};

TwoInputTx makeTwoInputTx(const PqSigningContext& signing) {
    CryptoPQ::SeedMaster ms = seedBytes(5, 11);
    auto spend = CryptoPQ::deriveSpendKeys(ms);
    auto recipV = CryptoPQ::deriveViewKeys(seedBytes(6, 12));
    auto recipS = CryptoPQ::deriveSpendKeys(seedBytes(6, 12));

    std::vector<PqSpendInput> inputs(2);
    std::vector<PqResolvedInput> resolved(2);
    for (size_t i = 0; i < 2; ++i) {
        for (size_t j = 0; j < 32; ++j) {
            inputs[i].prevTxid.data[j] = static_cast<uint8_t>(j + i * 17 + 3);
        }
        inputs[i].prevOutIndex = static_cast<uint32_t>(i);
        inputs[i].amount = 500000;
        inputs[i].rho = rhoBytes(static_cast<uint8_t>(7 + i), 13);

        CryptoPQ::Hash256 sc = CryptoPQ::spendCommit(spend.first, inputs[i].rho);
        resolved[i].exists = true;
        resolved[i].isPqOutput = true;
        resolved[i].amount = 500000;
        std::memcpy(resolved[i].spendCommit.data, sc.data(), 32);
    }

    PqSendOutput out{recipV.first, recipS.first, 900000};

    TwoInputTx result;
    result.tx = buildPqTransaction(inputs, {out}, spend.first, spend.second,
                                   /*unlockHeight=*/0, /*extra=*/{}, signing);
    result.resolved = resolved;
    return result;
}

}  // namespace

TEST(PqTranscriptV2, DigestBindsTheInputIndex) {
    CryptoPQ::UnsignedTx u;
    u.inputs.resize(2);
    u.fee = 7;
    const CryptoPQ::Hash256 chain = chainIdOf("chain");

    EXPECT_NE(CryptoPQ::txSigningDigestV2(u, chain, 0),
              CryptoPQ::txSigningDigestV2(u, chain, 1));
}

TEST(PqTranscriptV2, DigestBindsTheChain) {
    CryptoPQ::UnsignedTx u;
    u.inputs.resize(1);
    u.fee = 7;

    EXPECT_NE(CryptoPQ::txSigningDigestV2(u, chainIdOf("mainnet"), 0),
              CryptoPQ::txSigningDigestV2(u, chainIdOf("testnet"), 0));
}

TEST(PqTranscriptV2, DigestIsDomainSeparatedFromV1) {
    CryptoPQ::UnsignedTx u;
    u.inputs.resize(1);
    u.fee = 7;

    // Even with a zero chain id and input index 0, v2 must not collide with v1.
    CryptoPQ::Hash256 zeroChain{};
    EXPECT_NE(CryptoPQ::txSigningDigest(u),
              CryptoPQ::txSigningDigestV2(u, zeroChain, 0));
}

TEST(PqTranscriptV2, SignaturesDoNotCarryToAnotherNetwork) {
    // The concrete replay: the same transaction, judged on two chains. Under v2
    // the signature made for one chain must fail on the other.
    PqSigningContext mainnet;
    mainnet.useV2 = true;
    mainnet.chainId = chainIdOf("mainnet genesis");

    PqSigningContext testnet;
    testnet.useV2 = true;
    testnet.chainId = chainIdOf("testnet genesis");

    TwoInputTx built = makeTwoInputTx(mainnet);

    std::vector<Crypto::Hash> nf;
    std::string err;
    ASSERT_TRUE(checkPqTransactionInputs(built.tx, built.resolved, 0, &nf, &err, mainnet)) << err;

    nf.clear();
    EXPECT_FALSE(checkPqTransactionInputs(built.tx, built.resolved, 0, &nf, &err, testnet))
        << "a signature made for one chain verified on another";
}

TEST(PqTranscriptV2, SameKeySignaturesCannotBePermuted) {
    PqSigningContext signing;
    signing.useV2 = true;
    signing.chainId = chainIdOf("chain");

    TwoInputTx built = makeTwoInputTx(signing);
    ASSERT_EQ(2u, built.tx.pqSignatures.size());

    std::vector<Crypto::Hash> nf;
    std::string err;
    ASSERT_TRUE(checkPqTransactionInputs(built.tx, built.resolved, 0, &nf, &err, signing)) << err;

    // Both inputs are authorized by the same key, so under v1 the signatures are
    // interchangeable. Under v2 each is bound to its position.
    Transaction permuted = built.tx;
    std::swap(permuted.pqSignatures[0], permuted.pqSignatures[1]);
    EXPECT_NE(getObjectHash(built.tx), getObjectHash(permuted));

    nf.clear();
    EXPECT_FALSE(checkPqTransactionInputs(permuted, built.resolved, 0, &nf, &err, signing))
        << "signatures over the same key were still interchangeable";
}

TEST(PqTranscriptV2, VersionOneStillAcceptsWhatItAlwaysDid) {
    // The activation is not scheduled, so the v1 rules are what consensus applies
    // today -- including the permutation it accepts. Pinning it here makes the
    // change of behaviour at activation explicit rather than incidental.
    PqSigningContext v1;  // useV2 == false
    TwoInputTx built = makeTwoInputTx(v1);

    std::vector<Crypto::Hash> nf;
    std::string err;
    ASSERT_TRUE(checkPqTransactionInputs(built.tx, built.resolved, 0, &nf, &err, v1)) << err;

    Transaction permuted = built.tx;
    std::swap(permuted.pqSignatures[0], permuted.pqSignatures[1]);
    nf.clear();
    EXPECT_TRUE(checkPqTransactionInputs(permuted, built.resolved, 0, &nf, &err, v1))
        << "v1 behaviour changed; that is a consensus change and must be deliberate";
}

TEST(PqTranscriptV2, ATransactionSignedUnderOneVersionFailsUnderTheOther) {
    PqSigningContext v2;
    v2.useV2 = true;
    v2.chainId = chainIdOf("chain");
    PqSigningContext v1;

    std::vector<Crypto::Hash> nf;
    std::string err;

    TwoInputTx underV2 = makeTwoInputTx(v2);
    EXPECT_FALSE(checkPqTransactionInputs(underV2.tx, underV2.resolved, 0, &nf, &err, v1));

    nf.clear();
    TwoInputTx underV1 = makeTwoInputTx(v1);
    EXPECT_FALSE(checkPqTransactionInputs(underV1.tx, underV1.resolved, 0, &nf, &err, v2));
}

TEST(PqTranscriptV2, ActivationIsNotScheduled) {
    // Setting a real height is a hard fork. Until one is chosen deliberately, no
    // height reaches activation and every node keeps applying the v1 rules.
    EXPECT_EQ(std::numeric_limits<uint32_t>::max(), parameters::PQ_TRANSCRIPT_V2_HEIGHT);

    Crypto::Hash genesis{};
    EXPECT_FALSE(pqSigningContextForHeight(0, genesis).useV2);
    EXPECT_FALSE(pqSigningContextForHeight(1000000, genesis).useV2);
    EXPECT_FALSE(pqSigningContextForHeight(
        std::numeric_limits<uint32_t>::max() - 1, genesis).useV2);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
