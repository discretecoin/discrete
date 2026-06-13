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

// Fabricate a classical one-time output owned by `owner` and wrap it as a
// BridgeLegacyInput (ring size 1). Mirrors how a real source output is formed:
//   R = r*G ; P = Hs(r*A, idx)*G + B ; the wallet re-derives the same via its
//   view secret in generate_key_image_helper.
BridgeLegacyInput legacyInput(const CryptoNote::AccountBase& owner, uint64_t amount,
                              uint32_t globalIndex) {
    const CryptoNote::AccountKeys& ak = owner.getAccountKeys();
    Crypto::PublicKey R; Crypto::SecretKey r;
    Crypto::generate_keys(R, r);

    const size_t idx = 0;
    Crypto::KeyDerivation deriv;
    Crypto::generate_key_derivation(ak.address.viewPublicKey, r, deriv);
    Crypto::PublicKey P;
    Crypto::derive_public_key(deriv, idx, ak.address.spendPublicKey, P);

    BridgeLegacyInput bi;
    bi.senderKeys = ak;
    bi.keyInfo.amount = amount;
    bi.keyInfo.outputs.push_back(TransactionTypes::GlobalOutput{P, globalIndex});
    bi.keyInfo.realOutput.transactionPublicKey = R;
    bi.keyInfo.realOutput.transactionIndex = 0;   // real member's index in the ring
    bi.keyInfo.realOutput.outputInTransaction = idx;
    return bi;
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

    EXPECT_EQ(tx.version, TRANSACTION_VERSION_PQ);
    EXPECT_EQ(tx.txType, TX_PQ);
    EXPECT_TRUE(tx.signatures.empty());

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

TEST(PqTxBuilder, TamperedSignatureRejected) {
    PqWalletKeys sender = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys recip  = derivePqWalletKeys(spendSecret(9, 1));
    PqResolvedInput resolved;
    PqSpendInput in = fund(sender, 1000000, 0x11, 0, resolved);
    PqSendOutput out{recip.viewPub, recip.spendPub, 900000};

    Transaction tx = buildPqTransaction({in}, {out}, sender.spendPub, sender.spendSk);
    PqInput& pin = boost::get<PqInput>(tx.inputs[0]);
    pin.signature[0] ^= 0xFF;

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

// --- TX_BRIDGE (legacy -> PQ) ---------------------------------------------

TEST(PqBridgeBuilder, ShapeAndRingSignaturesValid) {
    CryptoNote::AccountBase sender; sender.generate();
    PqWalletKeys recip = derivePqWalletKeys(spendSecret(9, 1));

    std::vector<BridgeLegacyInput> ins{ legacyInput(sender, 1000000, 0) };
    PqSendOutput out{recip.viewPub, recip.spendPub, 900000};  // 100000 fee

    Transaction tx = buildBridgeTransaction(ins, {out});

    EXPECT_EQ(tx.version, TRANSACTION_VERSION_PQ);
    EXPECT_EQ(tx.txType, TX_BRIDGE);
    ASSERT_EQ(tx.inputs.size(), 1u);
    ASSERT_EQ(tx.signatures.size(), 1u);
    EXPECT_EQ(tx.inputs[0].type(), typeid(KeyInput));
    EXPECT_EQ(tx.outputs[0].target.type(), typeid(PqOutput));

    std::string err;
    EXPECT_TRUE(checkBridgeTransactionSemantic(tx, &err)) << err;

    // Ring signature must verify over the prefix hash (covers the PQ outputs).
    Crypto::Hash prefixHash =
        CryptoNote::getObjectHash(static_cast<const CryptoNote::TransactionPrefix&>(tx));
    const KeyInput& kin = boost::get<KeyInput>(tx.inputs[0]);
    std::vector<const Crypto::PublicKey*> ring{ &ins[0].keyInfo.outputs[0].targetKey };
    EXPECT_TRUE(Crypto::check_ring_signature(prefixHash, kin.keyImage, ring,
                                             tx.signatures[0].data()));
}

TEST(PqBridgeBuilder, SupportsClassicalChangeOutput) {
    CryptoNote::AccountBase sender; sender.generate();
    PqWalletKeys recip = derivePqWalletKeys(spendSecret(9, 1));

    std::vector<BridgeLegacyInput> ins{ legacyInput(sender, 1000000, 0) };
    PqSendOutput pqOut{recip.viewPub, recip.spendPub, 700000};
    BridgeKeyOutput change{sender.getAccountKeys().address, 200000};
    Transaction tx = buildBridgeTransaction(ins, {pqOut}, {change});

    ASSERT_EQ(tx.outputs.size(), 2u);
    EXPECT_EQ(tx.outputs[0].target.type(), typeid(PqOutput));
    EXPECT_EQ(tx.outputs[1].target.type(), typeid(KeyOutput));
    EXPECT_EQ(tx.outputs[1].amount, 200000u);

    std::string err;
    EXPECT_TRUE(checkBridgeTransactionSemantic(tx, &err)) << err;

    std::vector<size_t> outs;
    uint64_t received = 0;
    ASSERT_TRUE(lookup_acc_outs(sender.getAccountKeys(), tx,
                                getTransactionPublicKeyFromExtra(tx.extra),
                                outs, received));
    ASSERT_EQ(outs.size(), 1u);
    EXPECT_EQ(outs[0], 1u);
    EXPECT_EQ(received, 200000u);
}

TEST(PqBridgeBuilder, RecipientScansBridgedOutput) {
    CryptoNote::AccountBase sender; sender.generate();
    PqWalletKeys recip = derivePqWalletKeys(spendSecret(5, 5));

    std::vector<BridgeLegacyInput> ins{ legacyInput(sender, 2000000, 3) };
    PqSendOutput out{recip.viewPub, recip.spendPub, 1900000};
    Transaction tx = buildBridgeTransaction(ins, {out});

    // Receiver recomputes the same wallet-side inputsHash (key-image based).
    CryptoPQ::Hash256 ih = pqTransactionInputsHash(tx);

    const PqOutput& po = boost::get<PqOutput>(tx.outputs[0].target);
    CryptoPQ::PqScanOutput so;
    so.outputIndex = 0;
    so.amount = tx.outputs[0].amount;
    std::memcpy(so.kemCt.data(), po.kemCt.data(), so.kemCt.size());
    so.encPayload = po.encPayload;
    std::memcpy(so.spendCommit.data(), po.spendCommit.data, 32);

    auto owned = CryptoPQ::scanPqOutput(pqScanKeys(recip), ih, so);
    ASSERT_TRUE(owned.has_value());
    EXPECT_EQ(owned->amount, 1900000u);
}

TEST(PqBridgeBuilder, TamperedOutputBreaksRingSignature) {
    CryptoNote::AccountBase sender; sender.generate();
    PqWalletKeys recip = derivePqWalletKeys(spendSecret(9, 1));
    std::vector<BridgeLegacyInput> ins{ legacyInput(sender, 1000000, 0) };
    PqSendOutput out{recip.viewPub, recip.spendPub, 900000};
    Transaction tx = buildBridgeTransaction(ins, {out});

    // Mutate an output byte -> prefix hash changes -> ring signature must fail.
    PqOutput& po = boost::get<PqOutput>(tx.outputs[0].target);
    po.spendCommit.data[0] ^= 0xFF;

    Crypto::Hash prefixHash =
        CryptoNote::getObjectHash(static_cast<const CryptoNote::TransactionPrefix&>(tx));
    const KeyInput& kin = boost::get<KeyInput>(tx.inputs[0]);
    std::vector<const Crypto::PublicKey*> ring{ &ins[0].keyInfo.outputs[0].targetKey };
    EXPECT_FALSE(Crypto::check_ring_signature(prefixHash, kin.keyImage, ring,
                                              tx.signatures[0].data()));
}

// --- TX_FREE_REG (zero-fee account registration) ---------------------------

TEST(PqFreeReg, BuildsValidRegistration) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(5, 5));
    Crypto::Hash ref;
    for (int i = 0; i < 32; ++i) ref.data[i] = static_cast<uint8_t>(i + 1);

    // Grind the anti-spam PoW (instant under the current max-target placeholder).
    uint64_t nonce = 0;
    while (!CryptoNote::checkFreeRegPow(me.viewPub, ref, nonce)) ++nonce;

    Transaction tx = buildFreeRegTransaction(me.viewPub, me.spendPub, ref, nonce);
    EXPECT_EQ(tx.version, TRANSACTION_VERSION_PQ);
    EXPECT_EQ(tx.txType, TX_FREE_REG);
    EXPECT_TRUE(tx.inputs.empty());
    EXPECT_TRUE(tx.outputs.empty());
    EXPECT_TRUE(tx.signatures.empty());

    std::string err;
    EXPECT_TRUE(checkFreeRegTransactionSemantic(tx, &err)) << err;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
