// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Round-trip + tamper tests for the PQ Phase 1 wire format (transaction
// version 2): PqInput / PqOutput variants, the txType prefix byte, and the
// version-branched serialization (spec §5).

#include "gtest/gtest.h"

#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "PqTxType.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteTools.h"

#include <cstdint>
#include <vector>

using namespace CryptoNote;

namespace {

std::vector<uint8_t> blob(size_t n, uint8_t a, uint8_t b) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(i * a + b);
    return v;
}

Crypto::Hash hashPat(uint8_t a, uint8_t b) {
    Crypto::Hash h;
    for (size_t i = 0; i < sizeof(h.data); ++i) h.data[i] = static_cast<uint8_t>(i * a + b);
    return h;
}

PqInput makePqInput() {
    PqInput in;
    in.prevTxid = hashPat(1, 0);
    in.prevOutIndex = 3;
    in.authPub   = blob(PQ_AUTH_PUB_SIZE, 5, 1);
    in.rhoReveal = blob(PQ_RHO_SIZE, 3, 9);
    in.signature = blob(PQ_SIGNATURE_SIZE, 7, 2);
    return in;
}

TransactionOutput makePqOutput() {
    PqOutput o;
    o.kemCt      = blob(PQ_KEM_CIPHERTEXT_SIZE, 7, 3);
    o.encPayload = blob(PQ_ENC_PAYLOAD_SIZE, 2, 1);
    o.spendCommit = hashPat(4, 5);
    TransactionOutput out;
    out.amount = 1000000;
    out.target = o;
    return out;
}

Transaction makePqTx() {
    Transaction tx;
    tx.version = TRANSACTION_VERSION_PQ;  // 2
    tx.txType = TX_PQ;
    tx.unlockTime = 0;
    tx.inputs.push_back(makePqInput());
    tx.outputs.push_back(makePqOutput());
    // PQ signatures live inside the inputs; the legacy vector stays empty.
    return tx;
}

}  // namespace

TEST(PqWire, RoundTrip) {
    Transaction tx = makePqTx();
    BinaryArray ba = toBinaryArray(tx);
    ASSERT_FALSE(ba.empty());

    Transaction tx2;
    ASSERT_TRUE(fromBinaryArray(tx2, ba));

    EXPECT_EQ(tx2.version, TRANSACTION_VERSION_PQ);
    EXPECT_EQ(tx2.txType, TX_PQ);
    EXPECT_EQ(tx2.unlockTime, 0u);
    ASSERT_EQ(tx2.inputs.size(), 1u);
    ASSERT_EQ(tx2.outputs.size(), 1u);

    ASSERT_EQ(tx2.inputs[0].type(), typeid(PqInput));
    const PqInput& in = boost::get<PqInput>(tx2.inputs[0]);
    const PqInput& in0 = boost::get<PqInput>(tx.inputs[0]);
    EXPECT_EQ(in.prevTxid, in0.prevTxid);
    EXPECT_EQ(in.prevOutIndex, in0.prevOutIndex);
    EXPECT_EQ(in.authPub, in0.authPub);
    EXPECT_EQ(in.rhoReveal, in0.rhoReveal);
    EXPECT_EQ(in.signature, in0.signature);

    EXPECT_EQ(tx2.outputs[0].amount, 1000000u);
    ASSERT_EQ(tx2.outputs[0].target.type(), typeid(PqOutput));
    const PqOutput& o = boost::get<PqOutput>(tx2.outputs[0].target);
    const PqOutput& o0 = boost::get<PqOutput>(tx.outputs[0].target);
    EXPECT_EQ(o.kemCt, o0.kemCt);
    EXPECT_EQ(o.encPayload, o0.encPayload);
    EXPECT_EQ(o.spendCommit, o0.spendCommit);

    // Re-serializing the parsed tx reproduces the bytes exactly.
    EXPECT_EQ(toBinaryArray(tx2), ba);
}

TEST(PqWire, FieldSizesOnWire) {
    Transaction tx = makePqTx();
    BinaryArray ba = toBinaryArray(tx);
    // The big PQ blobs dominate: at least authPub + signature + kemCt bytes.
    EXPECT_GT(ba.size(), PQ_AUTH_PUB_SIZE + PQ_SIGNATURE_SIZE + PQ_KEM_CIPHERTEXT_SIZE);
}

TEST(PqWire, TxTypeIsCoveredByHash) {
    // The prefix hash must cover txType, so changing it changes the tx hash.
    Transaction a = makePqTx();
    Transaction b = makePqTx();
    b.txType = TX_BRIDGE;
    EXPECT_NE(getObjectHash(a), getObjectHash(b));
}

TEST(PqWire, WrongBlobSizeRejectedOnSerialize) {
    Transaction tx = makePqTx();
    PqInput& in = boost::get<PqInput>(tx.inputs[0]);
    in.signature.resize(PQ_SIGNATURE_SIZE - 1);  // malformed
    BinaryArray ba;
    EXPECT_FALSE(toBinaryArray(tx, ba));  // serializer throws -> wrapper returns false
}

TEST(PqWire, TamperedByteChangesContent) {
    Transaction tx = makePqTx();
    BinaryArray ba = toBinaryArray(tx);
    ba[ba.size() / 2] ^= 0xFF;  // flip a byte inside the blobs
    Transaction tx2;
    ASSERT_TRUE(fromBinaryArray(tx2, ba));  // still structurally valid (fixed sizes)
    EXPECT_NE(toBinaryArray(tx2), toBinaryArray(tx));  // but content differs
}

TEST(PqWire, LegacyV1HasNoTxTypeByte) {
    // A v1 transaction must serialize without a txType byte (backward compat):
    // its prefix is unchanged from before the PQ fork.
    Transaction tx;
    tx.version = 1;
    tx.unlockTime = 0;
    BaseInput bi; bi.blockIndex = 5;
    tx.inputs.push_back(bi);
    KeyOutput ko{};
    TransactionOutput out; out.amount = 50; out.target = ko;
    tx.outputs.push_back(out);

    BinaryArray ba = toBinaryArray(tx);
    Transaction tx2;
    ASSERT_TRUE(fromBinaryArray(tx2, ba));
    EXPECT_EQ(tx2.version, 1);
    EXPECT_EQ(tx2.txType, 0);  // defaulted, not read from wire
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
