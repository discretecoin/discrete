// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Round-trip + tamper tests for the PQ Phase 1 wire format (transaction
// version 2): PqInput / PqOutput variants, the txType prefix byte, and the
// version-branched serialization (spec §5).

#include "gtest/gtest.h"

#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "PqTxType.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/PqValidation.h"

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
    return in;
}

TransactionOutput makePqOutput() {
    PqOutput o;
    o.kemCt      = blob(PQ_KEM_CIPHERTEXT_SIZE, 7, 3);
    o.encPayload = blob(PQ_ENC_PAYLOAD_SIZE, 2, 1);
    o.spendCommit = hashPat(4, 5);
    TransactionOutput out;
    out.amount = 1000000;
    out.unlockHeight = 80000;  // per-output spend lock; must round-trip on the wire
    out.target = o;
    return out;
}

Transaction makePqTx() {
    Transaction tx;
    tx.version = TRANSACTION_VERSION_1;
    tx.txType = TX_PQ;
    tx.unlockHeight = 0;
    tx.inputs.push_back(makePqInput());
    tx.outputs.push_back(makePqOutput());
    // One ML-DSA-65 signature per PqInput; size fixed at compile time.
    std::array<uint8_t, PQ_SIGNATURE_SIZE> sig;
    for (size_t i = 0; i < PQ_SIGNATURE_SIZE; ++i) sig[i] = static_cast<uint8_t>(i * 7 + 2);
    tx.pqSignatures.push_back(sig);
    return tx;
}

Block makePqBlock() {
    Block b;
    b.majorVersion = BLOCK_MAJOR_VERSION_6;
    b.minorVersion = 0;
    b.timestamp = 123456;
    b.previousBlockHash = hashPat(9, 4);
    b.nonce = 7;

    Transaction tx;
    tx.version = TRANSACTION_VERSION_1;
    tx.txType = TX_COINBASE;
    tx.unlockHeight = 10;
    BaseInput bi;
    bi.blockIndex = 1;
    tx.inputs.push_back(bi);
    tx.outputs.push_back(makePqOutput());
    b.baseTransaction = tx;
    b.signature = blob(PQ_SIGNATURE_SIZE, 11, 3);
    return b;
}

}  // namespace

TEST(PqWire, RoundTrip) {
    Transaction tx = makePqTx();
    BinaryArray ba = toBinaryArray(tx);
    ASSERT_FALSE(ba.empty());

    Transaction tx2;
    ASSERT_TRUE(fromBinaryArray(tx2, ba));

    EXPECT_EQ(tx2.version, TRANSACTION_VERSION_1);
    EXPECT_EQ(tx2.txType, TX_PQ);
    EXPECT_EQ(tx2.unlockHeight, 0u);
    ASSERT_EQ(tx2.inputs.size(), 1u);
    ASSERT_EQ(tx2.outputs.size(), 1u);

    ASSERT_EQ(tx2.inputs[0].type(), typeid(PqInput));
    const PqInput& in = boost::get<PqInput>(tx2.inputs[0]);
    const PqInput& in0 = boost::get<PqInput>(tx.inputs[0]);
    EXPECT_EQ(in.prevTxid, in0.prevTxid);
    EXPECT_EQ(in.prevOutIndex, in0.prevOutIndex);
    EXPECT_EQ(in.authPub, in0.authPub);
    EXPECT_EQ(in.rhoReveal, in0.rhoReveal);
    ASSERT_EQ(tx2.pqSignatures.size(), 1u);
    EXPECT_EQ(tx2.pqSignatures[0], tx.pqSignatures[0]);

    EXPECT_EQ(tx2.outputs[0].amount, 1000000u);
    EXPECT_EQ(tx2.outputs[0].unlockHeight, 80000u);
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
    b.txType = TX_FREE_REG;
    EXPECT_NE(getObjectHash(a), getObjectHash(b));
}

TEST(PqWire, SigCountMismatchRejectedBySemantic) {
    // pqSignatures is std::array — size is compile-time fixed, so wrong-size blobs
    // cannot be constructed. Wrong COUNT (sigs != inputs) is the remaining failure mode.
    Transaction tx = makePqTx();
    tx.pqSignatures.clear();  // 0 sigs for 1 PqInput
    std::string err;
    EXPECT_FALSE(CryptoNote::checkPqTransactionSemantic(tx, &err));
}

TEST(PqWire, TamperedByteChangesContent) {
    Transaction tx = makePqTx();
    BinaryArray ba = toBinaryArray(tx);
    ba[ba.size() / 2] ^= 0xFF;  // flip a byte inside the blobs
    Transaction tx2;
    ASSERT_TRUE(fromBinaryArray(tx2, ba));  // still structurally valid (fixed sizes)
    EXPECT_NE(toBinaryArray(tx2), toBinaryArray(tx));  // but content differs
}

TEST(PqWire, SingleVersionAlwaysCarriesTxTypeByte) {
    // Discrete has no legacy dual-version wire format: version 1 IS the PQ
    // version, so every transaction carries a txType byte on the wire and it
    // round-trips.
    Transaction tx;
    tx.version = TRANSACTION_VERSION_1;  // == 1
    tx.txType = TX_PQ;
    tx.unlockHeight = 0;
    BaseInput bi; bi.blockIndex = 5;
    tx.inputs.push_back(bi);
    PqOutput po;
    po.kemCt.assign(PQ_KEM_CIPHERTEXT_SIZE, 0);
    po.encPayload.assign(PQ_ENC_PAYLOAD_SIZE, 0);
    TransactionOutput out; out.amount = 50; out.target = po;
    tx.outputs.push_back(out);

    BinaryArray ba = toBinaryArray(tx);
    Transaction tx2;
    ASSERT_TRUE(fromBinaryArray(tx2, ba));
    EXPECT_EQ(tx2.version, TRANSACTION_VERSION_1);
    EXPECT_EQ(tx2.txType, TX_PQ);  // read back from wire, not defaulted
}

TEST(PqWire, CoinbaseOutputRoundTrips) {
    // CoinbaseOutput (tag 0x11): only carries spendCommit (32 B), no kemCt/encPayload.
    // Verify serialization round-trips the correct type and data.
    CoinbaseOutput co;
    for (size_t i = 0; i < sizeof(co.spendCommit.data); ++i)
        co.spendCommit.data[i] = static_cast<uint8_t>(i * 3 + 7);

    Transaction tx;
    tx.version = TRANSACTION_VERSION_1;
    tx.txType = TX_COINBASE;
    tx.unlockHeight = 0;
    BaseInput bi; bi.blockIndex = 100;
    tx.inputs.push_back(bi);
    TransactionOutput out; out.amount = 1000000; out.target = co;
    tx.outputs.push_back(out);

    BinaryArray ba = toBinaryArray(tx);
    Transaction tx2;
    ASSERT_TRUE(fromBinaryArray(tx2, ba));
    ASSERT_EQ(tx2.outputs.size(), 1u);
    ASSERT_EQ(tx2.outputs[0].target.type(), typeid(CoinbaseOutput));
    const CoinbaseOutput& co2 = boost::get<CoinbaseOutput>(tx2.outputs[0].target);
    EXPECT_EQ(std::memcmp(co2.spendCommit.data, co.spendCommit.data, 32), 0);
    EXPECT_EQ(tx2.outputs[0].amount, 1000000u);
    EXPECT_EQ(tx2.txType, TX_COINBASE);
}

TEST(PqWire, BlockIdCommitsToSignatureViaWitness) {
    // DiscretePower: the hashing blob C_B excludes the signature, but the block ID
    // folds in a 32-byte witness over it. Two blocks that share a header but carry
    // different valid-length signatures therefore have the SAME hashing blob yet
    // DISTINCT block IDs (and DISTINCT PoW). This closes signature/PoW
    // malleability: an alternate signature can no longer masquerade under the same
    // block ID, so no in-zone/cache path can be poisoned by a same-ID variant.
    Block a = makePqBlock();
    Block b = a;
    b.signature = blob(PQ_SIGNATURE_SIZE, 13, 7);  // differs from makePqBlock()'s (11,3)

    BinaryArray unsignedA;
    BinaryArray unsignedB;
    ASSERT_TRUE(get_block_hashing_blob(a, unsignedA));
    ASSERT_TRUE(get_block_hashing_blob(b, unsignedB));
    EXPECT_EQ(unsignedA, unsignedB);  // hashing blob C_B still excludes the signature

    Crypto::Hash idA{};
    Crypto::Hash idB{};
    ASSERT_TRUE(get_block_hash(a, idA));
    ASSERT_TRUE(get_block_hash(b, idB));
    EXPECT_NE(idA, idB);  // block ID commits to the signature via the witness

    Crypto::Hash powA{};
    Crypto::Hash powB{};
    ASSERT_TRUE(get_block_longhash(a, powA));
    ASSERT_TRUE(get_block_longhash(b, powB));
    EXPECT_NE(powA, powB);  // the raw signature bytes drive the memory-hard core
}

TEST(PqWire, BlockIdDeterministicAndHeaderSensitive) {
    // The ID is a pure function of (C_B, signature): recomputing it for the same
    // block agrees, changing a header field (nonce) changes it, and changing the
    // signature changes it — the three properties the witness commitment must have.
    Block a = makePqBlock();
    Crypto::Hash id1{};
    Crypto::Hash id2{};
    ASSERT_TRUE(get_block_hash(a, id1));
    ASSERT_TRUE(get_block_hash(a, id2));
    EXPECT_EQ(id1, id2);  // deterministic

    Block hdr = a;
    hdr.nonce = a.nonce + 1;
    Crypto::Hash idHdr{};
    ASSERT_TRUE(get_block_hash(hdr, idHdr));
    EXPECT_NE(id1, idHdr);  // C_B change flows into the ID

    Block sig = a;
    sig.signature = blob(PQ_SIGNATURE_SIZE, 2, 5);
    Crypto::Hash idSig{};
    ASSERT_TRUE(get_block_hash(sig, idSig));
    EXPECT_NE(id1, idSig);  // signature change flows into the ID via the witness
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
