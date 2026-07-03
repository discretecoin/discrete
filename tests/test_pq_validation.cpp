// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Consensus-validation tests for v2 TX_PQ (spec §9, ownership-fixed). Builds a
// real signed PQ transaction (outputs via PqOutputBuilder, inputs signed with
// ML-DSA over the §8.1 digest), then asserts acceptance and that each rule
// rejects when violated.

#include "gtest/gtest.h"

#include "CryptoNote.h"
#include "CryptoNoteConfig.h"
#include "PqTxType.h"
#include "CryptoNoteCore/PqValidation.h"
#include "CryptoNoteCore/TransactionExtra.h"

#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqSeed.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqDsa.h"
#include "crypto/crypto.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace CryptoNote;

namespace {

template <std::size_t N> std::array<uint8_t, N> pat(uint8_t a, uint8_t b) {
    std::array<uint8_t, N> r;
    for (std::size_t i = 0; i < N; ++i) r[i] = static_cast<uint8_t>(i * a + b);
    return r;
}

Crypto::Hash hashPat(uint8_t a, uint8_t b) {
    Crypto::Hash h;
    for (size_t i = 0; i < sizeof(h.data); ++i) h.data[i] = static_cast<uint8_t>(i * a + b);
    return h;
}

template <std::size_t N> std::vector<uint8_t> toVec(const std::array<uint8_t, N>& a) {
    return std::vector<uint8_t>(a.begin(), a.end());
}

// A built, signed PQ transaction plus the resolved referenced outputs and the
// spender's secret (so tests can re-sign after mutating).
struct BuiltTx {
    Transaction tx;
    std::vector<PqResolvedInput> resolved;
    CryptoPQ::DsaSecretKey spendSk;
};

// One spender owns one input (amountIn) and sends amountOut to a recipient,
// leaving fee = amountIn - amountOut. `extra` is signed into the digest.
BuiltTx buildSignedTx(uint64_t amountIn, uint64_t amountOut,
                      const std::vector<uint8_t>& extra = {}) {
    BuiltTx b;

    CryptoPQ::SeedMaster ms = pat<32>(2, 7);   // spender
    CryptoPQ::SeedMaster mr = pat<32>(3, 9);   // recipient
    auto spenderSpend = CryptoPQ::deriveSpendKeys(ms);
    auto recipView = CryptoPQ::deriveViewKeys(mr);
    auto recipSpend = CryptoPQ::deriveSpendKeys(mr);
    b.spendSk = spenderSpend.second;

    // The input being spent: a PqOutput the spender owns, identified by
    // (prevTxid, prevOutIndex) with secret rho_in.
    Crypto::Hash prevTxid = hashPat(1, 0);
    uint32_t prevOutIndex = 2;
    CryptoPQ::Rho rhoIn = pat<32>(3, 9);

    PqInput in;
    in.prevTxid = prevTxid;
    in.prevOutIndex = prevOutIndex;
    in.authPub = toVec(spenderSpend.first);   // long-term spend pubkey
    in.rhoReveal = toVec(rhoIn);
    b.tx.inputs.push_back(in);

    // Resolved referenced output: its spend_commit binds the spender's spend key.
    PqResolvedInput r;
    r.exists = true; r.isPqOutput = true; r.isCoinbase = false;
    r.amount = amountIn;
    {
        CryptoPQ::Hash256 sc = CryptoPQ::spendCommit(spenderSpend.first, rhoIn);
        std::memcpy(r.spendCommit.data, sc.data(), 32);
    }
    b.resolved.push_back(r);

    // inputsHash over this tx's outpoints (binds outputs' out_context).
    std::vector<CryptoPQ::InputRef> refs(1);
    std::memcpy(refs[0].prevTxid.data(), prevTxid.data, 32);
    refs[0].prevOutIndex = prevOutIndex;
    CryptoPQ::Hash256 ih = CryptoPQ::inputsHash(refs);

    // One output to the recipient.
    CryptoPQ::PqBuiltOutput built =
        CryptoPQ::buildPqOutput(recipView.first, recipSpend.first, ih, 0, amountOut);
    PqOutput po;
    po.kemCt = toVec(built.kemCt);
    po.encPayload = built.encPayload;
    std::memcpy(po.spendCommit.data, built.spendCommit.data(), 32);
    TransactionOutput out;
    out.amount = amountOut;
    out.target = po;

    b.tx.version = TRANSACTION_VERSION_1;
    b.tx.txType = TX_PQ;
    b.tx.unlockHeight = 0;
    b.tx.extra = extra;
    b.tx.outputs.push_back(out);

    // Sign: digest over (tx, fee), ML-DSA with the spender's spend secret.
    uint64_t fee = amountIn - amountOut;
    CryptoPQ::Hash256 digest = pqSigningDigest(b.tx, fee);
    CryptoPQ::DsaSignature sig =
        CryptoPQ::dsa_sign(b.spendSk, digest.data(), digest.size());
    b.tx.pqSignatures.assign(1, sig);

    return b;
}

// Re-sign after a mutation that changes the digest (amount/fee/etc. or input count).
void resign(BuiltTx& b) {
    uint64_t sumIn = 0, sumOut = 0;
    for (auto& r : b.resolved) sumIn += r.amount;
    for (auto& o : b.tx.outputs) sumOut += o.amount;
    CryptoPQ::Hash256 d = pqSigningDigest(b.tx, sumIn - sumOut);
    CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(b.spendSk, d.data(), d.size());
    b.tx.pqSignatures.assign(b.tx.inputs.size(), sig);
}

const uint64_t kMinFee = 0;  // disable fee-floor except where tested

}  // namespace

TEST(PqValidation, AcceptsValidTx) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    std::string err;
    EXPECT_TRUE(checkPqTransactionSemantic(b.tx, &err)) << err;
    std::vector<Crypto::Hash> nfs;
    EXPECT_TRUE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, &nfs, &err)) << err;
    EXPECT_EQ(nfs.size(), 1u);
}

TEST(PqValidation, RejectsTamperedSignature) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.pqSignatures[0][10] ^= 0xFF;
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, RejectsSpendCommitMismatch) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.resolved[0].spendCommit.data[0] ^= 0xFF;  // referenced output binds a different key
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, RejectsMissingReferencedOutput) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.resolved[0].exists = false;
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, AcceptsCoinbaseReference) {
    // Discrete: coinbase PqOutputs ARE spendable (sole funds source — no legacy
    // chain or bridge). The context-free check accepts a coinbase reference;
    // coinbase maturity (minedMoneyUnlockWindow) is enforced by the chain-context
    // caller (Blockchain::checkPqInputs), exercised end-to-end by PqChainTests.
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.resolved[0].isCoinbase = true;
    std::string err;
    EXPECT_TRUE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err)) << err;
}

TEST(PqValidation, RejectsOutputsExceedInputs) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.outputs[0].amount = 2000000;  // > input
    resign(b);
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, RejectsAmountTamperWithoutResign) {
    // Changing an output amount without re-signing breaks the digest.
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.outputs[0].amount = 800000;  // fee would change; signature now stale
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, RejectsFeeBelowFlatMinimum) {
    BuiltTx b = buildSignedTx(1000000, 1000000);  // fee = 0
    std::string err;
    // The flat floor is MINIMUM_FEE (1 atom); a zero fee is below it regardless of size.
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, parameters::MINIMUM_FEE, nullptr, &err));
}

TEST(PqValidation, AcceptsFlatMinimumFee) {
    // The fee is flat: exactly MINIMUM_FEE (1 atom = 0.01 XDS) for any tx whose
    // extra fits the free allowance, independent of serialized size.
    BuiltTx b = buildSignedTx(1000000, 999999);  // fee = 1 atom
    std::string err;
    EXPECT_TRUE(checkPqTransactionInputs(b.tx, b.resolved,
        parameters::MINIMUM_FEE, nullptr, &err)) << err;
}

TEST(PqValidation, ChargesExtraFieldSurcharge) {
    // A large tx_extra is the only user-controllable bloat, so it is surcharged:
    // one MINIMUM_FEE per started TX_EXTRA_FEE_CHUNK_BYTES chunk beyond the free
    // allowance (sized to fit a paid account registration, 3137 bytes). The max
    // 4096-byte extra needs 1 + ceil(896/100) = 10 atoms; 1 atom must fail,
    // 10 must pass.
    const std::vector<uint8_t> bigExtra(parameters::MAX_EXTRA_SIZE_PQ, 0x00);
    const uint64_t floor =
        parameters::pqTxFeeFloor(parameters::MINIMUM_FEE, bigExtra.size());
    ASSERT_EQ(floor, 10u);

    BuiltTx low = buildSignedTx(1000000, 999999, bigExtra);   // fee = 1 atom
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(low.tx, low.resolved, parameters::MINIMUM_FEE,
                                          nullptr, &err));

    BuiltTx ok = buildSignedTx(1000000, 1000000 - floor, bigExtra);
    EXPECT_TRUE(checkPqTransactionInputs(ok.tx, ok.resolved, parameters::MINIMUM_FEE,
                                         nullptr, &err)) << err;
}

TEST(PqValidation, RejectsOversizedExtra) {
    // tx_extra above MAX_EXTRA_SIZE_PQ fails the semantic check outright, while
    // the same tx with a maximal-but-legal extra passes it.
    const std::vector<uint8_t> oversized(parameters::MAX_EXTRA_SIZE_PQ + 1, 0x00);
    BuiltTx b = buildSignedTx(1000000, 900000, oversized);
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));

    const std::vector<uint8_t> maximal(parameters::MAX_EXTRA_SIZE_PQ, 0x00);
    BuiltTx ok = buildSignedTx(1000000, 900000, maximal);
    EXPECT_TRUE(checkPqTransactionSemantic(ok.tx, &err)) << err;
}

TEST(PqValidation, RejectsExtraTamper) {
    // tx_extra is bound by the signing digest, so appending bytes after signing
    // (without re-signing) must fail signature verification — closes the
    // malleability gap where extra changed the txid but not the signature.
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.extra = {0xDE, 0xAD, 0xBE, 0xEF};  // mutate extra, keep stale signature
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, RejectsDuplicateNullifier) {
    // Two inputs spending the same output (same authPub+rho) -> same nullifier.
    BuiltTx b = buildSignedTx(1000000, 900000);
    PqInput dup = boost::get<PqInput>(b.tx.inputs[0]);
    b.tx.inputs.push_back(dup);
    b.resolved.push_back(b.resolved[0]);
    resign(b);
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(b.tx, b.resolved, kMinFee, nullptr, &err));
}

TEST(PqValidation, SemanticRejectsWrongSubtype) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.txType = 0x02;  // permanently-reserved/unknown subtype
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

TEST(PqValidation, SemanticRejectsUnlockTime) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.unlockHeight = 5;
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

TEST(PqValidation, SemanticRejectsWrongSigCount) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    // Extra signature blob for a tx with only one input.
    b.tx.pqSignatures.resize(2, b.tx.pqSignatures[0]);
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

TEST(PqValidation, SemanticRejectsMixedFamilyInput) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    BaseInput bi; bi.blockIndex = 1;  // any non-PqInput in a TX_PQ is rejected
    b.tx.inputs.push_back(bi);
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

TEST(PqValidation, SemanticRejectsZeroAmountOutput) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.outputs[0].amount = 0;
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

TEST(PqValidation, SemanticRejectsWrongFieldSize) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    boost::get<PqInput>(b.tx.inputs[0]).authPub.pop_back();  // 1951 bytes
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

// The permanently-reserved 0x02 subtype (never-deployed legacy bridge) must keep
// being rejected by the PQ semantic gate, which admits only TX_PQ.
TEST(PqValidation, ReservedSubtype0x02Rejected) {
    BuiltTx b = buildSignedTx(1000000, 900000);
    b.tx.txType = 0x02;
    std::string err;
    EXPECT_FALSE(checkPqTransactionSemantic(b.tx, &err));
}

// --- TX_FREE_REG semantic (zero-fee account registration + PoW) -------------

namespace {

std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE> freeRegViewPub() {
    std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE> vp;
    for (size_t i = 0; i < vp.size(); ++i) vp[i] = static_cast<uint8_t>(i * 3 + 1);
    return vp;
}
std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> freeRegSpendPub() {
    std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> sp;
    for (size_t i = 0; i < sp.size(); ++i) sp[i] = static_cast<uint8_t>(i * 5 + 2);
    return sp;
}

// Lenient PoW target for tests (1/16 per trial → grinds in O(1) iterations).
// The production parameters::FREE_REG_POW_TARGET is deliberately strong
// (~2^17 expected yespower calls), which would make these structural tests slow.
constexpr uint64_t kTestFreeRegPowTarget = UINT64_C(0x0FFFFFFFFFFFFFFF);

Transaction makeFreeRegTx() {
    Transaction tx;
    tx.version = TRANSACTION_VERSION_1;
    tx.txType = TX_FREE_REG;
    tx.unlockHeight = 0;
    // no inputs / outputs / signatures
    addPqAccountRegistrationToExtra(tx.extra, freeRegViewPub(), freeRegSpendPub());
    TransactionExtraPow pow{};
    pow.refBlockHash = hashPat(1, 1);
    while (!checkFreeRegPow(freeRegViewPub(), pow.refBlockHash, pow.nonce, kTestFreeRegPowTarget)) {
        ++pow.nonce;
    }
    appendPowTagToExtra(tx.extra, pow);  // PoW must be the last field
    return tx;
}

}  // namespace

TEST(PqValidation, FreeRegAcceptsValid) {
    Transaction tx = makeFreeRegTx();
    std::string err;
    EXPECT_TRUE(checkFreeRegTransactionSemantic(tx, &err, kTestFreeRegPowTarget)) << err;
}

TEST(PqValidation, FreeRegRejectsWrongSubtype) {
    Transaction tx = makeFreeRegTx();
    tx.txType = TX_PQ;
    std::string err;
    EXPECT_FALSE(checkFreeRegTransactionSemantic(tx, &err));
}

TEST(PqValidation, FreeRegRejectsNonEmptyInputs) {
    Transaction tx = makeFreeRegTx();
    BaseInput bi; bi.blockIndex = 1;  // any input at all is disallowed for TX_FREE_REG
    tx.inputs.push_back(bi);
    std::string err;
    EXPECT_FALSE(checkFreeRegTransactionSemantic(tx, &err));
}

TEST(PqValidation, FreeRegRejectsExtraField) {
    // A registration tx must carry ONLY the reg tag + PoW tag.
    Transaction tx;
    tx.version = TRANSACTION_VERSION_1;
    tx.txType = TX_FREE_REG;
    tx.unlockHeight = 0;
    addPqAccountRegistrationToExtra(tx.extra, freeRegViewPub(), freeRegSpendPub());
    Crypto::PublicKey pk{};
    addTransactionPublicKeyToExtra(tx.extra, pk);  // disallowed extra field
    TransactionExtraPow pow{}; pow.nonce = 1;
    appendPowTagToExtra(tx.extra, pow);
    std::string err;
    EXPECT_FALSE(checkFreeRegTransactionSemantic(tx, &err));
}

TEST(PqValidation, FreeRegRejectsPowNotLast) {
    // Append a registration AFTER the PoW tag so PoW is no longer the last field.
    Transaction tx;
    tx.version = TRANSACTION_VERSION_1;
    tx.txType = TX_FREE_REG;
    tx.unlockHeight = 0;
    TransactionExtraPow pow{}; pow.nonce = 1;
    appendPowTagToExtra(tx.extra, pow);
    addPqAccountRegistrationToExtra(tx.extra, freeRegViewPub(), freeRegSpendPub());
    std::string err;
    EXPECT_FALSE(checkFreeRegTransactionSemantic(tx, &err));
}

TEST(PqValidation, FreeRegRejectsMissingPow) {
    Transaction tx;
    tx.version = TRANSACTION_VERSION_1;
    tx.txType = TX_FREE_REG;
    tx.unlockHeight = 0;
    addPqAccountRegistrationToExtra(tx.extra, freeRegViewPub(), freeRegSpendPub());  // no PoW tag
    std::string err;
    EXPECT_FALSE(checkFreeRegTransactionSemantic(tx, &err));
}

TEST(PqValidation, FreeRegRejectsBadPow) {
    // Find the first nonce that does NOT satisfy the production target.
    // The production target is strong (~2^17 expected trials to PASS), so a
    // non-passing nonce is found almost immediately (nonce 0 fails w.h.p.).
    std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE> vp = freeRegViewPub();
    Crypto::Hash ref = hashPat(1, 1);
    uint64_t badNonce = 0;
    while (checkFreeRegPow(vp, ref, badNonce, parameters::FREE_REG_POW_TARGET)) {
        ++badNonce;
    }
    EXPECT_FALSE(checkFreeRegPow(vp, ref, badNonce, parameters::FREE_REG_POW_TARGET));
    // Same nonce trivially passes with UINT64_MAX target (any hash qualifies).
    EXPECT_TRUE(checkFreeRegPow(vp, ref, badNonce, UINT64_MAX));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
