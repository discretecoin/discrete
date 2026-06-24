// Copyright (c) 2026, The Karbo developers
//
// Tests for the common engine-agnostic PQ sender (src/Wallet/PqSender): input
// selection, canonical denomination decomposition, two-pass fee, change, and the
// consensus size/count caps. The sender is the single deterministic spend path used
// by every front-end.

#include "gtest/gtest.h"

#include "Wallet/PqSender.h"
#include "Wallet/PqWallet.h"
#include "Wallet/PqTransactionBuilder.h"
#include "Denominations.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNote.h"
#include "PqTxType.h"
#include "crypto_pq/PqSeed.h"   // deriveDepositSpendKeys

#include <cstring>
#include <numeric>
#include <vector>

using namespace CryptoNote;
namespace P = CryptoNote::parameters;

namespace {

Crypto::SecretKey spendSecret(uint8_t a, uint8_t b) {
    Crypto::SecretKey k;
    for (std::size_t i = 0; i < sizeof(k.data); ++i) k.data[i] = static_cast<uint8_t>(i * a + b);
    return k;
}

PqSpendInput mkInput(uint64_t amount, uint8_t seed) {
    PqSpendInput in;
    for (std::size_t i = 0; i < 32; ++i) in.prevTxid.data[i] = static_cast<uint8_t>(seed + i);
    in.prevOutIndex = 0;
    in.amount = amount;
    for (auto& x : in.rho) x = static_cast<uint8_t>(seed ^ 0xA5);  // non-zero rho
    return in;
}

uint64_t outputSum(const Transaction& tx) {
    uint64_t s = 0;
    for (const auto& o : tx.outputs) s += o.amount;
    return s;
}

PqSpendInput mkBucketInput(uint64_t amount, uint8_t seed, uint32_t depositIndex) {
    PqSpendInput in = mkInput(amount, seed);
    in.depositIndex = depositIndex;
    return in;
}

bool authPubIs(const Transaction& tx, size_t i, const CryptoPQ::DsaPublicKey& pub) {
    const PqInput& in = boost::get<PqInput>(tx.inputs[i]);
    return in.authPub.size() == pub.size() &&
           std::memcmp(in.authPub.data(), pub.data(), pub.size()) == 0;
}

}  // namespace

TEST(PqSender, AggregatedDepositInputSignedWithDepositKey) {
    // Under AggregatedMultikey, a deposit input must be authorized by its own derived
    // spend key, while the primary input uses the primary key.
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));
    auto dep = CryptoPQ::deriveDepositSpendKeys(me.seedMaster, 3);

    PqSpendInput primary = mkBucketInput(200, 0x10, PQ_PRIMARY_DEPOSIT);
    PqSpendInput deposit = mkBucketInput(100, 0x20, 3);  // smaller -> sorted second

    PqSendRequest req;
    req.scheme = PqDepositScheme::AggregatedMultikey;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 250});  // needs both

    PqSendResult r = buildPqSend({primary, deposit}, me, req);
    ASSERT_EQ(r.tx.inputs.size(), 2u);
    EXPECT_TRUE(authPubIs(r.tx, 0, me.spendPub));  // primary input -> primary key
    EXPECT_TRUE(authPubIs(r.tx, 1, dep.first));    // deposit input -> derived deposit key
}

TEST(PqSender, SingleKeyIndexUsesOneKeyForDeposits) {
    // Under SingleKeyIndex every output (including deposits) commits to the one key.
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    PqSpendInput deposit = mkBucketInput(300, 0x30, 4);
    PqSendRequest req;
    req.scheme = PqDepositScheme::SingleKeyIndex;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 200});

    PqSendResult r = buildPqSend({deposit}, me, req);
    ASSERT_EQ(r.tx.inputs.size(), 1u);
    EXPECT_TRUE(authPubIs(r.tx, 0, me.spendPub));  // the one key, NOT a derived deposit key
}

TEST(PqSender, SourceBucketFilterRestrictsInputs) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    PqSpendInput primary = mkBucketInput(300, 0x10, PQ_PRIMARY_DEPOSIT);
    PqSpendInput deposit = mkBucketInput(300, 0x20, 5);

    PqSendRequest req;
    req.scheme = PqDepositScheme::AggregatedMultikey;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 250});
    req.sourceBuckets = {5};  // spend only from deposit 5

    PqSendResult r = buildPqSend({primary, deposit}, me, req);
    ASSERT_EQ(r.selected.size(), 1u);
    EXPECT_EQ(r.selected[0].depositIndex, 5u);

    // Restricting to a bucket that cannot cover the amount -> InsufficientFunds, even
    // though the wallet as a whole has enough.
    PqSendRequest req2;
    req2.scheme = PqDepositScheme::AggregatedMultikey;
    req2.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 500});  // > 300
    req2.sourceBuckets = {PQ_PRIMARY_DEPOSIT};
    try {
        buildPqSend({primary, deposit}, me, req2);
        FAIL() << "expected PqSendError";
    } catch (const PqSendError& e) {
        EXPECT_EQ(e.code, PqSendErrorCode::InsufficientFunds);
    }
}

TEST(PqSender, SimpleTransferDecomposesAndBalances) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    std::vector<PqSpendInput> inputs = {mkInput(100, 0x10), mkInput(100, 0x20),
                                        mkInput(100, 0x30), mkInput(100, 0x40)};
    PqSendRequest req;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 250});

    PqSendResult r = buildPqSend(inputs, me, req);

    EXPECT_EQ(r.sent, 250u);
    EXPECT_GE(r.fee, 1u);
    EXPECT_EQ(r.selected.size(), 3u);                 // 100+100+100 covers 250
    EXPECT_EQ(r.tx.inputs.size(), r.selected.size());
    // Conservation: inputs == sent + change + fee; outputs == sent + change.
    uint64_t sumIn = 0;
    for (const auto& in : r.selected) sumIn += in.amount;
    EXPECT_EQ(sumIn, r.sent + r.change + r.fee);
    EXPECT_EQ(outputSum(r.tx), r.sent + r.change);
    EXPECT_LE(r.tx.outputs.size(), P::MAX_PQ_OUTPUTS_PER_TX);
    EXPECT_LE(toBinaryArray(r.tx).size(), P::MAX_PQ_TX_SIZE);
    // No coarsening at this size: every output is a canonical denomination.
    for (const auto& o : r.tx.outputs) EXPECT_TRUE(isCanonicalDenomination(o.amount));
}

TEST(PqSender, ExplicitFeeExactNoChange) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    std::vector<PqSpendInput> inputs = {mkInput(251, 0x50)};
    PqSendRequest req;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 250});
    req.explicitFee = 1;  // 251 - 250 - 1 = 0 change

    PqSendResult r = buildPqSend(inputs, me, req);
    EXPECT_EQ(r.fee, 1u);
    EXPECT_EQ(r.change, 0u);
    EXPECT_EQ(outputSum(r.tx), 250u);          // recipient only, no change output
    EXPECT_EQ(r.tx.outputs.size(), 2u);        // 250 -> 200 + 50
}

TEST(PqSender, InsufficientFundsThrows) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    std::vector<PqSpendInput> inputs = {mkInput(10, 0x60)};
    PqSendRequest req;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 250});

    try {
        buildPqSend(inputs, me, req);
        FAIL() << "expected PqSendError";
    } catch (const PqSendError& e) {
        EXPECT_EQ(e.code, PqSendErrorCode::InsufficientFunds);
    }
}

TEST(PqSender, CoarsensToOutputCap) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    // 165,000,000 au decomposes to 16 caps + 5,000,000 = 17 pieces > MAX_PQ_OUTPUTS_PER_TX,
    // so the sender must coarsen the recipient group down to fit. explicitFee keeps change 0.
    const uint64_t amount = 165000000;
    std::vector<PqSpendInput> inputs = {mkInput(amount + 100, 0x70)};
    PqSendRequest req;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, amount});
    req.explicitFee = 100;

    PqSendResult r = buildPqSend(inputs, me, req);
    EXPECT_EQ(r.change, 0u);
    EXPECT_EQ(outputSum(r.tx), amount);
    EXPECT_LE(r.tx.outputs.size(), P::MAX_PQ_OUTPUTS_PER_TX);
    EXPECT_LE(toBinaryArray(r.tx).size(), P::MAX_PQ_TX_SIZE);
}

TEST(PqSender, CarriesExtraForPaidRegistration) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    std::vector<PqSpendInput> inputs = {mkInput(1000, 0x90)};
    PqSendRequest req;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 100});
    req.extra = {0x05, 0xAA, 0xBB, 0xCC};  // stand-in for a registration tag

    PqSendResult r = buildPqSend(inputs, me, req);
    EXPECT_EQ(r.tx.extra, req.extra);  // extra is preserved verbatim (and signed over)
}

TEST(PqSender, NoRecipientsThrows) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    std::vector<PqSpendInput> inputs = {mkInput(100, 0x80)};
    PqSendRequest req;  // empty recipients
    try {
        buildPqSend(inputs, me, req);
        FAIL() << "expected PqSendError";
    } catch (const PqSendError& e) {
        EXPECT_EQ(e.code, PqSendErrorCode::NoRecipients);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
