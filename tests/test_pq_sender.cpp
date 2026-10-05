// Copyright (c) 2026, The Discrete developers
//
// Tests for the common engine-agnostic PQ sender (src/Wallet/PqSender): input
// selection (largest-first cover plus the small-input sweep), one output per
// recipient, the flat fee (MINIMUM_FEE + tx_extra surcharge), change, the
// consensus size/count caps, and consolidation. The sender is the single
// deterministic spend path used by every front-end.

#include "gtest/gtest.h"

#include "Wallet/PqSender.h"
#include "Wallet/PqWallet.h"
#include "Wallet/PqTransactionBuilder.h"
#include "CryptoNoteCore/PqValidation.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNote.h"
#include "PqTxType.h"
#include "crypto_pq/PqSeed.h"   // deriveDepositSpendKeys
#include "crypto_pq/PqScan.h"   // scanPqOutput (verify change routing)

#include <cstring>
#include <set>
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

CryptoPQ::Hash256 testGenesis() {
    CryptoPQ::Hash256 genesis{};
    for (std::size_t i = 0; i < genesis.size(); ++i)
        genesis[i] = static_cast<uint8_t>(0x80 + i);
    return genesis;
}

void expectProofsVerify(const PqSendRequest& req, const PqSendResult& result) {
    ASSERT_EQ(result.proofs.size(), req.recipients.size());
    PqPaymentProofTransaction proofTx = makePqPaymentProofTransaction(result.tx);
    for (std::size_t i = 0; i < req.recipients.size(); ++i) {
        const PqSendOutput& output = req.recipients[i];
        ResolvedRecipient recipient{
            output.recipientViewPub, output.recipientSpendPub, output.subaddrIndexT};
        EXPECT_EQ(verifyPqPaymentProof(
                      result.proofs[i], req.genesisId, proofTx, recipient),
                  output.amount);
    }
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

TEST(PqSender, SimpleTransferIsOneOutputPerRecipientPlusChange) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    std::vector<PqSpendInput> inputs = {mkInput(100, 0x10), mkInput(100, 0x20),
                                        mkInput(100, 0x30), mkInput(100, 0x40)};
    PqSendRequest req;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 250});

    PqSendResult r = buildPqSend(inputs, me, req);

    EXPECT_EQ(r.sent, 250u);
    EXPECT_GE(r.fee, 1u);
    // 100+100+100 covers 250 + fee; the one leftover input stays (the sweep keeps
    // a wallet above PQ_SWEEP_KEEP_OUTPUTS outputs).
    EXPECT_EQ(r.selected.size(), 3u);
    EXPECT_EQ(r.tx.inputs.size(), r.selected.size());
    // Conservation: inputs == sent + change + fee; outputs == sent + change.
    uint64_t sumIn = 0;
    for (const auto& in : r.selected) sumIn += in.amount;
    EXPECT_EQ(sumIn, r.sent + r.change + r.fee);
    EXPECT_EQ(outputSum(r.tx), r.sent + r.change);
    // Exactly one recipient output (the lump amount) and one change output.
    ASSERT_EQ(r.tx.outputs.size(), 2u);
    EXPECT_EQ(r.tx.outputs[0].amount, 250u);
    EXPECT_EQ(r.tx.outputs[1].amount, r.change);
    EXPECT_LE(toBinaryArray(r.tx).size(), P::MAX_PQ_TX_SIZE);
}

TEST(PqSender, SweepFoldsSmallestInputsIntoAnOrdinarySend) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    // One large input covers the payment; 50 small ones are lying around.
    std::vector<PqSpendInput> inputs = {mkInput(100000, 0x01)};
    for (uint8_t i = 0; i < 50; ++i) inputs.push_back(mkInput(10 + i, static_cast<uint8_t>(0x10 + i)));

    PqSendRequest req;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 50000});
    PqSendResult r = buildPqSend(inputs, me, req);

    // Cover (1) + the maximum sweep (PQ_SWEEP_MAX_EXTRA_INPUTS), smallest first,
    // leaving 50 - 8 = 42 > PQ_SWEEP_KEEP_OUTPUTS outputs in the wallet.
    ASSERT_EQ(r.selected.size(), 1 + PQ_SWEEP_MAX_EXTRA_INPUTS);
    EXPECT_EQ(r.selected[0].amount, 100000u);
    for (std::size_t i = 1; i < r.selected.size(); ++i) {
        EXPECT_EQ(r.selected[i].amount, 10u + (i - 1));  // the smallest ones, ascending
    }
    uint64_t sumIn = 0;
    for (const auto& in : r.selected) sumIn += in.amount;
    EXPECT_EQ(sumIn, r.sent + r.change + r.fee);
    ASSERT_EQ(r.tx.outputs.size(), 2u);  // still one recipient output + one change output

    // Opting out spends only what the payment needs.
    req.sweepSmallInputs = false;
    PqSendResult plain = buildPqSend(inputs, me, req);
    EXPECT_EQ(plain.selected.size(), 1u);
}

TEST(PqSender, SweepNeverLinksAKeyThePaymentDidNotNeed) {
    // Under per-deposit keys, spending an output publishes its deposit's key. The
    // payment needs only the primary key, so deposit dust must stay put however
    // small it is, while primary dust is still swept.
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    std::vector<PqSpendInput> inputs = {mkBucketInput(100000, 0x01, PQ_PRIMARY_DEPOSIT)};
    for (uint8_t i = 0; i < 24; ++i) {
        inputs.push_back(mkBucketInput(1, static_cast<uint8_t>(0x10 + i), 3));                  // tiniest
        inputs.push_back(mkBucketInput(20, static_cast<uint8_t>(0x40 + i), PQ_PRIMARY_DEPOSIT));
    }

    PqSendRequest req;
    req.scheme = PqDepositScheme::AggregatedMultikey;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 50000});
    PqSendResult r = buildPqSend(inputs, me, req);

    ASSERT_EQ(r.selected.size(), 1 + PQ_SWEEP_MAX_EXTRA_INPUTS);
    for (const auto& in : r.selected) EXPECT_EQ(in.depositIndex, PQ_PRIMARY_DEPOSIT);
    for (std::size_t i = 0; i < r.tx.inputs.size(); ++i) EXPECT_TRUE(authPubIs(r.tx, i, me.spendPub));
}

TEST(PqSender, SweepNeverDrainsTheWalletBelowTheKeepThreshold) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    // Cover takes the largest; PQ_SWEEP_KEEP_OUTPUTS + 2 small ones remain, of
    // which only 2 may be swept before the wallet would drop to the floor.
    std::vector<PqSpendInput> inputs = {mkInput(100000, 0x01)};
    for (uint8_t i = 0; i < PQ_SWEEP_KEEP_OUTPUTS + 2; ++i)
        inputs.push_back(mkInput(10, static_cast<uint8_t>(0x10 + i)));

    PqSendRequest req;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 50000});
    PqSendResult r = buildPqSend(inputs, me, req);
    EXPECT_EQ(r.selected.size(), 1u + 2u);

    // A wallet that is not fragmented is never swept.
    std::vector<PqSpendInput> few = {mkInput(100000, 0x01)};
    for (uint8_t i = 0; i < PQ_SWEEP_KEEP_OUTPUTS; ++i) few.push_back(mkInput(10, static_cast<uint8_t>(0x20 + i)));
    EXPECT_EQ(buildPqSend(few, me, req).selected.size(), 1u);
}

TEST(PqSender, ASecondPaymentCanBeBuiltBeforeTheFirstConfirms) {
    // Forty equal outputs: none of them is dust, so the sweep may hold back at most
    // a tenth of the spendable value. The rest stays available for the next
    // payment while the first one is unconfirmed.
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));
    std::vector<PqSpendInput> wallet;
    for (uint8_t i = 0; i < 40; ++i) wallet.push_back(mkInput(1000, static_cast<uint8_t>(0x10 + i)));

    PqSendRequest first;
    first.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 500});
    PqSendResult r1 = buildPqSend(wallet, me, first);
    uint64_t held = 0;
    for (const auto& in : r1.selected) held += in.amount;
    EXPECT_GT(r1.selected.size(), 1u);                         // it did sweep
    EXPECT_LE(held, 1000u + 40000u / PQ_SWEEP_VALUE_DIVISOR);  // cover + a tenth

    // Until it confirms, the first payment's inputs are reserved and its change is
    // locked; what is left must still fund a large second payment.
    std::vector<PqSpendInput> left;
    for (const auto& in : wallet) {
        bool reserved = false;
        for (const auto& s : r1.selected)
            reserved |= s.prevTxid == in.prevTxid && s.prevOutIndex == in.prevOutIndex;
        if (!reserved) left.push_back(in);
    }
    PqSendRequest second;
    second.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 30000});
    PqSendResult r2 = buildPqSend(left, me, second);
    EXPECT_EQ(r2.sent, 30000u);
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
    EXPECT_EQ(r.tx.outputs.size(), 1u);
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

TEST(PqSender, RejectsTxLevelUnlockHeight) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    std::vector<PqSpendInput> inputs = {mkInput(1000, 0x61)};
    PqSendRequest req;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 250});
    req.unlockHeight = 5;

    try {
        buildPqSend(inputs, me, req);
        FAIL() << "expected PqSendError";
    } catch (const PqSendError& e) {
        EXPECT_EQ(e.code, PqSendErrorCode::UnsupportedUnlockHeight);
    }
}

TEST(PqSender, AnyAmountIsASingleOutput) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    // Consensus accepts any non-zero amount, so 7,000,000.00 XDS is one output,
    // not seventy pieces of a largest denomination. explicitFee keeps change 0.
    const uint64_t amount = 700000000;
    std::vector<PqSpendInput> inputs = {mkInput(amount + 100, 0x70)};
    PqSendRequest req;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, amount});
    req.explicitFee = 100;

    PqSendResult r = buildPqSend(inputs, me, req);
    EXPECT_EQ(r.change, 0u);
    ASSERT_EQ(r.tx.outputs.size(), 1u);
    EXPECT_EQ(r.tx.outputs[0].amount, amount);
    EXPECT_LE(toBinaryArray(r.tx).size(), P::MAX_PQ_TX_SIZE);
}

TEST(PqSender, TooManyRecipientsThrows) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    std::vector<PqSpendInput> inputs = {mkInput(1000000, 0x71)};
    PqSendRequest req;
    // MAX_PQ_OUTPUTS_PER_TX - 1 recipients leave room for change; one more does not.
    for (std::size_t i = 0; i + 1 < P::MAX_PQ_OUTPUTS_PER_TX; ++i)
        req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 10});
    PqSendResult r = buildPqSend(inputs, me, req);
    EXPECT_EQ(r.tx.outputs.size(), P::MAX_PQ_OUTPUTS_PER_TX);

    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 10});
    try {
        buildPqSend(inputs, me, req);
        FAIL() << "expected PqSendError";
    } catch (const PqSendError& e) {
        EXPECT_EQ(e.code, PqSendErrorCode::TooLarge);
    }
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

TEST(PqSender, ChangeRoutedToChangeDestination) {
    // With an explicit change destination, all change must land on THAT identity and
    // none on the spending identity. (Default behavior — change to `keys` — is what
    // every other test exercises implicitly.)
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys changeOwner = derivePqWalletKeys(spendSecret(5, 5));

    std::vector<PqSpendInput> inputs = {mkInput(1000, 0x10)};
    PqSendRequest req;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 200});
    req.explicitFee = 50;  // change = 1000 - 200 - 50 = 750
    req.hasChangeDest = true;
    req.changeDest = PqSendOutput{changeOwner.viewPub, changeOwner.spendPub, 0, 0, 0};

    PqSendResult r = buildPqSend(inputs, me, req);
    ASSERT_EQ(r.change, 750u);

    std::vector<CryptoPQ::InputRef> refs(r.tx.inputs.size());
    for (std::size_t i = 0; i < r.tx.inputs.size(); ++i) {
        const PqInput& pin = boost::get<PqInput>(r.tx.inputs[i]);
        std::memcpy(refs[i].prevTxid.data(), pin.prevTxid.data, 32);
        refs[i].prevOutIndex = pin.prevOutIndex;
    }
    CryptoPQ::Hash256 ih = CryptoPQ::inputsHash(refs);

    uint64_t toChangeOwner = 0, toSpender = 0;
    for (std::size_t i = 0; i < r.tx.outputs.size(); ++i) {
        const PqOutput& po = boost::get<PqOutput>(r.tx.outputs[i].target);
        CryptoPQ::PqScanOutput so;
        so.outputIndex = static_cast<uint32_t>(i);
        so.amount = r.tx.outputs[i].amount;
        std::memcpy(so.kemCt.data(), po.kemCt.data(), so.kemCt.size());
        so.encPayload = po.encPayload;
        std::memcpy(so.spendCommit.data(), po.spendCommit.data, 32);
        if (CryptoPQ::scanPqOutput(pqScanKeys(changeOwner), ih, so).has_value())
            toChangeOwner += r.tx.outputs[i].amount;
        if (CryptoPQ::scanPqOutput(pqScanKeys(me), ih, so).has_value())
            toSpender += r.tx.outputs[i].amount;
    }
    EXPECT_EQ(toChangeOwner, 750u);  // all change went to the change destination
    EXPECT_EQ(toSpender, 0u);        // none leaked back to the spender
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

TEST(PqSender, PaymentProofCoversTheRecipientOutputAndExactTotal) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));
    PqSendRequest req;
    req.genesisId = testGenesis();
    req.explicitFee = 1;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 1234567});

    PqSendResult result = buildPqSend({mkInput(1234568, 0x91)}, me, req);
    expectProofsVerify(req, result);
    ASSERT_EQ(result.proofs.size(), 1u);
    ASSERT_EQ(result.proofs[0].entries.size(), 1u);
    EXPECT_EQ(result.proofs[0].entries[0].outputIndex, 0u);
}

TEST(PqSender, MultipleAndDuplicateRecipientRowsStaySeparatedAndExcludeChange) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys a = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys b = derivePqWalletKeys(spendSecret(5, 4));
    PqSendRequest req;
    req.genesisId = testGenesis();
    req.explicitFee = 50;
    req.recipients = {
        PqSendOutput{a.viewPub, a.spendPub, 250},
        PqSendOutput{b.viewPub, b.spendPub, 100},
        PqSendOutput{a.viewPub, a.spendPub, 250}};  // duplicate keys, distinct row

    PqSendResult result = buildPqSend({mkInput(1000, 0x92)}, me, req);
    ASSERT_EQ(result.change, 350u);
    expectProofsVerify(req, result);
    ASSERT_EQ(result.proofs.size(), 3u);
    EXPECT_EQ(result.proofs[0].spendAuthorityHash,
              result.proofs[2].spendAuthorityHash);

    std::set<uint32_t> recipientIndexes;
    for (const auto& proof : result.proofs) {
        for (const auto& entry : proof.entries) {
            EXPECT_TRUE(recipientIndexes.insert(entry.outputIndex).second);
        }
    }
    EXPECT_LT(recipientIndexes.size(), result.tx.outputs.size());  // change excluded
    uint64_t proven = 0;
    for (uint32_t index : recipientIndexes) proven += result.tx.outputs[index].amount;
    EXPECT_EQ(proven, 600u);
}

TEST(PqSender, RecipientOutputsKeepRowOrderAndProvenance) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys a = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys b = derivePqWalletKeys(spendSecret(5, 4));
    PqSendRequest req;
    req.genesisId = testGenesis();
    req.explicitFee = 100;
    req.recipients = {
        PqSendOutput{a.viewPub, a.spendPub, 400000000},
        PqSendOutput{b.viewPub, b.spendPub, 300000000}};

    PqSendResult result = buildPqSend({mkInput(800000100, 0x93)}, me, req);
    ASSERT_EQ(result.tx.outputs.size(), 3u);  // a, b, change
    EXPECT_EQ(result.tx.outputs[0].amount, 400000000u);
    EXPECT_EQ(result.tx.outputs[1].amount, 300000000u);
    EXPECT_EQ(result.tx.outputs[2].amount, result.change);
    expectProofsVerify(req, result);
    ASSERT_EQ(result.proofs.size(), 2u);
    ASSERT_EQ(result.proofs[0].entries.size(), 1u);
    ASSERT_EQ(result.proofs[1].entries.size(), 1u);
    EXPECT_EQ(result.proofs[0].entries[0].outputIndex, 0u);
    EXPECT_EQ(result.proofs[1].entries[0].outputIndex, 1u);
}

TEST(PqSender, SizeRetryShedsSweptInputsAndReturnsOnlyAcceptedWitnesses) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));
    std::vector<PqSpendInput> inputs = {mkInput(20000000, 0x01)};
    for (uint8_t i = 0; i < 40; ++i) inputs.push_back(mkInput(100, static_cast<uint8_t>(0x10 + i)));

    PqSendRequest req;
    req.genesisId = testGenesis();
    req.explicitFee = 100;
    // A huge extra leaves room for the covering input and only part of the sweep:
    // 1 + 8 inputs (~48 KB) + outputs + 215,000 B is over MAX_PQ_TX_SIZE.
    req.extra.assign(215000, 0x5a);
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 10000000});
    PqSendResult result = buildPqSend(inputs, me, req);

    // The sweep was shed until the draft fit; the covering input is never shed.
    EXPECT_LE(toBinaryArray(result.tx).size(), P::MAX_PQ_TX_SIZE);
    EXPECT_GE(result.selected.size(), 1u);
    EXPECT_LT(result.selected.size(), 1u + PQ_SWEEP_MAX_EXTRA_INPUTS);
    EXPECT_EQ(result.selected[0].amount, 20000000u);
    // Verification proves every returned m_j belongs to the accepted final
    // transaction, not a shed draft.
    expectProofsVerify(req, result);
    ASSERT_EQ(result.proofs.size(), 1u);
    ASSERT_EQ(result.proofs[0].entries.size(), 1u);

    // When even the covering inputs alone do not fit, the send is refused.
    req.extra.assign(256000, 0x5a);
    try {
        buildPqSend(inputs, me, req);
        FAIL() << "expected PqSendError";
    } catch (const PqSendError& e) {
        EXPECT_EQ(e.code, PqSendErrorCode::TooLarge);
    }
}

TEST(PqConsolidation, PlansAndBuildsFromTheThirtyTwoSmallestInputs) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(41, 17));
    std::vector<PqSpendInput> inputs;
    for (uint8_t i = 0; i < 32; ++i) inputs.push_back(mkInput(1, i));
    inputs.push_back(mkInput(500, 0x80));
    inputs.push_back(mkInput(1000, 0x90));

    PqConsolidationPlan plan = planPqConsolidation(inputs);
    ASSERT_TRUE(plan.useful());
    EXPECT_EQ(plan.availableInputs, 34u);
    EXPECT_EQ(plan.selectedInputs, 32u);
    EXPECT_EQ(plan.resultingOutputs, 1u);  // 32 inputs -> one 31 au output
    EXPECT_EQ(plan.fee, 1u);
    EXPECT_EQ(plan.amount, 31u);

    PqConsolidationRequest req;
    req.genesisId = testGenesis();
    req.scheme = PqDepositScheme::SingleKeyIndex;
    PqConsolidationResult result = buildPqConsolidation(inputs, me, req);

    EXPECT_EQ(result.plan.selectedInputs, plan.selectedInputs);
    ASSERT_EQ(result.transaction.tx.inputs.size(), 32u);
    ASSERT_EQ(result.transaction.tx.outputs.size(), 1u);
    EXPECT_EQ(outputSum(result.transaction.tx), 31u);
    EXPECT_EQ(result.transaction.change, 0u);
    EXPECT_EQ(result.transaction.fee, 1u);
    for (const auto& selected : result.transaction.selected) {
        EXPECT_EQ(selected.amount, 1u);  // the two large inputs were preserved
    }

    ASSERT_EQ(result.transaction.proofs.size(), 1u);
    PqPaymentProofTransaction proofTx =
        makePqPaymentProofTransaction(result.transaction.tx);
    ResolvedRecipient own{me.viewPub, me.spendPub, 0};
    EXPECT_EQ(verifyPqPaymentProof(
                  result.transaction.proofs[0], req.genesisId, proofTx, own),
              plan.amount);
}

TEST(PqConsolidation, RefusesASingleInput) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(43, 19));
    // One input cannot be merged into fewer outputs; paying a fee for that is
    // never useful and must never be signed.
    std::vector<PqSpendInput> inputs = {mkInput(56, 0x11)};

    PqConsolidationPlan plan = planPqConsolidation(inputs);
    EXPECT_FALSE(plan.useful());
    EXPECT_EQ(plan.availableInputs, 1u);
    EXPECT_EQ(plan.selectedInputs, 0u);
    EXPECT_THROW(buildPqConsolidation(inputs, me), PqSendError);

    // Two inputs are the smallest useful batch: they become exactly one output.
    inputs.push_back(mkInput(56, 0x22));
    PqConsolidationResult two = buildPqConsolidation(inputs, me);
    EXPECT_EQ(two.plan.selectedInputs, 2u);
    ASSERT_EQ(two.transaction.tx.outputs.size(), 1u);
    EXPECT_EQ(two.transaction.tx.outputs[0].amount, 56u + 56u - two.plan.fee);
}

TEST(PqConsolidation, RestrictsToSourceBucketsAndRoutesToTheDestination) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(44, 21));
    std::vector<PqSpendInput> inputs = {
        mkBucketInput(5, 0x11, 3), mkBucketInput(6, 0x12, 3), mkBucketInput(7, 0x13, 3),
        mkBucketInput(500, 0x21, PQ_PRIMARY_DEPOSIT)};

    PqConsolidationRequest req;
    req.scheme = PqDepositScheme::SingleKeyIndex;
    req.sourceBuckets = {3};
    req.hasDestination = true;
    req.destination = PqSendOutput{me.viewPub, me.spendPub, 0, 3 /*T*/, 0};

    PqConsolidationPlan plan = planPqConsolidation(inputs, req);
    ASSERT_TRUE(plan.useful());
    EXPECT_EQ(plan.availableInputs, 3u);  // the primary input is outside the bucket
    EXPECT_EQ(plan.selectedInputs, 3u);
    EXPECT_EQ(plan.amount, 5u + 6u + 7u - plan.fee);

    PqConsolidationResult result = buildPqConsolidation(inputs, me, req);
    ASSERT_EQ(result.transaction.tx.inputs.size(), 3u);
    for (const auto& selected : result.transaction.selected) EXPECT_EQ(selected.depositIndex, 3u);
    ASSERT_EQ(result.transaction.tx.outputs.size(), 1u);
    EXPECT_EQ(result.transaction.tx.outputs[0].amount, plan.amount);

    // The merged output is addressed to the bucket's own routing index T=3, so
    // the funds stay attributed to that deposit after the merge.
    PqPaymentProofTransaction proofTx = makePqPaymentProofTransaction(result.transaction.tx);
    ResolvedRecipient bucket{me.viewPub, me.spendPub, 3};
    EXPECT_EQ(verifyPqPaymentProof(result.transaction.proofs[0], req.genesisId, proofTx, bucket),
              plan.amount);
    const PqOutput& po = boost::get<PqOutput>(result.transaction.tx.outputs[0].target);
    CryptoPQ::PqScanOutput so;
    so.outputIndex = 0;
    so.amount = result.transaction.tx.outputs[0].amount;
    std::memcpy(so.kemCt.data(), po.kemCt.data(), so.kemCt.size());
    so.encPayload = po.encPayload;
    std::memcpy(so.spendCommit.data(), po.spendCommit.data, 32);
    auto owned = CryptoPQ::scanPqOutput(pqScanKeys(me), pqTransactionInputsHash(result.transaction.tx), so);
    ASSERT_TRUE(owned.has_value());
    EXPECT_EQ(owned->subaddrIndexT, 3u);
}

TEST(PqConsolidation, FeeCannotConsumeTheSelectedValue) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(47, 23));
    std::vector<PqSpendInput> inputs = {
        mkInput(1, 0x31), mkInput(1, 0x32)};

    PqConsolidationPlan plan = planPqConsolidation(inputs, 2);
    EXPECT_FALSE(plan.useful());
    EXPECT_EQ(plan.fee, 2u);

    PqConsolidationRequest req;
    req.explicitFee = 2;
    EXPECT_THROW(buildPqConsolidation(inputs, me, req), PqSendError);
}

TEST(PqConsolidation, DeclaresTheDeliverySubtypeForItsSigningHeight) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(53, 31));
    std::vector<PqSpendInput> inputs = {
        mkInput(1, 0x41), mkInput(1, 0x42), mkInput(1, 0x43)};

    PqConsolidationRequest req;
    req.genesisId = testGenesis();
    req.scheme = PqDepositScheme::SingleKeyIndex;
    req.signingHeight = 100;

    // Below the delivery-v2 activation the consolidation is an ordinary TX_PQ.
    req.deliveryV2Height = 101;
    EXPECT_EQ(buildPqConsolidation(inputs, me, req).transaction.tx.txType, TX_PQ);
    // At activation it must declare TX_PQ_V2 like every other wallet transfer,
    // or consensus rejects it (Currency::isPqTransferTypeAllowedAt).
    req.deliveryV2Height = 100;
    EXPECT_EQ(buildPqConsolidation(inputs, me, req).transaction.tx.txType, TX_PQ_V2);
    // The default keeps direct callers on v1, matching PqSendRequest.
    EXPECT_EQ(buildPqConsolidation(inputs, me).transaction.tx.txType, TX_PQ);
}

TEST(PqConsolidation, AggregatedDepositsUseTheirOwnSigningKeys) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(49, 29));
    const auto dep3 = CryptoPQ::deriveDepositSpendKeys(me.seedMaster, 3);
    const auto dep7 = CryptoPQ::deriveDepositSpendKeys(me.seedMaster, 7);
    std::vector<PqSpendInput> inputs = {
        mkBucketInput(4, 0x10, PQ_PRIMARY_DEPOSIT),
        mkBucketInput(4, 0x20, 3),
        mkBucketInput(4, 0x30, 7)};

    PqConsolidationRequest req;
    req.scheme = PqDepositScheme::AggregatedMultikey;
    PqConsolidationResult result = buildPqConsolidation(inputs, me, req);

    ASSERT_EQ(result.transaction.tx.inputs.size(), 3u);
    EXPECT_TRUE(authPubIs(result.transaction.tx, 0, me.spendPub));
    EXPECT_TRUE(authPubIs(result.transaction.tx, 1, dep3.first));
    EXPECT_TRUE(authPubIs(result.transaction.tx, 2, dep7.first));
    EXPECT_LT(result.transaction.tx.outputs.size(), result.transaction.tx.inputs.size());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// --- Signing transcript on the production path -----------------------------
//
// The transcript is chosen from PqSendRequest::signingHeight, which every wallet
// front-end fills with the index of the block the transaction expects to be in.
// These go through buildPqSend, the API the wallets actually call, rather than
// the low-level builder, because the gap this covers was that the production
// path never passed a context at all and so could only ever produce v1.
//
// The boundary is expressed with the constant, not a literal, so these follow
// PQ_TRANSCRIPT_V2_HEIGHT if it is ever scheduled.

namespace {

constexpr uint32_t kActivation = P::PQ_TRANSCRIPT_V2_HEIGHT;

// A spendable input owned by `owner`, plus the resolved view a node would
// reconstruct for it, so checkPqTransactionInputs can verify the signature.
PqSpendInput fundOwned(const PqWalletKeys& owner, uint64_t amount, uint8_t seed,
                       PqResolvedInput& resolvedOut, uint32_t depositIndex = PQ_PRIMARY_DEPOSIT) {
    PqSpendInput in = mkBucketInput(amount, seed, depositIndex);
    CryptoPQ::DsaPublicKey authPub = owner.spendPub;
    if (depositIndex != PQ_PRIMARY_DEPOSIT) {
        authPub = CryptoPQ::deriveDepositSpendKeys(owner.seedMaster, depositIndex).first;
    }
    const CryptoPQ::Hash256 sc = CryptoPQ::spendCommit(authPub, in.rho);
    resolvedOut = PqResolvedInput{};
    std::memcpy(resolvedOut.spendCommit.data, sc.data(), 32);
    resolvedOut.amount = amount;
    resolvedOut.exists = true;
    resolvedOut.isPqOutput = true;
    resolvedOut.isCoinbase = false;
    return in;
}

PqSigningContext contextAt(uint32_t height, const CryptoPQ::Hash256& genesis) {
    return pqSigningContextForHeight(height, genesis);
}

// buildPqSend sorts inputs largest-first, so give the caller the resolved views
// in the order the built transaction actually references them.
std::vector<PqResolvedInput> resolvedInSpendOrder(
    const PqSendResult& result,
    const std::vector<std::pair<PqSpendInput, PqResolvedInput>>& funded) {
    std::vector<PqResolvedInput> out;
    out.reserve(result.selected.size());
    for (const auto& sel : result.selected) {
        bool matched = false;
        for (const auto& f : funded) {
            if (f.first.prevTxid == sel.prevTxid && f.first.prevOutIndex == sel.prevOutIndex) {
                out.push_back(f.second);
                matched = true;
                break;
            }
        }
        EXPECT_TRUE(matched) << "selected input not among the funded set";
    }
    return out;
}

}  // namespace

TEST(PqSenderTranscript, BelowActivationTheWalletSignsV1) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(21, 5));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(22, 6));

    PqResolvedInput resolved;
    PqSpendInput in = fundOwned(me, 5000000, 0x31, resolved);

    PqSendRequest req;
    req.genesisId = testGenesis();
    req.signingHeight = kActivation - 1;
    req.recipients.push_back({to.viewPub, to.spendPub, 1000000});
    PqSendResult r = buildPqSend({in}, me, req);

    std::vector<Crypto::Hash> nf;
    std::string err;
    // Accepted under the rules of the height it was signed for.
    EXPECT_TRUE(checkPqTransactionInputs(r.tx, {resolved}, 0, &nf, &err,
                                         contextAt(kActivation - 1, req.genesisId))) << err;
    // And rejected under v2, which is what makes this a real v1 signature rather
    // than something that happens to satisfy both.
    nf.clear();
    EXPECT_FALSE(checkPqTransactionInputs(r.tx, {resolved}, 0, &nf, &err,
                                          contextAt(kActivation, req.genesisId)));
}

TEST(PqSenderTranscript, AtActivationTheWalletSignsV2) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(23, 7));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(24, 8));

    PqResolvedInput resolved;
    PqSpendInput in = fundOwned(me, 5000000, 0x32, resolved);

    PqSendRequest req;
    req.genesisId = testGenesis();
    req.signingHeight = kActivation;
    req.recipients.push_back({to.viewPub, to.spendPub, 1000000});
    PqSendResult r = buildPqSend({in}, me, req);

    std::vector<Crypto::Hash> nf;
    std::string err;
    EXPECT_TRUE(checkPqTransactionInputs(r.tx, {resolved}, 0, &nf, &err,
                                         contextAt(kActivation, req.genesisId))) << err;
    // A v2 signature must not also satisfy the pre-activation rules.
    nf.clear();
    EXPECT_FALSE(checkPqTransactionInputs(r.tx, {resolved}, 0, &nf, &err,
                                          contextAt(kActivation - 1, req.genesisId)));
}

TEST(PqSenderTranscript, V2SignatureIsBoundToTheChain) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(25, 9));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(26, 10));

    PqResolvedInput resolved;
    PqSpendInput in = fundOwned(me, 5000000, 0x33, resolved);

    PqSendRequest req;
    req.genesisId = testGenesis();
    req.signingHeight = kActivation;
    req.recipients.push_back({to.viewPub, to.spendPub, 1000000});
    PqSendResult r = buildPqSend({in}, me, req);

    CryptoPQ::Hash256 otherChain = req.genesisId;
    otherChain[0] ^= 0xFF;

    std::vector<Crypto::Hash> nf;
    std::string err;
    EXPECT_FALSE(checkPqTransactionInputs(r.tx, {resolved}, 0, &nf, &err,
                                          contextAt(kActivation, otherChain)));
}

// v1 signs one shared digest, so two inputs of the same owner are interchangeable.
// v2 binds each signature to its own index; reordering must therefore break it.
TEST(PqSenderTranscript, V2SignatureIsBoundToTheInputIndex) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(27, 11));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(28, 12));

    std::vector<std::pair<PqSpendInput, PqResolvedInput>> funded(2);
    funded[0].first = fundOwned(me, 4000000, 0x41, funded[0].second);
    funded[1].first = fundOwned(me, 3000000, 0x42, funded[1].second);

    PqSendRequest req;
    req.genesisId = testGenesis();
    req.signingHeight = kActivation;
    req.recipients.push_back({to.viewPub, to.spendPub, 6000000});
    PqSendResult r = buildPqSend({funded[0].first, funded[1].first}, me, req);
    ASSERT_EQ(r.tx.inputs.size(), 2u);

    std::vector<PqResolvedInput> resolved = resolvedInSpendOrder(r, funded);
    ASSERT_EQ(resolved.size(), 2u);

    std::vector<Crypto::Hash> nf;
    std::string err;
    ASSERT_TRUE(checkPqTransactionInputs(r.tx, resolved, 0, &nf, &err,
                                         contextAt(kActivation, req.genesisId))) << err;

    // Move each input to the other index, carrying its resolved view with it, so
    // the ONLY thing that changed is which index each signature sits at.
    Transaction swapped = r.tx;
    std::swap(swapped.inputs[0], swapped.inputs[1]);
    std::vector<PqResolvedInput> swappedResolved = {resolved[1], resolved[0]};

    nf.clear();
    EXPECT_FALSE(checkPqTransactionInputs(swapped, swappedResolved, 0, &nf, &err,
                                          contextAt(kActivation, req.genesisId)));
}

// Every input of a multi-input spend must carry its own correct v2 context, and
// that has to hold when the inputs are authorized by DIFFERENT keys.
TEST(PqSenderTranscript, MultiKeyDepositSpendSignsEveryInputUnderV2) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(29, 13));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(30, 14));

    std::vector<std::pair<PqSpendInput, PqResolvedInput>> funded(3);
    funded[0].first = fundOwned(me, 4000000, 0x51, funded[0].second, PQ_PRIMARY_DEPOSIT);
    funded[1].first = fundOwned(me, 3000000, 0x52, funded[1].second, 3);
    funded[2].first = fundOwned(me, 2000000, 0x53, funded[2].second, 7);

    PqSendRequest req;
    req.genesisId = testGenesis();
    req.signingHeight = kActivation;
    req.scheme = PqDepositScheme::AggregatedMultikey;
    req.recipients.push_back({to.viewPub, to.spendPub, 8000000});
    PqSendResult r = buildPqSend(
        {funded[0].first, funded[1].first, funded[2].first}, me, req);
    ASSERT_EQ(r.tx.inputs.size(), 3u);

    std::vector<PqResolvedInput> resolved = resolvedInSpendOrder(r, funded);
    std::vector<Crypto::Hash> nf;
    std::string err;
    EXPECT_TRUE(checkPqTransactionInputs(r.tx, resolved, 0, &nf, &err,
                                         contextAt(kActivation, req.genesisId))) << err;
}

// A multi-recipient, multi-input send must carry the requested context on every
// signature.
TEST(PqSenderTranscript, LargeMultiOutputSendKeepsTheRequestedContext) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(31, 15));
    PqWalletKeys a = derivePqWalletKeys(spendSecret(32, 16));
    PqWalletKeys b = derivePqWalletKeys(spendSecret(33, 17));

    std::vector<std::pair<PqSpendInput, PqResolvedInput>> funded(2);
    funded[0].first = fundOwned(me, 900000000, 0x61, funded[0].second);
    funded[1].first = fundOwned(me, 800000000, 0x62, funded[1].second);

    PqSendRequest req;
    req.genesisId = testGenesis();
    req.signingHeight = kActivation;
    req.recipients.push_back({a.viewPub, a.spendPub, 777777777});
    req.recipients.push_back({b.viewPub, b.spendPub, 888888888});
    PqSendResult r = buildPqSend({funded[0].first, funded[1].first}, me, req);
    ASSERT_EQ(r.tx.outputs.size(), 3u);  // two recipients + change

    std::vector<PqResolvedInput> resolved = resolvedInSpendOrder(r, funded);
    std::vector<Crypto::Hash> nf;
    std::string err;
    EXPECT_TRUE(checkPqTransactionInputs(r.tx, resolved, 0, &nf, &err,
                                         contextAt(kActivation, req.genesisId))) << err;
    nf.clear();
    EXPECT_FALSE(checkPqTransactionInputs(r.tx, resolved, 0, &nf, &err,
                                          contextAt(kActivation - 1, req.genesisId)));
}

// The default is the pre-activation transcript, so a caller that does not set a
// height cannot accidentally produce a transaction the current network rejects.
TEST(PqSenderTranscript, DefaultRequestSignsUnderV1) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(34, 18));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(35, 19));

    PqResolvedInput resolved;
    PqSpendInput in = fundOwned(me, 5000000, 0x71, resolved);

    PqSendRequest req;
    req.genesisId = testGenesis();
    req.recipients.push_back({to.viewPub, to.spendPub, 1000000});
    EXPECT_EQ(req.signingHeight, 0u);
    PqSendResult r = buildPqSend({in}, me, req);

    std::vector<Crypto::Hash> nf;
    std::string err;
    EXPECT_TRUE(checkPqTransactionInputs(r.tx, {resolved}, 0, &nf, &err,
                                         contextAt(0, req.genesisId))) << err;
}
