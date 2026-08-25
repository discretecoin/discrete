// Copyright (c) 2026, The Discrete developers
//
// Tests for the common engine-agnostic PQ sender (src/Wallet/PqSender): input
// selection, canonical denomination decomposition, the flat fee (MINIMUM_FEE +
// tx_extra surcharge), change, and the consensus size/count caps. The sender is
// the single deterministic spend path used by every front-end.

#include "gtest/gtest.h"

#include "Wallet/PqSender.h"
#include "Wallet/PqWallet.h"
#include "Wallet/PqTransactionBuilder.h"
#include "CryptoNoteCore/PqValidation.h"
#include "Denominations.h"
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

TEST(PqSender, CoarsensToOutputCap) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));

    // 700,000,000 au decomposes to 70 pieces of the 10,000,000 cap denomination, which is
    // > MAX_PQ_OUTPUTS_PER_TX, so the sender must coarsen the recipient group down to fit.
    // explicitFee keeps change 0.
    const uint64_t amount = 700000000;
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

TEST(PqSender, DecomposedPaymentProofCoversEveryRecipientOutputAndExactTotal) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));
    PqSendRequest req;
    req.genesisId = testGenesis();
    req.explicitFee = 1;
    req.recipients.push_back(PqSendOutput{to.viewPub, to.spendPub, 1234567});

    PqSendResult result = buildPqSend({mkInput(1234568, 0x91)}, me, req);
    expectProofsVerify(req, result);
    ASSERT_EQ(result.proofs.size(), 1u);
    EXPECT_EQ(result.proofs[0].entries.size(), result.tx.outputs.size());
    for (std::size_t i = 0; i < result.proofs[0].entries.size(); ++i)
        EXPECT_EQ(result.proofs[0].entries[i].outputIndex, i);
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

TEST(PqSender, CoarseningPreservesRecipientProvenance) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys a = derivePqWalletKeys(spendSecret(7, 3));
    PqWalletKeys b = derivePqWalletKeys(spendSecret(5, 4));
    PqSendRequest req;
    req.genesisId = testGenesis();
    req.explicitFee = 100;
    req.recipients = {
        PqSendOutput{a.viewPub, a.spendPub, 400000000},
        PqSendOutput{b.viewPub, b.spendPub, 400000000}};

    PqSendResult result = buildPqSend({mkInput(800000100, 0x93)}, me, req);
    EXPECT_LE(result.tx.outputs.size(), P::MAX_PQ_OUTPUTS_PER_TX);
    expectProofsVerify(req, result);
    ASSERT_EQ(result.proofs.size(), 2u);
    std::set<uint32_t> first;
    for (const auto& entry : result.proofs[0].entries) first.insert(entry.outputIndex);
    for (const auto& entry : result.proofs[1].entries)
        EXPECT_EQ(first.count(entry.outputIndex), 0u);
}

TEST(PqSender, SizeRetryReturnsOnlyAcceptedTransactionWitnesses) {
    PqWalletKeys me = derivePqWalletKeys(spendSecret(9, 1));
    PqWalletKeys to = derivePqWalletKeys(spendSecret(7, 3));
    std::vector<PqSpendInput> inputs;
    for (uint8_t i = 0; i < 32; ++i) inputs.push_back(mkInput(20000000, i));

    PqSendRequest req;
    req.genesisId = testGenesis();
    req.explicitFee = 100;
    req.extra.assign(30000, 0x5a);  // force the initial 64-output draft over 256 KiB
    req.recipients.push_back(
        PqSendOutput{to.viewPub, to.spendPub, 639999900});
    PqSendResult result = buildPqSend(inputs, me, req);

    // Thirty-two PQ input signatures plus tx_extra leave too little room for the initial 64-output
    // draft, so buildFitting must retry with fewer outputs. Verification proves
    // every returned m_j belongs to the accepted final transaction, not a draft.
    EXPECT_LT(result.tx.outputs.size(), P::MAX_PQ_OUTPUTS_PER_TX);
    EXPECT_LE(toBinaryArray(result.tx).size(), P::MAX_PQ_TX_SIZE);
    expectProofsVerify(req, result);
    ASSERT_EQ(result.proofs.size(), 1u);
    EXPECT_EQ(result.proofs[0].entries.size(), result.tx.outputs.size());
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

// buildFitting may rebuild the draft several times to fit the size cap. Each
// rebuild has to reuse the requested context; a send large enough to decompose
// into many outputs exercises that path.
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
    ASSERT_GT(r.tx.outputs.size(), 2u) << "expected a multi-denomination decomposition";

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
