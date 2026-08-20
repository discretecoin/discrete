// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Tests for receiver-side PQ scanning (spec §7, ownership-fixed). Covers:
// recognizing one's own outputs, ignoring others' outputs (silent), amount
// tamper, spend_commit tamper, multi-output selection, and that scanning needs
// only the view secret + spend public key (view-only capability).

#include "gtest/gtest.h"

#include "crypto_pq/PqScan.h"
#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqSeed.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqAead.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace CryptoPQ;

namespace {

template <std::size_t N> std::array<uint8_t, N> pat(uint8_t a, uint8_t b) {
    std::array<uint8_t, N> r;
    for (std::size_t i = 0; i < N; ++i) r[i] = static_cast<uint8_t>(i * a + b);
    return r;
}

std::vector<InputRef> fixedInputs() {
    std::vector<InputRef> ins(2);
    ins[0].prevTxid = pat<32>(1, 0);   ins[0].prevOutIndex = 7;
    ins[1].prevTxid = pat<32>(255, 5); ins[1].prevOutIndex = 0x01020304;
    return ins;
}

// Build an on-chain scan output for recipient (viewPub, spendPub).
PqScanOutput buildScanOutput(const KemPublicKey& viewPub, const DsaPublicKey& spendPub,
                             const Hash256& ih, uint32_t idx, uint64_t amount,
                             uint64_t T = 0) {
    PqBuiltOutput b = buildPqOutput(viewPub, spendPub, ih, idx, amount, T);
    PqScanOutput o;
    o.outputIndex = idx;
    o.amount = amount;
    o.kemCt = b.kemCt;
    o.encPayload = b.encPayload;
    o.spendCommit = b.spendCommit;
    return o;
}

PqScanKeys scanKeysFor(const SeedMaster& m) {
    PqScanKeys k;
    k.viewSk  = deriveViewKeys(m).second;
    k.spendPub = deriveSpendKeys(m).first;
    return k;
}

}  // namespace

TEST(PqScan, RecognizesOwnOutput) {
    SeedMaster m = pat<32>(2, 7);
    auto view = deriveViewKeys(m);
    auto spend = deriveSpendKeys(m);
    Hash256 ih = inputsHash(fixedInputs());

    PqScanOutput o = buildScanOutput(view.first, spend.first, ih, 4, 7777, /*T=*/0);

    auto owned = scanPqOutput(scanKeysFor(m), ih, o);
    ASSERT_TRUE(owned.has_value());
    EXPECT_EQ(owned->outputIndex, 4u);
    EXPECT_EQ(owned->amount, 7777u);
    EXPECT_EQ(owned->subaddrIndexT, 0u);
    EXPECT_EQ(owned->outContext, outContext(ih, o.kemCt, 4));
    // The recovered rho must reconstruct the on-chain spend_commit.
    EXPECT_EQ(spendCommit(spend.first, owned->rho), o.spendCommit);
}

TEST(PqScan, RecognizesAnyTInOneShotNoEnumeration) {
    // outContext-v2: T is read back from the decrypted payload, not guessed.
    // A single scanPqOutput call (no T parameter at all) must recognize an
    // output built at any T, including a large, non-sequential value — this
    // is the whole point of the fix (see PqDerive.h / PqScan.h).
    SeedMaster m = pat<32>(2, 7);
    auto view = deriveViewKeys(m);
    auto spend = deriveSpendKeys(m);
    Hash256 ih = inputsHash(fixedInputs());

    PqScanOutput o7 = buildScanOutput(view.first, spend.first, ih, 2, 9999, /*T=*/7);
    auto owned7 = scanPqOutput(scanKeysFor(m), ih, o7);
    ASSERT_TRUE(owned7.has_value());
    EXPECT_EQ(owned7->subaddrIndexT, 7u);
    EXPECT_EQ(owned7->amount, 9999u);

    const uint64_t bigT = 0xA1B2C3D4E5F60708ull;
    PqScanOutput oBig = buildScanOutput(view.first, spend.first, ih, 3, 1234, bigT);
    auto ownedBig = scanPqOutput(scanKeysFor(m), ih, oBig);
    ASSERT_TRUE(ownedBig.has_value());
    EXPECT_EQ(ownedBig->subaddrIndexT, bigT);

    // A different wallet's keys must not recognize either output.
    SeedMaster mOther = pat<32>(9, 5);
    EXPECT_FALSE(scanPqOutput(scanKeysFor(mOther), ih, o7).has_value());
    EXPECT_FALSE(scanPqOutput(scanKeysFor(mOther), ih, oBig).has_value());
}

TEST(PqScan, LegacyTZeroOutputStillRecognized) {
    // Fast-path fallback: an output built under the legacy (pre-v2) derivation
    // at T=0 — the way every output was minted before the v2 activation —
    // must still be recognized by the default scan path.
    SeedMaster m = pat<32>(2, 7);
    auto view = deriveViewKeys(m);
    auto spend = deriveSpendKeys(m);
    Hash256 ih = inputsHash(fixedInputs());

    auto encapsulation = kem_encaps(view.first);
    Rho rho = pat<32>(3, 9);
    Hash256 legacyOc = legacyOutContextV1(ih, encapsulation.first, 1, /*T=*/0);
    Hash256 aeadKey = deriveAeadKey(encapsulation.second, legacyOc);
    AeadNonce nonce{};
    std::array<uint8_t, 40> aad{};
    std::memcpy(aad.data(), legacyOc.data(), 32);
    const uint64_t amount = 555;
    for (int i = 0; i < 8; ++i) aad[32 + i] = static_cast<uint8_t>((amount >> (8 * i)) & 0xFF);
    std::array<uint8_t, 40> plaintext{};
    std::memcpy(plaintext.data(), rho.data(), 32);  // T=0 -> trailing 8 bytes stay zero

    PqScanOutput o;
    o.outputIndex = 1;
    o.amount = amount;
    o.kemCt = encapsulation.first;
    o.encPayload = aead_encrypt(aeadKey, nonce, aad.data(), aad.size(), plaintext.data(), plaintext.size());
    o.spendCommit = spendCommit(spend.first, rho);

    auto owned = scanPqOutput(scanKeysFor(m), ih, o);
    ASSERT_TRUE(owned.has_value());
    EXPECT_EQ(owned->subaddrIndexT, 0u);
    EXPECT_EQ(owned->amount, amount);
    EXPECT_EQ(spendCommit(spend.first, owned->rho), o.spendCommit);
}

TEST(PqScan, LegacyTWindowPathsRespectExclusiveBound) {
    // Released pre-v2 senders used the destination's real T in legacy
    // outContext. Exercise both the low-level recovery primitive and the
    // combined current-first compatibility path.
    SeedMaster m = pat<32>(2, 7);
    auto view = deriveViewKeys(m);
    auto spend = deriveSpendKeys(m);
    Hash256 ih = inputsHash(fixedInputs());

    auto encapsulation = kem_encaps(view.first);
    Rho rho = pat<32>(4, 2);
    const uint64_t legacyT = 5;
    Hash256 legacyOc = legacyOutContextV1(ih, encapsulation.first, 1, legacyT);
    Hash256 aeadKey = deriveAeadKey(encapsulation.second, legacyOc);
    AeadNonce nonce{};
    std::array<uint8_t, 40> aad{};
    std::memcpy(aad.data(), legacyOc.data(), 32);
    const uint64_t amount = 42;
    for (int i = 0; i < 8; ++i) aad[32 + i] = static_cast<uint8_t>((amount >> (8 * i)) & 0xFF);
    std::array<uint8_t, 40> plaintext{};
    std::memcpy(plaintext.data(), rho.data(), 32);
    for (int i = 0; i < 8; ++i)
        plaintext[32 + i] = static_cast<uint8_t>((legacyT >> (8 * i)) & 0xFF);

    PqScanOutput o;
    o.outputIndex = 1;
    o.amount = amount;
    o.kemCt = encapsulation.first;
    o.encPayload = aead_encrypt(aeadKey, nonce, aad.data(), aad.size(), plaintext.data(), plaintext.size());
    o.spendCommit = spendCommit(spend.first, rho);

    // The default fast path (v2 + legacy-T0) must NOT find it.
    EXPECT_FALSE(scanPqOutput(scanKeysFor(m), ih, o).has_value());

    // The exclusive bound must not scan T=5 when maxT is 5.
    EXPECT_FALSE(scanPqOutputWithLegacyTWindow(
        scanKeysFor(m), ih, o, /*maxT=*/legacyT).has_value());

    // maxT=6 includes T=5. The combined path tries current/T0 first, then the
    // bounded legacy range using the same decapsulated shared secret.
    auto owned = scanPqOutputWithLegacyTWindow(
        scanKeysFor(m), ih, o, /*maxT=*/legacyT + 1);
    ASSERT_TRUE(owned.has_value());
    EXPECT_EQ(owned->subaddrIndexT, legacyT);

    auto legacyOnly = scanPqOutputLegacyTWindow(
        scanKeysFor(m), ih, o, /*maxT=*/legacyT + 1);
    ASSERT_TRUE(legacyOnly.has_value());
    EXPECT_EQ(legacyOnly->subaddrIndexT, legacyT);
}

TEST(PqScan, IgnoresOthersOutput) {
    SeedMaster mA = pat<32>(2, 7);
    SeedMaster mB = pat<32>(3, 9);  // different wallet
    auto viewA = deriveViewKeys(mA);
    auto spendA = deriveSpendKeys(mA);
    Hash256 ih = inputsHash(fixedInputs());

    // Output addressed to A.
    PqScanOutput o = buildScanOutput(viewA.first, spendA.first, ih, 1, 500);

    // B scans it -> not recognized (silent).
    EXPECT_FALSE(scanPqOutput(scanKeysFor(mB), ih, o).has_value());
    // A still recognizes it.
    EXPECT_TRUE(scanPqOutput(scanKeysFor(mA), ih, o).has_value());
}

TEST(PqScan, AmountTamperNotRecognized) {
    SeedMaster m = pat<32>(2, 7);
    auto view = deriveViewKeys(m);
    auto spend = deriveSpendKeys(m);
    Hash256 ih = inputsHash(fixedInputs());

    PqScanOutput o = buildScanOutput(view.first, spend.first, ih, 0, 1000);
    o.amount += 1;  // attacker edits the on-chain amount

    EXPECT_FALSE(scanPqOutput(scanKeysFor(m), ih, o).has_value());
}

TEST(PqScan, SpendCommitTamperDiscarded) {
    // AEAD still succeeds (encPayload intact) but the ownership commit no longer
    // matches -> discarded at the final gate.
    SeedMaster m = pat<32>(2, 7);
    auto view = deriveViewKeys(m);
    auto spend = deriveSpendKeys(m);
    Hash256 ih = inputsHash(fixedInputs());

    PqScanOutput o = buildScanOutput(view.first, spend.first, ih, 0, 1000);
    o.spendCommit.data()[0] ^= 0xFF;

    EXPECT_FALSE(scanPqOutput(scanKeysFor(m), ih, o).has_value());
}

TEST(PqScan, WrongInputsHashNotRecognized) {
    // out_context binds inputs_hash; scanning with the wrong inputs_hash fails.
    SeedMaster m = pat<32>(2, 7);
    auto view = deriveViewKeys(m);
    auto spend = deriveSpendKeys(m);
    Hash256 ih = inputsHash(fixedInputs());

    PqScanOutput o = buildScanOutput(view.first, spend.first, ih, 2, 9);
    Hash256 wrong = ih; wrong.data()[0] ^= 0x01;
    EXPECT_FALSE(scanPqOutput(scanKeysFor(m), wrong, o).has_value());
}

TEST(PqScan, MultiOutputSelectsOwned) {
    SeedMaster mA = pat<32>(2, 7);
    SeedMaster mB = pat<32>(8, 1);
    auto viewA = deriveViewKeys(mA);
    auto spendA = deriveSpendKeys(mA);
    auto viewB = deriveViewKeys(mB);
    auto spendB = deriveSpendKeys(mB);
    Hash256 ih = inputsHash(fixedInputs());

    std::vector<PqScanOutput> outs;
    outs.push_back(buildScanOutput(viewB.first, spendB.first, ih, 0, 10));  // B's
    outs.push_back(buildScanOutput(viewA.first, spendA.first, ih, 1, 20));  // A's
    outs.push_back(buildScanOutput(viewB.first, spendB.first, ih, 2, 30));  // B's
    outs.push_back(buildScanOutput(viewA.first, spendA.first, ih, 3, 40));  // A's

    auto ownedA = scanPqOutputs(scanKeysFor(mA), ih, outs);
    ASSERT_EQ(ownedA.size(), 2u);
    EXPECT_EQ(ownedA[0].outputIndex, 1u);
    EXPECT_EQ(ownedA[0].amount, 20u);
    EXPECT_EQ(ownedA[1].outputIndex, 3u);
    EXPECT_EQ(ownedA[1].amount, 40u);
}

// --- Aggregated (exchange) scanning: shared view key, many deposit spend keys -

TEST(PqScan, AggregateRecognizesCorrectDeposit) {
    // One shared view keypair, three deposit spend keypairs.
    auto view = deriveViewKeys(pat<32>(2, 7));
    auto dep0 = deriveSpendKeys(pat<32>(10, 1));
    auto dep1 = deriveSpendKeys(pat<32>(20, 2));
    auto dep2 = deriveSpendKeys(pat<32>(30, 3));
    std::vector<DsaPublicKey> spendPubs = {dep0.first, dep1.first, dep2.first};

    Hash256 ih = inputsHash(fixedInputs());
    // An output paid to deposit #1 (shared viewPub + dep1 spendPub). A Spec-1
    // deposit address is a plain PQ address, so the sender uses subaddress T=0;
    // the aggregate scanner routes by which deposit spend key the output commits to.
    PqScanOutput o = buildScanOutput(view.first, dep1.first, ih, 5, 4242, /*T=*/0);

    auto owned = scanPqOutputAggregate(view.second, spendPubs, ih, o);
    ASSERT_TRUE(owned.has_value());
    EXPECT_EQ(owned->spendPubIndex, 1u);          // routed to deposit #1 by spend key
    EXPECT_EQ(owned->record.subaddrIndexT, 0u);   // Spec-1 deposits are subaddress 0
    EXPECT_EQ(owned->record.amount, 4242u);
    EXPECT_EQ(owned->record.outputIndex, 5u);
    EXPECT_EQ(spendCommit(dep1.first, owned->record.rho), o.spendCommit);
}

TEST(PqScan, AggregateRoutesEachDepositToItsOwnKey) {
    // Three deposits under one shared view key must each route to the right index.
    auto view = deriveViewKeys(pat<32>(2, 7));
    auto dep0 = deriveSpendKeys(pat<32>(10, 1));
    auto dep1 = deriveSpendKeys(pat<32>(20, 2));
    auto dep2 = deriveSpendKeys(pat<32>(30, 3));
    std::vector<DsaPublicKey> spendPubs = {dep0.first, dep1.first, dep2.first};
    Hash256 ih = inputsHash(fixedInputs());

    const DsaPublicKey* deps[3] = {&dep0.first, &dep1.first, &dep2.first};
    for (uint32_t i = 0; i < 3; ++i) {
        PqScanOutput o = buildScanOutput(view.first, *deps[i], ih, i, 100 + i, /*T=*/0);
        auto owned = scanPqOutputAggregate(view.second, spendPubs, ih, o);
        ASSERT_TRUE(owned.has_value());
        EXPECT_EQ(owned->spendPubIndex, i);
        EXPECT_EQ(owned->record.amount, 100u + i);
    }
}

TEST(PqScan, AggregateIgnoresOtherService) {
    auto viewA = deriveViewKeys(pat<32>(2, 7));
    auto depA  = deriveSpendKeys(pat<32>(10, 1));
    auto viewB = deriveViewKeys(pat<32>(4, 9));  // different service view key
    auto depB  = deriveSpendKeys(pat<32>(40, 4));

    Hash256 ih = inputsHash(fixedInputs());
    // B's deposit: T=0 (only one deposit key).
    PqScanOutput o = buildScanOutput(viewB.first, depB.first, ih, 0, 10, /*T=*/0);

    // Service A (its viewSk + its deposit keys) must not recognize it.
    std::vector<DsaPublicKey> aKeys = {depA.first};
    EXPECT_FALSE(scanPqOutputAggregate(viewA.second, aKeys, ih, o).has_value());
}

TEST(PqScan, AggregateAmountTamperNotRecognized) {
    auto view = deriveViewKeys(pat<32>(2, 7));
    auto dep = deriveSpendKeys(pat<32>(10, 1));
    std::vector<DsaPublicKey> spendPubs = {dep.first};

    Hash256 ih = inputsHash(fixedInputs());
    PqScanOutput o = buildScanOutput(view.first, dep.first, ih, 0, 1000, /*T=*/0);
    o.amount += 1;  // attacker edits the on-chain amount
    EXPECT_FALSE(scanPqOutputAggregate(view.second, spendPubs, ih, o).has_value());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
