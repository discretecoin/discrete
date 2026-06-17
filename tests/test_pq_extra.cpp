// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Tests for PQ Phase 1 consensus taxonomy (spec §1.2 / §4 / §11):
//   * version-gated tx_extra size cap (maxExtraSize)
//   * PQ tx-subtype enum values
//   * new tx_extra tags: PQ account registration (0x05) and PoW (0x06)
//   * PoW-tag-last invariant for free-fee registration

#include "gtest/gtest.h"

#include "CryptoNoteConfig.h"
#include "PqTxType.h"
#include "CryptoNoteCore/TransactionExtra.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace CryptoNote;

TEST(PqTaxonomy, TransactionVersion) {
    // Discrete has a single transaction version: PQ is active from genesis, so
    // TRANSACTION_VERSION_1 is the one and only (and current) version.
    EXPECT_EQ(1, TRANSACTION_VERSION_1);
    EXPECT_EQ(TRANSACTION_VERSION_1, CURRENT_TRANSACTION_VERSION);
}

TEST(PqTaxonomy, MaxExtraSizeIsPqSizeForAllVersions) {
    // Discrete is PQ from genesis — the extra-size cap is NOT version-gated; it
    // is always the PQ cap, large enough to hold a 1184-byte view key.
    EXPECT_EQ(parameters::MAX_EXTRA_SIZE_PQ, maxExtraSize(1));
    EXPECT_EQ(parameters::MAX_EXTRA_SIZE_PQ, maxExtraSize(6));
    EXPECT_EQ(parameters::MAX_EXTRA_SIZE_PQ, maxExtraSize(7));
    EXPECT_GT(maxExtraSize(1), TX_EXTRA_PQ_VIEW_PUBKEY_SIZE + 1);
}

TEST(PqTaxonomy, SubtypeEnumValues) {
    EXPECT_EQ(0x01, TX_PQ);
    // 0x02 is permanently reserved (no named constant; consensus rejects it).
    EXPECT_EQ(0x03, TX_FREE_REG);
}

TEST(PqExtra, PqAccountRegistrationRoundTrip) {
    std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE> viewPub;
    for (size_t i = 0; i < viewPub.size(); ++i) viewPub[i] = static_cast<uint8_t>(i * 7 + 1);
    std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> spendPub;
    for (size_t i = 0; i < spendPub.size(); ++i) spendPub[i] = static_cast<uint8_t>(i * 3 + 5);

    std::vector<uint8_t> extra;
    ASSERT_TRUE(addPqAccountRegistrationToExtra(extra, viewPub, spendPub));
    EXPECT_EQ(extra.size(), 1u + viewPub.size() + spendPub.size());

    TransactionExtraPqAccountRegistration reg;
    ASSERT_TRUE(getPqAccountRegistrationFromExtra(extra, reg));
    EXPECT_EQ(reg.viewPub, viewPub);
    EXPECT_EQ(reg.spendPub, spendPub);
}

TEST(PqExtra, PowTagRoundTripLittleEndianNonce) {
    TransactionExtraPow pow;
    for (size_t i = 0; i < sizeof(pow.refBlockHash.data); ++i)
        pow.refBlockHash.data[i] = static_cast<uint8_t>(0xA0 + i);
    pow.nonce = 0x0102030405060708ull;

    std::vector<uint8_t> extra;
    ASSERT_TRUE(appendPowTagToExtra(extra, pow));
    EXPECT_EQ(extra.size(), 1u + 32u + 8u);
    // nonce is the final 8 bytes, little-endian.
    EXPECT_EQ(0x08, extra[extra.size() - 8]);
    EXPECT_EQ(0x01, extra[extra.size() - 1]);

    TransactionExtraPow got;
    ASSERT_TRUE(getPowTagFromExtra(extra, got));
    EXPECT_EQ(got.nonce, pow.nonce);
    EXPECT_EQ(0, std::memcmp(got.refBlockHash.data, pow.refBlockHash.data, 32));
}

TEST(PqExtra, PowTagLastFieldDetection) {
    std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE> viewPub{};
    std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> spendPub{};

    // registration then PoW last -> ok.
    {
        std::vector<uint8_t> extra;
        addPqAccountRegistrationToExtra(extra, viewPub, spendPub);
        TransactionExtraPow pow{}; pow.nonce = 42;
        appendPowTagToExtra(extra, pow);
        EXPECT_TRUE(isPowTagLastField(extra));
    }
    // PoW then a pubkey after it -> not last.
    {
        std::vector<uint8_t> extra;
        TransactionExtraPow pow{}; pow.nonce = 42;
        appendPowTagToExtra(extra, pow);
        Crypto::PublicKey pk{};
        addTransactionPublicKeyToExtra(extra, pk);
        EXPECT_FALSE(isPowTagLastField(extra));
    }
    // No PoW tag at all -> false.
    {
        std::vector<uint8_t> extra;
        addPqAccountRegistrationToExtra(extra, viewPub, spendPub);
        EXPECT_FALSE(isPowTagLastField(extra));
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
