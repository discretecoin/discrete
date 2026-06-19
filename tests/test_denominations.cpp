// Copyright (c) 2026, The Karbo developers
//
// Tests for the canonical Discrete denomination table (include/Denominations.h):
// shape, membership/index lookup, and greedy decomposition.

#include "gtest/gtest.h"

#include "Denominations.h"

#include <cstdint>
#include <numeric>
#include <vector>

using namespace CryptoNote;

TEST(Denominations, TableShape) {
    EXPECT_EQ(DENOMINATION_COUNT, 64u);
    EXPECT_EQ(DENOMINATIONS.size(), 64u);
    EXPECT_EQ(MIN_CT_DENOMINATION, 1u);            // 0.01 XDS at 2 decimals
    EXPECT_EQ(MAX_DENOMINATION, 10000000u);        // 100,000 XDS cap
    // Strictly ascending.
    for (size_t i = 1; i < DENOMINATIONS.size(); ++i) {
        EXPECT_LT(DENOMINATIONS[i - 1], DENOMINATIONS[i]) << "at index " << i;
    }
    // 7 decades of {1..9} then the cap: every non-cap entry is d*10^k, d in 1..9.
    for (size_t i = 0; i + 1 < DENOMINATIONS.size(); ++i) {
        uint64_t v = DENOMINATIONS[i];
        while (v % 10 == 0) v /= 10;
        EXPECT_GE(v, 1u);
        EXPECT_LE(v, 9u) << "non-canonical mantissa at index " << i;
    }
}

TEST(Denominations, MembershipAndIndex) {
    for (size_t i = 0; i < DENOMINATIONS.size(); ++i) {
        EXPECT_TRUE(isCanonicalDenomination(DENOMINATIONS[i]));
        EXPECT_EQ(denominationIndex(DENOMINATIONS[i]), static_cast<int>(i));
    }
    EXPECT_FALSE(isCanonicalDenomination(0));
    EXPECT_FALSE(isCanonicalDenomination(11));     // 1*10 + 1 is not canonical
    EXPECT_FALSE(isCanonicalDenomination(15));
    EXPECT_FALSE(isCanonicalDenomination(12345));
    EXPECT_EQ(denominationIndex(11), -1);
}

TEST(Denominations, DecomposeSumsExactly) {
    const std::vector<uint64_t> cases = {1, 9, 11, 99, 100, 250, 12345, 9000000, 10000000};
    for (uint64_t amount : cases) {
        auto parts = decomposeToDenominations(amount);
        ASSERT_FALSE(parts.empty()) << "amount " << amount;
        uint64_t sum = std::accumulate(parts.begin(), parts.end(), uint64_t{0});
        EXPECT_EQ(sum, amount) << "amount " << amount;
        for (uint64_t p : parts) {
            EXPECT_TRUE(isCanonicalDenomination(p)) << "non-canonical piece " << p << " for " << amount;
        }
    }
}

TEST(Denominations, DecomposeGreedyShape) {
    // 250 au = 0x... -> 200 + 50 (two pieces).
    auto p = decomposeToDenominations(250);
    ASSERT_EQ(p.size(), 2u);
    // Pieces are emitted largest-first by the greedy loop.
    EXPECT_EQ(p[0], 200u);
    EXPECT_EQ(p[1], 50u);

    // 99 au -> 90 + 9.
    auto q = decomposeToDenominations(99);
    ASSERT_EQ(q.size(), 2u);
    EXPECT_EQ(q[0], 90u);
    EXPECT_EQ(q[1], 9u);
}

TEST(Denominations, AboveCapUsesMultipleCapPieces) {
    // 25,000,000 au = 2 * cap (10,000,000) + 5,000,000.
    auto p = decomposeToDenominations(25000000);
    uint64_t sum = std::accumulate(p.begin(), p.end(), uint64_t{0});
    EXPECT_EQ(sum, 25000000u);
    int caps = 0;
    for (uint64_t v : p) if (v == MAX_DENOMINATION) ++caps;
    EXPECT_EQ(caps, 2);
}

TEST(Denominations, DecomposeZeroThrows) {
    EXPECT_THROW(decomposeToDenominations(0), std::invalid_argument);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
