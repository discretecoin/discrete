// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// PQ (v2 TX_PQ) nullifiers are stored in the SAME type-agnostic spent-key set as
// classical/CT key images: a nullifier is just a 32-byte spend tag, and the two
// value spaces cannot collide (SHA3 hash vs EC-point key image, neither
// attacker-chosen). Blockchain routes both KeyInput key images and PqInput
// nullifiers through putSpentKey/hasSpentKey/removeSpentKey. These tests
// exercise that unified set with nullifier-shaped keys: insert / lookup /
// remove, and the reorg property that removing a tag (block pop) lets the same
// tag be re-inserted on a competing chain.

#include "gtest/gtest.h"

#include "CryptoNoteCore/LMDBBlockchainDB.h"
#include "CryptoTypes.h"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>

using namespace CryptoNote;

namespace {

// A 32-byte spend tag (shaped like a PQ nullifier) keyed into the spent-key set.
Crypto::KeyImage tagPat(uint8_t a, uint8_t b) {
    Crypto::KeyImage k;
    for (size_t i = 0; i < sizeof(k.data); ++i) k.data[i] = static_cast<uint8_t>(i * a + b);
    return k;
}

struct TempDb {
    std::filesystem::path dir;
    LMDBBlockchainDB db;
    TempDb() {
        std::error_code ec;
        dir = std::filesystem::path("pq_nullifier_test_data");
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);
        EXPECT_TRUE(db.open(dir.string()));
    }
    ~TempDb() {
        db.close();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

}  // namespace

TEST(PqNullifierSet, PutHasGetRemove) {
    TempDb t;
    Crypto::KeyImage nf = tagPat(7, 1);

    EXPECT_FALSE(t.db.hasSpentKey(nf));
    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.putSpentKey(nf, 12345));
    t.db.commitTxn();
    EXPECT_TRUE(t.db.hasSpentKey(nf));

    uint32_t h = 0;
    ASSERT_TRUE(t.db.getSpentKeyHeight(nf, h));
    EXPECT_EQ(h, 12345u);

    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.removeSpentKey(nf));
    t.db.commitTxn();
    EXPECT_FALSE(t.db.hasSpentKey(nf));
}

TEST(PqNullifierSet, AbsentNullifier) {
    TempDb t;
    EXPECT_FALSE(t.db.hasSpentKey(tagPat(1, 2)));
    uint32_t h = 0;
    EXPECT_FALSE(t.db.getSpentKeyHeight(tagPat(1, 2), h));
}

TEST(PqNullifierSet, ReorgRemoveAllowsReinsert) {
    TempDb t;
    Crypto::KeyImage nf = tagPat(3, 9);

    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.putSpentKey(nf, 100));
    t.db.commitTxn();
    EXPECT_TRUE(t.db.hasSpentKey(nf));

    // Block pop on reorg removes the tag.
    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.removeSpentKey(nf));
    t.db.commitTxn();
    EXPECT_FALSE(t.db.hasSpentKey(nf));

    // The same (auth_pub, rho_reveal) -> same nullifier may re-enter on the
    // competing chain at a new height.
    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.putSpentKey(nf, 101));
    t.db.commitTxn();
    uint32_t h = 0;
    ASSERT_TRUE(t.db.getSpentKeyHeight(nf, h));
    EXPECT_EQ(h, 101u);
}

TEST(PqNullifierSet, MultipleDistinct) {
    TempDb t;
    Crypto::KeyImage a = tagPat(2, 1), b = tagPat(2, 2), c = tagPat(2, 3);

    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.putSpentKey(a, 1));
    EXPECT_TRUE(t.db.putSpentKey(b, 2));
    EXPECT_TRUE(t.db.putSpentKey(c, 3));
    t.db.commitTxn();

    EXPECT_TRUE(t.db.hasSpentKey(a));
    EXPECT_TRUE(t.db.hasSpentKey(b));
    EXPECT_TRUE(t.db.hasSpentKey(c));

    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.removeSpentKey(b));
    t.db.commitTxn();
    EXPECT_TRUE(t.db.hasSpentKey(a));
    EXPECT_FALSE(t.db.hasSpentKey(b));
    EXPECT_TRUE(t.db.hasSpentKey(c));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
