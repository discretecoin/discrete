// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Tests for the PQ account-number registry (spec §11): the LMDB pq_acct_reg
// table with first-registration-wins + reorg rollback semantics, and the
// human-readable H-I-C account-number rendering.

#include "gtest/gtest.h"

#include "CryptoNoteCore/LMDBBlockchainDB.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "AccountNumber.h"
#include "CryptoTypes.h"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>

using namespace CryptoNote;

namespace {

Crypto::Hash hashPat(uint8_t a, uint8_t b) {
    Crypto::Hash h;
    for (size_t i = 0; i < sizeof(h.data); ++i) h.data[i] = static_cast<uint8_t>(i * a + b);
    return h;
}

struct TempDb {
    std::filesystem::path dir;
    LMDBBlockchainDB db;
    TempDb() {
        std::error_code ec;
        dir = std::filesystem::path("pq_acct_test_data");
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);
        EXPECT_TRUE(db.open(dir.string()));
    }
    ~TempDb() { db.close(); std::error_code ec; std::filesystem::remove_all(dir, ec); }
};

}  // namespace

TEST(PqAcctReg, PutHasGetRemove) {
    TempDb t;
    Crypto::Hash vp = hashPat(7, 1);
    EXPECT_FALSE(t.db.hasPqAcctReg(vp));

    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.putPqAcctReg(vp, 1234567, 42));
    t.db.commitTxn();

    EXPECT_TRUE(t.db.hasPqAcctReg(vp));
    uint32_t h = 0, ti = 0;
    ASSERT_TRUE(t.db.getPqAcctReg(vp, h, ti));
    EXPECT_EQ(h, 1234567u);
    EXPECT_EQ(ti, 42u);

    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.removePqAcctReg(vp));
    t.db.commitTxn();
    EXPECT_FALSE(t.db.hasPqAcctReg(vp));
}

TEST(PqAcctReg, AccountIdentityBindsSpendKey) {
    TransactionExtraPqAccountRegistration a{};
    TransactionExtraPqAccountRegistration b{};
    for (size_t i = 0; i < a.viewPub.size(); ++i) {
        a.viewPub[i] = static_cast<uint8_t>(i & 0xff);
        b.viewPub[i] = a.viewPub[i];
    }
    for (size_t i = 0; i < a.spendPub.size(); ++i) {
        a.spendPub[i] = static_cast<uint8_t>((i * 3) & 0xff);
        b.spendPub[i] = static_cast<uint8_t>((i * 5 + 1) & 0xff);
    }

    const Crypto::Hash aidA = getPqAccountIdentityHash(a);
    const Crypto::Hash aidB = getPqAccountIdentityHash(b);
    const Crypto::Hash aidA2 = getPqAccountIdentityHash(a.viewPub, a.spendPub);
    EXPECT_NE(0, std::memcmp(aidA.data, aidB.data, sizeof(aidA.data)));
    EXPECT_EQ(0, std::memcmp(aidA.data, aidA2.data, sizeof(aidA.data)));
}

TEST(PqAcctReg, FirstRegistrationWins) {
    // The consensus rule (in pushTransaction) rejects a second registration of
    // an already-present account identity. At the DB layer that's a
    // hasPqAcctReg() check
    // returning true for the duplicate.
    TempDb t;
    Crypto::Hash vp = hashPat(5, 5);

    t.db.beginWriteTxn();
    t.db.putPqAcctReg(vp, 100, 1);   // first registration wins at (100,1)
    t.db.commitTxn();

    EXPECT_TRUE(t.db.hasPqAcctReg(vp));  // a later tx with this id would be rejected
    uint32_t h, ti;
    t.db.getPqAcctReg(vp, h, ti);
    EXPECT_EQ(h, 100u);
    EXPECT_EQ(ti, 1u);
}

TEST(PqAcctReg, ReorgRollbackAllowsReregister) {
    TempDb t;
    Crypto::Hash vp = hashPat(3, 2);

    t.db.beginWriteTxn();
    t.db.putPqAcctReg(vp, 100, 1);
    t.db.commitTxn();
    EXPECT_TRUE(t.db.hasPqAcctReg(vp));

    // Block 100 orphaned by a reorg -> registration removed.
    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.removePqAcctReg(vp));
    t.db.commitTxn();
    EXPECT_FALSE(t.db.hasPqAcctReg(vp));

    // Same account identity may now register at a new height on the competing chain.
    t.db.beginWriteTxn();
    EXPECT_TRUE(t.db.putPqAcctReg(vp, 101, 3));
    t.db.commitTxn();
    uint32_t h, ti;
    ASSERT_TRUE(t.db.getPqAcctReg(vp, h, ti));
    EXPECT_EQ(h, 101u);
    EXPECT_EQ(ti, 3u);
}

// --- Account-number (H-I-C) rendering: PQ REUSES CryptoNote::AccountNumber ----
// The account number is just (blockHeight, txIndex) -> "H-I-C" with a luhnMod36
// check char. It does not encode CN-vs-PQ; resolving it looks up whatever
// registration sits at that tx slot. So PQ registrations use the SAME format as
// classical account numbers — no PQ-specific scheme.

TEST(PqAccountReuse, RoundTrip) {
    AccountNumber a{1234567, 42};
    std::string s = a.toString();
    AccountNumber b{};
    ASSERT_TRUE(AccountNumber::fromString(s, b));
    EXPECT_EQ(b.blockHeight, 1234567u);
    EXPECT_EQ(b.txIndex, 42u);
    EXPECT_EQ(s.substr(0, 10), "1234567-42");
}

TEST(PqAccountReuse, ChecksumRejectsTypo) {
    std::string s = AccountNumber{900, 7}.toString();
    s[s.size() - 1] = (s[s.size() - 1] == 'A') ? 'B' : 'A';  // corrupt the check char
    AccountNumber b{};
    EXPECT_FALSE(AccountNumber::fromString(s, b));
}

TEST(PqAccountReuse, ChecksumRejectsWrongHeight) {
    std::string s = AccountNumber{900, 7}.toString();
    std::string tampered = "901" + s.substr(s.find('-'));
    AccountNumber b{};
    EXPECT_FALSE(AccountNumber::fromString(tampered, b));
}

// --- H-I-T-C deposit subaddress (Spec 2 / single-key-index) ------------------

TEST(PqDepositAccount, HitcRoundTrip) {
    AccountNumber a{1234567, 42};
    std::string s = a.toStringWithIndex(9);
    EXPECT_EQ(s.substr(0, 12), "1234567-42-9");

    AccountNumber b{};
    uint32_t t = 0;
    ASSERT_TRUE(AccountNumber::fromStringWithIndex(s, b, t));
    EXPECT_EQ(b.blockHeight, 1234567u);
    EXPECT_EQ(b.txIndex, 42u);
    EXPECT_EQ(t, 9u);
}

TEST(PqDepositAccount, HitcDefaultIndexZero) {
    AccountNumber a{900, 7};
    std::string s = a.toStringWithIndex(0);
    AccountNumber b{};
    uint32_t t = 123;
    ASSERT_TRUE(AccountNumber::fromStringWithIndex(s, b, t));
    EXPECT_EQ(t, 0u);
}

TEST(PqDepositAccount, HitcCheckCharRejectsTypo) {
    std::string s = AccountNumber{900, 7}.toStringWithIndex(5);
    s[s.size() - 1] = (s[s.size() - 1] == 'A') ? 'B' : 'A';  // corrupt check char
    AccountNumber b{};
    uint32_t t = 0;
    EXPECT_FALSE(AccountNumber::fromStringWithIndex(s, b, t));
}

TEST(PqDepositAccount, HitcRejectsTamperedIndex) {
    // Changing T must invalidate the check char (it covers H, I and T).
    std::string s = AccountNumber{900, 7}.toStringWithIndex(5);  // "900-7-5-C"
    std::string tampered = s;
    tampered[s.find_last_of('-') - 1] = '6';  // T 5 -> 6, check char now wrong
    AccountNumber b{};
    uint32_t t = 0;
    EXPECT_FALSE(AccountNumber::fromStringWithIndex(tampered, b, t));
}

TEST(PqDepositAccount, HitcAndHicDoNotAlias) {
    // The 3-field H-I-C parser must reject a 4-field H-I-T-C string and vice versa.
    std::string hitc = AccountNumber{900, 7}.toStringWithIndex(5);
    AccountNumber b{};
    EXPECT_FALSE(AccountNumber::fromString(hitc, b));  // H-I-C rejects H-I-T-C

    std::string hic = AccountNumber{900, 7}.toString();
    uint32_t t = 0;
    EXPECT_FALSE(AccountNumber::fromStringWithIndex(hic, b, t));  // and the reverse
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
