// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Tests for the PQ account-number registry (spec §11): the LMDB pq_acct_reg
// table with first-registration-wins + reorg rollback semantics, and the
// human-readable H-I-A-C account-number rendering (with the key-fingerprint A).

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

TEST(PqAcctReg, CountTracksCanonicalEntries) {
    TempDb t;

    Crypto::Hash a = hashPat(3, 1);
    Crypto::Hash b = hashPat(5, 2);

    uint64_t count = 99;
    ASSERT_TRUE(t.db.getPqAccountRegistrationsCount(count));
    EXPECT_EQ(count, 0u);

    t.db.beginWriteTxn();
    ASSERT_TRUE(t.db.putPqAcctReg(a, 100, 1));
    ASSERT_TRUE(t.db.putPqAcctReg(b, 101, 2));
    t.db.commitTxn();

    ASSERT_TRUE(t.db.getPqAccountRegistrationsCount(count));
    EXPECT_EQ(count, 2u);

    t.db.beginWriteTxn();
    ASSERT_TRUE(t.db.removePqAcctReg(a));
    t.db.commitTxn();

    ASSERT_TRUE(t.db.getPqAccountRegistrationsCount(count));
    EXPECT_EQ(count, 1u);
}

// --- Account-number (H-I-A-C) rendering: PQ REUSES CryptoNote::AccountNumber ---
// The number is (blockHeight, txIndex) -> "H-I-A-C", where A is a 4-char Crockford
// fingerprint of the account's keys (the reorg failsafe) and C is a Crockford Luhn
// mod-32 check char over H, I and A. The fingerprint VALUE is produced elsewhere
// (pqAccountFingerprint over the keys); here we exercise the string codec with an
// arbitrary fingerprint. See docs/wallets/account-numbers.md.

namespace {
constexpr uint32_t kFp = 0xABCDEu;  // sample 20-bit fingerprint
}

TEST(PqAccountReuse, RoundTrip) {
    AccountNumber a{1234567, 42};
    std::string s = a.toString(kFp);
    AccountNumber b{};
    uint32_t fp = 0;
    ASSERT_TRUE(AccountNumber::fromString(s, b, fp));
    EXPECT_EQ(b.blockHeight, 1234567u);
    EXPECT_EQ(b.txIndex, 42u);
    EXPECT_EQ(fp, kFp);
    EXPECT_EQ(s.substr(0, 10), "1234567-42");
    // A is exactly 4 Crockford chars framed by dashes: "H-I-AAAA-C".
    EXPECT_EQ(s, std::string("1234567-42-") + AccountNumber::encodeFingerprint(kFp) +
                     "-" + s.substr(s.size() - 1));
}

TEST(PqAccountReuse, ChecksumRejectsCheckCharTypo) {
    std::string s = AccountNumber{900, 7}.toString(kFp);
    s[s.size() - 1] = (s[s.size() - 1] == 'A') ? 'B' : 'A';  // corrupt the check char
    AccountNumber b{};
    EXPECT_FALSE(AccountNumber::fromString(s, b));
}

TEST(PqAccountReuse, ChecksumRejectsFingerprintTypo) {
    // A is covered by C, so a single-char corruption of A is caught.
    std::string s = AccountNumber{900, 7}.toString(kFp);
    size_t aStart = s.find('-', s.find('-') + 1) + 1;  // first char of the A field
    s[aStart] = (s[aStart] == 'Z') ? 'Y' : 'Z';
    AccountNumber b{};
    EXPECT_FALSE(AccountNumber::fromString(s, b));
}

TEST(PqAccountReuse, ChecksumRejectsWrongHeight) {
    std::string s = AccountNumber{900, 7}.toString(kFp);
    std::string tampered = "901" + s.substr(s.find('-'));
    AccountNumber b{};
    EXPECT_FALSE(AccountNumber::fromString(tampered, b));
}

TEST(PqAccountFingerprint, CodecRoundTripAndTruncation) {
    for (uint32_t v : {0u, 1u, 31u, 0x12345u, 0xFFFFFu}) {
        std::string a = AccountNumber::encodeFingerprint(v);
        EXPECT_EQ(a.size(), 4u);
        uint32_t out = 0;
        ASSERT_TRUE(AccountNumber::decodeFingerprint(a, out));
        EXPECT_EQ(out, v & 0xFFFFFu);
    }
    // Values above 20 bits are masked, not overflowed.
    EXPECT_EQ(AccountNumber::encodeFingerprint(0x1FABCDEu),
              AccountNumber::encodeFingerprint(0xFABCDEu & 0xFFFFFu));
}

TEST(PqAccountFingerprint, LenientDecodeOfAmbiguousChars) {
    // O -> 0, I/L -> 1, case-insensitive: look-alikes decode to the canonical value.
    uint32_t withZero = 1, withO = 2;
    ASSERT_TRUE(AccountNumber::decodeFingerprint("0000", withZero));
    ASSERT_TRUE(AccountNumber::decodeFingerprint("O0o0", withO));
    EXPECT_EQ(withZero, withO);

    uint32_t withOne = 1, withI = 2, withL = 3;
    ASSERT_TRUE(AccountNumber::decodeFingerprint("1000", withOne));
    ASSERT_TRUE(AccountNumber::decodeFingerprint("I000", withI));
    ASSERT_TRUE(AccountNumber::decodeFingerprint("l000", withL));
    EXPECT_EQ(withOne, withI);
    EXPECT_EQ(withOne, withL);

    uint32_t u = 0;
    EXPECT_FALSE(AccountNumber::decodeFingerprint("U000", u));  // U is not a Crockford symbol
}

// --- H-I-A-T-C deposit subaddress (Spec 2 / single-key-index) ----------------

TEST(PqDepositAccount, HitcRoundTrip) {
    AccountNumber a{1234567, 42};
    std::string s = a.toStringWithIndex(9, kFp);
    EXPECT_EQ(s.substr(0, 10), "1234567-42");

    AccountNumber b{};
    uint32_t t = 0, fp = 0;
    ASSERT_TRUE(AccountNumber::fromStringWithIndex(s, b, t, fp));
    EXPECT_EQ(b.blockHeight, 1234567u);
    EXPECT_EQ(b.txIndex, 42u);
    EXPECT_EQ(t, 9u);
    EXPECT_EQ(fp, kFp);
}

TEST(PqDepositAccount, HitcDefaultIndexZero) {
    AccountNumber a{900, 7};
    std::string s = a.toStringWithIndex(0, kFp);
    AccountNumber b{};
    uint32_t t = 123;
    ASSERT_TRUE(AccountNumber::fromStringWithIndex(s, b, t));
    EXPECT_EQ(t, 0u);
}

TEST(PqDepositAccount, HitcCheckCharRejectsTypo) {
    std::string s = AccountNumber{900, 7}.toStringWithIndex(5, kFp);
    s[s.size() - 1] = (s[s.size() - 1] == 'A') ? 'B' : 'A';  // corrupt check char
    AccountNumber b{};
    uint32_t t = 0;
    EXPECT_FALSE(AccountNumber::fromStringWithIndex(s, b, t));
}

TEST(PqDepositAccount, HitcRejectsTamperedIndex) {
    // Changing T must invalidate the check char (it covers H, I, A and T).
    std::string s = AccountNumber{900, 7}.toStringWithIndex(5, kFp);  // "900-7-AAAA-5-C"
    std::string tampered = s;
    tampered[s.find_last_of('-') - 1] = '6';  // T 5 -> 6, check char now wrong
    AccountNumber b{};
    uint32_t t = 0;
    EXPECT_FALSE(AccountNumber::fromStringWithIndex(tampered, b, t));
}

TEST(PqDepositAccount, HitcAndHicDoNotAlias) {
    // The 3-dash H-I-A-C parser must reject a 4-dash H-I-A-T-C string and vice versa.
    std::string hitc = AccountNumber{900, 7}.toStringWithIndex(5, kFp);
    AccountNumber b{};
    EXPECT_FALSE(AccountNumber::fromString(hitc, b));  // H-I-A-C rejects H-I-A-T-C

    std::string hic = AccountNumber{900, 7}.toString(kFp);
    uint32_t t = 0;
    EXPECT_FALSE(AccountNumber::fromStringWithIndex(hic, b, t));  // and the reverse
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
