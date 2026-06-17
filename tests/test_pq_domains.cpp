// Copyright (c) 2026, The Discrete developers
//
// Pinning test for every consensus-critical constant in the Discrete PQ
// transaction family.  Any change to a value below is a hard fork.
//
// ── HOW THIS TEST WORKS ──────────────────────────────────────────────────────
// Each EXPECT_STREQ / EXPECT_EQ compares the live C++ constant against a
// string literal embedded in this file.  Renaming the constant, typo-editing
// its value, OR editing the literal here both cause a CI failure — the two
// sides are independent witnesses that must agree.
//
// The static_asserts fire at compile time; the gtest assertions provide a
// human-readable failure message at run time.
// ─────────────────────────────────────────────────────────────────────────────

#include "gtest/gtest.h"

#include "crypto_pq/PqDerive.h"   // kDomain*, kReservedCtMask
#include "crypto_pq/PqSeed.h"     // kDomainViewRoot, kDomainSpendRoot
#include "CryptoNote.h"           // PQ_*_SIZE
#include "CryptoNoteConfig.h"     // TRANSACTION_VERSION_1
#include "PqTxType.h"             // TX_COINBASE, TX_PQ, TX_FREE_REG

#include <cstring>

using namespace CryptoPQ;
using namespace CryptoNote;

// ===========================================================================
// Compile-time guards (fire immediately on any change)
// ===========================================================================

static_assert(PQ_KEM_CIPHERTEXT_SIZE == 1088,
              "PQ_KEM_CIPHERTEXT_SIZE changed — hard fork");
static_assert(PQ_ENC_PAYLOAD_SIZE    == 56,
              "PQ_ENC_PAYLOAD_SIZE changed — hard fork");
static_assert(PQ_AUTH_PUB_SIZE       == 1952,
              "PQ_AUTH_PUB_SIZE changed — hard fork");
static_assert(PQ_RHO_SIZE            == 32,
              "PQ_RHO_SIZE changed — hard fork");
static_assert(PQ_SIGNATURE_SIZE      == 3309,
              "PQ_SIGNATURE_SIZE changed — hard fork");

static_assert(TRANSACTION_VERSION_1 == 1,
              "TRANSACTION_VERSION_1 changed — hard fork");

static_assert(TX_COINBASE == 0x00, "TX_COINBASE changed — hard fork");
static_assert(TX_PQ       == 0x01, "TX_PQ changed — hard fork");
// 0x02 is permanently reserved (never-deployed legacy bridge subtype); it has no
// named constant and consensus rejects it as an unknown PQ subtype.
static_assert(TX_FREE_REG == 0x03, "TX_FREE_REG changed — hard fork");

// ===========================================================================
// Run-time byte-exact pins for domain strings
// ===========================================================================

TEST(PqDomains, DeriveDomainStrings) {
    // kDomainInputsHash — used in inputsHash()
    EXPECT_STREQ(kDomainInputsHash,  "karbo-pq-inputs-hash-v1");
    EXPECT_EQ(std::strlen(kDomainInputsHash), 23u);

    // kDomainOutContext — used in outContext()
    EXPECT_STREQ(kDomainOutContext,  "karbo-pq-out-context-v1");
    EXPECT_EQ(std::strlen(kDomainOutContext), 23u);

    // kDomainAeadKey — used in deriveAeadKey()
    EXPECT_STREQ(kDomainAeadKey,     "karbo-pq-aead-key-v1");
    EXPECT_EQ(std::strlen(kDomainAeadKey), 20u);

    // kDomainSpendCommit — used in spendCommit()
    EXPECT_STREQ(kDomainSpendCommit, "karbo-pq-spend-commit-v1");
    EXPECT_EQ(std::strlen(kDomainSpendCommit), 24u);

    // kDomainNullifier — used in nullifier()
    EXPECT_STREQ(kDomainNullifier,   "karbo-pq-nullifier-v1");
    EXPECT_EQ(std::strlen(kDomainNullifier), 21u);

    // kDomainTxSign — used in txSigningDigest()
    EXPECT_STREQ(kDomainTxSign,      "karbo-pq-tx-sign-v1");
    EXPECT_EQ(std::strlen(kDomainTxSign), 19u);

    // kDomainCoinbaseRho — used in coinbaseRho() (identity-bound mining)
    EXPECT_STREQ(kDomainCoinbaseRho, "discrete-coinbase-rho-v1");
    EXPECT_EQ(std::strlen(kDomainCoinbaseRho), 24u);
}

TEST(PqDomains, SeedDomainStrings) {
    // kDomainViewRoot — HKDF info for view keypair seed derivation
    EXPECT_STREQ(kDomainViewRoot,    "karbo-pq-view-root-v1");
    EXPECT_EQ(std::strlen(kDomainViewRoot), 21u);

    // kDomainSpendRoot — HKDF info for spend keypair seed derivation
    EXPECT_STREQ(kDomainSpendRoot,   "karbo-pq-spend-root-v1");
    EXPECT_EQ(std::strlen(kDomainSpendRoot), 22u);
}

TEST(PqDomains, ReservedCtMaskNotReused) {
    // kReservedCtMask is reserved for Phase 2 and must never collide with any
    // Phase 1 tag.  This test is belt-and-braces over the existing check in
    // test_pq_derive.cpp::ReservedCtMaskNamespaceUnused.
    EXPECT_STREQ(kReservedCtMask, "karbo-pq-ct-mask-v1");
    EXPECT_EQ(std::strlen(kReservedCtMask), 19u);

    const char* phase1[] = {
        kDomainInputsHash, kDomainOutContext, kDomainAeadKey,
        kDomainSpendCommit, kDomainNullifier, kDomainTxSign,
        kDomainCoinbaseRho, kDomainViewRoot, kDomainSpendRoot,
    };
    for (const char* tag : phase1) {
        EXPECT_STRNE(tag, kReservedCtMask) << "collision with reserved tag: " << tag;
    }
}

TEST(PqDomains, SizeConstants) {
    EXPECT_EQ(PQ_KEM_CIPHERTEXT_SIZE, 1088u);
    EXPECT_EQ(PQ_ENC_PAYLOAD_SIZE,      56u);
    EXPECT_EQ(PQ_AUTH_PUB_SIZE,       1952u);
    EXPECT_EQ(PQ_RHO_SIZE,              32u);
    EXPECT_EQ(PQ_SIGNATURE_SIZE,       3309u);
}

TEST(PqDomains, TransactionVersion) {
    EXPECT_EQ(static_cast<unsigned>(TRANSACTION_VERSION_1), 1u);
}

TEST(PqDomains, TxSubtypes) {
    EXPECT_EQ(static_cast<unsigned>(TX_COINBASE), 0x00u);
    EXPECT_EQ(static_cast<unsigned>(TX_PQ),       0x01u);
    // 0x02 stays reserved (no named constant; consensus rejects it as unknown).
    EXPECT_EQ(static_cast<unsigned>(TX_FREE_REG), 0x03u);
}

TEST(PqDomains, AeadParameters) {
    // The AEAD instantiation is normative: any change is a wire-format break.
    // Plaintext = rho (32) || LE64(T) (8) = 40 bytes -> ciphertext 40 bytes + 16-byte tag = 56.
    constexpr std::size_t kRhoBytes     = 32;
    constexpr std::size_t kTBytes       = 8;
    constexpr std::size_t kTagBytes     = 16;
    constexpr std::size_t kNonceBytes   = 12;
    constexpr std::size_t kAadBytes     = 40;  // outContext (32) || LE64(amount) (8)

    EXPECT_EQ(kRhoBytes + kTBytes + kTagBytes, PQ_ENC_PAYLOAD_SIZE);
    EXPECT_EQ(kNonceBytes, 12u);
    EXPECT_EQ(kAadBytes,   40u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
