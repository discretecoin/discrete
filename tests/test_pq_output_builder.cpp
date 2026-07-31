// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Tests for sender-side PQ output construction (spec §6, ownership-fixed).
// Covers: a deterministic KAT, cross-consistency with PqDerive, end-to-end
// recoverability by the recipient (previews scanning), and amount-tamper
// detection via the AEAD aad.

#include "gtest/gtest.h"

#include "crypto_pq/PqOutputBuilder.h"
#include "crypto_pq/PqScan.h"
#include "crypto_pq/PqAead.h"
#include "crypto_pq/PqSeed.h"
#include "crypto_pq/PqDerive.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace CryptoPQ;

namespace {

std::string to_hex(const uint8_t* d, std::size_t n) {
    static const char* h = "0123456789abcdef";
    std::string o; o.reserve(2 * n);
    for (std::size_t i = 0; i < n; ++i) { o += h[d[i] >> 4]; o += h[d[i] & 0xf]; }
    return o;
}
template <std::size_t N> std::string to_hex(const std::array<uint8_t, N>& a) {
    return to_hex(a.data(), N);
}
std::string to_hex(const std::vector<uint8_t>& v) { return to_hex(v.data(), v.size()); }

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

}  // namespace

// Deterministic core: fixed (kemCt, ss, spendPub, rho, T=0) -> fixed output.
TEST(PqOutputBuilder, DeterministicKat) {
    KemCiphertext kemCt = pat<1088>(7, 3);
    KemShared     ss    = pat<32>(1, 0);
    DsaPublicKey  spendPub = pat<1952>(5, 1);
    Hash256       ih    = inputsHash(fixedInputs());
    Rho           rho   = pat<32>(3, 9);

    PqBuiltOutput o = buildPqOutput(kemCt, ss, spendPub, ih, /*outputIndex=*/1,
                                    /*amount=*/1000000, rho, /*T=*/0);

    // Cross-check against the published PqDerive v2 KATs.
    EXPECT_EQ(to_hex(o.outContext),
              "f565b6181ad5bbdb55fb7594b23355aac1e388324fd9ced017680474a4a87ede");
    EXPECT_EQ(to_hex(o.spendCommit),
              "0efa5a91ce3a6df44730c7d0cbebbc3d3896264f6826991914bac993684a151a");

    // encPayload is 56 bytes (40 ct + 16 tag); pinned KAT.
    ASSERT_EQ(o.encPayload.size(), 56u);
    EXPECT_EQ(to_hex(o.encPayload),
              "e896788b3fbf1103b5be0bb4536172ac13f70e1c3e77387d0f0fe7ed7166c7b"
              "18ae91bad50f569d5fe5643833c4b33bf8c84cfb664d0f90c");
}

TEST(PqOutputBuilder, DeterministicReproducible) {
    KemCiphertext kemCt = pat<1088>(2, 1);
    KemShared     ss    = pat<32>(9, 4);
    DsaPublicKey  spendPub = pat<1952>(3, 7);
    Hash256       ih    = pat<32>(5, 2);
    Rho           rho   = pat<32>(1, 1);

    PqBuiltOutput a = buildPqOutput(kemCt, ss, spendPub, ih, 2, 42, rho);
    PqBuiltOutput b = buildPqOutput(kemCt, ss, spendPub, ih, 2, 42, rho);
    EXPECT_EQ(a.encPayload, b.encPayload);
    EXPECT_EQ(a.spendCommit, b.spendCommit);
    EXPECT_EQ(a.outContext, b.outContext);
}

// End-to-end: the recipient (holder of view_sk + spend keys) recovers rho+T and
// confirms ownership. Previews the Session 7 scanner.
TEST(PqOutputBuilder, RecipientCanRecoverAndVerify) {
    SeedMaster m = pat<32>(2, 7);
    auto view  = deriveViewKeys(m);   // (viewPub, viewSk)
    auto spend = deriveSpendKeys(m);  // (spendPub, spendSk)

    Hash256 ih = inputsHash(fixedInputs());
    const uint32_t idx = 4;
    const uint64_t amount = 7777;
    const uint64_t T = 0;

    PqBuiltOutput o = buildPqOutput(view.first, spend.first, ih, idx, amount, T);

    // Recipient side:
    KemShared ss2 = kem_decaps(view.second, o.kemCt);
    Hash256 oc2 = outContext(ih, o.kemCt, idx);
    EXPECT_EQ(oc2, o.outContext);
    Hash256 aeadKey2 = deriveAeadKey(ss2, oc2);

    AeadNonce nonce{};
    std::array<uint8_t, 40> aad{};
    std::memcpy(aad.data(), oc2.data(), 32);
    for (int i = 0; i < 8; ++i) aad[32 + i] = static_cast<uint8_t>((amount >> (8 * i)) & 0xFF);

    auto pt = aead_decrypt(aeadKey2, nonce, aad.data(), aad.size(),
                           o.encPayload.data(), o.encPayload.size());
    ASSERT_TRUE(pt.has_value());
    ASSERT_EQ(pt->size(), 40u);

    // First 32 bytes are rho.
    EXPECT_EQ(0, std::memcmp(pt->data(), o.rho.data(), 32));

    // Bytes 32-39 are LE64(T).
    uint64_t recoveredT = 0;
    for (int i = 0; i < 8; ++i)
        recoveredT |= static_cast<uint64_t>((*pt)[32 + i]) << (8 * i);
    EXPECT_EQ(recoveredT, T);

    // Ownership gate: recompute spend_commit with the recipient's spend_pub.
    Rho rhoArr{};
    std::memcpy(rhoArr.data(), pt->data(), 32);
    EXPECT_EQ(spendCommit(spend.first, rhoArr), o.spendCommit);
}

// outContext-v2 depends on (inputsHash, kemCt, outputIndex) only — NOT T (see
// PqDerive.h). Two different kemCt values (as every real send produces, since
// ML-KEM encapsulation is randomized) still give different keys and both
// round-trip; that is where output uniqueness actually comes from now.
TEST(PqOutputBuilder, DifferentKemCtProducesDifferentKeysAndBothRoundTrip) {
    KemCiphertext kemCt0 = pat<1088>(7, 3);
    KemCiphertext kemCt1 = pat<1088>(2, 9);
    KemShared     ss0    = pat<32>(1, 0);
    KemShared     ss1    = pat<32>(6, 4);
    DsaPublicKey  spendPub = pat<1952>(5, 1);
    Hash256       ih    = inputsHash(fixedInputs());
    Rho           rho   = pat<32>(3, 9);
    const uint64_t amount = 5000;

    PqBuiltOutput o0 = buildPqOutput(kemCt0, ss0, spendPub, ih, 0, amount, rho, /*T=*/0);
    PqBuiltOutput o1 = buildPqOutput(kemCt1, ss1, spendPub, ih, 0, amount, rho, /*T=*/1);

    EXPECT_NE(o0.outContext, o1.outContext);
    EXPECT_NE(o0.encPayload, o1.encPayload);
    // spendCommit is T-independent (only rho + spendPub).
    EXPECT_EQ(o0.spendCommit, o1.spendCommit);

    auto decryptWith = [&](const PqBuiltOutput& o, const KemShared& ss, uint64_t T) {
        AeadNonce nonce{};
        Hash256 aeadKey = deriveAeadKey(ss, o.outContext);
        std::array<uint8_t, 40> aad{};
        std::memcpy(aad.data(), o.outContext.data(), 32);
        for (int i = 0; i < 8; ++i)
            aad[32 + i] = static_cast<uint8_t>((amount >> (8 * i)) & 0xFF);
        auto pt = aead_decrypt(aeadKey, nonce, aad.data(), aad.size(),
                               o.encPayload.data(), o.encPayload.size());
        ASSERT_TRUE(pt.has_value());
        ASSERT_EQ(pt->size(), 40u);
        EXPECT_EQ(0, std::memcmp(pt->data(), rho.data(), 32));
        uint64_t recovT = 0;
        for (int i = 0; i < 8; ++i)
            recovT |= static_cast<uint64_t>((*pt)[32 + i]) << (8 * i);
        EXPECT_EQ(recovT, T);
    };
    decryptWith(o0, ss0, 0);
    decryptWith(o1, ss1, 1);
}

// outContext-v2 is T-independent: the SAME (kemCt, outputIndex) yields the
// SAME context regardless of T, so T changes only the AEAD plaintext (and
// therefore the ciphertext) — never the key. Both still round-trip and each
// reports its own recovered T.
TEST(PqOutputBuilder, SameContextDifferentTChangesOnlyPayload) {
    KemCiphertext kemCt = pat<1088>(7, 3);
    KemShared     ss    = pat<32>(1, 0);
    DsaPublicKey  spendPub = pat<1952>(5, 1);
    Hash256       ih    = inputsHash(fixedInputs());
    Rho           rho   = pat<32>(3, 9);
    const uint64_t amount = 5000;

    PqBuiltOutput o0 = buildPqOutput(kemCt, ss, spendPub, ih, 0, amount, rho, /*T=*/0);
    PqBuiltOutput o1 = buildPqOutput(kemCt, ss, spendPub, ih, 0, amount, rho, /*T=*/1);

    EXPECT_EQ(o0.outContext, o1.outContext);  // v2: context does not depend on T
    EXPECT_NE(o0.encPayload, o1.encPayload);  // different plaintext -> different ciphertext
    EXPECT_EQ(o0.spendCommit, o1.spendCommit);

    AeadNonce nonce{};
    Hash256 aeadKey = deriveAeadKey(ss, o0.outContext);
    std::array<uint8_t, 40> aad{};
    std::memcpy(aad.data(), o0.outContext.data(), 32);
    for (int i = 0; i < 8; ++i)
        aad[32 + i] = static_cast<uint8_t>((amount >> (8 * i)) & 0xFF);

    auto pt0 = aead_decrypt(aeadKey, nonce, aad.data(), aad.size(),
                            o0.encPayload.data(), o0.encPayload.size());
    auto pt1 = aead_decrypt(aeadKey, nonce, aad.data(), aad.size(),
                            o1.encPayload.data(), o1.encPayload.size());
    ASSERT_TRUE(pt0.has_value());
    ASSERT_TRUE(pt1.has_value());
    auto recoverT = [](const std::vector<uint8_t>& pt) {
        uint64_t t = 0;
        for (int i = 0; i < 8; ++i) t |= static_cast<uint64_t>(pt[32 + i]) << (8 * i);
        return t;
    };
    EXPECT_EQ(recoverT(*pt0), 0u);
    EXPECT_EQ(recoverT(*pt1), 1u);
}

// A tampered on-chain amount makes the recipient's AEAD decrypt fail.
TEST(PqOutputBuilder, AmountTamperBreaksDecrypt) {
    SeedMaster m = pat<32>(2, 7);
    auto view  = deriveViewKeys(m);
    auto spend = deriveSpendKeys(m);
    Hash256 ih = inputsHash(fixedInputs());
    const uint32_t idx = 4;
    const uint64_t amount = 7777;

    PqBuiltOutput o = buildPqOutput(view.first, spend.first, ih, idx, amount);

    KemShared ss2 = kem_decaps(view.second, o.kemCt);
    Hash256 oc2 = outContext(ih, o.kemCt, idx);
    Hash256 aeadKey2 = deriveAeadKey(ss2, oc2);
    AeadNonce nonce{};
    std::array<uint8_t, 40> aad{};
    std::memcpy(aad.data(), oc2.data(), 32);
    const uint64_t tampered = amount + 1;  // attacker changes the amount
    for (int i = 0; i < 8; ++i) aad[32 + i] = static_cast<uint8_t>((tampered >> (8 * i)) & 0xFF);

    auto rho2 = aead_decrypt(aeadKey2, nonce, aad.data(), aad.size(),
                             o.encPayload.data(), o.encPayload.size());
    EXPECT_FALSE(rho2.has_value());
}

TEST(PqOutputBuilder, StandardEncapsulationPathFullScans) {
    auto view = kem_keygen();
    auto spend = dsa_keygen();
    Hash256 ih{};
    ih[0] = 0x31;

    PqBuiltOutput first = buildPqOutput(
        view.first, spend.first, ih, 3, 12345, 9);

    PqScanOutput candidate;
    candidate.outputIndex = 3;
    candidate.amount = 12345;
    candidate.kemCt = first.kemCt;
    candidate.encPayload = first.encPayload;
    candidate.spendCommit = first.spendCommit;
    const auto shared = kem_decaps(view.second, first.kemCt);
    auto owned = scanPqOutputWithSharedSecret(shared, spend.first, ih, candidate);
    ASSERT_TRUE(owned.has_value());
    EXPECT_EQ(owned->subaddrIndexT, 9u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
