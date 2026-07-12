// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
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

    // Cross-check against the published PqDerive KATs (same fixed inputs, T=0):
    EXPECT_EQ(to_hex(o.outContext),
              "32cfc3d894c9c87a8d5f7ca9b0dfc69760b39f3c267b7e7cdd41c8f65492fb1b");
    EXPECT_EQ(to_hex(o.spendCommit),
              "0efa5a91ce3a6df44730c7d0cbebbc3d3896264f6826991914bac993684a151a");

    // encPayload is 56 bytes (40 ct + 16 tag); pinned KAT.
    ASSERT_EQ(o.encPayload.size(), 56u);
    EXPECT_EQ(to_hex(o.encPayload),
              "f11845aad534497826243aa9391ea7a015c921c66cb702d340afa42dc16ee68"
              "3f6846fb6bdb5733919f342bd0983a429d40c6b54bfe7c998");
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
    Hash256 oc2 = outContext(ih, o.kemCt, idx, T);
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

// Two different T values for the same (inputsHash, kemCt, outputIndex) produce
// different output keys and both round-trip through build->decrypt->verify.
TEST(PqOutputBuilder, TValuesProduceDifferentKeysAndBothRoundTrip) {
    KemCiphertext kemCt = pat<1088>(7, 3);
    KemShared     ss    = pat<32>(1, 0);
    DsaPublicKey  spendPub = pat<1952>(5, 1);
    Hash256       ih    = inputsHash(fixedInputs());
    Rho           rho   = pat<32>(3, 9);
    const uint64_t amount = 5000;

    PqBuiltOutput o0 = buildPqOutput(kemCt, ss, spendPub, ih, 0, amount, rho, /*T=*/0);
    PqBuiltOutput o1 = buildPqOutput(kemCt, ss, spendPub, ih, 0, amount, rho, /*T=*/1);

    // Different T -> different outContext -> different AEAD key -> different ciphertext.
    EXPECT_NE(o0.outContext, o1.outContext);
    EXPECT_NE(o0.encPayload, o1.encPayload);

    // spendCommit is T-independent (only rho + spendPub).
    EXPECT_EQ(o0.spendCommit, o1.spendCommit);

    // Both decrypt correctly with their respective T.
    AeadNonce nonce{};
    auto decryptWith = [&](const PqBuiltOutput& o, uint64_t T) {
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
    decryptWith(o0, 0);
    decryptWith(o1, 1);

    // Cross-decryption must fail (wrong outContext -> wrong key -> AEAD tag fail).
    {
        Hash256 aeadKeyForO1 = deriveAeadKey(ss, o1.outContext);
        std::array<uint8_t, 40> aad{};
        std::memcpy(aad.data(), o1.outContext.data(), 32);
        for (int i = 0; i < 8; ++i)
            aad[32 + i] = static_cast<uint8_t>((amount >> (8 * i)) & 0xFF);
        // Try to decrypt o0's payload with T=1's key.
        auto bad = aead_decrypt(aeadKeyForO1, nonce, aad.data(), aad.size(),
                                o0.encPayload.data(), o0.encPayload.size());
        EXPECT_FALSE(bad.has_value());
    }
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

TEST(PqOutputBuilder, ProofCapablePathRetainsFreshMessageAndFullScans) {
    auto view = kem_keygen();
    auto spend = dsa_keygen();
    Hash256 ih{};
    ih[0] = 0x31;

    PqBuiltOutputWithProof first = buildPqOutputWithProof(
        view.first, spend.first, ih, 3, 12345, 9);
    PqBuiltOutputWithProof second = buildPqOutputWithProof(
        view.first, spend.first, ih, 3, 12345, 9);
    EXPECT_NE(first.message, second.message);

    auto encapsulation = kem_encaps_explicit(view.first, first.message);
    EXPECT_EQ(encapsulation.first, first.output.kemCt);
    EXPECT_EQ(encapsulation.second, kem_decaps(view.second, first.output.kemCt));

    PqScanOutput candidate;
    candidate.outputIndex = 3;
    candidate.amount = 12345;
    candidate.kemCt = first.output.kemCt;
    candidate.encPayload = first.output.encPayload;
    candidate.spendCommit = first.output.spendCommit;
    EXPECT_TRUE(scanPqOutputWithSharedSecret(
        encapsulation.second, spend.first, ih, candidate, 9).has_value());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
