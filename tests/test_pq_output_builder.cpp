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

// Deterministic core: fixed (kemCt, ss, spendPub, rho) -> fixed output.
TEST(PqOutputBuilder, DeterministicKat) {
    KemCiphertext kemCt = pat<1088>(7, 3);
    KemShared     ss    = pat<32>(1, 0);
    DsaPublicKey  spendPub = pat<1952>(5, 1);
    Hash256       ih    = inputsHash(fixedInputs());
    Rho           rho   = pat<32>(3, 9);

    PqBuiltOutput o = buildPqOutput(kemCt, ss, spendPub, ih, /*outputIndex=*/1,
                                    /*amount=*/1000000, rho);

    // Cross-check against the published PqDerive KATs (same fixed inputs):
    EXPECT_EQ(to_hex(o.outContext),
              "2d8b4e207f8cd9b052e4ebd6e6a752b4a6f1363e52481a00445c8cec0a2f8615");
    EXPECT_EQ(to_hex(o.spendCommit),
              "e68cb8c9336055b6627ca1a23f7b1a0962a2952d1f58466d28039c67405ca46d");

    // encPayload is 48 bytes (32 ct + 16 tag); pinned KAT.
    ASSERT_EQ(o.encPayload.size(), 48u);
    EXPECT_EQ(to_hex(o.encPayload),
              "b228e03adc437d64c251fcb8bc35f115ccc096cf8a5af789fd72ac3533764593"
              "aa115dcb2b4845404ec9dcf2b06191da");
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

// End-to-end: the recipient (holder of view_sk + spend keys) recovers rho and
// confirms ownership. Previews the Session 7 scanner.
TEST(PqOutputBuilder, RecipientCanRecoverAndVerify) {
    SeedMaster m = pat<32>(2, 7);
    auto view  = deriveViewKeys(m);   // (viewPub, viewSk)
    auto spend = deriveSpendKeys(m);  // (spendPub, spendSk)

    Hash256 ih = inputsHash(fixedInputs());
    const uint32_t idx = 4;
    const uint64_t amount = 7777;

    PqBuiltOutput o = buildPqOutput(view.first, spend.first, ih, idx, amount);

    // Recipient side:
    KemShared ss2 = kem_decaps(view.second, o.kemCt);
    Hash256 oc2 = outContext(ih, o.kemCt, idx);
    EXPECT_EQ(oc2, o.outContext);
    Hash256 aeadKey2 = deriveAeadKey(ss2, oc2);

    AeadNonce nonce{};
    std::array<uint8_t, 40> aad{};
    std::memcpy(aad.data(), oc2.data(), 32);
    for (int i = 0; i < 8; ++i) aad[32 + i] = static_cast<uint8_t>((amount >> (8 * i)) & 0xFF);

    auto rho2 = aead_decrypt(aeadKey2, nonce, aad.data(), aad.size(),
                             o.encPayload.data(), o.encPayload.size());
    ASSERT_TRUE(rho2.has_value());
    EXPECT_EQ(0, std::memcmp(rho2->data(), o.rho.data(), 32));

    // Ownership gate: recompute spend_commit with the recipient's spend_pub.
    Rho rhoArr{};
    std::memcpy(rhoArr.data(), rho2->data(), 32);
    EXPECT_EQ(spendCommit(spend.first, rhoArr), o.spendCommit);
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

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
