// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Tests for the PQ Phase 1 seed-derivation chain (PqSeed) and address format
// (PqAddress) — spec §3/§4. Covers deterministic recovery, address round-trips
// under both encodings, checksum tamper rejection, and varying network prefix.

#include "gtest/gtest.h"

#include "crypto_pq/PqSeed.h"
#include "PqAddress.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

using namespace CryptoPQ;
using namespace CryptoNote;

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
template <std::size_t N> std::array<uint8_t, N> pat(uint8_t a, uint8_t b) {
    std::array<uint8_t, N> r;
    for (std::size_t i = 0; i < N; ++i) r[i] = static_cast<uint8_t>(i * a + b);
    return r;
}

}  // namespace

// --- Seed derivation chain (KAT + determinism) ----------------------------

TEST(PqSeed, ViewSeedKat) {
    SeedMaster m = pat<32>(1, 0);  // bytes 0..31
    EXPECT_EQ(to_hex(deriveViewSeed(m)),
              "79c534a401ab72ff802da7441fbfa1d027f5f38e81192b6e0e81e5b840341ef3"
              "3fd6632bafa1a8cfb124118b33d6d3346335c2b2adc3d053a664dca0e7bce3b7");
}

TEST(PqSeed, SpendSeedKat) {
    SeedMaster m = pat<32>(1, 0);
    EXPECT_EQ(to_hex(deriveSpendSeed(m)),
              "a79a34b7614d62dfc1e0a9364557e342c92cce4a09b814e96f7e8381043a2ad0");
}

TEST(PqSeed, ViewSeedAndSpendSeedDiffer) {
    SeedMaster m = pat<32>(1, 0);
    auto vs = deriveViewSeed(m);   // 64 bytes
    auto ss = deriveSpendSeed(m);  // 32 bytes
    // Compare the shared 32-byte prefix: different info domains -> different.
    EXPECT_NE(0, std::memcmp(vs.data(), ss.data(), 32));
}

TEST(PqSeed, ViewKeysDeterministic) {
    SeedMaster m = pat<32>(2, 7);
    auto a = deriveViewKeys(m);
    auto b = deriveViewKeys(m);
    EXPECT_EQ(a.first, b.first);
    EXPECT_EQ(a.second, b.second);
}

TEST(PqSeed, ViewKeysSeedSensitive) {
    SeedMaster m1 = pat<32>(2, 7);
    SeedMaster m2 = m1; m2[0] ^= 0x01;
    EXPECT_NE(deriveViewKeys(m1).first, deriveViewKeys(m2).first);
}

TEST(PqSeed, SpendKeysDeterministic) {
    SeedMaster m = pat<32>(2, 7);
    auto a = deriveSpendKeys(m);
    auto b = deriveSpendKeys(m);
    EXPECT_EQ(a.first, b.first);
    EXPECT_EQ(a.second, b.second);
}

TEST(PqSeed, SpendKeysSeedSensitive) {
    SeedMaster m1 = pat<32>(2, 7);
    SeedMaster m2 = m1; m2[0] ^= 0x01;
    EXPECT_NE(deriveSpendKeys(m1).first, deriveSpendKeys(m2).first);
}

TEST(PqSeed, ViewAndSpendKeysAreIndependent) {
    // The spend keypair must NOT be derivable from the view material (which a
    // sender learns via the KEM). They come from separate HKDF branches.
    SeedMaster m = pat<32>(2, 7);
    auto vk = deriveViewKeys(m);
    auto sk = deriveSpendKeys(m);
    EXPECT_NE(0, std::memcmp(vk.first.data(), sk.first.data(),
                             std::min(vk.first.size(), sk.first.size())));
}

// --- Deposit spend-key family (Spec 1 / aggregated-multikey) ---------------

TEST(PqSeed, DepositSpendSeedKat) {
    // Cement the deposit recovery derivation. Changing the domain, the LE32 index
    // encoding, or the HKDF params orphans deposit balances on restore — update
    // this ONLY when deliberately changing the contract.
    SeedMaster m = pat<32>(1, 0);  // bytes 0..31
    EXPECT_EQ(to_hex(deriveDepositSpendSeed(m, 0)),
              "0022e0e977bb331d83ea772cefc1caddb8ae19037e86c3c500030424bf5ad94d");
}

TEST(PqSeed, DepositSpendKeysDeterministic) {
    SeedMaster m = pat<32>(2, 7);
    auto a = deriveDepositSpendKeys(m, 5);
    auto b = deriveDepositSpendKeys(m, 5);
    EXPECT_EQ(a.first, b.first);
    EXPECT_EQ(a.second, b.second);
}

TEST(PqSeed, DepositSpendKeysIndexSensitive) {
    // Different deposit indices give different spend keys (one per deposit).
    SeedMaster m = pat<32>(2, 7);
    EXPECT_NE(deriveDepositSpendKeys(m, 0).first, deriveDepositSpendKeys(m, 1).first);
    EXPECT_NE(deriveDepositSpendKeys(m, 1).first, deriveDepositSpendKeys(m, 2).first);
    EXPECT_NE(deriveDepositSpendKeys(m, 0).first, deriveDepositSpendKeys(m, 1000).first);
}

TEST(PqSeed, DepositSpendKeysSeedSensitive) {
    SeedMaster m1 = pat<32>(2, 7);
    SeedMaster m2 = m1; m2[0] ^= 0x01;
    EXPECT_NE(deriveDepositSpendKeys(m1, 3).first, deriveDepositSpendKeys(m2, 3).first);
}

TEST(PqSeed, DepositKeysDistinctFromBaseSpendKey) {
    // Deposit #0 must NOT equal the account's main spend key (separate domain),
    // so the main address and deposit #0 never collide.
    SeedMaster m = pat<32>(2, 7);
    EXPECT_NE(deriveSpendKeys(m).first, deriveDepositSpendKeys(m, 0).first);
}

TEST(PqSeed, DepositKeysShareTheSingleViewKey) {
    // Spec 1: the whole deposit family decapsulates with ONE shared view key. The
    // view key is the account's view key, independent of any deposit index.
    SeedMaster m = pat<32>(2, 7);
    auto view = deriveViewKeys(m);
    // (No per-index view derivation exists — that is the point. This test just
    // documents that the view key is index-free and stable.)
    EXPECT_EQ(view.first, deriveViewKeys(m).first);
}

TEST(PqDepositAddress, Spec1AddressPerIndexIsDistinctAndDecodes) {
    // A Spec-1 deposit address pairs the ONE shared view key with a per-deposit
    // spend key. Each index yields a distinct, decodable address that recovers the
    // shared view key and that deposit's spend key (what WalletGreen::pqDepositAddress
    // builds for AggregatedMultikey).
    SeedMaster m = pat<32>(3, 9);
    auto view = deriveViewKeys(m);
    const uint64_t prefix = 111;

    std::string prev;
    for (uint32_t i = 0; i < 4; ++i) {
        auto dep = deriveDepositSpendKeys(m, i);
        PqAddress addr = makePqAddress(prefix, view.first, dep.first);
        std::string enc = encodePqAddress(addr);
        ASSERT_FALSE(enc.empty());
        EXPECT_NE(enc, prev);  // each deposit address differs
        prev = enc;

        PqAddress dec;
        ASSERT_TRUE(decodePqAddress(enc, dec));
        EXPECT_EQ(dec.viewPub, view.first);    // shared view key
        EXPECT_EQ(dec.spendPub, dep.first);    // this deposit's spend key
    }
}

// --- Address encode / decode ---------------------------------------------

TEST(PqAddress, ChecksumDerivation) {
    KemPublicKey vp = pat<1184>(3, 1);
    DsaPublicKey sp = pat<1952>(2, 3);
    PqAddress a = makePqAddress(0x2A, vp, sp);
    EXPECT_EQ(a.version, 0x01);
    EXPECT_EQ(a.checksum, pqAddressChecksum(a));
}

TEST(PqAddress, Bech32mRoundTrip) {
    KemPublicKey vp = pat<1184>(3, 1);
    DsaPublicKey sp = pat<1952>(2, 3);
    PqAddress a = makePqAddress(0x2A, vp, sp);
    std::string enc = encodePqAddress(a);  // defaults to the mainnet "disc" HRP
    ASSERT_FALSE(enc.empty());
    EXPECT_EQ(enc.rfind("disc1", 0), 0u);  // self-identifying mainnet prefix
    PqAddress b;
    ASSERT_TRUE(decodePqAddress(enc, b));
    EXPECT_EQ(a.version, b.version);
    EXPECT_EQ(a.networkPrefix, b.networkPrefix);
    EXPECT_EQ(a.viewPub, b.viewPub);
    EXPECT_EQ(a.spendPub, b.spendPub);
    EXPECT_EQ(a.checksum, b.checksum);
}

TEST(PqAddress, TestnetHrpRoundTripAndDistinct) {
    KemPublicKey vp = pat<1184>(3, 1);
    DsaPublicKey sp = pat<1952>(2, 3);
    PqAddress a = makePqAddress(0x2A, vp, sp);
    std::string mainnet = encodePqAddress(a, kPqBech32HrpMainnet);
    std::string testnet = encodePqAddress(a, kPqBech32HrpTestnet);
    EXPECT_EQ(testnet.rfind("tdisc1", 0), 0u);
    EXPECT_NE(mainnet, testnet);  // same keys, visibly different network prefix
    // Both are accepted on decode (the node knows its own network).
    PqAddress b;
    ASSERT_TRUE(decodePqAddress(testnet, b));
    EXPECT_EQ(a.spendPub, b.spendPub);
}

TEST(PqAddress, VaryingNetworkPrefix) {
    KemPublicKey vp = pat<1184>(5, 2);
    DsaPublicKey sp = pat<1952>(2, 3);
    for (uint64_t net : {0ull, 1ull, 0x7Full, 0x80ull, 0x3FFFull, 0xFFFFFFFFull}) {
        PqAddress a = makePqAddress(net, vp, sp);
        std::string enc = encodePqAddress(a);
        PqAddress b;
        ASSERT_TRUE(decodePqAddress(enc, b)) << net;
        EXPECT_EQ(net, b.networkPrefix);
    }
}

TEST(PqAddress, ChecksumTamperRejected) {
    KemPublicKey vp = pat<1184>(3, 1);
    DsaPublicKey sp = pat<1952>(2, 3);
    PqAddress a = makePqAddress(0x2A, vp, sp);
    std::string enc = encodePqAddress(a);
    // Flip a character near the end (inside the encoded checksum region). The
    // bech32m charset is lowercase, so swap within it to stay well-formed.
    enc[enc.size() - 2] = (enc[enc.size() - 2] == 'a') ? 'q' : 'a';
    PqAddress b;
    EXPECT_FALSE(decodePqAddress(enc, b));
}

TEST(PqAddress, WrongHrpRejected) {
    KemPublicKey vp = pat<1184>(3, 1);
    DsaPublicKey sp = pat<1952>(2, 3);
    PqAddress a = makePqAddress(0x2A, vp, sp);
    std::string enc = encodePqAddress(a);
    enc[0] = 'x';  // "disc1..." -> "xisc1...": an unknown HRP
    PqAddress b;
    EXPECT_FALSE(decodePqAddress(enc, b));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
