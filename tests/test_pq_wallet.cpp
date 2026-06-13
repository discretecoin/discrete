// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Tests for the wallet-core PQ identity bridge (src/Wallet/PqWallet). Covers
// deterministic derivation from the classical spend secret key (recovery
// contract), the wallet's own address round-trip, and PQ-vs-classical address
// detection used by the front-ends.

#include "gtest/gtest.h"

#include "Wallet/PqWallet.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

using namespace CryptoNote;

namespace {

// Deterministic fake spend secret key (content irrelevant; we only need 32
// stable bytes — these tests never touch the ed25519 curve).
Crypto::SecretKey makeSpendSecret(uint8_t a, uint8_t b) {
    Crypto::SecretKey k;
    for (std::size_t i = 0; i < sizeof(k.data); ++i)
        k.data[i] = static_cast<uint8_t>(i * a + b);
    return k;
}

constexpr uint64_t kNet = 111;  // placeholder PQ network prefix

}  // namespace

// --- Recovery contract: same spend secret -> same PQ identity --------------

TEST(PqWallet, DerivationDeterministic) {
    Crypto::SecretKey s = makeSpendSecret(7, 3);
    PqWalletKeys a = derivePqWalletKeys(s);
    PqWalletKeys b = derivePqWalletKeys(s);
    EXPECT_EQ(a.seedMaster, b.seedMaster);
    EXPECT_EQ(a.viewPub, b.viewPub);
    EXPECT_EQ(a.viewSk, b.viewSk);
    EXPECT_EQ(a.spendPub, b.spendPub);
    EXPECT_EQ(a.spendSk, b.spendSk);
}

TEST(PqWallet, DistinctSecretsGiveDistinctIdentities) {
    PqWalletKeys a = derivePqWalletKeys(makeSpendSecret(7, 3));
    PqWalletKeys b = derivePqWalletKeys(makeSpendSecret(7, 4));
    EXPECT_NE(a.seedMaster, b.seedMaster);
    EXPECT_NE(a.viewPub, b.viewPub);
    EXPECT_NE(a.spendPub, b.spendPub);
}

TEST(PqWallet, SeedMasterIsNotTheSpendSecret) {
    // Domain separation: the PQ master seed must differ from the raw classical
    // key it is derived from.
    Crypto::SecretKey s = makeSpendSecret(2, 9);
    CryptoPQ::SeedMaster m = pqSeedMasterFromSpendSecret(s);
    EXPECT_NE(0, std::memcmp(m.data(), s.data, sizeof(s.data)));
}

TEST(PqWallet, SeedMasterIsCemented) {
    // Pin the wallet-layer recovery derivation. A change here orphans every
    // existing PQ balance on restore, so it must be deliberate. Spend secret =
    // bytes 0..31 (i.e. value i for index i).
    Crypto::SecretKey s;
    for (std::size_t i = 0; i < sizeof(s.data); ++i) s.data[i] = static_cast<uint8_t>(i);
    CryptoPQ::SeedMaster m = pqSeedMasterFromSpendSecret(s);
    std::string hex; hex.reserve(64);
    static const char* h = "0123456789abcdef";
    for (uint8_t x : m) { hex += h[x >> 4]; hex += h[x & 0xf]; }
    // HKDF-SHA3-256(IKM=0x00..0x1f, salt=0x00*32, info="karbo-pq-wallet-seed-v1").
    // Recompute and update this line ONLY when deliberately changing the
    // recovery derivation (which orphans existing PQ balances).
    EXPECT_EQ(hex, "54b4cced4677aca6e56bc905484a7cc6e0d66a37de82b1537cdf31bd78b8cbd5");
}

// --- The wallet's own address ----------------------------------------------

TEST(PqWallet, AddressMatchesDerivedKeys) {
    Crypto::SecretKey s = makeSpendSecret(5, 1);
    PqWalletKeys keys = derivePqWalletKeys(s);
    PqAddress addr = pqWalletAddress(keys, kNet);
    EXPECT_EQ(addr.viewPub, keys.viewPub);
    EXPECT_EQ(addr.spendPub, keys.spendPub);
    EXPECT_EQ(addr.networkPrefix, kNet);
    EXPECT_EQ(addr.checksum, pqAddressChecksum(addr));

    // Convenience overload must agree.
    PqAddress addr2 = pqWalletAddress(s, kNet);
    EXPECT_EQ(addr.viewPub, addr2.viewPub);
    EXPECT_EQ(addr.spendPub, addr2.spendPub);
}

TEST(PqWallet, ScanKeysExposeViewSecretAndSpendPublic) {
    PqWalletKeys keys = derivePqWalletKeys(makeSpendSecret(8, 2));
    CryptoPQ::PqScanKeys sk = pqScanKeys(keys);
    EXPECT_EQ(sk.viewSk, keys.viewSk);
    EXPECT_EQ(sk.spendPub, keys.spendPub);
}

// --- Address detection / parsing for the front-ends ------------------------

TEST(PqWallet, DetectsOwnAddressBothEncodings) {
    PqWalletKeys keys = derivePqWalletKeys(makeSpendSecret(3, 6));
    PqAddress addr = pqWalletAddress(keys, kNet);

    std::string b58 = encodePqAddress(addr, PqAddressEncoding::Base58);
    std::string b32 = encodePqAddress(addr, PqAddressEncoding::Bech32m);
    ASSERT_FALSE(b58.empty());
    ASSERT_FALSE(b32.empty());

    EXPECT_TRUE(isPqAddressString(b58));
    EXPECT_TRUE(isPqAddressString(b32));

    PqAddress out;
    PqAddressEncoding enc;
    ASSERT_TRUE(parsePqAddress(b58, out, &enc));
    EXPECT_EQ(enc, PqAddressEncoding::Base58);
    EXPECT_EQ(out.viewPub, addr.viewPub);
    EXPECT_EQ(out.spendPub, addr.spendPub);

    ASSERT_TRUE(parsePqAddress(b32, out, &enc));
    EXPECT_EQ(enc, PqAddressEncoding::Bech32m);
    EXPECT_EQ(out.spendPub, addr.spendPub);
}

TEST(PqWallet, RejectsClassicalAndGarbageStrings) {
    // A classical Karbo address is ~98 chars; well below the PQ length floor.
    EXPECT_FALSE(isPqAddressString(
        "Kctv8e8GfNW4nXKMxRtFGfBjA9tQ4tCq9hQ1AYzM6r2Z3p5cN8m6tQ9LhP1xT2yU3vW4xY5zA6bC7dE8fG9hJ0kL1mNoP"));
    EXPECT_FALSE(isPqAddressString(""));
    EXPECT_FALSE(isPqAddressString("not a pq address"));

    PqAddress out;
    EXPECT_FALSE(parsePqAddress("garbage", out));
}

TEST(PqWallet, ChecksumTamperRejectedThroughParse) {
    PqAddress addr = pqWalletAddress(makeSpendSecret(4, 4), kNet);
    std::string b58 = encodePqAddress(addr, PqAddressEncoding::Base58);
    b58[b58.size() - 2] = (b58[b58.size() - 2] == 'A') ? 'B' : 'A';
    EXPECT_FALSE(isPqAddressString(b58));
}

// PQ account numbers reuse the shared CryptoNote::AccountNumber format; its
// round-trip/checksum behaviour is covered by the AccountNumber tests, not here.

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
