// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Tests for the wallet-core PQ identity derivation (src/Wallet/PqWallet). Covers
// deterministic derivation from the account spend secret key (recovery
// contract), the wallet's own address round-trip, and PQ-vs-classical address
// detection used by the front-ends.

#include "gtest/gtest.h"

#include "Wallet/PqWallet.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"

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

TEST(PqWallet, DetectsOwnAddressBothNetworks) {
    PqWalletKeys keys = derivePqWalletKeys(makeSpendSecret(3, 6));
    PqAddress addr = pqWalletAddress(keys, kNet);

    std::string mainnet = encodePqAddress(addr, kPqBech32HrpMainnet);
    std::string testnet = encodePqAddress(addr, kPqBech32HrpTestnet);
    ASSERT_FALSE(mainnet.empty());
    ASSERT_FALSE(testnet.empty());
    EXPECT_NE(mainnet, testnet);

    // Both networks' HRPs are accepted on decode.
    EXPECT_TRUE(isPqAddressString(mainnet));
    EXPECT_TRUE(isPqAddressString(testnet));

    PqAddress out;
    ASSERT_TRUE(parsePqAddress(mainnet, out));
    EXPECT_EQ(out.viewPub, addr.viewPub);
    EXPECT_EQ(out.spendPub, addr.spendPub);

    ASSERT_TRUE(parsePqAddress(testnet, out));
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
    std::string s = encodePqAddress(addr);
    s[s.size() - 2] = (s[s.size() - 2] == 'a') ? 'q' : 'a';
    EXPECT_FALSE(isPqAddressString(s));
}

// PQ account numbers reuse the shared CryptoNote::AccountNumber format; its
// round-trip/checksum behaviour is covered by the AccountNumber tests, not here.

// --- PQ message sign/verify (ML-DSA-65) ------------------------------------

TEST(PqMessage, SignVerifyRoundTrip) {
    PqWalletKeys keys = derivePqWalletKeys(makeSpendSecret(11, 7));
    const std::string msg = "I, the holder of this PQ address, authorize payout #42.";
    std::string sig = signMessagePq(msg, keys.spendSk);
    ASSERT_FALSE(sig.empty());
    EXPECT_TRUE(verifyMessagePq(msg, keys.spendPub, sig));
}

TEST(PqMessage, RejectsTamperedMessage) {
    PqWalletKeys keys = derivePqWalletKeys(makeSpendSecret(11, 7));
    std::string sig = signMessagePq("send 10 to Alice", keys.spendSk);
    EXPECT_FALSE(verifyMessagePq("send 10 to Mallory", keys.spendPub, sig));
}

TEST(PqMessage, RejectsTamperedSignature) {
    PqWalletKeys keys = derivePqWalletKeys(makeSpendSecret(11, 7));
    const std::string msg = "hello world";
    std::string sig = signMessagePq(msg, keys.spendSk);
    ASSERT_GT(sig.size(), 4u);
    // Flip a character in the middle of the base58 blob.
    sig[sig.size() / 2] = (sig[sig.size() / 2] == 'A') ? 'B' : 'A';
    EXPECT_FALSE(verifyMessagePq(msg, keys.spendPub, sig));
}

TEST(PqMessage, RejectsWrongSignerKey) {
    PqWalletKeys signer = derivePqWalletKeys(makeSpendSecret(11, 7));
    PqWalletKeys other  = derivePqWalletKeys(makeSpendSecret(11, 8));
    const std::string msg = "ownership proof";
    std::string sig = signMessagePq(msg, signer.spendSk);
    EXPECT_TRUE(verifyMessagePq(msg, signer.spendPub, sig));
    EXPECT_FALSE(verifyMessagePq(msg, other.spendPub, sig));
}

TEST(PqMessage, RejectsGarbageAndWrongPrefix) {
    PqWalletKeys keys = derivePqWalletKeys(makeSpendSecret(11, 7));
    EXPECT_FALSE(verifyMessagePq("m", keys.spendPub, "not-base58-at-all!!"));
    EXPECT_FALSE(verifyMessagePq("m", keys.spendPub, ""));
}

// Mirrors the DNS checkpoint verification path (src/Checkpoints/Checkpoints.cpp):
// a maintainer signs "<height>:<hash>" with their wallet's ML-DSA spend key and
// publishes their PQ address; the loader decodes that address back to the spend
// public key and verifies the record with verifyMessagePq.
TEST(PqMessage, CheckpointStyleSignAndVerify) {
    PqWalletKeys signer = derivePqWalletKeys(makeSpendSecret(13, 2));
    PqAddress addr = pqWalletAddress(signer, kNet);
    std::string addrStr = encodePqAddress(addr);
    ASSERT_FALSE(addrStr.empty());

    // Loader side: decode the published PQ address back to the ML-DSA spend pubkey.
    PqAddress decoded;
    ASSERT_TRUE(decodePqAddress(addrStr, decoded));
    EXPECT_EQ(decoded.spendPub, signer.spendPub);

    const std::string payload = "1000:" + std::string(64, 'a');
    std::string sig = signMessagePq(payload, signer.spendSk);
    EXPECT_TRUE(verifyMessagePq(payload, decoded.spendPub, sig));

    // A record for a different height is a different payload → rejected.
    EXPECT_FALSE(verifyMessagePq("1001:" + std::string(64, 'a'), decoded.spendPub, sig));
    // A signature from a non-approved signer → rejected.
    PqWalletKeys other = derivePqWalletKeys(makeSpendSecret(13, 3));
    EXPECT_FALSE(verifyMessagePq(payload, other.spendPub, sig));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
