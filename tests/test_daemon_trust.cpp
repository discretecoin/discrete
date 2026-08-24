// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Compact Account Numbers are locators, not self-contained addresses: the wallet
// asks a daemon which keys (H, I) points at and pays whatever comes back, so
// resolution is a trust decision. These tests pin the policy and the fail-closed
// behaviour: sending to a compact number through an untrusted daemon must stop
// before any output is built, while a full address goes through unaffected.

#include "gtest/gtest.h"

#include <cstring>
#include <string>

#include "AccountNumber.h"
#include "Common/DaemonTrust.h"
#include "CryptoNoteConfig.h"
#include "INode.h"
#include "PqAddress.h"
#include "Wallet/PqRecipient.h"
#include "crypto_pq/PqSeed.h"

using namespace CryptoNote;

namespace {

// A node that answers a compact-number lookup with keys of its own choosing. Its
// trust flag is settable so the same node can be tried from both sides of the
// policy.
class ColliderNode : public INode {
public:
  ColliderNode(bool trusted, const CryptoPQ::KemPublicKey& viewPub,
               const CryptoPQ::DsaPublicKey& spendPub)
      : m_trusted(trusted), m_viewPub(viewPub), m_spendPub(spendPub) {}
  ~ColliderNode() override {}

  bool isTrustedResolver() const override { return m_trusted; }

  void resolvePqAccount(uint32_t, uint32_t, bool& found, std::string& viewPubHex,
                        std::string& spendPubHex, const Callback& callback) override {
    ++m_lookups;
    found = true;
    viewPubHex = toHex(m_viewPub.data(), m_viewPub.size());
    spendPubHex = toHex(m_spendPub.data(), m_spendPub.size());
    callback(std::error_code());
  }

  size_t lookups() const { return m_lookups; }

  // Nothing else is exercised.
  bool addObserver(INodeObserver*) override { return true; }
  bool removeObserver(INodeObserver*) override { return true; }
  void init(const Callback& callback) override { callback(std::error_code()); }
  bool shutdown() override { return true; }
  size_t getPeerCount() const override { return 0; }
  uint32_t getLastLocalBlockHeight() const override { return 0; }
  uint32_t getLastKnownBlockHeight() const override { return 0; }
  uint32_t getLocalBlockCount() const override { return 0; }
  uint32_t getKnownBlockCount() const override { return 0; }
  uint64_t getLastLocalBlockTimestamp() const override { return 0; }
  uint32_t getNodeHeight() const override { return 0; }
  uint64_t getMinimalFee() const override { return 0; }
  uint64_t getNextDifficulty() const override { return 0; }
  uint64_t getNextReward() const override { return 0; }
  uint64_t getAlreadyGeneratedCoins() const override { return 0; }
  uint64_t getTransactionsCount() const override { return 0; }
  uint64_t getTransactionsPoolSize() const override { return 0; }
  uint64_t getAltBlocksCount() const override { return 0; }
  uint64_t getOutConnectionsCount() const override { return 0; }
  uint64_t getIncConnectionsCount() const override { return 0; }
  uint64_t getRpcConnectionsCount() const override { return 0; }
  uint64_t getWhitePeerlistSize() const override { return 0; }
  uint64_t getGreyPeerlistSize() const override { return 0; }
  std::string getNodeVersion() const override { return ""; }
  BlockHeaderInfo getLastLocalBlockHeaderInfo() const override { return BlockHeaderInfo(); }
  void relayTransaction(const Transaction&, const Callback& callback) override {
    callback(std::error_code());
  }
  void getNewBlocks(std::vector<Crypto::Hash>&&, std::vector<block_complete_entry>&,
                    uint32_t& startHeight, const Callback& callback) override {
    startHeight = 0;
    callback(std::error_code());
  }
  void getTransactionOutsGlobalIndices(const Crypto::Hash&, std::vector<uint32_t>&,
                                       const Callback& callback) override {
    callback(std::error_code());
  }
  void queryBlocks(std::vector<Crypto::Hash>&&, uint64_t, std::vector<BlockShortEntry>&,
                   uint32_t& startHeight, const Callback& callback) override {
    startHeight = 0;
    callback(std::error_code());
  }
  void getPoolSymmetricDifference(std::vector<Crypto::Hash>&&, Crypto::Hash, bool& isBcActual,
                                  std::vector<std::unique_ptr<ITransactionReader>>&,
                                  std::vector<Crypto::Hash>&, const Callback& callback) override {
    isBcActual = true;
    callback(std::error_code());
  }
  void getBlocks(const std::vector<uint32_t>&, std::vector<std::vector<BlockDetails>>&,
                 const Callback& callback) override {
    callback(std::error_code());
  }
  void getBlocks(const std::vector<Crypto::Hash>&, std::vector<BlockDetails>&,
                 const Callback& callback) override {
    callback(std::error_code());
  }
  void getBlocks(uint64_t, uint64_t, uint32_t, std::vector<BlockDetails>&, uint32_t&,
                 const Callback& callback) override {
    callback(std::error_code());
  }
  void getBlock(const uint32_t, BlockDetails&, const Callback& callback) override {
    callback(std::error_code());
  }
  void getTransaction(const Crypto::Hash&, Transaction&, const Callback& callback) override {
    callback(std::error_code());
  }
  void getTransactions(const std::vector<Crypto::Hash>&, std::vector<TransactionDetails>&,
                       const Callback& callback) override {
    callback(std::error_code());
  }
  void getTransactionsByPaymentId(const Crypto::Hash&, std::vector<TransactionDetails>&,
                                  const Callback& callback) override {
    callback(std::error_code());
  }
  void getPoolTransactions(uint64_t, uint64_t, uint32_t, std::vector<TransactionDetails>&,
                           uint64_t&, const Callback& callback) override {
    callback(std::error_code());
  }
  void getBlockTimestamp(uint32_t, uint64_t&, const Callback& callback) override {
    callback(std::error_code());
  }
  void isSynchronized(bool&, const Callback& callback) override { callback(std::error_code()); }
  void getConnections(std::vector<p2pConnection>&, const Callback& callback) override {
    callback(std::error_code());
  }
  void setRootCert(const std::string&) override {}
  void disableVerify() override {}

private:
  static std::string toHex(const uint8_t* data, size_t size) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
      out.push_back(digits[data[i] >> 4]);
      out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
  }

  bool m_trusted;
  CryptoPQ::KemPublicKey m_viewPub;
  CryptoPQ::DsaPublicKey m_spendPub;
  size_t m_lookups = 0;
};

CryptoPQ::SeedMaster seedOf(uint8_t base) {
  CryptoPQ::SeedMaster seed{};
  for (size_t i = 0; i < seed.size(); ++i) {
    seed[i] = static_cast<uint8_t>(base * 31 + i);
  }
  return seed;
}

}  // namespace

// --- Trust policy ----------------------------------------------------------

TEST(DaemonTrust, LocalDaemonsAreTrusted) {
  EXPECT_TRUE(Common::isTrustedByDefault("127.0.0.1"));
  EXPECT_TRUE(Common::isTrustedByDefault("127.1.2.3"));
  EXPECT_TRUE(Common::isTrustedByDefault("localhost"));
  EXPECT_TRUE(Common::isTrustedByDefault("LocalHost"));
  EXPECT_TRUE(Common::isTrustedByDefault("::1"));
  EXPECT_TRUE(Common::isTrustedByDefault("[::1]"));
}

TEST(DaemonTrust, OfficialEndpointsAreTrusted) {
  ASSERT_GT(sizeof(CryptoNote::OFFICIAL_REMOTE_NODES) / sizeof(char*), 0u);
  const std::string entry = CryptoNote::OFFICIAL_REMOTE_NODES[0];
  const std::string host = entry.substr(0, entry.rfind(':'));
  EXPECT_TRUE(Common::isTrustedByDefault(host));
}

TEST(DaemonTrust, ArbitraryRemoteHostsAreNotTrusted) {
  EXPECT_FALSE(Common::isTrustedByDefault("node.example.com"));
  EXPECT_FALSE(Common::isTrustedByDefault("203.0.113.9"));
  // A lookalike must not inherit the official endpoint's trust.
  EXPECT_FALSE(Common::isTrustedByDefault("node.discrete.cash.evil.example"));
  // Nor may a non-loopback address that merely starts with the same digits.
  EXPECT_FALSE(Common::isTrustedByDefault("12.7.0.1"));
}

// --- Fail-closed resolution ------------------------------------------------

class ResolverTest : public ::testing::Test {
protected:
  void SetUp() override {
    // The keys the payer means to pay.
    const CryptoPQ::SeedMaster real = seedOf(1);
    honestView = CryptoPQ::deriveViewKeys(real).first;
    honestSpend = CryptoPQ::deriveSpendKeys(real).first;

    // Different keys entirely: what a hostile resolver substitutes.
    const CryptoPQ::SeedMaster attacker = seedOf(2);
    forgedView = CryptoPQ::deriveViewKeys(attacker).first;
    forgedSpend = CryptoPQ::deriveSpendKeys(attacker).first;

    // The number the payer types, carrying the honest keys' fingerprint.
    honestFingerprint = pqAccountFingerprint(kTestnet, honestSpend.data(), honestSpend.size(),
                                             honestView.data(), honestView.size());
    AccountNumber acct{ 4821, 7 };
    number = acct.toString(honestFingerprint);
  }

  static constexpr bool kTestnet = true;

  CryptoPQ::KemPublicKey honestView{}, forgedView{};
  CryptoPQ::DsaPublicKey honestSpend{}, forgedSpend{};
  uint32_t honestFingerprint = 0;
  std::string number;
};

TEST_F(ResolverTest, CompactNumberIsRefusedOnAnUntrustedDaemon) {
  ColliderNode node(/*trusted=*/false, honestView, honestSpend);

  CryptoPQ::KemPublicKey viewPub{};
  CryptoPQ::DsaPublicKey spendPub{};
  uint64_t subaddrT = 0;
  std::string error;
  EXPECT_FALSE(resolvePqRecipient(node, kTestnet, number, viewPub, spendPub, subaddrT, &error));
  EXPECT_EQ(std::string(kUntrustedResolverMessage), error);

  // Refused before the lookup, so no output could have been built from it.
  EXPECT_EQ(0u, node.lookups());
}

TEST_F(ResolverTest, CompactNumberResolvesOnATrustedDaemon) {
  ColliderNode node(/*trusted=*/true, honestView, honestSpend);

  CryptoPQ::KemPublicKey viewPub{};
  CryptoPQ::DsaPublicKey spendPub{};
  uint64_t subaddrT = 0;
  std::string error;
  ASSERT_TRUE(resolvePqRecipient(node, kTestnet, number, viewPub, spendPub, subaddrT, &error))
      << error;
  EXPECT_EQ(honestView, viewPub);
  EXPECT_EQ(honestSpend, spendPub);
  EXPECT_EQ(1u, node.lookups());
}

TEST_F(ResolverTest, ColliderIsNeverReachedWhileUntrusted) {
  // The fingerprint check still catches an unrelated substitution, but on an
  // untrusted daemon the payment must not depend on it. Assert the lookup does
  // not even happen.
  ColliderNode node(/*trusted=*/false, forgedView, forgedSpend);

  CryptoPQ::KemPublicKey viewPub{};
  CryptoPQ::DsaPublicKey spendPub{};
  uint64_t subaddrT = 0;
  EXPECT_FALSE(resolvePqRecipient(node, kTestnet, number, viewPub, spendPub, subaddrT, nullptr));
  EXPECT_EQ(0u, node.lookups());
}

TEST_F(ResolverTest, FullAddressWorksThroughAnUntrustedDaemon) {
  ColliderNode node(/*trusted=*/false, forgedView, forgedSpend);

  PqAddress addr{};
  addr.viewPub = honestView;
  addr.spendPub = honestSpend;
  const std::string address = encodePqAddress(addr, pqBech32Hrp(kTestnet));
  CryptoPQ::KemPublicKey viewPub{};
  CryptoPQ::DsaPublicKey spendPub{};
  uint64_t subaddrT = 0;
  std::string error;
  ASSERT_TRUE(resolvePqRecipient(node, kTestnet, address, viewPub, spendPub, subaddrT, &error))
      << error;
  EXPECT_EQ(honestView, viewPub);
  EXPECT_EQ(honestSpend, spendPub);
  EXPECT_EQ(0u, node.lookups());
}

TEST_F(ResolverTest, DepositSubaddressNumberIsAlsoRefused) {
  ColliderNode node(/*trusted=*/false, honestView, honestSpend);

  AccountNumber acct{ 4821, 7 };
  const std::string deposit = acct.toStringWithIndex(3, honestFingerprint);

  CryptoPQ::KemPublicKey viewPub{};
  CryptoPQ::DsaPublicKey spendPub{};
  uint64_t subaddrT = 0;
  std::string error;
  EXPECT_FALSE(resolvePqRecipient(node, kTestnet, deposit, viewPub, spendPub, subaddrT, &error));
  EXPECT_EQ(std::string(kUntrustedResolverMessage), error);
  EXPECT_EQ(0u, node.lookups());
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
