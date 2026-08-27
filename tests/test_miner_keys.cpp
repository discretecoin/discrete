// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// The miner holds the wallet's long-lived ML-DSA spend secret so it can sign
// block candidates. That key also authorizes spends, so it must not stay
// resident once mining is not running: stopping, failing to start, and
// destruction all have to leave it zeroed. Only an explicit pause that intends
// to resume (the "all peers disconnected" case) may keep it.

#include "gtest/gtest.h"

#include <algorithm>

#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/Miner.h"
#include "crypto_pq/PqSeed.h"
#include <Logging/ConsoleLogger.h>

using namespace CryptoNote;

namespace {

// Minimal IMinerHandler. `templateAvailable` decides whether start() can obtain
// a block template, which is what makes start() succeed or fail.
class StubHandler : public IMinerHandler {
public:
  explicit StubHandler(bool templateAvailable) : m_templateAvailable(templateAvailable) {}

  bool handle_block_found(Block&) override { return true; }

  bool get_block_template_pq(Block& b, const CryptoPQ::KemPublicKey&,
                             const CryptoPQ::DsaPublicKey&, Difficulty& diffic,
                             uint32_t& height, const BinaryArray&) override {
    if (!m_templateAvailable) {
      return false;
    }
    b = Block();
    b.majorVersion = BLOCK_MAJOR_VERSION_1;
    b.minorVersion = BLOCK_MINOR_VERSION_0;
    // Unreachable difficulty: the workers must never actually find a block.
    diffic = std::numeric_limits<Difficulty>::max();
    height = 1;
    return true;
  }

  bool getBlockLongHash(Crypto::cn_context&, const Block&, Crypto::Hash& res) override {
    res = Crypto::Hash{};
    return true;
  }

private:
  bool m_templateAvailable;
};

CryptoPQ::DsaSecretKey miningSecret() {
  CryptoPQ::SeedMaster seed{};
  for (size_t i = 0; i < seed.size(); ++i) {
    seed[i] = static_cast<uint8_t>(i * 5 + 1);
  }
  return CryptoPQ::deriveSpendKeys(seed).second;
}

CryptoPQ::DsaPublicKey miningPublic() {
  CryptoPQ::SeedMaster seed{};
  for (size_t i = 0; i < seed.size(); ++i) {
    seed[i] = static_cast<uint8_t>(i * 5 + 1);
  }
  return CryptoPQ::deriveSpendKeys(seed).first;
}

class MinerKeyTest : public ::testing::Test {
protected:
  MinerKeyTest()
      : logger(Logging::ERROR),
        currency(CurrencyBuilder(logger).testnet(true).currency()) {}

  Logging::ConsoleLogger logger;
  Currency currency;
};

}  // namespace

TEST_F(MinerKeyTest, ArmingLoadsCredentials) {
  StubHandler handler(true);
  miner m(currency, handler, logger);

  ASSERT_FALSE(m.pqKeysLoaded());
  ASSERT_TRUE(m.pqSpendSecretCleared());

  ASSERT_TRUE(m.startPqWhenSynchronized(CryptoPQ::KemPublicKey{}, miningPublic(),
                                        miningSecret(), 1));
  EXPECT_TRUE(m.pqKeysLoaded());
  EXPECT_FALSE(m.pqSpendSecretCleared());

  m.stop();
}

TEST_F(MinerKeyTest, StopWipesTheSpendSecret) {
  StubHandler handler(true);
  miner m(currency, handler, logger);

  ASSERT_TRUE(m.startPqWhenSynchronized(CryptoPQ::KemPublicKey{}, miningPublic(),
                                        miningSecret(), 1));
  ASSERT_FALSE(m.pqSpendSecretCleared());

  m.stop(false);

  EXPECT_FALSE(m.pqKeysLoaded());
  EXPECT_TRUE(m.pqSpendSecretCleared())
      << "the ML-DSA spend secret is still resident after mining stopped";
}

TEST_F(MinerKeyTest, PauseForResumeKeepsCredentials) {
  // stop(true) is the "all peers disconnected" pause: mining is meant to resume
  // on its own, so the credentials have to survive it.
  StubHandler handler(true);
  miner m(currency, handler, logger);

  ASSERT_TRUE(m.startPqWhenSynchronized(CryptoPQ::KemPublicKey{}, miningPublic(),
                                        miningSecret(), 1));
  m.stop(true);

  EXPECT_TRUE(m.pqKeysLoaded());
  EXPECT_FALSE(m.pqSpendSecretCleared());

  m.stop(false);
  EXPECT_TRUE(m.pqSpendSecretCleared());
}

TEST_F(MinerKeyTest, FailedStartDoesNotLeaveTheSecretBehind) {
  // No block template, so start() fails. Nothing is mining, so nothing has any
  // use for the secret.
  StubHandler handler(false);
  miner m(currency, handler, logger);

  EXPECT_FALSE(m.startPq(CryptoPQ::KemPublicKey{}, miningPublic(), miningSecret(), 1));

  EXPECT_FALSE(m.pqKeysLoaded());
  EXPECT_TRUE(m.pqSpendSecretCleared())
      << "a failed mining start left the ML-DSA spend secret resident";
}

TEST_F(MinerKeyTest, RunningMinerReleasesTheSecretOnStop) {
  StubHandler handler(true);
  miner m(currency, handler, logger);

  ASSERT_TRUE(m.startPq(CryptoPQ::KemPublicKey{}, miningPublic(), miningSecret(), 1));
  EXPECT_TRUE(m.pqKeysLoaded());

  m.stop();

  EXPECT_FALSE(m.pqKeysLoaded());
  EXPECT_TRUE(m.pqSpendSecretCleared());
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
