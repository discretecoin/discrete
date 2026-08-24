// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Regression tests for the wallet key-derivation and container-encryption
// contract.

#include "gtest/gtest.h"

#include <cstdio>
#include <cstring>
#include <string>

#include "crypto/chacha8.h"

namespace {

Crypto::Hash makeSalt(uint8_t base) {
  Crypto::Hash salt{};
  for (std::size_t i = 0; i < sizeof(salt.data); ++i) {
    salt.data[i] = static_cast<uint8_t>(base * 7 + i);
  }
  return salt;
}

// RAII guard so a forced-failure test can never leak the flag into its neighbours.
struct ForcedKdfFailure {
  ForcedKdfFailure() { Crypto::kdf_forced_failure() = true; }
  ~ForcedKdfFailure() { Crypto::kdf_forced_failure() = false; }
};

}  // namespace

// --- KDF failure must be reported, never silently keyed --------------------

TEST(WalletKdf, FailureIsReportedAndKeyIsNotTheSentinel) {
  Crypto::chacha8_key key;
  std::memset(&key, 0x5A, sizeof(key));

  ForcedKdfFailure forced;
  Crypto::cn_context context;
  EXPECT_FALSE(Crypto::generate_chacha8_key(context, "correct horse", key));

  // yespower writes an all-0xFF binary on failure. That value is public, so it
  // must never survive as an encryption key.
  Crypto::chacha8_key sentinel;
  std::memset(&sentinel, 0xFF, sizeof(sentinel));
  EXPECT_NE(0, std::memcmp(&key, &sentinel, sizeof(key)));

  Crypto::chacha8_key zero;
  std::memset(&zero, 0, sizeof(zero));
  EXPECT_EQ(0, std::memcmp(&key, &zero, sizeof(key)));
}

TEST(WalletKdf, SucceedsWhenNotForcedToFail) {
  Crypto::chacha8_key key;
  Crypto::cn_context context;
  ASSERT_TRUE(Crypto::generate_chacha8_key(context, "correct horse", key));

  Crypto::chacha8_key sentinel;
  std::memset(&sentinel, 0xFF, sizeof(sentinel));
  EXPECT_NE(0, std::memcmp(&key, &sentinel, sizeof(key)));
}

// --- Salted derivation -----------------------------------------------------

TEST(WalletKdf, SamePasswordDifferentSaltDerivesDifferentKeys) {
  const std::string password = "shared password";
  Crypto::Hash sa = makeSalt(1), sb = makeSalt(2);
  ASSERT_NE(0, std::memcmp(sa.data, sb.data, sizeof(sa.data)));

  Crypto::chacha8_key a, b;
  ASSERT_TRUE(Crypto::generate_chacha8_key_salted(password, sa, a));
  ASSERT_TRUE(Crypto::generate_chacha8_key_salted(password, sb, b));
  EXPECT_NE(0, std::memcmp(&a, &b, sizeof(a)));
}

TEST(WalletKdf, SaltedDerivationDiffersFromLegacyUnsalted) {
  // An all-zero salt must not collapse onto the legacy password-only input, or a
  // migrated wallet would keep its pre-migration key.
  const std::string password = "shared password";
  Crypto::Hash zeroSalt{};
  Crypto::chacha8_key salted, legacy;
  ASSERT_TRUE(Crypto::generate_chacha8_key_salted(password, zeroSalt, salted));
  Crypto::cn_context context;
  ASSERT_TRUE(Crypto::generate_chacha8_key(context, password, legacy));
  EXPECT_NE(0, std::memcmp(&salted, &legacy, sizeof(salted)));
}

TEST(WalletKdf, SamePasswordSameSaltIsDeterministic) {
  const std::string password = "shared password";
  Crypto::chacha8_key a, b;
  ASSERT_TRUE(Crypto::generate_chacha8_key_salted(password, makeSalt(3), a));
  ASSERT_TRUE(Crypto::generate_chacha8_key_salted(password, makeSalt(3), b));
  EXPECT_EQ(0, std::memcmp(&a, &b, sizeof(a)));
}

TEST(WalletKdf, SaltedFailureAlsoZeroesTheKey) {
  Crypto::chacha8_key key;
  std::memset(&key, 0x5A, sizeof(key));

  ForcedKdfFailure forced;
  EXPECT_FALSE(Crypto::generate_chacha8_key_salted("pw", makeSalt(4), key));

  Crypto::chacha8_key zero;
  std::memset(&zero, 0, sizeof(zero));
  EXPECT_EQ(0, std::memcmp(&key, &zero, sizeof(key)));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
