// Copyright (c) 2026, The Discrete developers

#include "gtest/gtest.h"

#include "CryptoNoteProtocol/SyncPowThreadCount.h"

TEST(SyncPowThreadCount, ExplicitRequestIsAuthoritativeAndClamped) {
  EXPECT_EQ(CryptoNote::resolveSyncPowThreadCount(1, 32, 2), 1u);
  EXPECT_EQ(CryptoNote::resolveSyncPowThreadCount(5, 8, 2), 5u);
  EXPECT_EQ(CryptoNote::resolveSyncPowThreadCount(32, 0, 64), 32u);
  EXPECT_EQ(CryptoNote::resolveSyncPowThreadCount(64, 0, 64), 32u);
}

TEST(SyncPowThreadCount, AutoModeCapsAtEightAndReservesConcurrentWork) {
  EXPECT_EQ(CryptoNote::resolveSyncPowThreadCount(0, 0, 64), 8u);
  EXPECT_EQ(CryptoNote::resolveSyncPowThreadCount(0, 3, 8), 5u);
  EXPECT_EQ(CryptoNote::resolveSyncPowThreadCount(0, 7, 8), 1u);
  EXPECT_EQ(CryptoNote::resolveSyncPowThreadCount(0, 8, 8), 1u);
  EXPECT_EQ(CryptoNote::resolveSyncPowThreadCount(0, 99, 8), 1u);
}

TEST(SyncPowThreadCount, UnknownHardwareStillSelectsOneWorker) {
  EXPECT_EQ(CryptoNote::resolveSyncPowThreadCount(0, 0, 0), 1u);
  EXPECT_EQ(CryptoNote::resolveSyncPowThreadCount(0, 4, 0), 1u);
}
