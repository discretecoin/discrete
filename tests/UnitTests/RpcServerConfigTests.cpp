// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.

#include "gtest/gtest.h"

#include "Rpc/RpcServerConfig.h"

namespace {

TEST(RpcServerConfig, StopDaemonRequiresUnrestrictedLoopbackRpc) {
  EXPECT_TRUE(CryptoNote::isStopDaemonRpcAllowed(false, "127.0.0.0"));
  EXPECT_TRUE(CryptoNote::isStopDaemonRpcAllowed(false, "127.0.0.1"));
  EXPECT_TRUE(CryptoNote::isStopDaemonRpcAllowed(false, "127.1.2.3"));
  EXPECT_TRUE(CryptoNote::isStopDaemonRpcAllowed(false, "127.255.255.255"));

  EXPECT_FALSE(CryptoNote::isStopDaemonRpcAllowed(true, "127.0.0.1"));
  EXPECT_FALSE(CryptoNote::isStopDaemonRpcAllowed(false, "126.255.255.255"));
  EXPECT_FALSE(CryptoNote::isStopDaemonRpcAllowed(false, "128.0.0.0"));
  EXPECT_FALSE(CryptoNote::isStopDaemonRpcAllowed(false, "0.0.0.0"));
  EXPECT_FALSE(CryptoNote::isStopDaemonRpcAllowed(false, "192.168.1.10"));
  EXPECT_FALSE(CryptoNote::isStopDaemonRpcAllowed(false, "::1"));
  EXPECT_FALSE(CryptoNote::isStopDaemonRpcAllowed(false, "not-an-ip"));
}

TEST(RpcServerConfig, StopDaemonRequiresNonBrowserJsonPost) {
  EXPECT_TRUE(CryptoNote::isStopDaemonHttpRequestAllowed("POST", "application/json", false));
  EXPECT_TRUE(CryptoNote::isStopDaemonHttpRequestAllowed("POST", "application/json;charset=utf-8", false));
  EXPECT_TRUE(CryptoNote::isStopDaemonHttpRequestAllowed("POST", " Application/JSON ; charset=utf-8", false));

  EXPECT_FALSE(CryptoNote::isStopDaemonHttpRequestAllowed("GET", "application/json", false));
  EXPECT_FALSE(CryptoNote::isStopDaemonHttpRequestAllowed("OPTIONS", "application/json", false));
  EXPECT_FALSE(CryptoNote::isStopDaemonHttpRequestAllowed("POST", "", false));
  EXPECT_FALSE(CryptoNote::isStopDaemonHttpRequestAllowed("POST", "text/plain", false));
  EXPECT_FALSE(CryptoNote::isStopDaemonHttpRequestAllowed("POST", "application/jsonx", false));
  EXPECT_FALSE(CryptoNote::isStopDaemonHttpRequestAllowed("POST", "application/json", true));
}

} // namespace
