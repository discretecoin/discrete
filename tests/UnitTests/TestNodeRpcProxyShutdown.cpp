// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Regression test for issue #11's remaining shutdown hang: a context blocked
// inside a synchronous node RPC call (HttpClient::request(), reached via
// NodeRpcProxy's pull loop) didn't check the shutdown flag at all, so
// NodeRpcProxy::shutdown() waited on it for as long as the call took to
// resolve on its own -- unbounded against a daemon that never responds.

#include "gtest/gtest.h"

#include "NodeRpcProxy/NodeRpcProxy.h"

#include <System/ContextGroup.h>
#include <System/Dispatcher.h>
#include <System/InterruptedException.h>
#include <System/Ipv4Address.h>
#include <System/TcpConnection.h>
#include <System/TcpListener.h>

#include <chrono>
#include <future>
#include <thread>
#include <vector>

using namespace CryptoNote;

namespace {

// A fake daemon that accepts a connection but never reads or writes anything --
// exercising the "daemon accepted the connection but never responds" path
// without needing a real discreted process.
class UnresponsiveFakeDaemon {
public:
  explicit UnresponsiveFakeDaemon(uint16_t port) : m_port(port) {
    auto readyFuture = m_ready.get_future();
    m_thread = std::thread([this] { run(); });
    readyFuture.wait();
  }

  ~UnresponsiveFakeDaemon() {
    // Cross-thread cancellation, same technique NodeRpcProxy::shutdown() itself
    // uses: post into the dispatcher's own thread, interrupt from there.
    System::Dispatcher* dispatcher = m_dispatcher;
    System::ContextGroup* contextGroup = m_contextGroup;
    if (dispatcher != nullptr && contextGroup != nullptr) {
      dispatcher->remoteSpawn([contextGroup] {
        contextGroup->interrupt();
      });
    }

    if (m_thread.joinable()) {
      m_thread.join();
    }
  }

private:
  void run() {
    System::Dispatcher dispatcher;
    m_dispatcher = &dispatcher;
    System::ContextGroup contextGroup(dispatcher);
    m_contextGroup = &contextGroup;
    System::TcpListener listener(dispatcher, System::Ipv4Address("127.0.0.1"), m_port);

    std::vector<System::TcpConnection> heldConnections;

    contextGroup.spawn([&] {
      try {
        for (;;) {
          // Held open, never read or written to -- the connection is
          // accepted, then silence.
          heldConnections.push_back(listener.accept());
        }
      } catch (const System::InterruptedException&) {
      } catch (const std::exception&) {
      }
    });

    m_ready.set_value();

    contextGroup.wait();

    m_dispatcher = nullptr;
    m_contextGroup = nullptr;
  }

  uint16_t m_port;
  std::thread m_thread;
  std::promise<void> m_ready;
  System::Dispatcher* m_dispatcher{nullptr};
  System::ContextGroup* m_contextGroup{nullptr};
};

}

TEST(NodeRpcProxyShutdown, ShutdownIsBoundedAgainstAnUnresponsiveDaemon) {
  const uint16_t port = 18766;
  UnresponsiveFakeDaemon daemon(port);

  NodeRpcProxy nodeProxy("127.0.0.1", port, "/", false);

  std::promise<std::error_code> initCompleted;
  auto initFuture = initCompleted.get_future();
  nodeProxy.init([&initCompleted](std::error_code ec) mutable {
    initCompleted.set_value(ec);
  });

  ASSERT_EQ(initFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);

  // Give the background pull loop (fires immediately on init) time to issue
  // its first request against the fake daemon and get stuck on it.
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  auto start = std::chrono::steady_clock::now();
  bool result = nodeProxy.shutdown();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

  EXPECT_TRUE(result);
  // Bounded by contextGroup interruption, not by HttpClient's 120s watchdog --
  // this should come back in well under a second.
  EXPECT_LT(elapsed.count(), 5000);
}
