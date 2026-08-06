// Copyright (c) 2026, The Discrete developers

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <thread>

#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include "NodeRpcProxy/NodeRpcProxy.h"

namespace {

class StalledHttpServer {
public:
  StalledHttpServer()
    : acceptor(io, {boost::asio::ip::address_v4::loopback(), 0}),
      requestReceivedFuture(requestReceived.get_future().share()),
      worker([this] { run(); }) {
  }

  ~StalledHttpServer() {
    release();

    if (!accepted.load()) {
      boost::asio::io_context wakeIo;
      boost::asio::ip::tcp::socket wakeSocket(wakeIo);
      boost::system::error_code ignored;
      wakeSocket.connect({boost::asio::ip::address_v4::loopback(), port()}, ignored);
    }

    boost::system::error_code ignored;
    acceptor.close(ignored);
    if (worker.joinable()) {
      worker.join();
    }
  }

  uint16_t port() const {
    return acceptor.local_endpoint().port();
  }

  bool waitForRequest(std::chrono::milliseconds timeout) const {
    return requestReceivedFuture.wait_for(timeout) == std::future_status::ready;
  }

  void release() {
    {
      std::lock_guard<std::mutex> lock(releaseMutex);
      released = true;
    }
    releaseCondition.notify_all();
  }

private:
  void signalRequestReceived() {
    if (!requestSignaled.exchange(true)) {
      requestReceived.set_value();
    }
  }

  void signalRequestFailure() {
    if (!requestSignaled.exchange(true)) {
      requestReceived.set_exception(std::current_exception());
    }
  }

  void run() {
    try {
      boost::asio::ip::tcp::socket socket(io);
      acceptor.accept(socket);
      accepted.store(true);

      boost::asio::streambuf request;
      boost::asio::read_until(socket, request, "\r\n\r\n");
      signalRequestReceived();

      std::unique_lock<std::mutex> lock(releaseMutex);
      releaseCondition.wait_for(lock, std::chrono::seconds(5), [this] { return released; });
      lock.unlock();

      boost::system::error_code ignored;
      socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
      socket.close(ignored);
    } catch (...) {
      signalRequestFailure();
    }
  }

  boost::asio::io_context io;
  boost::asio::ip::tcp::acceptor acceptor;
  std::promise<void> requestReceived;
  std::shared_future<void> requestReceivedFuture;
  std::atomic<bool> accepted{false};
  std::atomic<bool> requestSignaled{false};
  std::mutex releaseMutex;
  std::condition_variable releaseCondition;
  bool released = false;
  std::thread worker;
};

} // namespace

TEST(NodeRpcProxyShutdown, cancelsInFlightHttpRequest) {
  using namespace std::chrono_literals;

  StalledHttpServer server;
  CryptoNote::NodeRpcProxy node("127.0.0.1", server.port(), "/", false);

  std::promise<std::error_code> initialized;
  auto initializedFuture = initialized.get_future();
  node.init([&initialized](std::error_code result) {
    initialized.set_value(result);
  });

  if (initializedFuture.wait_for(2s) != std::future_status::ready) {
    server.release();
    FAIL() << "NodeRpcProxy initialization timed out";
    return;
  }

  const std::error_code initResult = initializedFuture.get();
  if (initResult) {
    server.release();
    EXPECT_FALSE(initResult) << initResult.message();
    return;
  }

  if (!server.waitForRequest(2s)) {
    server.release();
    node.shutdown();
    FAIL() << "NodeRpcProxy did not start its HTTP status request";
    return;
  }

  auto shutdownFuture = std::async(std::launch::async, [&node] {
    return node.shutdown();
  });

  const bool stoppedPromptly = shutdownFuture.wait_for(1s) == std::future_status::ready;
  if (!stoppedPromptly) {
    server.release();
  }

  EXPECT_TRUE(shutdownFuture.get());
  EXPECT_TRUE(stoppedPromptly);
  server.release();
}
