// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2026, The Karbo developers
//
// This file is part of Karbo.

#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <boost/asio/ssl.hpp>

#include "HttpRequest.h"
#include "HttpResponse.h"
#include <System/Dispatcher.h>
#include <System/TcpConnection.h>
#include <System/TcpStream.h>
#include <System/SslTcpStreambuf.h>

namespace CryptoNote {

class ConnectException : public std::runtime_error {
public:
  explicit ConnectException(const std::string& whatArg);
};

class HttpClient {
public:
  HttpClient(System::Dispatcher& dispatcher, const std::string& address, uint16_t port);

  // SSL client
  HttpClient(System::Dispatcher& dispatcher, const std::string& address, uint16_t port,
    const std::string& certFile, const std::string& keyFile = "", bool sslVerify = true);

  ~HttpClient();

  void request(const HttpRequest& req, HttpResponse& res);

  bool isConnected() const;
  void disconnect();

  // Overrides the default request timeout (see DEFAULT_REQUEST_TIMEOUT below).
  // Exposed mainly so tests can exercise the timeout path without waiting out
  // the real production duration.
  void setRequestTimeout(std::chrono::milliseconds timeout);

private:
  void connect();
  void connectSsl();

  // Bounds one full request/response round trip. Unlike HttpServer's read
  // budgets, there's no keep-alive-idle phase to distinguish here: request()
  // is one self-contained call, and every caller (NodeRpcProxy's queryBlocks,
  // getPoolSymmetricDifference, etc., all reached through BlockchainSynchronizer)
  // blocks synchronously on it. Without a bound, an unresponsive or
  // silently-stalled daemon connection wedges that wait forever, which in turn
  // wedges BlockchainSynchronizer::stop()'s worker-thread join — observed as
  // walletd needing SIGKILL to exit. 2 minutes matches the existing
  // P2P_DEFAULT_INVOKE_TIMEOUT convention: generous enough that a daemon
  // legitimately catching up a deep resync isn't cut off mid-response.
  static constexpr std::chrono::seconds DEFAULT_REQUEST_TIMEOUT{120};
  std::chrono::milliseconds m_requestTimeout{DEFAULT_REQUEST_TIMEOUT};

  // Runs `operation`, aborting the connection if it hasn't finished within
  // m_requestTimeout. Returns true if the timeout fired (operation was aborted
  // mid-flight and its own exception, if any, was swallowed); false if
  // `operation` returned or threw before then (its exception, if any,
  // propagates normally).
  bool runWithTimeout(const std::function<void()>& operation);

  System::Dispatcher& m_dispatcher;
  std::string m_address;
  uint16_t m_port;

  bool m_connected{ false };
  System::TcpConnection m_connection;
  std::unique_ptr<System::TcpStreambuf> m_streamBuf;
  std::unique_ptr<System::SslTcpStreambuf> m_sslStreamBuf;

  // SSL support
  bool m_useSsl{ false };
  bool m_sslVerify{ true };
  std::unique_ptr<boost::asio::ssl::context> m_sslContext;
  std::string m_certFile;
  std::string m_keyFile;
};

} // namespace CryptoNote
