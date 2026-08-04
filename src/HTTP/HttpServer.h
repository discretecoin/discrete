// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2026, The Karbo developers
//
// This file is part of Karbo.

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <string>
#include <unordered_set>
#include <boost/asio/ssl.hpp>

#include "HttpRequest.h"
#include "HttpResponse.h"
#include <System/Dispatcher.h>
#include <System/ContextGroup.h>
#include <System/TcpListener.h>
#include <System/TcpConnection.h>
#include <Logging/LoggerRef.h>

namespace CryptoNote {

class HttpServer {
public:
  typedef std::function<void(const HttpRequest& request, HttpResponse& response)> RequestHandler;

  HttpServer(System::Dispatcher& dispatcher, Logging::ILogger& log);
  virtual ~HttpServer();

  // Start server without SSL
  void start(const std::string& address, uint16_t port, 
             const std::string& user = "", const std::string& password = "");
  
  // Start server with SSL
  void startSsl(const std::string& address, uint16_t port,
                const std::string& certFile, const std::string& keyFile,
                const std::string& dhFile = "",
                const std::string& user = "", const std::string& password = "");
  
  void stop();
  size_t getConnectionsCount() const;
  
  void setRequestHandler(RequestHandler handler);

protected:
  virtual void processRequest(const HttpRequest& request, HttpResponse& response);

private:
  // How long a connection may occupy a dispatcher context without making
  // progress. Reads are the only place the server waits on a client, so both
  // budgets are enforced there: IDLE_TIMEOUT covers waiting for a request to
  // begin (a client that connects and then says nothing), REQUEST_TIMEOUT
  // covers receiving one once it has started (a client that dribbles bytes).
  // The idle budget is deliberately far above any in-tree poll interval —
  // NodeRpcProxy polls every 5s — so keep-alive clients are never dropped
  // mid-conversation.
  static constexpr std::chrono::seconds IDLE_TIMEOUT{120};
  static constexpr std::chrono::seconds REQUEST_TIMEOUT{30};

  // Ceiling on concurrent connections. The timeouts above bound how long any
  // one connection lives without progress; this bounds how many can exist at
  // once, which is what actually caps the resources a peer can tie up.
  static constexpr size_t MAX_CONNECTIONS = 256;

  enum class ReadOutcome {
    Completed,
    TimedOut,
    Failed
  };

  void acceptLoop();
  void connectionWorker(System::TcpConnection& connection);
  ReadOutcome readWithWatchdog(System::TcpConnection& connection,
                               std::chrono::nanoseconds timeout,
                               const std::function<void()>& read);
  bool authenticate(const HttpRequest& request) const;

  System::Dispatcher& m_dispatcher;
  System::ContextGroup workingContextGroup;
  Logging::LoggerRef logger;
  
  System::TcpListener m_listener;
  std::unordered_set<System::TcpConnection*> m_connections;
  
  // SSL support
  bool m_useSsl{false};
  std::unique_ptr<boost::asio::ssl::context> m_sslContext;
  
  // Authentication
  std::string m_credentials; // Base64 encoded user:password
  
  // Request handler
  RequestHandler m_requestHandler;

  // Latch so a flood produces one warning per saturation episode rather than
  // one per refused connection — otherwise the defence becomes its own way to
  // fill the operator's log.
  bool m_connectionLimitReported{ false };

  std::atomic<bool> m_stopping{ false };
};

} // namespace CryptoNote
