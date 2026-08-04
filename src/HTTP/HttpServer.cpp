// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2026, The Karbo developers
//
// This file is part of Karbo.

#include "HttpServer.h"
#include "HttpParser.h"
#include <stdexcept>
#include <boost/scope_exit.hpp>
#include <Common/base64.hpp>
#include <Common/StringTools.h>
#include <System/ContextGroup.h>
#include <System/InterruptedException.h>
#include <System/TcpStream.h>
#include <System/Timer.h>
#include <System/Ipv4Address.h>
#include <System/SslTcpStreambuf.h>

using namespace Logging;

namespace {
  void fillUnauthorizedResponse(CryptoNote::HttpResponse& response) {
    response.setStatus(CryptoNote::HttpResponse::STATUS_401);
    response.addHeader("WWW-Authenticate", "Basic realm=\"RPC\"");
    response.addHeader("Content-Type", "text/plain");
    response.setBody("Authorization required");
  }
}

namespace CryptoNote {

HttpServer::HttpServer(System::Dispatcher& dispatcher, Logging::ILogger& log)
  : m_dispatcher(dispatcher), 
    workingContextGroup(dispatcher), 
    logger(log, "HttpServer") {
}

HttpServer::~HttpServer() {
  try {
    stop();
  }
  catch (...) {
    // Suppress exceptions in destructor
  }
}

void HttpServer::start(const std::string& address, uint16_t port,
                       const std::string& user, const std::string& password) {
  m_useSsl = false;
  
  try {
    m_listener = System::TcpListener(m_dispatcher, System::Ipv4Address(address), port);
  } catch (const std::exception& e) {
    logger(ERROR) << "Failed to start HTTP server on " << address << ":" << port 
                  << " - " << e.what();
    throw;
  }
  
  if (!user.empty() || !password.empty()) {
    m_credentials = base64::encode(Common::asBinaryArray(user + ":" + password));
  }
  
  logger(INFO) << "HTTP server started on " << address << ":" << port;
  
  workingContextGroup.spawn(std::bind(&HttpServer::acceptLoop, this));
}

void HttpServer::startSsl(const std::string& address, uint16_t port,
                          const std::string& certFile, const std::string& keyFile,
                          const std::string& dhFile,
                          const std::string& user, const std::string& password) {
  m_useSsl = true;
  
  try {
    // Initialize SSL context
    m_sslContext = std::make_unique<boost::asio::ssl::context>(
      boost::asio::ssl::context::tls_server);
    
    // Set options
    m_sslContext->set_options(
      boost::asio::ssl::context::default_workarounds |
      boost::asio::ssl::context::no_sslv2 |
      boost::asio::ssl::context::no_sslv3 |
      boost::asio::ssl::context::single_dh_use);
    
    // Load certificate
    m_sslContext->use_certificate_chain_file(certFile);
    
    // Load private key
    m_sslContext->use_private_key_file(keyFile, boost::asio::ssl::context::pem);
    
    // Load DH parameters if provided
    if (!dhFile.empty()) {
      m_sslContext->use_tmp_dh_file(dhFile);
    }
    
    // Create listener
    m_listener = System::TcpListener(m_dispatcher, System::Ipv4Address(address), port);
    
  } catch (const std::exception& e) {
    logger(ERROR) << "Failed to start HTTPS server on " << address << ":" << port 
                  << " - " << e.what();
    throw;
  }
  
  if (!user.empty() || !password.empty()) {
    m_credentials = base64::encode(Common::asBinaryArray(user + ":" + password));
  }
  
  logger(INFO) << "HTTPS server started on " << address << ":" << port;
  
  workingContextGroup.spawn(std::bind(&HttpServer::acceptLoop, this));
}

void HttpServer::stop() {
  if (m_stopping.exchange(true)) {
    return;  // Already stopped
  }

  logger(INFO) << "Stopping HTTP server...";

  // Close listener to stop accepting new connections
  try {
    m_listener.close();
    logger(INFO) << "Listener closed";
  }
  catch (const std::exception& e) {
    logger(INFO) << "Error closing listener: " << e.what();
  }

  // Close all active connections to unblock pending reads
  for (auto* conn : m_connections) {
    try {
      boost::system::error_code ec;
      conn->getSocket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
      conn->getSocket().close(ec);
    } catch (...) {
    }
  }

  workingContextGroup.interrupt();
  workingContextGroup.wait();

  logger(INFO) << "HTTP server stopped";
}

size_t HttpServer::getConnectionsCount() const {
  return m_connections.size();
}

void HttpServer::setRequestHandler(RequestHandler handler) {
  m_requestHandler = std::move(handler);
}

void HttpServer::acceptLoop() {
  try {
    System::TcpConnection connection;
    bool accepted = false;

    while (!accepted && !m_stopping) {
      try {
        connection = m_listener.accept();
        accepted = true;
      } catch (System::InterruptedException&) {
        //throw;
        return;
      } catch (const std::exception& e) {
        if (m_stopping) {
          return;
        }

        logger(WARNING) << "Accept failed: " << e.what();
        // try again
      }
    }

    if (m_stopping) {
      return;  // Exit before doing anything else
    }

    // Refuse the connection once the ceiling is reached, but keep accepting so
    // the listener recovers as soon as slots free up.
    if (m_connections.size() >= MAX_CONNECTIONS) {
      if (!m_connectionLimitReported) {
        m_connectionLimitReported = true;
        logger(WARNING) << "Refusing connections: limit of " << MAX_CONNECTIONS
                        << " concurrent connections reached";
      }

      workingContextGroup.spawn(std::bind(&HttpServer::acceptLoop, this));
      return;  // closes the socket with this scope
    }

    if (m_connectionLimitReported) {
      m_connectionLimitReported = false;
      logger(INFO) << "Accepting connections again, "
                   << m_connections.size() << " of " << MAX_CONNECTIONS << " in use";
    }

    // Register connection
    m_connections.insert(&connection);
    BOOST_SCOPE_EXIT_ALL(this, &connection) {
      m_connections.erase(&connection);
    };

    // Spawn new accept loop for next connection
    workingContextGroup.spawn(std::bind(&HttpServer::acceptLoop, this));

    // Handle this connection (pass by reference - connection lives on this stack frame)
    connectionWorker(connection);

  } catch (System::InterruptedException&) {
    // Normal shutdown
  } catch (const std::exception& e) {
    logger(ERROR) << "Accept loop error: " << e.what();
  }
}

HttpServer::ReadOutcome HttpServer::readWithWatchdog(System::TcpConnection& connection,
                                                    std::chrono::nanoseconds timeout,
                                                    const std::function<void()>& read) {
  // Declared before the context group so the group — and with it the sleeping
  // watchdog — is torn down first.
  System::Timer timer(m_dispatcher);
  System::ContextGroup watchdog(m_dispatcher);
  bool expired = false;

  watchdog.spawn([&] {
    try {
      timer.sleep(timeout);
      expired = true;
      // Drop the socket, which is the same lever stop() uses to unblock a
      // pending read. Interrupting the reading context is not enough: the SSL
      // streambuf waits in a plain dispatch loop that ignores interruption,
      // whereas a closed socket fails the read on both transports.
      boost::system::error_code ec;
      connection.getSocket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
      connection.getSocket().close(ec);
    } catch (const System::InterruptedException&) {
      // Read finished in time; the watchdog was cancelled.
    } catch (const std::exception& e) {
      logger(DEBUGGING) << "Read watchdog error: " << e.what();
    }
  });

  bool failed = false;
  try {
    read();
  } catch (const std::exception&) {
    failed = true;
  }

  // Cancel the watchdog and let it finish before its verdict is read.
  watchdog.interrupt();
  watchdog.wait();

  if (expired) {
    return ReadOutcome::TimedOut;
  }

  return failed ? ReadOutcome::Failed : ReadOutcome::Completed;
}

void HttpServer::connectionWorker(System::TcpConnection& connection) {
  std::pair<System::Ipv4Address, uint16_t> addr(static_cast<System::Ipv4Address>(0), 0);
  try {
    addr = connection.getPeerAddressAndPort();
  }
  catch (const std::exception&) {
    logger(WARNING) << "Could not get IP of connection";
  }

  logger(DEBUGGING) << "Incoming connection from " << addr.first.toDottedDecimal()
                    << ":" << addr.second;

  try {
    std::unique_ptr<std::streambuf> streambuf;

    if (m_useSsl) {
      // Create SSL stream buffer
      auto sslBuf = std::make_unique<System::SslTcpStreambuf>(
        m_dispatcher,
        connection,
        *m_sslContext,
        true);

      // Perform SSL handshake
      try {
        sslBuf->handshake();
        logger(DEBUGGING) << "SSL handshake completed for "
          << addr.first.toDottedDecimal() << ":" << addr.second;
      }
      catch (const std::exception& e) {
        logger(WARNING) << "SSL handshake failed for "
          << addr.first.toDottedDecimal() << ":" << addr.second
          << " - " << e.what();
        return;
      }

      streambuf = std::move(sslBuf);
    }
    else {
      // Plain TCP
      streambuf = std::make_unique<System::TcpStreambuf>(connection);
    }

    std::iostream stream(streambuf.get());
    HttpParser parser;

    for (;;) {
      // Wait for the next request to start. This is where a keep-alive
      // connection rests between requests and where a freshly accepted one
      // waits for its first byte, so it is charged the idle budget.
      ReadOutcome outcome = readWithWatchdog(connection, IDLE_TIMEOUT, [&stream] {
        if (stream.peek() == std::iostream::traits_type::eof()) {
          throw std::runtime_error("connection closed by peer");
        }
      });

      if (outcome != ReadOutcome::Completed) {
        if (outcome == ReadOutcome::TimedOut) {
          logger(DEBUGGING) << "Idle timeout for " << addr.first.toDottedDecimal()
            << ":" << addr.second;
        }
        break;
      }

      HttpRequest req;
      HttpResponse resp;

      resp.addHeader("Access-Control-Allow-Origin", "*");
      resp.addHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
      resp.addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");

      outcome = readWithWatchdog(connection, REQUEST_TIMEOUT, [&parser, &stream, &req] {
        parser.receiveRequest(stream, req);
      });

      if (outcome != ReadOutcome::Completed) {
        logger(DEBUGGING) << (outcome == ReadOutcome::TimedOut
          ? "Timed out receiving request from " : "Failed to parse request from ")
          << addr.first.toDottedDecimal() << ":" << addr.second;
        break;
      }

      if (authenticate(req)) {
        processRequest(req, resp);
      }
      else {
        logger(WARNING) << "Authorization required from "
          << addr.first.toDottedDecimal() << ":" << addr.second;
        fillUnauthorizedResponse(resp);
      }

      stream << resp;
      stream.flush();

      if (!stream) {
        break;  // peer vanished mid-response
      }
    }

    logger(DEBUGGING) << "Closing connection from " << addr.first.toDottedDecimal()
      << ":" << addr.second;

  }
  catch (System::InterruptedException&) {
    logger(DEBUGGING) << "Connection interrupted";
  }
  catch (const std::exception& e) {
    logger(DEBUGGING) << "Connection error: " << e.what();
  }
}

bool HttpServer::authenticate(const HttpRequest& request) const {
  if (!m_credentials.empty()) {
    auto headerIt = request.getHeaders().find("authorization");
    if (headerIt == request.getHeaders().end()) {
      return false;
    }

    if (headerIt->second.substr(0, 6) != "Basic ") {
      return false;
    }

    if (headerIt->second.substr(6) != m_credentials) {
      return false;
    }
  }

  return true;
}

void HttpServer::processRequest(const HttpRequest& request, HttpResponse& response) {
  if (m_requestHandler) {
    m_requestHandler(request, response);
  } else {
    response.setStatus(HttpResponse::STATUS_404);
    response.setBody("Not Found");
  }
}

} // namespace CryptoNote
