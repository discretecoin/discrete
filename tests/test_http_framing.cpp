// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Regression tests for HTTP response framing.
//
// The RPC keep-alive loop writes a response and then blocks reading the next
// request on the same connection. If a response carries neither Content-Length
// nor Transfer-Encoding, an HTTP/1.1 client must read until the connection
// closes — which that loop never does — so both sides wait until the client
// times out. Every response must therefore be self-delimiting, including the
// ones whose body was never set (an RPC handler bailing out early).

#include "gtest/gtest.h"

#include "HTTP/HttpClient.h"
#include "HTTP/HttpParser.h"
#include "HTTP/HttpRequest.h"
#include "HTTP/HttpResponse.h"

#include "CryptoNoteConfig.h"

#include <System/ContextGroup.h>
#include <System/Dispatcher.h>
#include <System/Ipv4Address.h>
#include <System/TcpListener.h>
#include <System/Timer.h>

#include <chrono>
#include <sstream>
#include <string>

using namespace CryptoNote;

namespace {

std::string serialize(const HttpResponse& response) {
  std::stringstream stream;
  stream << response;
  return stream.str();
}

size_t countOccurrences(const std::string& haystack, const std::string& needle) {
  size_t count = 0;
  for (size_t pos = haystack.find(needle); pos != std::string::npos;
       pos = haystack.find(needle, pos + needle.size())) {
    ++count;
  }
  return count;
}

}

// A response left untouched by its handler still has to be framed, otherwise
// the client hangs waiting for a close that the keep-alive loop never performs.
TEST(HttpFraming, BodylessResponseCarriesZeroContentLength) {
  HttpResponse response;
  response.addHeader("Access-Control-Allow-Origin", "*");

  const std::string wire = serialize(response);

  EXPECT_NE(wire.find("\r\nContent-Length: 0\r\n"), std::string::npos);
  EXPECT_EQ(countOccurrences(wire, "Content-Length"), 1u);
}

TEST(HttpFraming, ContentLengthMatchesBodySize) {
  HttpResponse response;
  response.setBody("{\"status\":\"OK\"}");

  const std::string wire = serialize(response);

  EXPECT_NE(wire.find("\r\nContent-Length: 15\r\n"), std::string::npos);
  EXPECT_EQ(countOccurrences(wire, "Content-Length"), 1u);
}

// A handler may set the header by hand under any casing; the serializer owns
// the authoritative value and must not emit a second, contradictory one.
TEST(HttpFraming, ManualContentLengthHeaderIsNotDuplicated) {
  HttpResponse response;
  response.addHeader("content-length", "9999");
  response.setBody("hello");

  const std::string wire = serialize(response);

  EXPECT_EQ(countOccurrences(wire, "ontent-length"), 0u);
  EXPECT_EQ(countOccurrences(wire, "Content-Length"), 1u);
  EXPECT_NE(wire.find("\r\nContent-Length: 5\r\n"), std::string::npos);
}

// End-to-end proof that a client can finish reading the bodyless response
// without relying on the connection being closed.
TEST(HttpFraming, ClientParsesBodylessResponseWithoutBlocking) {
  HttpResponse response;
  response.setStatus(HttpResponse::STATUS_400);

  std::stringstream stream(serialize(response));
  HttpParser parser;
  HttpResponse parsed;
  parser.receiveResponse(stream, parsed);

  EXPECT_EQ(parsed.getStatus(), HttpResponse::STATUS_400);
  EXPECT_TRUE(parsed.getBody().empty());

  auto header = parsed.getHeaders().find("content-length");
  ASSERT_NE(header, parsed.getHeaders().end());
  EXPECT_EQ(header->second, "0");
}

// A body is read in chunks, so it must reassemble correctly across chunk
// boundaries — the case a single read() could never get wrong.
TEST(HttpFraming, BodySpanningManyChunksIsReassembled) {
  const std::string payload(200000, 'x');

  std::stringstream stream;
  stream << "POST / HTTP/1.1\r\nContent-Length: " << payload.size() << "\r\n\r\n" << payload;

  HttpParser parser;
  HttpRequest request;
  parser.receiveRequest(stream, request);

  EXPECT_EQ(request.getBody().size(), payload.size());
  EXPECT_EQ(request.getBody(), payload);
}

// A peer that announces a body and then sends less than it promised must fail
// rather than being handed a short body as if it were complete. This is also
// the shape of the cheap attack the chunked read defends against: the memory
// held now tracks what was actually sent, not what was claimed.
TEST(HttpFraming, TruncatedBodyIsRejected) {
  std::stringstream stream;
  stream << "POST / HTTP/1.1\r\nContent-Length: 100000\r\n\r\n" << std::string(64, 'y');

  HttpParser parser;
  HttpRequest request;
  try {
    parser.receiveRequest(stream, request);
    FAIL() << "expected receiveRequest to reject a truncated body";
  } catch (const std::runtime_error& e) {
    EXPECT_STREQ(e.what(), "Failed to read complete HTTP body");
  }
}

// A Content-Length above the sane maximum must be rejected before the parser
// trusts it enough to allocate — otherwise a peer can force a large
// allocation merely by claiming one, without ever sending a matching body.
TEST(HttpFraming, OversizedContentLengthRejectedBeforeAllocating) {
  std::stringstream stream;
  stream << "POST / HTTP/1.1\r\nContent-Length: "
         << (static_cast<unsigned long long>(CryptoNote::P2P_DEFAULT_PACKET_MAX_SIZE) + 1)
         << "\r\n\r\n";

  HttpParser parser;
  HttpRequest request;
  try {
    parser.receiveRequest(stream, request);
    FAIL() << "expected receiveRequest to reject an oversized Content-Length";
  } catch (const std::runtime_error& e) {
    EXPECT_STREQ(e.what(), "HTTP body too large");
  }
}

// HttpClient::request() previously had no read/write timeout at all: a
// stalled or unresponsive daemon connection wedged it forever, which in turn
// wedged BlockchainSynchronizer::stop()'s worker-thread join -- observed as
// walletd needing SIGKILL to exit (issue #11). This proves request() gives up
// within its configured budget instead of hanging.
TEST(HttpClientTimeout, RequestTimesOutAgainstAnUnresponsivePeer) {
  const uint16_t port = 18765;

  System::Dispatcher dispatcher;
  System::TcpListener listener(dispatcher, System::Ipv4Address("127.0.0.1"), port);
  System::ContextGroup contextGroup(dispatcher);

  contextGroup.spawn([&] {
    // Accept the connection but never write a response or close it --
    // simulates a stalled/unresponsive daemon. Held open comfortably longer
    // than the client's configured timeout below.
    auto connection = listener.accept();
    System::Timer(dispatcher).sleep(std::chrono::milliseconds(500));
  });

  bool threw = false;
  std::string message;
  std::chrono::steady_clock::time_point start;
  std::chrono::steady_clock::time_point finish;

  contextGroup.spawn([&] {
    CryptoNote::HttpClient client(dispatcher, "127.0.0.1", port);
    client.setRequestTimeout(std::chrono::milliseconds(150));

    CryptoNote::HttpRequest request;
    request.setMethod("GET");
    request.setUrl("/");
    CryptoNote::HttpResponse response;

    start = std::chrono::steady_clock::now();
    try {
      client.request(request, response);
    } catch (const std::exception& e) {
      threw = true;
      message = e.what();
    }
    finish = std::chrono::steady_clock::now();
  });

  contextGroup.wait();

  ASSERT_TRUE(threw);
  EXPECT_NE(message.find("timed out"), std::string::npos) << "message: " << message;

  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(finish - start);
  EXPECT_GE(elapsed.count(), 150);
  EXPECT_LT(elapsed.count(), 2000);
}

TEST(HttpFraming, BadRequestStatusIsReportable) {
  HttpResponse response;
  response.setStatus(HttpResponse::STATUS_400);
  response.setBody("Failed to parse request body as JSON");

  const std::string wire = serialize(response);

  EXPECT_EQ(wire.find("HTTP/1.1 400 Bad Request\r\n"), 0u);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
