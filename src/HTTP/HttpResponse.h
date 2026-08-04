// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2026, The Karbo developers
//
// This file is part of Karbo.

#pragma once

#include <cctype>
#include <map>
#include <string>
#include <ostream>

namespace CryptoNote {

class HttpResponse {
public:
  enum HTTP_STATUS {
    STATUS_200 = 200,
    STATUS_400 = 400,
    STATUS_401 = 401,
    STATUS_404 = 404,
    STATUS_500 = 500
  };

  typedef std::map<std::string, std::string> Headers;

  HttpResponse();

  const Headers& getHeaders() const;
  const std::string& getBody() const;
  HTTP_STATUS getStatus() const;

  void addHeader(const std::string& name, const std::string& value);
  void setBody(const std::string& b);
  void setStatus(HTTP_STATUS s);

private:
  friend std::ostream& operator<<(std::ostream& os, const HttpResponse& resp);
  friend std::istream& operator>>(std::istream& is, HttpResponse& resp);

  HTTP_STATUS status;
  Headers headers;
  std::string body;

  static std::string statusToString(HTTP_STATUS status);
};

namespace Detail {
  inline bool isContentLengthHeader(const std::string& name) {
    static const std::string contentLength("content-length");
    if (name.size() != contentLength.size()) {
      return false;
    }
    for (size_t i = 0; i < name.size(); ++i) {
      if (static_cast<char>(::tolower(static_cast<unsigned char>(name[i]))) != contentLength[i]) {
        return false;
      }
    }
    return true;
  }
}

inline std::ostream& operator<<(std::ostream& os, const HttpResponse& resp) {
  os << "HTTP/1.1 " << static_cast<int>(resp.status) << " "
     << HttpResponse::statusToString(resp.status) << "\r\n";

  // Content-Length is written unconditionally below, so any copy carried in the
  // header map is dropped here to avoid emitting it twice. Framing must not
  // depend on setBody() having been called: an HTTP/1.1 response with neither
  // Content-Length nor Transfer-Encoding is terminated by connection close, and
  // the keep-alive loop never closes — it blocks reading the next request while
  // the client blocks reading the body, hanging both until the client times out.
  for (const auto& header : resp.headers) {
    if (Detail::isContentLengthHeader(header.first)) {
      continue;
    }
    os << header.first << ": " << header.second << "\r\n";
  }

  os << "Content-Length: " << resp.body.size() << "\r\n";
  os << "\r\n";
  if (!resp.body.empty()) {
    os << resp.body;
  }

  return os;
}

} // namespace CryptoNote
