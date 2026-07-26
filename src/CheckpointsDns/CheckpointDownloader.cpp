// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Discrete is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Discrete is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Discrete.  If not, see <http://www.gnu.org/licenses/>.

#include "CheckpointDownloader.h"

#include <cstdlib>

#include "HTTP/HttpClient.h"
#include "HTTP/HttpRequest.h"
#include "HTTP/HttpResponse.h"

namespace CryptoNote {

bool downloadCheckpointFile(System::Dispatcher& dispatcher,
                            const CheckpointPointer& ptr,
                            std::string& outBytes,
                            std::string& err,
                            std::size_t maxBytes) {
  outBytes.clear();
  err.clear();

  // Defense in depth: parseCheckpointPointer already pins the host, but never
  // dial a host we didn't expect even if a pointer reached us another way.
  if (ptr.host != kCheckpointHost) {
    err = "refusing to fetch from unexpected host: " + ptr.host;
    return false;
  }

  try {
    // SSL client, verify peer against system CA store (empty certFile => default
    // verify paths in HttpClient's SSL ctor).
    HttpClient client(dispatcher, ptr.host, 443, "", "", /*sslVerify=*/true);

    HttpRequest req;
    req.setMethod("GET");
    req.setUrl(ptr.path);
    req.addHeader("Host", ptr.host);
    req.addHeader("User-Agent", "discrete-checkpoint/1");
    req.addHeader("Accept", "application/json");
    req.addHeader("Connection", "close");

    HttpResponse res;
    client.request(req, res);

    if (res.getStatus() != HttpResponse::STATUS_200) {
      err = "unexpected HTTP status " + std::to_string(static_cast<int>(res.getStatus()));
      return false;
    }

    // Reject oversize up front when the server advertises the length, then guard
    // again against the actual body (a lying/absent Content-Length).
    const auto& headers = res.getHeaders();
    auto cl = headers.find("Content-Length");
    if (cl == headers.end()) cl = headers.find("content-length");
    if (cl != headers.end()) {
      char* end = nullptr;
      unsigned long long advertised = std::strtoull(cl->second.c_str(), &end, 10);
      if (end != cl->second.c_str() && advertised > maxBytes) {
        err = "checkpoint file too large (" + cl->second + " > " +
              std::to_string(maxBytes) + " bytes)";
        return false;
      }
    }

    const std::string& body = res.getBody();
    if (body.size() > maxBytes) {
      err = "checkpoint file too large (" + std::to_string(body.size()) + " > " +
            std::to_string(maxBytes) + " bytes)";
      return false;
    }

    outBytes = body;
    return true;
  } catch (const std::exception& e) {
    err = std::string("download failed: ") + e.what();
    return false;
  }
}

}  // namespace CryptoNote
