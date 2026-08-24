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

#include "Common/DaemonTrust.h"

#include <algorithm>
#include <cctype>

#include "CryptoNoteConfig.h"

namespace Common {

namespace {

std::string normalizeHost(const std::string& host) {
  std::string out = host;
  // Strip brackets from a literal IPv6 host, then lowercase.
  if (out.size() >= 2 && out.front() == '[' && out.back() == ']') {
    out = out.substr(1, out.size() - 2);
  }
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

// Host part of a "host:port" entry, with no port and no scheme.
std::string hostOf(const std::string& endpoint) {
  const std::size_t colon = endpoint.rfind(':');
  if (colon == std::string::npos) {
    return normalizeHost(endpoint);
  }
  return normalizeHost(endpoint.substr(0, colon));
}

}  // namespace

bool isLoopbackHost(const std::string& host) {
  const std::string h = normalizeHost(host);
  if (h == "localhost" || h == "::1" || h == "0:0:0:0:0:0:0:1") {
    return true;
  }
  // Any address in 127.0.0.0/8.
  return h.rfind("127.", 0) == 0;
}

bool isOfficialRemoteHost(const std::string& host) {
  const std::string h = normalizeHost(host);
  for (const char* entry : CryptoNote::OFFICIAL_REMOTE_NODES) {
    if (hostOf(entry) == h) {
      return true;
    }
  }
  return false;
}

bool isTrustedByDefault(const std::string& host) {
  return isLoopbackHost(host) || isOfficialRemoteHost(host);
}

}  // namespace Common
