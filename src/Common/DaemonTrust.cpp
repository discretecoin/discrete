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

// Parse one dotted-quad octet: 1-3 decimal digits, no sign, no leading zero, and
// at most 255. Leading zeros are refused rather than guessed at, because their
// meaning (decimal here, octal in inet_aton) is not agreed across parsers, and a
// trust decision must not depend on which reading a resolver happens to use.
bool parseOctet(const std::string& text, unsigned& value) {
  if (text.empty() || text.size() > 3) {
    return false;
  }
  if (text.size() > 1 && text[0] == '0') {
    return false;
  }
  unsigned acc = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return false;
    }
    acc = acc * 10 + static_cast<unsigned>(c - '0');
  }
  if (acc > 255) {
    return false;
  }
  value = acc;
  return true;
}

// Whether the WHOLE string is a numeric dotted-quad IPv4 address, and if so what
// its first octet is. Anything else — a name, a name that merely looks like an
// address, a host:port pair, a truncated quad — is not an address.
bool parseIpv4(const std::string& text, unsigned& firstOctet) {
  std::size_t start = 0;
  unsigned octets[4] = {0, 0, 0, 0};
  for (int i = 0; i < 4; ++i) {
    const bool last = (i == 3);
    const std::size_t dot = last ? std::string::npos : text.find('.', start);
    if (!last && dot == std::string::npos) {
      return false;  // fewer than four parts
    }
    const std::string part =
        last ? text.substr(start) : text.substr(start, dot - start);
    if (!parseOctet(part, octets[i])) {
      return false;
    }
    start = last ? start : dot + 1;
  }
  firstOctet = octets[0];
  return true;
}

}  // namespace

bool isLoopbackHost(const std::string& host) {
  const std::string h = normalizeHost(host);
  if (h == "localhost" || h == "::1" || h == "0:0:0:0:0:0:0:1") {
    return true;
  }
  // 127.0.0.0/8, and only as a complete numeric address. Matching on a leading
  // "127." would also accept a DNS name that begins with those characters, which
  // a remote host can choose freely; the name is never resolved here, so trust
  // follows from the literal the caller was configured with and cannot change
  // between this check and the connection.
  unsigned firstOctet = 0;
  return parseIpv4(h, firstOctet) && firstOctet == 127;
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

bool isTrustedByDefault(const std::string& host, bool authenticatedTransport) {
  if (isLoopbackHost(host)) {
    return true;  // our own machine; no network in between to impersonate it
  }
  return isOfficialRemoteHost(host) && authenticatedTransport;
}

}  // namespace Common
