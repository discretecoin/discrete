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

#pragma once

#include <string>

namespace Common {

// Whether a daemon may be trusted to answer a Compact Account Number lookup.
//
// A compact number (H-I-A-C) is a locator, not a self-contained address: the
// wallet hands (H, I) to a daemon and spends to whatever keys come back. The
// 4-character A fingerprint is a transcription and reorg failsafe, not an
// authentication of the party that answers. Whoever answers the lookup therefore
// picks the recipient.
//
// Full Bech32m addresses carry both public keys, so they are safe through any
// daemon and are never subject to this check.
//
// TLS says nothing here: a correctly configured hostile endpoint presents a
// perfectly valid certificate.

// A daemon on this machine. Its operator is the wallet's operator.
bool isLoopbackHost(const std::string& host);

// An endpoint the project ships (see CryptoNote::OFFICIAL_REMOTE_NODES). Matching
// is on the host name only; the port is not part of the identity.
bool isOfficialRemoteHost(const std::string& host);

// The default policy: local daemons and project-operated endpoints are trusted,
// everything else has to be trusted explicitly by the user.
bool isTrustedByDefault(const std::string& host);

}  // namespace Common
