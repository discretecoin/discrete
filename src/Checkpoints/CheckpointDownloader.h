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

#include <cstddef>
#include <string>

#include "DnsCheckpoint.h"

namespace System { class Dispatcher; }

namespace CryptoNote {

// Fetch the checkpoint JSON referenced by a parsed pointer over HTTPS.
//
// The connection is host-pinned to kCheckpointHost (a mismatch is refused before
// dialing), TLS certificates are verified against the system CA store, and the
// response body is capped at maxBytes. This is the I/O half of the scheme; the
// caller passes the returned bytes to verifyCheckpointFile (SHA-256 + signature)
// before trusting anything. Returns false with `err` set on any failure; a
// failed download never invalidates an already-trusted checkpoint.
//
// NOTE: this call has no deadline of its own — neither the resolver nor the
// TLS/HTTP stack enforces one, so a server that completes the TCP handshake and
// then goes silent blocks here forever. Callers that cannot tolerate that must
// impose their own bound; Checkpoints::load_checkpoints_from_dns runs the whole
// discovery on a detached worker under a wall-clock deadline.
bool downloadCheckpointFile(System::Dispatcher& dispatcher,
                            const CheckpointPointer& ptr,
                            std::string& outBytes,
                            std::string& err,
                            std::size_t maxBytes = 64 * 1024);

}  // namespace CryptoNote
