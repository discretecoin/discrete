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

#include "Checkpoints/Checkpoints.h"
#include "CryptoTypes.h"
#include "Logging/ILogger.h"

// Deliberately its own tiny library, separate from Checkpoints: this is the
// ONLY piece of DNS checkpoint discovery that needs an HTTPS client (Http +
// System::Dispatcher + OpenSSL's full SSL stack). Checkpoints itself — linked
// by CryptoNoteCore, and therefore by nearly every target in the project
// including all the Pq* unit tests — stays free of that dependency; only the
// three executables that actually perform DNS discovery (discreted, walletd,
// admin-tools) link CheckpointsDns.

namespace CryptoNote {

// Discover checkpoints via the DNS TXT pointer at DNS_CHECKPOINTS_HOST and the
// HTTPS-hosted signed JSON it references (see Checkpoints/DnsCheckpoint.h).
// Bounded by an overall wall-clock deadline so an unreachable or silent
// DNS/web server cannot stall node startup. Never throws; a failed lookup
// simply leaves the already-loaded checkpoints untouched. Verified checkpoints
// are added to `checkpoints` via its public add_checkpoint API.
bool fetchDnsCheckpoints(Checkpoints& checkpoints, Logging::ILogger& log,
                         const Crypto::Hash& genesisBlockHash, bool testnet);

}  // namespace CryptoNote
