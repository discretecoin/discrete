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

// Cryptographically secure random bytes for the PQ layer. Thin wrapper over the
// shared OS-CSPRNG helper ::secure_random_bytes (src/crypto/crypto-util.c) —
// the same source the rest of the crypto/wallet stack uses after the RNG fix
// ported from the CT work. Suitable for secret material like the per-output rho.

namespace CryptoPQ {

void secure_random_bytes(void* out, std::size_t len);

}  // namespace CryptoPQ
