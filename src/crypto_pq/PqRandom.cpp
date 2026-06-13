// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#include "PqRandom.h"

extern "C" {
#include "crypto/crypto-util.h"
}

namespace CryptoPQ {

void secure_random_bytes(void* out, std::size_t len) {
  // Route through the shared OS-CSPRNG helper (src/crypto/crypto-util.c),
  // the same source the rest of the crypto/wallet stack uses. Keeps all
  // randomness on one vetted path rather than a parallel mechanism.
  ::secure_random_bytes(out, len);
}

}  // namespace CryptoPQ
