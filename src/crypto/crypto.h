// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2017, The Monero Project
// Copyright (c) 2016-2020, The Karbo developers
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

#pragma once

#include <cstddef>
#include <cstring>

#include <CryptoTypes.h>

#include "generic-ops.h"
#include "crypto-util.h"
#include "hash.h"
#include "random.h"

namespace Crypto {

  // Small typed-random helper used by tests and non-consensus fixtures.
  template<typename T>
  inline T rand() {
    T result;
    Random::randomBytes(sizeof(result), reinterpret_cast<uint8_t*>(&result));
    return result;
  }

} // namespace Crypto

CRYPTO_MAKE_COMPARABLE(Crypto::Hash, std::memcmp)
CRYPTO_MAKE_COMPARABLE(Crypto::EllipticCurveScalar, sodium_compare)
CRYPTO_MAKE_COMPARABLE(Crypto::EllipticCurvePoint, std::memcmp)
CRYPTO_MAKE_COMPARABLE(Crypto::PublicKey, std::memcmp)
CRYPTO_MAKE_COMPARABLE(Crypto::SecretKey, sodium_compare)
CRYPTO_MAKE_COMPARABLE(Crypto::KeyDerivation, std::memcmp)
CRYPTO_MAKE_COMPARABLE(Crypto::KeyImage, std::memcmp)
CRYPTO_MAKE_COMPARABLE(Crypto::Signature, std::memcmp)
