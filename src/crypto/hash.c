// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hash-ops.h"
#include "keccak.h"

#include <oqs/sha3.h>

void hash_permutation(union hash_state *state) {
  keccakf((uint64_t*)state, 24);
}

void hash_process(union hash_state *state, const uint8_t *buf, size_t count) {
  keccak1600(buf, (int)count, (uint8_t*)state);
}

// Discrete's chain hash is SHA3-256 (FIPS 202) via liboqs — the single chokepoint
// for tx ids, block ids, merkle/tree roots, and hashing blobs. This is distinct
// from CryptoNote Keccak-256 (different padding); see PqHash for the PQ-side use.
void cn_fast_hash(const void *data, size_t length, char *hash) {
  OQS_SHA3_sha3_256((uint8_t *)hash, (const uint8_t *)data, length);
}
