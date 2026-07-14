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

#include "PqKem.h"

#include <cstring>
#include <mutex>
#include <stdexcept>

#include "PqHash.h"

extern "C" {
#include <oqs/kem_ml_kem.h>
#include <oqs/rand.h>
}

namespace CryptoPQ {

namespace {

// Deterministic RNG used only while building the genesis coinbase. The OQS
// custom-RNG hook is a context-free function pointer, so the seed/counter live
// in thread-local state. Stream = SHA3-256(seed || LE64(counter)) blocks.
thread_local std::array<uint8_t, 32> g_derandSeed{};
thread_local uint64_t                g_derandCounter = 0;

// OQS's random-algorithm selection is PROCESS-GLOBAL, so kem_encaps_derand must
// not run concurrently with itself or with any other OQS randomized call
// (kem_keygen, dsa_keygen, kem_encaps...) — otherwise that call could transiently
// observe the deterministic algorithm. This mutex serializes derand encapsulations
// with each other; the caller (offline, single-threaded genesis construction) is
// responsible for ensuring no other OQS randomized operation is in flight.
std::mutex g_derandMutex;

void derandRng(uint8_t* out, size_t n) {
  size_t off = 0;
  while (off < n) {
    uint8_t in[40];
    std::memcpy(in, g_derandSeed.data(), 32);
    for (int i = 0; i < 8; ++i) {
      in[32 + i] = static_cast<uint8_t>((g_derandCounter >> (8 * i)) & 0xFF);
    }
    Hash256 block = sha3_256(in, sizeof(in));
    size_t take = (n - off) < 32 ? (n - off) : 32;
    std::memcpy(out + off, block.data(), take);
    off += take;
    ++g_derandCounter;
  }
}

}  // namespace

static_assert(kKemPublicKeyBytes  == OQS_KEM_ml_kem_768_length_public_key,    "ML-KEM-768 pubkey size mismatch");
static_assert(kKemSecretKeyBytes  == OQS_KEM_ml_kem_768_length_secret_key,    "ML-KEM-768 secret key size mismatch");
static_assert(kKemCiphertextBytes == OQS_KEM_ml_kem_768_length_ciphertext,    "ML-KEM-768 ciphertext size mismatch");
static_assert(kKemSharedBytes     == OQS_KEM_ml_kem_768_length_shared_secret, "ML-KEM-768 shared secret size mismatch");
static_assert(kKemKeypairSeedBytes == OQS_KEM_ml_kem_768_length_keypair_seed, "ML-KEM-768 keypair seed size mismatch");

std::pair<KemPublicKey, KemSecretKey> kem_keygen() {
    KemPublicKey pub;
    KemSecretKey sk;
    OQS_STATUS rc = OQS_KEM_ml_kem_768_keypair(pub.data(), sk.data());
    if (rc != OQS_SUCCESS) {
        throw std::runtime_error("OQS_KEM_ml_kem_768_keypair failed");
    }
    return {pub, sk};
}

std::pair<KemPublicKey, KemSecretKey> kem_keygen_from_seed(const KemKeypairSeed& seed) {
    KemPublicKey pub;
    KemSecretKey sk;
    OQS_STATUS rc = OQS_KEM_ml_kem_768_keypair_derand(pub.data(), sk.data(), seed.data());
    if (rc != OQS_SUCCESS) {
        throw std::runtime_error("OQS_KEM_ml_kem_768_keypair_derand failed");
    }
    return {pub, sk};
}

std::pair<KemCiphertext, KemShared> kem_encaps(const KemPublicKey& pub) {
    KemCiphertext ct;
    KemShared     ss;
    OQS_STATUS rc = OQS_KEM_ml_kem_768_encaps(ct.data(), ss.data(), pub.data());
    if (rc != OQS_SUCCESS) {
        throw std::runtime_error("OQS_KEM_ml_kem_768_encaps failed");
    }
    return {ct, ss};
}

std::pair<KemCiphertext, KemShared> kem_encaps_derand(const KemPublicKey& pub,
                                                      const std::array<uint8_t, 32>& seed) {
    KemCiphertext ct;
    KemShared     ss;
    // Serialize the process-global RNG swap so two derand calls cannot interleave.
    std::lock_guard<std::mutex> derandGuard(g_derandMutex);
    g_derandSeed = seed;
    g_derandCounter = 0;
    OQS_randombytes_custom_algorithm(&derandRng);
    OQS_STATUS rc = OQS_KEM_ml_kem_768_encaps(ct.data(), ss.data(), pub.data());
    // Always restore the secure system RNG, even on failure — otherwise later
    // randomized OQS calls (e.g. kem_keygen) would inherit the deterministic RNG.
    OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
    // Don't leave the deterministic seed sitting in thread-local state.
    g_derandSeed.fill(0);
    g_derandCounter = 0;
    if (rc != OQS_SUCCESS) {
        throw std::runtime_error("OQS_KEM_ml_kem_768_encaps (derand) failed");
    }
    return {ct, ss};
}

KemShared kem_decaps(const KemSecretKey& sk, const KemCiphertext& ct) {
    KemShared ss;
    // FIPS 203 §7.3 (implicit rejection): on malformed ct this returns
    // pseudorandom bytes derived from sk and ct, NOT an error. liboqs mirrors
    // that behaviour and returns OQS_SUCCESS in both the valid and the
    // implicit-rejection path. We propagate the value unchanged — discarding
    // it via "tag failure" higher up is the spec-defined channel for
    // detecting non-owned outputs.
    OQS_STATUS rc = OQS_KEM_ml_kem_768_decaps(ss.data(), ct.data(), sk.data());
    if (rc != OQS_SUCCESS) {
        // Reachable only on internal errors (e.g. allocator failure); not on
        // adversarial ciphertexts. Treat as a hard fault.
        throw std::runtime_error("OQS_KEM_ml_kem_768_decaps failed");
    }
    return ss;
}

}  // namespace CryptoPQ
