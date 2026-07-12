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

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

// ML-KEM-768 (FIPS 203) — view / scan key for the Karbo PQ transaction family.
// Spec §2 / §4. Used for stealth-output delivery: every output to a PQ address
// runs ML-KEM.Encaps to establish a 32-byte shared secret with the recipient.

namespace CryptoPQ {

constexpr std::size_t kKemPublicKeyBytes  = 1184;
constexpr std::size_t kKemSecretKeyBytes  = 2400;
constexpr std::size_t kKemCiphertextBytes = 1088;
constexpr std::size_t kKemSharedBytes     = 32;
constexpr std::size_t kKemEncapsMessageBytes = 32;
// FIPS 203 ML-KEM.KeyGen takes 64 bytes of randomness (d || z, two 32-byte
// values). Spec §4 derives view_seed at L=32; session 3 will resolve how that
// 32-byte HKDF output expands to the 64 bytes required here.
constexpr std::size_t kKemKeypairSeedBytes = 64;

using KemPublicKey  = std::array<uint8_t, kKemPublicKeyBytes>;
using KemSecretKey  = std::array<uint8_t, kKemSecretKeyBytes>;
using KemCiphertext = std::array<uint8_t, kKemCiphertextBytes>;
using KemShared     = std::array<uint8_t, kKemSharedBytes>;
using KemEncapsMessage = std::array<uint8_t, kKemEncapsMessageBytes>;
using KemKeypairSeed = std::array<uint8_t, kKemKeypairSeedBytes>;

// Random keygen — pulls 64 bytes from liboqs's CSPRNG.
std::pair<KemPublicKey, KemSecretKey> kem_keygen();

// Deterministic keygen — reproducible from `seed`. Required for wallet
// recovery: a wallet seed → view_seed → keypair must always produce the
// same (pub, sk) pair (spec §4).
std::pair<KemPublicKey, KemSecretKey> kem_keygen_from_seed(const KemKeypairSeed& seed);

// Encapsulate against the recipient's public key. Returns (ciphertext,
// shared_secret); the ciphertext goes on chain inside PqOutput.kemCt and
// the shared_secret is the IKM for per-output HKDFs.
std::pair<KemCiphertext, KemShared> kem_encaps(const KemPublicKey& pub);

// Reentrant ML-KEM-768 Encaps_Internal application interface. `message` is
// the 32-byte m input from FIPS 203 Algorithm 17. Callers on production paths
// MUST supply a fresh uniformly random value from the OS CSPRNG for every
// output. Supplying fresh random m has the normal Encaps distribution, but
// exposing m at the application boundary is deliberately outside strict
// FIPS 203 conformance and requires the specialist review documented in
// docs/PQ-PAYMENT-PROOF.md. This function never swaps global OQS RNG state.
std::pair<KemCiphertext, KemShared> kem_encaps_explicit(
    const KemPublicKey& pub, const KemEncapsMessage& message);

// Deterministic encapsulation — reproducible from `seed`. The ML-KEM message m
// (the only randomness Encaps consumes) is drawn from a seed-derived stream, so
// a fixed (seed, pub) always yields the same (ciphertext, shared_secret). The
// result is a real encapsulation the recipient can still decapsulate normally.
//
// Used to build a byte-identical genesis coinbase (so `--print-genesis-tx` is
// reproducible). NOT thread-safe: it temporarily swaps the process-global OQS
// RNG to a deterministic stream and restores the system RNG afterwards. Call
// only from single-threaded genesis/tooling code, never on a hot path.
std::pair<KemCiphertext, KemShared> kem_encaps_derand(const KemPublicKey& pub,
                                                      const std::array<uint8_t, 32>& seed);

// Decapsulate. Per FIPS 203, this NEVER returns an error: a malformed
// ciphertext yields a deterministic pseudorandom shared secret rather than
// signalling failure. The PQ output-scan path (spec §7) uses the AEAD tag
// check to detect "not for me" cases; do NOT add a defensive failure mode
// here.
KemShared kem_decaps(const KemSecretKey& sk, const KemCiphertext& ct);

}  // namespace CryptoPQ
