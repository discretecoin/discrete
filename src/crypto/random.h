// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2019, The TurtleCoin Developers
// Copyright (c) 2019, The Karbo Developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo. If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <array>
#include <cstdint>
#include <cstddef>
#include <limits>
#include <random>
#include <vector>

#include "crypto-util.h"

// Random number primitives used across the crypto / wallet stack.
//
// All byte-level randomness (signing nonces, blinding factors, ephemeral
// keys, shuffle seeds) is drawn from the OS CSPRNG via secure_random_bytes
// in crypto-util.c (BCryptGenRandom on Windows, getrandom/urandom on
// Linux, arc4random_buf on *BSD/Mac). The previous implementation seeded
// a per-thread std::mt19937 from std::random_device — that yields at most
// 2³² distinct PRNG states (Mersenne Twister's single-uint32 seed
// constructor), well within reach of an offline brute force given any
// observed proof. Routing through the platform CSPRNG removes that
// failure mode.
//
// `generator()` returns a freshly-seeded std::mt19937 on EVERY call (used
// for non-cryptographic shuffles — output decoy order, CT mixing bucket
// selection, peer-list rotation, etc.). The previous "static thread_local
// returned by value" idiom looked like a shared PRNG but was a footgun: it
// returned a fresh copy each call, so callers that did
//   `std::mt19937 rng = Random::generator(); std::shuffle(..., rng);`
// were always reading from the same starting state and the static stored
// generator was never advanced. That made the shuffle output predictable
// to anyone who could observe one prior shuffle from the same thread —
// a privacy/fingerprinting issue for output ordering and decoy bucket
// choices. Reseeding from the OS CSPRNG each call costs ~2.5 KB of OS
// entropy per call but is invoked at most once per wallet send / network
// event, so the cost is negligible.

namespace Random
{
    inline void randomBytes(size_t n, uint8_t *result)
    {
        secure_random_bytes(result, n);
    }

    inline std::vector<uint8_t> randomBytes(size_t n)
    {
        std::vector<uint8_t> result(n);
        if (n > 0) {
            secure_random_bytes(result.data(), n);
        }
        return result;
    }

    /**
     * Generate a random value of the type specified, in the full range of the
     * type. Uses the OS CSPRNG.
     */
    template <typename T>
    T randomValue()
    {
        static_assert(std::is_trivially_copyable<T>::value,
                      "randomValue<T>(): T must be trivially copyable");
        T value;
        secure_random_bytes(&value, sizeof(T));
        return value;
    }

    /**
     * Generate a random value of the type specified, in the range [min, max]
     * (inclusive). Backed by the CSPRNG-seeded MT19937 — uniform_int_distribution
     * needs a UniformRandomBitGenerator, and seeding MT from the OS CSPRNG
     * each call would be wasteful. Callers must not rely on this routine
     * for cryptographic secrets; use randomBytes / randomValue<T>() for that.
     *
     * Note that min must be <= max, or undefined behaviour will occur.
     */
    template <typename T>
    T randomValue(T min, T max)
    {
        static thread_local std::mt19937 gen = []() {
            std::array<uint32_t, std::mt19937::state_size> state{};
            secure_random_bytes(state.data(), state.size() * sizeof(uint32_t));
            std::seed_seq seq(state.begin(), state.end());
            return std::mt19937(seq);
        }();
        std::uniform_int_distribution<T> distribution{min, max};
        return distribution(gen);
    }

    /**
     * Obtain a freshly-seeded generator for passing to functions like
     * std::shuffle. Each call draws a full 624-word MT state from the OS
     * CSPRNG, so consecutive calls — including across short-lived helpers
     * that copy the returned value into a local — produce independent
     * sequences. Callers MUST treat this as a hot factory and not cache the
     * result across operations they want to remain unlinkable.
     *
     * Returning a fresh instance every call is intentional: passing the
     * result by value to std::shuffle or storing it in a local would have
     * silently shared a starting state across callers under the old
     * "static thread_local returned by value" idiom.
     */
    inline std::mt19937 generator()
    {
        std::array<uint32_t, std::mt19937::state_size> state{};
        secure_random_bytes(state.data(), state.size() * sizeof(uint32_t));
        std::seed_seq seq(state.begin(), state.end());
        return std::mt19937(seq);
    }
}
