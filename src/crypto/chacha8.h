// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2016-2019, The Karbo Developers
// 
// Please see the included LICENSE file for more information.#pragma once

#pragma once

#include <string>
#include <vector>

#include <crypto/crypto-util.h>

#include <crypto/hash.h>
#include <crypto/random.h>

#define CHACHA8_KEY_SIZE 32
#define CHACHA8_IV_SIZE 8

namespace Crypto
{
    void chacha8(const void* data, size_t length, const uint8_t* key, const uint8_t* iv, char* cipher);

    #pragma pack(push, 1)
    struct chacha8_key
    {
        uint8_t data[CHACHA8_KEY_SIZE];
    };

    struct chacha8_iv
    {
        uint8_t data[CHACHA8_IV_SIZE];
    };
    #pragma pack(pop)

    static_assert(sizeof(chacha8_key) == CHACHA8_KEY_SIZE && sizeof(chacha8_iv) == CHACHA8_IV_SIZE, "Invalid structure size");


    inline void chacha8(const void* data, size_t length, const chacha8_key& key, const chacha8_iv& iv, char* cipher)
    {
        chacha8(data, length, reinterpret_cast<const uint8_t*>(&key), reinterpret_cast<const uint8_t*>(&iv), cipher);
    }

    // Test-only fault injection. yespower fails when it cannot obtain its
    // multi-megabyte scratch region, which is impractical to provoke from a unit
    // test; flipping this makes the KDF take its failure path so the callers'
    // abort-and-leave-the-file-alone behaviour can be exercised. Never set
    // outside tests: production code only ever reads it.
    inline bool& kdf_forced_failure() {
      static bool forced = false;
      return forced;
    }

    // Memory-hard password KDF via yespower (the same primitive as the PoW).
    //
    // The KDF is fallible: yespower needs a multi-megabyte scratch region and
    // returns an error when it cannot get one. On failure it fills its output
    // with 0xFF, which is a publicly known value, so the result MUST NOT be used
    // as a key. Callers get `false` and must abort the operation; `key` is
    // zeroed rather than left holding the sentinel.
    [[nodiscard]] inline bool derive_chacha8_key(const void* input, size_t inputLen, chacha8_key& key) {
      static_assert(sizeof(chacha8_key) <= sizeof(Hash), "Size of hash must be at least that of chacha8_key");
      Hash seed;
      memset(&seed, 0, sizeof(seed));
      Hash pwd_hash;
      if (kdf_forced_failure() || !y_slow_hash(input, inputLen, seed, pwd_hash)) {
        memset(&pwd_hash, 0, sizeof(pwd_hash));
        memset(&key, 0, sizeof(key));
        return false;
      }
      memcpy(&key, &pwd_hash, sizeof(key));
      memset(&pwd_hash, 0, sizeof(pwd_hash));
      return true;
    }

    // Salted derivation: two wallets sharing a password derive different keys
    // because each carries its own random salt.
    //
    // The salt is prepended to the yespower INPUT rather than handed over as its
    // `pers` personalization parameter. `pers` reaches yespower through
    // pbkdf2_blake256(), which passes the salt length to the bit-counting
    // hmac_blake256_update() as if it were a byte count; the salt therefore never
    // makes it into the digest. Correcting that would change every proof-of-work
    // this chain has already accepted, so the KDF works around it instead. The
    // input is a fixed-length salt followed by the password, so distinct
    // (salt, password) pairs never share a preimage.
    [[nodiscard]] inline bool generate_chacha8_key_salted(const std::string& password,
                                                          const Hash& salt, chacha8_key& key) {
      std::vector<uint8_t> input;
      input.reserve(sizeof(salt.data) + password.size());
      input.insert(input.end(), salt.data, salt.data + sizeof(salt.data));
      input.insert(input.end(), password.begin(), password.end());
      const bool ok = derive_chacha8_key(input.data(), input.size(), key);
      if (!input.empty()) {
        sodium_memzero(input.data(), input.size());
      }
      return ok;
    }

    // Legacy unsalted derivation (the password alone). Retained only so pre-salt
    // wallet files can still be opened and migrated.
    [[nodiscard]] inline bool generate_chacha8_key(Crypto::cn_context& /*context*/, const std::string& password, chacha8_key& key) {
      return derive_chacha8_key(password.data(), password.size(), key);
    }

    /**
     * Generates a random chacha8 IV
     */
    inline chacha8_iv randomChachaIV()
    {
        chacha8_iv result;
        Random::randomBytes(CHACHA8_IV_SIZE, result.data);
        return result;
    }
}
