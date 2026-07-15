// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2026, Karbo developers
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
#include <cstdint>

#include <CryptoNote.h>
#include "CryptoNoteBasic.h"
#include "CryptoNoteSerialization.h"
#include "ITransfersContainer.h"
#include "crypto_pq/PqDsa.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/BinaryInputStreamSerializer.h"

namespace Logging {
class ILogger;
}

namespace CryptoNote {

bool parseAndValidateTransactionFromBinaryArray(const BinaryArray& transactionBinaryArray, Transaction& transaction, Crypto::Hash& transactionHash, Crypto::Hash& transactionPrefixHash);

// PQ message signing (ML-DSA-65). Discrete has no ECC account identity, so a
// human-signed message is authorized by the wallet's long-term ML-DSA spend key
// (the same key its PQ address publishes). The signed bytes are a domain-separated
// SHA3-256 digest of `data`; the domain is distinct from every consensus signing
// domain, so a message signature can never be replayed as a transaction signature.
// The signature is base58-encoded with the CRYPTONOTE_KEYS_SIGNATURE_BASE58_PREFIX
// tag (same tag as the classical scheme, but the blob is 3309 bytes vs. 64).
// verifyMessagePq checks it against a PQ address's spendPub.
std::string signMessagePq(const std::string &data, const CryptoPQ::DsaSecretKey &spendSk);
bool verifyMessagePq(const std::string &data, const CryptoPQ::DsaPublicKey &spendPub, const std::string &signature);

// Derive the Discrete PQ mining identity (ML-KEM view + ML-DSA spend keypair)
// from the wallet's 32-byte PQ-native seed. Mirrors Wallet/PqWallet
// derivePqWalletKeys, so the daemon mines+signs with the SAME identity the
// wallet holds — the reward recipient is the block signer. Used by start_mining
// (console + RPC).
void deriveMinerPqKeys(const Crypto::SecretKey& spendSecretKey,
                       CryptoPQ::KemPublicKey& viewPub,
                       CryptoPQ::DsaPublicKey& spendPub,
                       CryptoPQ::DsaSecretKey& spendSk);

bool get_tx_fee(const Transaction& tx, uint64_t & fee);
uint64_t get_tx_fee(const Transaction& tx);
std::string short_hash_str(const Crypto::Hash& h);

bool get_block_hashing_blob(const Block& b, BinaryArray& blob);

// DiscretePower consensus domains (https://docs.discrete.cash/#/consensus/pow, revision D).
// ASCII, hashed with SHAKE-256 without a trailing NUL. No tag is reused by any
// other subsystem (derivation, messaging, CT).
constexpr char DISCRETE_POWER_HEADER_DOMAIN[]     = "DiscretePower/v2/header";  // -> H  (64 B)
constexpr char DISCRETE_POWER_MEMORY_DOMAIN[]     = "DiscretePower/v2/memory";  // -> P  (32 B)
constexpr char DISCRETE_POWER_SIGN_DOMAIN[]       = "DiscretePower/v2/sign";    // -> m  (64 B)
constexpr char DISCRETE_POWER_FINAL_DOMAIN[]      = "DiscretePower/v2/final";   // -> PoW (32 B)
// Block-identity domains. The block ID commits to the block signature through a
// 32-byte witness W = SHAKE256(witness-domain || signature), then
// ID = SHAKE256(block-id-domain || LE64(|C_B|) || C_B || W) where C_B is the
// unsigned block-hashing blob. Distinct valid signatures over one header yield
// distinct IDs (no same-ID proof aliasing), and a checkpoint pin transitively
// commits to every signature below it. W is separable so a future pruned-storage
// format can retain it, but the current wire and database keep full signatures.
constexpr char DISCRETE_POWER_WITNESS_DOMAIN[]    = "DiscretePower/v2/witness";  // -> W  (32 B)
constexpr char DISCRETE_POWER_BLOCK_ID_DOMAIN[]   = "DiscretePower/v2/block-id"; // -> block ID (32 B)

// W = SHAKE256(witness-domain || signature, 32). This commitment is part of
// the block ID and is exposed separately for diagnostics/explorers. It is
// derived on demand today; no pruned-block storage format is implemented yet.
Crypto::Hash get_block_signature_witness(const std::vector<uint8_t>& signature);

// H = SHAKE256(header-domain || get_block_hashing_blob(b), 64) — the 64-byte
// DiscretePower header digest that binds the whole candidate template.
bool get_block_pow_header_hash(const Block& b, std::array<uint8_t, 64>& H);
// m = SHAKE256(sign-domain || H, 64) — the ML-DSA-65 message signed per attempt.
std::array<uint8_t, 64> discrete_power_sign_message(const std::array<uint8_t, 64>& H);
// P = SHAKE256(memory-domain, 32) — the constant yespower-discrete personalization.
const std::array<uint8_t, 32>& discrete_power_memory_personalization();

// Distinct reasons discrete_power_verify can reject before running any yespower-discrete work.
enum class DiscretePowerReject { None, BadLength, BadSignature };

// Miner path (spec §5): sign m with the resident spend key and run the
// signature-tape yespower-discrete chain. `blob` is get_block_hashing_blob(b).
// Fills signature (exactly DISCRETE_POWER_SIG_LEN bytes) and powHash.
bool discrete_power_prove(const BinaryArray& blob, const CryptoPQ::DsaSecretKey& sk,
               std::vector<uint8_t>& signature, Crypto::Hash& powHash);

// Verifier path (spec §9 steps 1-6), STRICTLY ordered: length check -> recompute
// H/m -> ML-DSA Verify (BEFORE any yespower-discrete) -> tape chain -> final PoW. On a
// length or signature failure it returns false having executed ZERO yespower-discrete
// (the DoS bound); *reason distinguishes the cause when non-null.
bool discrete_power_verify(const BinaryArray& blob, const CryptoPQ::DsaPublicKey& pk,
                const std::vector<uint8_t>& signature, Crypto::Hash& powHash,
                DiscretePowerReject* reason = nullptr);

// PoW hash of an already-signed block, WITHOUT re-verifying the signature (uses
// b.signature). For self-built blocks (miner/tests/Core); consensus uses
// discrete_power_verify so the signature is checked before the memory-hard path runs.
bool get_block_longhash(const Block& b, Crypto::Hash& res);
bool get_parent_block_hashing_blob(const Block& b, BinaryArray& blob);
bool get_aux_block_header_hash(const Block& b, Crypto::Hash& res);
bool get_block_hash(const Block& b, Crypto::Hash& res);
Crypto::Hash get_block_hash(const Block& b);
bool get_inputs_money_amount(const Transaction& tx, uint64_t& money);
uint64_t get_outs_money_amount(const Transaction& tx);
bool check_inputs_types_supported(const TransactionPrefix& tx);
bool check_outs_valid(const TransactionPrefix& tx, std::string* error = 0);

bool check_money_overflow(const TransactionPrefix& tx);
bool check_outs_overflow(const TransactionPrefix& tx);
bool check_inputs_overflow(const TransactionPrefix& tx);
uint32_t get_block_height(const Block& b);
std::vector<uint32_t> relative_output_offsets_to_absolute(const std::vector<uint32_t>& off);
std::vector<uint32_t> absolute_output_offsets_to_relative(const std::vector<uint32_t>& off);


// 62387455827 -> 455827 + 7000000 + 80000000 + 300000000 + 2000000000 + 60000000000, where 455827 <= dust_threshold
template<typename chunk_handler_t, typename dust_handler_t>
void decompose_amount_into_digits(uint64_t amount, uint64_t dust_threshold, const chunk_handler_t& chunk_handler, const dust_handler_t& dust_handler) {
  if (0 == amount) {
    return;
  }

  bool is_dust_handled = false;
  uint64_t dust = 0;
  uint64_t order = 1;
  while (0 != amount) {
    uint64_t chunk = (amount % 10) * order;
    amount /= 10;
    order *= 10;

    if (dust + chunk <= dust_threshold) {
      dust += chunk;
    } else {
      if (!is_dust_handled && 0 != dust) {
        dust_handler(dust);
        is_dust_handled = true;
      }
      if (0 != chunk) {
        chunk_handler(chunk);
      }
    }
  }

  if (!is_dust_handled && 0 != dust) {
    dust_handler(dust);
  }
}

void get_tx_tree_hash(const std::vector<Crypto::Hash>& tx_hashes, Crypto::Hash& h);
Crypto::Hash get_tx_tree_hash(const std::vector<Crypto::Hash>& tx_hashes);
Crypto::Hash get_tx_tree_hash(const Block& b);
bool is_valid_decomposed_amount(uint64_t amount);
}
