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

#include <CryptoNote.h>
#include "CryptoNoteBasic.h"
#include "CryptoNoteSerialization.h"
#include "ITransfersContainer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/BinaryInputStreamSerializer.h"

namespace Logging {
class ILogger;
}

namespace CryptoNote {

bool parseAndValidateTransactionFromBinaryArray(const BinaryArray& transactionBinaryArray, Transaction& transaction, Crypto::Hash& transactionHash, Crypto::Hash& transactionPrefixHash);

bool getTransactionProof(const Crypto::Hash& transactionHash, const CryptoNote::AccountPublicAddress& destinationAddress, const Crypto::SecretKey& transactionKey, std::string& transactionProof, Logging::ILogger& log);


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
// from a classical 32-byte spend secret. Mirrors Wallet/PqWallet
// derivePqWalletKeys (CEMENTED domain "karbo-pq-wallet-seed-v1"), so the daemon
// mines+signs with the SAME identity the wallet holds — the reward recipient is
// the block signer. Used by start_mining (console + RPC).
void deriveMinerPqKeys(const Crypto::SecretKey& spendSecretKey,
                       CryptoPQ::KemPublicKey& viewPub,
                       CryptoPQ::DsaPublicKey& spendPub,
                       CryptoPQ::DsaSecretKey& spendSk);

bool is_out_to_acc(const AccountKeys& acc, const KeyOutput& out_key, const Crypto::PublicKey& tx_pub_key, size_t keyIndex);
bool is_out_to_acc(const AccountKeys& acc, const KeyOutput& out_key, const Crypto::KeyDerivation& derivation, size_t keyIndex);
bool get_tx_fee(const Transaction& tx, uint64_t & fee);
uint64_t get_tx_fee(const Transaction& tx);
std::string short_hash_str(const Crypto::Hash& h);

bool get_block_hashing_blob(const Block& b, BinaryArray& blob);
bool get_signed_block_hashing_blob(const Block& b, BinaryArray& blob);
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
