// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2026, Karbo developers
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

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>
#include <boost/variant.hpp>

#include <CryptoNote.h>

#define TX_EXTRA_PADDING_MAX_COUNT          255
#define TX_EXTRA_NONCE_MAX_COUNT            255

#define TX_EXTRA_TAG_PADDING                  0x00
#define TX_EXTRA_TAG_PUBKEY                   0x01
#define TX_EXTRA_NONCE                        0x02
#define TX_EXTRA_MERGE_MINING_TAG             0x03
#define TX_EXTRA_TAG_ACCOUNT_REGISTRATION     0x04
// PQ Phase 1 tags (spec §4 / §11). Distinct from the classical 0x04 tag.
#define TX_EXTRA_TAG_PQ_ACCOUNT_REGISTRATION  0x05
#define TX_EXTRA_TAG_POW                      0x06
// Coinbase (miner) ML-DSA-65 spend public key — carried in every coinbase extra
// so that validate_block_signature can recover the miner's spend pub without a
// separate index lookup. On the wire: tag(1) || spendPub(1952).
#define TX_EXTRA_TAG_PQ_MINER_SPEND_PUB       0x07

#define TX_EXTRA_NONCE_PAYMENT_ID           0x00

// ML-KEM-768 public (view) key length carried by a PQ account registration.
#define TX_EXTRA_PQ_VIEW_PUBKEY_SIZE          1184
// ML-DSA-65 public (spend) key length. A registration carries BOTH keys so an
// account number resolves to a full, payable PqAddress (the ownership fix binds
// spend_commit to the recipient's spend pubkey — see https://docs.discrete.cash/#/reference/pq-ownership-model).
#define TX_EXTRA_PQ_SPEND_PUBKEY_SIZE         1952

namespace CryptoNote {

struct TransactionExtraPadding {
  size_t size;
};

struct TransactionExtraPublicKey {
  Crypto::PublicKey publicKey;
};

struct TransactionExtraNonce {
  std::vector<uint8_t> nonce;
};

struct TransactionExtraMergeMiningTag {
  size_t depth;
  Crypto::Hash merkleRoot;
};

struct TransactionExtraAccountRegistration {
  Crypto::PublicKey spendPublicKey;
  Crypto::PublicKey viewPublicKey;
};

// PQ account registration: the identity's ML-KEM-768 view key + ML-DSA-65 spend
// key (spec §4, amended by the ownership fix). On the wire: tag(1) ||
// viewPub(1184) || spendPub(1952).
struct TransactionExtraPqAccountRegistration {
  std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE>  viewPub;
  std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> spendPub;
};

// Miner spend public key in coinbase transaction (tag 0x07).
struct TransactionExtraPqMinerSpendPub {
  std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE> spendPub;
};

// Anti-spam PoW for free-fee registration (spec §11.2). On the wire this tag is
// laid out as: tag(1) || refBlockHash(32) || nonce(8, little-endian). It MUST be
// the LAST field in tx_extra so the nonce is the final 8 bytes — letting a phone
// grind nonces without re-serializing the whole transaction.
struct TransactionExtraPow {
  Crypto::Hash refBlockHash;
  uint64_t     nonce;
};

// tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
//   varint tag;
//   varint size;
//   varint data[];
typedef boost::variant<TransactionExtraPadding, TransactionExtraPublicKey, TransactionExtraNonce, TransactionExtraMergeMiningTag, TransactionExtraAccountRegistration, TransactionExtraPqAccountRegistration, TransactionExtraPow, TransactionExtraPqMinerSpendPub> TransactionExtraField;



template<typename T>
bool findTransactionExtraFieldByType(const std::vector<TransactionExtraField>& tx_extra_fields, T& field) {
  auto it = std::find_if(tx_extra_fields.begin(), tx_extra_fields.end(),
    [](const TransactionExtraField& f) { return typeid(T) == f.type(); });

  if (tx_extra_fields.end() == it)
    return false;

  field = boost::get<T>(*it);
  return true;
}

bool parseTransactionExtra(const std::vector<uint8_t>& tx_extra, std::vector<TransactionExtraField>& tx_extra_fields);
bool writeTransactionExtra(std::vector<uint8_t>& tx_extra, const std::vector<TransactionExtraField>& tx_extra_fields);

Crypto::PublicKey getTransactionPublicKeyFromExtra(const std::vector<uint8_t>& tx_extra);
bool addTransactionPublicKeyToExtra(std::vector<uint8_t>& tx_extra, const Crypto::PublicKey& tx_pub_key);
bool addExtraNonceToTransactionExtra(std::vector<uint8_t>& tx_extra, const BinaryArray& extra_nonce);
void setPaymentIdToTransactionExtraNonce(BinaryArray& extra_nonce, const Crypto::Hash& payment_id);
bool getPaymentIdFromTransactionExtraNonce(const BinaryArray& extra_nonce, Crypto::Hash& payment_id);
bool appendMergeMiningTagToExtra(std::vector<uint8_t>& tx_extra, const TransactionExtraMergeMiningTag& mm_tag);
bool getMergeMiningTagFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraMergeMiningTag& mm_tag);

bool createTxExtraWithPaymentId(const std::string& paymentIdString, std::vector<uint8_t>& extra);
//returns false if payment id is not found or parse error
bool getPaymentIdFromTxExtra(const std::vector<uint8_t>& extra, Crypto::Hash& paymentId);
bool parsePaymentId(const std::string& paymentIdString, Crypto::Hash& paymentId);

bool addAccountRegistrationToExtra(std::vector<uint8_t>& tx_extra, const Crypto::PublicKey& spendKey, const Crypto::PublicKey& viewKey);
bool getAccountRegistrationFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraAccountRegistration& reg);
bool isWellFormedAccountRegistration(const std::vector<uint8_t>& tx_extra);

// PQ account registration (tag 0x05).
bool addPqAccountRegistrationToExtra(std::vector<uint8_t>& tx_extra,
                                     const std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE>& viewPub,
                                     const std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE>& spendPub);
bool getPqAccountRegistrationFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraPqAccountRegistration& reg);
Crypto::Hash getPqAccountIdentityHash(const TransactionExtraPqAccountRegistration& reg);
Crypto::Hash getPqAccountIdentityHash(
    const std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE>& viewPub,
    const std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE>& spendPub);

// PQ miner spend pub tag (tag 0x07) — coinbase identity.
bool addPqMinerSpendPubToExtra(std::vector<uint8_t>& tx_extra,
                               const std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE>& spendPub);
bool getPqMinerSpendPubFromExtra(const std::vector<uint8_t>& tx_extra,
                                 std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE>& spendPub);

// PQ anti-spam PoW tag (tag 0x06). appendPowTagToExtra MUST be the final write
// into tx_extra; the layout guarantees the nonce occupies the last 8 bytes.
bool appendPowTagToExtra(std::vector<uint8_t>& tx_extra, const TransactionExtraPow& pow);
bool getPowTagFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraPow& pow);
// True iff the PoW tag is present exactly once and is the last field in tx_extra
// (so the nonce is the final 8 bytes). Required for free-reg validity (spec §11.2).
bool isPowTagLastField(const std::vector<uint8_t>& tx_extra);

}
