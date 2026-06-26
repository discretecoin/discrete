// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2020, Karbo developers
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

#include "TransactionExtra.h"

#include "Common/MemoryInputStream.h"
#include "Common/StreamTools.h"
#include "Common/StringTools.h"
#include "CryptoNoteTools.h"
#include "../crypto/crypto.h"
#include "crypto_pq/PqHash.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/BinaryInputStreamSerializer.h"

#include <cstring>

using namespace Crypto;
using namespace Common;

namespace CryptoNote {

bool parseTransactionExtra(const std::vector<uint8_t> &transactionExtra, std::vector<TransactionExtraField> &transactionExtraFields) {
  transactionExtraFields.clear();

  if (transactionExtra.empty())
    return true;

  try {
    MemoryInputStream iss(transactionExtra.data(), transactionExtra.size());
    BinaryInputStreamSerializer ar(iss);

    int c = 0;

    while (!iss.endOfStream()) {
      c = read<uint8_t>(iss);
      switch (c) {
      case TX_EXTRA_TAG_PADDING: {
        size_t size = 1;
        for (; !iss.endOfStream() && size <= TX_EXTRA_PADDING_MAX_COUNT; ++size) {
          if (read<uint8_t>(iss) != 0) {
            return false; // all bytes should be zero
          }
        }

        if (size > TX_EXTRA_PADDING_MAX_COUNT) {
          return false;
        }

        transactionExtraFields.push_back(TransactionExtraPadding{ size });
        break;
      }

      case TX_EXTRA_TAG_PUBKEY: {
        TransactionExtraPublicKey extraPk;
        ar(extraPk.publicKey, "public_key");
        transactionExtraFields.push_back(extraPk);
        break;
      }

      case TX_EXTRA_NONCE: {
        TransactionExtraNonce extraNonce;
        uint8_t size = read<uint8_t>(iss);
        if (size > 0) {
          extraNonce.nonce.resize(size);
          read(iss, extraNonce.nonce.data(), extraNonce.nonce.size());
        }

        transactionExtraFields.push_back(extraNonce);
        break;
      }

      case TX_EXTRA_MERGE_MINING_TAG: {
        TransactionExtraMergeMiningTag mmTag;
        ar(mmTag, "mm_tag");
        transactionExtraFields.push_back(mmTag);
        break;
      }

      case TX_EXTRA_TAG_ACCOUNT_REGISTRATION: {
        TransactionExtraAccountRegistration reg;
        ar(reg.spendPublicKey, "spend_public_key");
        ar(reg.viewPublicKey, "view_public_key");
        transactionExtraFields.push_back(reg);
        break;
      }

      case TX_EXTRA_TAG_PQ_ACCOUNT_REGISTRATION: {
        TransactionExtraPqAccountRegistration reg;
        read(iss, reg.viewPub.data(), reg.viewPub.size());
        read(iss, reg.spendPub.data(), reg.spendPub.size());
        transactionExtraFields.push_back(reg);
        break;
      }

      case TX_EXTRA_TAG_POW: {
        TransactionExtraPow pow;
        ar(pow.refBlockHash, "ref_block_hash");
        uint8_t le[8];
        read(iss, le, sizeof(le));
        pow.nonce = 0;
        for (int i = 0; i < 8; ++i) {
          pow.nonce |= static_cast<uint64_t>(le[i]) << (8 * i);
        }
        transactionExtraFields.push_back(pow);
        break;
      }

      case TX_EXTRA_TAG_PQ_MINER_SPEND_PUB: {
        TransactionExtraPqMinerSpendPub minerKey;
        read(iss, minerKey.spendPub.data(), minerKey.spendPub.size());
        transactionExtraFields.push_back(minerKey);
        break;
      }
      }
    }
  } catch (std::exception &) {
    return false;
  }

  return true;
}

struct ExtraSerializerVisitor : public boost::static_visitor<bool> {
  std::vector<uint8_t>& extra;

  ExtraSerializerVisitor(std::vector<uint8_t>& tx_extra)
    : extra(tx_extra) {}

  bool operator()(const TransactionExtraPadding& t) {
    if (t.size > TX_EXTRA_PADDING_MAX_COUNT) {
      return false;
    }
    extra.insert(extra.end(), t.size, 0);
    return true;
  }

  bool operator()(const TransactionExtraPublicKey& t) {
    return addTransactionPublicKeyToExtra(extra, t.publicKey);
  }

  bool operator()(const TransactionExtraNonce& t) {
    return addExtraNonceToTransactionExtra(extra, t.nonce);
  }

  bool operator()(const TransactionExtraMergeMiningTag& t) {
    return appendMergeMiningTagToExtra(extra, t);
  }

  bool operator()(const TransactionExtraAccountRegistration& t) {
    return addAccountRegistrationToExtra(extra, t.spendPublicKey, t.viewPublicKey);
  }

  bool operator()(const TransactionExtraPqAccountRegistration& t) {
    return addPqAccountRegistrationToExtra(extra, t.viewPub, t.spendPub);
  }

  bool operator()(const TransactionExtraPow& t) {
    return appendPowTagToExtra(extra, t);
  }

  bool operator()(const TransactionExtraPqMinerSpendPub& t) {
    return addPqMinerSpendPubToExtra(extra, t.spendPub);
  }
};

bool writeTransactionExtra(std::vector<uint8_t>& tx_extra, const std::vector<TransactionExtraField>& tx_extra_fields) {
  ExtraSerializerVisitor visitor(tx_extra);

  for (const auto& tag : tx_extra_fields) {
    if (!boost::apply_visitor(visitor, tag)) {
      return false;
    }
  }

  return true;
}

PublicKey getTransactionPublicKeyFromExtra(const std::vector<uint8_t>& tx_extra) {
  std::vector<TransactionExtraField> tx_extra_fields;
  parseTransactionExtra(tx_extra, tx_extra_fields);

  TransactionExtraPublicKey pub_key_field;
  if (!findTransactionExtraFieldByType(tx_extra_fields, pub_key_field))
    return boost::value_initialized<PublicKey>();

  return pub_key_field.publicKey;
}

bool addTransactionPublicKeyToExtra(std::vector<uint8_t>& tx_extra, const PublicKey& tx_pub_key) {
  tx_extra.resize(tx_extra.size() + 1 + sizeof(PublicKey));
  tx_extra[tx_extra.size() - 1 - sizeof(PublicKey)] = TX_EXTRA_TAG_PUBKEY;
  *reinterpret_cast<PublicKey*>(&tx_extra[tx_extra.size() - sizeof(PublicKey)]) = tx_pub_key;
  return true;
}


bool addExtraNonceToTransactionExtra(std::vector<uint8_t>& tx_extra, const BinaryArray& extra_nonce) {
  if (extra_nonce.size() > TX_EXTRA_NONCE_MAX_COUNT) {
    return false;
  }

  size_t start_pos = tx_extra.size();
  tx_extra.resize(tx_extra.size() + 2 + extra_nonce.size());
  //write tag
  tx_extra[start_pos] = TX_EXTRA_NONCE;
  //write len
  ++start_pos;
  tx_extra[start_pos] = static_cast<uint8_t>(extra_nonce.size());
  //write data
  ++start_pos;
  memcpy(&tx_extra[start_pos], extra_nonce.data(), extra_nonce.size());
  return true;
}

bool appendMergeMiningTagToExtra(std::vector<uint8_t>& tx_extra, const TransactionExtraMergeMiningTag& mm_tag) {
  BinaryArray blob;
  if (!toBinaryArray(mm_tag, blob)) {
    return false;
  }

  tx_extra.push_back(TX_EXTRA_MERGE_MINING_TAG);
  std::copy(reinterpret_cast<const uint8_t*>(blob.data()), reinterpret_cast<const uint8_t*>(blob.data() + blob.size()), std::back_inserter(tx_extra));
  return true;
}

bool getMergeMiningTagFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraMergeMiningTag& mm_tag) {
  std::vector<TransactionExtraField> tx_extra_fields;
  parseTransactionExtra(tx_extra, tx_extra_fields);

  return findTransactionExtraFieldByType(tx_extra_fields, mm_tag);
}

void setPaymentIdToTransactionExtraNonce(std::vector<uint8_t>& extra_nonce, const Hash& payment_id) {
  extra_nonce.clear();
  extra_nonce.push_back(TX_EXTRA_NONCE_PAYMENT_ID);
  const uint8_t* payment_id_ptr = reinterpret_cast<const uint8_t*>(&payment_id);
  std::copy(payment_id_ptr, payment_id_ptr + sizeof(payment_id), std::back_inserter(extra_nonce));
}

bool getPaymentIdFromTransactionExtraNonce(const std::vector<uint8_t>& extra_nonce, Hash& payment_id) {
  if (sizeof(Hash) + 1 != extra_nonce.size())
    return false;
  if (TX_EXTRA_NONCE_PAYMENT_ID != extra_nonce[0])
    return false;
  payment_id = *reinterpret_cast<const Hash*>(extra_nonce.data() + 1);
  return true;
}

bool parsePaymentId(const std::string& paymentIdString, Hash& paymentId) {
  return Common::podFromHex(paymentIdString, paymentId);
}

bool createTxExtraWithPaymentId(const std::string& paymentIdString, std::vector<uint8_t>& extra) {
  Hash paymentIdBin;

  if (!parsePaymentId(paymentIdString, paymentIdBin)) {
    return false;
  }

  std::vector<uint8_t> extraNonce;
  CryptoNote::setPaymentIdToTransactionExtraNonce(extraNonce, paymentIdBin);

  if (!CryptoNote::addExtraNonceToTransactionExtra(extra, extraNonce)) {
    return false;
  }

  return true;
}

bool getPaymentIdFromTxExtra(const std::vector<uint8_t>& extra, Hash& paymentId) {
  std::vector<TransactionExtraField> tx_extra_fields;
  if (!parseTransactionExtra(extra, tx_extra_fields)) {
    return false;
  }

  TransactionExtraNonce extra_nonce;
  if (findTransactionExtraFieldByType(tx_extra_fields, extra_nonce)) {
    if (!getPaymentIdFromTransactionExtraNonce(extra_nonce.nonce, paymentId)) {
      return false;
    }
  } else {
    return false;
  }

  return true;
}

bool addAccountRegistrationToExtra(std::vector<uint8_t>& tx_extra, const PublicKey& spendKey, const PublicKey& viewKey) {
  size_t start = tx_extra.size();
  tx_extra.resize(start + 1 + sizeof(PublicKey) + sizeof(PublicKey));
  tx_extra[start] = TX_EXTRA_TAG_ACCOUNT_REGISTRATION;
  memcpy(&tx_extra[start + 1], &spendKey, sizeof(PublicKey));
  memcpy(&tx_extra[start + 1 + sizeof(PublicKey)], &viewKey, sizeof(PublicKey));
  return true;
}

bool getAccountRegistrationFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraAccountRegistration& reg) {
  std::vector<TransactionExtraField> tx_extra_fields;
  if (!parseTransactionExtra(tx_extra, tx_extra_fields)) {
    return false;
  }
  return findTransactionExtraFieldByType(tx_extra_fields, reg);
}

bool isWellFormedAccountRegistration(const std::vector<uint8_t>& tx_extra) {
  std::vector<TransactionExtraField> extraFields;
  if (!parseTransactionExtra(tx_extra, extraFields)) {
    return false;
  }

  int regCount = 0;
  bool hasNonce = false;
  for (const auto& field : extraFields) {
    if (field.type() == typeid(TransactionExtraAccountRegistration)) {
      ++regCount;
    }
    if (field.type() == typeid(TransactionExtraNonce)) {
      hasNonce = true;
    }
  }

  if (regCount != 1) {
    return false;
  }

  if (hasNonce) {
    return false;
  }

  TransactionExtraAccountRegistration reg;
  findTransactionExtraFieldByType(extraFields, reg);

  // No ECC curve check (classical AccountRegistration is not the PQ path).
  static const Crypto::PublicKey identity = {};
  if (reg.spendPublicKey == identity || reg.viewPublicKey == identity) {
    return false;
  }

  return true;
}

bool addPqAccountRegistrationToExtra(std::vector<uint8_t>& tx_extra,
                                     const std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE>& viewPub,
                                     const std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE>& spendPub) {
  size_t start = tx_extra.size();
  tx_extra.resize(start + 1 + viewPub.size() + spendPub.size());
  tx_extra[start] = TX_EXTRA_TAG_PQ_ACCOUNT_REGISTRATION;
  memcpy(&tx_extra[start + 1], viewPub.data(), viewPub.size());
  memcpy(&tx_extra[start + 1 + viewPub.size()], spendPub.data(), spendPub.size());
  return true;
}

bool getPqAccountRegistrationFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraPqAccountRegistration& reg) {
  std::vector<TransactionExtraField> tx_extra_fields;
  if (!parseTransactionExtra(tx_extra, tx_extra_fields)) {
    return false;
  }
  return findTransactionExtraFieldByType(tx_extra_fields, reg);
}

Crypto::Hash getPqAccountIdentityHash(const TransactionExtraPqAccountRegistration& reg) {
  return getPqAccountIdentityHash(reg.viewPub, reg.spendPub);
}

Crypto::Hash getPqAccountIdentityHash(
    const std::array<uint8_t, TX_EXTRA_PQ_VIEW_PUBKEY_SIZE>& viewPub,
    const std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE>& spendPub) {
  static const char domain[] = "karbo-pq-account-id-v1";
  std::vector<uint8_t> buf;
  buf.reserve(sizeof(domain) - 1 + viewPub.size() + spendPub.size());
  buf.insert(buf.end(), domain, domain + sizeof(domain) - 1);
  buf.insert(buf.end(), viewPub.begin(), viewPub.end());
  buf.insert(buf.end(), spendPub.begin(), spendPub.end());

  CryptoPQ::Hash256 digest = CryptoPQ::sha3_256(buf.data(), buf.size());
  Crypto::Hash out;
  std::memcpy(out.data, digest.data(), 32);
  return out;
}

bool appendPowTagToExtra(std::vector<uint8_t>& tx_extra, const TransactionExtraPow& pow) {
  size_t start = tx_extra.size();
  tx_extra.resize(start + 1 + sizeof(Hash) + 8);
  tx_extra[start] = TX_EXTRA_TAG_POW;
  memcpy(&tx_extra[start + 1], &pow.refBlockHash, sizeof(Hash));
  // nonce: 8 bytes little-endian, the final bytes of the tag (and of tx_extra,
  // when this is appended last).
  size_t noncePos = start + 1 + sizeof(Hash);
  for (int i = 0; i < 8; ++i) {
    tx_extra[noncePos + i] = static_cast<uint8_t>((pow.nonce >> (8 * i)) & 0xFF);
  }
  return true;
}

bool getPowTagFromExtra(const std::vector<uint8_t>& tx_extra, TransactionExtraPow& pow) {
  std::vector<TransactionExtraField> tx_extra_fields;
  if (!parseTransactionExtra(tx_extra, tx_extra_fields)) {
    return false;
  }
  return findTransactionExtraFieldByType(tx_extra_fields, pow);
}

bool isPowTagLastField(const std::vector<uint8_t>& tx_extra) {
  std::vector<TransactionExtraField> extraFields;
  if (!parseTransactionExtra(tx_extra, extraFields) || extraFields.empty()) {
    return false;
  }
  int powCount = 0;
  for (const auto& f : extraFields) {
    if (f.type() == typeid(TransactionExtraPow)) {
      ++powCount;
    }
  }
  return powCount == 1 && extraFields.back().type() == typeid(TransactionExtraPow);
}

bool addPqMinerSpendPubToExtra(std::vector<uint8_t>& tx_extra,
                               const std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE>& spendPub) {
  tx_extra.push_back(TX_EXTRA_TAG_PQ_MINER_SPEND_PUB);
  tx_extra.insert(tx_extra.end(), spendPub.begin(), spendPub.end());
  return true;
}

bool getPqMinerSpendPubFromExtra(const std::vector<uint8_t>& tx_extra,
                                 std::array<uint8_t, TX_EXTRA_PQ_SPEND_PUBKEY_SIZE>& spendPub) {
  std::vector<TransactionExtraField> fields;
  if (!parseTransactionExtra(tx_extra, fields)) {
    return false;
  }
  TransactionExtraPqMinerSpendPub field;
  if (!findTransactionExtraFieldByType(fields, field)) {
    return false;
  }
  spendPub = field.spendPub;
  return true;
}

}
