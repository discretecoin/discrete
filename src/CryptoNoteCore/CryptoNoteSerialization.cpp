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

#include "CryptoNoteSerialization.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>

#include <boost/variant/static_visitor.hpp>
#include <boost/variant/apply_visitor.hpp>

#include "Serialization/ISerializer.h"
#include "Serialization/SerializationOverloads.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"

#include "Common/StringOutputStream.h"
#include "crypto/crypto.h"

#include "Account.h"
#include "CryptoNoteConfig.h"
#include "CryptoNoteFormatUtils.h"
#include "CryptoNoteTools.h"
#include "TransactionExtra.h"

using namespace Common;

namespace {

using namespace CryptoNote;
using namespace Common;

size_t getSignaturesCount(const TransactionInput& input) {
  struct txin_signature_size_visitor : public boost::static_visitor<size_t> {
    size_t operator()(const BaseInput&) const { return 0; }
    // KeyInput is a stub — should never appear in Discrete transactions.
    size_t operator()(const KeyInput& txin) const { return txin.outputIndexes.size(); }
    // PQ signatures live inside PqInput, not in Transaction.signatures.
    size_t operator()(const PqInput&) const { return 0; }
  };
  return boost::apply_visitor(txin_signature_size_visitor(), input);
}

struct BinaryVariantTagGetter: boost::static_visitor<uint8_t> {
  uint8_t operator()(const CryptoNote::BaseInput&) { return  0xff; }
  // KeyInput stub — should never be serialised on Discrete.
  uint8_t operator()(const CryptoNote::KeyInput&) { throw std::runtime_error("KeyInput not allowed in Discrete"); }
  uint8_t operator()(const CryptoNote::PqInput&) { return  0x10; }
  // KeyOutput stub — should never be serialised on Discrete.
  uint8_t operator()(const CryptoNote::KeyOutput&) { throw std::runtime_error("KeyOutput not allowed in Discrete"); }
  uint8_t operator()(const CryptoNote::PqOutput&) { return  0x10; }
  uint8_t operator()(const CryptoNote::Transaction&) { return  0xcc; }
  uint8_t operator()(const CryptoNote::Block&) { return  0xbb; }
};

struct VariantSerializer : boost::static_visitor<> {
  VariantSerializer(CryptoNote::ISerializer& serializer, const std::string& name) : s(serializer), name(name) {}

  template <typename T>
  void operator() (T& param) { s(param, name); }

  CryptoNote::ISerializer& s;
  std::string name;
};

void getVariantValue(CryptoNote::ISerializer& serializer, uint8_t tag, CryptoNote::TransactionInput& in) {
  switch(tag) {
  case 0xff: {
    CryptoNote::BaseInput v;
    serializer(v, "value");
    in = v;
    break;
  }
  case 0x2:
    // ECC KeyInput — rejected on Discrete.
    throw std::runtime_error("KeyInput (ECC ring-sig) not allowed in Discrete transactions");
  case 0x10: {
    CryptoNote::PqInput v;
    serializer(v, "value");
    in = v;
    break;
  }
  default:
    throw std::runtime_error("Unknown transaction input tag");
  }
}

void getVariantValue(CryptoNote::ISerializer& serializer, uint8_t tag, CryptoNote::TransactionOutputTarget& out) {
  switch(tag) {
  case 0x2:
    // ECC KeyOutput — rejected on Discrete.
    throw std::runtime_error("KeyOutput (ECC stealth) not allowed in Discrete transactions");
  case 0x10: {
    CryptoNote::PqOutput v;
    serializer(v, "data");
    out = v;
    break;
  }
  default:
    throw std::runtime_error("Unknown transaction output tag");
  }
}

template <typename T>
bool serializePod(T& v, Common::StringView name, CryptoNote::ISerializer& serializer) {
  return serializer.binary(&v, sizeof(v), name);
}

bool serializeVarintVector(std::vector<uint32_t>& vector, CryptoNote::ISerializer& serializer, Common::StringView name) {
  size_t size = vector.size();
  
  if (!serializer.beginArray(size, name)) {
    vector.clear();
    return false;
  }

  vector.resize(size);

  for (size_t i = 0; i < size; ++i) {
    serializer(vector[i], "");
  }

  serializer.endArray();
  return true;
}

}

namespace Crypto {

bool serialize(PublicKey& pubKey, Common::StringView name, CryptoNote::ISerializer& serializer) {
  return serializePod(pubKey, name, serializer);
}

bool serialize(SecretKey& secKey, Common::StringView name, CryptoNote::ISerializer& serializer) {
  return serializePod(secKey, name, serializer);
}

bool serialize(Hash& h, Common::StringView name, CryptoNote::ISerializer& serializer) {
  return serializePod(h, name, serializer);
}

bool serialize(KeyImage& keyImage, Common::StringView name, CryptoNote::ISerializer& serializer) {
  return serializePod(keyImage, name, serializer);
}

bool serialize(chacha8_iv& chacha, Common::StringView name, CryptoNote::ISerializer& serializer) {
  return serializePod(chacha, name, serializer);
}

bool serialize(Signature& sig, Common::StringView name, CryptoNote::ISerializer& serializer) {
  return serializePod(sig, name, serializer);
}

bool serialize(EllipticCurveScalar& ecScalar, Common::StringView name, CryptoNote::ISerializer& serializer) {
  return serializePod(ecScalar, name, serializer);
}

bool serialize(EllipticCurvePoint& ecPoint, Common::StringView name, CryptoNote::ISerializer& serializer) {
  return serializePod(ecPoint, name, serializer);
}

}

namespace CryptoNote {

void serialize(TransactionPrefix& txP, ISerializer& serializer) {
  serializer(txP.version, "version");

  // Discrete only accepts the PQ transaction version; legacy ECC v1 is rejected.
  if (txP.version != TRANSACTION_VERSION_PQ) {
    throw std::runtime_error("Wrong transaction version — Discrete only accepts PQ transactions");
  }

  serializer(txP.txType, "tx_type");
  serializer(txP.unlockTime, "unlock_time");
  serializer(txP.inputs, "vin");
  serializer(txP.outputs, "vout");
  serializeAsBinary(txP.extra, "extra", serializer);
}

void serialize(Transaction& tx, ISerializer& serializer) {
  serialize(static_cast<TransactionPrefix&>(tx), serializer);
  // Discrete: PQ signatures live inside PqInput — Transaction.signatures is always
  // empty. No ring-signature vector is written or read.
  tx.signatures.clear();
}

void serialize(TransactionInput& in, ISerializer& serializer) {
  if (serializer.type() == ISerializer::OUTPUT) {
    BinaryVariantTagGetter tagGetter;
    uint8_t tag = boost::apply_visitor(tagGetter, in);
    serializer.binary(&tag, sizeof(tag), "type");

    VariantSerializer visitor(serializer, "value");
    boost::apply_visitor(visitor, in);
  } else {
    uint8_t tag;
    serializer.binary(&tag, sizeof(tag), "type");

    getVariantValue(serializer, tag, in);
  }
}

void serialize(BaseInput& gen, ISerializer& serializer) {
  serializer(gen.blockIndex, "height");
}

void serialize(KeyInput& /*key*/, ISerializer& /*serializer*/) {
  throw std::runtime_error("KeyInput serialization not supported in Discrete");
}

// Fixed-length byte blob: exactly `expected` bytes, no length prefix. On read
// the buffer is resized and exactly that many bytes are consumed; on write the
// buffer must already be `expected` bytes (consensus well-formedness). This is
// how the PQ field-length checks are enforced.
static void serializePqBlob(std::vector<uint8_t>& v, size_t expected, Common::StringView name, ISerializer& serializer) {
  if (serializer.type() == ISerializer::INPUT) {
    v.resize(expected);
  } else if (v.size() != expected) {
    throw std::runtime_error("PQ wire field has wrong size");
  }
  serializer.binary(v.data(), expected, name);
}

void serialize(PqInput& key, ISerializer& serializer) {
  serializer(key.prevTxid, "prev_txid");
  serializer(key.prevOutIndex, "prev_out_index");
  serializePqBlob(key.authPub,   PQ_AUTH_PUB_SIZE,   "auth_pub",   serializer);
  serializePqBlob(key.rhoReveal, PQ_RHO_SIZE,        "rho_reveal", serializer);
  serializePqBlob(key.signature, PQ_SIGNATURE_SIZE,  "signature",  serializer);
}

void serialize(TransactionInputs & inputs, ISerializer & serializer) {
  serializer(inputs, "vin");
}

void serialize(TransactionOutput& output, ISerializer& serializer) {
  serializer(output.amount, "amount");
  serializer(output.target, "target");
}

void serialize(TransactionOutputTarget& output, ISerializer& serializer) {
  if (serializer.type() == ISerializer::OUTPUT) {
    // Always write tag 0x10 (PqOutput). KeyOutput (0x2) is never written.
    uint8_t tag = 0x10;
    serializer.binary(&tag, sizeof(tag), "type");
    CryptoNote::PqOutput& pqOut = boost::get<CryptoNote::PqOutput>(output);
    serializer(pqOut, "data");
  } else {
    uint8_t tag;
    serializer.binary(&tag, sizeof(tag), "type");
    if (tag != 0x10) {
      throw std::runtime_error("KeyOutput (ECC) not allowed in Discrete — only PQ outputs (tag 0x10) accepted");
    }
    CryptoNote::PqOutput v;
    serializer(v, "data");
    output = v;
  }
}

void serialize(KeyOutput& /*key*/, ISerializer& /*serializer*/) {
  throw std::runtime_error("KeyOutput serialization not supported in Discrete");
}

void serialize(PqOutput& output, ISerializer& serializer) {
  serializePqBlob(output.kemCt,      PQ_KEM_CIPHERTEXT_SIZE, "kem_ct",      serializer);
  serializePqBlob(output.encPayload, PQ_ENC_PAYLOAD_SIZE,    "enc_payload", serializer);
  serializer(output.spendCommit, "spend_commit");
}

void serialize(ParentBlockSerializer& pbs, ISerializer& serializer) {
  serializer(pbs.m_parentBlock.majorVersion, "majorVersion");

  serializer(pbs.m_parentBlock.minorVersion, "minorVersion");
  serializer(pbs.m_timestamp, "timestamp");
  serializer(pbs.m_parentBlock.previousBlockHash, "prevId");
  serializer.binary(&pbs.m_nonce, sizeof(pbs.m_nonce), "nonce");

  if (pbs.m_hashingSerialization) {
    Crypto::Hash minerTxHash;
    if (!getObjectHash(pbs.m_parentBlock.baseTransaction, minerTxHash)) {
      throw std::runtime_error("Get transaction hash error");
    }

    Crypto::Hash merkleRoot;
    Crypto::tree_hash_from_branch(pbs.m_parentBlock.baseTransactionBranch.data(), pbs.m_parentBlock.baseTransactionBranch.size(), minerTxHash, 0, merkleRoot);

    serializer(merkleRoot, "merkleRoot");
  }

  uint64_t txNum = static_cast<uint64_t>(pbs.m_parentBlock.transactionCount);
  serializer(txNum, "numberOfTransactions");
  pbs.m_parentBlock.transactionCount = static_cast<uint16_t>(txNum);
  if (pbs.m_parentBlock.transactionCount < 1) {
    throw std::runtime_error("Wrong transactions number");
  }

  if (pbs.m_headerOnly) {
    return;
  }

  size_t branchSize = Crypto::tree_depth(pbs.m_parentBlock.transactionCount);
  if (serializer.type() == ISerializer::OUTPUT) {
    if (pbs.m_parentBlock.baseTransactionBranch.size() != branchSize) {
      throw std::runtime_error("Wrong miner transaction branch size");
    }
  } else {
    pbs.m_parentBlock.baseTransactionBranch.resize(branchSize);
  }

//  serializer(m_parentBlock.baseTransactionBranch, "baseTransactionBranch");
  //TODO: Make arrays with computable size! This code won't work with json serialization!
  for (Crypto::Hash& hash: pbs.m_parentBlock.baseTransactionBranch) {
    serializer(hash, "");
  }

  serializer(pbs.m_parentBlock.baseTransaction, "minerTx");

  TransactionExtraMergeMiningTag mmTag;
  if (!getMergeMiningTagFromExtra(pbs.m_parentBlock.baseTransaction.extra, mmTag)) {
    throw std::runtime_error("Can't get extra merge mining tag");
  }

  if (mmTag.depth > 8 * sizeof(Crypto::Hash)) {
    throw std::runtime_error("Wrong merge mining tag depth");
  }

  if (serializer.type() == ISerializer::OUTPUT) {
    if (mmTag.depth != pbs.m_parentBlock.blockchainBranch.size()) {
      throw std::runtime_error("Blockchain branch size must be equal to merge mining tag depth");
    }
  } else {
    pbs.m_parentBlock.blockchainBranch.resize(mmTag.depth);
  }

//  serializer(m_parentBlock.blockchainBranch, "blockchainBranch");
  //TODO: Make arrays with computable size! This code won't work with json serialization!
  for (Crypto::Hash& hash: pbs.m_parentBlock.blockchainBranch) {
    serializer(hash, "");
  }
}

void serializeBlockHeader(BlockHeader& header, ISerializer& serializer) {
  serializer(header.majorVersion, "major_version");
  if (header.majorVersion < BLOCK_MAJOR_VERSION_1 || header.majorVersion > BLOCK_MAJOR_VERSION_8) {
    throw std::runtime_error("Wrong block major version");
  }

  serializer(header.minorVersion, "minor_version");
  serializer(header.timestamp, "timestamp");
  serializer(header.previousBlockHash, "prev_id");
  serializer.binary(&header.nonce, sizeof(header.nonce), "nonce");
}

void serialize(BlockHeader& header, ISerializer& serializer) {
  serializeBlockHeader(header, serializer);
}

void serialize(Block& block, ISerializer& serializer) {
  serializeBlockHeader(block, serializer);
  // All Discrete blocks are v6+ — ML-DSA-65 block signature always present,
  // merge-mining parent block never present.
  serializePqBlob(block.signature, CryptoNote::PQ_SIGNATURE_SIZE, "signature", serializer);
  serializer(block.baseTransaction, "miner_tx");
  serializer(block.transactionHashes, "tx_hashes");
}

void serialize(AccountPublicAddress& address, ISerializer& serializer) {
  serializer(address.spendPublicKey, "m_spend_public_key");
  serializer(address.viewPublicKey, "m_view_public_key");
}

void serialize(AccountKeys& keys, ISerializer& s) {
  s(keys.address, "m_account_address");
  s(keys.spendSecretKey, "m_spend_secret_key");
  s(keys.viewSecretKey, "m_view_secret_key");
}

void doSerialize(TransactionExtraMergeMiningTag& tag, ISerializer& serializer) {
  uint64_t depth = static_cast<uint64_t>(tag.depth);
  serializer(depth, "depth");
  tag.depth = static_cast<size_t>(depth);
  serializer(tag.merkleRoot, "merkle_root");
}

void serialize(TransactionExtraMergeMiningTag& tag, ISerializer& serializer) {
  if (serializer.type() == ISerializer::OUTPUT) {
    std::string field;
    StringOutputStream os(field);
    BinaryOutputStreamSerializer output(os);
    doSerialize(tag, output);
    serializer(field, "");
  } else {
    std::string field;
    serializer(field, "");
    MemoryInputStream stream(field.data(), field.size());
    BinaryInputStreamSerializer input(stream);
    doSerialize(tag, input);
  }
}

void serialize(KeyPair& keyPair, ISerializer& serializer) {
  serializer(keyPair.secretKey, "secret_key");
  serializer(keyPair.publicKey, "public_key");
}


} //namespace CryptoNote
