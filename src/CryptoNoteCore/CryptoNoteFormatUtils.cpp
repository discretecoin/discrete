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

#include "CryptoNoteFormatUtils.h"

#include <algorithm>
#include <set>

#include <Common/BinaryArray.hpp>
#include <Common/Varint.h>
#include "Common/Base58.h"

#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "CryptoNoteSerialization.h"

#include "Account.h"
#include "CryptoNoteBasicImpl.h"
#include "CryptoNoteSerialization.h"
#include "TransactionExtra.h"
#include "CryptoNoteTools.h"
#include "Currency.h"

#include "CryptoNoteConfig.h"
#include "PqTxType.h"
#include "crypto_pq/PqHash.h"
#include "crypto_pq/PqSeed.h"
#include "crypto_pq/PqDsa.h"
#include "crypto/yespower.h"

#include <array>
#include <cstring>

using namespace Logging;
using namespace Crypto;
using namespace Common;

namespace CryptoNote {

bool parseAndValidateTransactionFromBinaryArray(const BinaryArray& tx_blob, Transaction& tx, Hash& tx_hash, Hash& tx_prefix_hash) {
  if (!fromBinaryArray(tx, tx_blob)) {
    return false;
  }

  //TODO: validate tx
  cn_fast_hash(tx_blob.data(), tx_blob.size(), tx_hash);
  getObjectHash(*static_cast<TransactionPrefix*>(&tx), tx_prefix_hash);
  return true;
}

uint64_t power_integral(uint64_t a, uint64_t b) {
  if (b == 0)
    return 1;
  uint64_t total = a;
  for (uint64_t i = 1; i != b; i++)
    total *= a;
  return total;
}

bool get_tx_fee(const Transaction& tx, uint64_t & fee) {
  uint64_t amount_in = 0;
  uint64_t amount_out = 0;

  // PQ inputs don't carry inline amounts; fee is computed from referenced outputs.
  (void)tx;

  for (const auto& o : tx.outputs) {
    amount_out += o.amount;
  }

  if (!(amount_in >= amount_out)) {
    return false;
  }

  fee = amount_in - amount_out;
  return true;
}

uint64_t get_tx_fee(const Transaction& tx) {
  uint64_t r = 0;
  if (!get_tx_fee(tx, r))
    return 0;
  return r;
}

bool get_inputs_money_amount(const Transaction& /*tx*/, uint64_t& money) {
  // PQ inputs don't carry inline amounts; amount is resolved from referenced outputs.
  money = 0;
  return true;
}

uint32_t get_block_height(const Block& b) {
  if (b.baseTransaction.inputs.size() != 1) {
    return 0;
  }
  const auto& in = b.baseTransaction.inputs[0];
  if (in.type() != typeid(BaseInput)) {
    return 0;
  }
  return boost::get<BaseInput>(in).blockIndex;
}

bool check_inputs_types_supported(const TransactionPrefix& tx) {
  const bool pqInputs = tx.version >= TRANSACTION_VERSION_1 && tx.txType == TX_PQ;
  for (const auto& in : tx.inputs) {
    if (pqInputs) {
      if (in.type() != typeid(PqInput)) return false;
    } else {
      if (in.type() != typeid(BaseInput)) return false;
    }
  }
  return true;
}

bool check_outs_valid(const TransactionPrefix& tx, std::string* error) {
  for (const TransactionOutput& out : tx.outputs) {
    if (tx.version >= TRANSACTION_VERSION_1) {
      if (out.target.type() == typeid(PqOutput)) {
        if (tx.txType != TX_PQ) {
          if (error) *error = "PqOutput is not allowed for this tx type";
          return false;
        }
        if (out.amount == 0) {
          if (error) *error = "Zero amount output";
          return false;
        }
        continue;
      }
      if (out.target.type() == typeid(CoinbaseOutput)) {
        if (tx.txType != TX_COINBASE) {
          if (error) *error = "CoinbaseOutput is not allowed outside coinbase transactions";
          return false;
        }
        if (out.amount == 0) {
          if (error) *error = "Zero amount coinbase output";
          return false;
        }
        continue;
      }
    }

    if (out.target.type() == typeid(KeyOutput)) {
      // Discrete has no classical (ECC) outputs — only PQ outputs exist.
      if (error) *error = "KeyOutput is not allowed in Discrete";
      return false;
    } else {
      if (error) {
        *error = "Output with invalid type";
      }
      return false;
    }
  }

  return true;
}

bool check_money_overflow(const TransactionPrefix &tx) {
  return check_inputs_overflow(tx) && check_outs_overflow(tx);
}

bool check_inputs_overflow(const TransactionPrefix& /*tx*/) {
  // PQ inputs have no inline amount; no overflow to check.
  return true;
}

bool check_outs_overflow(const TransactionPrefix& tx) {
  uint64_t money = 0;
  for (const auto& o : tx.outputs) {
    if (money > o.amount + money)
      return false;
    money += o.amount;
  }
  return true;
}

uint64_t get_outs_money_amount(const Transaction& tx) {
  uint64_t outputs_amount = 0;
  for (const auto& o : tx.outputs) {
    outputs_amount += o.amount;
  }
  return outputs_amount;
}

std::string short_hash_str(const Hash& h) {
  std::string res = Common::podToHex(h);

  if (res.size() == 64) {
    auto erased_pos = res.erase(8, 48);
    res.insert(8, "....");
  }

  return res;
}

bool get_block_hashing_blob(const Block& b, BinaryArray& ba) {
  if (!toBinaryArray(static_cast<const BlockHeader&>(b), ba)) {
    return false;
  }

  Hash treeRootHash = get_tx_tree_hash(b);
  ba.insert(ba.end(), treeRootHash.data, treeRootHash.data + 32);
  auto transactionCount = asBinaryArray(Tools::get_varint_data(b.transactionHashes.size() + 1));
  ba.insert(ba.end(), transactionCount.begin(), transactionCount.end());
  return true;
}

namespace {

void appendBytes(BinaryArray& out, const void* data, size_t size) {
  const auto* bytes = static_cast<const uint8_t*>(data);
  out.insert(out.end(), bytes, bytes + size);
}

Crypto::Hash shake256Hash(const BinaryArray& input) {
  Crypto::Hash result{};
  CryptoPQ::shake256(input.data(), input.size(), result.data, sizeof(result.data));
  return result;
}

// Witness-commitment block identity (DiscretePower). cB is the unsigned
// block-hashing blob C_B. The signature is bound through a separable 32-byte
// witness so it can later be pruned while the ID stays recomputable:
//   W  = SHAKE256(witness-domain  || signature, 32)
//   ID = SHAKE256(block-id-domain || LE64(|C_B|) || C_B || W, 32)
Crypto::Hash discretePowerBlockId(const BinaryArray& cB,
                                  const std::vector<uint8_t>& signature) {
  std::array<uint8_t, 32> W{};
  {
    BinaryArray t;
    t.reserve(sizeof(DISCRETE_POWER_WITNESS_DOMAIN) - 1 + signature.size());
    appendBytes(t, DISCRETE_POWER_WITNESS_DOMAIN, sizeof(DISCRETE_POWER_WITNESS_DOMAIN) - 1);
    appendBytes(t, signature.data(), signature.size());
    CryptoPQ::shake256(t.data(), t.size(), W.data(), W.size());
  }
  uint8_t lenLE[8];
  const uint64_t n = static_cast<uint64_t>(cB.size());
  for (int i = 0; i < 8; ++i) lenLE[i] = static_cast<uint8_t>((n >> (8 * i)) & 0xFFu);
  BinaryArray t;
  t.reserve(sizeof(DISCRETE_POWER_BLOCK_ID_DOMAIN) - 1 + sizeof(lenLE) + cB.size() + W.size());
  appendBytes(t, DISCRETE_POWER_BLOCK_ID_DOMAIN, sizeof(DISCRETE_POWER_BLOCK_ID_DOMAIN) - 1);
  appendBytes(t, lenLE, sizeof(lenLE));
  appendBytes(t, cB.data(), cB.size());
  appendBytes(t, W.data(), W.size());
  return shake256Hash(t);
}

}  // namespace

namespace {

// DiscretePower compile-time bindings (https://docs.discrete.cash/#/consensus/pow §4).
static_assert(parameters::DISCRETE_POWER_SIG_LEN == CryptoPQ::kDsaSignatureBytes,
              "DISCRETE_POWER_SIG_LEN must equal the liboqs ML-DSA-65 signature length");
static_assert(parameters::DISCRETE_POWER_SIG_LEN == PQ_SIGNATURE_SIZE,
              "DISCRETE_POWER_SIG_LEN must equal PQ_SIGNATURE_SIZE");
static_assert(parameters::DISCRETE_POWER_TAPE_LEN == parameters::DISCRETE_POWER_SIG_LEN + 3,
              "DiscretePower tape is the signature plus the 3-byte 0x80 00 00 delimiter");
static_assert(parameters::DISCRETE_POWER_TAPE_WORDS * 8 == parameters::DISCRETE_POWER_TAPE_LEN,
              "DiscretePower tape must be an integral number of 8-byte words");

// H = SHAKE256("DiscretePower/v2/header" || blob, 64).
std::array<uint8_t, 64> discretePowerHeaderFromBlob(const BinaryArray& blob) {
  BinaryArray t;
  t.reserve(sizeof(DISCRETE_POWER_HEADER_DOMAIN) - 1 + blob.size());
  appendBytes(t, DISCRETE_POWER_HEADER_DOMAIN, sizeof(DISCRETE_POWER_HEADER_DOMAIN) - 1);
  t.insert(t.end(), blob.begin(), blob.end());
  std::array<uint8_t, 64> H{};
  CryptoPQ::shake256(t.data(), t.size(), H.data(), H.size());
  return H;
}

// Spec §5/§9 steps 4-6: build the 3312-byte tape from the raw signature bytes,
// run one yespower-discrete execution, and finalize. Returns false only on a
// yespower-discrete allocation failure (never on a mere hash mismatch).
bool discretePowerMemoryAndFinal(const std::array<uint8_t, 64>& H,
                       const uint8_t* sig /* DISCRETE_POWER_SIG_LEN bytes */,
                       Crypto::Hash& powHash) {
  std::array<uint8_t, parameters::DISCRETE_POWER_TAPE_LEN> tape{};
  std::memcpy(tape.data(), sig, parameters::DISCRETE_POWER_SIG_LEN);
  tape[parameters::DISCRETE_POWER_SIG_LEN + 0] = 0x80;   // §5.1 fixed delimiter
  tape[parameters::DISCRETE_POWER_SIG_LEN + 1] = 0x00;
  tape[parameters::DISCRETE_POWER_SIG_LEN + 2] = 0x00;

  const std::array<uint8_t, 32>& P = discrete_power_memory_personalization();
  yespower_params_t yp{ parameters::DISCRETE_POWER_N, parameters::DISCRETE_POWER_R, P.data(), P.size() };
  yespower_binary_t y{};
  if (yespower_discrete_tls(H.data(), H.size(), &yp, tape.data(), &y) != 0) {
    return false;
  }

  BinaryArray t;
  t.reserve(sizeof(DISCRETE_POWER_FINAL_DOMAIN) - 1 + H.size() + sizeof(y.uc));
  appendBytes(t, DISCRETE_POWER_FINAL_DOMAIN, sizeof(DISCRETE_POWER_FINAL_DOMAIN) - 1);
  appendBytes(t, H.data(), H.size());
  appendBytes(t, y.uc, sizeof(y.uc));
  powHash = shake256Hash(t);
  return true;
}

}  // namespace

const std::array<uint8_t, 32>& discrete_power_memory_personalization() {
  static const std::array<uint8_t, 32> P = [] {
    std::array<uint8_t, 32> p{};
    CryptoPQ::shake256(DISCRETE_POWER_MEMORY_DOMAIN,
                       sizeof(DISCRETE_POWER_MEMORY_DOMAIN) - 1,
                       p.data(), p.size());
    return p;
  }();
  return P;
}

std::array<uint8_t, 64> discrete_power_sign_message(const std::array<uint8_t, 64>& H) {
  BinaryArray t;
  t.reserve(sizeof(DISCRETE_POWER_SIGN_DOMAIN) - 1 + H.size());
  appendBytes(t, DISCRETE_POWER_SIGN_DOMAIN, sizeof(DISCRETE_POWER_SIGN_DOMAIN) - 1);
  appendBytes(t, H.data(), H.size());
  std::array<uint8_t, 64> m{};
  CryptoPQ::shake256(t.data(), t.size(), m.data(), m.size());
  return m;
}

bool get_block_pow_header_hash(const Block& b, std::array<uint8_t, 64>& H) {
  BinaryArray blob;
  if (!get_block_hashing_blob(b, blob)) {
    return false;
  }
  H = discretePowerHeaderFromBlob(blob);
  return true;
}

bool discrete_power_prove(const BinaryArray& blob, const CryptoPQ::DsaSecretKey& sk,
               std::vector<uint8_t>& signature, Crypto::Hash& powHash) {
  std::array<uint8_t, 64> H = discretePowerHeaderFromBlob(blob);
  std::array<uint8_t, 64> m = discrete_power_sign_message(H);
  CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(sk, m.data(), m.size());
  signature.assign(sig.begin(), sig.end());
  return discretePowerMemoryAndFinal(H, sig.data(), powHash);
}

bool discrete_power_verify(const BinaryArray& blob, const CryptoPQ::DsaPublicKey& pk,
                const std::vector<uint8_t>& signature, Crypto::Hash& powHash,
                DiscretePowerReject* reason) {
  if (reason) *reason = DiscretePowerReject::None;
  // §9 step 1: exact signature length, cheaply, before touching anything else.
  if (signature.size() != parameters::DISCRETE_POWER_SIG_LEN) {
    if (reason) *reason = DiscretePowerReject::BadLength;
    return false;
  }
  // step 2: recompute H and m from the candidate template.
  std::array<uint8_t, 64> H = discretePowerHeaderFromBlob(blob);
  std::array<uint8_t, 64> m = discrete_power_sign_message(H);
  // step 3: ML-DSA-65 Verify BEFORE any yespower-discrete work — this is the DoS bound.
  CryptoPQ::DsaSignature sig{};
  std::copy(signature.begin(), signature.end(), sig.begin());
  if (!CryptoPQ::dsa_verify(pk, m.data(), m.size(), sig)) {
    if (reason) *reason = DiscretePowerReject::BadSignature;
    return false;
  }
  // steps 4-6: reconstruct the tape, run one yespower-discrete, and finalize.
  return discretePowerMemoryAndFinal(H, sig.data(), powHash);
}

bool get_parent_block_hashing_blob(const Block& b, BinaryArray& blob) {
  auto serializer = makeParentBlockSerializer(b, true, true);
  return toBinaryArray(serializer, blob);
}

// DiscretePower (https://docs.discrete.cash/#/consensus/pow): PoW hash of an ALREADY-signed
// block. Recomputes H from the hashing blob and runs the signature-tape
// yespower-discrete chain over b.signature, then finalizes. It does NOT verify the
// signature — consensus uses discrete_power_verify (verify-before-yespower); this entry is
// for self-built blocks (miner/tests/Core) and is a pure function of the block.
bool get_block_longhash(const Block& b, Crypto::Hash& res) {
  if (b.signature.size() != parameters::DISCRETE_POWER_SIG_LEN) {
    return false;
  }
  BinaryArray blob;
  if (!get_block_hashing_blob(b, blob)) {
    return false;
  }
  std::array<uint8_t, 64> H = discretePowerHeaderFromBlob(blob);
  return discretePowerMemoryAndFinal(H, b.signature.data(), res);
}

bool get_block_hash(const Block& b, Hash& res) {
  BinaryArray ba;
  if (!get_block_hashing_blob(b, ba)) {
    return false;
  }

  // The header of block version 1 differs from headers of blocks starting from v.2
  if (BLOCK_MAJOR_VERSION_2 == b.majorVersion || BLOCK_MAJOR_VERSION_3 == b.majorVersion) {
    BinaryArray parent_blob;
    auto serializer = makeParentBlockSerializer(b, true, false);
    if (!toBinaryArray(serializer, parent_blob))
      return false;

    ba.insert(ba.end(), parent_blob.begin(), parent_blob.end());
  }

  // Witness-commitment block ID: ba is the unsigned block-hashing blob C_B
  // (header + transaction-tree commitment). The ID commits to b.signature through
  // a 32-byte witness (discretePowerBlockId), so distinct valid signatures over
  // one header yield distinct IDs — closing signature/PoW malleability — and a
  // checkpoint pin transitively commits to every signature below it. Non-circular:
  // the signature signs C_B; the ID is computed afterward. The block ID is an
  // identifier only; consensus admission still verifies the signature and
  // recomputes the DiscretePower PoW, never treating an ID cache hit as a verdict.
  res = discretePowerBlockId(ba, b.signature);
  return true;
}

Hash get_block_hash(const Block& b) {
  Hash p = NULL_HASH;
  get_block_hash(b, p);
  return p;
}

bool get_aux_block_header_hash(const Block& b, Hash& res) {
  BinaryArray blob;
  if (!get_block_hashing_blob(b, blob)) {
    return false;
  }

  return getObjectHash(blob, res);
}

std::vector<uint32_t> relative_output_offsets_to_absolute(const std::vector<uint32_t>& off) {
  std::vector<uint32_t> res = off;
  for (size_t i = 1; i < res.size(); i++)
    res[i] += res[i - 1];
  return res;
}

std::vector<uint32_t> absolute_output_offsets_to_relative(const std::vector<uint32_t>& off) {
  std::vector<uint32_t> res = off;
  if (!off.size())
    return res;
  std::sort(res.begin(), res.end());//just to be sure, actually it is already should be sorted
  for (size_t i = res.size() - 1; i != 0; i--)
    res[i] -= res[i - 1];

  return res;
}

void get_tx_tree_hash(const std::vector<Hash>& tx_hashes, Hash& h) {
  tree_hash(tx_hashes.data(), tx_hashes.size(), h);
}

Hash get_tx_tree_hash(const std::vector<Hash>& tx_hashes) {
  Hash h = NULL_HASH;
  get_tx_tree_hash(tx_hashes, h);
  return h;
}

Hash get_tx_tree_hash(const Block& b) {
  std::vector<Hash> txs_ids;
  Hash h = NULL_HASH;
  getObjectHash(b.baseTransaction, h);
  txs_ids.push_back(h);
  for (auto& th : b.transactionHashes) {
    txs_ids.push_back(th);
  }
  return get_tx_tree_hash(txs_ids);
}

bool is_valid_decomposed_amount(uint64_t amount) {
  auto it = std::lower_bound(Currency::PRETTY_AMOUNTS.begin(), Currency::PRETTY_AMOUNTS.end(), amount);
  if (it == Currency::PRETTY_AMOUNTS.end() || amount != *it) {
    return false;
  }
  return true;
}

namespace {
// Wallet-layer message-signing domain. NOT a consensus constant, but signers and
// verifiers must agree on it. It is deliberately distinct from every PqDerive
// consensus domain (esp. kDomainTxSign) so a signed message digest can never
// collide with a transaction signing digest.
constexpr char kPqMessageDomain[] = "discrete-pq-message-v1";

CryptoPQ::Hash256 pqMessageDigest(const std::string& data) {
  std::vector<uint8_t> buf;
  buf.reserve((sizeof(kPqMessageDomain) - 1) + data.size());
  buf.insert(buf.end(), kPqMessageDomain, kPqMessageDomain + (sizeof(kPqMessageDomain) - 1));
  buf.insert(buf.end(), data.begin(), data.end());
  return CryptoPQ::sha3_256(buf.data(), buf.size());
}
}  // namespace

std::string signMessagePq(const std::string& data, const CryptoPQ::DsaSecretKey& spendSk) {
  CryptoPQ::Hash256 digest = pqMessageDigest(data);
  CryptoPQ::DsaSignature sig = CryptoPQ::dsa_sign(spendSk, digest.data(), digest.size());
  return Tools::Base58::encode_addr(
      CryptoNote::parameters::CRYPTONOTE_KEYS_SIGNATURE_BASE58_PREFIX,
      std::string(reinterpret_cast<const char*>(sig.data()), sig.size()));
}

bool verifyMessagePq(const std::string& data, const CryptoPQ::DsaPublicKey& spendPub,
                     const std::string& signature) {
  std::string decoded;
  uint64_t prefix = 0;
  if (!Tools::Base58::decode_addr(signature, prefix, decoded) ||
      prefix != CryptoNote::parameters::CRYPTONOTE_KEYS_SIGNATURE_BASE58_PREFIX) {
    return false;
  }
  if (decoded.size() != CryptoPQ::kDsaSignatureBytes) {
    return false;
  }
  CryptoPQ::DsaSignature sig;
  std::memcpy(sig.data(), decoded.data(), sig.size());
  CryptoPQ::Hash256 digest = pqMessageDigest(data);
  return CryptoPQ::dsa_verify(spendPub, digest.data(), digest.size(), sig);
}

void deriveMinerPqKeys(const Crypto::SecretKey& masterSeed,
                       CryptoPQ::KemPublicKey& viewPub,
                       CryptoPQ::DsaPublicKey& spendPub,
                       CryptoPQ::DsaSecretKey& spendSk) {
  // The wallet's 32-byte master seed IS the PqSeed SeedMaster (PQ-native: no HKDF
  // indirection). This must match Wallet/PqWallet.cpp derivePqWalletKeys(SeedMaster),
  // which also feeds the seed straight into the cemented PqSeed chain — so the daemon
  // mines to exactly the address the wallet owns.
  CryptoPQ::SeedMaster sm{};
  std::copy(std::begin(masterSeed.data), std::end(masterSeed.data), sm.begin());
  auto view = CryptoPQ::deriveViewKeys(sm);
  auto spend = CryptoPQ::deriveSpendKeys(sm);
  viewPub = view.first;
  spendPub = spend.first;
  spendSk = spend.second;
}


}
