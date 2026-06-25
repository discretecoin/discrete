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

#include "PqValidation.h"

#include <cstring>
#include <unordered_set>

#include "CryptoNoteConfig.h"
#include "CryptoNoteTools.h"
#include "PqTxType.h"
#include "TransactionExtra.h"
#include "../crypto/hash.h"

#include "crypto/crypto.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqDsa.h"

namespace CryptoNote {

namespace {

bool pqInputFieldsValid(const PqInput& in) {
  return in.authPub.size() == PQ_AUTH_PUB_SIZE &&
         in.rhoReveal.size() == PQ_RHO_SIZE;
}

bool pqOutputFieldsValid(const PqOutput& o) {
  return o.kemCt.size() == PQ_KEM_CIPHERTEXT_SIZE &&
         o.encPayload.size() == PQ_ENC_PAYLOAD_SIZE;
}

CryptoPQ::DsaPublicKey toDsaPub(const std::vector<uint8_t>& v) {
  CryptoPQ::DsaPublicKey k;
  std::memcpy(k.data(), v.data(), k.size());
  return k;
}

CryptoPQ::Rho toRho(const std::vector<uint8_t>& v) {
  CryptoPQ::Rho r;
  std::memcpy(r.data(), v.data(), r.size());
  return r;
}

Crypto::Hash toHash(const CryptoPQ::Hash256& h) {
  Crypto::Hash out;
  std::memcpy(out.data, h.data(), 32);
  return out;
}

bool fail(std::string* error, const char* msg) {
  if (error) *error = msg;
  return false;
}

}  // namespace

CryptoPQ::Hash256 pqSigningDigest(const Transaction& tx, uint64_t fee) {
  CryptoPQ::UnsignedTx u;
  u.version = tx.version;
  u.txType = tx.txType;
  u.unlockHeight = tx.unlockHeight;
  u.extra = tx.extra;
  u.fee = fee;
  for (const auto& in : tx.inputs) {
    const PqInput& pin = boost::get<PqInput>(in);
    CryptoPQ::DigestInput di;
    std::memcpy(di.prevTxid.data(), pin.prevTxid.data, 32);
    di.prevOutIndex = pin.prevOutIndex;
    di.authPub = toDsaPub(pin.authPub);
    di.rhoReveal = toRho(pin.rhoReveal);
    u.inputs.push_back(di);
  }
  for (const auto& out : tx.outputs) {
    const PqOutput& po = boost::get<PqOutput>(out.target);
    CryptoPQ::DigestOutput dou;
    dou.type = 0x10;  // PQ output variant tag
    dou.amount = out.amount;
    dou.unlockHeight = out.unlockHeight;
    std::memcpy(dou.kemCt.data(), po.kemCt.data(), dou.kemCt.size());
    std::memcpy(dou.encPayload.data(), po.encPayload.data(), dou.encPayload.size());
    std::memcpy(dou.spendCommit.data(), po.spendCommit.data, 32);
    u.outputs.push_back(dou);
  }
  return CryptoPQ::txSigningDigest(u);
}

Crypto::Hash pqNullifier(const PqInput& in) {
  if (!pqInputFieldsValid(in)) {
    return Crypto::Hash{};
  }
  CryptoPQ::Hash256 prevTxid;
  std::memcpy(prevTxid.data(), in.prevTxid.data, 32);
  return toHash(CryptoPQ::nullifier(toDsaPub(in.authPub), toRho(in.rhoReveal),
                                    prevTxid, in.prevOutIndex));
}

Crypto::KeyImage pqInputNullifierAsKeyImage(const PqInput& in) {
  Crypto::Hash nf = pqNullifier(in);
  Crypto::KeyImage ki;
  std::memcpy(&ki, &nf, sizeof(ki));
  return ki;
}

bool checkPqTransactionSemantic(const Transaction& tx, std::string* error) {
  if (tx.txType != TX_PQ) {
    return fail(error, "not a TX_PQ subtype");
  }
  if (tx.inputs.empty() || tx.outputs.empty()) {
    return fail(error, "TX_PQ with empty inputs or outputs");
  }
  if (tx.inputs.size() > parameters::MAX_PQ_INPUTS_PER_TX) {
    return fail(error, "too many PQ inputs");
  }
  if (tx.outputs.size() > parameters::MAX_PQ_OUTPUTS_PER_TX) {
    return fail(error, "too many PQ outputs");
  }
  if (tx.unlockHeight != 0) {
    return fail(error, "PQ tx must have unlockHeight == 0");
  }
  for (const auto& in : tx.inputs) {
    if (in.type() != typeid(PqInput)) {
      return fail(error, "TX_PQ input is not a PqInput");
    }
    if (!pqInputFieldsValid(boost::get<PqInput>(in))) {
      return fail(error, "PqInput field has wrong length");
    }
  }
  if (tx.pqSignatures.size() != tx.inputs.size()) {
    return fail(error, "pqSignatures count must equal input count");
  }
  for (const auto& out : tx.outputs) {
    if (out.target.type() != typeid(PqOutput)) {
      return fail(error, "TX_PQ output is not a PqOutput");
    }
    if (out.amount == 0) {
      return fail(error, "PQ output with zero amount");
    }
    if (!pqOutputFieldsValid(boost::get<PqOutput>(out.target))) {
      return fail(error, "PqOutput field has wrong length");
    }
  }

  if (toBinaryArray(tx).size() > parameters::MAX_PQ_TX_SIZE) {
    return fail(error, "PQ tx exceeds MAX_PQ_TX_SIZE");
  }
  return true;
}

bool checkFreeRegPow(const std::array<uint8_t, 1184>& viewPub,
                     const Crypto::Hash& refBlockHash, uint64_t nonce,
                     uint64_t target) {
  // PoW preimage: viewPub(1184) || refBlockHash(32) || LE64(nonce).
  std::vector<uint8_t> buf;
  buf.reserve(1184 + 32 + 8);
  buf.insert(buf.end(), viewPub.begin(), viewPub.end());
  buf.insert(buf.end(), refBlockHash.data, refBlockHash.data + 32);
  for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>((nonce >> (8 * i)) & 0xFF));

  Crypto::cn_context ctx;
  Crypto::Hash h;
  Crypto::cn_slow_hash(ctx, buf.data(), buf.size(), h);

  // Target semantics: leading 8 bytes (big-endian) <= target.
  uint64_t lead = 0;
  for (int i = 0; i < 8; ++i) lead = (lead << 8) | static_cast<uint8_t>(h.data[i]);
  return lead <= target;
}

uint64_t grindFreeRegPow(const std::array<uint8_t, 1184>& viewPub,
                         const Crypto::Hash& refBlockHash, uint64_t powTarget) {
  uint64_t nonce = 0;
  while (!checkFreeRegPow(viewPub, refBlockHash, nonce, powTarget)) {
    ++nonce;
  }
  return nonce;
}

bool checkFreeRegTransactionSemantic(const Transaction& tx, std::string* error, uint64_t powTarget) {
  if (tx.txType != TX_FREE_REG) {
    return fail(error, "not a TX_FREE_REG subtype");
  }
  if (!tx.inputs.empty() || !tx.outputs.empty()) {
    return fail(error, "TX_FREE_REG must have no inputs or outputs");
  }
  if (!tx.pqSignatures.empty()) {
    return fail(error, "TX_FREE_REG must not carry pqSignatures");
  }
  if (tx.unlockHeight != 0) {
    return fail(error, "TX_FREE_REG must have unlockHeight == 0");
  }

  // tx_extra must contain EXACTLY one PQ registration tag + one PoW tag, nothing else.
  std::vector<TransactionExtraField> fields;
  if (!parseTransactionExtra(tx.extra, fields)) {
    return fail(error, "TX_FREE_REG: malformed tx_extra");
  }
  int regCount = 0, powCount = 0;
  for (const auto& f : fields) {
    if (f.type() == typeid(TransactionExtraPqAccountRegistration)) ++regCount;
    else if (f.type() == typeid(TransactionExtraPow)) ++powCount;
    else return fail(error, "TX_FREE_REG: unexpected tx_extra field");
  }
  if (regCount != 1 || powCount != 1) {
    return fail(error, "TX_FREE_REG must have exactly one registration and one PoW tag");
  }
  // PoW tag must be the last field (so the nonce is the final 8 bytes).
  if (!isPowTagLastField(tx.extra)) {
    return fail(error, "TX_FREE_REG: PoW tag is not the final tx_extra field");
  }

  TransactionExtraPqAccountRegistration reg;
  TransactionExtraPow pow;
  getPqAccountRegistrationFromExtra(tx.extra, reg);
  getPowTagFromExtra(tx.extra, pow);

  if (!checkFreeRegPow(reg.viewPub, pow.refBlockHash, pow.nonce, powTarget)) {
    return fail(error, "TX_FREE_REG: anti-spam PoW not satisfied");
  }
  return true;
}

bool checkPqTransactionInputs(const Transaction& tx,
                             const std::vector<PqResolvedInput>& resolved,
                             uint64_t minFeePer4000Bytes,
                             std::vector<Crypto::Hash>* outNullifiers,
                             std::string* error) {
  if (resolved.size() != tx.inputs.size()) {
    return fail(error, "resolved inputs size mismatch");
  }

  std::unordered_set<Crypto::Hash> nullifiers;
  std::vector<Crypto::Hash> computed;
  computed.reserve(tx.inputs.size());

  uint64_t sumIn = 0;
  for (size_t i = 0; i < tx.inputs.size(); ++i) {
    if (tx.inputs[i].type() != typeid(PqInput)) {
      return fail(error, "TX_PQ input is not a PqInput");
    }
    const PqInput& in = boost::get<PqInput>(tx.inputs[i]);
    if (!pqInputFieldsValid(in)) {
      return fail(error, "PqInput field has wrong length");
    }

    const PqResolvedInput& r = resolved[i];
    if (!r.exists) {
      return fail(error, "referenced output does not exist");
    }
    if (!r.isPqOutput) {
      return fail(error, "referenced output is not a PqOutput");
    }
    // NOTE: coinbase PqOutputs ARE spendable in Discrete (they are the sole
    // funds source — there is no legacy chain). Coinbase maturity
    // (minedMoneyUnlockWindow) is height-dependent, so it is enforced in the
    // chain-context layer (Blockchain::checkPqInputs via is_tx_spendheight_unlocked),
    // not here in the context-free shape/balance check.

    // Ownership / authorization binding.
    Crypto::Hash sc = toHash(CryptoPQ::spendCommit(toDsaPub(in.authPub), toRho(in.rhoReveal)));
    if (sc != r.spendCommit) {
      return fail(error, "spend_commit mismatch");
    }

    // Intra-tx nullifier uniqueness.
    Crypto::Hash nf = pqNullifier(in);
    if (!nullifiers.insert(nf).second) {
      return fail(error, "duplicate nullifier within transaction");
    }
    computed.push_back(nf);

    // Overflow-safe input sum.
    if (sumIn + r.amount < sumIn) {
      return fail(error, "input amount overflow");
    }
    sumIn += r.amount;
  }

  uint64_t sumOut = 0;
  for (const auto& out : tx.outputs) {
    if (sumOut + out.amount < sumOut) {
      return fail(error, "output amount overflow");
    }
    sumOut += out.amount;
  }

  if (sumIn < sumOut) {
    return fail(error, "outputs exceed inputs");
  }
  uint64_t fee = sumIn - sumOut;

  // Fee floor: fee >= ceil(minFeePer4000Bytes * size / 4000).
  uint64_t size = toBinaryArray(tx).size();
  if (minFeePer4000Bytes != 0 && size != 0) {
    if (size > (UINT64_MAX - 3999) / minFeePer4000Bytes) {
      return fail(error, "fee floor overflow");  // implausibly large tx
    }
    uint64_t floor = (minFeePer4000Bytes * size + 3999) / 4000;
    if (fee < floor) {
      return fail(error, "fee below minimum");
    }
  }

  // ML-DSA signature verification over the recomputed digest.
  CryptoPQ::Hash256 digest = pqSigningDigest(tx, fee);
  for (size_t i = 0; i < tx.inputs.size(); ++i) {
    const PqInput& in = boost::get<PqInput>(tx.inputs[i]);
    CryptoPQ::DsaPublicKey pub = toDsaPub(in.authPub);
    CryptoPQ::DsaSignature sig;
    std::memcpy(sig.data(), tx.pqSignatures[i].data(), sig.size());
    if (!CryptoPQ::dsa_verify(pub, digest.data(), digest.size(), sig)) {
      return fail(error, "ML-DSA signature verification failed");
    }
  }

  if (outNullifiers) {
    *outNullifiers = std::move(computed);
  }
  return true;
}

}  // namespace CryptoNote
