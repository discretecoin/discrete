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

#include "PqTransactionBuilder.h"

#include <cstring>
#include <stdexcept>

#include "CryptoNoteConfig.h"
#include "PqTxType.h"
#include "crypto/crypto.h"
#include "CryptoNoteCore/PqValidation.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "crypto_pq/PqOutputBuilder.h"

namespace CryptoNote {

CryptoPQ::Hash256 pqTransactionInputsHash(const TransactionPrefix& tx) {
  std::vector<CryptoPQ::InputRef> refs;
  refs.reserve(tx.inputs.size());
  for (const auto& input : tx.inputs) {
    if (input.type() == typeid(PqInput)) {
      const PqInput& in = boost::get<PqInput>(input);
      CryptoPQ::InputRef ref{};
      std::memcpy(ref.prevTxid.data(), in.prevTxid.data, 32);
      ref.prevOutIndex = in.prevOutIndex;
      refs.push_back(ref);
    } else if (input.type() == typeid(BaseInput)) {
      // Coinbase: no prior outpoints — inputsHash is zeros, matching constructMinerTxPq.
    } else {
      throw std::runtime_error("pqTransactionInputsHash: unsupported input type");
    }
  }
  if (refs.empty()) {
    return CryptoPQ::Hash256{};  // coinbase convention: zeros
  }
  return CryptoPQ::inputsHash(refs);
}

Transaction buildPqTransaction(const std::vector<PqSpendInput>& inputs,
                               const std::vector<PqSendOutput>& outputs,
                               const std::vector<PqInputAuth>& inputAuth,
                               uint64_t unlockHeight,
                               const std::vector<uint8_t>& extra) {
  if (inputs.empty()) {
    throw std::runtime_error("buildPqTransaction: no inputs");
  }
  if (outputs.empty()) {
    throw std::runtime_error("buildPqTransaction: no outputs");
  }
  if (unlockHeight != 0) {
    throw std::runtime_error("buildPqTransaction: tx-level unlockHeight is not supported for TX_PQ");
  }
  if (inputAuth.size() != inputs.size()) {
    throw std::runtime_error("buildPqTransaction: input auth count mismatch");
  }
  if (inputs.size() > parameters::MAX_PQ_INPUTS_PER_TX) {
    throw std::runtime_error("buildPqTransaction: too many inputs");
  }
  if (outputs.size() > parameters::MAX_PQ_OUTPUTS_PER_TX) {
    throw std::runtime_error("buildPqTransaction: too many outputs");
  }

  Transaction tx;
  tx.version = TRANSACTION_VERSION_1;
  tx.txType = TX_PQ;
  tx.unlockHeight = unlockHeight;
  tx.extra = extra;  // authorized below (set before the signing digest)

  // Inputs (unsigned for now): reveal the spend pubkey that authorizes THIS input and
  // the per-output rho. spend_commit(inputAuth[i].spendPub, rho) must match the
  // referenced output's commitment — true because this wallet owns the output and
  // supplies the key its bucket committed to (primary, or a per-deposit key).
  tx.inputs.reserve(inputs.size());
  uint64_t sumIn = 0;
  for (size_t i = 0; i < inputs.size(); ++i) {
    const PqSpendInput& si = inputs[i];
    PqInput in;
    in.prevTxid = si.prevTxid;
    in.prevOutIndex = si.prevOutIndex;
    in.authPub.assign(inputAuth[i].spendPub.begin(), inputAuth[i].spendPub.end());
    in.rhoReveal.assign(si.rho.begin(), si.rho.end());
    tx.inputs.push_back(std::move(in));
    if (sumIn + si.amount < sumIn) {
      throw std::runtime_error("buildPqTransaction: input amount overflow");
    }
    sumIn += si.amount;
  }

  // inputsHash binds the canonical input order; the same value seeds every
  // output's out_context (the receiver recomputes it identically).
  CryptoPQ::Hash256 ih = pqTransactionInputsHash(tx);

  // Outputs: out_context uses the output's index within tx.outputs (the same
  // index the receiver scans by), so build in order.
  tx.outputs.reserve(outputs.size());
  uint64_t sumOut = 0;
  for (size_t i = 0; i < outputs.size(); ++i) {
    const PqSendOutput& so = outputs[i];
    CryptoPQ::PqBuiltOutput built = CryptoPQ::buildPqOutput(
        so.recipientViewPub, so.recipientSpendPub, ih,
        static_cast<uint32_t>(i), so.amount, so.subaddrIndexT);

    PqOutput po;
    po.kemCt.assign(built.kemCt.begin(), built.kemCt.end());
    po.encPayload = built.encPayload;
    std::memcpy(po.spendCommit.data, built.spendCommit.data(), 32);

    TransactionOutput out;
    out.amount = so.amount;
    out.unlockHeight = so.unlockHeight;  // per-output spend lock (0 for change)
    out.target = std::move(po);
    tx.outputs.push_back(std::move(out));

    if (sumOut + so.amount < sumOut) {
      throw std::runtime_error("buildPqTransaction: output amount overflow");
    }
    sumOut += so.amount;
  }

  if (sumIn < sumOut) {
    throw std::runtime_error("buildPqTransaction: outputs exceed inputs");
  }
  const uint64_t fee = sumIn - sumOut;

  // Sign every input over the canonical digest with ITS authorizing secret key; sigs
  // go to Transaction.pqSignatures. Consensus verifies sig[i] against in[i].authPub.
  CryptoPQ::Hash256 digest = pqSigningDigest(tx, fee);
  tx.pqSignatures.resize(tx.inputs.size());
  for (size_t i = 0; i < tx.inputs.size(); ++i)
    tx.pqSignatures[i] = CryptoPQ::dsa_sign(inputAuth[i].spendSk, digest.data(), digest.size());

  return tx;
}

// Single-key convenience overload: authorize every input with one keypair (used by
// SingleKeyIndex wallets and by tests). Equivalent to the per-input form with the key
// repeated.
Transaction buildPqTransaction(const std::vector<PqSpendInput>& inputs,
                               const std::vector<PqSendOutput>& outputs,
                               const CryptoPQ::DsaPublicKey& spendPub,
                               const CryptoPQ::DsaSecretKey& spendSk,
                               uint64_t unlockHeight,
                               const std::vector<uint8_t>& extra) {
  std::vector<PqInputAuth> auth(inputs.size());
  for (auto& a : auth) {
    a.spendPub = spendPub;
    a.spendSk = spendSk;
  }
  return buildPqTransaction(inputs, outputs, auth, unlockHeight, extra);
}

Transaction buildFreeRegTransaction(const CryptoPQ::KemPublicKey& viewPub,
                                    const CryptoPQ::DsaPublicKey& spendPub,
                                    const Crypto::Hash& refBlockHash,
                                    uint64_t nonce) {
  Transaction tx;
  tx.version = TRANSACTION_VERSION_1;
  tx.txType = TX_FREE_REG;
  tx.unlockHeight = 0;
  tx.extra.clear();
  // tx_extra = PQ account-registration tag (view + spend pubkeys), then the PoW
  // tag LAST (so its nonce occupies the final 8 bytes — required by consensus and
  // by nonce grinding).
  addPqAccountRegistrationToExtra(tx.extra, viewPub, spendPub);
  TransactionExtraPow pow;
  pow.refBlockHash = refBlockHash;
  pow.nonce = nonce;
  appendPowTagToExtra(tx.extra, pow);
  return tx;
}

}  // namespace CryptoNote
