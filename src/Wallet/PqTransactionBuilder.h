// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Discrete is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Discrete is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Discrete.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <vector>

#include "CryptoNote.h"
#include "ITransaction.h"
#include "CryptoNoteCore/Account.h"
#include "crypto_pq/PqKem.h"
#include "crypto_pq/PqDsa.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqHash.h"
#include "crypto_pq/PqPaymentProof.h"
#include "crypto/crypto-util.h"

// High-level builders for the PQ transaction family (spec §6/§8, ownership fix
// in https://docs.discrete.cash/#/reference/pq-ownership-model). These assemble a fully-signed CryptoNote::
// Transaction the node will accept; tests previously hand-rolled this.
//
// This header covers TX_PQ (PQ inputs -> PQ outputs), which is node-independent,
// and TX_FREE_REG (account-number registration).

#include "CryptoNoteCore/PqValidation.h"  // PqSigningContext

namespace CryptoNote {

// Sentinel depositIndex meaning "the wallet's own primary address" (not a deposit
// subaddress). Defined here, next to PqSpendInput, so the spend path and the ledger
// share one definition.
constexpr uint32_t PQ_PRIMARY_DEPOSIT = 0xFFFFFFFFu;

// Sentinel depositIndex meaning "ours, but we cannot say which deposit". Used
// when an incoming output carries a routing index outside the range the wallet
// can account for; the funds are still recognised, owned and spendable, only the
// deposit attribution is withheld.
constexpr uint32_t PQ_UNATTRIBUTED_DEPOSIT = 0xFFFFFFFEu;

// The largest routing index a wallet can attribute to a deposit bucket. T is
// 64 bits on the wire and the ledger buckets are 32, and the top two 32-bit
// values are the sentinels above, so the usable range stops below them.
constexpr uint64_t PQ_MAX_DEPOSIT_ROUTE = 0xFFFFFFFDull;

// Map a wire routing index T onto a ledger deposit bucket.
//
// T is 64 bits on the wire and the buckets are 32, and the sender chooses T, so
// the value is range-checked rather than cast: anything outside the attributable
// range is classified as unattributed instead of folding onto a bucket or onto a
// sentinel.
inline uint32_t pqDepositIndexForRoute(uint64_t subaddrIndexT) {
  if (subaddrIndexT == 0) {
    return PQ_PRIMARY_DEPOSIT;  // T = 0 IS the primary address
  }
  if (subaddrIndexT > PQ_MAX_DEPOSIT_ROUTE) {
    return PQ_UNATTRIBUTED_DEPOSIT;
  }
  return static_cast<uint32_t>(subaddrIndexT);
}

// A PQ output this wallet owns and is spending. `rho` comes from the scan record
// (CryptoPQ::PqOwnedOutput.rho). The spend is authorized by the ML-DSA spend secret
// that matches the output's spend_commit: the wallet's primary key for primary
// outputs and (under AggregatedMultikey) the per-deposit key for deposit outputs.
// `depositIndex` records which bucket the output belongs to so the spend path can
// pick the right key; PQ_PRIMARY_DEPOSIT = primary.
struct PqSpendInput {
  Crypto::Hash  prevTxid{};
  uint32_t      prevOutIndex = 0;
  uint64_t      amount = 0;
  CryptoPQ::Rho rho{};
  uint32_t      depositIndex = PQ_PRIMARY_DEPOSIT;
};

// Per-input spend authority: the ML-DSA (pub, secret) that authorizes one input.
// authPub must equal the spend key the referenced output committed to.
struct PqInputAuth {
  CryptoPQ::DsaPublicKey spendPub{};
  CryptoPQ::DsaSecretKey spendSk{};

  // Sender code necessarily copies per-input signing authority. Scrub every
  // copy when its container or temporary is destroyed so a completed one-shot
  // hardware authorization does not leave ML-DSA secret keys in freed memory.
  ~PqInputAuth() { sodium_memzero(spendSk.data(), spendSk.size()); }
};

// A recipient of one new PQ output (public address material only).
struct PqSendOutput {
  CryptoPQ::KemPublicKey recipientViewPub{};
  CryptoPQ::DsaPublicKey recipientSpendPub{};
  uint64_t               amount = 0;
  uint64_t               subaddrIndexT = 0;  // deposit routing index; 0 for standard addresses
  uint64_t               unlockHeight = 0;   // per-output spend lock; 0 = none (e.g. change)
};

// A signed transaction and each output's independently generated rho opening.
// The openings support a public spend-authority proof without exposing ML-KEM
// internals or changing the wire transaction.
struct PqTransactionBuildResult {
  Transaction tx;
  std::vector<CryptoPQ::Rho> outputRhos;

  PqTransactionBuildResult() = default;
  ~PqTransactionBuildResult();
  PqTransactionBuildResult(const PqTransactionBuildResult&) = delete;
  PqTransactionBuildResult& operator=(const PqTransactionBuildResult&) = delete;
  PqTransactionBuildResult(PqTransactionBuildResult&& other) noexcept;
  PqTransactionBuildResult& operator=(PqTransactionBuildResult&& other) noexcept;

  void clearWitnesses() noexcept;
};

// The PQ "inputs hash" a wallet binds into every output's out_context. This is a
// WALLET-SIDE convention (consensus never recomputes out_context); sender and
// receiver MUST agree on it or outputs become undetectable, so it is part of the
// recovery contract — cemented, like the seed_master derivation.
//   * TX_PQ inputs (PqInput): SHA3 over (prevTxid || LE32(prevOutIndex)) — the
//     outpoint is on the wire.
// Reuses the cemented CryptoPQ::inputsHash function/domain.
// Takes a TransactionPrefix (Transaction derives from it) because the wallet's
// scanner only has the prefix available (ITransactionReader::getTransactionData).
CryptoPQ::Hash256 pqTransactionInputsHash(const TransactionPrefix& tx);

// Build and sign a TX_PQ.
//
//   spendPub / spendSk : the spender's long-term ML-DSA keypair (derivePqWalletKeys).
//   fee = sum(input amounts) - sum(output amounts), computed implicitly; the
//   caller sizes outputs to leave the intended fee. Throws std::runtime_error on
//   empty/oversized input or output sets or if outputs exceed inputs.
//
// Every input is authorized by an ML-DSA signature over the canonical signing
// digest (pqSigningDigest). `spendSk` is used only here and should be derived on
// demand and discarded by the caller after the call returns.
// `unlockHeight` is the legacy tx-level field. TX_PQ consensus requires it to be
// zero; use PqSendOutput::unlockHeight for per-output spend locks.
// `extra` (default empty) is placed verbatim in tx.extra before the signing digest
// is computed, so it is authorized along with the rest of the transaction. It is
// used to carry a PQ account registration (a paid registration is a fee-paying
// TX_PQ whose extra holds the registration tag).
Transaction buildPqTransaction(const std::vector<PqSpendInput>& inputs,
                               const std::vector<PqSendOutput>& outputs,
                               const CryptoPQ::DsaPublicKey& spendPub,
                               const CryptoPQ::DsaSecretKey& spendSk,
                               uint64_t unlockHeight = 0,
                               const std::vector<uint8_t>& extra = {},
                               const PqSigningContext& signing = PqSigningContext());

PqTransactionBuildResult buildPqTransactionWithProof(
    const std::vector<PqSpendInput>& inputs,
    const std::vector<PqSendOutput>& outputs,
    const CryptoPQ::DsaPublicKey& spendPub,
    const CryptoPQ::DsaSecretKey& spendSk,
    uint64_t unlockHeight = 0,
    const std::vector<uint8_t>& extra = {});

// Per-input spend authority: inputAuth[i] authorizes inputs[i]. This is what lets a
// single TX_PQ spend outputs owned by DIFFERENT spend keys — e.g. AggregatedMultikey
// deposit outputs, each committing to its own per-deposit key. inputAuth.size() must
// equal inputs.size(). (The single-key overload above is this with one key repeated.)
// `signing` selects the transcript the inputs are signed under. The default is
// version 1, which is what consensus requires until
// parameters::PQ_TRANSCRIPT_V2_HEIGHT activates; a builder aimed at a height past
// activation passes the version-2 context so each signature binds the chain
// identity and its own input index. Signing and verification read the same
// PqSigningContext, so the two can never drift.
Transaction buildPqTransaction(const std::vector<PqSpendInput>& inputs,
                               const std::vector<PqSendOutput>& outputs,
                               const std::vector<PqInputAuth>& inputAuth,
                               uint64_t unlockHeight = 0,
                               const std::vector<uint8_t>& extra = {},
                               const PqSigningContext& signing = PqSigningContext());

PqTransactionBuildResult buildPqTransactionWithProof(
    const std::vector<PqSpendInput>& inputs,
    const std::vector<PqSendOutput>& outputs,
    const std::vector<PqInputAuth>& inputAuth,
    uint64_t unlockHeight = 0,
    const std::vector<uint8_t>& extra = {},
    const PqSigningContext& signing = PqSigningContext());

// Translate a final signed wire transaction into the pure payment-proof view,
// including its canonical txid and inputs hash. Throws if any output is not a
// well-sized PqOutput.
PqPaymentProofTransaction makePqPaymentProofTransaction(const Transaction& tx);

// Assemble a TX_FREE_REG (zero-fee account-number registration) given a PoW
// solution: an empty-input/output v2 tx whose tx_extra is exactly the PQ
// account-registration tag (viewPub + spendPub) followed by the anti-spam PoW tag (which
// must be last). The caller finds `nonce` such that checkFreeRegPow(viewPub,
// spendPub, refBlockHash, nonce) holds (see PqValidation.h). No signing — the PoW is the
// only authorization.
Transaction buildFreeRegTransaction(const CryptoPQ::KemPublicKey& viewPub,
                                    const CryptoPQ::DsaPublicKey& spendPub,
                                    const Crypto::Hash& refBlockHash,
                                    uint64_t nonce);

}  // namespace CryptoNote
