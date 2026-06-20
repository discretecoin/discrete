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

#pragma once

#include <vector>

#include "CryptoNote.h"
#include "ITransaction.h"
#include "CryptoNoteCore/Account.h"
#include "crypto_pq/PqKem.h"
#include "crypto_pq/PqDsa.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqHash.h"

// High-level builders for the PQ transaction family (spec §6/§8, ownership fix
// in docs/PQ-OWNERSHIP-FIX.md). These assemble a fully-signed CryptoNote::
// Transaction the node will accept; tests previously hand-rolled this.
//
// This header covers TX_PQ (PQ inputs -> PQ outputs), which is node-independent
// (no ring/mixin resolution), and TX_FREE_REG (account-number registration).

namespace CryptoNote {

// A PQ output this wallet owns and is spending. `rho` comes from the scan record
// (CryptoPQ::PqOwnedOutput.rho); the wallet authorizes the spend with its
// long-term ML-DSA spend secret, not with anything derived per-output.
struct PqSpendInput {
  Crypto::Hash  prevTxid{};
  uint32_t      prevOutIndex = 0;
  uint64_t      amount = 0;
  CryptoPQ::Rho rho{};
};

// A recipient of one new PQ output (public address material only).
struct PqSendOutput {
  CryptoPQ::KemPublicKey recipientViewPub{};
  CryptoPQ::DsaPublicKey recipientSpendPub{};
  uint64_t               amount = 0;
  uint64_t               subaddrIndexT = 0;  // deposit routing index; 0 for standard addresses
  uint64_t               unlockHeight = 0;   // per-output spend lock; 0 = none (e.g. change)
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
// `extra` (default empty) is placed verbatim in tx.extra before the signing digest
// is computed, so it is authorized along with the rest of the transaction. It is
// used to carry a PQ account registration (a paid registration is a fee-paying
// TX_PQ whose extra holds the registration tag).
Transaction buildPqTransaction(const std::vector<PqSpendInput>& inputs,
                               const std::vector<PqSendOutput>& outputs,
                               const CryptoPQ::DsaPublicKey& spendPub,
                               const CryptoPQ::DsaSecretKey& spendSk,
                               uint64_t unlockHeight = 0,
                               const std::vector<uint8_t>& extra = {});

// Assemble a TX_FREE_REG (zero-fee account-number registration) given a PoW
// solution: an empty-input/output v2 tx whose tx_extra is exactly the PQ
// account-registration tag (viewPub) followed by the anti-spam PoW tag (which
// must be last). The caller finds `nonce` such that checkFreeRegPow(viewPub,
// refBlockHash, nonce) holds (see PqValidation.h). No signing — the PoW is the
// only authorization.
Transaction buildFreeRegTransaction(const CryptoPQ::KemPublicKey& viewPub,
                                    const CryptoPQ::DsaPublicKey& spendPub,
                                    const Crypto::Hash& refBlockHash,
                                    uint64_t nonce);

}  // namespace CryptoNote
