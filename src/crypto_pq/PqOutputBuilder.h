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

#include <cstdint>
#include <vector>

#include "PqHash.h"
#include "PqKem.h"
#include "PqDsa.h"
#include "PqDerive.h"

// Sender-side construction of one PQ output (spec §6, amended by the
// ownership-model fix in docs/PQ-OWNERSHIP-FIX.md).
//
// The output binds the RECIPIENT'S long-term ML-DSA spend public key (from
// their address) via spend_commit = SHA3(spend_pub || rho). The sender can
// build the output from public address material but cannot spend it.
//
// The result fields map 1:1 onto CryptoNote::PqOutput; the wallet-side
// TransactionBuilder (later session) copies them into the wire type. We keep
// this builder in the crypto layer so it has no dependency on the transaction
// wire types.

namespace CryptoPQ {

struct PqBuiltOutput {
  // Wire fields (-> CryptoNote::PqOutput).
  KemCiphertext        kemCt;        // 1088 — ML-KEM ciphertext
  std::vector<uint8_t> encPayload;   // 48   — ChaCha20-Poly1305(rho)
  Hash256              spendCommit;  // 32

  // Sender hint: lets the sender later spend its own change output without a
  // rescan. Not serialized.
  Hash256 outContext;
  Rho     rho;
};

// Deterministic core: caller supplies the KEM result (kemCt, ss) and rho. Used
// for tests/KAT and for callers that manage their own RNG.
PqBuiltOutput buildPqOutput(const KemCiphertext& kemCt,
                            const KemShared& ss,
                            const DsaPublicKey& recipientSpendPub,
                            const Hash256& inputsHash,
                            uint32_t outputIndex,
                            uint64_t amount,
                            const Rho& rho);

// Full path: encapsulates to the recipient's view key and draws rho from the
// secure CSPRNG. This is the normal sender entry point.
PqBuiltOutput buildPqOutput(const KemPublicKey& recipientViewPub,
                            const DsaPublicKey& recipientSpendPub,
                            const Hash256& inputsHash,
                            uint32_t outputIndex,
                            uint64_t amount);

}  // namespace CryptoPQ
