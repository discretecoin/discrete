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
  std::vector<uint8_t> encPayload;   // 56   — ChaCha20-Poly1305(rho||LE64(T))
  Hash256              spendCommit;  // 32

  // Sender hint: lets the sender later spend its own change output without a
  // rescan. Not serialized.
  Hash256 outContext;
  Rho     rho;
};

// Proof-capable construction owns the output and the exact ML-KEM message that
// produced its ciphertext. Keeping them together prevents callers from pairing
// a witness with a different output after a rebuild.
struct PqBuiltOutputWithProof {
  PqBuiltOutput output;
  KemEncapsMessage message{};

  PqBuiltOutputWithProof() = default;
  ~PqBuiltOutputWithProof();
  PqBuiltOutputWithProof(const PqBuiltOutputWithProof&) = delete;
  PqBuiltOutputWithProof& operator=(const PqBuiltOutputWithProof&) = delete;
  PqBuiltOutputWithProof(PqBuiltOutputWithProof&& other) noexcept;
  PqBuiltOutputWithProof& operator=(PqBuiltOutputWithProof&& other) noexcept;
};

// Deterministic core: caller supplies the KEM result (kemCt, ss) and rho. Used
// for tests/KAT and for callers that manage their own RNG.
PqBuiltOutput buildPqOutput(const KemCiphertext& kemCt,
                            const KemShared& ss,
                            const DsaPublicKey& recipientSpendPub,
                            const Hash256& inputsHash,
                            uint32_t outputIndex,
                            uint64_t amount,
                            const Rho& rho,
                            uint64_t subaddrIndexT = 0);

// Compatibility path for callers that do not retain payment proofs. It uses
// the proof-capable explicit-message builder and securely discards the witness.
PqBuiltOutput buildPqOutput(const KemPublicKey& recipientViewPub,
                            const DsaPublicKey& recipientSpendPub,
                            const Hash256& inputsHash,
                            uint32_t outputIndex,
                            uint64_t amount,
                            uint64_t subaddrIndexT = 0);

// Normal proof-capable sender entry point. Draws fresh independent m and rho,
// uses only reentrant explicit-message ML-KEM, re-encapsulates for consistency,
// and runs the receiver's complete shared-secret scan predicate before return.
PqBuiltOutputWithProof buildPqOutputWithProof(
    const KemPublicKey& recipientViewPub,
    const DsaPublicKey& recipientSpendPub,
    const Hash256& inputsHash,
    uint32_t outputIndex,
    uint64_t amount,
    uint64_t subaddrIndexT = 0);

}  // namespace CryptoPQ
