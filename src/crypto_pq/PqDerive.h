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

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "PqHash.h"
#include "PqKem.h"
#include "PqDsa.h"

// Domain-separated protocol derivations for the Karbo PQ transaction family
// (transaction version 4, block major v7). See PQ Phase 1 spec §6 / §8.
//
// Every derivation here is consensus-critical: a byte-order or domain-string
// mismatch between independent implementations is a chain split (spec §14).
// The accompanying KAT vectors (tests/pq/kat_vectors.json) pin one fixed
// input -> output triple per derivation; they MUST be published before any
// consensus code that depends on these functions is merged.
//
// Wire-format domain strings keep their literal `-v1` suffix: they are
// normative cross-implementation protocol constants, NOT C++ versioning.

namespace CryptoPQ {

// --- Domain-separation tags (spec §6 / §8) -------------------------------
// Bytes hashed are the string contents WITHOUT a trailing NUL.
constexpr char kDomainInputsHash[]  = "karbo-pq-inputs-hash-v1";
constexpr char kDomainOutContext[]  = "karbo-pq-out-context-v1";
constexpr char kDomainAeadKey[]     = "karbo-pq-aead-key-v1";
constexpr char kDomainSpendCommit[] = "karbo-pq-spend-commit-v1";
constexpr char kDomainNullifier[]   = "karbo-pq-nullifier-v1";
constexpr char kDomainTxSign[]      = "karbo-pq-tx-sign-v1";

// RESERVED for Phase 2 (KDSK-CT) — MUST NOT be used by any v4-plain code.
// A unit test asserts none of the tags above collides with this string.
constexpr char kReservedCtMask[]    = "karbo-pq-ct-mask-v1";

using Rho = std::array<uint8_t, 32>;

// NOTE (ownership-model fix, docs/PQ-OWNERSHIP-FIX.md): the "spend public key"
// bound by spendCommit / nullifier / revealed as authPub is the recipient's
// LONG-TERM ML-DSA-65 spend key (from the address), NOT a per-output key derived
// from the KEM shared secret. The draft's per-output spend_seed derivation was
// removed because the sender (who knows ss) could reconstruct it and spend.

// One referenced UTXO, in the transaction's canonical input order.
struct InputRef {
  std::array<uint8_t, 32> prevTxid;
  uint32_t                prevOutIndex;
};

// Fields of one PqInput as they enter the signing digest (spec §8.1).
struct DigestInput {
  std::array<uint8_t, 32> prevTxid;
  uint32_t                prevOutIndex;
  DsaPublicKey            authPub;    // pk_i revealed at spend (1952 bytes)
  Rho                     rhoReveal;
};

// Fields of one PqOutput as they enter the signing digest (spec §8.1).
struct DigestOutput {
  uint8_t                 type;
  uint64_t                amount;
  KemCiphertext           kemCt;       // 1088 bytes
  std::array<uint8_t, 56> encPayload;  // ChaCha20-Poly1305 ct||tag
  Hash256                 spendCommit; // 32 bytes
};

// An unsigned PQ transaction body, the input to the ML-DSA signing digest.
// The digest binds the ENTIRE transaction prefix except the per-input
// signatures: version, txType, unlockTime, every input's outpoint+auth_pub+rho,
// every output, the tx_extra blob, and the fee. Omitting any prefix field that
// the txid covers (txType / unlockTime / extra) would let a relayer mutate it
// without invalidating the signature — a malleability hole. (Amends draft §8.1.)
struct UnsignedTx {
  uint8_t                   version = 2;  // TRANSACTION_VERSION_PQ
  uint8_t                   txType = 1;   // TX_PQ
  uint64_t                  unlockTime = 0;
  std::vector<DigestInput>  inputs;
  std::vector<DigestOutput> outputs;
  std::vector<uint8_t>      extra;
  uint64_t                  fee = 0;
};

// 1. inputsHash = SHA3-256(domain || foreach in: prevTxid || LE32(prevOutIndex)).
//    Canonical input order; never re-sorted.
Hash256 inputsHash(const std::vector<InputRef>& inputs) noexcept;

// 2. outContext = SHA3-256(domain || inputsHash || kemCt || LE32(outputIndex) || LE64(T)).
//    T = subaddress index; default 0 for single-address wallets.
Hash256 outContext(const Hash256& inputsHash,
                   const KemCiphertext& kemCt,
                   uint32_t outputIndex,
                   uint64_t subaddrIndexT = 0) noexcept;

// 3. aeadKey = HKDF-SHA3-256(IKM=ss, salt=0, info=domain || outContext, L=32).
//    Encrypts/decrypts the per-output rho delivered to the recipient.
Hash256 deriveAeadKey(const KemShared& ss, const Hash256& outContext) noexcept;

// 4. spendCommit = SHA3-256(domain || spendPub || rho). spendPub is the
//    recipient's long-term ML-DSA spend public key (from the address).
Hash256 spendCommit(const DsaPublicKey& spendPub, const Rho& rho) noexcept;

// 5. nullifier = SHA3-256(domain || spendPub || rho). Node-side only; never
//    serialized. rho makes it unique per output, so reusing one spend key across
//    many outputs still yields distinct nullifiers.
Hash256 nullifier(const DsaPublicKey& spendPub, const Rho& rho) noexcept;

// 6. txSigningDigest — amended §8.1 (see UnsignedTx). Binds the whole prefix
//    minus per-input signatures: version || txType || LE64(unlockTime) ||
//    inputs || outputs || LE32(extra_len) || extra || LE64(fee). Each input's
//    authPub is the long-term spend public key revealed at spend time.
Hash256 txSigningDigest(const UnsignedTx& tx) noexcept;

}  // namespace CryptoPQ
