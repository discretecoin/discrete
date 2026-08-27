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

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "PqHash.h"
#include "PqKem.h"
#include "PqDsa.h"

// Domain-separated protocol derivations for the Discrete PQ transaction family
// (transaction version 1; PQ is active from genesis). See PQ Phase 1 spec §6 / §8.
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
constexpr char kDomainInputsHash[]  = "discrete-pq-inputs-hash-v1";
// LEGACY: the original outContext formula folded LE64(T) into the hash used
// to derive the AEAD key, so a receiver had to enumerate candidate T values
// to decrypt (see PqScan's old scanPqOutputTWindow). Released pre-v2 senders
// used the destination's actual T, including nonzero SingleKeyIndex deposits.
// Retained ONLY so those outputs stay scannable/spendable — see
// legacyOutContextV1 below. MUST NOT be used by new senders.
constexpr char kDomainOutContext[]  = "discrete-pq-out-context-v1";
// CURRENT: outContext no longer depends on T. T travels only inside the
// AEAD-encrypted payload (rho || T) and is read back after a single decrypt,
// so scanning never needs to enumerate candidate T values — any T (sequential
// or random) costs exactly one AEAD attempt, the same as T=0.
constexpr char kDomainOutContextV2[] = "discrete-pq-out-context-v2";
constexpr char kDomainAeadKey[]     = "discrete-pq-aead-key-v1";
constexpr char kDomainSpendCommit[] = "discrete-pq-spend-commit-v1";
constexpr char kDomainNullifier[]   = "discrete-pq-nullifier-v1";
constexpr char kDomainTxSign[]      = "discrete-pq-tx-sign-v1";
constexpr char kDomainTxSignV2[]    = "discrete-pq-tx-sign-v2";
constexpr char kDomainCoinbaseRho[] = "discrete-coinbase-rho-v1";

// RESERVED for Phase 2 (KDSK-CT) — MUST NOT be used by any v1-plain code.
// A unit test asserts none of the tags above collides with this string.
constexpr char kReservedCtMask[]    = "discrete-pq-ct-mask-v1";

// RESERVED for Phase 3 (shielded / untraceable spends) — MUST NOT be used by any
// Phase-1/2 code. A shielded spend reveals a serial S = H_lat(s) as its
// double-spend tag (the coin is proven in a membership set, never named by
// outpoint). S is derived under THIS domain and stored in the SAME unified
// spent-marker set as Phase-1 nullifiers and (historically) classical key images:
// all three are 32-byte "already spent" tags with identical lookup semantics, so
// one table is correct. The ONLY separation needed is the derivation domain — with
// it, a serial can never be valid as a plain nullifier (and vice versa) except by
// a 2^-256 hash accident, the exact assumption that already lets nullifiers and
// key images share spent_keys. No separate namespace/table is needed or wanted.
//   NOTE: the serial *secret* seed-branch derivation (s from the master seed) is
//   deliberately NOT cemented here — no shielded coins exist before Phase 3, so
//   there is nothing to recover yet, and that seed tag is fixed when Phase 3 is
//   designed. This reservation pins only the on-wire/lookup serial domain.
// A unit test asserts no Phase-1/2 tag collides with this string.
constexpr char kReservedShieldedSerial[] = "discrete-pq-serial-v1";

using Rho = std::array<uint8_t, 32>;

// NOTE (ownership-model fix, https://docs.discrete.cash/#/reference/pq-ownership-model): the "spend public key"
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
  uint64_t                unlockHeight = 0; // per-output spend lock (consensus)
  KemCiphertext           kemCt;       // 1088 bytes
  std::array<uint8_t, 56> encPayload;  // ChaCha20-Poly1305 ct||tag
  Hash256                 spendCommit; // 32 bytes
};

// An unsigned PQ transaction body, the input to the ML-DSA signing digest.
// The digest binds the ENTIRE transaction prefix except the per-input
// signatures: version, txType, unlockHeight, every input's outpoint+auth_pub+rho,
// every output, the tx_extra blob, and the fee. Omitting any prefix field that
// the txid covers (txType / unlockHeight / extra) would let a relayer mutate it
// without invalidating the signature — a malleability hole. (Amends draft §8.1.)
struct UnsignedTx {
  uint8_t                   version = 1;  // TRANSACTION_VERSION_1
  uint8_t                   txType = 1;   // TX_PQ
  uint64_t                  unlockHeight = 0;
  std::vector<DigestInput>  inputs;
  std::vector<DigestOutput> outputs;
  std::vector<uint8_t>      extra;
  uint64_t                  fee = 0;
};

// 1. inputsHash = SHA3-256(domain || foreach in: prevTxid || LE32(prevOutIndex)).
//    Canonical input order; never re-sorted.
Hash256 inputsHash(const std::vector<InputRef>& inputs) noexcept;

// 2. outContext = SHA3-256(domain-v2 || inputsHash || kemCt || LE32(outputIndex)).
//    T is NOT part of the context — it lives only in the encrypted payload
//    (see deriveAeadKey below). This is what every new output must use.
Hash256 outContext(const Hash256& inputsHash,
                   const KemCiphertext& kemCt,
                   uint32_t outputIndex) noexcept;

// 2legacy. legacyOutContextV1 = SHA3-256(domain-v1 || inputsHash || kemCt ||
//    LE32(outputIndex) || LE64(T)). The original (pre-v2) formula. Retained
//    ONLY as a receiver-side fallback so outputs minted before the v2
//    activation remain scannable. Never call this to build a new output.
Hash256 legacyOutContextV1(const Hash256& inputsHash,
                           const KemCiphertext& kemCt,
                           uint32_t outputIndex,
                           uint64_t subaddrIndexT) noexcept;

// 3. aeadKey = HKDF-SHA3-256(IKM=ss, salt=0, info=domain || outContext, L=32).
//    Encrypts/decrypts the per-output rho delivered to the recipient.
Hash256 deriveAeadKey(const KemShared& ss, const Hash256& outContext) noexcept;

// 4. spendCommit = SHA3-256(domain || spendPub || rho). spendPub is the
//    recipient's long-term ML-DSA spend public key (from the address).
Hash256 spendCommit(const DsaPublicKey& spendPub, const Rho& rho) noexcept;

// 5. nullifier = SHA3-256(domain || spendPub || rho || prevTxid || LE32(prevOutIndex)).
//    Node-side only; never serialized. Binding the spent output's OUTPOINT makes
//    the nullifier unique per output even if two outputs share (spendPub, rho) —
//    so a publicly-known rho (the canonical coinbase rho, §5b) can never be
//    replayed into a colliding output to brick the original. The outpoint is
//    revealed in the spending PqInput anyway, so this leaks nothing extra.
Hash256 nullifier(const DsaPublicKey& spendPub, const Rho& rho,
                  const Hash256& prevTxid, uint32_t prevOutIndex) noexcept;

// 5b. coinbaseRho = SHA3-256(domain || spendPub || LE32(height) || LE32(outputIndex)).
//     The CANONICAL, publicly-recomputable rho for a coinbase output. Consensus uses
//     it to bind the coinbase reward recipient to the block signer: each coinbase
//     output's spendCommit MUST equal spendCommit(signerSpendPub, coinbaseRho),
//     so the reward can only be spent by the key that signed the block (identity
//     -bound mining — no pools/botnets without sharing the spend secret). Unique
//     per (signer, height, outputIndex), so each coinbase output gets a distinct
//     nullifier even when the genesis block delivers multiple batches to the same key.
//     outputIndex is 0 for all normal mined blocks (which have a single output).
Rho coinbaseRho(const DsaPublicKey& spendPub, uint32_t height,
                uint32_t outputIndex = 0) noexcept;

// 6. txSigningDigest — amended §8.1 (see UnsignedTx). Binds the whole prefix
//    minus per-input signatures: version || txType || LE64(unlockHeight) ||
//    inputs || outputs || LE32(extra_len) || extra || LE64(fee). Each input's
//    authPub is the long-term spend public key revealed at spend time.
Hash256 txSigningDigest(const UnsignedTx& tx) noexcept;

// 6b. txSigningDigestV2 -- the next-version transcript. Same body as v1, wrapped
//     in a new domain and prefixed with the chain identity, suffixed with the
//     index of the input this signature authorizes:
//
//       SHA3-256(domainV2 || chainId || <v1 body> || LE32(inputIndex))
//
//     It closes two holes in v1 that cannot be fixed without changing what is
//     signed:
//
//     * v1 says nothing about which chain the transaction belongs to. The
//       outpoints it names are just (txid, index), so if two networks ever hold
//       the same live outpoint, a signature made for one verifies on the other.
//       chainId is the genesis block id, which is immutable and distinct per
//       network.
//
//     * v1 gives every input of a transaction the same digest, so two inputs
//       spending under the SAME key carry interchangeable signatures. Swapping
//       them leaves the transaction valid but changes its id -- a third party
//       can mutate an unconfirmed payment's id without touching what it does.
//       Binding the input index makes each signature usable in exactly one
//       position.
//
//     This is a consensus change: an activation height gates which transcript is
//     required, and both paths exist around it. Nothing is scheduled yet -- see
//     parameters::PQ_TRANSCRIPT_V2_HEIGHT.
Hash256 txSigningDigestV2(const UnsignedTx& tx, const Hash256& chainId,
                          uint32_t inputIndex) noexcept;

}  // namespace CryptoPQ
