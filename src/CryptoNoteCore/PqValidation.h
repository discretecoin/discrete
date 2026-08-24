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
#include <cstdint>
#include <string>
#include <vector>

#include "CryptoNote.h"
#include "CryptoTypes.h"
#include "../CryptoNoteConfig.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqHash.h"

// Consensus validation for PQ Phase 1 transactions (TRANSACTION_VERSION_1,
// subtype TX_PQ). Spec §9, amended by the ownership-model fix
// (https://docs.discrete.cash/#/reference/pq-ownership-model). These functions are CONTEXT-FREE: chain-state
// lookups (resolving referenced outputs, checking the on-disk nullifier set,
// height gating) are done by the caller (Blockchain) and fed in here, so the
// consensus crypto is deterministic and unit-testable in isolation.

namespace CryptoNote {

// A referenced output resolved from the chain, parallel to a PqInput.
struct PqResolvedInput {
  Crypto::Hash spendCommit;       // referenced PqOutput.spendCommit
  uint64_t     amount = 0;        // referenced output amount (plain)
  bool         exists = false;    // referenced output was found
  bool         isPqOutput = false;// output is spendable by a PQ input (PqOutput or CoinbaseOutput)
  bool         isCoinbase = false;// referenced output is from a coinbase tx
};

// Context-free shape / semantic checks for one v2 TX_PQ transaction:
//  - subtype == TX_PQ
//  - non-empty; all inputs PqInput; all outputs PqOutput (mixed-family reject)
//  - inputs <= MAX_PQ_INPUTS_PER_TX, outputs <= MAX_PQ_OUTPUTS_PER_TX
//  - serialized size <= MAX_PQ_TX_SIZE
//  - every PQ blob field has the exact consensus length
//  - every output amount != 0
//  - unlockHeight == 0; legacy signatures vector empty
bool checkPqTransactionSemantic(const Transaction& tx, std::string* error);

// Context-free checks for one v2 TX_FREE_REG transaction (zero-fee account
// registration, spec §11.1):
//  - subtype == TX_FREE_REG; inputs & outputs empty; no legacy signatures;
//    unlockHeight == 0
//  - tx_extra carries EXACTLY one PQ account-registration tag (0x05) and EXACTLY
//    one PoW tag (0x06), and nothing else
//  - the PoW tag is the last field (so the nonce is the final 8 bytes)
//  - anti-spam PoW: yespower(domain || viewPub || spendPub || refBlockHash ||
//    LE64(nonce)) meets FREE_REG_POW_TARGET
// Chain-context rules (refBlockHash recency + main-chain, first-reg-wins,
// per-block count) are enforced by the Blockchain layer.
// powTarget defaults to parameters::FREE_REG_POW_TARGET; pass a custom value
// (e.g. UINT64_MAX) in tests to bypass PoW grinding.
//
// The check is split so callers can run the cheap half first. Verifying the PoW
// costs a full memory-hard yespower evaluation (16 MiB, milliseconds), which a
// peer can trigger for free by replaying a blob, so the expensive half must only
// run once everything a node can decide cheaply — shape, whether the transaction
// is already known, whether the reference block is in the window, whether the
// identity is already registered — has already passed.
bool checkFreeRegTransactionShape(const Transaction& tx, std::string* error);

// How many registration-proof evaluations the calling thread has run. Node-local
// instrumentation, not consensus: the relay layer samples the delta across one
// transaction admission to charge the peer that caused the work, and tests use
// it to assert that cheap rejections never reach the proof at all.
uint64_t freeRegPowEvaluationCount();
bool checkFreeRegTransactionPow(const Transaction& tx, std::string* error,
                                uint64_t powTarget = parameters::FREE_REG_POW_TARGET);
bool checkFreeRegTransactionSemantic(const Transaction& tx, std::string* error,
                                     uint64_t powTarget = parameters::FREE_REG_POW_TARGET);

// Consensus domain for the free-registration PoW preimage. Binding both public
// keys prevents one proof for a view key from being replayed with arbitrarily
// many spend keys. Keep byte-for-byte stable after launch.
constexpr char FREE_REG_POW_DOMAIN[] = "discrete-pq-free-reg-pow-v1";

// The free-reg anti-spam PoW predicate. Reused by wallet nonce grinding.
// target defaults to parameters::FREE_REG_POW_TARGET.
bool checkFreeRegPow(const std::array<uint8_t, 1184>& viewPub,
                     const std::array<uint8_t, 1952>& spendPub,
                     const Crypto::Hash& refBlockHash, uint64_t nonce,
                     uint64_t target = parameters::FREE_REG_POW_TARGET);

// Grind the free-reg anti-spam PoW: return a nonce such that
// checkFreeRegPow(viewPub, spendPub, refBlockHash, nonce, powTarget) holds. Shared by every
// wallet front-end (simplewallet, walletd) so they all grind to the same
// consensus target. Always terminates (the predicate is satisfiable for some
// nonce), but the work scales with 1/powTarget.
uint64_t grindFreeRegPow(const std::array<uint8_t, 1184>& viewPub,
                         const std::array<uint8_t, 1952>& spendPub,
                         const Crypto::Hash& refBlockHash,
                         uint64_t powTarget = parameters::FREE_REG_POW_TARGET);

// Which signing transcript a transaction is judged against.
//
// Before parameters::PQ_TRANSCRIPT_V2_HEIGHT every input signs one shared digest
// (version 1). From that height each input signs a digest that also binds the
// chain identity and the input's own index (version 2). Both paths exist so the
// activation boundary can be crossed, and reorgs across it re-evaluate at the
// height the block actually lands on.
struct PqSigningContext {
  bool useV2 = false;
  CryptoPQ::Hash256 chainId{};  // genesis block id; only read when useV2
};

// The signing context for a transaction being validated at `height` on the chain
// whose genesis block id is `genesisId`.
PqSigningContext pqSigningContextForHeight(uint32_t height, const Crypto::Hash& genesisId);

// Context-free input/balance/signature checks given resolved referenced outputs
// (resolved[i] corresponds to tx.inputs[i]). On success, *outNullifiers (if not
// null) is filled with each input's nullifier so the caller can test them
// against the on-disk pq_nullifiers set.
//
// Checks, in order (fail fast on the cheap ones):
//  - resolved.size() == inputs.size(); every referenced output exists and is a
//    PqOutput (coinbase PqOutputs are spendable; their maturity is enforced by
//    the chain-context caller, not here)
//  - spend_commit(authPub, rhoReveal) == referenced spendCommit
//  - intra-tx nullifier uniqueness
//  - balance: sum(referenced amounts) == sum(output amounts) + fee, fee >= 0
//  - fee >= pqTxFeeFloor(minFee, extra size): flat minimum + tx_extra surcharge
//  - ML-DSA verify each input over the recomputed txSigningDigest
bool checkPqTransactionInputs(const Transaction& tx,
                             const std::vector<PqResolvedInput>& resolved,
                             uint64_t minFee,
                             std::vector<Crypto::Hash>* outNullifiers,
                             std::string* error,
                             const PqSigningContext& signing = PqSigningContext());

// Helper: recompute one PQ input's nullifier. Returns a zero hash if the input
// fields are malformed (wrong sizes).
Crypto::Hash pqNullifier(const PqInput& in);

// Map a PQ nullifier to a KeyImage so it can be stored in the type-agnostic
// spent-keys set alongside classical key images.
Crypto::KeyImage pqInputNullifierAsKeyImage(const PqInput& in);

// The spec §8.1 signing digest for a v2 TX_PQ given its computed fee
// (fee = sum(referenced amounts) - sum(output amounts)). The spender signs this
// with its ML-DSA spend secret; the validator recomputes and verifies it.
CryptoPQ::Hash256 pqSigningDigest(const Transaction& tx, uint64_t fee);

// The transaction body both transcript versions are computed over.
CryptoPQ::UnsignedTx pqUnsignedTx(const Transaction& tx, uint64_t fee);

}  // namespace CryptoNote
