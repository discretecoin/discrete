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
#include <optional>
#include <vector>

#include "PqHash.h"
#include "PqKem.h"
#include "PqDsa.h"
#include "PqDerive.h"

// Receiver-side PQ output scanning (spec §7, amended by the ownership-model fix
// in docs/PQ-OWNERSHIP-FIX.md).
//
// Scanning needs only the VIEW SECRET (to decapsulate) and the wallet's own
// long-term spend PUBLIC key (to recompute spend_commit) — NOT the spend
// secret. So a view-only wallet can detect incoming funds without any ability
// to spend, exactly like a CryptoNote view key.
//
// GARBAGE-OUTPUT DISCIPLINE (spec §7): a non-owned output and a tampered output
// are both reported as "not mine" (nullopt) with no distinguishing side effect.
// Callers MUST NOT add metrics/logging that separate AEAD failure from a
// non-output — that would leak wallet scan state to an observer.

namespace CryptoPQ {

// What a wallet records for an owned PQ output. Contains NO secret key — the
// spend secret is re-derived on demand at spend time, never persisted here.
struct PqOwnedOutput {
  uint32_t outputIndex = 0;
  uint64_t amount = 0;
  uint64_t subaddrIndexT = 0;  // deposit routing index; 0 for single-address wallets
  Rho      rho{};
  Hash256  outContext{};
};

// The keys required to scan. viewSk decapsulates; spendPub recomputes the
// ownership commitment. (Both are derivable from the wallet seed.)
struct PqScanKeys {
  KemSecretKey viewSk;
  DsaPublicKey spendPub;
};

// One candidate output as seen on chain. `amount` is the plain on-chain amount
// (TransactionOutput.amount); it is bound into the AEAD aad.
struct PqScanOutput {
  uint32_t             outputIndex = 0;
  uint64_t             amount = 0;
  KemCiphertext        kemCt{};
  std::vector<uint8_t> encPayload;   // 48 bytes
  Hash256              spendCommit{};
};

// Try to recognize ONE output for the given subaddress index T (default 0 for
// single-address wallets). Returns the owned record on success, nullopt
// otherwise (not ours, OR tampered — indistinguishable by design).
std::optional<PqOwnedOutput> scanPqOutput(const PqScanKeys& keys,
                                          const Hash256& inputsHash,
                                          const PqScanOutput& out,
                                          uint64_t subaddrIndexT = 0);

// Scan every output of one transaction for the given T.
std::vector<PqOwnedOutput> scanPqOutputs(const PqScanKeys& keys,
                                         const Hash256& inputsHash,
                                         const std::vector<PqScanOutput>& outputs,
                                         uint64_t subaddrIndexT = 0);

// Try to recognize ONE output for any subaddress index T in [0, maxT).
// T is bound into the AEAD key derivation, so the receiver has to enumerate
// candidate indices; this decapsulates ONCE and each T trial costs only a
// SHA3 (outContext) + one AEAD attempt. Returns the owned record with
// subaddrIndexT = the matching T, or nullopt. Same garbage-output discipline
// as scanPqOutput.
std::optional<PqOwnedOutput> scanPqOutputTWindow(const PqScanKeys& keys,
                                                 const Hash256& inputsHash,
                                                 const PqScanOutput& out,
                                                 uint64_t maxT);

// --- Aggregated scanning (exchange / service wallets) ----------------------
// A service issues many deposit addresses sharing ONE ML-KEM view key but with
// distinct ML-DSA spend keys: addr_i = shared_viewPub || deposit_spendPub_i.
// The expensive ML-KEM decapsulation is done ONCE per output here; only the
// cheap spend_commit check is repeated per deposit key. No sender-provided
// routing hint is used — the sender cannot influence which deposit matched.

struct PqAggregateOwned {
  PqOwnedOutput record;
  std::size_t   spendPubIndex = 0;  // index into the supplied spendPubs vector
};

// Try to recognize ONE output against a set of deposit spend keys sharing viewSk.
// Iterates T = 0..spendPubs.size()-1: for each T, derives outContext(T), decrypts,
// reads back T from the payload, and checks spend_commit(spendPubs[T]).
// Decapsulates once per call; each T trial is a cheap AEAD + SHA3 operation.
// Returns the first match (or nullopt). Tampering and non-ownership are silent.
std::optional<PqAggregateOwned> scanPqOutputAggregate(
    const KemSecretKey& viewSk,
    const std::vector<DsaPublicKey>& spendPubs,
    const Hash256& inputsHash,
    const PqScanOutput& out);

}  // namespace CryptoPQ
