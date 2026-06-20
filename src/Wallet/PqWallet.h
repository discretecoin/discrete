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

#include <string>

#include "CryptoTypes.h"
#include "PqAddress.h"
#include "crypto_pq/PqSeed.h"
#include "crypto_pq/PqScan.h"

// Wallet-core link between a wallet's mnemonic-backed account secret and its
// post-quantum identity. The PQ keypairs are derived deterministically from the
// account's spend secret key, so the SAME 25-word mnemonic that backs up the
// wallet also recovers its PQ funds — no second seed to store.
//
//   seed_master = HKDF-SHA3-256(IKM = classical spendSecretKey (32 B),
//                               salt = 0x00*32,
//                               info = "karbo-pq-wallet-seed-v1",
//                               L = 32)
//   then the cemented PqSeed chain (PqSeed.h):
//     (viewPub,  viewSk)  = ML-KEM-768.KeyGen(HKDF(seed_master, "...view-root-v1"))
//     (spendPub, spendSk) = ML-DSA-65 .KeyGen(HKDF(seed_master, "...spend-root-v1"))
//
// CEMENTED (wallet layer): the seed_master derivation above is part of the
// recovery contract. Changing the info string, the IKM source, or the HKDF
// parameters silently orphans every existing PQ balance on restore. It must
// never change once a PQ-capable wallet ships. (This complements the cemented
// CONSENSUS surface in PqSeed.h / PqAddress.h.)

namespace CryptoNote {

// Domain string for the wallet-layer seed_master derivation. Distinct from the
// reserved "karbo-pq-ct-*-v1" Phase-2 namespace and from the consensus
// derivations in PqDerive.h. CEMENTED — see file header.
constexpr char kPqWalletSeedDomain[] = "karbo-pq-wallet-seed-v1";

// Deposit-wallet scheme, chosen once at container creation and persisted (it
// changes how deposit keys are derived and how the encPayload routing field is
// interpreted, so it cannot be a per-run toggle). See docs/WALLETD-PQ.md and the
// deposit-wallet-modes spec.
enum class PqDepositScheme : uint8_t {
  // Spec 1: one shared ML-KEM view key + a FAMILY of ML-DSA spend keys (one per
  // deposit). Per-deposit spend isolation. DEFAULT. Use case: custodial web wallet.
  AggregatedMultikey = 0,
  // Spec 2 / H-I-T-C: one view + one spend key; deposits are distinguished by an
  // integer subaddress index T (no per-deposit key, no per-deposit registration).
  // Use case: exchange.
  SingleKeyIndex = 1,
};

// A complete PQ identity. `spendSk` is spending authority — treat as sensitive
// and prefer to derive it on demand (derivePqSpendKeys) rather than holding it.
struct PqWalletKeys {
  CryptoPQ::SeedMaster   seedMaster{};
  CryptoPQ::KemPublicKey viewPub{};
  CryptoPQ::KemSecretKey viewSk{};
  CryptoPQ::DsaPublicKey spendPub{};
  CryptoPQ::DsaSecretKey spendSk{};
};

// View-only PQ audit credential. This can scan the primary PQ address and detect
// spends, but it cannot sign transactions.
struct PqTrackingKeys {
  CryptoPQ::KemPublicKey viewPub{};
  CryptoPQ::KemSecretKey viewSk{};
  CryptoPQ::DsaPublicKey spendPub{};
};

// seed_master from the classical account spend secret key (see file header).
CryptoPQ::SeedMaster pqSeedMasterFromSpendSecret(const Crypto::SecretKey& spendSecretKey) noexcept;

// Full PQ identity (view + spend keypairs) for a classical wallet.
PqWalletKeys derivePqWalletKeys(const Crypto::SecretKey& spendSecretKey);

// Strip a full wallet identity down to the view-only audit credential.
PqTrackingKeys pqTrackingKeys(const PqWalletKeys& keys);

// The wallet's own PQ address for the given network prefix.
PqAddress pqWalletAddress(const PqWalletKeys& keys, uint64_t networkPrefix);
PqAddress pqWalletAddress(const PqTrackingKeys& keys, uint64_t networkPrefix);

// Convenience: derive the wallet's PQ address straight from the spend secret.
PqAddress pqWalletAddress(const Crypto::SecretKey& spendSecretKey, uint64_t networkPrefix);

// The scan credential (view-only capable): viewSk decapsulates, spendPub
// recomputes the ownership commitment. A tracking wallet holds exactly this.
CryptoPQ::PqScanKeys pqScanKeys(const PqWalletKeys& keys);
CryptoPQ::PqScanKeys pqScanKeys(const PqTrackingKeys& keys);

// User-facing PQ tracking key format:
//   pqview1:<hex(viewPub || spendPub || viewSk)>
// `viewSk` is secret audit authority; `spendPub` is public and cannot spend.
constexpr char kPqTrackingKeyPrefix[] = "pqview1:";
std::string encodePqTrackingKey(const PqTrackingKeys& keys);
bool decodePqTrackingKey(const std::string& encoded, PqTrackingKeys& keys);

// --- Address parsing / detection (shared by both front-ends) ---------------

// True if `s` is a well-formed PQ address (correct length + valid checksum) in
// either supported encoding. Cheap reject for non-PQ strings: a PQ address is
// far longer than a classical Karbo address, so length screens out the common
// case before any decode work.
bool isPqAddressString(const std::string& s);

// Parse a PQ address string, trying base58 then bech32m. Returns false if it is
// not a valid PQ address in either encoding. On success `out` is fully
// populated and `encoding` (if non-null) reports which encoding matched.
bool parsePqAddress(const std::string& s, PqAddress& out, PqAddressEncoding* encoding = nullptr);

// PQ identities reuse the shared CryptoNote::AccountNumber ("H-I-C") format for
// human-readable account numbers — see include/AccountNumber.h. There is no
// PQ-specific rendering.

}  // namespace CryptoNote
