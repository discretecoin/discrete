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
#include <cstdint>
#include <utility>

#include "PqHash.h"
#include "PqKem.h"
#include "PqDsa.h"

// Wallet seed -> key derivation chain for the Karbo PQ transaction family.
// CEMENTED v2 surface: recovery from a seed must always produce the same keys.
//
//   seed_master  (32 bytes, BIP39 or CSPRNG)
//
//   view branch (scanning / stealth delivery):
//     view_seed  = HKDF-SHA3-256(seed_master, salt=0, info="karbo-pq-view-root-v1", L=64)
//     (view_pub, view_sk) = ML-KEM-768.KeyGen(seed = view_seed)
//
//   spend branch (spending authority):
//     spend_seed = HKDF-SHA3-256(seed_master, salt=0, info="karbo-pq-spend-root-v1", L=32)
//     (spend_pub, spend_sk) = ML-DSA-65.KeyGen(xi = spend_seed)
//
// OWNERSHIP-MODEL FIX (decided 2026-06-04, deviates from draft spec §4/§6):
// the draft derived the per-output spend key from the ML-KEM shared secret ss
// alone. Because the SENDER computes ss via Encaps, the sender could also derive
// the spend key and spend the output it sent — every payment was clawable. We
// fix this by giving each identity a LONG-TERM ML-DSA-65 spend keypair (this
// "spend branch", formerly reserved). The spend public key lives in the address;
// only the holder of spend_sk can sign a spend. See docs/PQ-OWNERSHIP-FIX.md.
//
// L note: ML-DSA.KeyGen takes a 32-byte xi (FIPS 204), so the spend branch uses
// L=32 directly. The view branch uses L=64 because FIPS 203 ML-KEM.KeyGen
// consumes 64 bytes (d || z) — see the view_seed note above.

namespace CryptoPQ {

constexpr char kDomainViewRoot[]  = "karbo-pq-view-root-v1";
constexpr char kDomainSpendRoot[] = "karbo-pq-spend-root-v1";
// Deposit-wallet Spec 1 (aggregated-multikey): a FAMILY of ML-DSA spend keys, one
// per deposit index, all sharing the single view key above. CEMENTED recovery
// contract — see deriveDepositSpendKeys.
constexpr char kDomainDepositSpendRoot[] = "discrete-pq-deposit-spend-v1";

using SeedMaster = std::array<uint8_t, 32>;

// view_seed: the 64-byte ML-KEM keypair seed.
KemKeypairSeed deriveViewSeed(const SeedMaster& seedMaster) noexcept;

// Full view keypair (scanning) derived deterministically from the master seed.
std::pair<KemPublicKey, KemSecretKey> deriveViewKeys(const SeedMaster& seedMaster);

// spend_seed: the 32-byte ML-DSA keypair seed (xi).
DsaKeypairSeed deriveSpendSeed(const SeedMaster& seedMaster) noexcept;

// Long-term ML-DSA spend keypair (spending authority) derived from the master
// seed. spend_pub goes in the address; spend_sk authorizes spends.
std::pair<DsaPublicKey, DsaSecretKey> deriveSpendKeys(const SeedMaster& seedMaster);

// Deposit spend-key family (Spec 1 / aggregated-multikey). One ML-DSA-65 spend
// keypair per deposit index, all under the SAME shared view key (deriveViewKeys),
// so a deposit walletd hands out many addresses that differ only in the spend key
// and decapsulate with one view secret. Each per-deposit spend seed is
//   HKDF-SHA3-256(IKM=seed_master, salt=0, info="discrete-pq-deposit-spend-v1" || LE32(index), L=32)
// then ML-DSA-65.KeyGen(xi=seed). This family is DISTINCT from the account's base
// spend key (deriveSpendKeys), so deposit #0 != the main address. CEMENTED — the
// domain, the LE32 index encoding, and the HKDF parameters must never change or
// existing deposit balances become unrecoverable on restore.
DsaKeypairSeed deriveDepositSpendSeed(const SeedMaster& seedMaster, uint32_t depositIndex) noexcept;
std::pair<DsaPublicKey, DsaSecretKey> deriveDepositSpendKeys(const SeedMaster& seedMaster,
                                                             uint32_t depositIndex);

}  // namespace CryptoPQ
