// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

#include "Account.h"

#include <cstring>

#include "CryptoNoteSerialization.h"
#include "crypto/crypto.h"
#include "crypto/crypto-util.h"   // secure_random_bytes
#include "crypto_pq/PqSeed.h"     // deriveViewKeys / deriveSpendKeys

namespace {
// The 32-byte master secret is the PQ SeedMaster (fed straight into the PqSeed
// chain — no HKDF — matching the wallet and the daemon mining-key derivation).
CryptoPQ::SeedMaster toSeedMaster(const Crypto::SecretKey& s) {
  CryptoPQ::SeedMaster sm{};
  std::memcpy(sm.data(), s.data, sm.size());
  return sm;
}
}  // namespace

namespace CryptoNote {
//-----------------------------------------------------------------
AccountBase::AccountBase() {
  setNull();
}
//-----------------------------------------------------------------
void AccountBase::setNull() {
  m_keys = AccountKeys();
}
//-----------------------------------------------------------------
void AccountBase::generate() {
  // Mint a PQ-native master seed (32 CSPRNG bytes). The whole identity (view, spend,
  // per-deposit) derives from it; there is no classical (Ed25519) keypair. The
  // spendPublicKey slot carries a hash-of-seed checksum used only as the wallet-file
  // password check; viewPublicKey / viewSecretKey stay zero.
  secure_random_bytes(m_keys.spendSecretKey.data, sizeof(m_keys.spendSecretKey.data));
  Crypto::cn_fast_hash(m_keys.spendSecretKey.data, sizeof(m_keys.spendSecretKey.data),
                       reinterpret_cast<Crypto::Hash&>(m_keys.address.spendPublicKey));
  m_keys.address.viewPublicKey = Crypto::PublicKey{};
  m_keys.viewSecretKey = Crypto::SecretKey{};

  m_creation_timestamp = time(NULL);
}

//-----------------------------------------------------------------
void AccountBase::generateDeterministic() {
  // A PQ wallet has a single master seed; there is no separate deterministic scheme.
  generate();
}

//-----------------------------------------------------------------
void AccountBase::generateViewFromSpend(const Crypto::SecretKey &spendSecret, Crypto::SecretKey &viewSecret, Crypto::PublicKey &viewPublic) {
  // Deterministic view secret = SHA3-256(spend secret). This carries no ECC: on
  // the PQ chain the wallet's real view key is the ML-KEM key derived from the
  // master seed, so the classical view public key is vestigial and stays zero.
  Crypto::cn_fast_hash(&spendSecret, sizeof(spendSecret), reinterpret_cast<Crypto::Hash&>(viewSecret));
  viewPublic = Crypto::PublicKey{};
}

void AccountBase::generateViewFromSpend(const Crypto::SecretKey &spendSecret, Crypto::SecretKey &viewSecret) {
  /* If we don't need the pub key */
  Crypto::PublicKey unused_dummy_variable;
  generateViewFromSpend(spendSecret, viewSecret, unused_dummy_variable);
}

//-----------------------------------------------------------------
const AccountKeys &AccountBase::getAccountKeys() const {
  return m_keys;
}

void AccountBase::setAccountKeys(const AccountKeys &keys) {
  m_keys = keys;
}
//-----------------------------------------------------------------
CryptoPQ::DsaPublicKey AccountBase::pqSpendPk() const {
  return CryptoPQ::deriveSpendKeys(toSeedMaster(m_keys.spendSecretKey)).first;
}
CryptoPQ::DsaSecretKey AccountBase::pqSpendSk() const {
  return CryptoPQ::deriveSpendKeys(toSeedMaster(m_keys.spendSecretKey)).second;
}
CryptoPQ::KemPublicKey AccountBase::pqViewPk() const {
  return CryptoPQ::deriveViewKeys(toSeedMaster(m_keys.spendSecretKey)).first;
}
CryptoPQ::KemSecretKey AccountBase::pqViewSk() const {
  return CryptoPQ::deriveViewKeys(toSeedMaster(m_keys.spendSecretKey)).second;
}
//-----------------------------------------------------------------

void AccountBase::serialize(ISerializer &s) {
  s(m_keys, "m_keys");
  s(m_creation_timestamp, "m_creation_timestamp");
}
}
