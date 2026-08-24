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

#pragma once

#include <cstring>
#include <limits>
#include <vector>
#include <map>
#include <unordered_map>

#include "ITransfersContainer.h"
#include "IWallet.h"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/random_access_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/member.hpp>

#include "Common/FileMappedVector.h"
#include "crypto/chacha8.h"
#include "crypto/crypto-util.h"
#include "crypto/random.h"
#include "crypto_pq/PqAead.h"
#include "crypto_pq/PqSeed.h"

namespace CryptoNote {

const uint64_t ACCOUNT_CREATE_TIME_ACCURACY = 60 * 60 * 24;
const uint32_t WALLET_INVALID_HD_INDEX = std::numeric_limits<uint32_t>::max();

// PQ-native wallet identity. The wallet's master secret is a post-quantum
// CryptoPQ::SeedMaster (32 CSPRNG bytes); every PQ key (view, spend, per-deposit
// spend) derives from it through the cemented PqSeed chain. There is no classical
// (Ed25519) keypair. A tracking (audit-only) wallet holds an all-zero seedMaster
// and carries its PqTrackingKeys credential separately (persisted in the PQ state
// blob); `tracking` records that distinction.
struct WalletRecord {
  CryptoPQ::SeedMaster seedMaster{};
  bool tracking = false;
  uint64_t pendingBalance = 0;
  uint64_t actualBalance = 0;
  time_t creationTimestamp = 0;
  uint32_t hdIndex = WALLET_INVALID_HD_INDEX;
};

// ---- Wallet container format ---------------------------------------------
//
// The container is versioned. Version 10 is the current format; version 9 is
// still readable so an existing wallet can be opened once and migrated.
//
// What changed, and why:
//   * The password KDF takes a per-wallet random salt, so two wallets sharing a
//     password no longer derive the same encryption key and no precomputation
//     carries from one wallet to another.
//   * Records and the cache blob are AEAD (ChaCha20-Poly1305) rather than raw
//     ChaCha8. A stream cipher with no tag lets anyone who can write the file
//     flip chosen bits of the decrypted plaintext.
//   * Every ciphertext carries a freshly drawn 96-bit nonce. Version 9 handed
//     nonces out from a mutable counter in the unauthenticated header, which
//     could repeat under one key and, for a stream cipher, leak plaintext.
//   * The header (version, KDF id and parameters, salt) is authenticated as
//     associated data, so it cannot be edited to steer how the body is read.
constexpr uint8_t WALLET_CONTAINER_VERSION = 10;
constexpr uint8_t WALLET_CONTAINER_VERSION_LEGACY = 9;

// KDF identifiers. 1 = yespower(N, r) over salt || password, i.e.
// Crypto::generate_chacha8_key_salted.
constexpr uint8_t WALLET_KDF_YESPOWER_SALTED = 1;
constexpr uint32_t WALLET_KDF_YESPOWER_N = 2048;
constexpr uint32_t WALLET_KDF_YESPOWER_R = 32;

constexpr size_t WALLET_CONTAINER_SALT_SIZE = 32;

#pragma pack(push, 1)

// --- version 9 (legacy, read-only) ---
struct EncryptedWalletRecordV1 {
  Crypto::chacha8_iv iv;
  // magic(4) || seedMaster(32) || creationTimestamp(8), ChaCha8, no tag.
  uint8_t data[4 + sizeof(CryptoPQ::SeedMaster) + sizeof(uint64_t)];
};

struct ContainerStoragePrefixV1 {
  uint8_t version;
  Crypto::chacha8_iv nextIv;
};

// --- version 10 ---
struct ContainerStoragePrefix {
  uint8_t  version;
  uint8_t  kdf;
  uint8_t  reserved[2];
  uint32_t kdfN;
  uint32_t kdfR;
  uint8_t  salt[WALLET_CONTAINER_SALT_SIZE];

  // The salt in the shape the KDF takes.
  Crypto::Hash saltHash() const {
    Crypto::Hash h{};
    static_assert(sizeof(h.data) == WALLET_CONTAINER_SALT_SIZE, "salt must fill a Hash");
    std::memcpy(h.data, salt, sizeof(salt));
    return h;
  }
};

struct EncryptedWalletRecord {
  uint8_t nonce[CryptoPQ::kAeadNonceBytes];
  // AEAD(seedMaster(32) || creationTimestamp(8)) || tag(16). No magic value: the
  // tag is the password check, and unlike a magic it also detects tampering.
  uint8_t data[sizeof(CryptoPQ::SeedMaster) + sizeof(uint64_t) + CryptoPQ::kAeadTagBytes];
};
#pragma pack(pop)

typedef Common::FileMappedVector<EncryptedWalletRecordV1> ContainerStorageV1;
typedef Common::FileMappedVector<EncryptedWalletRecord> ContainerStorage;

// A fresh header: current version, current KDF parameters, and a salt from the
// OS CSPRNG.
inline ContainerStoragePrefix makeContainerHeader() {
  ContainerStoragePrefix header{};
  header.version = WALLET_CONTAINER_VERSION;
  header.kdf = WALLET_KDF_YESPOWER_SALTED;
  header.kdfN = WALLET_KDF_YESPOWER_N;
  header.kdfR = WALLET_KDF_YESPOWER_R;
  Random::randomBytes(sizeof(header.salt), header.salt);
  return header;
}

// Derive the container key from the password and the header's salt. False means
// the KDF failed and the caller must abort; `key` is left zeroed rather than
// holding the yespower failure sentinel.
inline bool deriveContainerKey(const std::string& password,
                               const ContainerStoragePrefix& header,
                               Crypto::chacha8_key& key) {
  return Crypto::generate_chacha8_key_salted(password, header.saltHash(), key);
}

constexpr char WALLET_AAD_RECORD[] = "discrete-wallet-seed-record-v1";
constexpr char WALLET_AAD_CACHE[] = "discrete-wallet-cache-v1";

// Everything a body ciphertext is bound to. Editing any of it -- claiming a
// different version, different KDF parameters, or a different salt -- makes
// every record and the cache blob fail to authenticate.
inline std::vector<uint8_t> containerAad(const ContainerStoragePrefix& header,
                                         const char* domain) {
  const auto* raw = reinterpret_cast<const uint8_t*>(&header);
  std::vector<uint8_t> aad(raw, raw + sizeof(header));
  const size_t domainLen = std::strlen(domain);
  aad.insert(aad.end(), domain, domain + domainLen);
  return aad;
}

inline CryptoPQ::AeadKey toAeadKey(const Crypto::chacha8_key& key) {
  CryptoPQ::AeadKey out{};
  static_assert(sizeof(key.data) == CryptoPQ::kAeadKeyBytes, "container key must be 32 bytes");
  std::memcpy(out.data(), key.data, out.size());
  return out;
}

// Encrypt one seed record. The nonce is drawn fresh on every call, so
// re-encrypting a record in place -- which a rescan does to every record, right
// before the cache blob is rewritten -- can never repeat a (key, nonce) pair.
inline EncryptedWalletRecord encryptSeedRecord(const CryptoPQ::SeedMaster& seedMaster,
                                               uint64_t creationTimestamp,
                                               const Crypto::chacha8_key& key,
                                               const ContainerStoragePrefix& header) {
  uint8_t plain[sizeof(CryptoPQ::SeedMaster) + sizeof(uint64_t)];
  std::memcpy(plain, seedMaster.data(), seedMaster.size());
  std::memcpy(plain + seedMaster.size(), &creationTimestamp, sizeof(creationTimestamp));

  EncryptedWalletRecord result{};
  CryptoPQ::AeadNonce nonce{};
  Random::randomBytes(nonce.size(), nonce.data());
  std::memcpy(result.nonce, nonce.data(), nonce.size());

  const std::vector<uint8_t> aad = containerAad(header, WALLET_AAD_RECORD);
  const std::vector<uint8_t> sealed =
      CryptoPQ::aead_encrypt(toAeadKey(key), nonce, aad.data(), aad.size(), plain, sizeof(plain));
  sodium_memzero(plain, sizeof(plain));

  std::memcpy(result.data, sealed.data(), sizeof(result.data));
  return result;
}

// False = wrong password, or the record (or the header it is bound to) was
// tampered with. The two are deliberately indistinguishable.
inline bool decryptSeedRecord(const EncryptedWalletRecord& cipher,
                              CryptoPQ::SeedMaster& seedMaster,
                              uint64_t& creationTimestamp,
                              const Crypto::chacha8_key& key,
                              const ContainerStoragePrefix& header) {
  CryptoPQ::AeadNonce nonce{};
  std::memcpy(nonce.data(), cipher.nonce, nonce.size());

  const std::vector<uint8_t> aad = containerAad(header, WALLET_AAD_RECORD);
  auto plain = CryptoPQ::aead_decrypt(toAeadKey(key), nonce, aad.data(), aad.size(),
                                      cipher.data, sizeof(cipher.data));
  if (!plain || plain->size() != sizeof(CryptoPQ::SeedMaster) + sizeof(uint64_t)) {
    return false;
  }

  std::memcpy(seedMaster.data(), plain->data(), seedMaster.size());
  std::memcpy(&creationTimestamp, plain->data() + seedMaster.size(), sizeof(creationTimestamp));
  sodium_memzero(plain->data(), plain->size());
  return true;
}

// The wallet cache blob: nonce || ciphertext || tag.
inline std::vector<uint8_t> encryptContainerBlob(const void* data, size_t size,
                                                 const Crypto::chacha8_key& key,
                                                 const ContainerStoragePrefix& header) {
  CryptoPQ::AeadNonce nonce{};
  Random::randomBytes(nonce.size(), nonce.data());

  const std::vector<uint8_t> aad = containerAad(header, WALLET_AAD_CACHE);
  const std::vector<uint8_t> sealed =
      CryptoPQ::aead_encrypt(toAeadKey(key), nonce, aad.data(), aad.size(), data, size);

  std::vector<uint8_t> out;
  out.reserve(nonce.size() + sealed.size());
  out.insert(out.end(), nonce.begin(), nonce.end());
  out.insert(out.end(), sealed.begin(), sealed.end());
  return out;
}

inline bool decryptContainerBlob(const uint8_t* data, size_t size,
                                 const Crypto::chacha8_key& key,
                                 const ContainerStoragePrefix& header,
                                 std::vector<uint8_t>& out) {
  if (size < CryptoPQ::kAeadNonceBytes + CryptoPQ::kAeadTagBytes) {
    return false;
  }
  CryptoPQ::AeadNonce nonce{};
  std::memcpy(nonce.data(), data, nonce.size());

  const std::vector<uint8_t> aad = containerAad(header, WALLET_AAD_CACHE);
  auto plain = CryptoPQ::aead_decrypt(toAeadKey(key), nonce, aad.data(), aad.size(),
                                      data + nonce.size(), size - nonce.size());
  if (!plain) {
    return false;
  }
  out = std::move(*plain);
  return true;
}

// --- version 9 record codec (read-only, for migration) ---------------------

// Magic prefix inside every version-9 encrypted seed record. A wrong password
// decrypted to garbage and this would not match, which is how version 9 detected
// a bad password. Version 10 uses the AEAD tag instead, which also catches
// tampering that a magic value cannot.
constexpr uint8_t SEED_RECORD_MAGIC_V1[4] = { 'D', 'P', 'Q', 'S' };

inline bool decryptSeedRecordV1(const EncryptedWalletRecordV1& cipher,
                                CryptoPQ::SeedMaster& seedMaster,
                                uint64_t& creationTimestamp,
                                const Crypto::chacha8_key& key) {
  unsigned char buffer[sizeof(cipher.data)];
  Crypto::chacha8(cipher.data, sizeof(cipher.data), key, cipher.iv, reinterpret_cast<char*>(buffer));
  if (std::memcmp(buffer, SEED_RECORD_MAGIC_V1, sizeof(SEED_RECORD_MAGIC_V1)) != 0) {
    sodium_memzero(buffer, sizeof(buffer));
    return false;
  }
  std::memcpy(seedMaster.data(), buffer + sizeof(SEED_RECORD_MAGIC_V1), seedMaster.size());
  std::memcpy(&creationTimestamp, buffer + sizeof(SEED_RECORD_MAGIC_V1) + seedMaster.size(),
              sizeof(creationTimestamp));
  sodium_memzero(buffer, sizeof(buffer));
  return true;
}

struct RandomAccessIndex {};
struct KeysIndex {};

struct WalletIndex {};
struct TransactionOutputIndex {};
struct BlockHeightIndex {};

struct TransactionHashIndex {};
struct TransactionIndex {};
struct BlockHashIndex {};

// PQ wallets are single-identity (one master seed) plus derived deposit addresses,
// so the container only needs positional access — there is no classical spend
// public key left to hash on.
typedef boost::multi_index_container <
  WalletRecord,
  boost::multi_index::indexed_by <
    boost::multi_index::random_access < boost::multi_index::tag <RandomAccessIndex> >
  >
> WalletsContainer;

struct UnlockTransactionJob {
  uint32_t blockHeight;
  Crypto::Hash transactionHash;
};

typedef boost::multi_index_container <
  UnlockTransactionJob,
  boost::multi_index::indexed_by <
    boost::multi_index::ordered_non_unique < boost::multi_index::tag <BlockHeightIndex>,
    BOOST_MULTI_INDEX_MEMBER(UnlockTransactionJob, uint32_t, blockHeight)
    >,
    boost::multi_index::hashed_non_unique < boost::multi_index::tag <TransactionHashIndex>,
      BOOST_MULTI_INDEX_MEMBER(UnlockTransactionJob, Crypto::Hash, transactionHash)
    >
  >
> UnlockTransactionJobs;

typedef boost::multi_index_container <
  CryptoNote::WalletTransaction,
  boost::multi_index::indexed_by <
    boost::multi_index::random_access < boost::multi_index::tag <RandomAccessIndex> >,
    boost::multi_index::hashed_unique < boost::multi_index::tag <TransactionIndex>,
      boost::multi_index::member<CryptoNote::WalletTransaction, Crypto::Hash, &CryptoNote::WalletTransaction::hash >
    >,
    boost::multi_index::ordered_non_unique < boost::multi_index::tag <BlockHeightIndex>,
      boost::multi_index::member<CryptoNote::WalletTransaction, uint32_t, &CryptoNote::WalletTransaction::blockHeight >
    >
  >
> WalletTransactions;

typedef std::pair<size_t, CryptoNote::WalletTransfer> TransactionTransferPair;
typedef std::vector<TransactionTransferPair> WalletTransfers;
typedef std::map<size_t, CryptoNote::Transaction> UncommitedTransactions;

typedef boost::multi_index_container<
  Crypto::Hash,
  boost::multi_index::indexed_by <
    boost::multi_index::random_access<
      boost::multi_index::tag<BlockHeightIndex>
    >,
    boost::multi_index::hashed_unique<
      boost::multi_index::tag<BlockHashIndex>,
      boost::multi_index::identity<Crypto::Hash>
    >
  >
> BlockHashesContainer;

}
