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
#include <string>

#include "crypto_pq/PqKem.h"
#include "crypto_pq/PqDsa.h"

// PQ address (spec §3, amended). CEMENTED v2 surface — the layout and checksum
// never change. The string encoding (base58 vs bech32m) is still an open item,
// so we support both behind a runtime selector until the choice is finalized.
//
// The address carries TWO public keys:
//   * viewPub  (ML-KEM-768, 1184 B) — stealth delivery / scanning.
//   * spendPub (ML-DSA-65,  1952 B) — spending authority. Added by the
//     ownership-model fix (docs/PQ-OWNERSHIP-FIX.md): only the holder of the
//     matching spend secret can spend, so the sender cannot claw payments back.
//
// Wire layout fed to the encoder:
//   version (1) || varint(networkPrefix) || viewPub (1184) || spendPub (1952) || checksum (4)
// checksum = first 4 bytes of
//   SHA3-256(version || varint(networkPrefix) || viewPub || spendPub)

namespace CryptoNote {

struct PqAddress {
  uint8_t                            version = 0x01;
  uint64_t                           networkPrefix = 0;
  std::array<uint8_t, CryptoPQ::kKemPublicKeyBytes> viewPub{};   // 1184
  std::array<uint8_t, CryptoPQ::kDsaPublicKeyBytes> spendPub{};  // 1952
  std::array<uint8_t, 4>             checksum{};
};

enum class PqAddressEncoding {
  Base58,   // CryptoNote block-based base58 (matches existing addresses)
  Bech32m,  // BIP-350 bech32m, recommended for QR density on the 1190-byte payload
};

// Build an address from its parts, filling version=1 and the derived checksum.
PqAddress makePqAddress(uint64_t networkPrefix,
                        const CryptoPQ::KemPublicKey& viewPub,
                        const CryptoPQ::DsaPublicKey& spendPub);

// The 4-byte checksum over (version || varint(networkPrefix) || viewPub).
std::array<uint8_t, 4> pqAddressChecksum(const PqAddress& addr);

// Encode to a string. The stored checksum is ignored and recomputed so callers
// can't accidentally emit a stale checksum.
std::string encodePqAddress(const PqAddress& addr,
                            PqAddressEncoding encoding = PqAddressEncoding::Base58);

// Decode and verify. Returns false on malformed input, wrong length, or a
// checksum mismatch. On success, out is fully populated (checksum included).
bool decodePqAddress(const std::string& str,
                     PqAddress& out,
                     PqAddressEncoding encoding = PqAddressEncoding::Base58);

// For bech32m: the human-readable part. PQ mainnet/testnet prefix is an open
// item; "karbopq" is a placeholder until the network byte is finalized.
constexpr char kPqBech32Hrp[] = "karbopq";

}  // namespace CryptoNote
