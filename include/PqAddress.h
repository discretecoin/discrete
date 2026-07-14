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

#include "crypto_pq/PqKem.h"
#include "crypto_pq/PqDsa.h"

// PQ address (spec §3, amended). CEMENTED v2 surface — the layout and checksum
// never change. The string encoding uses the Bech32m checksum and alphabet but
// deliberately exceeds BIP-173's 90-character profile because PQ public keys
// make the payload ~3.1 KiB. It is therefore an extended Bech32m-derived
// transport, not a BIP-350 Bitcoin address. Its human-readable part identifies the network
// (mainnet "disc", testnet "tdisc"), so addresses are self-describing.
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

// Build an address from its parts, filling version=1 and the derived checksum.
PqAddress makePqAddress(uint64_t networkPrefix,
                        const CryptoPQ::KemPublicKey& viewPub,
                        const CryptoPQ::DsaPublicKey& spendPub);

// The 4-byte checksum over (version || varint(networkPrefix) || viewPub).
std::array<uint8_t, 4> pqAddressChecksum(const PqAddress& addr);

// The bech32m human-readable part, which also tags the network. Mainnet uses
// "disc", testnet "tdisc", so a testnet address can't be mistaken for mainnet.
constexpr char kPqBech32HrpMainnet[] = "disc";
constexpr char kPqBech32HrpTestnet[] = "tdisc";

// The HRP for a given network. Encode call-sites pass pqBech32Hrp(isTestnet()).
inline const char* pqBech32Hrp(bool testnet) {
  return testnet ? kPqBech32HrpTestnet : kPqBech32HrpMainnet;
}

// Encode to an extended Bech32m-derived string under the given HRP. The stored checksum is ignored
// and recomputed so callers can't accidentally emit a stale checksum.
std::string encodePqAddress(const PqAddress& addr,
                            const std::string& hrp = kPqBech32HrpMainnet);

// Decode and verify. Accepts either known Discrete HRP (mainnet or testnet);
// anything else fails the bech32m checksum. Returns false on malformed input,
// wrong length, or a checksum mismatch. On success, out is fully populated.
//
// NOTE: this form does NOT enforce which network the address belongs to (it is
// used by network-agnostic paths such as message-signature verification). A
// send path must use the network-restricted overload below — the embedded
// numeric networkPrefix is identical on mainnet and testnet, so only the HRP
// distinguishes them.
bool decodePqAddress(const std::string& str, PqAddress& out);

// Decode and verify, accepting ONLY the HRP for the given network (testnet ?
// "tdisc" : "disc"). An address from the other network is rejected even though
// its bech32m checksum is valid — this is what stops a mainnet wallet from
// paying a testnet "tdisc1…" address (and vice versa).
bool decodePqAddress(const std::string& str, bool testnet, PqAddress& out);

}  // namespace CryptoNote
