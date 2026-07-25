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

// DNS checkpoint discovery, pointer form. The normative spec — TXT format, JSON
// schema, signed payload, publishing workflow, and migration notes — lives in the
// DNS_CHECKPOINT_SIGNERS comment block in CryptoNoteConfig.h.
//
// The DNS TXT record is a small pointer:
//   v=1;alg=sha256;height=<H>;hash=<sha256_hex_of_file>;url=https://discrete.cash/checkpoints/<H>.json
// The full signed checkpoint — including the ~3.3 KB ML-DSA-65 signature that
// cannot fit a 4096-wire-byte TXT record in any encoding — lives in the JSON
// file the pointer references. This header holds the PURE (no-I/O) half of the
// scheme: pointer parsing, canonical serialization, the signed-payload string,
// and file verification. The HTTPS fetch lives in CheckpointDownloader.

#include <cstdint>
#include <string>
#include <vector>

#include "CryptoTypes.h"
#include "crypto_pq/PqDsa.h"

namespace CryptoNote {

// The one HTTPS host checkpoint files are ever fetched from. The pointer's URL is
// rejected if its host differs (defends against a tampered TXT record pointing a
// syncing node at an attacker-controlled file).
constexpr char kCheckpointHost[] = "discrete.cash";

// Domain-separated, genesis-bound signing prefix. Bump the version suffix if the
// payload layout below ever changes.
constexpr char kCheckpointSignedPayloadPrefix[] = "discrete-dns-checkpoint-v1";

// Signature algorithm identifier written into (and required by) the JSON file.
constexpr char kCheckpointSigAlg[] = "ML-DSA-65";

enum class CheckpointStatus { Accepted, Malformed, BadSignature };

// Parsed TXT pointer.
struct CheckpointPointer {
  uint32_t    version = 0;      // must be 1
  std::string alg;              // must be "sha256"
  uint32_t    height = 0;
  std::string sha256Hex;        // 64 lowercase hex — SHA-256 of the exact file bytes
  std::string url;              // full https URL as published
  std::string host;             // parsed host (validated == kCheckpointHost)
  std::string path;             // parsed request path, e.g. /checkpoints/123.json
};

// Parsed / verified checkpoint JSON.
struct CheckpointRecord {
  uint32_t     version = 0;
  std::string  network;         // "mainnet" | "testnet"
  uint32_t     height = 0;
  Crypto::Hash blockHash{};
  std::string  sigAlg;          // "ML-DSA-65"
  std::string  keyId;           // advisory 8-hex signer fingerprint
  std::string  signature;       // base58, as produced by signMessagePq
};

// Parse and validate a DNS TXT pointer string. Enforces v=1, alg=sha256, a
// 64-hex file hash, an https URL whose host == kCheckpointHost, and a
// "<height>.json" filename that matches the pointer height. Returns false and
// sets `reject` on any failure.
bool parseCheckpointPointer(const std::string& txt, CheckpointPointer& out,
                            std::string& reject);

// The canonical string handed to signMessagePq / verifyMessagePq:
//   "discrete-dns-checkpoint-v1:<genesis_hex>:<network>:<height>:<block_hash_hex>"
// The genesis hash binds the record to exactly one chain; network + the versioned
// prefix add format/domain separation so a signature can't be reused elsewhere.
std::string buildCheckpointSignedPayload(const std::string& genesisHex,
                                         const std::string& network,
                                         uint32_t height,
                                         const std::string& blockHashHex);

// Deterministic canonical JSON bytes for publishing (UTF-8, no BOM, compact,
// fixed field order, no trailing newline). The publisher hashes exactly these
// bytes; verification hashes the raw downloaded bytes, so only the publisher
// must produce canonical output.
std::string serializeCheckpointJsonCanonical(const CheckpointRecord& rec);

// Advisory key_id: first 8 hex chars of SHA3-256(signer spend pubkey).
std::string checkpointKeyId(const CryptoPQ::DsaPublicKey& spendPub);

// SHA-256 of arbitrary bytes, as 64 lowercase hex chars.
std::string sha256Hex(const std::string& bytes);

// Verify a downloaded checkpoint file end to end:
//   1. SHA-256(fileBytes) == ptr.sha256Hex
//   2. JSON parses and matches the schema/version
//   3. json.height == ptr.height and json.network == expectedNetwork
//   4. the signature verifies against ANY of signerSpendPubs (any-of-N)
// On Accepted, `out` is populated. `reject` carries the reason otherwise.
CheckpointStatus verifyCheckpointFile(
    const std::string& fileBytes,
    const CheckpointPointer& ptr,
    const std::vector<CryptoPQ::DsaPublicKey>& signerSpendPubs,
    const Crypto::Hash& genesisBlockHash,
    const std::string& expectedNetwork,
    CheckpointRecord& out,
    std::string& reject);

}  // namespace CryptoNote
