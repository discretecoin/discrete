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

#include "DnsCheckpoint.h"

#include <map>
#include <sstream>

#include <openssl/evp.h>

#include "Common/JsonValue.h"
#include "Common/StringTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "crypto_pq/PqHash.h"

namespace CryptoNote {

namespace {

// A clean unsigned integer with no leading sign, whitespace, or trailing junk.
bool parseCleanU32(const std::string& s, uint32_t& out) {
  if (s.empty()) return false;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
  }
  std::istringstream ss(s);
  uint64_t v = 0;
  ss >> v;
  // Overflow sets failbit, so an absurdly long run of digits is rejected here.
  if (ss.fail() || !ss.eof() || v > 0xFFFFFFFFull) return false;
  out = static_cast<uint32_t>(v);
  return true;
}

// 64 lowercase hex chars (a Crypto::Hash / SHA-256 digest in hex).
bool isLower64Hex(const std::string& s) {
  if (s.size() != 64) return false;
  for (char c : s) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

}  // namespace

std::string sha256Hex(const std::string& bytes) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int mdLen = 0;
  // One-shot EVP digest — avoids the deprecated SHA256() convenience symbol.
  EVP_Digest(bytes.data(), bytes.size(), md, &mdLen, EVP_sha256(), nullptr);
  static const char* hexd = "0123456789abcdef";
  std::string out;
  out.reserve(mdLen * 2);
  for (unsigned int i = 0; i < mdLen; ++i) {
    out.push_back(hexd[md[i] >> 4]);
    out.push_back(hexd[md[i] & 0x0F]);
  }
  return out;
}

std::string checkpointKeyId(const CryptoPQ::DsaPublicKey& spendPub) {
  CryptoPQ::Hash256 h = CryptoPQ::sha3_256(spendPub.data(), spendPub.size());
  static const char* hexd = "0123456789abcdef";
  std::string out;
  out.reserve(8);
  for (int i = 0; i < 4; ++i) {
    out.push_back(hexd[h[i] >> 4]);
    out.push_back(hexd[h[i] & 0x0F]);
  }
  return out;
}

std::string buildCheckpointSignedPayload(const std::string& genesisHex,
                                         const std::string& network,
                                         uint32_t height,
                                         const std::string& blockHashHex) {
  std::ostringstream ss;
  ss << kCheckpointSignedPayloadPrefix << ':' << genesisHex << ':' << network
     << ':' << height << ':' << blockHashHex;
  return ss.str();
}

std::string serializeCheckpointJsonCanonical(const CheckpointRecord& rec) {
  // Fixed field order, compact, no trailing newline. Every value comes from a
  // constrained charset (decimal, lowercase hex, base58, or "mainnet"/"testnet"),
  // so no JSON string escaping is required — asserted by the publisher's own
  // re-parse-and-verify step.
  std::ostringstream ss;
  ss << "{\"version\":" << rec.version
     << ",\"network\":\"" << rec.network << "\""
     << ",\"height\":" << rec.height
     << ",\"block_hash\":\"" << Common::podToHex(rec.blockHash) << "\""
     << ",\"signature_algorithm\":\"" << rec.sigAlg << "\""
     << ",\"key_id\":\"" << rec.keyId << "\""
     << ",\"signature\":\"" << rec.signature << "\"}";
  return ss.str();
}

bool parseCheckpointPointer(const std::string& txt, CheckpointPointer& out,
                            std::string& reject) {
  out = CheckpointPointer{};

  // Split "k=v;k=v;..." into a key->value map. Duplicate keys are rejected.
  std::map<std::string, std::string> kv;
  std::string field;
  std::istringstream ss(txt);
  while (std::getline(ss, field, ';')) {
    if (field.empty()) continue;
    const size_t eq = field.find('=');
    if (eq == std::string::npos) {
      reject = "field without '=': " + field;
      return false;
    }
    std::string key = field.substr(0, eq);
    std::string val = field.substr(eq + 1);
    if (!kv.emplace(key, val).second) {
      reject = "duplicate field: " + key;
      return false;
    }
  }

  auto need = [&](const char* k, std::string& dst) -> bool {
    auto it = kv.find(k);
    if (it == kv.end()) {
      reject = std::string("missing field: ") + k;
      return false;
    }
    dst = it->second;
    return true;
  };

  std::string vStr, hStr, hashStr;
  if (!need("v", vStr) || !need("alg", out.alg) || !need("height", hStr) ||
      !need("hash", hashStr) || !need("url", out.url)) {
    return false;
  }

  if (vStr != "1") {
    reject = "unsupported version: " + vStr;
    return false;
  }
  out.version = 1;

  if (out.alg != "sha256") {
    reject = "unsupported hash algorithm: " + out.alg;
    return false;
  }

  if (!parseCleanU32(hStr, out.height)) {
    reject = "height not a clean number: " + hStr;
    return false;
  }

  if (!isLower64Hex(hashStr)) {
    reject = "file hash not 64 lowercase hex";
    return false;
  }
  out.sha256Hex = hashStr;

  // Require HTTPS and split host/path by hand: parseUrlAddress (UrlTools) rejects
  // a path with a filename, so it can't be reused here.
  const std::string scheme = "https://";
  if (out.url.compare(0, scheme.size(), scheme) != 0) {
    reject = "url is not https";
    return false;
  }
  const std::string rest = out.url.substr(scheme.size());
  const size_t slash = rest.find('/');
  if (slash == std::string::npos) {
    reject = "url has no path";
    return false;
  }
  out.host = rest.substr(0, slash);
  out.path = rest.substr(slash);

  if (out.host != kCheckpointHost) {
    reject = "unexpected url host: " + out.host;
    return false;
  }

  // The filename must be "<height>.json" so the URL can't disagree with the
  // pointer height.
  const std::string wantSuffix = "/" + std::to_string(out.height) + ".json";
  if (out.path.size() < wantSuffix.size() ||
      out.path.compare(out.path.size() - wantSuffix.size(), wantSuffix.size(),
                       wantSuffix) != 0) {
    reject = "url filename does not match height";
    return false;
  }

  return true;
}

CheckpointStatus verifyCheckpointFile(
    const std::string& fileBytes,
    const CheckpointPointer& ptr,
    const std::vector<CryptoPQ::DsaPublicKey>& signerSpendPubs,
    const Crypto::Hash& genesisBlockHash,
    const std::string& expectedNetwork,
    CheckpointRecord& out,
    std::string& reject) {
  out = CheckpointRecord{};

  // (1) Hash the exact bytes BEFORE parsing — a mismatch rejects the file without
  // ever handing untrusted JSON to the parser.
  const std::string got = sha256Hex(fileBytes);
  if (got != ptr.sha256Hex) {
    reject = "file hash mismatch (expected " + ptr.sha256Hex + ", got " + got + ")";
    return CheckpointStatus::Malformed;
  }

  // (2) Parse the JSON.
  Common::JsonValue root;
  try {
    root = Common::JsonValue::fromString(fileBytes);
  } catch (const std::exception&) {
    reject = "json parse failed";
    return CheckpointStatus::Malformed;
  }
  if (!root.isObject()) {
    reject = "json root is not an object";
    return CheckpointStatus::Malformed;
  }

  auto getStr = [&](const char* k, std::string& dst) -> bool {
    if (!root.contains(k) || !root(k).isString()) return false;
    dst = root(k).getString();
    return true;
  };
  auto getInt = [&](const char* k, int64_t& dst) -> bool {
    if (!root.contains(k) || !root(k).isInteger()) return false;
    dst = root(k).getInteger();
    return true;
  };

  int64_t version = 0, height = 0;
  std::string blockHashHex;
  if (!getInt("version", version) || !getStr("network", out.network) ||
      !getInt("height", height) || !getStr("block_hash", blockHashHex) ||
      !getStr("signature_algorithm", out.sigAlg) ||
      !getStr("signature", out.signature)) {
    reject = "json missing or wrong-typed required field";
    return CheckpointStatus::Malformed;
  }
  getStr("key_id", out.keyId);  // advisory, optional

  if (version != 1) {
    reject = "unsupported json version: " + std::to_string(version);
    return CheckpointStatus::Malformed;
  }
  out.version = 1;

  if (out.sigAlg != kCheckpointSigAlg) {
    reject = "unsupported signature algorithm: " + out.sigAlg;
    return CheckpointStatus::Malformed;
  }

  if (height < 0 || height > 0xFFFFFFFFll) {
    reject = "json height out of range";
    return CheckpointStatus::Malformed;
  }
  out.height = static_cast<uint32_t>(height);

  // (3) Cross-checks: the file must agree with the pointer and this network.
  if (out.height != ptr.height) {
    reject = "json height " + std::to_string(out.height) +
             " != pointer height " + std::to_string(ptr.height);
    return CheckpointStatus::Malformed;
  }
  if (out.network != expectedNetwork) {
    reject = "wrong network: " + out.network + " (expected " + expectedNetwork + ")";
    return CheckpointStatus::Malformed;
  }
  if (!isLower64Hex(blockHashHex) || !Common::podFromHex(blockHashHex, out.blockHash)) {
    reject = "block_hash not 64 lowercase hex";
    return CheckpointStatus::Malformed;
  }

  // (4) Verify the signature over the genesis-bound canonical payload against any
  // one approved signer.
  const std::string payload = buildCheckpointSignedPayload(
      Common::podToHex(genesisBlockHash), out.network, out.height, blockHashHex);
  for (const auto& spendPub : signerSpendPubs) {
    if (verifyMessagePq(payload, spendPub, out.signature)) {
      // Report the key_id of the signer that actually verified, not the one the
      // file claims: `key_id` is unauthenticated (it sits outside the signed
      // payload), so echoing it back would let a crafted file misattribute an
      // otherwise-valid checkpoint to the wrong maintainer in logs.
      out.keyId = checkpointKeyId(spendPub);
      return CheckpointStatus::Accepted;
    }
  }
  reject = "signature did not match any approved signer";
  return CheckpointStatus::BadSignature;
}

}  // namespace CryptoNote
