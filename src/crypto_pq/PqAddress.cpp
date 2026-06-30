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

#include "PqAddress.h"

#include <cstring>
#include <vector>

#include "crypto_pq/PqHash.h"

namespace CryptoNote {

namespace {

// --- varint (unsigned LEB128) -------------------------------------------
void writeVarint(std::string& s, uint64_t v) {
  while (v >= 0x80) {
    s.push_back(static_cast<char>((v & 0x7f) | 0x80));
    v >>= 7;
  }
  s.push_back(static_cast<char>(v & 0x7f));
}

bool readVarint(const std::string& s, std::size_t& pos, uint64_t& v) {
  v = 0;
  int shift = 0;
  while (pos < s.size()) {
    uint8_t b = static_cast<uint8_t>(s[pos++]);
    if (shift > 63) return false;
    v |= static_cast<uint64_t>(b & 0x7f) << shift;
    if (!(b & 0x80)) return true;
    shift += 7;
  }
  return false;
}

// Bytes hashed for the checksum:
//   version || varint(networkPrefix) || viewPub || spendPub.
std::string checksumPreimage(const PqAddress& addr) {
  std::string m;
  m.push_back(static_cast<char>(addr.version));
  writeVarint(m, addr.networkPrefix);
  m.append(reinterpret_cast<const char*>(addr.viewPub.data()), addr.viewPub.size());
  m.append(reinterpret_cast<const char*>(addr.spendPub.data()), addr.spendPub.size());
  return m;
}

// Full byte payload that the encoder turns into a string.
std::string addressPayload(const PqAddress& addr, const std::array<uint8_t, 4>& chk) {
  std::string p = checksumPreimage(addr);
  p.append(reinterpret_cast<const char*>(chk.data()), chk.size());
  return p;
}

bool parsePayload(const std::string& p, PqAddress& out) {
  std::size_t pos = 0;
  if (p.empty()) return false;
  out.version = static_cast<uint8_t>(p[pos++]);
  if (!readVarint(p, pos, out.networkPrefix)) return false;
  if (p.size() - pos != out.viewPub.size() + out.spendPub.size() + 4) return false;
  std::memcpy(out.viewPub.data(), p.data() + pos, out.viewPub.size());
  pos += out.viewPub.size();
  std::memcpy(out.spendPub.data(), p.data() + pos, out.spendPub.size());
  pos += out.spendPub.size();
  std::memcpy(out.checksum.data(), p.data() + pos, 4);
  // Verify checksum.
  return pqAddressChecksum(out) == out.checksum;
}

// --- bech32m (BIP-350) ---------------------------------------------------
const char* kCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

uint32_t bech32Polymod(const std::vector<uint8_t>& values) {
  static const uint32_t GEN[5] = {0x3b6a57b2u, 0x26508e6du, 0x1ea119fau,
                                  0x3d4233ddu, 0x2a1462b3u};
  uint32_t chk = 1;
  for (uint8_t v : values) {
    uint8_t b = static_cast<uint8_t>(chk >> 25);
    chk = ((chk & 0x1ffffffu) << 5) ^ v;
    for (int i = 0; i < 5; ++i)
      if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

std::vector<uint8_t> hrpExpand(const std::string& hrp) {
  std::vector<uint8_t> r;
  r.reserve(hrp.size() * 2 + 1);
  for (char c : hrp) r.push_back(static_cast<uint8_t>(c) >> 5);
  r.push_back(0);
  for (char c : hrp) r.push_back(static_cast<uint8_t>(c) & 31);
  return r;
}

constexpr uint32_t kBech32mConst = 0x2bc830a3u;

bool convertBits(std::vector<uint8_t>& out, const uint8_t* in, std::size_t inLen,
                 int fromBits, int toBits, bool pad) {
  uint32_t acc = 0;
  int bits = 0;
  const uint32_t maxv = (1u << toBits) - 1;
  const uint32_t maxacc = (1u << (fromBits + toBits - 1)) - 1;
  for (std::size_t i = 0; i < inLen; ++i) {
    uint32_t value = in[i];
    if (value >> fromBits) return false;
    acc = ((acc << fromBits) | value) & maxacc;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
    }
  }
  if (pad) {
    if (bits) out.push_back(static_cast<uint8_t>((acc << (toBits - bits)) & maxv));
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    return false;
  }
  return true;
}

std::string bech32mEncode(const std::string& hrp, const std::string& payload) {
  std::vector<uint8_t> data;
  if (!convertBits(data, reinterpret_cast<const uint8_t*>(payload.data()),
                   payload.size(), 8, 5, true)) {
    return std::string();
  }
  // checksum
  std::vector<uint8_t> values = hrpExpand(hrp);
  values.insert(values.end(), data.begin(), data.end());
  for (int i = 0; i < 6; ++i) values.push_back(0);
  uint32_t polymod = bech32Polymod(values) ^ kBech32mConst;
  std::vector<uint8_t> combined = data;
  for (int i = 0; i < 6; ++i)
    combined.push_back(static_cast<uint8_t>((polymod >> (5 * (5 - i))) & 31));

  std::string out = hrp + "1";
  for (uint8_t v : combined) out.push_back(kCharset[v]);
  return out;
}

bool bech32mDecode(const std::string& str, const std::string& expectedHrp,
                   std::string& payload) {
  std::size_t sep = str.rfind('1');
  if (sep == std::string::npos || sep == 0 || sep + 7 > str.size()) return false;
  std::string hrp = str.substr(0, sep);
  if (hrp != expectedHrp) return false;

  std::vector<uint8_t> data;
  data.reserve(str.size() - sep - 1);
  for (std::size_t i = sep + 1; i < str.size(); ++i) {
    const char* p = std::strchr(kCharset, str[i]);
    if (!p || str[i] == '\0') return false;
    data.push_back(static_cast<uint8_t>(p - kCharset));
  }
  // verify checksum
  std::vector<uint8_t> values = hrpExpand(hrp);
  values.insert(values.end(), data.begin(), data.end());
  if (bech32Polymod(values) != kBech32mConst) return false;

  // strip 6-symbol checksum, convert 5->8
  data.resize(data.size() - 6);
  std::vector<uint8_t> bytes;
  if (!convertBits(bytes, data.data(), data.size(), 5, 8, false)) return false;
  payload.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  return true;
}

}  // namespace

std::array<uint8_t, 4> pqAddressChecksum(const PqAddress& addr) {
  std::string pre = checksumPreimage(addr);
  CryptoPQ::Hash256 h = CryptoPQ::sha3_256(pre.data(), pre.size());
  std::array<uint8_t, 4> chk{};
  std::memcpy(chk.data(), h.data(), 4);
  return chk;
}

PqAddress makePqAddress(uint64_t networkPrefix,
                        const CryptoPQ::KemPublicKey& viewPub,
                        const CryptoPQ::DsaPublicKey& spendPub) {
  PqAddress a;
  a.version = 0x01;
  a.networkPrefix = networkPrefix;
  a.viewPub = viewPub;
  a.spendPub = spendPub;
  a.checksum = pqAddressChecksum(a);
  return a;
}

std::string encodePqAddress(const PqAddress& addr, const std::string& hrp) {
  std::array<uint8_t, 4> chk = pqAddressChecksum(addr);
  std::string payload = addressPayload(addr, chk);
  return bech32mEncode(hrp, payload);
}

bool decodePqAddress(const std::string& str, PqAddress& out) {
  // Accept either known Discrete HRP; the bech32m checksum is computed over the
  // HRP, so any other prefix (a typo, or another coin's address) is rejected.
  std::string payload;
  if (!bech32mDecode(str, kPqBech32HrpMainnet, payload) &&
      !bech32mDecode(str, kPqBech32HrpTestnet, payload)) {
    return false;
  }
  return parsePayload(payload, out);
}

bool decodePqAddress(const std::string& str, bool testnet, PqAddress& out) {
  // Accept ONLY this network's HRP. The numeric networkPrefix embedded in the
  // payload is the same on both networks, so the HRP is the sole discriminator.
  std::string payload;
  if (!bech32mDecode(str, pqBech32Hrp(testnet), payload)) {
    return false;
  }
  return parsePayload(payload, out);
}

}  // namespace CryptoNote
