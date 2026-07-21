// Copyright (c) 2026, The Discrete developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "PqBech32.h"

#include <cstdint>
#include <cstring>
#include <vector>

namespace CryptoNote {
namespace {

constexpr char kCharset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr uint32_t kBech32mConst = 0x2bc830a3u;

uint32_t polymod(const std::vector<uint8_t>& values) {
  static const uint32_t generators[5] = {
      0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u};
  uint32_t checksum = 1;
  for (uint8_t value : values) {
    const uint8_t top = static_cast<uint8_t>(checksum >> 25);
    checksum = ((checksum & 0x1ffffffu) << 5) ^ value;
    for (int i = 0; i < 5; ++i) {
      if ((top >> i) & 1) checksum ^= generators[i];
    }
  }
  return checksum;
}

std::vector<uint8_t> expandHrp(const std::string& hrp) {
  std::vector<uint8_t> expanded;
  expanded.reserve(hrp.size() * 2 + 1);
  for (char c : hrp) expanded.push_back(static_cast<uint8_t>(c) >> 5);
  expanded.push_back(0);
  for (char c : hrp) expanded.push_back(static_cast<uint8_t>(c) & 31);
  return expanded;
}

bool convertBits(std::vector<uint8_t>& out, const uint8_t* in, std::size_t inLen,
                 int fromBits, int toBits, bool pad) {
  uint32_t accumulator = 0;
  int bits = 0;
  const uint32_t maxValue = (1u << toBits) - 1;
  const uint32_t maxAccumulator = (1u << (fromBits + toBits - 1)) - 1;
  for (std::size_t i = 0; i < inLen; ++i) {
    const uint32_t value = in[i];
    if (value >> fromBits) return false;
    accumulator = ((accumulator << fromBits) | value) & maxAccumulator;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push_back(static_cast<uint8_t>((accumulator >> bits) & maxValue));
    }
  }
  if (pad) {
    if (bits) out.push_back(static_cast<uint8_t>((accumulator << (toBits - bits)) & maxValue));
  } else if (bits >= fromBits || ((accumulator << (toBits - bits)) & maxValue)) {
    return false;
  }
  return true;
}

}  // namespace

std::string encodeBech32m(const std::string& hrp, const std::string& payload) {
  if (hrp.empty()) return {};
  std::vector<uint8_t> data;
  if (!convertBits(data, reinterpret_cast<const uint8_t*>(payload.data()),
                   payload.size(), 8, 5, true)) {
    return {};
  }

  std::vector<uint8_t> values = expandHrp(hrp);
  values.insert(values.end(), data.begin(), data.end());
  values.insert(values.end(), 6, 0);
  const uint32_t checksum = polymod(values) ^ kBech32mConst;

  std::string encoded = hrp + "1";
  encoded.reserve(encoded.size() + data.size() + 6);
  for (uint8_t value : data) encoded.push_back(kCharset[value]);
  for (int i = 0; i < 6; ++i) {
    encoded.push_back(kCharset[(checksum >> (5 * (5 - i))) & 31]);
  }
  return encoded;
}

bool decodeBech32m(const std::string& encoded, const std::string& expectedHrp,
                   std::string& payload) {
  const std::size_t separator = encoded.rfind('1');
  if (separator == std::string::npos || separator == 0 ||
      separator + 7 > encoded.size() || encoded.substr(0, separator) != expectedHrp) {
    return false;
  }

  std::vector<uint8_t> data;
  data.reserve(encoded.size() - separator - 1);
  for (std::size_t i = separator + 1; i < encoded.size(); ++i) {
    const char* found = std::strchr(kCharset, encoded[i]);
    if (found == nullptr || encoded[i] == '\0') return false;
    data.push_back(static_cast<uint8_t>(found - kCharset));
  }

  std::vector<uint8_t> values = expandHrp(expectedHrp);
  values.insert(values.end(), data.begin(), data.end());
  if (polymod(values) != kBech32mConst) return false;

  data.resize(data.size() - 6);
  std::vector<uint8_t> bytes;
  if (!convertBits(bytes, data.data(), data.size(), 5, 8, false)) return false;
  payload.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  return true;
}

}  // namespace CryptoNote
