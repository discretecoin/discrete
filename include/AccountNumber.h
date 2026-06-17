// Copyright (c) 2016-2026, The Karbo developers
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

#include <cstdint>
#include <string>

namespace CryptoNote {

struct AccountNumber {
  uint32_t blockHeight;
  uint32_t txIndex;

  uint64_t toUint64() const {
    return (static_cast<uint64_t>(blockHeight) << 32) | static_cast<uint64_t>(txIndex);
  }

  static AccountNumber fromUint64(uint64_t packed) {
    return { static_cast<uint32_t>(packed >> 32), static_cast<uint32_t>(packed & 0xFFFFFFFF) };
  }

  std::string toString() const {
    std::string digits = std::to_string(blockHeight) + std::to_string(txIndex);
    char check = luhnMod36Generate(digits);
    return std::to_string(blockHeight) + "-" + std::to_string(txIndex) + "-" + check;
  }

  static bool fromString(const std::string& str, AccountNumber& out) {
    // Format: H-I-C
    size_t dash1 = str.find('-');
    if (dash1 == std::string::npos) return false;

    size_t dash2 = str.find('-', dash1 + 1);
    if (dash2 == std::string::npos) return false;

    std::string hStr = str.substr(0, dash1);
    std::string iStr = str.substr(dash1 + 1, dash2 - dash1 - 1);
    std::string cStr = str.substr(dash2 + 1);

    if (hStr.empty() || iStr.empty() || cStr.size() != 1) return false;

    // Validate H and I are numeric
    for (char c : hStr) { if (c < '0' || c > '9') return false; }
    for (char c : iStr) { if (c < '0' || c > '9') return false; }

    uint64_t h, i;
    try {
      h = std::stoull(hStr);
      i = std::stoull(iStr);
    } catch (...) {
      return false;
    }

    if (h > UINT32_MAX || i > UINT32_MAX) return false;

    // Validate check character
    std::string digits = hStr + iStr;
    char expectedCheck = luhnMod36Generate(digits);
    char actualCheck = static_cast<char>(std::toupper(static_cast<unsigned char>(cStr[0])));
    if (actualCheck != expectedCheck) return false;

    out.blockHeight = static_cast<uint32_t>(h);
    out.txIndex = static_cast<uint32_t>(i);
    return true;
  }

  // --- H-I-T-C: deposit subaddress of this account (Spec 2 / KRB-ACCT-SPEC-002) -
  // A deposit address is the base account (H-I = one ML-KEM view + one ML-DSA
  // spend key) plus a subaddress index T. T is NOT a key: spend authority reads
  // only H-I, while T routes attribution and is recovered from the output by
  // decapsulation (no lookup table). The check char C is Luhn mod-36 over the
  // concatenated decimal digits of H, I and T, so a transcription typo in any
  // field is caught. "H-I-T-C" (3 dashes) is distinct from the base "H-I-C"
  // (2 dashes), so the two never alias.
  std::string toStringWithIndex(uint32_t subaddrIndex) const {
    std::string digits = std::to_string(blockHeight) + std::to_string(txIndex) +
                         std::to_string(subaddrIndex);
    char check = luhnMod36Generate(digits);
    return std::to_string(blockHeight) + "-" + std::to_string(txIndex) + "-" +
           std::to_string(subaddrIndex) + "-" + check;
  }

  static bool fromStringWithIndex(const std::string& str, AccountNumber& out,
                                  uint32_t& subaddrIndex) {
    // Format: H-I-T-C (exactly three dashes).
    size_t dash1 = str.find('-');
    if (dash1 == std::string::npos) return false;
    size_t dash2 = str.find('-', dash1 + 1);
    if (dash2 == std::string::npos) return false;
    size_t dash3 = str.find('-', dash2 + 1);
    if (dash3 == std::string::npos) return false;
    if (str.find('-', dash3 + 1) != std::string::npos) return false;  // no 4th field

    std::string hStr = str.substr(0, dash1);
    std::string iStr = str.substr(dash1 + 1, dash2 - dash1 - 1);
    std::string tStr = str.substr(dash2 + 1, dash3 - dash2 - 1);
    std::string cStr = str.substr(dash3 + 1);

    if (hStr.empty() || iStr.empty() || tStr.empty() || cStr.size() != 1) return false;
    for (char c : hStr) { if (c < '0' || c > '9') return false; }
    for (char c : iStr) { if (c < '0' || c > '9') return false; }
    for (char c : tStr) { if (c < '0' || c > '9') return false; }

    uint64_t h, i, t;
    try {
      h = std::stoull(hStr);
      i = std::stoull(iStr);
      t = std::stoull(tStr);
    } catch (...) {
      return false;
    }
    if (h > UINT32_MAX || i > UINT32_MAX || t > UINT32_MAX) return false;

    std::string digits = hStr + iStr + tStr;
    char expectedCheck = luhnMod36Generate(digits);
    char actualCheck = static_cast<char>(std::toupper(static_cast<unsigned char>(cStr[0])));
    if (actualCheck != expectedCheck) return false;

    out.blockHeight = static_cast<uint32_t>(h);
    out.txIndex = static_cast<uint32_t>(i);
    subaddrIndex = static_cast<uint32_t>(t);
    return true;
  }

private:
  static const char* alphabet() {
    return "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  }

  static int charToCode(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    return -1;
  }

  // Luhn mod 36: compute check character for input string of digits
  static char luhnMod36Generate(const std::string& input) {
    const int n = 36;
    int sum = 0;
    // Process from right to left; first char from right gets factor 2
    bool doubleFlag = true;
    for (int idx = static_cast<int>(input.size()) - 1; idx >= 0; --idx) {
      int codePoint = charToCode(input[idx]);
      if (codePoint < 0) return '?';

      if (doubleFlag) {
        codePoint *= 2;
        if (codePoint >= n) {
          codePoint = (codePoint / n) + (codePoint % n);
        }
      }
      sum += codePoint;
      doubleFlag = !doubleFlag;
    }
    int remainder = sum % n;
    int checkCodePoint = (n - remainder) % n;
    return alphabet()[checkCodePoint];
  }
};

} // namespace CryptoNote
