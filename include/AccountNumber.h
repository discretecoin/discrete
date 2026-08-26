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

#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>

namespace CryptoNote {

// Account number — a short, human-readable reference to an on-chain PQ account
// registration. Two forms (see docs/wallets/account-numbers.md):
//
//   H-I-A-C      base account         e.g.  4821-7-KQ9D-X
//   H-I-A-T-C    deposit subaddress   e.g.  4821-7-KQ9D-3-X
//
//   H = registration block height (decimal)
//   I = registration transaction index within that block (decimal)
//   A = 20-bit fingerprint of the account's public keys, 4 Crockford-Base32 chars.
//   T = deposit subaddress routing index (decimal); present in the deposit form only.
//   C = one Crockford-Base32 check char (Luhn mod-32 over the symbols of H, I, A[, T]).
//
// A is the reorg FAILSAFE. (H, I) is only a pointer into chain state; a chain
// reorg that repoints (H, I) to a different registration would otherwise silently
// change who a payment resolves to. A binds the number to the actual keys: a
// resolver recomputes A from the on-chain keys (pqAccountFingerprint(), see
// PqAddress.h) and refuses the payment if it does not match the A the payer typed.
//
// A is short by design: decisive against an accidental or reorg mismatch
// (~1/1,048,576), but a failsafe rather than an authentication of the party that
// answers the lookup. Wallets therefore resolve a compact number only through a
// daemon the user has trusted; see Common/DaemonTrust.h. Full Bech32m addresses
// carry both keys and are safe through any daemon.
//
// The whole number uses only Crockford-Base32-safe symbols (digits plus letters,
// excluding the ambiguous I, L, O, U), so 0/O and 1/I/L can never be confused. The
// check char is likewise Crockford, so it too is unambiguous. Decoding of A and C
// is lenient (I,L -> 1 ; O -> 0 ; case-insensitive).
//
// This header stays free of crypto dependencies: it only ENCODES/DECODES the 20-bit
// fingerprint value. The value itself is produced from the keys by
// pqAccountFingerprint() and threaded in by callers.

struct AccountNumber {
  uint32_t blockHeight;
  uint32_t txIndex;

  uint64_t toUint64() const {
    return (static_cast<uint64_t>(blockHeight) << 32) | static_cast<uint64_t>(txIndex);
  }

  static AccountNumber fromUint64(uint64_t packed) {
    return { static_cast<uint32_t>(packed >> 32), static_cast<uint32_t>(packed & 0xFFFFFFFF) };
  }

  // --- base account: H-I-A-C ---------------------------------------------------
  // `fingerprint` is the 20-bit key fingerprint (0..0xFFFFF) from pqAccountFingerprint().
  std::string toString(uint32_t fingerprint) const {
    const std::string h = std::to_string(blockHeight);
    const std::string i = std::to_string(txIndex);
    const std::string a = encodeFingerprint(fingerprint);
    const char c = luhn32Generate(h + i + a);
    return h + "-" + i + "-" + a + "-" + std::string(1, c);
  }

  // Parse H-I-A-C (exactly three dashes). On success `fingerprint` receives the
  // parsed 20-bit A so the caller can compare it to pqAccountFingerprint(resolved keys).
  static bool fromString(const std::string& str, AccountNumber& out, uint32_t& fingerprint) {
    std::string hStr, iStr, aStr, cStr;
    if (!splitFields(str, /*dashes*/ 3, hStr, iStr, aStr, cStr, /*tStr*/ nullptr)) return false;
    return finalize(hStr, iStr, aStr, cStr, /*tStr*/ nullptr, out, fingerprint, /*subaddr*/ nullptr);
  }

  // Convenience overload for syntactic-validity checks that don't need the fingerprint.
  static bool fromString(const std::string& str, AccountNumber& out) {
    uint32_t fp = 0;
    return fromString(str, out, fp);
  }

  // --- deposit subaddress: H-I-A-T-C -------------------------------------------
  std::string toStringWithIndex(uint32_t subaddrIndex, uint32_t fingerprint) const {
    const std::string h = std::to_string(blockHeight);
    const std::string i = std::to_string(txIndex);
    const std::string a = encodeFingerprint(fingerprint);
    const std::string t = std::to_string(subaddrIndex);
    const char c = luhn32Generate(h + i + a + t);
    return h + "-" + i + "-" + a + "-" + t + "-" + std::string(1, c);
  }

  // Parse H-I-A-T-C (exactly four dashes).
  static bool fromStringWithIndex(const std::string& str, AccountNumber& out,
                                  uint32_t& subaddrIndex, uint32_t& fingerprint) {
    std::string hStr, iStr, aStr, tStr, cStr;
    if (!splitFields(str, /*dashes*/ 4, hStr, iStr, aStr, cStr, &tStr)) return false;
    return finalize(hStr, iStr, aStr, cStr, &tStr, out, fingerprint, &subaddrIndex);
  }

  static bool fromStringWithIndex(const std::string& str, AccountNumber& out,
                                  uint32_t& subaddrIndex) {
    uint32_t fp = 0;
    return fromStringWithIndex(str, out, subaddrIndex, fp);
  }

  // --- fingerprint (A) codec: 20 bits <-> 4 Crockford-Base32 chars --------------
  static std::string encodeFingerprint(uint32_t fp20) {
    fp20 &= 0xFFFFFu;
    std::string s(4, '0');
    for (int idx = 3; idx >= 0; --idx) {
      s[idx] = crockford()[fp20 & 31u];
      fp20 >>= 5;
    }
    return s;
  }

  static bool decodeFingerprint(const std::string& s, uint32_t& fp20) {
    if (s.size() != 4) return false;
    uint32_t v = 0;
    for (char ch : s) {
      int cv = crockfordVal(ch);
      if (cv < 0) return false;
      v = (v << 5) | static_cast<uint32_t>(cv);
    }
    fp20 = v & 0xFFFFFu;
    return true;
  }

private:
  // Crockford Base32: digits + letters, excluding the ambiguous I, L, O, U.
  static const char* crockford() { return "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; }

  // Lenient Crockford value of a symbol, or -1 if invalid. Accepts the ambiguous
  // look-alikes on input (O->0, I/L->1); U is rejected. Case-insensitive.
  static int crockfordVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    char u = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (u == 'O') return 0;
    if (u == 'I' || u == 'L') return 1;
    const char* p = std::strchr(crockford(), u);
    if (p && u != '\0') return static_cast<int>(p - crockford());
    return -1;
  }

  // Luhn mod 32 over a run of Crockford symbols (decimal digits and A chars are all
  // valid Crockford symbols). Returns one Crockford check char.
  static char luhn32Generate(const std::string& symbols) {
    const int n = 32;
    int sum = 0;
    bool doubleFlag = true;
    for (int idx = static_cast<int>(symbols.size()) - 1; idx >= 0; --idx) {
      int codePoint = crockfordVal(symbols[idx]);
      if (codePoint < 0) return '?';
      if (doubleFlag) {
        codePoint *= 2;
        if (codePoint >= n) codePoint = (codePoint / n) + (codePoint % n);
      }
      sum += codePoint;
      doubleFlag = !doubleFlag;
    }
    int remainder = sum % n;
    int checkCodePoint = (n - remainder) % n;
    return crockford()[checkCodePoint];
  }

  // Split "H-I-A-C" (dashes==3) or "H-I-A-T-C" (dashes==4). When dashes==4 the T
  // field is written through tStr (which must be non-null).
  static bool splitFields(const std::string& str, int dashes,
                          std::string& hStr, std::string& iStr, std::string& aStr,
                          std::string& cStr, std::string* tStr) {
    size_t pos = 0;
    std::string fields[5];
    int count = 0;
    while (true) {
      size_t dash = str.find('-', pos);
      if (dash == std::string::npos) {
        if (count >= 5) return false;
        fields[count++] = str.substr(pos);
        break;
      }
      if (count >= 5) return false;
      fields[count++] = str.substr(pos, dash - pos);
      pos = dash + 1;
    }
    if (count != dashes + 1) return false;  // exact field count -> forms never alias
    hStr = fields[0];
    iStr = fields[1];
    aStr = fields[2];
    if (dashes == 4) {
      if (!tStr) return false;
      *tStr = fields[3];
      cStr = fields[4];
    } else {
      cStr = fields[3];
    }
    return true;
  }

  static bool parseU32Decimal(const std::string& s, uint32_t& out) {
    if (s.empty()) return false;
    for (char c : s) if (c < '0' || c > '9') return false;
    uint64_t v;
    try {
      v = std::stoull(s);
    } catch (...) {
      return false;
    }
    if (v > UINT32_MAX) return false;
    out = static_cast<uint32_t>(v);
    return true;
  }

  static bool finalize(const std::string& hStr, const std::string& iStr,
                       const std::string& aStr, const std::string& cStr,
                       const std::string* tStr, AccountNumber& out,
                       uint32_t& fingerprint, uint32_t* subaddrOut) {
    if (cStr.size() != 1) return false;
    uint32_t h, i, t = 0;
    if (!parseU32Decimal(hStr, h) || !parseU32Decimal(iStr, i)) return false;
    if (tStr && !parseU32Decimal(*tStr, t)) return false;

    uint32_t fp;
    if (!decodeFingerprint(aStr, fp)) return false;
    const std::string aCanon = encodeFingerprint(fp);  // canonicalize (O->0, I/L->1)

    const std::string payload = tStr ? (hStr + iStr + aCanon + *tStr)
                                     : (hStr + iStr + aCanon);
    const char expected = luhn32Generate(payload);
    const int actual = crockfordVal(cStr[0]);
    if (actual < 0 || crockford()[actual] != expected) return false;

    out.blockHeight = h;
    out.txIndex = i;
    fingerprint = fp;
    if (subaddrOut) *subaddrOut = t;
    return true;
  }
};

// Whether a destination string names one specific deposit route, i.e. is in the
// H-I-A-T-C form rather than a base H-I-A-C number or a full address.
//
// Anything that verifies a payment has to know this: a payment proof establishes
// spend authority over an account and commits to nothing about T, so a caller
// that named a route has asked a question the proof cannot answer, and must be
// told no rather than yes. See COMMAND_RPC_CHECK_TRANSACTION_PROOF.
inline bool namesDepositRoute(const std::string& destination) {
  AccountNumber account;
  uint32_t subaddrIndex = 0;
  uint32_t fingerprint = 0;
  return AccountNumber::fromStringWithIndex(destination, account, subaddrIndex, fingerprint);
}

}  // namespace CryptoNote
