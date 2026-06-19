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

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace CryptoNote {

// Canonical Discrete denomination set in atomic units (au). Discrete uses
// CRYPTONOTE_DISPLAY_DECIMAL_POINT = 2 (1 XDS = 100 au), so the smallest unit is
// 1 au = 0.01 XDS. Output amounts decompose into these fixed denominations so the
// on-chain amount universe is uniform across wallets.
//
// FORWARD-COMPAT (cemented count): the future PQ hidden-amounts design commits each
// output to a fixed denomination set and proves membership with a Groth-Kohlweiss
// one-out-of-many proof whose anonymity set is exactly this table — so the COUNT is
// fixed at 64. Adopting the table now (plain-amount stage) means output amounts
// already live in the right universe and need no migration when amounts are hidden.
//
// Layout: 7 decades of 9 entries each (1-9 x 10^0 .. 1-9 x 10^6) = 63, plus the
// 10^7 au cap (= 100,000 XDS) = 64, sorted ascending. Because the floor is the
// atomic unit (1 au), EVERY amount is exactly representable; there is no sub-floor
// dust case. Amounts above the cap are expressed as multiple cap (and lower)
// outputs by the greedy decomposition below.
static constexpr size_t DENOMINATION_COUNT = 64;

static constexpr std::array<uint64_t, DENOMINATION_COUNT> DENOMINATIONS = {{
  // 0.01 .. 0.09 XDS
  UINT64_C(1),        UINT64_C(2),        UINT64_C(3),
  UINT64_C(4),        UINT64_C(5),        UINT64_C(6),
  UINT64_C(7),        UINT64_C(8),        UINT64_C(9),
  // 0.1 .. 0.9 XDS
  UINT64_C(10),       UINT64_C(20),       UINT64_C(30),
  UINT64_C(40),       UINT64_C(50),       UINT64_C(60),
  UINT64_C(70),       UINT64_C(80),       UINT64_C(90),
  // 1 .. 9 XDS
  UINT64_C(100),      UINT64_C(200),      UINT64_C(300),
  UINT64_C(400),      UINT64_C(500),      UINT64_C(600),
  UINT64_C(700),      UINT64_C(800),      UINT64_C(900),
  // 10 .. 90 XDS
  UINT64_C(1000),     UINT64_C(2000),     UINT64_C(3000),
  UINT64_C(4000),     UINT64_C(5000),     UINT64_C(6000),
  UINT64_C(7000),     UINT64_C(8000),     UINT64_C(9000),
  // 100 .. 900 XDS
  UINT64_C(10000),    UINT64_C(20000),    UINT64_C(30000),
  UINT64_C(40000),    UINT64_C(50000),    UINT64_C(60000),
  UINT64_C(70000),    UINT64_C(80000),    UINT64_C(90000),
  // 1,000 .. 9,000 XDS
  UINT64_C(100000),   UINT64_C(200000),   UINT64_C(300000),
  UINT64_C(400000),   UINT64_C(500000),   UINT64_C(600000),
  UINT64_C(700000),   UINT64_C(800000),   UINT64_C(900000),
  // 10,000 .. 90,000 XDS
  UINT64_C(1000000),  UINT64_C(2000000),  UINT64_C(3000000),
  UINT64_C(4000000),  UINT64_C(5000000),  UINT64_C(6000000),
  UINT64_C(7000000),  UINT64_C(8000000),  UINT64_C(9000000),
  // 100,000 XDS cap
  UINT64_C(10000000)
}};

// Smallest canonical denomination (the atomic unit, 1 au = 0.01 XDS).
static constexpr uint64_t MIN_CT_DENOMINATION = DENOMINATIONS[0];
// Largest single canonical denomination (the cap).
static constexpr uint64_t MAX_DENOMINATION = DENOMINATIONS[DENOMINATION_COUNT - 1];

// True if `amount` is exactly one of the canonical denominations.
inline bool isCanonicalDenomination(uint64_t amount) {
  auto it = std::lower_bound(DENOMINATIONS.begin(), DENOMINATIONS.end(), amount);
  return it != DENOMINATIONS.end() && *it == amount;
}

// Index of `amount` in DENOMINATIONS [0..63], or -1 if it is not canonical.
inline int denominationIndex(uint64_t amount) {
  auto it = std::lower_bound(DENOMINATIONS.begin(), DENOMINATIONS.end(), amount);
  if (it != DENOMINATIONS.end() && *it == amount) {
    return static_cast<int>(std::distance(DENOMINATIONS.begin(), it));
  }
  return -1;
}

// Greedy decomposition of `amount` into canonical denominations (descending), so
// the result sums exactly to `amount`. Since 1 au is a denomination, every
// non-zero amount is representable. Throws std::invalid_argument on zero.
// Named distinctly from CryptoNoteTools::decomposeAmount (the generic power-of-10
// splitter) to avoid ambiguity.
inline std::vector<uint64_t> decomposeToDenominations(uint64_t amount) {
  if (amount == 0) {
    throw std::invalid_argument("cannot decompose zero amount");
  }
  std::vector<uint64_t> result;
  uint64_t remaining = amount;
  for (int i = static_cast<int>(DENOMINATION_COUNT) - 1; i >= 0 && remaining > 0; --i) {
    uint64_t denom = DENOMINATIONS[static_cast<size_t>(i)];
    while (remaining >= denom) {
      result.push_back(denom);
      remaining -= denom;
    }
  }
  // remaining is always 0 here (1 au denomination guarantees representability).
  return result;
}

}  // namespace CryptoNote
