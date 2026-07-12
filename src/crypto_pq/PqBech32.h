// Copyright (c) 2026, The Karbo developers
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <string>

namespace CryptoNote {

// Binary-payload bech32m codec used by PQ address and proof artifacts. The
// caller owns the HRP policy; checksum validation alone is not network binding.
std::string encodeBech32m(const std::string& hrp, const std::string& payload);
bool decodeBech32m(const std::string& encoded, const std::string& expectedHrp,
                   std::string& payload);

}  // namespace CryptoNote
