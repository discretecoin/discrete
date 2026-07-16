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

#include "PqRecipient.h"

#include <future>
#include <system_error>

#include "AccountNumber.h"
#include "Common/StringTools.h"
#include "PqAddress.h"
#include "PqWallet.h"  // parsePqAddress

namespace CryptoNote {

bool resolvePqRecipient(INode& node, bool testnet, const std::string& s,
                        CryptoPQ::KemPublicKey& viewPub,
                        CryptoPQ::DsaPublicKey& spendPub, uint64_t& subaddrIndexT) {
  subaddrIndexT = 0;

  // 1. A raw PQ address carries both keys directly (subaddress T = 0). Only this
  //    network's HRP is accepted, so a foreign-network address (e.g. a "tdisc…"
  //    testnet address pasted into a mainnet wallet) is rejected here.
  CryptoNote::PqAddress addr;
  if (CryptoNote::decodePqAddress(s, testnet, addr)) {
    viewPub = addr.viewPub;
    spendPub = addr.spendPub;
    return true;
  }

  // 2. An account number, either H-I-A-C (base account, T = 0) or H-I-A-T-C
  //    (deposit subaddress, T = parsed index). BOTH resolve the SAME (H,I)
  //    registration via the node; only the subaddress T differs. The node only
  //    resolves a registration once it is buried past first-seen finality, so a
  //    reorg cannot repoint (H,I) under a payer's feet (finality gate). The A
  //    fingerprint is the belt-and-suspenders failsafe: we recompute it from the
  //    keys the node returned and refuse the number unless it matches the A the
  //    payer typed — even a lying node cannot steer the payment to other keys.
  CryptoNote::AccountNumber acct;
  uint32_t t = 0;
  uint32_t wantFingerprint = 0;
  bool isHitc = CryptoNote::AccountNumber::fromStringWithIndex(s, acct, t, wantFingerprint);
  if (isHitc || CryptoNote::AccountNumber::fromString(s, acct, wantFingerprint)) {
    if (isHitc) subaddrIndexT = t;
    bool found = false;
    std::string viewHex, spendHex;
    std::promise<std::error_code> promise;
    auto future = promise.get_future();
    node.resolvePqAccount(acct.blockHeight, acct.txIndex, found, viewHex, spendHex,
                          [&promise](std::error_code ec) { promise.set_value(ec); });
    if (future.get() || !found) {
      return false;
    }
    size_t sz = 0;
    if (!Common::fromHex(viewHex, viewPub.data(), viewPub.size(), sz) || sz != viewPub.size()) {
      return false;
    }
    if (!Common::fromHex(spendHex, spendPub.data(), spendPub.size(), sz) || sz != spendPub.size()) {
      return false;
    }
    // Failsafe: the on-chain keys must fingerprint to the A embedded in the number.
    const uint32_t gotFingerprint = CryptoNote::pqAccountFingerprint(
        testnet, spendPub.data(), spendPub.size(), viewPub.data(), viewPub.size());
    if (gotFingerprint != wantFingerprint) {
      return false;
    }
    return true;
  }

  return false;
}

}  // namespace CryptoNote
