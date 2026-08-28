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

#include <cctype>
#include <cstddef>
#include <future>
#include <system_error>

#include "AccountNumber.h"
#include "Common/StringTools.h"
#include "PqAddress.h"
#include "PqWallet.h"  // parsePqAddress

namespace CryptoNote {

const char* const kUntrustedResolverMessage =
    "Account numbers can only be resolved by a trusted daemon. Use the full "
    "address instead, connect to your own daemon, or use verified HTTPS and "
    "pass --trusted-daemon if you trust this one. Remote resolvers reached over "
    "plain HTTP, or with certificate verification disabled, are not trusted.";

namespace {
// Both sides are hex, but only one of them is ours; the daemon's casing is not
// ours to assume.
bool sameHex(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

bool fail(std::string* error, const char* message) {
  if (error != nullptr) {
    *error = message;
  }
  return false;
}
}  // namespace

bool resolvePqRecipient(INode& node, bool testnet, const std::string& s,
                        CryptoPQ::KemPublicKey& viewPub,
                        CryptoPQ::DsaPublicKey& spendPub, uint64_t& subaddrIndexT,
                        std::string* error) {
  subaddrIndexT = 0;
  if (error != nullptr) {
    error->clear();
  }

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
  //    reorg cannot repoint (H,I) under a payer's feet (finality gate).
  //
  //    The A fingerprint is recomputed from the keys the node returned and the
  //    number is refused unless it matches. That covers a typo or a reorg, but a
  //    short fingerprint is a failsafe, not an authentication of the responder,
  //    so an untrusted resolver is refused above rather than checked here.
  CryptoNote::AccountNumber acct;
  uint32_t t = 0;
  uint32_t wantFingerprint = 0;
  bool isHitc = CryptoNote::AccountNumber::fromStringWithIndex(s, acct, t, wantFingerprint);
  if (isHitc || CryptoNote::AccountNumber::fromString(s, acct, wantFingerprint)) {
    // Fail closed BEFORE the lookup, and so before any output is constructed.
    // Resolution takes the recipient keys from whoever answers, so it is only
    // performed against a resolver the user has trusted.
    if (!node.isTrustedResolver()) {
      return fail(error, kUntrustedResolverMessage);
    }
    if (isHitc) subaddrIndexT = t;
    bool found = false;
    std::string viewHex, spendHex;
    std::promise<std::error_code> promise;
    auto future = promise.get_future();
    node.resolvePqAccount(acct.blockHeight, acct.txIndex, found, viewHex, spendHex,
                          [&promise](std::error_code ec) { promise.set_value(ec); });
    if (future.get() || !found) {
      return fail(error, "No account is registered at that account number.");
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
      return fail(error,
                  "The account number's fingerprint does not match the keys on chain. "
                  "Check the number, and do not send to it.");
    }
    return true;
  }

  return fail(error, "Not a valid address or account number.");
}

// ---------------------------------------------------------------------------

PqAccountPublication lookupOwnPqAccount(INode& node,
                                        const std::string& viewPubHex,
                                        const std::string& spendPubHex,
                                        uint32_t& blockHeight, uint32_t& txIndex) {
  blockHeight = 0;
  txIndex = 0;

  if (viewPubHex.empty() || spendPubHex.empty()) {
    return PqAccountPublication::NotRegistered;  // tracking wallet: no identity to publish
  }

  // Fail closed BEFORE the query, exactly as the payer side does before a
  // resolution. Whatever this daemon answers becomes what the user hands out.
  if (!node.isTrustedResolver()) {
    return PqAccountPublication::UntrustedResolver;
  }

  bool registered = false;
  uint32_t h = 0, i = 0;
  {
    std::promise<std::error_code> promise;
    auto future = promise.get_future();
    node.getPqAccount(viewPubHex, spendPubHex, registered, h, i,
                      [&promise](std::error_code ec) { promise.set_value(ec); });
    if (future.get()) {
      return PqAccountPublication::QueryFailed;
    }
  }
  if (!registered) {
    return PqAccountPublication::NotRegistered;
  }

  // Ask what those coordinates actually resolve to. The daemon is trusted, so
  // this is not the defence against a lying daemon -- it is the payability gate:
  // resolution is refused until the registration is buried past first-seen
  // finality, so a number that does not resolve yet must not be published as if
  // it were payable. Comparing the full keys, never the 20-bit fingerprint.
  bool found = false;
  std::string gotViewHex, gotSpendHex;
  {
    std::promise<std::error_code> promise;
    auto future = promise.get_future();
    node.resolvePqAccount(h, i, found, gotViewHex, gotSpendHex,
                          [&promise](std::error_code ec) { promise.set_value(ec); });
    if (future.get()) {
      return PqAccountPublication::QueryFailed;
    }
  }
  if (!found) {
    return PqAccountPublication::NotYetPayable;
  }
  if (!sameHex(gotViewHex, viewPubHex) || !sameHex(gotSpendHex, spendPubHex)) {
    return PqAccountPublication::Mismatch;
  }

  blockHeight = h;
  txIndex = i;
  return PqAccountPublication::Ok;
}

const char* pqAccountPublicationMessage(PqAccountPublication status) {
  switch (status) {
    case PqAccountPublication::Ok:
      return "";
    case PqAccountPublication::NotRegistered:
      return "No account number registered yet. Use 'register', then re-check once "
             "it is confirmed.";
    case PqAccountPublication::NotYetPayable:
      return "Your registration is on chain but not yet deep enough for anyone to "
             "pay it. Re-check in a few blocks; share your full address meanwhile.";
    case PqAccountPublication::UntrustedResolver:
      return "Your account number can only be looked up through a trusted daemon: "
             "whichever daemon answers decides the number you would hand out. "
             "Connect to your own daemon, or use verified HTTPS and pass "
             "--trusted-daemon if you trust this one. Your full address is "
             "unaffected and always safe to share.";
    case PqAccountPublication::Mismatch:
      return "The daemon reported an account number that does not resolve back to "
             "this wallet's keys. Nothing was shown; share your full address and "
             "check which daemon you are connected to.";
    case PqAccountPublication::QueryFailed:
      return "Could not reach the daemon to look up your account number.";
  }
  return "Could not look up your account number.";
}

}  // namespace CryptoNote
