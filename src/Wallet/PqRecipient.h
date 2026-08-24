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

#include <cstdint>
#include <string>

#include "INode.h"
#include "crypto_pq/PqKem.h"
#include "crypto_pq/PqDsa.h"

// The single recipient-string resolver shared by every front-end (simplewallet,
// greenwallet, walletd). It turns a user-supplied destination into the view+spend
// public keys plus the deposit subaddress index T, so the send path never has to
// duplicate (and risk diverging on) address/account-number parsing.

namespace CryptoNote {

// Resolve `s` into recipient keys + subaddress index T. Accepts:
//   - a raw bech32m PQ address — keys carried directly, T = 0;
//   - an H-I-A-C account number — base account resolved via the node, T = 0;
//   - an H-I-A-T-C deposit subaddress — same account resolved via the node, T = parsed.
// Account-number forms block on `node` for the registry lookup. Returns false if `s`
// is not a valid PQ recipient or the referenced account is not registered.
//
// `testnet` selects which address HRP is accepted (testnet "tdisc" vs mainnet
// "disc"); a raw address for the other network is rejected, so a wallet can't
// pay a foreign-network address. Pass currency.isTestnet().
// An account number is resolved by the daemon, which therefore chooses the keys
// the payment goes to; the A fingerprint is a transcription failsafe, not an
// authentication of the responder. Resolution is refused outright on a daemon
// the user has not trusted, before any output is built. `error`, when given, receives a message suitable for showing to the
// user. Raw addresses carry both keys and are always accepted.
extern const char* const kUntrustedResolverMessage;

bool resolvePqRecipient(INode& node, bool testnet, const std::string& s,
                        CryptoPQ::KemPublicKey& viewPub,
                        CryptoPQ::DsaPublicKey& spendPub,
                        uint64_t& subaddrIndexT,
                        std::string* error = nullptr);

}  // namespace CryptoNote
