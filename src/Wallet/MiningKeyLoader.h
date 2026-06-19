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

#include <string>

#include "CryptoTypes.h"
#include "Logging/ILogger.h"

namespace CryptoNote {

// Read-only, offline extraction of the classical spend secret from an encrypted
// wallet container, for identity-bound mining. The whole PQ identity (the
// multi-KB ML-DSA-65 spend key and ML-KEM view key) is derived deterministically
// from this 32-byte secret (see deriveMinerPqKeys / PqWallet.h), so it is the one
// root secret the daemon must guard.
//
// Unlike WalletGreen::load, this:
//   - never touches the network and never starts a blockchain synchronizer
//     (so it needs no INode / Dispatcher), and
//   - NEVER mutates the wallet file: no legacy auto-conversion, no upgrade-save.
//
// Only the current FileMappedVector container format (WalletSerializerV2,
// version >= MIN_VERSION) is supported. Legacy wallet files cannot be read here
// without a live node, and converting them in place would mutate the user's
// wallet — so they are refused: upgrade once with simplewallet/greenwallet
// (which migrates to the current format), then mine against the upgraded file.
//
// Returns the spend secret of the primary address (index 0). Throws
// std::system_error (error::WRONG_PASSWORD / WRONG_VERSION / WRONG_STATE / ...)
// on failure. The caller OWNS the returned secret and MUST zeroize it after the
// PQ keys have been derived.
Crypto::SecretKey loadMiningSpendSecret(const std::string& path,
                                        const std::string& password,
                                        Logging::ILogger& logger);

}  // namespace CryptoNote
