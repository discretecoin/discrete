// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete — a post-quantum-only cryptocurrency.
//
// Discrete is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.

#pragma once

#include <cstddef>
#include <cstdint>

#include "CryptoNote.h"

// Genesis premine.
//
// The genesis coinbase carries the entire premine allocation as a set of
// per-output-unlocked PqOutputs (one tranche per recipient). Because Discrete
// added a per-output `unlockHeight` to the wire, all staggered tranches fit in
// the single genesis coinbase transaction — so GENESIS_COINBASE_TX_HEX remains
// the one frozen artifact, and the network id (derived elsewhere) stays stable.
//
// The transaction is built DETERMINISTICALLY (deterministic ML-KEM
// encapsulation + seed-derived rho per tranche), so two `--print-genesis-tx`
// runs on any host produce byte-identical hex. Only the recipients' PUBLIC keys
// are baked into GenesisPremine.cpp; the matching mnemonics/secrets live outside
// the repo (see docs/GENESIS.md).

namespace CryptoNote {

// Number of premine tranches baked into the genesis coinbase.
constexpr std::size_t GENESIS_PREMINE_TRANCHES = 14;

// Atoms per tranche. 500,000 XDS at CRYPTONOTE_DISPLAY_DECIMAL_POINT = 2
// (COIN = 100) => 50,000,000 atoms. Total premine = 14 * 500,000 = 7,000,000 XDS
// (700,000,000 atoms).
constexpr uint64_t GENESIS_PREMINE_TRANCHE_ATOMS = UINT64_C(50000000);

// Block-height step between consecutive tranche unlocks. Tranche i (0-based)
// unlocks at height i * STEP: 0, 80000, 160000, ... 1,040,000 (last ≈ 3 years
// at a 90 s target). Tranche 0 (unlockHeight 0) is spendable from genesis.
constexpr uint64_t GENESIS_PREMINE_UNLOCK_STEP = UINT64_C(80000);

// Total premine in atoms (sum of all tranches).
constexpr uint64_t GENESIS_PREMINE_TOTAL_ATOMS =
    GENESIS_PREMINE_TRANCHE_ATOMS * GENESIS_PREMINE_TRANCHES;

// Build the deterministic genesis coinbase transaction (BaseInput at height 0 +
// the GENESIS_PREMINE_TRANCHES premine outputs). Throws std::runtime_error if
// the baked recipient public keys are not yet provisioned.
Transaction buildGenesisPremineCoinbase();

}  // namespace CryptoNote
