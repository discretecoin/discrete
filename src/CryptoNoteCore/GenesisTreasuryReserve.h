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

// Discrete Treasury Reserve.
//
// The genesis coinbase carries the entire Treasury Reserve allocation as a set of
// per-output-unlocked PqOutputs (one batch per recipient). Because Discrete added
// a per-output `unlockHeight` to the wire, all staggered batches fit in the single
// genesis coinbase transaction — so GENESIS_COINBASE_TX_HEX remains the one frozen
// artifact, and the network id (derived elsewhere) stays stable.
//
// The Treasury Reserve is 5% of the 21,000,000 XDS emission ceiling (1,050,000
// XDS). It is not an ICO, private sale, or dev tax: it is a locked reserve that
// unlocks gradually and is limited to development, audits, infrastructure,
// listings, documentation, and grants.
//
// The transaction is built DETERMINISTICALLY (deterministic ML-KEM encapsulation +
// seed-derived rho per batch), so two `--print-genesis-tx` runs on any host
// produce byte-identical hex. Only the recipients' PUBLIC keys are baked into
// GenesisTreasuryReserveKeys.inc; the matching mnemonics/secrets live outside the
// repo (see https://docs.discrete.cash/#/consensus/genesis).

namespace CryptoNote {

// Number of Treasury Reserve batches baked into the genesis coinbase.
constexpr std::size_t GENESIS_TREASURY_RESERVE_BATCHES = 21;

// Atoms per batch. 50,000 XDS at CRYPTONOTE_DISPLAY_DECIMAL_POINT = 2 (COIN = 100)
// => 5,000,000 atoms. Total reserve = 21 * 50,000 = 1,050,000 XDS (105,000,000
// atoms), i.e. 5% of the 21,000,000 XDS ceiling.
constexpr uint64_t GENESIS_TREASURY_RESERVE_BATCH_ATOMS = UINT64_C(5000000);

// Block-height step between consecutive batch unlocks. Batch i (0-based) unlocks
// at height i * STEP. At a 90 s target, 87,600 blocks ≈ one quarter, so the 21
// batches unlock one per quarter: 0, 87,600, ... 1,752,000 (last ≈ 5.0 years).
// Batch 0 (unlockHeight 0) is spendable from genesis.
constexpr uint64_t GENESIS_TREASURY_RESERVE_UNLOCK_STEP = UINT64_C(87600);

// Total Treasury Reserve in atoms (sum of all batches).
constexpr uint64_t GENESIS_TREASURY_RESERVE_TOTAL_ATOMS =
    GENESIS_TREASURY_RESERVE_BATCH_ATOMS * GENESIS_TREASURY_RESERVE_BATCHES;

// Marker appended to the testnet genesis coinbase extra so the two networks do
// not share a genesis transaction.
//
// A TX_PQ spend signature is made over the transaction body, which names the
// outpoints being spent but says nothing about which chain they live on. If both
// networks began from the same genesis transaction they would have the same
// genesis transaction id and therefore the same genesis outpoints, and a
// signature spending one of them would verify on either chain. Differing in the
// enclosing block's nonce is not enough: the outpoints come from the transaction,
// not the block.
//
// This is a mitigation, not domain separation. The real fix is to bind the chain
// identity into the signing transcript, which changes consensus and is scheduled
// for the next protocol upgrade.
constexpr char GENESIS_TESTNET_MARKER[] = "discrete-testnet-genesis-v1";

// Build the deterministic genesis coinbase transaction (BaseInput at height 0 +
// the GENESIS_TREASURY_RESERVE_BATCHES reserve outputs). Throws std::runtime_error
// if the baked recipient public keys are not yet provisioned.
//
// `testnet` appends GENESIS_TESTNET_MARKER to the coinbase extra. The mainnet
// output is unchanged and must stay byte-identical to GENESIS_COINBASE_TX_HEX.
Transaction buildGenesisTreasuryReserveCoinbase(bool testnet = false);

}  // namespace CryptoNote
