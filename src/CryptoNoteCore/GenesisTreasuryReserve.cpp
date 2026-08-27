// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete — a post-quantum-only cryptocurrency.
//
// Discrete is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.

#include "GenesisTreasuryReserve.h"

#include <array>
#include <cstring>
#include <stdexcept>
#include <string>

#include "../Common/StringTools.h"
#include "../CryptoNoteConfig.h"
#include "PqTxType.h"
#include "TransactionExtra.h"
#include "crypto_pq/PqDerive.h"
#include "crypto_pq/PqDsa.h"
#include "crypto_pq/PqHash.h"

namespace CryptoNote {

// Recipient PUBLIC keys (view + spend), one per Treasury Reserve batch.
// AUTO-GENERATED; see https://docs.discrete.cash/#/consensus/genesis. Defines kGenesisTreasuryReserveViewPubHex[]
// / kGenesisTreasuryReserveSpendPubHex[] (GENESIS_TREASURY_RESERVE_BATCHES entries
// each).
#include "GenesisTreasuryReserveKeys.inc"

namespace {

// Genesis coinbase headline, embedded in the coinbase `extra` as a TX_EXTRA_NONCE
// — Discrete's analogue of Bitcoin's "The Times 03/Jan/2009 Chancellor on brink of
// second bailout for banks". It is part of the frozen genesis artifact, so it must
// never change after launch. The em dash is UTF-8 (0xE2 0x80 0x94), matching the
// rest of this UTF-8 source file; the byte length is well under TX_EXTRA_NONCE_MAX_COUNT.
constexpr char kGenesisMessage[] =
    "Reuters 08/Jul/2026 \xE2\x80\x94 Crypto firms prepare defenses as quantum threat to encryption draws nearer";

template <std::size_t N>
std::array<uint8_t, N> decodeFixedHex(const std::string& hex, const char* what) {
  if (hex.empty()) {
    throw std::runtime_error(std::string("Genesis Treasury Reserve recipient key not provisioned (") +
                             what + "). Run: admin-tools --treasury-reserve-accounts and rebuild.");
  }
  std::array<uint8_t, N> out{};
  size_t sz = 0;
  if (!Common::fromHex(hex, out.data(), out.size(), sz) || sz != N) {
    throw std::runtime_error(std::string("Genesis Treasury Reserve recipient key has wrong size (") + what + ")");
  }
  return out;
}

}  // namespace

Transaction buildGenesisTreasuryReserveCoinbase(bool testnet) {
  Transaction tx;
  tx.version = TRANSACTION_VERSION_1;
  tx.txType = TX_COINBASE;
  tx.unlockHeight = 0;  // genesis uses PER-OUTPUT unlockHeights for the batches
  tx.inputs.clear();
  tx.outputs.clear();
  tx.extra.clear();
  tx.pqSignatures.clear();

  // Coinbase input: block height 0.
  BaseInput in;
  in.blockIndex = 0;
  tx.inputs.push_back(in);

  for (uint32_t i = 0; i < GENESIS_TREASURY_RESERVE_BATCHES; ++i) {
    // viewPub is no longer needed; only spendPub determines the ownership commitment.
    auto spendPub = decodeFixedHex<CryptoPQ::kDsaPublicKeyBytes>(
        kGenesisTreasuryReserveSpendPubHex[i], "spendPub");

    // Stripped CoinbaseOutput: rho = coinbaseRho(spendPub, height=0, outputIndex=i).
    // Publicly recomputable by the recipient; no KEM ciphertext or encrypted payload.
    CryptoPQ::Rho cbRho = CryptoPQ::coinbaseRho(spendPub, /*height=*/0, /*outputIndex=*/i);
    CryptoPQ::Hash256 sc = CryptoPQ::spendCommit(spendPub, cbRho);

    CoinbaseOutput co;
    std::memcpy(co.spendCommit.data, sc.data(), 32);

    TransactionOutput out;
    out.amount = GENESIS_TREASURY_RESERVE_BATCH_ATOMS;
    out.unlockHeight = static_cast<uint64_t>(i) * GENESIS_TREASURY_RESERVE_UNLOCK_STEP;
    out.target = std::move(co);
    tx.outputs.push_back(std::move(out));
  }

  // Genesis headline, embedded in the coinbase extra (Bitcoin-style). Frozen.
  std::vector<uint8_t> genesisMessage(
      kGenesisMessage, kGenesisMessage + sizeof(kGenesisMessage) - 1);
  addExtraNonceToTransactionExtra(tx.extra, genesisMessage);

  // Testnet marker, so the two networks do not share a genesis transaction id and
  // therefore do not share genesis outpoints. Written before the identity tag so
  // the mainnet byte layout is untouched.
  if (testnet) {
    std::vector<uint8_t> marker(
        GENESIS_TESTNET_MARKER, GENESIS_TESTNET_MARKER + sizeof(GENESIS_TESTNET_MARKER) - 1);
    addExtraNonceToTransactionExtra(tx.extra, marker);
  }

  // Coinbase identity tag. Genesis is trusted (block signature skipped at height
  // 0), so a fixed all-zero ML-DSA spend pub is used — there is no miner.
  std::array<uint8_t, CryptoPQ::kDsaPublicKeyBytes> zeroMinerSpendPub{};
  addPqMinerSpendPubToExtra(tx.extra, zeroMinerSpendPub);

  return tx;
}

}  // namespace CryptoNote
