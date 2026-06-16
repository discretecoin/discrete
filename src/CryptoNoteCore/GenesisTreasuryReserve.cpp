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
#include "crypto_pq/PqKem.h"
#include "crypto_pq/PqOutputBuilder.h"

namespace CryptoNote {

// Recipient PUBLIC keys (view + spend), one per Treasury Reserve batch.
// AUTO-GENERATED; see docs/GENESIS.md. Defines kGenesisTreasuryReserveViewPubHex[]
// / kGenesisTreasuryReserveSpendPubHex[] (GENESIS_TREASURY_RESERVE_BATCHES entries
// each).
#include "GenesisTreasuryReserveKeys.inc"

namespace {

// Domain-separated, deterministic per-batch seeds. The ML-KEM encapsulation
// message and the output blinding value rho are both derived from the batch
// index so the whole coinbase reproduces byte-for-byte on any host. These
// domain strings are part of the frozen genesis artifact — do not change.
constexpr char kKemSeedDomain[] = "discrete-genesis-kem-v1";
constexpr char kRhoSeedDomain[] = "discrete-genesis-rho-v1";

// Genesis coinbase headline, embedded in the coinbase `extra` as a TX_EXTRA_NONCE
// — Discrete's analogue of Bitcoin's "The Times 03/Jan/2009 Chancellor on brink of
// second bailout for banks". It is part of the frozen genesis artifact, so it must
// never change after launch. The em dash is UTF-8 (0xE2 0x80 0x94), matching the
// rest of this UTF-8 source file; the byte length is well under TX_EXTRA_NONCE_MAX_COUNT.
constexpr char kGenesisMessage[] =
    "Reuters 16/Jun/2026 \xE2\x80\x94 France to stop certifying products without quantum-safe encryption";

CryptoPQ::Hash256 batchSeed(const char* domain, std::size_t domainLen, uint32_t i) {
  uint8_t ikm[4];
  for (int b = 0; b < 4; ++b) ikm[b] = static_cast<uint8_t>((i >> (8 * b)) & 0xFF);
  return CryptoPQ::hkdf_sha3_256(ikm, sizeof(ikm), domain, domainLen);
}

template <std::size_t N>
std::array<uint8_t, N> decodeFixedHex(const std::string& hex, const char* what) {
  if (hex.empty()) {
    throw std::runtime_error(std::string("Genesis Treasury Reserve recipient key not provisioned (") +
                             what + "). Run: vanitygen --treasury-reserve-accounts and rebuild.");
  }
  std::array<uint8_t, N> out{};
  size_t sz = 0;
  if (!Common::fromHex(hex, out.data(), out.size(), sz) || sz != N) {
    throw std::runtime_error(std::string("Genesis Treasury Reserve recipient key has wrong size (") + what + ")");
  }
  return out;
}

}  // namespace

Transaction buildGenesisTreasuryReserveCoinbase() {
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

  // Coinbase inputsHash is zeros (no prior outpoints) — same convention the
  // miner coinbase and the scanner use.
  const CryptoPQ::Hash256 inputsHash{};

  for (uint32_t i = 0; i < GENESIS_TREASURY_RESERVE_BATCHES; ++i) {
    auto viewPub = decodeFixedHex<CryptoPQ::kKemPublicKeyBytes>(
        kGenesisTreasuryReserveViewPubHex[i], "viewPub");
    auto spendPub = decodeFixedHex<CryptoPQ::kDsaPublicKeyBytes>(
        kGenesisTreasuryReserveSpendPubHex[i], "spendPub");

    CryptoPQ::Hash256 kemSeed = batchSeed(kKemSeedDomain, sizeof(kKemSeedDomain) - 1, i);
    CryptoPQ::Rho      rho     = batchSeed(kRhoSeedDomain, sizeof(kRhoSeedDomain) - 1, i);

    // Deterministic encapsulation against this recipient's view key. The result
    // is a real ciphertext the recipient decapsulates normally; it is just
    // reproducible because the encaps randomness comes from kemSeed.
    auto enc = CryptoPQ::kem_encaps_derand(viewPub, kemSeed);

    CryptoPQ::PqBuiltOutput built = CryptoPQ::buildPqOutput(
        enc.first, enc.second, spendPub, inputsHash, /*outputIndex=*/i,
        GENESIS_TREASURY_RESERVE_BATCH_ATOMS, rho, /*T=*/0);

    PqOutput po;
    po.kemCt.assign(built.kemCt.begin(), built.kemCt.end());
    po.encPayload = built.encPayload;
    std::memcpy(po.spendCommit.data, built.spendCommit.data(), 32);

    TransactionOutput out;
    out.amount = GENESIS_TREASURY_RESERVE_BATCH_ATOMS;
    out.unlockHeight = static_cast<uint64_t>(i) * GENESIS_TREASURY_RESERVE_UNLOCK_STEP;
    out.target = std::move(po);
    tx.outputs.push_back(std::move(out));
  }

  // Genesis headline, embedded in the coinbase extra (Bitcoin-style). Frozen.
  std::vector<uint8_t> genesisMessage(
      kGenesisMessage, kGenesisMessage + sizeof(kGenesisMessage) - 1);
  addExtraNonceToTransactionExtra(tx.extra, genesisMessage);

  // Coinbase identity tag. Genesis is trusted (block signature skipped at height
  // 0), so a fixed all-zero ML-DSA spend pub is used — there is no miner.
  std::array<uint8_t, CryptoPQ::kDsaPublicKeyBytes> zeroMinerSpendPub{};
  addPqMinerSpendPubToExtra(tx.extra, zeroMinerSpendPub);

  return tx;
}

}  // namespace CryptoNote
