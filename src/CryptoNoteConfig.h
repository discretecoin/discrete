// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2026, The Karbo developers
// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete — a post-quantum-only cryptocurrency.
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

#include <cstddef>
#include <cstdint>

namespace CryptoNote {
namespace parameters {

const uint64_t DIFFICULTY_TARGET                             = 90; // seconds
const uint64_t EXPECTED_NUMBER_OF_BLOCKS_PER_DAY             = 24 * 60 * 60 / DIFFICULTY_TARGET;
const uint64_t CRYPTONOTE_MAX_BLOCK_NUMBER                   = 500000000;
const size_t   CRYPTONOTE_MAX_BLOCK_BLOB_SIZE                = 500000000;
const size_t   CRYPTONOTE_MAX_TX_SIZE                        = 1000000000;
const uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX       = 0x3445db; // disc
const uint64_t CRYPTONOTE_KEYS_SIGNATURE_BASE58_PREFIX       = 176103705;
const size_t   CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW          = 10;
const size_t   CRYPTONOTE_TX_SPENDABLE_AGE                   = 3;

// First-seen finality: reject an alternative chain that forks deeper than this
// many blocks below the current tip (see the is_in_checkpoint_zone exemption).
// This is a CONSENSUS parameter enforced by EVERY node from genesis — it is NOT a
// runtime-configurable option. Changing it is a hard fork.
//
// At DIFFICULTY_TARGET = 90s, 10 blocks ≈ 15 minutes of finality window. This is
// the trade the chain makes deliberately: a refused deep reorg is a recoverable
// liveness event, an accepted one is an irreversible safety event.
const uint32_t CRYPTONOTE_FINALITY_DEPTH                     = 10;
const uint64_t CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT            = DIFFICULTY_TARGET * 7;
const uint64_t CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V1         = DIFFICULTY_TARGET * 3;
const size_t   BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW             = 60;
const size_t   BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V1          = 11;

// Monetary policy — Discrete has NO fixed supply cap.
//
// Per-block emission is max(exponential, tail), computed in
// Currency::calculateReward():
//   * Exponential phase: (EMISSION_CURVE_TARGET - alreadyGeneratedCoins) >>
//     EMISSION_SPEED_FACTOR. This decays toward zero as circulating supply
//     approaches EMISSION_CURVE_TARGET, front-loading issuance over the early
//     years.
//   * Perpetual tail (Milton Friedman's k-percent rule): a fixed 2% of the
//     circulating supply per YEAR, spread evenly over the blocks in a year.
//     This term never stops.
//
// EMISSION_CURVE_TARGET is therefore NOT a supply ceiling — it only shapes the
// initial exponential curve. Because the 2% tail is a percentage of an
// ever-growing base, total supply grows without bound at a long-run rate of
// ~2% per annum (the exponential term dominates early; once 2%/yr exceeds the
// decaying exponential reward, the tail takes over). Every atom minted is
// validated exactly against calculateReward() by validate_miner_transaction(),
// so this inflation is fully deterministic and publicly auditable — a
// deliberate policy choice, NOT uncapped or hidden emission. See https://docs.discrete.cash/#/consensus/emission.
const uint64_t EMISSION_CURVE_TARGET                         = UINT64_C(2100000000); // shapes the initial curve (~21,000,000.00 XDS issued before the 2%/yr tail dominates)
const uint64_t COIN                                          = UINT64_C(100);
// Vestigial: floor of the EXPONENTIAL term once alreadyGeneratedCoins reaches
// EMISSION_CURVE_TARGET. In practice the 2% Friedman tail (calculateReward())
// exceeds it long before that point, so it is never the effective reward.
const uint64_t TAIL_EMISSION_REWARD                          = UINT64_C(100);
const size_t CRYPTONOTE_COIN_VERSION                         = 1;
const unsigned EMISSION_SPEED_FACTOR                         = 18;
static_assert(EMISSION_SPEED_FACTOR <= 8 * sizeof(uint64_t), "Bad EMISSION_SPEED_FACTOR");

const size_t   CRYPTONOTE_REWARD_BLOCKS_WINDOW               = 100;
const size_t   CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE     = 1000000; //size of block (bytes) after which reward for block calculated using block size
const size_t   CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2  = 1000000;
const size_t   CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1  = 100000;
const size_t   CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_CURRENT = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
const size_t   CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE        = 600;
const size_t   CRYPTONOTE_DISPLAY_DECIMAL_POINT              = 2;

const uint64_t MINIMUM_FEE                                   = UINT64_C(1);
const uint64_t MAXIMUM_FEE                                   = UINT64_C(100);

const uint64_t DEFAULT_DUST_THRESHOLD                        = UINT64_C(1);
const uint64_t MAX_EXTRA_SIZE                                = 4096;
const uint64_t MAX_EXTRA_SIZE_PQ                             = 4096;

// Flat-fee model. A transaction pays MINIMUM_FEE (0.01 XDS) regardless of its
// serialized size. Input/output counts are consensus-capped, while tx_extra is
// free-form within its cap; bytes beyond TX_EXTRA_FEE_FREE_BYTES are therefore
// surcharged at MINIMUM_FEE per TX_EXTRA_FEE_CHUNK_BYTES started. The free
// allowance fits a paid account registration (3,137 bytes) plus a payment-id
// nonce. This is an explicit policy choice; block-size penalties and miner
// selection provide the remaining bloat controls.
const uint64_t TX_EXTRA_FEE_FREE_BYTES                       = 3200;
const uint64_t TX_EXTRA_FEE_CHUNK_BYTES                      = 100;

// Consensus fee floor for TX_PQ: flat minimum plus the tx_extra surcharge.
inline uint64_t pqTxExtraSurcharge(uint64_t minFee, uint64_t extraSize) {
  if (extraSize <= TX_EXTRA_FEE_FREE_BYTES) {
    return 0;
  }
  uint64_t chargeable = extraSize - TX_EXTRA_FEE_FREE_BYTES;
  return minFee * ((chargeable + TX_EXTRA_FEE_CHUNK_BYTES - 1) / TX_EXTRA_FEE_CHUNK_BYTES);
}
inline uint64_t pqTxFeeFloor(uint64_t minFee, uint64_t extraSize) {
  return minFee + pqTxExtraSurcharge(minFee, extraSize);
}

// PQ Phase 1 transaction limits (spec §1.2). These are consensus caps. A PQ input is
// ~5.3 KB (ML-DSA-65 auth pub 1952 + signature 3309 + outpoint) and a PQ output is
// ~1.2 KB (ML-KEM-768 ct 1088 + enc payload 56 + commit 32). The size cap is sized so
// the input AND output counts can both be maxed in one tx: 32*5.3K + 64*1.2K ~= 246 KB.
const uint64_t MAX_PQ_INPUTS_PER_TX                          = 32;
const uint64_t MAX_PQ_OUTPUTS_PER_TX                         = 64;
const uint64_t MAX_PQ_TX_SIZE                                = 256 * 1024;

// Free-fee account registration (spec §11).
//
// TX_FREE_REG carries no fee, so its ONLY anti-spam cost is a memory-hard
// yespower proof-of-work (checkFreeRegPow). The predicate accepts a nonce when
// the top 64 bits of the yespower hash are <= FREE_REG_POW_TARGET, so the
// expected number of yespower evaluations per registration is
//   D = 2^64 / (FREE_REG_POW_TARGET + 1).
//
// Strong anti-spam setting: target 0x00007FFFFFFFFFFF => D = 2^17 = 131072
// expected yespower calls. With the stock y_slow_hash params (N=2048, r=32,
// ~8 MiB),
// that is on the order of minutes of single-core work / tens of seconds on a
// multicore machine for a ONE-TIME registration, while making bulk squatting or
// mempool-flooding with fresh-identity registrations cost real CPU-hours. To
// retarget after measuring yespower throughput H (hashes/sec) on reference
// hardware for a desired wall-clock t: D = H * t, FREE_REG_POW_TARGET =
// (2^64 / D) - 1. This is a launch parameter — recalibrate before mainnet.
//
// Defense in depth: FREE_REG_PER_BLOCK caps how many registrations are MINED per
// block; parameters::FREE_REG_POOL_LIMIT caps how many zero-fee registrations
// may sit in the mempool at once (see tx_memory_pool::add_tx).
const uint64_t FREE_REG_REF_WINDOW                          = 60;
const uint64_t FREE_REG_PER_BLOCK                           = 100;
const uint64_t FREE_REG_POW_TARGET                          = UINT64_C(0x00007FFFFFFFFFFF);

// Mempool admission cap on pending zero-fee TX_FREE_REG transactions. Because
// free registrations pay no fee, the fee-priority pool eviction cannot shed
// them, and an attacker using a fresh keypair each time bypasses the
// per-identity duplicate check — so without an explicit cap they could bloat the
// pool up to the tx-livetime horizon. Sized at ~20 blocks of registration
// capacity (FREE_REG_PER_BLOCK * 20) so miners always have a full block to draw
// from while bounding pool occupancy (~20*100*3.2KB ~= 6.4 MB worst case).
const uint64_t FREE_REG_POOL_LIMIT                          = FREE_REG_PER_BLOCK * 20;

// ─── DiscretePower (signature-tape proof of work) ────────────────────────────
// Consensus PoW. Every candidate carries exactly one ML-DSA-65 signature which is
// padded to a 3312-byte "tape" and injected, 8 bytes at a time, throughout a
// modified yespower-1.0 memory-hard execution (yespower-discrete). The mechanism is
// identity-bound and delegation-hostile — it binds the coinbase reward to the
// signing key and forces a remote worker to carry the whole per-candidate tape,
// not a short digest. It is NOT pool-proof or botnet-proof. See
// https://docs.discrete.cash/#/consensus/pow (revision D) for the normative construction.
//
// These are consensus constants; changing any of them is a hard fork. DISCRETE_POWER_SIG_LEN
// is compile-time checked against the liboqs ML-DSA-65 signature length in
// CryptoNoteCore/CryptoNoteFormatUtils.cpp. DISCRETE_POWER_N/DISCRETE_POWER_R are the revision-D DRAFT
// parameter set (16 MiB) and MUST be frozen after the §12 benchmark gate.
const size_t   DISCRETE_POWER_SIG_LEN                                  = 3309;   // ML-DSA-65 canonical signature length
const size_t   DISCRETE_POWER_TAPE_LEN                                 = 3312;   // sig || 0x80 || 0x00 || 0x00
const size_t   DISCRETE_POWER_TAPE_WORDS                               = 414;    // DISCRETE_POWER_TAPE_LEN / 8 little-endian words
const uint32_t DISCRETE_POWER_N                                        = 4096;   // large-V memory: 128*r*N = 16 MiB / thread
const uint32_t DISCRETE_POWER_R                                        = 32;

// Discrete is PQ-only from genesis: the node admission cap must match the
// consensus TX_PQ cap that wallets fit against.
const uint64_t MAX_TRANSACTION_SIZE_LIMIT                    = MAX_PQ_TX_SIZE;

const size_t   DANDELION_EPOCH                               = 600;
const size_t   DANDELION_STEMS                               = 2;
const size_t   DANDELION_STEM_EMBARGO                        = 173;
const uint8_t  DANDELION_STEM_TX_PROPAGATION_PROBABILITY     = 90;

// LWMA-1 is the only difficulty algorithm.
const size_t   DIFFICULTY_WINDOW                             = 60;
const size_t   DIFFICULTY_CUT                                = 0;
const size_t   DIFFICULTY_LAG                                = 0;
// Mainnet difficulty floor: nextDifficulty never returns below this. Protects a young,
// low-hashrate chain from cheap reorgs and caps the genesis instamine window. MUST stay
// comfortably below the honest network hashrate (a floor above it stalls the chain with
// no recovery, since difficulty can't drop past it): ~MINIMUM_DIFFICULTY / DIFFICULTY_TARGET
// hashes/sec are required. 0 disables the floor (the absolute minimum is then 1).
const uint64_t MINIMUM_DIFFICULTY                            = 10000;

const size_t   MAX_BLOCK_SIZE_INITIAL                        = 1000000;
const uint64_t MAX_BLOCK_SIZE_GROWTH_SPEED_NUMERATOR         = 512 * 1024;
const uint64_t MAX_BLOCK_SIZE_GROWTH_SPEED_DENOMINATOR       = 365 * 24 * 60 * 60 / DIFFICULTY_TARGET;

const uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS     = 1;
const uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS    = DIFFICULTY_TARGET * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS;

const uint64_t CRYPTONOTE_MEMPOOL_TX_LIVETIME                = 60 * 60 * 24;     //seconds, one day
const uint64_t CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME = 60 * 60 * 24 * 7; //seconds, one week
const uint64_t CRYPTONOTE_NUMBER_OF_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL = 7;  // CRYPTONOTE_NUMBER_OF_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL * CRYPTONOTE_MEMPOOL_TX_LIVETIME = time to forget tx

// Discrete launches at block major version 1 and stays there: the full Discrete
// consensus ruleset applies from genesis (block 0). The historical Karbo
// "upgrade heights" (which phased rules in across versions 2..6) do not apply —
// Discrete ships the final ruleset at v1, so every version 2..8 is RESERVED for a
// genuine future hard fork. `4294967294` means "never" (it exceeds
// CRYPTONOTE_MAX_BLOCK_NUMBER), so getBlockMajorVersionForHeight() returns v1 at
// every height. The version-gated rule selectors in Currency/Core have been
// collapsed to the single v1 ruleset accordingly.
const uint32_t UPGRADE_HEIGHT_V2                             = 4294967294; // reserved
const uint32_t UPGRADE_HEIGHT_V3                             = 4294967294; // reserved
const uint32_t UPGRADE_HEIGHT_V4                             = 4294967294; // reserved
const uint32_t UPGRADE_HEIGHT_V5                             = 4294967294; // reserved
const uint32_t UPGRADE_HEIGHT_V6                             = 4294967294; // reserved
const uint32_t UPGRADE_HEIGHT_V7                             = 4294967294; // reserved
const uint32_t UPGRADE_HEIGHT_V8                             = 4294967294; // reserved

const unsigned UPGRADE_VOTING_THRESHOLD                      = 90; // percent
const uint32_t UPGRADE_VOTING_WINDOW                         = EXPECTED_NUMBER_OF_BLOCKS_PER_DAY;  // blocks
const uint32_t UPGRADE_WINDOW                                = EXPECTED_NUMBER_OF_BLOCKS_PER_DAY;  // blocks
static_assert(0 < UPGRADE_VOTING_THRESHOLD && UPGRADE_VOTING_THRESHOLD <= 100, "Bad UPGRADE_VOTING_THRESHOLD");
static_assert(UPGRADE_VOTING_WINDOW > 1, "Bad UPGRADE_VOTING_WINDOW");

const char     CRYPTONOTE_BLOCKS_FILENAME[]                  = "blocks.dat";
const char     CRYPTONOTE_BLOCKINDEXES_FILENAME[]            = "blockindexes.dat";
const char     CRYPTONOTE_BLOCKSCACHE_FILENAME[]             = "blockscache.dat";
const char     CRYPTONOTE_BLOCKCHAIN_INDICES_FILENAME[]      = "blockchainindices.dat";
const char     CRYPTONOTE_POOLDATA_FILENAME[]                = "poolstate.bin";
const char     P2P_NET_DATA_FILENAME[]                       = "p2pstate.bin";
const char     MINER_CONFIG_FILE_NAME[]                      = "miner_conf.json";
} // parameters

const char     CRYPTONOTE_NAME[]                             = "Discrete";
const char     CRYPTONOTE_TICKER[]                           = "XDS";
// Candidate genesis generated 2026-07-15 13:49:13 UTC.
const uint64_t GENESIS_BLOCK_TIMESTAMP                      = UINT64_C(1784123353);
// FROZEN genesis coinbase. Carries the 1,050,000 XDS Discrete Treasury Reserve
// (5% of the 21,000,000 XDS ceiling) as 21 per-output-unlocked PqOutputs of
// 50,000 XDS each (unlock heights 0, 87600, ... 1,752,000 — one batch per quarter
// over 5 years). Built deterministically by buildGenesisTreasuryReserveCoinbase()
// (src/CryptoNoteCore/GenesisTreasuryReserve.cpp); regenerate/verify with
// `discreted --print-genesis-tx`. DO NOT EDIT — changing it forks the network and
// orphans the Treasury Reserve. See https://docs.discrete.cash/#/consensus/genesis.
const char     GENESIS_COINBASE_TX_HEX[]                     = "01000001ff0015c096b1020011d50a5a8c6b7bb99413359fcaea5160d49b879b99b7751fd28355ed85b97b7770c096b102b0ac0511d6fe026fe0997278b2cbb63b6d5e1c7473df6e2cd8a645931a9121c914396d72c096b102e0d80a1140e97a90342e59f6d9c7e652629be8c2ee240c1e7d65764bf33a0b9c6883c9e1c096b102908510113ab4c611008097b11e8d497affd50a97aa61bbb0336843846f8a57fcb49aa36ac096b102c0b1151177121d091c3238211b05701bdb9e7cb268be9b4fa27bf841d6a138c9fe6666d5c096b102f0dd1a119b0fbae6a7e1682703eba0945be0a6c9b6c5c779d0d643e64e815c857f546c48c096b102a08a2011bb45b6ee3e893409afede0de8a705bc8ad923828400a01b13ecdb345021af8f0c096b102d0b62511b5a8d21e0de13f9e52cc15f68975761a79f74c01b4dace1673e4600401a98219c096b10280e32a11e7ccfe7367310ff66f0e8f1a7e4dbdc7bd529ebf29500f5c3a7cfe946072d284c096b102b08f30111ac734f9f736148f5c5ef83063f41ce295f08ecb37862b01b1cba34d834db901c096b102e0bb35115759c64a3c931230c6e15859c6ce689e8f791c0f50ae308e7c593e33d475399bc096b10290e83a11efda61fb4cf8fc410d72b59cb037eb7e59fb497490434c4d13ce6f2e4486f500c096b102c0944011e621da48bebf8ce82215b012c3119c106fcf7a55830ed71fee7020a425ae7901c096b102f0c045118bd96a1d004629af9c54265bf2c2afb38070ce5da6ef6742f784a789e03025acc096b102a0ed4a117a5fce9267f3dc26174bd0fa5892a0b5555365bd0051f403fd0616c7dffaa180c096b102d099501183260a7a43144325d5063b1cdc9bb7480b8326fa58b7e18dc2a303e7170ed1f0c096b10280c655114d307e4ce43c302af57092155fa3ca6c650157623ff655af5b5b25fdb23985a5c096b102b0f25a119536029c4b5706ffb08f8819f0af7d40d917fa5366a54e3a884ee3dcbdd49de1c096b102e09e6011d818a4cd814f9da198655415cf8b478d04d5b0f643b985aa35b93e1a2aad6afac096b10290cb6511d6cfc97b2cfa401a6021a37e859b0a524830875495857829c143a3b0c8483e5dc096b102c0f76a1130a950457d8f4b26be06e7b671f5b74bcd7cea561e924e2f3b470ca23c91502085100262526575746572732030382f4a756c2f3230323620e280942043727970746f206669726d73207072657061726520646566656e736573206173207175616e74756d2074687265617420746f20656e6372797074696f6e206472617773206e6561726572070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const char     DNS_CHECKPOINTS_HOST[]                        = "checkpoints.discrete.cash";

// Approved PQ signer addresses for DNS checkpoint records.
//
// DNS TXT records served from DNS_CHECKPOINTS_HOST must be in the form
//   "<height>:<block_hash_hex>:<signature>"
// where <signature> is produced by signing the GENESIS-BOUND string
//   "<genesis_block_hash_hex>:<height>:<block_hash_hex>"
// with one of the wallets whose PQ address appears in DNS_CHECKPOINT_SIGNERS.
// Prefixing this network's genesis block hash (64 lowercase hex chars) binds
// every record to exactly one chain: a record signed for a testnet, a staging
// deployment, or a code fork that trusts the same signer key can never be
// replayed onto mainnet through the shared DNS host (a wrong replayed pin would
// otherwise hard-stall syncing nodes at that height). The signature scheme is
// the post-quantum one wired into simplewallet's
// `sign_message` command (CryptoNoteFormatUtils::signMessagePq / verifyMessagePq)
// — ML-DSA-65 over the wallet's long-term spend key, over a domain-separated
// SHA3-256 digest, Base58-encoded with the CRYPTONOTE_KEYS_SIGNATURE_BASE58_PREFIX
// tag. Each entry here is a Discrete PQ address (the string `address` prints);
// the loader extracts its ML-DSA spend public key and verifies against it
// (Checkpoints::verify_signed_dns_record).
//
// Operational workflow for a maintainer (offline ML-DSA signer wallet):
//   1. simplewallet --generate-new-wallet checkpoint-signer.wallet
//   2. run `address` and note the printed PQ address; add it to this array in
//      the next release build.
//   3. encrypt the wallet file and keep it offline; it never needs funds — the
//      only operation it performs is `sign_message`.
//   4. to publish a new checkpoint, load the wallet on an offline machine, run
//      `sign_message` with the argument
//      "<genesis_block_hash_hex>:<height>:<block_hash_hex>" (genesis hash as
//      shown on the explorer's block-0 page), then publish the DNS TXT record
//      as "<height>:<block_hash_hex>:<signature>" — the genesis prefix is
//      implied by the network and is NOT repeated in the record itself.
//
// Multi-signer / any-of-N semantics: a DNS record is accepted if its signature
// verifies against ANY PQ address in this list. This lets the project rotate a
// signing wallet (add the new address in release N, drop the old one in
// release N+1) without an emergency rollout, and lets multiple maintainers hold
// independent signers without coordinating on a single hot key.
//
// Empty signer set: leave just the nullptr sentinel below — DNS checkpoint
// loading then fail-closes (the loader logs once and skips every record).
// Fail-closed is the guaranteed fallback: if every configured entry is removed
// or fails to parse, no DNS record is ever trusted.
//
// Implementation note: nullptr-terminated C array, not std::array. The
// previous std::array<const char*, N> form required maintainers to update
// N manually each time they added or removed a signer; under MSVC the
// extra initializers were silently dropped (no diagnostic, COUNT stayed
// at N), which fail-closed the loader even with real signers configured —
// the security-degrading kind of "silent". The sentinel scheme makes
// COUNT auto-track the entry count via sizeof, requires no manual sizing,
// and works for any count including zero (MSVC rejects zero-element C
// arrays, but a one-element `{ nullptr }` is well-formed).
constexpr const char* const DNS_CHECKPOINT_SIGNERS[]         = {
  // Maintainer checkpoint signer #1 (offline wallet, provisioned 2026-07-17).
  "disc1q8dch5gp27jhem5x9pcu9yaz22sj5zpgufprdm45f7dsn2nf7j0acxvp4jd8xzwtt8xg9sr9t0qnqhre4lu5f44usv238jd9fgj5kvqcaf5mqkufxph2vlutvwjp2tqugvn363dgnc6v5ul9xxzdd8yppn3k8azh9l7d4gfvp9a20zkguckfn5d5kq85nz7l2l8gmk6xud35jgte0wrgvkxt2cwdv5de7upcqsmhffdmwtx2qcxydpe9fd2gxrvceqwxsls6vnrjtu4wqffgkdr3pu7mvd2gy09d6x3a62e36p4gqf0fced0s7pppu5y59kzcls9thts4v5q88pknv5cpna8hng504h7saj0zzj6lec2v0y9k564t0yvgpf7cfjhdtr9hq5ylfwff3kwzutmtwvqtcar0a3qzq92vsm3gmug3x0f6ckv8kyq7n4c5c7qcka2s9f2kk6e7vug827x2u09v72c2awhmuzqmqngf78kjetxp9l2ptxc9us9vrjmvfp9yyfc9ysvg4kq8s28xmp5pyt4qmfcyz3szewnhtxzjqvjv97mjyune80r6zwkwscldydnccpnkgrtz9e26wwzc7sglk26mve9x4fzjq20xlzkdaq6hxt92rnkeme6vts43f6agugwl7enk5c63g8p3y0lunzahw723w7y0xd5nje5v4eyx9hlz467cvg2eh8rw23qq426hgwd22gqtu45zh6sc3y457us4jt2carn7wtf5zf2cl874txna2rw4ggxtn3nrw5xzqnqnd9c6x5h3ens225g4454sevxkanjqhq99uyu2f3xfujjkn90ex9l0g5nf7f2xzaqcgdnd3n9kmjujvmjhs6vz534e2m5kn068jnm03e6dfpnusmjwjezyvt7qj5xdfkf7kkye4uh253pyqep2d63wwmq23je6ec4vvh3vexv30a7gaxrsa66a9pzgw3esu789x5n2sx55auz0e4q4c8evqp2zd8hze0tyl9msrpsqw0e0w65pyglntxgrqg70u7ztlqzearthgzaaxc3s3rz0ve6rzszhsg2ve0atzp87cwrfdmg398kgh58qqjwyqg8pz3c873py2uu08d9pwyt2qkyhsgsqhvf6rw6r6y3yhhpgkjcgrrh8ffv2d38daahetuwujyskkpg3q32d80y9lmyjvwyvpxywrxzj6dk35gyz950g2wr8q9ndae5xk4h6r39t8a8kzspjw5u32e84ganc9xtfyv75lwk7ur3masax22kqumn0waw502k7zfnpw6pahw98qntfw725v9ag90s7u3e6j92gxy5k4sgg3z8lsa7m7arjx2924dmgd8zq8xzrfnpy4z53n6tvtp92cytw3rqkj62e7jmxavpd52gyz2a4j5xevtgndqdkdjc25l9fhysrgkue2mm739g5wcntvff3n05cnqxp3spkvd4ytkrsrf8rrzecgurpfkxndtxrvvcx0a3zsl70ppx7ufcua5kz2j4de04y7c3ftnpwdu2a6q57m9mklqkgd6k9pndy2xjvg5z87ym0l6p92vk0z9lfxukak6pceyr6v98cdr84px976766fp82769yaqh50y054t0usf7vccqd7pfeerpy2522jpdnvcanjxp2wspex9eqpqvn92p4gf6cjysrjsu567gfl9gnqv7lg3la7ut3cyzmpqmc5z2sgrwp0rqtpw0ls63j7j6zj2try867wey5dympsrsp0xvkfv7c3xjuylkg4mpq9p2nurqwcymxk02yx2efqyy5nv93vqyexwnj3kay988flywaqmk96lnhchy3zq2wxe3xd0wsmdzmypqn07yz5unsl8zh6latvqhuf7mlkn049kpxn55k2n2vejd43kg2asyel50ux088rwjh9u9jrqgwpuewf8qjslr3lprcmlzlnpgxm58cpt0gzjhgm643gxlfhr40nwweyfnx3udqngser7grl6pz4vadgp5evp2fwlyw7t2hmw27uepj2y32pgq5xezysj3rclrym2spcgnzalrjyrtkc2urz653k0smpw7llvzs0zxdqa7z3a3a02x8xwf7us8nqdtt44y6x96hw33ynn9cxasuqpgp56tv28guymhrgng9lulua7t7dumwgqr58jmq7x5afwrqpfes6rknaak22t3w5e54nqe4p3snl205u58lavx0dhv6nrvtq0nqqr7z482myzdl0hgadf2qpswwd3ucn8e4ff5kyge5x9yqhrw9t7tcwzs270esdg6alzk2zxfwssf7msg20kqq938y759llka55agv2l54rrje5ep54llhklspqvexwjwuvy32ypwvm3ghypqmcwrgr08s3rxttjptw5v4a8vr6s3xehj2wru70rvrrnzsh5z93hwx2wramt5a3ddmzznqlurhl8vtjhxgydkqsef2jr6tyj7papzxk38rtxf3s2zvvy3k4t42we8j8kegsdpy0znkhxtggfnevwvk3k385326hyef9q24nkl5n9fge8cgrj82gq9tszy79epqu375ldmkjnyzd4hej5caae37vucs7g9g83k9svny4eepr5zx5p7752dl3qkpae52uzgs05fjpxqcahumsmqprmxxxd3hqw0kftfkxrs7kv8uxd0y65d6wrxz7n2r2rl60s2xn43zn60kjgeydukx628uam3gyum68sulpsw04mtrxnqdjdq5eje32380xsxk0ndsh4tnrx7jaa8e92y57yny0qyq7fsd6mz2wu6keuv5druwjhrs0a0jd4epujscf77q35h3ls8vky030th6knjw2eg4n2gwmvravkl3tj0fr9987enrhurphkxpj34076wzlhn6hj4t2uuspewsmcls0fkj7gcunudv9tscjdx6zuqh4v2d7nd30ujllzln0swt8tx2mgvnu8azerzplwjfslr6yucpg0uw7l6pdl4gt83z5wuptagr2zumay0uwxvtn8384esqpcs2c4xug26ye2e06g3adypq489vc00huhq74s0tkm0gt7v62hjku2fhay3km00tz9pg0rf6m6fkpwuyvh4aalhp49luq5zytxdmp0nx384p94rt623rwjj6ug9jsmd5d932jwtlmfhtf5kkt3y9tr3k7uknhgtghc2zl6jx5l8jzdxhf677sch890xeqfmqsk49hyhxq00cysgzqcpfylen6ynhuf02u3hfcjdyrfsd3c6dxkfls3g7ptrp2g2w00su5m0e4akl8fzltelzqc37qhtf9nmfgs49lypcvqz4svqa2uq0ykhg4wkl0c7zz7gczmxq2plp4p2uxh3n38kr74e26u7rqzhemk2d7rpc9z4pv4u56248ynkm8qyy9nvgklxfwfttkfvqyfkc595ayh9mcwnky2j7gencjpx3exvlk9645gdv5laajh7klk33fstvg6ecf66s6ttgeg08yuedgdqwm8xgnw4karu9jq9z4xn7f59787t2z2w6njyuzuszrz4lht4zkea8988cku25zm2h4hac7zz2gn9g5q29hqywrkjprmhaz50lhvp45sa35r5xky9ayqeamuzhnmcqhq3j267ugcx0y47dwucumpyqx5r5a86wg4vuu3rd209m5mcn2v46uc97qy6wyru4gpcuenu6d47qe2yqt60vecrdgnp264nd0r0qa90rav8vf7u52vxqul0xp3exya6u5vxecxa8w2yjnxrcj4mqa9q2k4ppgakr2ygfx9jvgx6uqcuunwndfdww6jrvtdd93209a4lmcs8t4kcamz6ye8ajdsw82azuyntuem8frn4n89kkn9zcjcny2uz6j8gsz4ms09n745e94a78dctf8kdfr34zszxwqtw4zmjtahtk6xhjfy586h9ky554jnr3mde9av66rvvx08jpq4uz28wkj2sz3zeajfyh8c7j536gt0xatj985k5jz32kr9mhed3q37tzhwa6y2yu8yvy0992hhat6c6xqyg5pzngz6z5pkcrky2plwxugjr9yz6pjpk4aqpaxkgf4gyva82ydy8wm8luz4wq8vl8v54w23h7m5aruvvjzldl75r09xyw90pm3j7jh5r4rjlxkrlz3jah3aqhzzfqxq2cnczutyhc0tgplyzxdf44xvwzvv7ja24xjms8j3qnfmxs9xdl2du74lvfp3zwt8fml7dyu3fp9qfuq5uj4affylwret76jrg85m6n0qw7584a9dkn4guaupxd25gwmvwdhgcldpqg2vrmvjtqzmjprll8h94lnr4pclpv5w9etjxlwk0apzuzmh09wlpkfgwvexlz7nq0lu7x5gnx54gdq9u5dckfhwh6l3u0wuq2h79nvvsc40s2wsds7xkuq8rnvqasluazy6v48s9y8fdf2yj7rd9zazeajqllwrv6ny4pyh675mmhk2rh6m864z5eh44x7g2l3fr2xt2r6kyuq0h8gngsqjsfvz7klht3s97jpn32epafetu9qeqvfeqv492ucyryvcm050v3vwyql96tf2nvts5mlvkg5l7qje2huqk3m7k4t9lk09ndxsgzzwhqhdnkdkzk9h5lst4qcv39y9v5v882c5gu8sqwtlml026ly27vr6rzacgl05srnepu4khgzt5z3x3t0f4rtt6n5kfq8lj66gvwpcz90x4nku5uqxcgwjagsjucze6ly3twpcnccydjg2gl6gv6x2jcj25zytvaj0q8zp7plxdadus5qkrz78y3f7hwpuefhelqy5ls0k88yk8gxckmv6dz0uhulftuvfluhrce4kz8gcrm3zfrmgzg545jsdv43hmq7vp248gxa2j7emz5as7axqd25dpdxr0pzf8k3kxdlfxnc9tzh5tf9gyylxgzv86lrpzt3p64f3dvxwvld6clrraj4fcy0gwcke86urpzzmpa0mmqmn4cgh87nxxxhggvw003fue3gmt5r",
  nullptr   // sentinel — keeps DNS_CHECKPOINT_SIGNERS_COUNT auto-tracking
};
constexpr size_t DNS_CHECKPOINT_SIGNERS_COUNT                =
  (sizeof(DNS_CHECKPOINT_SIGNERS) / sizeof(DNS_CHECKPOINT_SIGNERS[0])) - 1;

// Transaction versions. v1 = PQ. v2+ reserved for future upgrades.
const uint8_t  TRANSACTION_VERSION_1                         =  1;
const uint8_t  CURRENT_TRANSACTION_VERSION                   =  TRANSACTION_VERSION_1;

// Block major versions — all kept as natural values for future hard-fork use.
// Discrete uses v1 from genesis (PQ-only). v2-v8 are reserved for future upgrades.
const uint8_t  BLOCK_MAJOR_VERSION_1                         =  1;  // PQ genesis version
const uint8_t  BLOCK_MAJOR_VERSION_2                         =  2;  // reserved
const uint8_t  BLOCK_MAJOR_VERSION_3                         =  3;  // reserved
const uint8_t  BLOCK_MAJOR_VERSION_4                         =  4;  // reserved
const uint8_t  BLOCK_MAJOR_VERSION_5                         =  5;  // reserved
const uint8_t  BLOCK_MAJOR_VERSION_6                         =  6;  // reserved
const uint8_t  BLOCK_MAJOR_VERSION_7                         =  7;  // reserved
const uint8_t  BLOCK_MAJOR_VERSION_8                         =  8;  // reserved

inline uint64_t maxExtraSize(uint8_t /*blockMajorVersion*/) {
  return parameters::MAX_EXTRA_SIZE_PQ;
}
const uint8_t  BLOCK_MINOR_VERSION_0                         =  0;
const uint8_t  BLOCK_MINOR_VERSION_1                         =  1;

const size_t   BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT        =  10000;  //by default, blocks ids count in synchronizing
const size_t   BLOCKS_SYNCHRONIZING_DEFAULT_COUNT            =  128;    //by default, blocks count in blocks downloading
const size_t   COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT         =  1000;

const int      P2P_DEFAULT_PORT                              =  9330;
const int      RPC_DEFAULT_PORT                              =  9331;
const int      RPC_DEFAULT_SSL_PORT                          =  9332;
const int      WALLET_RPC_DEFAULT_PORT                       =  9333;
const int      WALLET_RPC_DEFAULT_SSL_PORT                   =  9334;
const int      GATE_RPC_DEFAULT_PORT                         =  9335;
const int      GATE_RPC_DEFAULT_SSL_PORT                     =  9336;
const char     RPC_DEFAULT_CHAIN_FILE[]                      = "rpc_server.crt";
const char     RPC_DEFAULT_KEY_FILE[]                        = "rpc_server.key";

const size_t   P2P_LOCAL_WHITE_PEERLIST_LIMIT                =  1000;
const size_t   P2P_LOCAL_GRAY_PEERLIST_LIMIT                 =  5000;
const size_t   P2P_LOCAL_ANCHOR_PEERLIST_LIMIT               =  100;

// This defines our current P2P network version
// and the minimum version for communication between nodes
const uint8_t  P2P_VERSION_1                                 = 1;
const uint8_t  P2P_VERSION_2                                 = 2;
const uint8_t  P2P_VERSION_3                                 = 3;
const uint8_t  P2P_VERSION_4                                 = 4;
const uint8_t  P2P_CURRENT_VERSION                           = P2P_VERSION_1;
const uint8_t  P2P_MINIMUM_VERSION                           = 1;

// This defines the number of versions ahead we must see peers before
// we start displaying warning messages that we need to upgrade our software
const uint8_t  P2P_UPGRADE_WINDOW                            = 2;

// This defines the minimum P2P version required for lite blocks propogation
const uint8_t  P2P_LITE_BLOCKS_PROPOGATION_VERSION           = 3;

const size_t   P2P_CONNECTION_MAX_WRITE_BUFFER_SIZE          = 64 * 1024 * 1024; // 64 MB
const uint32_t P2P_DEFAULT_CONNECTIONS_COUNT                 = 12;
const size_t   P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT          = 2;
const size_t   P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT     = 70;
const uint32_t P2P_DEFAULT_HANDSHAKE_INTERVAL                = 60;            // seconds
const uint32_t P2P_DEFAULT_PACKET_MAX_SIZE                   = 50000000;      // 50000000 bytes maximum packet size
const uint32_t P2P_DEFAULT_PEERS_IN_HANDSHAKE                = 250;
const uint32_t P2P_MAX_PEERS_IN_HANDSHAKE                    = 256;
const uint32_t P2P_DEFAULT_CONNECTION_TIMEOUT                = 5000;          // 5 seconds
const uint32_t P2P_DEFAULT_PING_CONNECTION_TIMEOUT           = 2000;          // 2 seconds
const uint64_t P2P_DEFAULT_INVOKE_TIMEOUT                    = 60 * 2 * 1000; // 2 minutes
const size_t   P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT          = 5000;          // 5 seconds
const uint32_t P2P_FAILED_ADDR_FORGET_SECONDS                = (60 * 60);     //1 hour
const uint32_t P2P_IP_BLOCKTIME                              = (60 * 60 * 24);//24 hour
const uint32_t P2P_IP_FAILS_BEFORE_BLOCK                     = 10;
const uint32_t P2P_IDLE_CONNECTION_KILL_INTERVAL             = (5 * 60);      //5 minutes

// P2P stat-reporting trusted key. UNUSED in Discrete — no code reads this value,
// and the optional stat-reporting feature it gated is not wired. Set to all-zero
// (disabled). If the feature is ever enabled, generate a keypair here and keep
// the secret offline (see https://docs.discrete.cash/#/consensus/network).
const char     P2P_STAT_TRUSTED_PUB_KEY[]                    = "0000000000000000000000000000000000000000000000000000000000000000";

// Discrete seed nodes (P2P port 9330). Placeholders pending DNS; the daemon
// tolerates unreachable seeds.
const char* const SEED_NODES[] = {
  "seed1.discrete.cash:9330",
  "seed2.discrete.cash:9330",
};

} // CryptoNote

