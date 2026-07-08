# Discrete genesis

The genesis block is frozen. Every node must agree on it byte-for-byte. This
document records what it contains, how to regenerate/verify it, and where the
recipient secrets live.

## What genesis contains

The genesis coinbase carries the entire **Discrete Treasury Reserve** as
per-output-unlocked `PqOutput`s — one batch per recipient — in a single
transaction. This is possible because Discrete added a per-output `unlockHeight`
to the wire (see [PQ-WIRE-FROZEN.md](PQ-WIRE-FROZEN.md)), so staggered unlock
times fit in one coinbase tx and `GENESIS_COINBASE_TX_HEX` remains the single
frozen artifact.

The genesis coinbase `extra` also carries a headline, embedded as a
`TX_EXTRA_NONCE` — Discrete's analogue of Bitcoin's *"The Times 03/Jan/2009
Chancellor on brink of second bailout for banks"*:

> Reuters 08/Jul/2026 — Crypto firms prepare defenses as quantum threat to encryption draws nearer

### Monetary policy

- **Total initial emission target:** 21,000,000 XDS (the emission-curve ceiling).
- **Treasury Reserve:** 1,050,000 XDS — **5%** of the ceiling. The reserve counts
  *within* the cap (it reduces ongoing block reward; it is not minted on top).
- **No ICO. No private sale. No separate dev tax.** The reserve is a locked
  allocation that unlocks gradually.
- **Treasury use is limited to:** development, audits, infrastructure, listings,
  documentation, and grants.

### Unlock schedule

- **50,000 XDS per batch** (5,000,000 atoms at `CRYPTONOTE_DISPLAY_DECIMAL_POINT
  = 2`).
- **21 batches total** = 1,050,000 XDS.
- **Unlocked gradually over 5 years.** Batch *k* (1-based) unlocks at height
  `(k-1) × 87,600`. At a 90 s block target, 87,600 blocks ≈ one quarter, so one
  batch unlocks each quarter; the last unlocks at height 1,752,000 ≈ 5.0 years.
  Batch 1 (unlock height 0) is spendable from genesis.

| Batch | Amount (XDS) | Unlock height |
|------:|-------------:|--------------:|
| 1  | 50,000 | 0         |
| 2  | 50,000 | 87,600    |
| 3  | 50,000 | 175,200   |
| 4  | 50,000 | 262,800   |
| 5  | 50,000 | 350,400   |
| 6  | 50,000 | 438,000   |
| 7  | 50,000 | 525,600   |
| 8  | 50,000 | 613,200   |
| 9  | 50,000 | 700,800   |
| 10 | 50,000 | 788,400   |
| 11 | 50,000 | 876,000   |
| 12 | 50,000 | 963,600   |
| 13 | 50,000 | 1,051,200 |
| 14 | 50,000 | 1,138,800 |
| 15 | 50,000 | 1,226,400 |
| 16 | 50,000 | 1,314,000 |
| 17 | 50,000 | 1,401,600 |
| 18 | 50,000 | 1,489,200 |
| 19 | 50,000 | 1,576,800 |
| 20 | 50,000 | 1,664,400 |
| 21 | 50,000 | 1,752,000 |

The recipients' **public** ML-KEM/ML-DSA keys are baked into
`src/CryptoNoteCore/GenesisTreasuryReserveKeys.inc` (auto-generated; committed).
Each batch's full bech32m PQ address (~2.6 KB — too long to table here) is
recorded in the offline secrets file below, and is recomputable by anyone from
the committed `.inc` public keys (`makePqAddress(viewPub, spendPub)`).

**Genesis block timestamp:** 2026-06-22 16:00:00 UTC (kept from original genesis generation).
The embedded headline (Reuters 08/Jul/2026) post-dates the timestamp — the timestamp reflects
when the genesis keys and structure were frozen; the headline is the canonical news anchor
(`m_genesisBlock.timestamp` in `Currency::generateGenesisBlock`).

**Genesis block hash (mainnet):**
`b1df0152bb41d12bef471f322ac8fef52889cdb4128759a41877d26d08edace8`
(pinned by `tests/test_pq_genesis.cpp`).

## Recipient secrets

`vanitygen --treasury-reserve-accounts 21` wrote the 21 recipients' 25-word
mnemonics, PQ addresses, and public keys to
`genesis/treasury-reserve-accounts.txt`. That file is **gitignored and must never
be committed** — it controls 1,050,000 XDS. Move it to cold storage. Each
mnemonic, loaded into `simplewallet`, recovers its batch (the wallet derives the
same PQ identity via `derivePqWalletKeys`). Multisig recipients were considered
but are out of scope (no PQ multisig exists yet); recipients are single-key
accounts.

## How the coinbase is built (deterministically)

`buildGenesisTreasuryReserveCoinbase()`
(`src/CryptoNoteCore/GenesisTreasuryReserve.cpp`) builds the coinbase
deterministically so two runs on any host produce identical bytes:

- For batch *i*: `kemSeed = HKDF(LE32(i), "discrete-genesis-kem-v1")`,
  `rho = HKDF(LE32(i), "discrete-genesis-rho-v1")`.
- `(kemCt, ss) = kem_encaps_derand(viewPub_i, kemSeed)` — a real encapsulation the
  recipient can still decapsulate, made reproducible via a seed-driven RNG.
- `buildPqOutput(kemCt, ss, spendPub_i, inputsHash=0, outputIndex=i, 5,000,000,
  rho, T=0)`, then `unlockHeight = i × 87,600`.
- Input is a `BaseInput` at height 0; `extra` carries the headline
  (`TX_EXTRA_NONCE`) followed by an all-zero ML-DSA miner spend pub (genesis is
  trusted — its block signature is skipped at height 0).

These domain strings, amounts, and the headline are part of the frozen artifact —
do not change.

## Regenerate / verify the frozen hex

1. Build the daemon: `cmake --build build --config Release --target Daemon`.
2. `discreted --print-genesis-tx` — prints `GENESIS_COINBASE_TX_HEX`. Run it twice;
   the output is identical.
3. Paste the hex into `src/CryptoNoteConfig.h` `GENESIS_COINBASE_TX_HEX`. (MSVC
   caps a string literal at ~16 KB, so the constant is split into adjacent string
   literals — the compiler concatenates them.)
4. `ctest -C Release -R PqGenesis` verifies: the 21-batch structure and unlock
   schedule, total = 105,000,000 atoms, builder determinism, that the frozen hex
   equals the builder output, and the pinned genesis block hash.

To regenerate the recipient accounts (new chain only — this changes the genesis):
`vanitygen --treasury-reserve-accounts 21 --file genesis/treasury-reserve-accounts`,
copy `genesis/treasury-reserve-accounts.inc` over
`src/CryptoNoteCore/GenesisTreasuryReserveKeys.inc`, rebuild, re-run
`--print-genesis-tx`, and re-freeze the hex + the pinned hashes.
