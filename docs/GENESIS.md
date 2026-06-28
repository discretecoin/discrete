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

> Reuters 16/Jun/2026 — France to stop certifying products without quantum-safe encryption

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

| Batch | Amount (XDS) | Unlock height | Recipient reserve address |
|------:|-------------:|--------------:|-------------------------------|
| 1  | 50,000 | 0         | discvLkR4dYha5ofRu9WymcCSAM4RJ8Kxd9oJXS8HUNhEJZAUBj6o7wZgZZsQEfZd46x7seW7UfLiZieSuzYFQqvLz2KSevxuuY |
| 2  | 50,000 | 87,600    | discvJiX2CGZsABoUgaRZEYmjcmMKJ4yY9xgN8LQ7zpoBiHeWUmbwJFRvWt4YnQDZbSyP1XRhwVP8W6fbHp3JTYFhepeCMyNmS1 |
| 3  | 50,000 | 175,200   | discvGtwVvwVaUiyTvJf2EazYx5fgHFVP6KZLB6sDDhALPb9uprSWGDFkgPL84kpZhNJojbL964vQTsA45WTRMzyXra5b6JMF9V |
| 4  | 50,000 | 262,800   | discvHBVdRM8W4xnXuARR87x4La8Lo2FSYJCo2DFreNVXPP4SbuWaWTbD6UHyr2R8DWkBk1cnNBahRdFFSY6Xqe2iSqGVztkGTk |
| 5  | 50,000 | 350,400   | discvNN8RQLjYRfVAHJiQkK4UArXyt37VUrUqEVAvoTHhzbEan35ZKq4LAMkfcCNYW94gekoy8sdQ85KE4FFXvaa3buWKryeDey |
| 6  | 50,000 | 438,000   | discvGx4wyp9hXxUPE9YPS6rYBSjTisWJdhmKg8Qb2zWCegkfGpzRczfkUYNPDe6T1eQpiNNb34m5V5PNTyHdq597HsEJzybq8k |
| 7  | 50,000 | 525,600   | discvHCK6CubyVi98ApA3hHZe6upLsQFBgxynvP6Qh8YVvmsm8KGmh5jo8pgBRi3hnMzHzBwdYLTr5VGbttzrbay4fmcnmjzGL4 |
| 8  | 50,000 | 613,200   | discvMQMcojCZEu2ftC4VJjTcWNoKC7BzVaoacJ6VLV1U1JRErbRSui6sbFD3niNYYDeBRTxMuSoP46JY3dqPdogPHMrSm4hNB8 |
| 9  | 50,000 | 700,800   | discvHqUUHDUcoMS5rhBrk1SLogbuvJrtJ8C2ELHF8AXiojEbgaJzyG1qQDrsvSU763i9rRYbsWzoe6WnqNnwxFU1jfv6FDevEW |
| 10 | 50,000 | 788,400   | discvN6sfcei19H5di7DhTCX3A3iRtGGy7Qjd7TvarANY79qwdPhgy5ao9TixPMngNMhE4L9qtPsZWRKQCpvJwUGUfDmeQBb7qu |
| 11 | 50,000 | 876,000   | discvP3X1kUUYoN27qG9ePRjrPDdJwM6hAzm6SF7HjByScivyyphTjJjEi5xPxzMaXZn4P4gkwqJr8SZXpJMv3PoYVPvDB8L1q1 |
| 12 | 50,000 | 963,600   | discvM5Byex9PXCQ3EBi4eCHNeqa5SCbUXtqkMs5dmcnY8nzPVAqUUQLmJYikqPzxwcSivU2LytcpCAhuwfitqksKYnM16HDLwP |
| 13 | 50,000 | 1,051,200 | discvNYfnh7T162gwWFiPbTVZms3KFbyxFseYvR67madZdeCGV9Pbnv3gZM15Xi4j9dooj7tyDJfV1n7DrJTUB2wLq6dDkFRBU7 |
| 14 | 50,000 | 1,138,800 | discvMmRc8b69cmap97R88YdcdnhmXE7UdzGTa91A3pQCtkV1kEj8LAGYG54Ttsi6HW27x3Q94MKe8oxMMGKKHm7GSt9xiCr3qq |
| 15 | 50,000 | 1,226,400 | discvMDUnoFhXdRLU6bTo5RBLP4x9QGEs79xi38GSAcBcqMERQYxghnTXepni8MPqY8yZvGCXpAFs7FGUudRVbvkeAangvYd5xW |
| 16 | 50,000 | 1,314,000 | discvKrfdhE3GE8Vn4imDk3qiJkgFmtkEYNRqe9viUhWVpnctcekaNXVWJiQJwDmgw9YnS9ZZh2sge8nh5B8LuhmLsDA5qp6oP8 |
| 17 | 50,000 | 1,401,600 | discvLoeXB5iQ5DsetxjG5VWMrgEFo1neCEQ3ny4ymGBZUcVnL9XQB83ErRd9LC3ZLCxcD3XZ27ZJd8HUV8Kttn8APJsMavN5d6 |
| 18 | 50,000 | 1,489,200 | discvKMgdJ4Xfdez8zthBKg6Yf8hHibC7GUm7AnUMzMLMKovJNUYgY647pDkMfhPyaRx7WLZ2NjtREngWAbfpf37epuimYcK7Sn |
| 19 | 50,000 | 1,576,800 | discvLQEHjYBGbu2xcr4HNN4opLn9SBd68RQdgzk68EFC32vT3YPTVwKcmwRvWKLVfNvWyEa9qAEpdAPjA3VQYucZnDTg8yEsyZ |
| 20 | 50,000 | 1,664,400 | discvK6a8MzJQ78SPRLJaEGrnncRnsGcmHr4StT33Lu3iXQbrvWPVigEwmdrkdq6ghMjjgnf4weEKgNsbCwD8xMzQwvNrYtj6ut |
| 21 | 50,000 | 1,752,000 | discvKDfytnhr5bww3aqipLUtts17A1mxVLzvpxKMhCELbC5ZdEAtfh7sYNoX528LoKd7F9nMzpJzeV6xvdFFvNheQc8JNoAZFJ |

The recipients' **public** ML-KEM/ML-DSA keys are baked into
`src/CryptoNoteCore/GenesisTreasuryReserveKeys.inc` (auto-generated; committed).
Each batch also has a full PQ address (the spendable address) recorded in the
offline secrets file below.

**Genesis block timestamp:** 2026-06-16 14:21:00 UTC (9:21 AM CDT) — the
publication time of the embedded Reuters headline (`m_genesisBlock.timestamp` in
`Currency::generateGenesisBlock`).

**Genesis block hash (mainnet):**
`a77e3f242f03f8ebe1d6bc4b50873fe157f4c2c95d9ff4207107991439c399ee`
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
- Input is a `BaseInput` at height 0; `extra` carries the Reuters headline
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
