# Discrete genesis

The genesis block is frozen. Every node must agree on it byte-for-byte. This
document records what it contains, how to regenerate/verify it, and where the
recipient secrets live.

## What genesis contains

The genesis coinbase carries the entire **premine** as per-output-unlocked
`PqOutput`s — one tranche per recipient — in a single transaction. This is
possible because Discrete added a per-output `unlockHeight` to the wire (see
[PQ-WIRE-FROZEN.md](PQ-WIRE-FROZEN.md)), so staggered unlock times fit in one
coinbase tx and `GENESIS_COINBASE_TX_HEX` remains the single frozen artifact.

- **Total premine:** 7,000,000 XDS (700,000,000 atoms; ~33% of the 21,000,000 XDS
  emission ceiling — premine counts *within* the cap, so it reduces ongoing block
  reward, it is not minted on top).
- **Tranches:** 14 × 500,000 XDS (50,000,000 atoms each).
- **Unlock schedule:** tranche *k* (1-based) unlocks at height `(k-1) × 80,000`.
  At a 90 s block target the last tranche unlocks in ~2.97 years.

| Tranche | Amount (XDS) | Unlock height | Recipient (classical address) |
|--------:|-------------:|--------------:|-------------------------------|
| 1  | 500,000 | 0         | discvJNdeTDJdAF9K5mq6hEX3uSS4R7p3hMrH2eRk5iY5q8XDpk2YwWGBeqcGXUiPjQEuWwnZ27LtBUsRKwrZDQeLqusTq7bwRd |
| 2  | 500,000 | 80,000    | discvLZGEDPLnHV8htRQG2NJ57x3QpLrrDD694p724HpSRv4rhE84J4QY6UupUjS1ebQQGZZtTw6YNhSDo727ckJ6MgHCwYHYSf |
| 3  | 500,000 | 160,000   | discvNfMDNEApeKDaqxJvKPZxYBkL4C3VCvexvrmYdvra99xTavgSMkFEr6fYHgstLdQkmZPaBbviQgXKBSZyVp1LUD8EejPqTu |
| 4  | 500,000 | 240,000   | discvMWCF1rRbW8bpf64dTVe4fnxpnPpN236NM8SkUXy8pK4eaHUFEVdzh3bnyr4mNMK9RiUWZcs9AgoHFabovac64g92dSjKvf |
| 5  | 500,000 | 320,000   | discvLEZdSegvwYrsg7qgUVB52FQ6mFzDUhmhE7wjhaYUJoiR7hz7mFeV7qSF4gfhzdMcHC3cV6vxCVqSNQuitH5GxfD3dmnad9 |
| 6  | 500,000 | 400,000   | discvJdaJuN7u1Y4pZHX5NPhdnUDPS6rjZVtHtc6uSHuTRDZrosYqsqcF5iKxSRYUzCeqqN95cxDa21PeJimp3evECbKA2KoRau |
| 7  | 500,000 | 480,000   | discvLc8Q4gNekowJjM9Df4gvQbdRVbRsFhoaaTqLRuhAT64RSD3jJxV6UmTHidBH6DV3wTkG5CtJiknhNfs2odH2G7bEem1uFA |
| 8  | 500,000 | 560,000   | discvKjh2iq3VCYNCuK3VMHaBLr9GPjPq1To9PNPNkdT2fRQ3G7HePZEx6dXB2Kbt7eJ71w1QWafXjoRERTVQknMMuHEDfkhh7E |
| 9  | 500,000 | 640,000   | discvHf9N5fG9WCnWG1JAvFhrtrZQhKwrG1aGKhsn2gDCHB6vhUTKxzX7sGWnSr7yND8pKDAKLDA51SfdWG14gVG3UUezyJQjHZ |
| 10 | 500,000 | 720,000   | discvNBKdmzW7TyMQJUnnkfmHZ39yRsfhbEf4jfx7cwCNqdWECmVFBNDWDxS5rfG9RSqW9KRN8csmhiM2Xsg3L13PWnAcr6cm4x |
| 11 | 500,000 | 800,000   | discvL7J6EDSu5MaUCw5MK6my8pfFkDmr5VM6vMNihmK7zxh3rJLN7qSxbnpLTRT64ATgDGXPGGmq6cTS6X3q5sqYzAKJzCRifE |
| 12 | 500,000 | 880,000   | discvMoKpKDjHiwUvqVmhK8VSS3TmzKq91Ah32eviMLkfJ1iRp5pdoA3EuQeGjwbUfKuHFUqiEg4PNTridq1RPdCFDESyLdf52j |
| 13 | 500,000 | 960,000   | discvJHwyuMDJz9wopjDJKesdZBjjVXQY8M1tQSHcYuv3G8nRkPdDZrXpCyjGu1Aq1WsahxUV9cK21shMEBiSZEGNULw5Uw8y97 |
| 14 | 500,000 | 1,040,000 | discvJDyxEoNaYekphMHFKV6VGQAvACLDcu47ub2Jv1MQp9JSNRB137QMBAwjsiaSzeyRxrjcartY6E2VfqyscQRhjwADd9xJXG |

The recipients' **public** ML-KEM/ML-DSA keys are baked into
`src/CryptoNoteCore/GenesisPremineKeys.inc` (auto-generated; committed). Each
tranche also has a full PQ address (the spendable address) recorded in the
offline secrets file below.

**Genesis block hash (mainnet):**
`69462d0732edab6182c8872315dc0ea7a0d6a8695971c405894f4e17014b1de8`
(pinned by `tests/test_pq_genesis.cpp`).

## Recipient secrets

`vanitygen --premine-accounts 14` wrote the 14 recipients' 25-word mnemonics,
classical + PQ addresses, and public keys to `genesis/premine-accounts.txt`. That
file is **gitignored and must never be committed** — it controls 7,000,000 XDS.
Move it to cold storage. Each mnemonic, loaded into `simplewallet`, recovers its
tranche (the wallet derives the same PQ identity via `derivePqWalletKeys`).
Multisig recipients were considered but are out of scope (no PQ multisig exists
yet); recipients are single-key accounts.

## How the coinbase is built (deterministically)

`buildGenesisPremineCoinbase()` (`src/CryptoNoteCore/GenesisPremine.cpp`) builds
the coinbase deterministically so two runs on any host produce identical bytes:

- For tranche *i*: `kemSeed = HKDF(LE32(i), "discrete-genesis-kem-v1")`,
  `rho = HKDF(LE32(i), "discrete-genesis-rho-v1")`.
- `(kemCt, ss) = kem_encaps_derand(viewPub_i, kemSeed)` — a real encapsulation the
  recipient can still decapsulate, made reproducible via a seed-driven RNG.
- `buildPqOutput(kemCt, ss, spendPub_i, inputsHash=0, outputIndex=i, 50,000,000,
  rho, T=0)`, then `unlockHeight = i × 80,000`.
- Input is a `BaseInput` at height 0; `extra` carries an all-zero ML-DSA miner
  spend pub (genesis is trusted — its block signature is skipped at height 0).

These domain strings and amounts are part of the frozen artifact — do not change.

## Regenerate / verify the frozen hex

1. Build the daemon: `cmake --build build --config Release --target Daemon`.
2. `discreted --print-genesis-tx` — prints `GENESIS_COINBASE_TX_HEX`. Run it twice;
   the output is identical.
3. Paste the hex into `src/CryptoNoteConfig.h` `GENESIS_COINBASE_TX_HEX`. (MSVC
   caps a string literal at ~16 KB, so the constant is split into adjacent string
   literals — the compiler concatenates them.)
4. `ctest -C Release -R PqGenesis` verifies: the 14-tranche structure and unlock
   schedule, total = 700,000,000 atoms, builder determinism, that the frozen hex
   equals the builder output, and the pinned genesis block hash.

To regenerate the recipient accounts (new chain only — this changes the genesis):
`vanitygen --premine-accounts 14 --file genesis/premine-accounts`, copy
`genesis/premine-accounts.inc` over `src/CryptoNoteCore/GenesisPremineKeys.inc`,
rebuild, re-run `--print-genesis-tx`, and re-freeze the hex + the pinned hashes.
