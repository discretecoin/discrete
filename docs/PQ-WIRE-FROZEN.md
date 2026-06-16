# PQ Wire Format — Frozen Constants

> **DO NOT CHANGE any value in this file after the Discrete mainnet launch.**
> Every item below is consensus-critical: an independent implementation that
> disagrees on even one byte produces a different chain and cannot sync.
> Changes require a hard fork with a new domain tag or a bumped version byte.

Each constant is pinned by `tests/test_pq_domains.cpp`.  CI will fail on any
edit to a constant or to that test file's expected values.

---

## 1. Transaction wire format

| Constant | Value | File |
|---|---|---|
| `TRANSACTION_VERSION_1` | `1` | `src/CryptoNoteConfig.h` |
| `TX_COINBASE` (txType) | `0x00` | `include/PqTxType.h` |
| `TX_PQ` (txType) | `0x01` | `include/PqTxType.h` |
| `TX_BRIDGE` (reserved; consensus rejects) | `0x02` | `include/PqTxType.h` |
| `TX_FREE_REG` (txType) | `0x03` | `include/PqTxType.h` |

---

## 2. PQ blob size constants (consensus-enforced)

| Constant | Value (bytes) | Meaning |
|---|---|---|
| `PQ_KEM_CIPHERTEXT_SIZE` | `1088` | ML-KEM-768 ciphertext |
| `PQ_ENC_PAYLOAD_SIZE` | `56` | ChaCha20-Poly1305(rho \|\| LE64(T)): 40 ct + 16 tag |
| `PQ_AUTH_PUB_SIZE` | `1952` | ML-DSA-65 public spend key |
| `PQ_RHO_SIZE` | `32` | per-output blinding value |
| `PQ_SIGNATURE_SIZE` | `3309` | ML-DSA-65 signature |

All defined in `include/CryptoNote.h`.

---

## 3. Domain-separation tags (SHA3-256 preimage prefix, NUL excluded)

All tags are in `src/crypto_pq/PqDerive.h` and `src/crypto_pq/PqSeed.h`.
The bytes hashed are the ASCII contents of the string **without** any trailing
NUL terminator.

### Transaction derivation (PqDerive.h)

| Constant | String (ASCII) | Len |
|---|---|---|
| `kDomainInputsHash` | `karbo-pq-inputs-hash-v1` | 23 |
| `kDomainOutContext` | `karbo-pq-out-context-v1` | 23 |
| `kDomainAeadKey` | `karbo-pq-aead-key-v1` | 20 |
| `kDomainSpendCommit` | `karbo-pq-spend-commit-v1` | 24 |
| `kDomainNullifier` | `karbo-pq-nullifier-v1` | 21 |
| `kDomainTxSign` | `karbo-pq-tx-sign-v1` | 19 |
| `kDomainCoinbaseRho` | `discrete-coinbase-rho-v1` | 24 |

### Seed / key derivation (PqSeed.h)

| Constant | String (ASCII) | Len |
|---|---|---|
| `kDomainViewRoot` | `karbo-pq-view-root-v1` | 21 |
| `kDomainSpendRoot` | `karbo-pq-spend-root-v1` | 22 |

### Reserved (Phase 2, must not be used by Phase 1 code)

| Constant | String (ASCII) | Len |
|---|---|---|
| `kReservedCtMask` | `karbo-pq-ct-mask-v1` | 19 |

---

## 4. AEAD instantiation (normative)

ChaCha20-Poly1305 IETF (RFC 8439), one output:

| Field | Size / value |
|---|---|
| Key | 32 bytes — `deriveAeadKey(ss, outContext)` |
| Nonce | 12 zero bytes (safe: key is unique per output) |
| AAD | 40 bytes: `outContext` (32) \|\| `LE64(amount)` (8) |
| Plaintext | 40 bytes: `rho` (32) \|\| `LE64(T)` (8) |
| Ciphertext | 40 bytes |
| Auth tag | 16 bytes |
| On-wire (`encPayload`) | 56 bytes = ciphertext \|\| tag |

`T` (subaddress index) is bound into both `outContext` (key derivation) and the
plaintext so that a tampered routing hint breaks AEAD tag verification.

---

## 5. outContext derivation formula

```
outContext = SHA3-256(
    kDomainOutContext          ||   // "karbo-pq-out-context-v1", 23 bytes
    inputsHash                 ||   // 32 bytes
    kemCt                      ||   // 1088 bytes
    LE32(outputIndex)          ||   // 4 bytes
    LE64(subaddrIndexT)            // 8 bytes  ← added Step 0.1
)
```

`subaddrIndexT = 0` for all single-address (non-deposit-wallet) outputs.

---

## 6. Signing digest formula

```
txSigningDigest = SHA3-256(
    kDomainTxSign              ||   // "karbo-pq-tx-sign-v1", 19 bytes
    version (1 byte)           ||   // TRANSACTION_VERSION_1 = 1
    txType  (1 byte)           ||
    LE64(unlockHeight)           ||
    LE32(#inputs)              ||
    for each input:
        prevTxid (32)          ||
        LE32(prevOutIndex)     ||
        authPub  (1952)        ||
        rhoReveal (32)         ||
    LE32(#outputs)             ||
    for each output:
        type (1 byte = 0x10)   ||
        LE64(amount)           ||
        LE64(unlockHeight)     ||   // added per-output spend lock
        kemCt (1088)           ||
        encPayload (56)        ||
        spendCommit (32)       ||
    LE32(extra_len)            ||
    extra                      ||
    LE64(fee)
)
```

---

## 7. On-chain TransactionOutput layout

Each `TransactionOutput` (`vout` entry) serializes as:

```
LE64(amount)                  ||
LE64(unlockHeight)            ||   // added per-output spend lock
type (1 byte = 0x10)          ||   // PqOutput variant tag
kemCt (1088) || encPayload (56) || spendCommit (32)
```

`unlockHeight` is a consensus field: the output is unspendable until the chain
reaches that block height (`0` = no lock). It is per-output — distinct from the
per-tx `TransactionPrefix.unlockHeight` — so one transaction can time-lock some
outputs (a vesting payment, a genesis premine tranche) while leaving others
(change) spendable. It is bound into `txSigningDigest` (§6) and the txid, so it is
not malleable. It is **not** part of `outContext` or the AEAD AAD (key derivation
and ownership are independent of the lock).

---

## 8. Coinbase recipient == block signer (identity-bound mining)

Every non-genesis block carries an ML-DSA-65 signature over
`SHA3-256(get_block_hashing_blob(b))`, verified against the producer spend pubkey
in the coinbase `extra` (tag `0x07`). Additionally, the **single** coinbase
`PqOutput` must pay that same identity:

```
rho_C        = SHA3-256(kDomainCoinbaseRho || signerSpendPub || LE32(height))
require: coinbaseOutput.spendCommit == SHA3-256(kDomainSpendCommit || signerSpendPub || rho_C)
```

`rho_C` is canonical (publicly recomputable from the signer pubkey + height), so
consensus enforces that the miner who *signs* the block is the miner who gets
*paid* — you cannot mine to a key you do not hold. This is the anti-pool/botnet
property: aggregating hashpower requires sharing the spend secret. The coinbase is
a single undivided output (one signature, minimal size). Genesis (height 0) is
exempt (it is trusted and carries the premine to many recipients). Enforced in
`Blockchain::validate_block_signature`; built in `Currency::constructMinerTxPq`.

Because `rho_C` is **public** (unlike a normal output's secret random `rho`), the
nullifier binds the spent output's **outpoint** so the public value can't be
replayed into a colliding output:

```
nullifier = SHA3-256(kDomainNullifier || spendPub || rho || prevTxid || LE32(prevOutIndex))
```

Two outputs that share `(spendPub, rho)` therefore still get distinct nullifiers.
The outpoint is revealed in the spending `PqInput` regardless, so this adds no
leakage. Normal (non-coinbase) outputs keep a secret random `rho`, so their
recipient stays unlinkable until spend.

---

*(§§ renumbered as features were added.)*

---

*Last updated: 2026-06-14 (per-output unlockHeight added to the wire and
signing digest;*
