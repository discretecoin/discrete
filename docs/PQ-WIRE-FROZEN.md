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
| `0x02` (permanently reserved; no named constant; consensus rejects) | `0x02` | `include/PqTxType.h` |
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
| `kDomainInputsHash` | `discrete-pq-inputs-hash-v1` | 26 |
| `kDomainOutContext` | `discrete-pq-out-context-v1` | 26 |
| `kDomainAeadKey` | `discrete-pq-aead-key-v1` | 23 |
| `kDomainSpendCommit` | `discrete-pq-spend-commit-v1` | 27 |
| `kDomainNullifier` | `discrete-pq-nullifier-v1` | 24 |
| `kDomainTxSign` | `discrete-pq-tx-sign-v1` | 22 |
| `kDomainCoinbaseRho` | `discrete-coinbase-rho-v1` | 24 |

### Seed / key derivation (PqSeed.h)

| Constant | String (ASCII) | Len |
|---|---|---|
| `kDomainViewRoot` | `discrete-pq-view-root-v1` | 24 |
| `kDomainSpendRoot` | `discrete-pq-spend-root-v1` | 25 |

### Reserved (Phase 2, must not be used by Phase 1 code)

| Constant | String (ASCII) | Len |
|---|---|---|
| `kReservedCtMask` | `discrete-pq-ct-mask-v1` | 22 |

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
    kDomainOutContext          ||   // "discrete-pq-out-context-v1", 26 bytes
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
    kDomainTxSign              ||   // "discrete-pq-tx-sign-v1", 22 bytes
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
LE64(unlockHeight)            ||   // per-output spend lock (0 = none)
type (1 byte)                 ||   // variant tag — see below
<variant-specific payload>
```

Two output variants exist:

| Tag | Type | Payload |
|---|---|---|
| `0x10` | `PqOutput` (regular TX_PQ) | `kemCt (1088)` \|\| `encPayload (56)` \|\| `spendCommit (32)` = **1176 B** |
| `0x11` | `CoinbaseOutput` (TX_COINBASE) | `spendCommit (32)` = **32 B** |

`CoinbaseOutput` is used for all coinbase transactions (mined blocks and the genesis Treasury Reserve). It carries only the 32-byte spend commitment; there is no KEM ciphertext or encrypted payload because the recipient recovers ownership deterministically via `coinbaseRho` (§8). Savings per mined block: **1,144 B** (1,088 + 56).

`unlockHeight` is a consensus field: the output is unspendable until the chain
reaches that block height (`0` = no lock). It is per-output — distinct from the
per-tx `TransactionPrefix.unlockHeight` — so one transaction can time-lock some
outputs (a vesting payment, a genesis Treasury Reserve batch) while leaving others
(change) spendable. It is bound into `txSigningDigest` (§6) and the txid, so it is
not malleable. It is **not** part of `outContext` or the AEAD AAD (key derivation
and ownership are independent of the lock).

---

## 8. Coinbase recipient == block signer (identity-bound mining)

Every non-genesis block carries an ML-DSA-65 signature over
`cn_fast_hash(get_block_hashing_blob(b))`, verified against the producer spend
pubkey in the coinbase `extra` (tag `0x07`). (`cn_fast_hash` is the CryptoNote
block hash — Keccak with 0x01 padding — i.e. the block's own identity hash, NOT
NIST SHA3-256. The SHA3-256 family is used only for the PQ *derivations* in §§3–6;
the block signature reuses the existing block-hash function. Enforced in
`Blockchain::validate_block_signature`.) Additionally, the **single** coinbase
`CoinbaseOutput` must pay that same identity:

```
rho_C        = SHA3-256(kDomainCoinbaseRho || signerSpendPub || LE32(height) || LE32(outputIndex))
require: coinbaseOutput.spendCommit == SHA3-256(kDomainSpendCommit || signerSpendPub || rho_C)
```

For normal mined blocks `outputIndex = 0` (single output). For the genesis
Treasury Reserve (height 0, 21 outputs to independent keys), `outputIndex = i`
for the `i`-th batch, ensuring each batch gets a unique `rho_C` even at the same
height. Wallets scan by trying `coinbaseRho(ownSpendPub, height, i)` for each
output index `i` — no KEM decapsulation, constant time per candidate.

`rho_C` is canonical (publicly recomputable from the signer pubkey + height +
outputIndex), so consensus enforces that the miner who *signs* the block is the
miner who gets *paid* — you cannot mine to a key you do not hold. This is the
anti-pool/botnet property: aggregating hashpower requires sharing the spend
secret. The coinbase is a single undivided output (one signature, minimal size).
Genesis (height 0) is exempt from signature validation (trusted) and carries the
Treasury Reserve to 21 independent recipients. Enforced in
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
