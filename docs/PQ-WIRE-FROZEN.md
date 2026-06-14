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
| `TRANSACTION_VERSION_PQ` | `1` | `src/CryptoNoteConfig.h` |
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
    version (1 byte)           ||   // TRANSACTION_VERSION_PQ = 1
    txType  (1 byte)           ||
    LE64(unlockTime)           ||
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
        kemCt (1088)           ||
        encPayload (56)        ||
        spendCommit (32)       ||
    LE32(extra_len)            ||
    extra                      ||
    LE64(fee)
)
```

---

*Last updated: 2026-06-13 (Step 0.1 + Step 0.2 of Phase 0 wire freeze)*
