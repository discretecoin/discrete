# PQ Payer Payment Proof (minimal, off-chain)

Status: **Phases 1–3 implemented; Phase 4 not implemented. Phase 3 awaits follow-up review.** 2026-07-12.
Branch `dev/payment_proof`. This is the *minimal* payer proof chosen after three security
reviews (see [PQ-TX-PROOFS.md](PQ-TX-PROOFS.md) on branch `dev/tx_proof` for the
heavier seed-recoverable/tx-secret-key design that was **rejected as too invasive** for
an optional feature). **No wire, consensus, fee, `tx_extra`, or seed-recovery change.**
Gate before production: specialist review of explicit-coins ML-KEM (§10).

---

## 1. Goal

Let a **payer** prove, off-chain and after the fact, that a specific transaction paid a
specific recipient a specific amount — verifiable by a party who does **not** hold the
recipient's view key (an auditor, a counterparty, or an exchange support desk acting on
a depositor's claim). This is the classic "transaction proof" an exchange asks a
depositor for when automated attribution fails.

Non-goals (already covered without any change): a recipient who *holds* the view key —
e.g. the exchange verifying its own deposits — just scans the txid with its own key via
the existing `scanPqOutput` path. This document is only for the payer-side, no-view-key
case.

## 2. The single change to established code: explicit-coins encapsulation

Today `buildPqOutput` calls `kem_encaps(view_pub)`, which draws the ML-KEM message `m`
from the RNG internally and **discards it** — so nothing can be proven later. The one
change:

- generate a **fresh 32-byte CSPRNG message `m_j`** per output (the same secure RNG the
  wallet already uses);
- encapsulate with a **reentrant explicit-coins** call `enc_derand(view_pub, m_j)`
  (mlkem-native `crypto_kem_enc_derand(ct, ss, pk, coins)`), **not** the existing
  `kem_encaps_derand` global-RNG-swap helper (§10);
- keep `rho` independently random, exactly as today;
- retain `m_j` in memory for the proof.

FIPS 203 `Encaps` *is* "draw random `m`, then `Encaps_internal(pk, m)`", so supplying a
fresh CSPRNG `m_j` produces an **output identically distributed and byte-identical in
format** to the current path. `kem_ct`, `enc_payload`, `spend_commit` are unchanged.
Nothing else in the send path changes — no `tx_extra`, no fee/size accounting, no
wallet-format schema, no consensus rule, no seed-recovery contract. The genesis coinbase
keeps its own pinned `kem_encaps_derand` path untouched.

## 3. Proof artifact

A payment decomposes into several canonical-denomination outputs, so one logical payment
to a recipient is **several outputs**; the proof must cover all of them:

```
PaymentProof {
  version                    // u8
  genesis_id                 // 32B — network binding (in the signed/verified data, not the HRP)
  txid                       // 32B
  recipient_descriptor_hash  // 32B = SHA3-256("discrete-pq-recipient-v1" || canonical(viewPub, spendPub, LE64(T)))
  entries[] {                // one per output paying THIS recipient; change outputs excluded
    output_index             // u32 (position in tx.outputs)
    m_j                      // 32B ML-KEM message for that output
  }
}
```

- **One proof per logical recipient.** Change outputs (to self) are never included.
- **Encoding:** versioned bech32m, HRP `disctxp`/`tdisctxp` (`disctxp1…`). bech32m gives
  typo detection + a human label **only**; it is not authentication and does not bind
  the network — anyone can re-encode under another HRP (BIP-350). Network/recipient
  binding comes from `genesis_id` and `recipient_descriptor_hash` inside the artifact and
  from the verification checks, never from the checksum.

## 4. Verification (full receiver scan)

Inputs: the proof, the on-chain transaction (fetched by `txid`), and a canonical
**`ResolvedRecipient { KemPublicKey viewPub; DsaPublicKey spendPub; uint64_t
subaddrIndexT; }`**. Account numbers (H-I-C / H-I-T-C) are resolved to a
`ResolvedRecipient` by the caller (daemon registry) *before* the pure verifier runs —
the crypto core takes keys+T, never an address string.

```
require proof.genesis_id == this network's genesis id
require proof.recipient_descriptor_hash == SHA3(... || canonical(viewPub, spendPub, T))
total = 0
for each entry:
    j  = entry.output_index;  out = tx.outputs[j] must be a PqOutput
    (ct', ss') = enc_derand(viewPub, entry.m_j)          # explicit-coins re-encaps
    require ct' == out.kem_ct                             # delivered to recipient's VIEW key
    oc  = outContext(inputs_hash(tx), out.kem_ct, j, T)
    pt  = AEAD_decrypt(deriveAeadKey(ss', oc), nonce=0,
                       aad = oc || LE64(out.amount), out.enc_payload)
    require pt == rho || LE64(T)                          # authenticates payload, recovers rho, checks T
    require out.spend_commit == spendCommit(spendPub, rho)# pays recipient's SPEND key
    require j not already counted                         # duplicate-index guard
    total += out.amount
return total    # amount proven paid to this recipient in this tx
```

This is exactly the receiver's own scan predicate, so a valid proof means the recipient's
wallet genuinely detects and can spend those outputs.

## 5. Soundness

- **Delivery** is proven by `ct' == kem_ct` (ML-KEM ciphertexts are public-key-binding;
  an output encapsulated to a different view key won't match).
- **Recipient** is proven by `spend_commit == spendCommit(spendPub, rho)` (a SHA3
  second-preimage would be needed to point it at a different spend key).
- **Amount/T integrity** is proven by the AEAD tag over `aad = out_context || LE64(amount)`.
- **No over-reporting:** a non-recipient output fails the `spend_commit` check, so it
  cannot be added. **No forgery:** without the real `m_j`, `ct'` won't match. A dishonest
  payer can only *under*-report (omit outputs), which cannot inflate the proven amount —
  so the result is "these outputs paid the recipient, summing to `total`" (exact when all
  of the recipient's outputs are included).
- Spending still requires the recipient's ML-DSA `spend_sk`; the proof never enables a
  spend.

## 6. Crash-safety and storage

The proof is **not recoverable from the mnemonic** (its `m_j` values are fresh randomness
retained only at send time), so it must be captured atomically, before the tx can exist
without it:

1. build outputs (explicit-coins), **self-verify each** (§7), assemble the proof(s);
2. **atomically persist** the finished proof(s) in the wallet-specific archive described
   below — **before** relaying;
3. relay the transaction;
4. display / return the proof;
5. let the user export or delete the saved copy later.

Saving before relay closes the crash window where a tx could broadcast but the proof be
lost. A record saved before an unsuccessful or ambiguous relay is deliberately retained:
"not found" does not prove that the transaction was never accepted.

The authoritative archive is `<wallet-file>.payment-proofs/`. Each transaction is stored
as `<lowercase-txid>.pproof`; no user-controlled path component is used. Archive version
1 is `DPPR || u8(version) || genesis[32] || txid[32] || LE32(row-count)`, followed by
ordered rows `LE32(address-size) || address || LE64(amount) || LE32(proof-size) || proof`.
Lengths and row counts are bounded. Rows are the wallet's existing `SentPaymentEntry`
records and use its existing opaque `proof` field; there is no parallel payment schema.

Writes use a temporary sibling file, durable file flush, atomic rename, and parent
directory flush where supported. The completed file is read back and all enclosed proofs
must decode and match its network and txid before relay is authorized. Identical writes
are idempotent; a conflicting record for the same txid is never overwritten.

At startup, files are validated independently and reconciled into `SentPaymentsStore`.
A damaged file is reported by filename without logging proof contents and does not hide
other records or prevent wallet access. The encrypted wallet cache mirrors the store, but
is not the pre-relay durability barrier. Blockchain reset/rescan rebuilds chain-derived
state and then reloads this archive; it does not delete payer proofs. Mnemonic-only
restoration without this directory cannot recreate them.

Both wallet engines follow `build/sign -> final proof verification -> durable archive ->
relay`. WalletGreen rolls back its input reservation on persistence or relay failure;
both engines retain the already-durable proof record after relay failure.

Send-result UX:

```
Transaction sent:
  txid: ...
  paid: 125.00 XDS
  payment proof: disctxp1...
IMPORTANT: store this proof — it cannot be recovered from your mnemonic.
```

## 7. Sender self-check (hardening, retained)

The builder holds `ss` for every output, so before relay it re-runs §4's scan on each
output it built and aborts if any does not round-trip to `rho || LE64(T)` and its
`spend_commit`. This makes an honest wallet structurally unable to emit an undetectable
output (catches decomposition/`T` bugs); it cannot stop a deliberately malicious build,
but that only harms the attacker's own payments.

## 8. Privacy

Publishing a proof reveals, for the covered outputs only, the **recipient relationship**
and `rho` (via decryption). It does **not** permit spending (needs the recipient's
ML-DSA secret). This is Phase-1-safe: Phase-1 spends already reveal the outpoint openly,
so the coin is already traceable and the revealed `rho` adds nothing. **It must not be
extended to Phase 3 shielded coins**, where `rho`-class material would leak serial
linkage — a shielded proof needs a NIZK instead.

## 9. What this omits vs. the shelved `dev/tx_proof` design

No transaction secret key `r`; no HKDF proof derivation; no `tx_extra` salt tag; no
parser/consensus/fee changes; no seed-recovery contract; and therefore **no
same-input deterministic AEAD reuse risk** (every `m_j` is fresh random, so keys/nonces
never repeat). The cost is the accepted, documented tradeoff: mnemonic-only restore does
not recover past outgoing payment proofs (§6 handles this operationally).

## 10. Gate before production

- **Explicit-coins ML-KEM specialist review.** FIPS 203 restricts internal derandomised
  interfaces to testing; using `enc_derand` on a production path (with a wallet-chosen
  CSPRNG `m_j`) needs sign-off. No strict-FIPS claim until then.
- **OQS exposure.** `crypto_kem_enc_derand` is namespaced inside mlkem-native and is not
  in OQS's public API (`OQS_KEM_ml_kem_768_encaps` only). Add a thin, reentrant C wrapper
  (or export the symbol) — do **not** reuse the global-RNG-swap `kem_encaps_derand`.
- Freeze `version`, `genesis_id` inclusion, `recipient_descriptor_hash` preimage, and the
  bech32m HRPs before pinning any proof KAT vectors.

## 11. Implementation phases (each independently testable)

1. **crypto_pq:** reentrant `enc_derand` wrapper; `PqPaymentProof` (assemble / encode /
   decode / full-scan verify taking `ResolvedRecipient`); KAT + adversarial tests
   (foreign view key, garbage payload, wrong T, duplicate index, over-report attempt,
   wrong recipient/network). No wallet dependency.
2. **Send path:** switch output construction to explicit-coins with retained `m_j`
   (byte-identical outputs); self-verify (§7); assemble per-recipient proofs; return them.
3. **Wallet storage/UX (implemented, review pending):** atomic save-before-relay;
   wallet-specific archive; CLI print/retrieve/export/import/delete; authenticated walletd
   send/retrieve/export/import/delete RPC. Import fetches the transaction and runs the
   full verifier before persistence.
4. **Verify surface:** daemon/library `check_payment_proof(proof, recipient|account)` →
   amount; explorer "Prove payment" box (separate repo). Recipient resolution
   (account-number → `ResolvedRecipient`) is upstream of the pure verifier.
