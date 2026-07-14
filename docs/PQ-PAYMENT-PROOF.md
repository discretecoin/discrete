# PQ payer spend-authority proof (minimal, off-chain)

Status: **Phases 1–3 implemented; Phase 4 not implemented.** 2026-07-12.
Branch `dev/payment_proof`.

The artifact remains exposed through the existing payment-proof wallet fields and RPC
names, but version 2 has deliberately narrower cryptographic semantics: it proves that
listed transaction outputs commit to a recipient spend public key. It does **not** prove
ML-KEM/view-key delivery or a SingleKeyIndex routing index `T`.

There is no wire, consensus, fee, `tx_extra`, seed-recovery, or vendored-liboqs change.
Output construction calls the normal public `OQS_KEM_ml_kem_768_encaps` interface.

---

## 1. Why the original delivery proof was replaced

The original version retained the 32-byte `m` input to ML-KEM's internal deterministic
encapsulation operation, then re-encapsulated publicly during verification. That is not
an application interface defined by FIPS 203. FIPS 203 requires application-facing
encapsulation to generate its randomness inside the cryptographic module and limits the
internal deterministic operation to testing. liboqs likewise exposes only ordinary
encapsulation through its public ML-KEM API.

With the standard public API, the sender receives `(ciphertext, shared_secret)` but not
the internal randomness. Neither value provides a publicly checkable witness tying the
ciphertext to a view public key: the shared secret is not publicly derivable and cannot
be verified without the view secret key. Therefore a unilateral, noninteractive proof
of view-key delivery is impossible with the current wire format and public ML-KEM API.

Version 2 instead uses an independent value the sender already creates: `rho`.

## 2. What version 2 proves

Every current PQ output contains:

```
spend_commit = SHA3-256(spend_pub || rho)
```

The sender knows the independently random `rho` while constructing the output. A proof
reveals `rho` for selected output indexes. A verifier recomputes the commitment against
the claimed spend public key and sums the public on-chain amounts.

This proves:

- the listed, txid-bound outputs commit to the claimed ML-DSA spend authority;
- the output indexes are unique and in range;
- the public amounts of those outputs sum to the returned total;
- an output committed to another spend key cannot be added without a SHA3-256
  second-preimage.

It does not prove:

- that `kem_ct` was encapsulated to the recipient's ML-KEM view key;
- that the recipient wallet detected or decrypted the output;
- the encrypted routing value `T` used by SingleKeyIndex deposits;
- that a malicious payer did not intentionally construct an undetectable/burned output.

For ordinary addresses and AggregatedMultikey deposits, a distinct spend key generally
identifies the intended authority. Under SingleKeyIndex, all deposits share the spend
key, so this proof identifies only the shared wallet, not an individual `T` deposit.
The saved recipient address remains useful payer-side metadata, not cryptographic
evidence of view-key or `T` delivery.

## 3. Artifact

```
SpendAuthorityProof {
  version               // u8 = 2
  genesis_id            // 32B network binding
  txid                  // 32B transaction binding
  spend_authority_hash  // SHA3-256(domain || spend_pub)
  entries[] {
    output_index        // u32
    rho                 // 32B commitment opening
  }
}
```

The existing bech32m HRPs remain `disctxp` and `tdisctxp`. The HRP/checksum is only a
human label and typo check; `genesis_id` supplies the cryptographic network binding.
Version 2 prevents old explicit-ML-KEM witnesses from being reinterpreted as rho.

One artifact is produced per logical recipient row. Canonical denomination splitting
may place several output entries in one artifact. Change outputs are excluded.

## 4. Verification

The verifier receives a canonical chain transaction and a resolved recipient:

```
require proof.version == 2
require proof.genesis_id == selected network genesis
require proof.txid == canonical transaction id
require proof.spend_authority_hash == H(domain || recipient.spend_pub)

total = 0
for entry in proof.entries:
    require entry.output_index is unique and in range
    out = transaction.outputs[entry.output_index]
    require out is the canonical output at that index
    require spendCommit(recipient.spend_pub, entry.rho) == out.spend_commit
    total += out.public_amount with overflow checking
return total
```

The caller must construct the proof view from the fetched canonical transaction; the
txid binds its output contents. Import paths fetch the transaction and verify it before
persisting the artifact.

## 5. Strong delivery proof: recipient-signed receipt

A full proof of actual receipt can be added without changing liboqs or transaction wire
formats, but it is interactive:

1. the recipient scans the canonical transaction using its ML-KEM view secret key;
2. after confirming output indexes, amounts, spend commitments, and `T`, it signs a
   domain-separated receipt with the corresponding ML-DSA spend secret key;
3. the receipt covers `genesis_id`, `txid`, recipient descriptor, output indexes,
   amounts, and an optional payer nonce;
4. anyone verifies the receipt using the recipient ML-DSA public key.

This uses only standard public ML-KEM decapsulation and ML-DSA sign/verify operations.
It is the recommended future Phase 4 surface where proof of view-key delivery or exact
SingleKeyIndex attribution is required. The unilateral rho artifact can be attached to
the receipt but is not a substitute for it.

## 6. Sender construction and self-check

Output construction remains conventional:

1. call public `ML-KEM.Encaps(view_pub)`;
2. draw independent random `rho` from the existing OS CSPRNG;
3. build `enc_payload` and `spend_commit`;
4. use the returned shared secret to run the complete receiver-side predicate as a
   sender self-check before the output is accepted;
5. retain `rho` only long enough to assemble and durably store version-2 artifacts.

The self-check catches honest implementation errors. It does not turn the unilateral
proof into evidence of view-key delivery against a deliberately malicious sender.

## 7. Storage and crash safety

The authoritative archive is `<wallet-file>.payment-proofs/`. Transaction records are
stored as `<lowercase-txid>.pproof` and contain the wallet's existing ordered
`SentPaymentEntry { address, amount, proof }` rows. There is no parallel recipient
schema.

Writes use a temporary sibling, durable file flush, atomic replacement, parent-directory
flush where supported, and exact read-back validation before relay. The archive has an
authority marker. Before the marker exists, cached records are migrated once. After it
exists, the directory is a complete snapshot: a missing transaction file is an explicit
deletion and a stale encrypted cache cannot resurrect it.

On POSIX the directory/files are restricted to mode 0700/0600. On Windows they receive
a protected DACL granting access only to the current user. Export paths inside the
authoritative directory are rejected so a selected-row export cannot overwrite archive
state.

Both wallet engines follow `build/sign -> verify proof -> durable archive -> relay`.
The encrypted wallet cache mirrors the archive but is not the durability authority.

## 8. RPC and logging security

RPC Basic Auth is optional for both `walletd` and `simplewallet`: authentication is
disabled when both `--rpc-user` and `--rpc-password` are omitted. `walletd` is restricted
to a loopback bind. Remote operation must use an authenticated TLS tunnel or reverse proxy;
the built-in server always exposes a plaintext HTTP listener even when its additional
HTTPS listener is enabled. Malformed JSON-RPC logs never serialize the request body, so
proof blobs are not copied into logs.

## 9. Privacy and future hidden amounts

Publishing version 2 reveals `rho` for covered outputs and links them to a spend public
key. That is acceptable only for the current traceable transaction model: current
spends already reveal `rho` and the authorizing public key. Do not reuse this artifact
unchanged for an untraceable transaction design.

For hidden amounts, the rho opening can continue to prove spend authority, but it cannot
prove a concealed amount. The hidden-amount design must expose a public amount commitment
and define a separate proof/opening for the claimed amount (or a zero-knowledge proof).
Do not reveal ML-KEM internal randomness or the ML-KEM shared secret to open an amount;
that would couple payment evidence to view-key confidentiality.

## 10. Remaining work

- Phase 4 public verification surface and explorer integration.
- Optional recipient-signed ML-DSA receipt for strong delivery and exact `T` evidence.
- Hidden-amount proof composition after the amount-commitment format is finalized.
- Independent cryptographic and operational review before production release.
