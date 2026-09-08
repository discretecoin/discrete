# Agave v3 loader operations — independent evidence review

Reviewed 2026-09-08 UTC. The retained evidence supports an actual standard-loader upgrade and subsequent authority removal for the owned, genesis-preloaded program on the specified private Agave chain. The current finalized account readback confirms ProgramData authority `None` and the exact reviewed Rust ELF. The initial metadata-verifier failure remains recorded as a failure; it is not relabeled as a successful original verification run.

No source/protocol edits, remote access, RPC request or transaction submission was performed by this reviewer. Local public receipts were parsed, legacy transaction messages reconstructed, both Ed25519 signatures verified, instruction/account ordering checked, and the ProgramData PDA independently derived.

## Exact public evidence

Paths are under `swap-vps-v05/`.

| Receipt | SHA256 |
|---|---|
| `remote-evidence/public-metadata-v3/v3-pre-upgrade-public.json` | `18dfa9d0be621448d971861a719d5e41d7faea45fbf62448c4f6955b1a8d4754` |
| `remote-evidence/public-metadata-v3/v3-standard-upgrade-public.json` | `8780c78fd73294acafb7d9505fd126ac84d3c9c7917448176bb544793aca8051` |
| `remote-evidence/public-metadata-v3/v3-standard-finalization-public.json` | `0c597a39d5b0c7e0b091576a690f3474d918b6cae986735a9f8d563554c76d34` |
| `remote-evidence/public-metadata-v3/v3-current-immutable-public.json` | `4b6abb7b259d280dc1f708c34884667654e96b015d486214e1a2e1c66c3e132c` |
| Independent offline signature/accounting result, `audit/agave-v3-loader-signature-check.json` | `88df3d32883b8bccd62fc616606e00106e4bb8b5139719998e015b7631feb2ba` |

Fixed chain and program bindings:

- Genesis: `H6SXasBhyzMhf5qCmcXwRUGU4UQGzS9Jc5zEjXKxtpxe`.
- Agave: 4.2.2, reported feature set 565236538.
- Program: `cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN`.
- ProgramData: `Hibe1esmNpASGJBynhevaMybmY2gcGcPDrfz8zMZyw1J`; independently derived from the program key under the upgradeable loader, bump 254.
- Loader: `BPFLoaderUpgradeab1e11111111111111111111111`.
- ELF: 32912 bytes, SHA256 `30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7`; local candidate hash was recomputed and matches the reported on-chain payload.

## Observed transition and instruction checks

The pre-upgrade receipt at slot 100 already contains this v3 ELF and an owned payer upgrade authority, `3sjBU9ZHSiuu5BoDtKGcSDxjucwf8krku7L7AeWLvTEs`. Therefore this sequence does **not** demonstrate initial program-address creation, or a C-to-Rust byte transition during this particular upgrade. It demonstrates the ordinary loader accepting an upgrade of an existing owned program with the reviewed v3 bytes. The private namespace snapshot contains only loopback interfaces; the recorded CLI target is loopback RPC/WS.

The standard CLI upgrade returned code 0 and signature `2bocSgfX3PvW4dFXYDZfwuKUw8PB8FTGWhc3AbfZZPNE9Uk8briDuTWgU4v7SufzwymoD7m5scuNjDXq6FnpCuTF`. The retained transaction is at slot 300, has `meta.err = null`, and logs successful upgrade. Base58 instruction data `5Sxr3` decodes to `03 00 00 00`, the loader Upgrade discriminator. Its seven indexed accounts resolve in the required order to ProgramData, Program, buffer, spill recipient, Rent, Clock and current authority. The payer is also spill recipient and authority; it is the only required signer. The buffer's refunded lamports and payer change are consistent, and aggregate pre/post balance difference equals the 5000-lamport fee.

The authority-removal signature is `26YUWsuWzV1DrujTtMcnCJaSeccyPyQFoGi6W83tAsfih9v78kUZkK6ZKT122HBxLPsHveDpQBG1RgeDNQrTL22j`. Its retained transaction is at slot 455, has `meta.err = null`, and logs `New authority None` followed by loader success. Data `6vx8P` decodes to `04 00 00 00`, SetAuthority. There are exactly two instruction accounts: writable ProgramData and the signing current authority. There is no third/new-authority account. The Program address is absent from the complete transaction account-key list. Payer debit is exactly the 5000-lamport fee.

Both signatures were independently checked against the canonical legacy message bytes reconstructed from the JSON, including header, public keys, recent blockhash and compiled instructions. Upgrade message: 275 bytes, SHA256 `3e83b6edccd11db26e4b73fe0ab2bfb0dbc7e11a7ec3c8e4ab2072e6b4c3b449`. Finalization message: 142 bytes, SHA256 `a38af9ebcca84837752ee6b5bc7bd047ac14f1a21aa08d6a36e2730d357017bb`. Signature verification proves message authorization and consistency; chain inclusion/finality additionally relies on the retained RPC evidence below.

## Finalized state and historical evidence limit

The original recovery invocation, recorded by the parent, queried `getSignaturesForAddress(ProgramData, {commitment: finalized, limit: 10})`, required an error-free `confirmationStatus = finalized` entry, and fetched the exact transaction with `getTransaction(signature, {commitment: finalized, encoding: json, maxSupportedTransactionVersion: 0})`. The final receipt retains the resulting transaction and describes that context, but does not separately persist the original query envelope/status entry. That is an evidence-completeness limitation; the reviewer cannot reconstruct a missing raw response from the receipt alone. The earlier `inspect-v3-finalization-public-state.log` separately retains an explicit finalized status for the upgrade signature.

The later supplemental receipt does preserve its actual query envelope: `getAccountInfo(ProgramData, {encoding: base64, commitment: finalized, minContextSlot: 455})`. Its returned context slot is 1425. Independent decoding of the retained first 45 bytes gives ProgramData discriminator 3, last upgrade slot 300, and authority option byte 0. The data account is non-executable and owned by the expected loader; total length 32957 equals the 45-byte metadata region plus the exact 32912-byte ELF, with no padding. Residual bytes in the reserved metadata region after the `None` tag are not an active authority and must not be interpreted as `Some(pubkey)`.

The pinned strict verifier (`rpc-v3-stage/solana-rpc-harness/driver.py`, SHA256 `1d866b3887dfaf0eff56cad2285ff87e8fe29fbecfe8d287e40e2c131ecec6a3`, lines 139–164) follows Program's stored ProgramData link, checks loader/structure, requires the `None` option byte, checks exact ELF hash/size and trailing padding, and verifies genesis before/after. Its returned summary matches the retained current-state receipt. Raw payload bytes are not duplicated in that public receipt; payload identity is the collector's digest/strict-verifier output, cross-checked against the local reviewed ELF.

Fresh historical lookup is **not** reported as PASS. The supplemental `getSignatureStatuses(..., searchTransactionHistory: true)` response at context slot 1456 contains two null entries. `getFirstAvailableBlock = 1026` and `minimumLedgerSlot = 1025` are later than slots 300 and 455; the bounded private ledger has pruned those records. This explains why a new lookup cannot recover the old transactions, without contradicting the earlier retained receipts. Current finalized immutability and retained transaction evidence are distinct from fresh historical availability.

## Classification of the failed attempt

`v3-standard-loader-finalize.log` (SHA256 `c0155cc2df840c23ef1d778188b4e9281e90e031c8154b49808e62ecacbe2b74`) records an `AssertionError` in the metadata verifier. The parent identified its query as a search under Program rather than ProgramData after successful CLI finalization and the strict authority-None check. The independent transaction decoding supports that diagnosis: SetAuthority references ProgramData only, so Program-address history need not contain its signature. The subsequent ProgramData lookup recovered the exact successful transaction; the recorded recovery did not resubmit or repeat finalization.

Classification: **post-transaction verification/receipt-discovery failure, followed by separate successful evidence recovery**. It is neither a failed loader state transition nor a clean success of the original verifier run. Preserve the failed log, recovered receipt, current-state receipt and pruning note together. A future collector should retain request commitment, signature-status entry and relevant account header before the short ledger prunes history; no contract change follows from this reporting issue.

## Scope boundary

This review accepts the loader upgrade/authority-removal evidence for the named owned private chain and exact ELF. It does not establish initial address creation, public/mainnet deployment, Circle USDC, real assets, production custody, all swap behavior or current live process health. The six standalone RPC cases and two paired XDS/Solana scenarios are separate qualification receipts; no paired-completion claim is made here. No source or consensus behavior changed; the parent maintains project-wide runtime status documentation.
