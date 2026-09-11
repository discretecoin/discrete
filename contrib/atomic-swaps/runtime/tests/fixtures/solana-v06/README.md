# Private Solana v06 executable fixture

These two files are byte-exact copies of the offline build used for the successful fresh private Agave 4.2.2 qualification on 2026-09-10. The manifest retains its original build paths and provenance; those paths are historical metadata, not prerequisites for running the tests. No keypairs, signing seeds, wallets, ledger or credentials are included.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `solana_escrow.so` | 32960 | `561e0b7ad5e4be59a3056482ea94370064d201f45a378964d0fdb9f0ff76a901` |
| `build-manifest.json` | 2516 | `3280a82ad13cd2671b558f001678615ced7fee1b8dbfae820071f87836f7bd7f` |

The configured synthetic program is `75vLTrZ2mMJVLMF1fLsTzrMYAMc9s8YhaoQQcra3yap2`, mint `2HRD7QMkjciZ4ZuVoXyrBJ7WSqJL5BzmsQd3iTZ51So7`, private genesis `4desBxgtAgjkUvFoeRjDinRVFbR4z2czpvwwxW2nTavo`. These identify one isolated test ledger. They are not a public deployment or production USDC configuration. The private validator was stopped after qualification.

The initial RPC run exercised normal initial program deployment, rejection while upgradeable, finalized removal of upgrade authority, and exact-principal claim/refund with full finalized receipts. Its adapter SHA-256 was `203f971f97c6847704cd0938f3afa99c08b867643fd8213e91b95cbd5d767a5c`. The final adapter, SHA `92640e163f2b5623561ec08e40247a1038ad8ad0dfa36233ddb3ec581e26761b`, subsequently passed three real XDS/Solana Session cases against this same immutable deployment: successful exchange/receipt reopening, both refunds and actual blockhash-expiry renewal after process restart. See [revision 0.6 qualification](../../../../QUALIFICATION_V06.md). The ELF did not change.

Set `XDS_SOLANA_BUILD` to this directory's absolute path and run the suites with `solders==0.29.0`:

```sh
# From contrib/atomic-swaps/runtime:
python -m unittest discover -s tests -p test_solana.py -v
# From contrib/atomic-swaps/solana, using the same XDS_SOLANA_BUILD:
python -m unittest discover -s tests -p test_vm.py -v
python -m unittest discover -s tests -p test_profile.py -v
```

The VM tests check the ELF against the manifest before loading it. They execute synthetic LiteSVM state and actual SPL Token CPI without network access. The fixture allows CI to repeat execution without installing platform-tools; it does **not** prove a new source-to-binary rebuild or cross-host reproducible compilation. Use `contrib/atomic-swaps/solana/build.py` for a separate build qualification. Source SHA-256 of the escrow body is recorded in the manifest (`src/lib.rs`: `a74cfdcc454b4553e7a4b340aba72d8c61021285c625c3abf32422c30a154ed9`); the generated program/mint constants and pinned Cargo inputs are recorded there too.
