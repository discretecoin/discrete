# Isolated RPC stage for the Rust SBPFv3 candidate

This new stage binds the already reviewed standalone and paired RPC harnesses to one new ELF. Original V05 harnesses, frozen V04 and prior signed intents/results remain unchanged. The stage's offline guards passed; no actual RPC, deployment or paired chain outcome is asserted by this staging task. The parent owns those next gates and the independent program review remains separate from this mechanical staging review.

Program copy: `../sbf-v3/solana_escrow.so`, 32,912 bytes, SHA256 `30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7`. Its Rust source is `6fa662506bd667f6e510aaa3ea9aea74edaadeebdc829bd82bcfc05325b60eea`; Cargo.lock is `ecb88b8469a190be6c5587f4762eaef619f4e8bdaaa45171821f6ea4c41f2102`. The old C/SBPFv0 program remains the separate 9,248-byte baseline `91004de413fa707ebd61d743cb01a2bfea80b0077fef3e15bc1f11bdb6100a89`. New implementation/toolchain/ELF bytes require their own program validation; an old runtime result cannot qualify them.

The public program ID, synthetic mint, ten-account interface, 49/33/1-byte instruction forms, 192-byte state and ordinary SPL owner-control checks remain the intended program contract. This stage changes no amounts, fees, secret handling, timing budgets, confirmation/commitment requirements, immutable-loader checks, RPC origin/genesis restrictions, private-key handling or journal/retry rules.

Runtime changes are exactly:

1. `solana-rpc-harness/driver.py`: two constants, `SBF_SHA` and `SBF_SIZE`. New file SHA256 `1d866b3887dfaf0eff56cad2285ff87e8fe29fbecfe8d287e40e2c131ecec6a3`.
2. `paired-rpc-harness/bindings.py`: the single driver dependency hash. Paired runtime, its guard assertions and all four Linux helpers are byte-identical to the reviewed originals.
3. New root wrapper `../run_solana_rpc_v3.py`: only `PACKAGE`, `EXPECTED_DRIVER` and the `.so` path differ from reviewed wrapper `eac74feca1ab00fa2f54c52a1dacdeb15f2c1ddf7cee3843dfa8533c8ca39439`. New wrapper SHA256 `0d2c551b0b8a2a918586dc1f8f52d81c89cec9866f4451905febdfee4833c400`.

`mechanical-runtime.diff` records all three source comparisons. `source-copy-baseline.json` records the original 17-file inventory and source-manifest hashes. `candidate-provenance.json` records the initial candidate binding before the offline runs, so its pending status is historical. Current offline outcomes are recorded below and the independent audit provides the subsequent review status.

Deploy the directories as siblings if the parent proceeds:

- `/var/lib/discrete-swap-lab/rpc-v3-stage/solana-rpc-harness`: exactly the original five file roles with new profile/docs bindings and a freshly computed package manifest.
- `/var/lib/discrete-swap-lab/rpc-v3-stage/paired-rpc-harness`: eight current files: four Python sources, README, test manifest and the two retained review diffs. Old logs, prior review candidates and historical receipts are intentionally omitted; the original 21-file package manifest remains available at the original path and is hash-bound by the copy baseline.
- `/var/lib/discrete-swap-lab/rpc-v3-stage/linux-harness`: only `runtime_paths.py`, `swap_journal.py`, `test_xds_wallet_network.py` and `xds_localnet.py`. The fifth dependency in paired bindings is the sibling Solana driver; there is no fifth Linux helper.

The new standalone wrapper hashes `/opt/discrete-swap-lab/program-v3/solana_escrow.so` and uses the staged package path above. It preserves the original 900-second child deadline, cleanup, resource sampling, exact six-case names, finalized commitment, expected-genesis and before/after evidence gates. The paired wrapper and its resource/remote evidence collection are parent-owned. Select the intended XDS candidate binaries through the unchanged explicit absolute-path environment variables; the staging task did not start nodes or mutate any native binary.

Local offline evidence is `../audit/rpc-v3-offline-qualification-01.json`, SHA256 `e456c7bec68f3b2f60915038a7ba1a8362fa78497b01b6b75ab4d0cbf5e054ec`. All captured source/wrapper/collector hashes were unchanged before/after:

| Gate | Outcome | Evidence log |
|---|---|---|
| Mechanical source/package verification | PASS | `../audit/rpc-v3-mechanical-01.log` |
| Standalone RPC guards | 11/11 PASS | `../audit/rpc-v3-standalone-guards-01.log` |
| Paired guards | 20/20 PASS | `../audit/rpc-v3-paired-guards-01.log` |
| Existing root-helper controls through isolated test copy | 10/10 PASS | `../audit/rpc-v3-root-helper-control-01.log` and nested `rpc-v3-root-helper-01.json` |

The portable guard runs used the existing solders 0.29.0 distribution and cryptography 50.0.1. The root-helper copy changes only the wrapper loader and source-hash inventory. It keeps the original harmless real Python child and in-memory SSH double controls: exception cleanup, deadline-race refusal, exact six-case/genesis gating and malformed/mismatched collection refusal. They do not use a protected credential or a real SSH/RPC endpoint. Original helper tests remain unchanged.

Use new run labels and new private run directories. Never copy old signed intents into a new run or relabel their saved program hash. Actual immutable program deployment/finalization, feature-state consistency, six standalone RPC outcomes, two paired outcomes and combined resources must be measured against this new program and selected native binaries. A successful local guard test does not provide any of those chain outcomes. No feature deactivation, relaxed loader gate, modified deadline or real funds are part of this stage.

Перевірено: exact mechanical profile/path/pin changes; preserved original sources; staged 11/20 offline guard suites and 10 helper controls; before/after hash equality and explicit package inventories.

Не перевірено: actual new-ELF RPC or paired runtime, Linux combined resources, process-death/expiry recovery, Circle USDC, production funds or mainnet activation.
