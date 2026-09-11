# Isolated Rust / SBPFv3 candidate

Status: local SBPFv3 build, 13 original VM tests and four differential test methods passed. Parent owns the VPS, feature-state evidence and later real-RPC qualification; those outcomes are not claimed here. Frozen C, SBFv0, V03/V04/Core and previous harnesses remain unchanged. `README-pre-build.md` preserves the product map and gates written before implementation.

## Product-to-code map before implementation

The product stays the same foreign escrow used in the XDS atomic-swap laboratory. This changes its implementation language and ELF target because the active SIMD-0500 deployment/finalization policy rejects SBPFv0. It adds no swap feature, fee, administration, redirect, close or migration operation.

| Frozen C area | Rust implementation acceptance criterion |
|---|---|
| account count/deserialization | Read only the runtime ABI's initial u64 count; reject counts other than ten with Custom 4097, then use the official SDK deserializer and standard heap/panic handlers. No custom account parser. |
| program/profile and aliases | Same fixed program, synthetic mint, SPL Token, Clock and Sysvar IDs; all ten keys distinct; preserve checks/error order. |
| state | Exactly 192 bytes, same magic, status/bump/reserved bytes, amount/deadline/hash and four public-key offsets. |
| funding | Exactly 49 instruction bytes; state+depositor signatures; source authority, immutable destinations, amount/deadline and empty-vault checks unchanged. |
| redemption | Exactly 33 bytes, SHA256 same 32-byte preimage, no claim cutoff added after the refund deadline. |
| refund | Exactly one byte; the current Clock account slot must meet the original stored deadline. |
| PDA/CPI | Same `xds-swap-v1` + state key + bump; exact `TransferChecked` opcode 12, amount and decimals 6, same four SPL metas. Drop all data borrows before `invoke_signed`; write contract state only after successful CPI. |
| terminal behavior | Claim/refund leave status 2/3 tombstones; cannot reinitialize or consume twice; no authority/close path. |
| accounting/errors | Preserve u64 overflow rejection before CPI, amount sufficiency, Custom 0x1001..0x1012 and forwarded CPI errors. Do not add eligibility restrictions absent in C. |

Baseline: `../../swap-localnet-v04/solana_escrow.c` SHA256 `c64e6f25aa506565d553c5959c5fc3a7c27895c7b22ecffc643091d8c9bf2123`; profile `cc86c7703a1e7edf9b2ec7c1a8bbcaa60788f5f375b9292cef8207eb56666551`; original SBF 9248 bytes / `91004de413fa707ebd61d743cb01a2bfea80b0077fef3e15bc1f11bdb6100a89`.

## Toolchain and dependency gates

Use official Anza platform-tools **1.57**, present locally, with Rust **1.95.0-dev (ae660768a 2026-08-17)** and target **sbpfv3-solana-solana**. `rust-sbpfv3-target.json` was obtained from that compiler: CPU v3, `+static-syscalls`, fixed SBPFv3 text/rodata layout. The official wrapper command is `cargo-build-sbf --arch v3`; cargo-build-sbf 4.0.0+ and platform-tools 1.53+ are the documented minimum. No C ABI or ELF-header patching is proposed.

The direct application dependency is **solana-program =3.0.0**, default features disabled. The actual retained Cargo.lock SHA256 is `ecb88b8469a190be6c5587f4762eaef619f4e8bdaaa45171821f6ea4c41f2102`: 158 registry dependencies plus this root package. Resolved entrypoint/account-info are 3.1.1, CPI and SHA256 hasher 3.1.0; the complete versions and registry checksums are in the lock. The SHA API wraps the standard syscall; the pinned Agave syscall either writes the whole 32-byte digest and returns zero or aborts with a VM error. No custom hash ABI was introduced.

`source-dependency-audit.json` records an executed read-only audit: all 158 cached crate archives matched Cargo.lock, and all 3872 regular files unpacked from those archives matched their actual build-source copies. It also records 57 compiler/linker/runtime-library/target-library identities, source/baseline hashes and Python 3.12.14 with solders 0.29.0. Dependency identity is not a claim that every dependency has received a security audit.

Actual compilation used the **direct official platform-tools Cargo/rustc target**, not an installed cargo-build-sbf wrapper. The target specification selects the official linker layout and static syscalls; the resulting ELF is v3 and has no named undefined symbols. Initial dependency resolution/fetch used the official Cargo registry. Builds then used `--offline --locked`. `build-dev01.log` records an initial missing host dependency; `dependency-fetch-all.log` records fetching the same locked graph, and `build-dev02.log` records the successful build. No lock versions were changed for that retry.

## Artifact and executed local qualification

| Artifact | SHA256 / result |
|---|---|
| `src/lib.rs` | `6fa662506bd667f6e510aaa3ea9aea74edaadeebdc829bd82bcfc05325b60eea` |
| `Cargo.toml` | `95fbea4c3925ab8043baa328dd2bdc0509883841474ee8c811af10356e02e965` |
| `solana_escrow.so` | `30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7`, 32912 bytes, ELF flags 3 |
| `test_solana_vm.py` | Byte-identical to frozen V04: `48187e48a95a1a94f92ba99e4ea6e3755289e0592c8d94d874c4d4d861892c54` |
| `vm-original13.log` | 13/13 original tests passed against the candidate, including actual SPL Token CPI and compute-exhaustion rollback. |
| `vm-differential-dev01.log` | Four test methods passed: 24 C/Rust paired fixture scenarios, exact full persisted account comparison and 192-byte expected state, all 18 custom-error codes, deadline/terminal ordering and subsequent ordinary transfer. |
| `target-repro-02/result.json` | Fresh target directory, one build job, same source/lock/toolchain/path spelling: whole ELF SHA256 matches the candidate exactly. |

Differential tests use identical deterministic synthetic keys in two independent LiteSVM instances and hash-gate both program artifacts. Negative state mutations are in-process VM fixtures, not claims that those states are reachable on-chain. Tests deliberately preserve the C contract's permitted source close authority and destination internal owner/delegate/close fields. They compare complete token/mint/state accounts and SOL payer balances; they do not require identical compute units or logs. These finite cases and source review support equivalence for the observed paths, not a formal proof for every runtime input.

The source keeps the fixed program ID `cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN`, the fixed synthetic mint `EdmxWPmx2WH6WgFfTdu9xfkYf3k1g5wD1zccTVySEEh1`, all ten account positions and the exact state/instruction bytes. This is not Circle-issued USDC. The ELF target, binary hash/size, implementation language and compute profile change. Loader upgrade authority is outside the escrow interface and still needs actual finalization plus on-chain readback in the next stage.

## Reproduce locally

From this directory, with the frozen V04 solders 0.29.0 dependencies on PYTHONPATH:

```powershell
$env:PYTHONPATH = (Resolve-Path '../../swap-localnet-v04/python-deps').Path
& 'python' -B -m unittest -v test_solana_vm test_differential
./reproduce-build.ps1 -RunName target-repro-new
```

`reproduce-build.ps1` checks the frozen source/manifest/lock hashes, uses the same platform-tools 1.57 binaries, records compiler/linker identities, builds offline into a fresh directory and compares the whole ELF hash. It refuses to overwrite an earlier run. Cached crates under `cargo-home` and platform-tools must be present; neither is implicitly downloaded by this script. The matching fresh build is under `target-repro-02/`. Reproduction on a different host/OS or at a different source/cache path is a separate gate.

The first reproduction attempt, `target-repro-01/`, compiled but produced SHA256 `e22474092bbc8426b830799ec42735d1ca0b47a05f80e4221302111452d34642`. The initial script converted CARGO_HOME's forward slashes to Windows backslashes. Rust embeds dependency panic source paths: this changed 483 `.rodata` bytes and two `.text` bytes for relocated string addresses, with no changes to the symbol/string tables. Restoring the original path spelling in a new target directory reproduced the exact candidate. Both artifacts, their commands/environment metadata and the initial script (`reproduce-build-dev01.ps1`) are retained. `inspect-repro.py` and `repro-comparison.json` record section hashes and differing instruction bytes. No ELF patching or candidate replacement occurred.

## Risks and qualification gates

1. Rust AccountInfo borrowing, SDK error encoding, entrypoint deserialization and CPI argument construction can introduce regressions despite identical business logic. Independent source review must compare validation order and all public bytes against frozen C.
2. Same source semantics do not imply same ELF, size, compute use or native loader behavior. Require actual successful SBPFv3 build, ELF flags 3, correct sections/entrypoint and no unresolved symbols, then loader verification in the existing local VM.
3. Rerun all **13 original VM tests** through an isolated test copy against the new binary, preserving their assertions. Add differential byte/error/state checks where existing assertions are insufficient. A local VM run does not prove the real validator's deployment/finalization behavior.
4. Parent then uses a separate candidate profile with the new exact hash/size, unchanged immutable/feature gates, and reruns the six real-RPC cases plus the two paired cases. No previous test result qualifies the new binary automatically.
5. Preserve program ID, mint, instruction wire and state interfaces. The transaction bytes are generated using the same unchanged interface, but fresh signed transactions in a new run are new identities; never relabel an old signed intent with a new program artifact/profile.
6. No VPS access, feature deactivation, deployment, mainnet activation or real assets in this subtask. No resource-capacity claim follows from compilation.

## Primary-source basis

- [SIMD-0500](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0500-disable-deployment-of-sbpf-v0-v1-v2.md) specifies rejection of old-version deployment and finalization, while preserving execution for existing programs.
- [Agave v4.2.2 loader](https://github.com/anza-xyz/agave/blob/v4.2.2/programs/bpf_loader/src/lib.rs) checks the disable-deployment feature when SetAuthority clears authority. The parent separately verified the exact deployed commit/feature/ELF.
- [Agave v4.2.2 changelog](https://github.com/anza-xyz/agave/blob/v4.2.2/CHANGELOG.md) states that SBPFv3 support is via the Rust toolchain; the inherited C makefile supports only v0/v1/v2 target selection.
- [Anza cargo-build-sbf](https://github.com/anza-xyz/cargo-build-sbf) documents `--arch v3`, minimum component versions and static syscalls.
- [solana-program 3.0.0](https://docs.rs/solana-program/3.0.0/solana_program/) provides the standard entrypoint, AccountInfo, SHA256, PDA and CPI APIs; its declared on-chain define-syscall dependency is ^3.0.0.

Project-wide status documentation is coordinated by the parent. This candidate directory does not close any V05/runtime/production gate on its own.
