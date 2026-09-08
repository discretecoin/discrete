# Isolated Rust / SBPFv3 candidate

Status: authorized implementation/build preparation; no candidate runtime outcome claimed yet. Parent owns the VPS, feature-state evidence and later real-RPC qualification. Frozen C, SBFv0, V03/V04/Core and previous harnesses remain unchanged.

## Product-to-code map before implementation

The product stays the same foreign escrow used in the XDS atomic-swap laboratory. This changes its implementation language and ELF target because the active SIMD-0500 deployment/finalization policy rejects SBPFv0. It adds no swap feature, fee, administration, redirect, close or migration operation.

| Frozen C area | Rust implementation acceptance criterion |
|---|---|
| account count/deserialization | Standard Solana Rust entrypoint; reject any account count other than ten with Custom 4097. Inspect the SDK's bounded entrypoint before deciding whether a small count-before-deserialization wrapper is needed for exact parser behavior. |
| program/profile and aliases | Same fixed program, synthetic mint, SPL Token, Clock and Sysvar IDs; all ten keys distinct; preserve checks/error order. |
| state | Exactly 192 bytes, same magic, status/bump/reserved bytes, amount/deadline/hash and four public-key offsets. |
| funding | Exactly 49 instruction bytes; state+depositor signatures; source authority, immutable destinations, amount/deadline and empty-vault checks unchanged. |
| redemption | Exactly 33 bytes, SHA256 same 32-byte preimage, no claim cutoff added after the refund deadline. |
| refund | Exactly one byte; the current Clock account slot must meet the original stored deadline. |
| PDA/CPI | Same `xds-swap-v1` + state key + bump; exact `TransferChecked` opcode 12, amount and decimals 6, same four SPL metas. Drop all data borrows before `invoke_signed`; write contract state only after successful CPI. |
| terminal behavior | Claim/refund leave status 2/3 tombstones; cannot reinitialize or consume twice; no authority/close path. |
| accounting/errors | Preserve u64 overflow rejection before CPI, amount sufficiency, Custom 0x1001..0x1012 and forwarded CPI errors. Do not add eligibility restrictions absent in C. |

Baseline: `../.. /swap-localnet-v04/solana_escrow.c` SHA256 `c64e6f25aa506565d553c5959c5fc3a7c27895c7b22ecffc643091d8c9bf2123`; profile `cc86c7703a1e7edf9b2ec7c1a8bbcaa60788f5f375b9292cef8207eb56666551`; original SBF 9248 bytes / `91004de413fa707ebd61d743cb01a2bfea80b0077fef3e15bc1f11bdb6100a89`.

## Toolchain and dependency gates

Use official Anza platform-tools **1.57**, present locally, with Rust **1.95.0-dev (ae660768a 2026-08-17)** and target **sbpfv3-solana-solana**. `rust-sbpfv3-target.json` was obtained from that compiler: CPU v3, `+static-syscalls`, fixed SBPFv3 text/rodata layout. The official wrapper command is `cargo-build-sbf --arch v3`; cargo-build-sbf 4.0.0+ and platform-tools 1.53+ are the documented minimum. No C ABI or ELF-header patching is proposed.

The direct application dependency is **solana-program =3.0.0**, default features disabled. Generate and retain the actual complete Cargo.lock before compiling; record every resolved crate version/checksum, compiler/linker identity and exact commands. No claim of a fully locked graph is made until that file exists. The v3-compatible define-syscall implementation must be checked in the resolved graph and artifact (no unresolved syscalls).

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
