# Settled-state restart control — correction review

Reviewed 2026-09-08 UTC. Accept the exact corrected control `v3_restart_state.py`, SHA256 `5f1b644bfd009e2cf7744094f73993d42f12d758bc6f5e7abe037bd1ae366326`, for the parent's separately authorized actual clean-restart run. No remaining blocker was identified within the four reviewed issues. This is not a claim that the restart has run or passed.

The preserved baseline remains `audit/v3_restart_state_pre_review.py`, SHA256 `682aba4a1ba00821d2d3df9cc4dfe465afc895ed6bd1717086f2b2ec1fb74055`. Root authored the correction; this reviewer changed only separate audit artifacts. The before/after account snapshot implementation is unchanged.

## Corrections checked

- Lines 44–57 now validate both outer and inner successful receipts, matching expected genesis, finalized commitment, program/payload identity and Agave version, exact ordered case names and per-case status; paired exposure must be `[true,false]`.
- Lines 31–36 apply the shared remaining deadline before systemctl and reject a successful return after it. `stop_owned_target` shares a single 50-second budget across the stop and all status reads. Its accepted terminal state includes inactive, zero MainPID where applicable and empty ControlGroup.
- Lines 138–153 include target start in the 90-second readiness budget, constrain RPC call timeouts and reject late successful genesis/slot responses. The bounds are operation/readiness bounds, not a claim that the entire script including all snapshots finishes within 90 seconds.
- Lines 114–115 pin the imported driver's actual source file. Lines 132–133 and 157–158 independently bind old/new executable bytes to the same validator hash.
- Lines 166–174 now always stop the owned target after comparison or post-stop failure. A cleanup exception forces FAIL even after a successful comparison; the original error and cleanup error are stored separately. The deliberate final state of a successful qualification is inactive, consistent with the parent's updated requested lifecycle.

## Offline controls actually executed

`audit/test_v3_restart_state_controls.py` SHA256 `8446f016cb82c671271f58b9197775ecfb93a9ac221e37f92ba755e4cac7f91e` pins the exact source and calls the actual control functions. Both ordinary Python and Python `-O` ran **14/14 methods PASS, no skips**, in 0.191/0.196 seconds. These are the same 14 methods in two interpreter modes.

Coverage: the downloaded six/two-case receipts are accepted; 20 outer/inner result, genesis, commitment and program/version mutations are rejected; case ordering/count/status and paired exposure changes are rejected; expired-before-invocation does not call systemctl; late successful systemctl and a late final state in a shared stop budget fail; success exactly at the declared deadline is accepted. Actual `main` exception/publication logic rejects late successful genesis and slot replies, rejects an old executable mismatch before stopping anything, returns zero only with successful final cleanup, makes cleanup failure dominate prior success, and retains both errors when account comparison and cleanup fail.

The tests use boundary stubs for systemctl, RPC, `/proc`, executable bytes and main snapshots. Public temporary files are created under this audit directory and removed. No child process, network call, service action, signing or remote access occurs. Thus they establish control flow, not actual systemd cleanup, RPC transport or on-chain persistence. The initial and final source hashes match.

Machine-readable provenance and exact input/log hashes are in `audit/v3-restart-controls-receipt.json`. Normal log SHA256 `ba6740f3ceb1de7e34fc48028624ef7695fe1d9cb28691efa86e7e972b333fe6`; optimized log `fdfb39695e6add504986f9646af2fcd7036c5ef26753508bf769a630e712ba8c`.

## Retained limits

Preflight failures before the lifecycle `try` still produce no restart JSON; they execute no stop/start, and their process logs must be retained. A JSON write failure is a failed execution even if a partial file contains an earlier PASS value; qualification must require successful process exit and intact receipt readback. The control does not claim crash-atomic publication.

The eventual permissible result is equality of these 23 settled synthetic accounts, lamports and program profile across one clean validator/target stop/start followed by final stop. It does not establish VPS reboot, power-loss recovery, restore from old backup, websocket resubscription, new post-restart swaps, mainnet or actual USDC. Root remains responsible for exact staged hashes, actual current service/unit readback, successful execution and final inactive/cgroup evidence.

This report supersedes the pre-run review only for corrected source `5f1b644b...`; the original review and source are retained. Broad project documents remain with root's active runtime evidence consolidation.
