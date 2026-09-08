# Independent review: Timer deadline patch v2

Decision: the exact v2 patch below is suitable for application to a new isolated candidate for full qualification. No unresolved source/arithmetic finding remains in this bounded review. This is not a runtime PASS or permission to replace a mainnet binary. The reviewer did not edit Core, apply the patch, build it, run nodes or access the VPS.

## Reviewed identity and actual failure

Baseline is frozen Core `1e947a8e66ec963e8e634b14fec29343ef7d8822`. Only `src/System/Timer.h` and `tests/System/TimerTests.cpp` change. V1 and its evidence remain preserved; it must not be applied in place of v2.

| Artifact below V05 | SHA256 |
|---|---|
| `timer-fix/v2/timer-deadline.patch` | `2dd736dd40302396429338255b00c88a48e364bcc526bfe0bb7980fca078f30f` |
| `timer-fix/v2/final-review.json` | `5b89934e0d6e9bf9feba2bd4a330e42f3c8d7852b8a050a7157e453ba20c4259` |
| `timer-fix/v2/candidate/src/System/Timer.h` | `6d0aac47ed9f17b5f3e748374fa984fbae3344453e27ac8cd8cc2d66d9d6d5e0` |
| `timer-fix/v2/candidate/tests/System/TimerTests.cpp` | `2d1072a2bb7e9205202068f1c842eddd726864751dbb8c4f478615b913735b9d` |
| `timer-fix/v2/validation-receipt.json` | `53415c91adcef0cb3e71748bbc22c9c5230428233d62b767e6d4e95c529ad615` |
| `timer-fix/v2/deadline-property.log` | `b0d941f87d09bd31add022ae1c61bc5d64671d1434071ca0895a4a32427e54a0` |
| `remote-evidence/native/run-manifests/linux-http-repeat.json` | `840e5d78ece2f1acf9fe559878b57f2cc1266d8607fcc9cefe9ad679e7d585cf` |
| `remote-evidence/native/linux-http-repeat.log` | `f68fba9a25024842123ebe703ab106365926c57d65ba7e9feb30efac65149a0b` |

All 19 public artifacts listed by the v2 final review matched their recorded sizes and hashes. The retained Linux repeat log was checked independently: the unchanged original executable `8bde44314fee197aeacbbeeb1e72d4606d84ced42eb37863dcf52db38a3e363e` fails all 20 iterations at 149 ms versus the unchanged 150 ms lower bound. Its before/after source and binary manifest reports equality and HEAD `1e947a8`. This strengthens the earlier source diagnosis in `http-timeout-quantization-review.md`; it does not establish the new candidate's runtime result.

## Finding in v1 and its correction

V1 patch `2df2a6435fe1e13b7618d75451ec5ae98d7b774ec4cc697adaaa079fb1378d34` correctly formed an unsigned whole-millisecond ceiling but did not bound the later signed clock-duration conversion in `Dispatcher.cpp:237–239`.

With sampled now zero and requested duration `INT64_MAX` nanoseconds, the old floor is 9,223,372,036,854 ms, which converts to 9,223,372,036,854,000,000 ns and fits. V1's ceiling is 9,223,372,036,855 ms, which converts to 9,223,372,036,855,000,000 ns: 224,193 ns beyond the signed maximum. Thus this was a new downstream representability error for an input whose old floored endpoint fit. The original unsigned oracle did not check that constraint.

V2 adds an explicit `<stdexcept>` dependency and, only for positive requests, rejects a rounded endpoint above `floor_ms(steady_clock::duration::max())` with `std::overflow_error`. The check occurs before obtaining/installing the waiting context, installing an interrupt handler or calling `addTimer`. Rejection does not leave a pending timer. It also rejects other positive endpoints outside the representable clock range; this is an explicit extreme-input behavior change. Saturating instead would undermine the no-early-timeout requirement.

## Arithmetic and state-preservation proof

For the verified Linux/MSVC signed 64-bit nanosecond clock profile, let `M = 1,000,000 ns` and decompose a nonnegative sampled start and a duration of at least one millisecond as `now = qn*M + rn`, `duration = qd*M + rd`, with each remainder in `[0,M)`. The patch forms:

`expire_ms = qn + qd + ceil((rn + rd)/M) = ceil((now + duration)/M)`.

The remainder sum is below 2 ms, so its conversion/ceiling cannot overflow the nanosecond representation. Whole milliseconds are added as unsigned values; for this clock/input profile their maximum sum is far below the unsigned limit. Unlike direct signed `now + duration`, the implementation never adds two potentially maximal nanosecond values. The new upper guard then ensures conversion of the accepted endpoint from milliseconds back to the signed steady duration fits.

For `0 < duration < 1 ms`, the existing minimum converts its whole part to one millisecond and the new fractional-duration contribution is zero. The result is `ceil_ms(now + 1 ms)`, preserving the intended minimum while ensuring a full positive minimum wait rather than the old potentially shorter next-tick wait. This positive-input strengthening is explicitly documented.

For `duration <= 0`, the new positive branch and upper guard are skipped. The old signed duration conversion, zero-result minimum substitution, sampled-now truncation, unsigned cast and unsigned addition remain equivalent. The reviewer is not endorsing negative-duration scheduling or its old extreme behavior; preserving that behavior is the requested regression boundary.

The complete suffix beginning at `auto* context = dispatcher->getCurrentContext()` is byte-identical between saved baseline and candidate. `addTimer(expireTime, context)` and `interruptTimer(expireTime, context)` still use the same unchanged captured key. Entry interruption checks, handler clearing, dispatch and post-wait interruption checks are unchanged. No scheduler timing queue, HTTP request flow or public Timer signature was refactored.

## Tests and precise evidence level

The author compiled and executed the exact-block arithmetic control: 65 representable positive vectors pass, 20 unrepresentable positive endpoints require rejection, and 56 zero/negative vectors match baseline. The old arithmetic is early on 52 representable vectors. The control uses an independent unsigned absolute-nanosecond oracle and a separate representability bound, with an explicit clock-profile assertion. It covers exact last-valid integer/fractional boundaries, one nanosecond above them and the independently identified `now=0 / nanoseconds::max()` example. The reviewer read the extraction/control source and hash-bound receipt; these counts describe arithmetic vectors, not CTest results.

Four actual Timer tests are appended: fractional 1.5/2.5 ms waits, integer 2 ms waits targeted at a fractional start, positive sub-ms minimum behavior, and extreme-positive rejection followed by a normal one-ms reuse. They measure with `steady_clock` and assert real duration lower bounds; they do not mirror the deadline formula. Live scheduling overhead can mask an old early-return bug, which is why the independent deterministic control is valuable. The last test checks rejection/reusability without intentionally waiting for a huge deadline. The retained compiler receipt identifies the actual v2 Timer header and test source, but those new real-Timer tests have only been compiled at this stage.

All existing Timer tests and the original HTTP file remain unchanged. The HTTP assertions are still `elapsed >= 150 ms` and `< 2000 ms`; no tolerance was relaxed. Existing disabled Timer/OperationTimeout cases remain disabled and cannot be counted as executed by an ordinary SystemTests run.

## Next qualification boundary

Apply only the exact v2 patch after an apply-check in a new candidate, retaining `1e947a8` and the failed original receipts. Rebuild all Timer consumers; run SystemTests/HttpFramingTests, the finite HTTP repeat, then the complete native and owned wallet/RPC/network/boundary/adapter/pair selections against the new exact source/executable hashes. The original baseline's other passing results cannot be relabeled as qualification of this shared Timer change. The final real-Solana escrow and paired runs must bind the same final Timer/Core candidate and the actual finalized immutable program profile selected by the parent.

**Перевірено:** actual unchanged-binary 20/20 original failures, final v2 hashes, positive ceiling/range arithmetic, non-positive equivalence, unchanged interrupt-key/suffix behavior, meaningful added-test source, unchanged HTTP limits, and the author's arithmetic/compilation receipts.

**Не перевірено:** execution of the candidate Timer/System/HTTP cases, Linux overflow/reuse behavior, the rebuilt complete native/runtime selection or mainnet suitability. No patch was applied by this reviewer.
