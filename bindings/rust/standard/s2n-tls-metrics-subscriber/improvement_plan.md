# cert.rs Performance Improvement Plan

## Problem

Our changes in `19dd2c187` ("specific der types") introduced a ~2x performance
regression: **237ns/cert → 438ns/cert**.

The changes were a single commit containing multiple independent improvements.
This plan applies them one at a time, benchmarking after each, to identify the
culprit and find a way to keep the correctness improvements without the
performance cost.

## Baseline

| Commit | Description | ns/cert |
|--------|-------------|---------|
| `80caac2d1` | safety lints (pre-change baseline) | 239 |
| `19dd2c187` | all changes combined | 438 |

## Results

| Step | Change | ns/cert | Delta |
|------|--------|---------|-------|
| 0 | Baseline | 239 | — |
| 1 | Non-minimal DER length validation | 228 | -11 (noise) |
| 2 | Tag enum + multi-byte tag rejection | 469 | **+241 (2x regression)** |

**Root cause identified: Step 2.** The `Tag` enum decode is the sole culprit.
Replacing `buffer.decode::<u8>()` with `buffer.decode::<Tag>()` (which does a
multi-byte check + a 10-arm match) on every TLV in the cert doubles parse time.

Steps 3–5 were not measured because the regression is entirely in Step 2.

## Fix Strategy

Keep the correctness benefits (multi-byte tag rejection) without the `Tag` enum
overhead on the hot path. Options:

**Option A: Validate in `Tlv::decode`, keep `u8` tag internally.**
Add the multi-byte rejection check (`tag & 0x1F == 0x1F`) directly in
`Tlv::decode` as a single branch on the raw `u8`. Keep `Tlv.tag` as `u8`.
Convert to `Tag` enum only at comparison sites (which are cold relative to
decode). This preserves the type safety at comparison points while keeping the
hot path as a single byte read + one branch.

**Option B: `#[inline(always)]` on `Tag::decode`.**
The match may not be inlining into `Tlv::decode`. Force it and see if the
compiler optimizes it away for the common case. Quick to test but may not help
if the issue is the match itself rather than call overhead.

**Option C: Reorder — decode tag as `u8`, validate + convert lazily.**
`Tlv` stores the raw `u8`. Add a `Tlv::tag()` method that returns `Tag` (doing
the match). The typed `der_element!` wrappers call `tag()` once. Untyped
`Tlv` decodes that skip the tag pay no match cost.
