# Debugging SideTrail

This is a guide for what to do when SideTrail reports a potential timing violation / throws a red `x` in CI.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [How to locally rerun the tests](#how-to-locally-rerun-the-tests)
- [Updating the patch files](#updating-the-patch-files)
- [Undefined functions](#undefined-functions)
- [Loop related errors](#loop-related-errors)
- [Warning: No entrypoints found.](#warning-no-entrypoints-found)
- [SideTrail fails with a long error trace](#sidetrail-fails-with-a-long-error-trace)
- [What to do if the proof gets really slow](#what-to-do-if-the-proof-gets-really-slow)
- [Expected runtimes:](#expected-runtimes)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## How to locally rerun the tests

The first step to debugging is to locally rerun the failing proof(s).
Follow [the instructions here](README.md#how-to-execute-the-tests) to get SideTrail docker container and execute the tests.

## Updating the patch files

The most common error you are likely to see is a failure to apply the necessary patches.
Sidetrail depends on a set of patch files, stored in the `s2n/tests/sidetrail/working/patches`.
These files patch away certain C constructs that SideTrail has trouble with.
They are applied by the `copy_as_needed.sh` script in each proof.
If the file they are patching is modified, `patch` may be unable to apply the needed patches, and fail with an error.

```
patching file utils/s2n_safety.c
Hunk #1 FAILED at 57.
1 out of 2 hunks FAILED -- saving rejects to file utils/s2n_safety.c.rej
```

To fix this, regenerate the patch file.

1. View the failing patch to see what it does.
   It may be useful to apply it to a previous version of the file, so you can see what the patched file looks like.
   Identify any failing chunks, and figure out why they are failing to apply.
   
2. In a clean branch of s2n, modify the file in need of patching to have the required changes.
   Work directly on the file in the s2n src folders - we will revert it back before committing our changes.
   You may find it useful to also (temporarily) modify the `copy_as_needed.sh` file [(example)](https://github.com/awslabs/s2n/blob/main/tests/sidetrail/working/s2n-cbc/copy_as_needed.sh) to just copy the file, and not patch it.

3. Iterate on the file in need of patching until the tests pass.

4. In the `s2n/tests/sidetrail/working/patches` folder, regenerate the patch using `git diff -u <path-to-changed-file> > <patch_filename>.patch`

5. Restore all other changed files using `git checkout`.

6. Some of the current patch files were not generated following this standard procedure, and hence are invoked using `-p5`, instead of the `-p1` this procedure will generate.
   You may need to change the `./copy_as_needed.sh` files to use the correct `-p` level.
   
7. Rerun the proofs using the docker container to ensure they work.

8. Commit the new patch file, and attach it to your PR.

## Undefined functions

Another common error comes if a new function is called, for which SideTrail does not have a definition.
In this case, you will see a warning like:

```
warning: module contains undefined functions: malloc, __CONTRACT_invariant, nondet, foo
```

The list above is the list of functions for which SMACK does not have a model.
In some cases, this is expected and benign --- you can find a list of `allowed_undefined` functions [here](https://github.com/awslabs/s2n/blob/main/tests/sidetrail/count_success.pl#L33).
If there are any functions in the warning that are not in that list, then one of three things needs to happen.

1. The new function does not need a timing stub, and should be added to the list of `allowed_undefined`.

1. The new function is in a file that SideTrail doesn't currently compile.
   Update `Makefile` and `copy_as_needed.sh` for the proof, and rerun.
   
1. The new function needs a timing stub.
   Take a look at existing timing stubs in the `working/stubs` folder to see what these look like, and how to write them.

## Loop related errors

When Sidetrail analyzes a program, it needs to know how many times a loop will execute.
If Sidetrail encounters a loop, and can't tell how many times it will execute, it may give a spurious counterexample.
You can fix this using the `S2N_INVARIANT` macro.
A good example of this is in `s2n_constant_time_equals`.

```C
    uint8_t xor = 0;
    for (uint32_t i = 0; i < len; i++) {
        /* Invariants must hold for each execution of the loop
	 * and at loop exit, hence the <= */
        S2N_INVARIANT(i <= len);
        xor |= a[i] ^ b[i];
    }
```

## Warning: No entrypoints found.

For unknown reasons, this warning sometimes appears in CI, although the same docker container does not display it when run locally.
This appears to be benign, although we are investigating and hope to close it out.

## SideTrail fails with a long error trace

Your best bet here is to do delta-debugging to get a minimal reproducing test case.
- Take a look at the test-case.
- Did it introduce a timing violation?
- If so, fix it.

If you can't see an obvious timing issue in the minimal reproducing case, it may be worth taking a look at the trace.
The trace is not easy to read, and is super long.
I've found the best thing is to dump it to a file, and then to start annotating that file with the call-stack that led to the failure.
In particular, the trace will consist of two sequential traces: the initial, and the "shadow" trace.
Those should be equal - if they are not, that's where the timing violation comes in.
Look for the place where the two traces diverged.
It might be helpful to add/uncomment `printModel += true` in the `Makefile`.

An example failure trace on `s2n-cbc`:

```
$ ./clean && ./run.sh
.
.
.
__     __        _  __
\ \   / /__ _ __(_)/ _|_   _
 \ \ / / _ \ '__| | |_| | | |
  \ V /  __/ |  | |  _| |_| |
   \_/ \___|_|  |_|_|  \__, |
                       |___/
simple_cbc_wrapper@cbc.c

+  boogie /doModSetAnalysis simple_cbc_wrapper@cbc.c.product.bpl
Boogie program verifier version 2.3.0.61016, Copyright (c) 2003-2014, Microsoft.
simple_cbc_wrapper@cbc.c.product.bpl(634,3): Error BP5001: This assertion might not hold.
Execution trace:
    simple_cbc_wrapper@cbc.c.product.bpl(630,3): anon0
    simple_cbc_wrapper@cbc.c.product.bpl(121,40): inline$simple_cbc_wrapper$0$Entry
.
.
.
    simple_cbc_wrapper@cbc.c.product.bpl(2999,1): inline$s2n_verify_cbc.shadow$0$$bb20
    simple_cbc_wrapper@cbc.c.product.bpl(691,1): inline$simple_cbc_wrapper.shadow$0$$bb0$13
    simple_cbc_wrapper@cbc.c.product.bpl(630,3): anon0$2

Boogie program verifier finished with 0 verified, 1 error

real    0m20.076s
user    0m20.322s
sys     0m1.000s
```

The violated assertion (line 634 of simple_cbc_wrapper@cbc.c.product.bpl) is:

```
  assert ($l <= ($l.shadow + 68));
```

and the bound `68` appears to be specified using the `__VERIFIER_ASSERT_MAX_LEAKAGE` constant:

```
procedure {:entrypoint} {:cost_modeling} simple_cbc_wrapper.wrapper($i0: i32, $i0.shadow: i32, $i1: i32, $i1.shadow: i32, $p2: ref, $p2.shadow: ref, $p3: ref, $p3.shadow: ref) returns ($r: i32, $r.shadow: i32)
requires {:__VERIFIER_ASSERT_MAX_LEAKAGE 68} true;
requires {:public_in $i0} true;
requires {:public_in $i1} true;
requires ($i0 == $i0.shadow);
requires ($i1 == $i1.shadow);
{

  call $r := simple_cbc_wrapper($i0, $i1, $p2, $p3);
  call $r.shadow := simple_cbc_wrapper.shadow($i0.shadow, $i1.shadow, $p2.shadow, $p3.shadow);
  assume ($l >= $l.shadow);
  $__delta := ($l - $l.shadow);
  assert ($l <= ($l.shadow + 68));
  return;
}
```

Now if we rerun the prover, we would get a counterexample model as well,
and we can inspect the difference between `$l` and `$l.shadow` in this model:

```
$ ./clean && ./run.sh
.
.
.
__     __        _  __
\ \   / /__ _ __(_)/ _|_   _
 \ \ / / _ \ '__| | |_| | | |
  \ V /  __/ |  | |  _| |_| |
   \_/ \___|_|  |_|_|  \__, |
                       |___/
simple_cbc_wrapper@cbc.c

+  boogie /printModel 4 /doModSetAnalysis simple_cbc_wrapper@cbc.c.product.bpl
Boogie program verifier version 2.3.0.61016, Copyright (c) 2003-2014, Microsoft.
*** MODEL
$__delta@0 -> 69
$0 -> 0
.
.
.
$l.shadow@92 -> 29
$l.shadow@93 -> 29
$l.shadow@94 -> 30
$l.shadow@95 -> 31
$l.shadow@96 -> 31
$l.shadow@97 -> 31
$l.shadow@98 -> 32
$l.shadow@99 -> 32
$l@0 -> 0
$l@1 -> 0
$l@10 -> 1
$l@100 -> 33
$l@101 -> 33
$l@102 -> 33
$l@103 -> 33
$l@104 -> 33
$l@105 -> 33
$l@106 -> 33
$l@107 -> 33
.
.
.
```

We see several different values for `$l` and `$l.shadow` at various points.
To see why the assertion failed, we need to check the maximum difference between `$l` and `$l.shadow`,
and if it exceeds our `__VERIFIER_ASSERT_MAX_LEAKAGE` bound.
For this particular case, the maximum difference in the model was close to `100`,
so bumping `__VERIFIER_ASSERT_MAX_LEAKAGE` up to `100` resolved the issue.

## What to do if the proof gets really slow

1. Delta-debugging is your friend here.
   Find the last fast commit.
   Then, apply parts of the diff until it suddenly gets slow.
   That's your culprit.
1. Slowdown is often because alias analysis has failed to distinguish cases that can't actually alias.
   Sidetrail exports information about how many alias sets it had as part of its output.
   Did that change from the last fast version?
   In this case, sometimes simple syntactic changes are enough to fix it; if that doesn't work, consult an AR expert.


## Expected runtimes:

| Test name                         | Runtime | 
| --------------------------------- | ------: |
| s2n-record-read-cbc-negative-test | 20s     |
| s2n-cbc                           | 5m 45s  |
| s2n-record-read-composite         | 15s     |
| s2n-record-read-aead              | 4m 10s  |
| s2n-record-read-stream            | 25s     |
| s2n-record-read-cbc               | 20s     |

