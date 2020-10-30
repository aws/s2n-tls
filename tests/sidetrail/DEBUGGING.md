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
You can fix this using the `S2N_INVARIENT` macro.
A good example of this is in `s2n_constant_time_equals`.

```C
    uint8_t xor = 0;
    for (int i = 0; i < len; i++) {
        /* Invariants must hold for each execution of the loop
	 * and at loop exit, hence the <= */
        S2N_INVARIENT(i <= len);
        xor |= a[i] ^ b[i];
    }
```

## Warning: No entrypoints found.

For unknown reasons, this warning sometimes appears in CI, although the same docker container does not display it when run locally.
This appears to be benign, although we are investigating and hope to close it out.

## SideTrail fails with a long error trace

Your best bet here is to do delta-debugging to get a minimal reproducing test case.
Take a look at the test-case.
Did it introduce a timing violation?
If so, fix it.

If you can't see an obvious timing issue in the minimal reproducing case, it may be worth taking a look at the trace.
The trace is not easy to read, and is super long.
I've found the best thing is to dump it to a file, and then to start annotating that file with the call-stack that led to the failure.
In particular, the trace will consist of two sequential traces: the initial, and the "shadow" trace.
Those should be equal - if they are not, that's where the timing violation comes in.
Look for the place where the two traces diverged.

## What to do if the proof gets really slow

1. Delta-debugging is your friend here.
   Find the last fast commit.
   Then, apply parts of the diff until it suddenly gets slow.
   That's your culprit.
1. Slowdown is often because alias analysis has failed to distinguish cases that can't actually alias.
   Sidetrail exports information about how many alias sets it had as part of its output.
   Did that change from the last fast version?
   In this case, sometimes simple syntatic changes are enough to fix it; if that doesn't work, consult an AR expert.


## Expected runtimes:

| Test name                         | Runtime | 
| --------------------------------- | ------: |
| s2n-record-read-cbc-negative-test | 20s     |
| s2n-cbc                           | 5m 45s  |
| s2n-record-read-composite         | 15s     |
| s2n-record-read-aead              | 4m 10s  |
| s2n-record-read-stream            | 25s     |
| s2n-record-read-cbc               | 20s     |

