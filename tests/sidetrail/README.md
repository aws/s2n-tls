**Note: For support with using SideTrail project outside of s2n-tls, please contact
the main project repository: https://github.com/danielsn/smack**

# Constant Time Verification Tests for s2n

This repository contains tests which ensure that key s2n functions
are not susceptible to timing attacks.
For more details, see https://github.com/awslabs/s2n/issues/463

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [What are timing side channels](#what-are-timing-side-channels)
- [s2n countermeasures against timing side channels](#s2n-countermeasures-against-timing-side-channels)
- [Why use formal methods to prove the correctness of s2n's countermeasures?](#why-use-formal-methods-to-prove-the-correctness-of-s2ns-countermeasures)
- [How does SideTrail prove the correctness of code blinding countermeasures](#how-does-sidetrail-prove-the-correctness-of-code-blinding-countermeasures)
  - [High level overview](#high-level-overview)
  - [User annotations](#user-annotations)
  - [The gory details](#the-gory-details)
- [How to execute the tests](#how-to-execute-the-tests)
  - [Get Docker](#get-docker)
  - [Building the image](#building-the-image)
  - [Starting docker](#starting-docker)
  - [Running a proof inside docker](#running-a-proof-inside-docker)
- [Debugging SideTrail failures](#debugging-sidetrail-failures)
- [Questions?](#questions)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## What are timing side channels

Cryptographic protocols such as TLS are supposed to keep secret information secret.
They do this by ensuring that WHICH bytes go over the wire is hidden using encryption.
However, if the code is not carefully written, WHEN bytes go over the wire may depend
on values that were supposed to remain secret.

For example, if code checks a password as follows

```C
for (i = 0; i < length; ++i) {
  if password[i] != input[i] {
    send("bad password");
  }
}
```

then the amount of time until the reply message is received will depend on which byte in the password is incorrect.
An attacker can simply guess

  * a*******
  * b*******
  * c*******

until the time to receive the error message changes, and then they know the first letter in the password.
Repeating for the remaining characters turns an exponential guessing challenge into a linear one.

A variant of this attack, called LUCKY13, has been demonstrated against some implementations the Cipher Block Chaining (CBC) mode of SSL/TLS.
In this attack, the TLS server is tricked into treating a (secret) encrypted byte as a padding length field.
A naive TLS implementation will remove the specified amount of padding, then calculate a hash on the remaining bytes in the packet.
If the value in the secret byte was large, a small number of bytes will be hashed; if it was small, a larger number of bytes will be hashed, creating a timing difference, which in theory can reveal the value in the secret byte.

For a detailed discussion of the LUCKY13 attack and how s2n mitigates against it, see [this blog post](https://aws.amazon.com/blogs/security/s2n-and-lucky-13/).

## s2n countermeasures against timing side channels

s2n takes a belt and suspenders approach to preventing side-channel attacks.
1. First of all, it uses code-balancing to ensure that the same number of hash compression rounds are processed, no matter the value in the secret byte.
2. Second, it adds a delay of up to 10 seconds whenever any error is triggered, which increases by orders of magnitude the number of timing samples an attacker would need, even if they found a way around countermeasure 1.

## Why use formal methods to prove the correctness of s2n's countermeasures?
Side channels are notoriously difficult to defend against, since code with a side-channel has the same functional behaviour as code that is side-channel free.
Testing can find bugs, but it cannot prove their absence.
In order to prove the absence of a timing side-channel (up to a timing model of system execution), you need a formal proof.

Formal proofs are also useful because they help prevent regressions.
If a code change causes a timing side-channel to be introduced, the proof will fail, and the developer will be notified before the bug goes to production.

## How does SideTrail prove the correctness of code blinding countermeasures

### High level overview
A program has a timing side channel if the amount of time needed to execute it depends on the value of a secret input to the program.
SideTrail take a program, annotates every instruction with its runtime cost, and then generates a mathematical formula which symbolically represents the cost of executing the program given an input.
SideTrail then asks an automated theorem prover, called a Satisfiability Modulo Theories (SMT) solver, if there is a pair of secret inputs to the program that would take different amounts of time to process.
The SMT solver, using clever heuristics, exhaustively searches the state of all possible program inputs, and either returns a proof that there is no timing side-channel, or an example of a pair of inputs that lead to a timing channel, along with the estimated leakage.

### User annotations
In addition to the standard `assert()/assume()/` annotations supported through SMACK, there are several annotations supported by SideTrail, which allow the user to pass information to the SideTrail proof:

1. `__VERIFIER_ASSUME_LEAKAGE(arg)`: When the timing-modeling transformation encounters this call, it increments the leakage tracking variables by "arg"
2. `S2N_PUBLIC_INPUT(arg)`: the argument given here is taken to be public.
   All other variables are assumed private by default.
3. `S2N_INVARIANT(arg)`: asserts that the given argument is an invariant of the loop, and as such holds on each execution of the loop, and at loop exit.
4. `__VERIFIER_ASSERT_MAX_LEAKAGE(arg)`: asserts that the given function is time-balanced, with a leakage of less than "arg" time units.

### The gory details

Mathematically, a program `P(secret, public)` has runtime `Time(P(secret,public))`.
A program has a timing side-channel of delta if `|Time(P(secret_1,public)) - Time(P(secret_2,public))| = delta`.
If we can represent `Time(P(secret,public))` as a mathematical formula, we can use a theorem prover to mathematically prove that the timing leakage of the program, for all choices of `secret_1, secret_2`, is less than `delta`.

SideTrail proceeds in several steps:

1. Compile the code to llvm bitcode - this allows SideTrail to accurately represent the effect of compiler optimizations on runtime
2. Use LLVM's timing model to associate every bitcode operation with a timing cost
3. Use SMACK to compile the annotated LLVM code to BoogiePL (this represents `(P(secret,public))` in the above formula
4. Use bam-bam-boogieman to
  * Add a timing cost variable to the program, generating `Time(P(secret,public))`
  * Make two copies of the resulting program, one which has inputs `(secret_1, public)`, the other of which has inputs `(secret_2, public)`
  * Assert that the difference in time between the two programs is less than `delta`
5. Use boogie to prove (via the z3 theorem prover) that either
  * The time is indeed less than `delta`
  * or, the time is greater than `delta`, in which case the prover can emit a trace leading to the error


## How to execute the tests

### Get Docker

We assume you have docker installed and running on your machine.
If not, follow the instructions to install it https://docs.docker.com/get-docker/

We will assume that you have a variable `$S2N` which encodes the path to s2n on your machine

```shell
export S2N=<path_to_s2n>
```

### Building the image

To build the image, start with `s2n/codebuild/spec/sidetrail/Dockerfile`

```shell
cd $S2N
docker build -f codebuild/spec/sidetrail/Dockerfile --tag sidetrail .
```

This step takes about 25 minutes on my laptop.

### Starting docker

```shell
cd $S2N
docker run -u `id -u` \
           -v `pwd`:/home/s2n \
           -w /home/s2n/tests/sidetrail/working \
           --entrypoint /bin/bash \
           -it sidetrail
```

You will now be presented with a docker shell.
Inside this shell, run:

```shell
source /sidetrail-install-dir/smack.environment
```

This step is important.
If you do not source this file when you begin working, SideTrail may appear to run, but not actually analyze the code.

### Running a proof inside docker

```shell
cd <testname>
./clean.sh && ./run.sh
```

You should see output that looks something like this

```
...
...
warning: memory intrinsic length exceeds threshold (0); adding quantifiers.
SMACK generated s2n_record_parse_wrapper@s2n_record_read_wrapper.c.compiled.bpl
warning: module contains undefined functions: malloc, __CONTRACT_invariant, nondet

 ____                _            _
|  _ \ _ __ ___   __| |_   _  ___| |_
| |_) | '__/ _ \ / _` | | | |/ __| __|
|  __/| | | (_) | (_| | |_| | (__| |_
|_|   |_|  \___/ \__,_|\__,_|\___|\__|

s2n_record_parse_wrapper@s2n_record_read_wrapper.c



__     __        _  __
\ \   / /__ _ __(_)/ _|_   _
 \ \ / / _ \ '__| | |_| | | |
  \ V /  __/ |  | |  _| |_| |
   \_/ \___|_|  |_|_|  \__, |
                       |___/
s2n_record_parse_wrapper@s2n_record_read_wrapper.c

+  boogie /printModel 4 /doModSetAnalysis s2n_record_parse_wrapper@s2n_record_read_wrapper.c.product.bpl
Boogie program verifier version 2.3.0.61016, Copyright (c) 2003-2014, Microsoft.

Boogie program verifier finished with 1 verified, 0 errors

real	0m23.334s
user	0m20.983s
sys	0m2.395s
```

If you do not see the line,

```
Boogie program verifier finished with 1 verified, 0 errors
```

then you probably forgot to source `smack.environment`.
Go back and do so.

## Debugging SideTrail failures

Consult [the debugging guide](DEBUGGING.md).

## Questions?

contact aws-arg-platforms-support@amazon.com
