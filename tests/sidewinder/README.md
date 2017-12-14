# Constant Time Verification Tests for s2n

This repository contains tests which ensure that key s2n functions
are not susceptible to timing attacks.

For more details, see https://github.com/awslabs/s2n/issues/463


## What are timing side channels

Cryptographic protocols such as TLS are supposed to keep secret information secret.
They do this by ensuring that WHICH bytes go over the wire is hidden using encryption.
However, if the code is not carefully written, WHEN bytes go over the wire may depend
on values that were supposed to remain secret.

For example, if code checks a password as follows

```
for (i = 0; i < length; ++i) {
  if password[i] != input[i] {
    send("bad password");
  }
}
```
then the amount of time until the reply message is received will depend on which byte in the password
is incorrect.  An attacker can simply guess
  * a*******
  * b*******
  * c*******

until the time to receive the error message changes, and then they know the first letter in the password.
Repeating for the remaining characters turns an exponential guessing challenge into a linear one.

A varient of this attack, called LUCKY13, has been demonstrated against some implementations the Cipher Block Chaining (CBC) mode of SSL/TLS. In this attack, the TLS server is tricked into treating a (secret) encrypted byte as a padding length field. A naive TLS implementation will remove the specified amount of padding, then calculate a hash on the remaining btyes in the packet. If the value in the secret byte was large, a small number of bytes will be hashed; if it was small, a larger number of bytes will be hashed, creating a timing difference, which in theory can reveal the value in the secret byte.

For a detailed discussion of the LUCKY13 attack and how s2n mitigates against it, see [this blog post](https://aws.amazon.com/blogs/security/s2n-and-lucky-13/). 

## s2n countermeasures against timing side channels

s2n takes a belt and suspenders approach to preventing side-channel attacks.
1. First of all, it uses code-balancing to ensure that the same number of hash compression rounds are processed, no matter the value in the secret byte.
2. Second, it adds a delay of up to 10 seconds whenever any error is triggered, which increases by orders of magnitude the number of timing samples an attacker would need, even if they found a way around countermeasure 1. 

## Why use formal methods to prove the correctness of s2n's countermeasures?
Side channels are notoriously difficult to defend against, since code with a side-channel has the same functional behaviour as code that is side-channel free. Testing can find bugs, but it cannot prove their absence.  In order to prove the absence of a timing side-channel (up to a timing model of system execution), you need a formal proof.

Formal proofs are also useful because they help prevent regressions.  If a code change causes a timing side-channel to be introduced, the proof will fail, and the developer will be notified before the bug goes to production.

## How does Sidewinder prove the correctness of code blinding countermeasures

### High level overview
A program has a timing side channel if the amount of time needed to execute it depends on the value of a secret input to the program. Sidewinder take a program, annotates every instuction with its runtime cost, and then generates a mathematical formula which symbolically represents the cost of executing the program given an input.  Sidewinder then asks an automated theorem prover, called a Satisfiability Modulo Theories (SMT) solver, if there is a pair of secret inputs to the program that would take different amounts of time to process.  The SMT solver, using clever heuristics, exhaustively searches the state of all possible program inputs, and either returns a proof that there is no timing side-channel, or an example of a pair of inputs that lead to a timing channel, along with the estimated leakage.

### The gory details

Mathematically, a program `P(secret, public)` has runtime `Time(P(secret,public))`. A program has a timing side-channel of delta if `|Time(P(secret_1,public)) - Time(P(secret_2,public))| = delta`.  If we can represent `Time(P(secret,public))` as a mathematical formula, we can use a theorem prover to mathematically prove that the timing leakage of the program, for all choices of `secret_1, secret_2`, is less than `delta`. 

Sidewinder proceedes in several steps:
1. Compile the code to llvm bitcode - this allows Sidewinder to accuratly represent the effect of compiler optimizations on runtime
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

### Install the dependencies
Running these tests will require the following dependencies
(tested on Ubuntu 14.04).  To see how to install this on a clean ubuntu machine, 
take a look at the .travis scripts in this repo.

- bam-bam-boogieman 
- SMACK and all its dependencies
  - The easiest way to get these is to use the build.sh in smack/bin
  - Ensure that all of the installed depencies are on the $PATH
  - source the smack.environment that the smack build script creates

### Execute the test

```
cd tests/sidewinder/working/s2n-cbc
./clean.sh
./run.sh

If the tests pass, you will see a message like: Boogie program verifier finished with 1 verified, 0 error

If the tests fail, you will see a message like: Boogie program verifier finished with 0 verified, 1 error
```


## Questions?
contact dsn@amazon.com