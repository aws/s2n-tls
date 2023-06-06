# Constant Time Verification Tests for s2n

This repository contains tests which ensure that key s2n functions
are not susceptible to timing attacks and are indeed constant time.

For more details, see https://github.com/awslabs/s2n/issues/463


## What are timing side channels

Crypographic protocols such as TLS are supposed to keep secret information secret.
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

There are two major ways that timing side channels appear in code

### Branches that depend on secret data
In this case, the program may execute more code, and hence take more time, in one branch than another.   The password example above is a branch based timing side-channel.

### Memory accesses that depend on secret data
In this case, if one memory location is in cache, while another is not, there will be a detectable
delay fetching the location from main memory.  For example, an AES computation that uses 
software lookup tables can leak the secret key over the network based on cache timing
https://cr.yp.to/antiforgery/cachetiming-20050414.pdf

### The implication
The runtime of code should not depend on the value of secret data, and therefore, cryptographic code should ensure that
   1. No branch depends on secret data
   2. No memory access depends on secret data 




## The tests

Currently, we have constant-time proofs of two functions from utils/s2n_safety.c
1. s2n_constant_time_equals
2. s2n_constant_time_copy_or_dont


A proof proceeds in the following steps:
1. Annotate public inputs using S2N_PUBLIC_INPUT().  All other inputs are assumed to be private
2. Use the ct-verif tool, which compiles the program into the Boogie intermediate representation, and adds assertions that:
   1. No branch depends on secret data
   2. No memory access depends on secret data 
3. Use the Boogie program-analysis framework to convert the code under test into an SMT formula
4. Use the z3 prover to prove that either:
   * None of the assertions can be violated (in which case the code is constant time) OR
   * Some of the assertions can be violated, in which case the code is not guaranteed to be constant time.


## How to execute the tests

### Install the dependencies
Running these tests will require the following dependencies
(tested on Ubuntu 14.04).  To see how to install this on a clean ubuntu machine, 
take a look at the ci scripts in this repo.

- ct-verif (available from https://github.com/imdea-software/verifying-constant-time/)
  - Export its base directory as $CTVERIF_DIR
- SMACK and all its dependencies
  - The easiest way to get these is to use the build.sh in smack/bin
  - Ensure that all of the installed dependencies are on the $PATH
  - source the smack.environment that the smack build script creates

### Move the code you want to test into place 
```
cp ../../utils/s2n_safety.c .
```
### Execute the test

```
make clean
EXPECTED_PASS=2
EXPECTED_FAIL=0
make 2>&1 | ./count_success.pl $EXPECTED_PASS $EXPECTED_FAIL
```

If both tests pass, you will see
```
verified: 2 errors: 0 as expected
```

If not all tests pass, you will see a message like:

```
ERROR:  Expected verified: 2    errors: 0.
        Got      verified: 1    errors: 1.
```


## Questions?
contact dsn@amazon.com