# s2n-tls testing
s2n-tls has a wide variety of tests covering a wide variety of different functionality. This document serves as a "quick reference", providing an overview of all the testing that s2n-tls does and linking to additional documentation.

## Unit Tests
_Is the internal functionality of s2n-tls correct?_

These test the correctness of low-level s2n-tls functions. These functions are commonly private. We have unit tests for both the [C library](unit/) and the [rust bindings](../bindings/rust). 

### Sanitizers
The C unit tests are additionally run with the following sanitizers enabled
- Valgrind: used to detect memory errors
- Address Sanitizer (ASAN): used to detect memory errors
- Thread Sanitizer (TSAN): used to detect race conditions

## Integration Tests
_Is the functionality of s2n-tls correct and RFC-compliant?_

Our integration tests involve interoperation with other TLS implementations, because testing against another implementation improves confidence that s2n-tls has implemented the feature correctly and is compliant with relevant RFCs.

s2n-tls integration tests are run using our [integrationv2](integrationv2/README.md) framework. Tests are implemented using "client" and "server" executables from various implementations. The client and server interactions are coordinated with [pytest](https://docs.pytest.org/en/stable/).

## Fuzz Tests
Fuzz Tests provide additional confidence in s2n-tls correctness by testing s2n-tls functionality under a wide vareity of inputs.

s2n-tls [fuzz tests](fuzz/Readme.md) use LibFuzzer as the fuzzing engine. Fuzzing is generally only applied to functions that take external input.

## Formal Methods
s2n-tls includes a variety of formal methods which are used to _prove_ that s2n-tls has certain behaviors.

### CBMC
> CBMC verifies memory safety (which includes array bounds checks and checks for the safe use of pointers), checks for various further variants of undefined behavior, and user-specified as­ser­tions.

s2n-tls writes CBMC proofs for a number of sensitive or commonly used functions in the codebase. Proof harnesses can be viewed [here](cbmc/proofs/)

### SAW
SAW verifies the correctness of code. More specifically, SAW can verify that some LLVM bitcode (compiled from C) matches the behavior of a cryptol specification. s2n-tls includes SAW proofs for its HMAC and DRBG implementations, as well as the TLS handshake state machine.

### Sidetrail
Sidetrail verifies the absence of timing side-channels, and is implemented using [smack](https://github.com/smackers/smack). Our [SideTrail proofs](sidetrail/working/) cover a number of the record processing functions.

### ctverif
`ctverif` is another tool that verifies the absence of timing side-channels and is also implemented using [smack](https://github.com/smackers/smack). Our [ctverif proofs](ctverif/Makefile) verify that `s2n_constant_time_equals` and `s2n_constant_time_copy_or_dont` are both constant time.

## Benchmarks
s2n-tls maintains a set of Rust [criterion benchmarks](../bindings/rust/bench/README.md) to assess the performance of s2n-tls. These benchmarks show
- performance of handshakes
- performance of data transfer (bulk encryption)
