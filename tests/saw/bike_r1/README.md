# SAW verification of BIKE R1

This is a SAW memory safety only proof of the C implementation of BIKE R1. It guarantees that there is not any undefined behavior (e.g. segmentation faults, memory safety violations, etc) when the BIKE code is compiled through the LLVM toolchain and executed.

## Limitations

The proof makes the following assumptions:
- Calls to OpenSSL functions always succeed (return 0). The proof does not model that if a call fails then memory is not guaranteed to be written. Manual inspection confirms that the BIKE code defends against this.
- `get_rand_mod_len` always generates the random position before `aes_ctr_prf` runs out of invocations.
- `get_threshold` does not exhibit any undefined behavior. This is because SAW does not support floating-point arithmetic.

