# SAW verification of BIKE R2

This is a SAW memory safety only proof of the C implementation of BIKE R2. It guarantees that there is not any undefined behavior (e.g. segmentation faults, memory safety violations, etc) when the BIKE code is compiled through the LLVM toolchain and executed.

## Limitations

The proof makes the following assumptions:
- the specifications of OpenSSL functions are accurate.
- `get_threshold` does not exhibit any undefined behavior. This is because SAW does not support floating-point arithmetic.

