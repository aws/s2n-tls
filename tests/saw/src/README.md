The `sha.h` is copied from OpenSSL version 1.0.2d, and the `hmac.bc`
and `hmac.ll` were copied from `tmp` after running `make`. We're
versioning these files in order to have consistent artifacts to
verify, as they can differ on differ platforms, or with different
underlying SSL libs.

The s2n source is in `s2n`. We are not currently tracking a specific
revision, but we may want to get consistent builds.

As temporary workaround until SAW is extended to support multiple
specs for the same function, we patch the s2n sources trivially using
`distinguish_update_calls_at_different_sizes.patch`, to distinguish
update calls with different size arguments.

To build the LLVM files, do

    make s2n; make
