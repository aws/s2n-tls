The `sha.h` is copied from OpenSSL version 1.0.2d, and the `hmac.bc`
and `hmac.ll` were copied from `tmp` after running `make`. We're
versioning these files in order to have consistent artifacts to
verify, as they can differ on differ platforms, or with different
underlying SSL libs.

The s2n source is in `s2n`. We are not currently tracking a specific
revision, but we may want to get consistent builds.
