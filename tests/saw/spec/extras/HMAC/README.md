These are files detailing the verification of HMAC with respect to the
HMAC specification provided by Andrew Appel's HMAC verification effort.

The files in this repository constitue a proof of equivalence between
the [Cryptol specification of HMAC](../../HMAC.cry) and the [HMAC
specification](HMAC_spec.v) used for the FCF proof of HMAC.

This proof of equivalence is done through a [mechanized semantics of
Cryptol](https://github.com/GaloisInc/cryptol-semantics).

You can read more about the FCF proof of correctness for HMAC in
[this paper](https://www.cs.princeton.edu/~appel/papers/verified-hmac.pdf)

These files don't build by themselves, but rather require the
[cryptol-semantics repository](https://github.com/GaloisInc/cryptol-semantics) checked out and built
in the same directory as s2n.

These is verification effort used Coq 8.6, if you use a different
version YMMV.

Build instructions:
  1. Build the cryptol-semantics repository
  2. make (in this directory)

NOTE: When you make you may see some warnings about ambiguous paths,
as the cryptol-semantics repository contains all of these files as
well.