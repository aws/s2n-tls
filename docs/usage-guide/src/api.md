# s2n-tls API

The API exposed by s2n-tls is the set of functions and declarations that
are in the [s2n.h](https://github.com/aws/s2n-tls/blob/main/api/s2n.h) header file. Any functions and declarations that are in the [s2n.h](https://github.com/aws/s2n-tls/blob/main/api/s2n.h) file
are intended to be stable (API and ABI) within major version numbers of s2n-tls releases. Other functions
and structures used in s2n-tls internally can not be considered stable and their parameters, names, and
sizes may change.

The [VERSIONING.rst](https://github.com/aws/s2n-tls/blob/main/VERSIONING.rst) document contains more details about s2n's approach to versions and API changes.

## API Reference

s2n-tls uses [Doxygen](https://doxygen.nl/index.html) to document its public API. The latest s2n-tls documentation can be found on [GitHub pages](https://aws.github.io/s2n-tls/doxygen/).

Documentation for older versions or branches of s2n-tls can be generated locally. To generate the documentation, install doxygen and run `doxygen docs/doxygen/Doxyfile`. The doxygen documentation can now be found at `docs/doxygen/output/html/index.html`.

Doxygen installation instructions are available at the [Doxygen](https://doxygen.nl/download.html) webpage.

The doxygen documentation should be used in conjunction with this guide.

## Supported TLS Versions

Currently TLS 1.2 is our default version, but we recommend TLS 1.3 where possible. To use TLS 1.3 you need a security policy that supports TLS 1.3. See the [Security Policies](#security-policies) section for more information.

**Note:** s2n-tls does not support SSL2.0 for sending and receiving encrypted data, but does accept SSL2.0 hello messages.

## Examples

To understand the API it may be easiest to see examples in action. s2n-tls's [bin](https://github.com/aws/s2n-tls/blob/main/bin/) directory
includes an example client (`s2nc`) and server (`s2nd`).

**Note:** `s2nc` and `s2nd` are intended for testing purposes only, and should not be used in production.
