# s2n-tls API

The API exposed by s2n-tls is the set of functions and declarations that
are in the [s2n.h](https://github.com/aws/s2n-tls/blob/main/api/s2n.h) header file. Any functions and declarations that are in the [s2n.h](https://github.com/aws/s2n-tls/blob/main/api/s2n.h) file
are intended to be stable (API and ABI) within major version numbers of s2n-tls releases. Other functions
and structures used in s2n-tls internally can not be considered stable and their parameters, names, and
sizes may change.

In general, s2n-tls APIs are not thread safe unless explicitly specified otherwise.

Read [Error Handling](./ch03-error-handling.md) for information on processing API return values safely.

The [VERSIONING.rst](https://github.com/aws/s2n-tls/blob/main/VERSIONING.rst) document contains more details about s2n's approach to versions and API changes.

## API Reference

s2n-tls uses [Doxygen](https://doxygen.nl/index.html) to document its public API. The latest s2n-tls documentation can be found on [GitHub pages](https://aws.github.io/s2n-tls/doxygen/).

The doxygen documentation should be used in conjunction with this guide.

## Examples

To understand the API it may be easiest to see examples in action. s2n-tls's [bin](https://github.com/aws/s2n-tls/blob/main/bin/) directory
includes an example client (`s2nc`) and server (`s2nd`).

**Note:** `s2nc` and `s2nd` are intended for testing purposes only, and should not be used in production.
