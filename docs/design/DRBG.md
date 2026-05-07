
# Deterministic Random Bit Generator Deprecation

## Background
s2n-tls uses cryptographically secure randomness in several places, including:
- Random field of a client/server hello handshake message
- RSA TLS 1.2 fallback pre-master secret generation.
- TLS 1.3 new session ticket: random ticket_age_add per ticket.
- TLS 1.1/1.2 CBC to generate a fresh random explicit IV per record

s2n defines two streams of randomness, public and private, to ensure that the public entropy which is visible on the wire cannot be used to leak information about the private entropy.

## Historical Context
From its inception, s2n took the stance of implementing its own custom DRBG implementation to ensure a high cryptographic security and performance bar, though this evolved over the years. Here is a brief timeline:

1. Direct kernel entropy (defense-in-depth): Initially s2n sourced randomness straight from /dev/urandom, preferring kernel randomness over userspace RNGs for defense-in-depth ([article](https://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/) for more).

2. Libcrypto compatibility via override: To keep OpenSSL/libcrypto behavior aligned, s2n added an OpenSSL RAND override (first via RAND_METHOD, then via the ENGINE API) so libcrypto calls would be backed by s2n's entropy strategy, with cleanup restoring the original method.

3. Performance drove in-process RNG: Reading /dev/urandom was too slow (kernel locks + context switches), so s2n introduced an in-process DRBG and stopped pulling fresh bytes from the device for every request.

4. Per-thread split RNGs (public vs private): The design evolved into thread-local DRBGs with separate public and private streams, keeping handshake randomness fast and compartmentalized.

5. Prediction resistance + extra entropy mixing: s2n added prediction resistance by mixing in fresh entropy on generation, so learning DRBG state at one point would not let an attacker predict future outputs.

6. Fork-safety hardened over time: To avoid duplicated RNG state after fork(), s2n added fork-detection/mitigations (atfork hooks, OS-supported zero-on-fork / wipe-on-fork pages, later a fork-generation-number approach), forcing DRBG re-init when uniqueness could be broken.

7. FIPS correctness and modern libcrypto paths: In FIPS mode, s2n avoids custom overrides and uses the FIPS-validated libcrypto RNG, with later fixes to use RAND_priv_bytes for private randomness when supported.

## Why the Custom DRBG Was Removed
s2n's DRBG and randomness code added significant complexity to the codebase and was historically a source of subtle, high-impact issues. A custom randomness subsystem necessarily spans:

* OS entropy sources and file descriptors
* Thread-local state and cleanup
* Dynamic loading and unloading
* Fork detection and process lifecycle assumptions
* libcrypto backend interaction
* CPU- and compiler-specific behavior

These are areas prone to portability issues across platforms, runtimes, and deployment environments. Libcrypto providers are better positioned to design, validate, and maintain DRBG implementations.

Meanwhile, modern libcrypto backends significantly improved. OpenSSL 1.1.1+ and AWS-LC now provide fork-safe, standards-compliant RNGs with explicit public/private separation, closely matching the security properties that originally motivated s2n's DRBG. AWS-LC added separate public/private randomness support in this [PR](https://github.com/aws/aws-lc/pull/2963), removing the primary blocker to DRBG deprecation.

## Current State
The custom DRBG has been fully removed. s2n-tls now delegates all randomness to either the linked libcrypto or the system entropy source (`/dev/urandom`), depending on the capabilities of the libcrypto at compile time.

The gate function `s2n_use_libcrypto_rand()` determines which path is taken:

- When the libcrypto supports at least one of `RAND_priv_bytes` or `RAND_public_bytes` (detected via CMake feature probes `S2N_LIBCRYPTO_SUPPORTS_PRIVATE_RAND` and `S2N_LIBCRYPTO_SUPPORTS_PUBLIC_RAND`), s2n uses libcrypto for all randomness. Where the specific API is available it is called directly; otherwise `RAND_bytes` is used as a fallback.

- When the libcrypto supports neither (e.g. OpenSSL 1.0.2), s2n falls back to system random (`/dev/urandom`) for both public and private streams, avoiding any dependency on the older single-stream PRNG.
