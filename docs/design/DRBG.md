# Deterministic Random Bit Generator

## Background
s2n-tls uses a deterministic random bit generator (DRBG) to generate cryptographically secure randomness. s2n uses randomly generated data in several places including:
- Random field of a client/server hello handshake message
- RSA TLS 1.2 fallback pre-master secret generation.
- TLS 1.3 new session ticket: random ticket_age_add per ticket.
- TLS 1.1/1.2 CBC to generate a fresh random explicit IV per record

s2n defines two streams of randomness, public and private, to ensure that the public entropy which is visible on the wire cannot be used to leak information about the private entropy. 

## Historical Context
From its inception, s2n has taken the stance of implementing its own custom DRBG implementation to ensure a high cryptographic security and performance bar though this has come in different shapes and sizes over the years.

1. Direct kernel entropy (defense-in-depth): Initially s2n sourced randomness straight from /dev/urandom, preferring kernel randomness over userspace RNGs for defense-in-depth ([article](https://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/) for more).

2. Libcrypto compatibility via override: To keep OpenSSL/libcrypto behavior aligned, s2n added an OpenSSL RAND override (first via RAND_METHOD, then via the ENGINE API) so libcrypto calls would be backed by s2n’s entropy strategy, with cleanup restoring the original method.

3. Performance drove in-process RNG: Reading /dev/urandom was too slow (kernel locks + context switches), so s2n introduced an in-process DRBG and stopped pulling fresh bytes from the device for every request.

4. Per-thread split RNGs (public vs private): The design evolved into thread-local DRBGs with separate public and private streams, keeping handshake randomness fast and compartmentalized.

5. Prediction resistance + extra entropy mixing: s2n added prediction resistance by mixing in fresh entropy on generation, so learning DRBG state at one point doesn’t let an attacker predict future outputs.

6. Fork-safety hardened over time: To avoid duplicated RNG state after fork(), s2n added fork-detection/mitigations (atfork hooks → OS-supported zero-on-fork / wipe-on-fork pages → later a fork-generation-number approach), forcing DRBG re-init when uniqueness could be broken.

7. FIPS correctness and modern libcrypto paths: In FIPS mode, s2n avoids custom overrides and uses the FIPS-validated libcrypto RNG, with later fixes to use RAND_priv_bytes for private randomness when supported.

## Maintining a Custom DRBG is Increasingly Costly
s2n’s DRBG and randomness code adds significant complexity to the codebase and has historically been a source of subtle, high-impact issues. Although many individual issues have been fixed, their recurrence highlights a structural concern.

A custom randomness subsystem necessarily spans:

* OS entropy sources and file descriptors
* Thread-local state and cleanup
* Dynamic loading and unloading
* Fork detection and process lifecycle assumptions
* libcrypto backend interaction
* CPU- and compiler-specific behavior

These are areas prone to portability issues across platforms, runtimes, and deployment environments.

Even when specific bugs are resolved, changes in platform behavior, toolchains, or usage patterns can reintroduce similar classes of issues. The ongoing risk is not any single historical failure, but the continued exposure to lifecycle concerns. Libcrypto providers are better positioned to design, validate, and maintain DRBG implementations for our customers.

## Current Behavior
The "libcrypto" layer refers to randomness generated inside the cryptographic backend itself (e.g., via RAND_bytes() / RAND_priv_bytes() and other internal libcrypto consumers), while the "TLS layer" refers to randomness generated directly by s2n-tls to implement the TLS protocol (handshake randoms, nonces, tickets, and key schedule inputs).

s2n relies on the backend libcrypto’s native random implementation at the libcrypto layer when building with AWS-LC, BoringSSL, LibreSSL, or with FIPS libcrypto. The only configuration where s2n forces its custom random implementation into the libcrypto layer is when building against OpenSSL in non-FIPS mode. At the TLS layer, s2n uses its custom per-thread DRBG by default, delegating TLS-layer randomness to libcrypto only when operating in FIPS mode.

s2n’s custom DRBG has been maintained primarily because AWS-LC did not provide distinct public and private randomness, which s2n guarantees as a defense-in-depth measure for TLS-layer randomness. AWS-LC added separate public/private randomness support in this [PR](https://github.com/aws/aws-lc/pull/2963), removing the primary blocker.

## Path Forward
Since s2n first introduced its custom DRBG, modern libcrypto backends have significantly improved. OpenSSL 1.1.1+ and AWS-LC now provide fork-safe, standards-compliant RNGs with explicit public/private separation, closely matching the security properties that originally motivated s2n’s DRBG.

Given this, the proposed path forward is to deprecate s2n’s internal DRBG and delegate randomness to libcrypto backends by default, consistent with s2n’s goal of being a simple and small TLS library.

For modern backends (AWS-LC, OpenSSL ≥ 1.1.1, BoringSSL, LibreSSL), s2n can fully rely on backend-provided randomness at both the libcrypto and TLS layers, using native public/private APIs where available.
