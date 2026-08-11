# TLS Handshake Benchmarking

Per-message and operation-level timing comparison of **s2n-tls** and **rustls**
TLS 1.3 handshake performance.

## Two-track methodology

These two libraries decompose the TLS handshake state machine differently, so a
naive per-message comparison is unsound (the same message name measures different
work in each). This harness therefore produces two distinct kinds of output:

1. **Per-message profiles (within-implementation only).** Each implementation's
   own breakdown of where handshake time goes, message by message. Useful as a
   navigation aid; NOT overlaid across implementations.
2. **Operation-level comparison (cross-implementation).** The sound comparison —
   derived from CPU profiles, comparing the cost of actual operations (RSA sign,
   cert validation, key derivation, etc.) that exist identically in both libs.

How each works:
- **Per-message:** s2n-tls (C) emits a monotonic timestamp checkpoint after each
  handshake message handler; rustls (forked, `timing` feature) emits equivalent
  checkpoints. The harness drives in-memory handshakes (no sockets), collects
  checkpoints, and computes per-message durations as deltas. Both pinned to
  AES-128-GCM-SHA256 so the comparison is cipher-suite-matched.
- **Operation-level:** the harness runs a tight handshake loop under `perf`, and
  each operation's share of CPU self-time is converted to absolute µs using the
  loop's own measured mean handshake time. Validated against an isolated crypto
  microbenchmark.

## Dependencies

- **s2n-tls** — local checkout at `../s2n-tls`. Per-message instrumentation is
  in upstream (PR #5903), so any recent checkout works; which branch you check
  out determines what you benchmark.
- **rustls** — local checkout at `../rustls` on the `timing` branch of the
  `MrMistic/rustls` fork (upstream rustls has no checkpoint instrumentation;
  the harness requires the fork's `timing` feature).
- Python 3 with matplotlib, seaborn, pandas, numpy (visualization only; the
  interactive HTML loads Plotly from a CDN, so no Python package is needed)
- For operation-level analysis: `perf`. Flamegraph SVGs additionally need the
  FlameGraph scripts on PATH (`stackcollapse-perf.pl`, `flamegraph.pl`) and the
  frame-pointer build. See `--flamegraphs` below.

## Quick start

```bash
cargo build --release
```

### 0. One command: full version folder (recommended)

Builds the harness against the current `../s2n-tls` checkout (re-vendoring its C
sources first) and produces everything: message-timing run, per-message charts,
interactive HTML, and the operation-level comparison, for both cert types.
~20 min per cert type.

```bash
./make_version.sh <folder-name>            # -> charts_<folder-name>/, results_<folder-name>_<cert>.json
./make_version.sh <folder-name> rsa2048    # one cert type
./make_version.sh --no-lto <folder-name>   # GCC build (see "LTO and attribution")
./make_version.sh --flamegraphs <folder-name>
./make_version.sh --skip-build <folder-name>   # reuse the binary already in target/
./make_version.sh --impls a,b <folder-name>   # defaults to s2n-tls,rustls;
                          # non-default pairings are operation-level only
# options are s2n-tls, rustls, openssl, and boringssl(coming soon)

./make_version.sh --full <folder-name> # generates additional folders for mtls, resumed, and no-pq handshakes.
# force a non-default cert-verify backend (e.g. a libcrypto A/B baseline):
S2N_BENCH_CERT_BACKEND=libcrypto ./make_version.sh <folder-name>-baseline
```

Each run writes `charts_v<N>/provenance.txt` recording the s2n branch/commit,
toolchain (clang+LTO vs GCC), cert backend, and CPU. so a folder's numbers stay
interpretable later. Keep one version folder per build so runs never mix.

Each run takes a while, about 30 minutes. just run the one-liner and work on something else while it goes.

### 1. Per-message timing (both impls, JSON + charts) (make_version.sh does this for you)

```bash
# Runs s2n-tls AND rustls, writes combined JSON. Cert types:
#   rsa2048 | rsa3072 | rsa4096 | ecdsa256 | ecdsa384
S2N_DONT_MLOCK=1 ./target/release/tls-handshake-benchmarking rsa2048 results.json

# Per-message charts + combined interactive HTML -> charts_manual/<cert>/
pip install matplotlib seaborn pandas numpy
python3 visualize/visualize.py results.json --output-dir charts_manual/
```

### 2. Operation-level cross-implementation comparison

The authoritative flow is **DWARF self-time** (`make_version.sh` runs all of
this for you). Method: each operation's self-time share of CPU samples is
converted to absolute µs via `share x hot_loop_mean`. This is the mean handshake time
of an uninstrumented tight loop, NOT perf's wall-clock (which includes startup,
cert generation, and teardown). The conversion is validated by an isolated
RSA-sign microbenchmark (`--microbench`), which agrees with `share x mean` and
the per-message checkpoint to within ~3%.

```bash
# One-time perf setup
sudo sysctl kernel.perf_event_paranoid=1
sudo sysctl kernel.kptr_restrict=0

# 1. Capture each impl (20 s hot loop). The [hotloop] stderr line and the
#    hotloop_mean_<impl>_<cert>.txt sidecar record the mean_us for step 3.
perf record -g --call-graph dwarf -F 999 -o /tmp/s2n.data -- \
    ./target/release/tls-handshake-benchmarking --hotloop s2n-tls rsa2048 20
perf record -g --call-graph dwarf -F 999 -o /tmp/r.data -- \
    ./target/release/tls-handshake-benchmarking --hotloop rustls rsa2048 20

# 2. Self-time reports (slow on DWARF data, ~5 min each)
perf report -i /tmp/s2n.data --stdio --sort symbol > /tmp/s2n.rpt
perf report -i /tmp/r.data   --stdio --sort symbol > /tmp/r.rpt

# 3. Bucket into operations + render the chart. Means come from step 1's
#    sidecar files.
python3 analyze_selftime.py \
    --report  /tmp/s2n.rpt --mean  $(cat hotloop_mean_s2n-tls_rsa2048.txt) --label s2n-tls \
    --report2 /tmp/r.rpt   --mean2 $(cat hotloop_mean_rustls_rsa2048.txt)  --label2 rustls \
    --cert-type rsa2048 --chart charts/rsa2048/operation_comparison_rsa2048.png
```

Error bars: at 999 Hz over ~20 s, a 0.5% bucket is ~100 samples (±~10% noise).
Cite small buckets as differences, not precise absolutes.

### 3. Ground-truth crypto anchor (optional, validates the conversion)

Times an isolated RSA sign/verify outside the handshake. If `share x mean` and
this agree, the operation-level conversion is anchored to ground truth.

```bash
./target/release/tls-handshake-benchmarking --microbench rsa2048
```

## LTO and attribution (read before comparing runs or trusting small buckets)

The s2n-tls-sys build uses **clang + LTO when it finds clang**, and silently
falls back to **GCC with LTO disabled** otherwise (its own warning estimates a
2-4% performance penalty. Accurate since ~3% was measured on identical code). Two
consequences:

1. **Cross-run comparability.** Two runs built with different toolchains differ
   by ~3% on identical code, which masquerades as a code-level improvement or
   regression. Before comparing s2n means across builds, confirm the toolchain:
   `readelf -p .comment target/release/tls-handshake-benchmarking`. A GCC-only
   stamp means no LTO. A clang stamp means LTO.
2. **Bucket attribution.** LTO inlines s2n's small hot functions (the
   stuffer/blob validators, etc.), so their self-time redistributes into their
   callers and the fine-grained buckets (especially "Buffer serialization")
   become unreliable. A bucket "dropping" after a toolchain change is an
   artifact, not a win (`nm <binary> | grep s2n_stuffer_validate`: no symbol =
   inlined = don't trust its bucket).

Rule: **LTO build for headline totals** (it's the shipping configuration),
**non-LTO build for attribution work**. `./make_version.sh --no-lto <version>`
selects the GCC build (or `CC=gcc cargo build --release` by hand); either way
the per-function symbols survive and `provenance.txt` records which you got.

## Flamegraph SVGs (browsing, not numbers)

Self-time tells you what costs time, not who called it. For caller context, you
can render flamegraphs. These use a separate **frame-pointer build** (which
`--flamegraphs` builds for you) because DWARF cannot unwind through aws-lc's
hand-written assembly. DWARF captures fold into near-empty graphs.

```bash
./make_version.sh --flamegraphs <folder-name>   # adds SVGs alongside the charts_<folder-name> output

# or one implementation on its own:
RUSTFLAGS="-C force-frame-pointers=yes" CFLAGS="-fno-omit-frame-pointer -g" \
  cargo build --profile bench-fg
./target/bench-fg/tls-handshake-benchmarking --flamegraph s2n-tls rsa2048
```

Browse these for structure only. Frame-pointer stacks break through crypto
assembly and misattribute small buckets (this once inflated an EC bucket ~10x),
so cite numbers from the DWARF self-time chart.

## JSON output format

```json
{
  "metadata": { "cpu_model": "...", "warmup_iterations": 200,
                "measurement_iterations": 1000, "cert_type": "rsa2048" },
  "measurements": [
    { "implementation": "s2n-tls" | "rustls", "handshake_type": "tls13_full",
      "iteration": 0, "message_name": "SERVER_CERT_VERIFY",
      "role": "server", "direction": "write", "duration_ns": 295000 }
  ],
  "reproducibility": {
    "<impl>|<MESSAGE>_<role>_<direction>": { "mean_ns": ..., "stddev_ns": ..., "cv_percent": ... }
  }
}
```

Reproducibility keys are namespaced by implementation AND direction
(`s2n-tls|SERVER_CERT_VERIFY_server_write`) so the two are never merged and
read (processing) vs write (producing) costs stay distinct.

## Comparing across implementations (read this before making claims)

Both s2n-tls and rustls libraries emit read + write checkpoints and use the same handler-local delta
rule (cost measured from the preceding `RECORD_READ`, so peer-wait is excluded).
But they structure their state machines differently, so only some buckets are
1:1 comparable:

- **Cleanly 1:1 — `SERVER_CERT_VERIFY` server/write (RSA sign):** both isolate the
  signature op. (Measured: s2n ~355 µs vs rustls
  ~356 µs — identical, as expected on shared aws-lc.)
- **Compare as a SUM, not per-bucket, client cert path:** s2n puts chain
  validation in `SERVER_CERT`; rustls bundles it into `SERVER_CERT_VERIFY`. Only
  `SERVER_CERT + SERVER_CERT_VERIFY` combined is comparable (s2n ~68 µs vs rustls
  ~53 µs).
- **NOT comparable per-bucket — Finished, HKDF/key-schedule:** rustls bundles
  verify+derive+produce into one handler; s2n splits across handlers and
  transition gaps.

Rule of thumb: if you can't point to both implementations doing the same work
inside a bucket, don't compare that bucket — use the operation-level comparison.

## Comparing against other TLS libraries (operation-level only)

The operation-level pipeline is implementation-agnostic downstream of the perf
capture. It just needs a hot loop to profile. `openssl_hotloop.c` provides one
for OpenSSL (adaptable to BoringSSL), config-matched to the harness: TLS 1.3
only, AES-128-GCM-SHA256, X25519MLKEM768, tickets off, chain validation on. It
prints a `[config]` line on the first handshake so every run self-verifies the
negotiated parameters, and writes the same `[hotloop]` mean + sidecar file.

The easy path is `./make_version.sh --impls openssl,rustls <folder-name>`: if no
symbolized OpenSSL is available it downloads and builds one automatically
(one-time, ~5 min, cached in `~/.cache/bench-openssl-*`; needs curl/wget, perl,
make, gcc). Set `OPENSSL_DIR` to use your own source tree, or `OPENSSL_VERSION`
to pin a different release. The manual flow:

```bash
# 1. Dump the harness's exact cert chain so the chain shape matches
./target/release/tls-handshake-benchmarking --dump-certs rsa2048 /tmp/bench_certs

# 2. Build against an OpenSSL WITH DEBUG SYMBOLS (distro libssl is stripped —
#    self-time attribution needs symbols; build from source with -g):
#    ./Configure linux-x86_64 -g no-shared no-tests no-docs no-apps && make
gcc -O2 -g openssl_hotloop.c -o openssl_hotloop \
    -I<openssl-src>/include <openssl-src>/libssl.a <openssl-src>/libcrypto.a -lpthread -ldl

# 3. Same capture/report/analyze flow as above; labels are arbitrary
./openssl_hotloop rsa2048 /tmp/bench_certs/rsa2048_{chain,key,ca}.pem 20  # under perf record
python3 analyze_selftime.py --report s2n.rpt --mean <..> --label s2n-tls \
    --report2 openssl.rpt --mean2 <..> --label2 "OpenSSL 3.5.5" \
    --cert-type rsa2048 --chart out.png
```

Interpretation caveat: unlike s2n-vs-rustls (both on aws-lc-rs, ~60% byte-identical
crypto), a third library brings its own crypto. Bucket diffs mix TLS-stack overhead
with crypto-implementation differences. Bucket
regexes in `analyze_selftime.py` cover aws-lc and OpenSSL 3.5 symbol names. When
adding another library, check what falls into "Framework overhead" for symbols
the patterns miss (AI can handle this).

## Key configuration decisions (and why)

- **Security policy: `CloudFront-TLS-1-3-2025`** (set in `build_s2n_configs`,
  `src/main.rs`). Chosen so BOTH s2n optimizations under test fire:
  TLS 1.3-only minimum (enables transcript-hash narrowing) AND x25519 first in
  its ecc preferences, matching the x25519_mlkem768 hybrid's classical curve
  (enables classical key-share reuse). Do NOT switch to
  `CloudFront-Upstream-TLS-1-3-2025-PQ`: it puts secp256r1 first, which silently
  disables key-share reuse and adds a ~10 µs P-256 keygen per handshake.
- **Cert verify backend: `S2N_BENCH_CERT_BACKEND` env var** (`zero_copy` |
  `libcrypto` | `differential`; unset = the build's default, which is zero-copy
  on CBS-capable builds with the current fix branches). This hook is a
  harness-only commit on the s2n integration branch. The internal C setter
  isn't reachable from the Rust bindings. Do not upstream it.
- **s2n build target: whatever is checked out at `../s2n-tls`** (override with
  `S2N_DIR`). That checkout determines what you measure, which is why
  `make_version.sh` records its commit in `provenance.txt`. Gotcha the script
  handles for you: the sys crate compiles VENDORED copies of the C sources, so
  it re-runs `bindings/rust/extended/generate.sh` and `cargo clean -p
  s2n-tls-sys` before building. Building by hand without those steps silently
  measures stale C code.
- **Cipher suite pinned to AES-128-GCM-SHA256 on both sides** — rustls otherwise
  defaults to AES-256-GCM-SHA384 and the ~70 µs heavier SHA-384 transcript
  masquerades as a hashing gap.
- **Which mean to cite:** hot-loop means (no subscriber overhead) for headline
  totals; the message-timing means include instrumentation overhead and are for
  within-implementation profiles only. Note the hot-loop means printed by
  `make_version.sh` are captured under `perf record` (DWARF), which adds ~25 µs
  vs a bare run. Compare DWARF runs with DWARF runs. If you only use the make_version.sh, you don't have anything to worry about, it handles everything for you.
- **Toolchain: pin it per comparison.** The sys crate silently switches between
  clang+LTO and GCC-no-LTO depending on whether it finds clang (~3% swing, and
  LTO breaks bucket attribution. See "LTO and attribution" above). Use
  `--no-lto` to select deliberately; `provenance.txt` records what you got.

## Notes

- Both implementations run full handshakes (rustls resumption is disabled) so the
  certificate flight (RSA/ECDSA verify) is present every time.
- Cross-implementation per-message bars are intentionally NOT produced; only
  operation-level comparison is sound across the two libraries.
