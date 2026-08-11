#!/usr/bin/env bash
# Build the harness against the ../s2n-tls checkout (override: S2N_DIR), then
# generate a complete charts_<folder-name> folder. Flag details: see README.
#
# Usage: ./make_version.sh [flags] <folder-name> [cert_type ...]
#   default cert types: rsa2048 ecdsa256
#   --no-lto        GCC build, no LTO (for trustworthy bucket attribution)
#   --flamegraphs   also render SVGs (needs FlameGraph scripts on PATH)
#   --skip-build    reuse the existing binary as-is
#   --impls a,b     implementations to compare (default s2n-tls,rustls;
#                   openssl pairings are operation-level only, need OPENSSL_DIR)
#   --full          also run mtls/resumed/no-pq variants (per-message only)
#
# Env: S2N_BENCH_CERT_BACKEND=zero_copy|libcrypto|differential (default: build's)
# Runtime: ~20 min per cert type; perf report on DWARF data is the slow part.
set -euo pipefail

FLAMEGRAPHS=0
NO_LTO=0
SKIP_BUILD=0
FULL=0
IMPLS="s2n-tls,rustls"
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --flamegraphs) FLAMEGRAPHS=1 ;;
        --no-lto)      NO_LTO=1 ;;
        --skip-build)  SKIP_BUILD=1 ;;
        --full)        FULL=1 ;;
        --impls)       IMPLS="${2:?--impls needs a value, e.g. openssl,rustls}"; shift ;;
        --impls=*)     IMPLS="${1#--impls=}" ;;
        -*) echo "ERROR: unknown flag $1" >&2; exit 1 ;;
        *)  ARGS+=("$1") ;;
    esac
    shift
done
set -- "${ARGS[@]}"

IFS=',' read -r IMPL_A IMPL_B _extra <<< "$IMPLS"
[ -n "${IMPL_B:-}" ] && [ -z "${_extra:-}" ] \
    || { echo "ERROR: --impls needs exactly two, e.g. --impls openssl,rustls" >&2; exit 1; }
for i in "$IMPL_A" "$IMPL_B"; do
    case "$i" in
        s2n-tls|rustls|openssl) ;;
        *) echo "ERROR: unknown impl '$i' (valid: s2n-tls, rustls, openssl)" >&2; exit 1 ;;
    esac
done
[ "$IMPL_A" != "$IMPL_B" ] || { echo "ERROR: --impls needs two different implementations" >&2; exit 1; }
# The per-message track needs checkpoint instrumentation, which only s2n-tls and
# rustls have; the harness binary always runs that pair together.
PER_MESSAGE=0
if [ "$IMPL_A,$IMPL_B" = "s2n-tls,rustls" ] || [ "$IMPL_A,$IMPL_B" = "rustls,s2n-tls" ]; then
    PER_MESSAGE=1
fi
if [ "$FULL" = 1 ] && [ "$PER_MESSAGE" = 0 ]; then
    echo "ERROR: --full variants are per-message only and need the s2n-tls,rustls pairing" >&2
    exit 1
fi

VERSION="${1:?usage: ./make_version.sh [--no-lto] [--flamegraphs] [--skip-build] [--full] [--impls a,b] <version> [cert_type ...]}"
shift
CERTS=("$@")
if [ $# -eq 0 ]; then CERTS=(rsa2048 ecdsa256); fi
# Validate upfront: an unknown cert type would otherwise fail mid-run (or worse,
# --dump-certs silently falls back to rsa2048 and mislabels openssl results).
for cert in "${CERTS[@]}"; do
    case "$cert" in
        rsa2048|rsa3072|rsa4096|ecdsa256|ecdsa384) ;;
        *) echo "ERROR: unknown cert type '$cert' (valid: rsa2048 rsa3072 rsa4096 ecdsa256 ecdsa384)" >&2; exit 1 ;;
    esac
done

S2N_DIR="${S2N_DIR:-../s2n-tls}"
BIN=./target/release/tls-handshake-benchmarking
FG_BIN=./target/bench-fg/tls-handshake-benchmarking
OUT="charts_${VERSION}"
HOTLOOP_SECS=20

command -v perf >/dev/null || { echo "ERROR: perf not on PATH" >&2; exit 1; }
# Probe that perf can actually record (fresh machines often block it).
perf record -o "/tmp/perf_probe_$$.data" -- true > /dev/null 2>&1 \
    || { echo "ERROR: perf cannot record. Try: sudo sysctl kernel.perf_event_paranoid=1 kernel.kptr_restrict=0" >&2; exit 1; }
rm -f "/tmp/perf_probe_$$.data"
if [ "$FLAMEGRAPHS" = 1 ]; then
    command -v stackcollapse-perf.pl >/dev/null && command -v flamegraph.pl >/dev/null \
        || { echo "ERROR: --flamegraphs needs stackcollapse-perf.pl + flamegraph.pl on PATH" >&2; exit 1; }
    # With --skip-build nothing will produce the FP binary, so require it upfront.
    if [ "$SKIP_BUILD" = 1 ] && [ ! -x "$FG_BIN" ]; then
        echo "ERROR: --flamegraphs with --skip-build needs an existing $FG_BIN (see header for the bench-fg build)" >&2
        exit 1
    fi
fi

echo "== Version: ${VERSION}  cert types: ${CERTS[*]}"
echo "== Comparing: ${IMPL_A} vs ${IMPL_B}$([ "$PER_MESSAGE" = 0 ] && echo '  (operation-level only)')"
echo "== S2N_BENCH_CERT_BACKEND=${S2N_BENCH_CERT_BACKEND:-<unset: build default>}"

needs_openssl=0
[ "$IMPL_A" = openssl ] || [ "$IMPL_B" = openssl ] && needs_openssl=1
OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.5}"
if [ "$needs_openssl" = 1 ] && [ ! -x ./openssl_hotloop ] && [ -z "${OPENSSL_DIR:-}" ]; then
    # No symbolized OpenSSL provided: fetch and build one (distro libssl is
    # stripped, so self-time attribution needs a from-source -g build).
    OPENSSL_DIR="${HOME}/.cache/bench-openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}"
    if [ ! -f "${OPENSSL_DIR}/libssl.a" ]; then
        command -v curl >/dev/null || command -v wget >/dev/null \
            || { echo "ERROR: need curl or wget to fetch OpenSSL (or set OPENSSL_DIR)" >&2; exit 1; }
        command -v perl >/dev/null && command -v make >/dev/null && command -v gcc >/dev/null \
            || { echo "ERROR: building OpenSSL needs perl, make, and gcc (or set OPENSSL_DIR)" >&2; exit 1; }
        echo "== fetch: OpenSSL ${OPENSSL_VERSION} (one-time, ~5 min build) -> ${OPENSSL_DIR}"
        mkdir -p "$(dirname "$OPENSSL_DIR")"
        url="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
        if command -v curl >/dev/null; then
            curl -fsSL "$url" | tar xz -C "$(dirname "$OPENSSL_DIR")"
        else
            wget -qO- "$url" | tar xz -C "$(dirname "$OPENSSL_DIR")"
        fi
        (cd "$OPENSSL_DIR" \
            && ./Configure linux-x86_64 -g no-shared no-tests no-docs no-apps \
            && make build_generated \
            && make -j"$(nproc)" libssl.a libcrypto.a) > "/tmp/${VERSION}_openssl_build.log" 2>&1 \
            || { echo "ERROR: OpenSSL build failed; see /tmp/${VERSION}_openssl_build.log" >&2; exit 1; }
    else
        echo "== fetch: using cached OpenSSL at ${OPENSSL_DIR}"
    fi
fi

# Capture one implementation under perf. Each impl has its own workload driver
# but the same output contract: a [hotloop] line and a hotloop_mean_* sidecar.
# The sidecar is deleted first and required after, so a crashed hot loop can
# never silently fall back to a stale mean from an earlier run.
capture_impl() {
    local impl="$1" cert="$2" data="$3"
    rm -f "hotloop_mean_${impl}_${cert}.txt"
    case "$impl" in
        s2n-tls|rustls)
            perf record -g --call-graph dwarf -F 999 -o "$data" -- \
                "$BIN" --hotloop "$impl" "$cert" "$HOTLOOP_SECS" 2>&1 | grep '\[hotloop\]' || true
            ;;
        openssl)
            perf record -g --call-graph dwarf -F 999 -o "$data" -- \
                ./openssl_hotloop "$cert" \
                    "/tmp/${VERSION}_certs/${cert}_chain.pem" \
                    "/tmp/${VERSION}_certs/${cert}_key.pem" \
                    "/tmp/${VERSION}_certs/${cert}_ca.pem" \
                    "$HOTLOOP_SECS" 2>&1 | grep -E '\[hotloop\]|\[config\]' || true
            ;;
    esac
    [ -s "hotloop_mean_${impl}_${cert}.txt" ] || {
        echo "ERROR: ${impl} hot loop produced no mean for ${cert} (crashed under perf?)" >&2
        exit 1
    }
}

# ---------------------------------------------------------------- build
if [ "$SKIP_BUILD" = 1 ]; then
    echo "== build: skipped (--skip-build); using the existing binary"
    [ -x "$BIN" ] || { echo "ERROR: $BIN does not exist" >&2; exit 1; }
    if [ "$needs_openssl" = 1 ] && [ ! -x ./openssl_hotloop ]; then
        echo "ERROR: --skip-build with openssl needs a prebuilt ./openssl_hotloop" >&2
        exit 1
    fi
else
    # The sys crate compiles VENDORED copies of the s2n C sources, so re-vendor
    # first or the build silently measures stale code.
    echo "== build: re-vendoring s2n C sources from ${S2N_DIR}"
    (cd "${S2N_DIR}/bindings/rust/extended" && ./generate.sh) > /tmp/${VERSION}_generate.log 2>&1 \
        || { echo "ERROR: generate.sh failed; see /tmp/${VERSION}_generate.log" >&2; exit 1; }
    cargo clean -p s2n-tls-sys > /dev/null 2>&1 || true

    # No pipes here: a pipeline would mask cargo's exit status and let a failed
    # build fall through into the benchmark run. set -e catches it as written.
    if [ "$NO_LTO" = 1 ]; then
        echo "== build: release (GCC, no LTO — symbols preserved for attribution)"
        CC=gcc cargo build --release
    else
        echo "== build: release (clang + LTO if available — shipping config)"
        cargo build --release
    fi

    if [ "$FLAMEGRAPHS" = 1 ]; then
        echo "== build: bench-fg (frame pointers, for flamegraphs)"
        RUSTFLAGS="-C force-frame-pointers=yes" CFLAGS="-fno-omit-frame-pointer -g" \
            cargo build --profile bench-fg
    fi

    if [ "$needs_openssl" = 1 ] && [ -n "${OPENSSL_DIR:-}" ]; then
        echo "== build: openssl_hotloop against ${OPENSSL_DIR}"
        gcc -O2 -g openssl_hotloop.c -o openssl_hotloop \
            -I"${OPENSSL_DIR}/include" "${OPENSSL_DIR}/libssl.a" "${OPENSSL_DIR}/libcrypto.a" \
            -lpthread -ldl
    fi
fi

# ------------------------------------------------------------ provenance
# Record what was actually measured. A toolchain flip alone moves s2n means ~3%,
# so "which build was this" has to travel with the results.
if [ -d "$OUT" ]; then
    echo "WARNING: ${OUT} already exists; new files overwrite old ones and leftovers from previous runs will mix in" >&2
fi
mkdir -p "$OUT"
s2n_commit=$(git -C "$S2N_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
s2n_branch=$(git -C "$S2N_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
rustls_commit=$(git -C ../rustls rev-parse --short HEAD 2>/dev/null || echo unknown)
if readelf -p .comment "$BIN" 2>/dev/null | grep -q clang; then
    toolchain="clang+LTO"
else
    toolchain="gcc (no LTO)"
fi
{
    echo "version:      ${VERSION}"
    echo "date:         $(date -Is)"
    echo "impls:        ${IMPL_A} vs ${IMPL_B}"
    echo "s2n:          ${s2n_branch} @ ${s2n_commit}"
    echo "rustls:       ${rustls_commit}"
    [ "$needs_openssl" = 1 ] && echo "openssl:      ${OPENSSL_VERSION}"
    echo "toolchain:    ${toolchain}"
    echo "cert_backend: ${S2N_BENCH_CERT_BACKEND:-build default}"
    echo "cpu:          $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)"
} > "${OUT}/provenance.txt"
echo "== s2n: ${s2n_branch} @ ${s2n_commit} | toolchain: ${toolchain}"

# ------------------------------------------------------------- per cert
for cert in "${CERTS[@]}"; do
    echo
    if [ "$PER_MESSAGE" = 1 ]; then
        results="results_${VERSION}_${cert}.json"
        echo "== [$cert] 1/4: message-timing benchmark -> ${results}"
        "$BIN" "$cert" "$results" > /dev/null

        echo "== [$cert] 2/4: per-message charts + interactive HTML -> ${OUT}/${cert}/"
        python3 visualize/visualize.py "$results" --output-dir "./${OUT}"
    else
        echo "== [$cert] 1-2/4: per-message track skipped (needs s2n-tls + rustls)"
    fi

    if [ "$needs_openssl" = 1 ]; then
        # Non-harness drivers need the same cert chain the harness generates.
        mkdir -p "/tmp/${VERSION}_certs"
        "$BIN" --dump-certs "$cert" "/tmp/${VERSION}_certs" > /dev/null
    fi

    echo "== [$cert] 3/4: perf captures (${HOTLOOP_SECS}s hot loop each, DWARF)"
    data_a="/tmp/${VERSION}_${IMPL_A}_${cert}.data"
    data_b="/tmp/${VERSION}_${IMPL_B}_${cert}.data"
    capture_impl "$IMPL_A" "$cert" "$data_a"
    capture_impl "$IMPL_B" "$cert" "$data_b"

    # Each hot loop writes its mean to a sidecar file; read it so nobody has to
    # copy numbers by hand (stale means silently scale the whole chart).
    mean_a=$(cat "hotloop_mean_${IMPL_A}_${cert}.txt")
    mean_b=$(cat "hotloop_mean_${IMPL_B}_${cert}.txt")
    echo "   hot-loop means: ${IMPL_A}=${mean_a}us ${IMPL_B}=${mean_b}us"

    echo "== [$cert] 4/4: perf reports + operation comparison (slow: ~5 min/report)"
    rpt_a="/tmp/${VERSION}_${IMPL_A}_${cert}.rpt"
    rpt_b="/tmp/${VERSION}_${IMPL_B}_${cert}.rpt"
    perf report -i "$data_a" --stdio --sort symbol > "$rpt_a" 2>/dev/null &
    perf report -i "$data_b" --stdio --sort symbol > "$rpt_b" 2>/dev/null &
    wait
    # `wait` doesn't propagate background failures; require real content so an
    # empty report can't flow into the analysis as an all-zero profile.
    for r in "$rpt_a" "$rpt_b"; do
        grep -q '%' "$r" || { echo "ERROR: perf report produced no samples in $r" >&2; exit 1; }
    done

    mkdir -p "${OUT}/${cert}"
    python3 analyze_selftime.py \
        --report  "$rpt_a" --mean  "$mean_a" --label  "$IMPL_A" \
        --report2 "$rpt_b" --mean2 "$mean_b" --label2 "$IMPL_B" \
        --cert-type "$cert" \
        --chart "${OUT}/${cert}/operation_comparison_${cert}.png"

    if [ "$FLAMEGRAPHS" = 1 ]; then
        echo "== [$cert] extra: flamegraph SVGs (frame-pointer captures, 20 s each)"
        for name in "$IMPL_A" "$IMPL_B"; do
            if [ "$name" = openssl ]; then
                echo "   (skipping openssl: --flamegraph is a harness mode)"
                continue
            fi
            "$FG_BIN" --flamegraph "$name" "$cert" > /dev/null 2>&1
            mv "flamegraph_${name}_${cert}.svg" "${OUT}/${cert}/"
            echo "   ✓ ${OUT}/${cert}/flamegraph_${name}_${cert}.svg"
        done
    fi

    if [ "$FULL" = 1 ]; then
        # Handshake variants: per-message charts only (see header). Each gets
        # its own subfolder because visualize.py names outputs by cert type,
        # which is the same across variants.
        for variant in mtls resumed no-pq; do
            vdir="${variant//-/_}"   # no-pq -> no_pq (folder-friendly)
            vresults="results_${VERSION}_${cert}_${vdir}.json"
            echo "== [$cert] variant '${variant}': message-timing -> ${vresults}"
            "$BIN" "--${variant}" "$cert" "$vresults" > /dev/null
            python3 visualize/visualize.py "$vresults" --output-dir "./${OUT}/${vdir}"
        done
    fi
done

echo
echo "== Done. Contents of ${OUT}:"
find "$OUT" -type f | sort
