#!/usr/bin/env python3
"""
Operation-level analysis from DWARF self-time (trustworthy).

This reads `perf report --sort symbol` and uses SELF time, the instruction-pointer leaf.

Input: the text output of
    perf report -i <data.dwarf> --stdio --sort symbol
Pass the file (or stdin). Multiply shares by the hot-loop mean for absolute us.

Usage:
    perf report -i perf_s2n_dwarf.data --stdio --sort symbol > s2n.rpt
    python3 analyze_selftime.py --report s2n.rpt --mean 590.5 --label s2n-tls
"""
import argparse
import re

BUCKETS = [
    ("RSA sign/verify", [r"rsaz_amm", r"bn_sqrx", r"bn_sqr8x", r"bn_mulx", r"bn_mul",
                         r"mulx4x", r"extract_multiplier", r"bn_mod_exp", r"bn_from_montgomery",
                         r"bn_mont", r"rsa_", r"\brsa\b", r"mod_exp",
                         r"bn_add", r"bn_sub", r"bn_mod", r"bn_cmp", r"bn_rshift",
                         r"bn_uadd", r"bn_select", r"BN_div", r"BN_mod_inverse",
                         r"bn_minimal_width", r"bn_fits_in_words", r"bn_rshift_words",
                         r"bn_powerx5", r"bn_cmp_words", r"bn_set_minimal_width",
                         r"bn_wexpand", r"BN_num_bits", r"bn_usub", r"BN_is_odd"]),
    ("ECDSA/EC P-256",  [r"ecp_nistz", r"nistz256", r"p256", r"ecdsa", r"bignum_montinv_p256"]),
    # fe_* = OpenSSL curve25519 field-element internals (no aws-lc collisions)
    ("X25519 key exchange", [r"25519", r"curve25519", r"x25519", r"\bfe_"]),
    # scalar_ntt/matrix_expand/etc = OpenSSL ML-KEM internals (crypto/ml_kem)
    ("ML-KEM (post-quantum)", [r"keccak", r"sha3", r"kyber", r"mlkem", r"ml_kem",
                               r"SHAKE", r"KeccakF1600",
                               r"scalar_ntt", r"inverse_ntt", r"matrix_expand",
                               r"encrypt_cpa", r"\bdecap\b", r"\bcmov\b",
                               r"scalar_encode", r"scalar_decode"]),
    ("Transcript hashing (SHA/MD5)", [r"sha256_block", r"sha512_block", r"sha1_block", r"sha256", r"sha512",
                                   r"md5_block", r"SHA256", r"SHA512", r"SHA1_",
                                   r"s2n_hash_", r"s2n_evp_hash", r"EVP_Digest"]),
    ("Key derivation (HKDF)", [r"hkdf", r"hmac", r"secrets_update", r"key_schedule", r"derive",
                               r"expand_label", r"tls13_"]),
    ("AES-GCM encryption", [r"aes", r"gcm", r"aead", r"chacha", r"poly1305", r"ghash"]),
    ("Certificate validation", [r"x509", r"asn1", r"\bcbs_", r"parse_asn1", r"cache_extensions",
                                r"verify_cert", r"name_constraints", r"name_canon", r"\bder_", r"webpki"]),
    ("Buffer serialization (s2n)", [r"s2n_stuffer", r"s2n_blob", r"s2n_record_"]),
    ("RNG", [r"rdrand", r"rand_bytes", r"drbg", r"ctr_drbg", r"CRYPTO_rdrand",
                           r"jent_"]),
    ("Memory alloc/free", [r"malloc", r"\bfree\b", r"cfree", r"alloc", r"memcpy", r"memset", r"memmove",
                           r"OPENSSL_free", r"OPENSSL_malloc", r"OPENSSL_cleanse",
                           r"_int_free", r"unlink_chunk", r"__rust.*alloc", r"__rust.*dealloc",
                           r"tcache_get", r"_int_malloc"]),
]


def parse_report(path):
    """Return list of (self_pct, symbol). Reads perf report --sort symbol stdio."""
    rows = []
    # Match lines like:  44.21%    44.20%  [.] symbol_name
    line_re = re.compile(r"^\s*([\d.]+)%\s+([\d.]+)%\s+\[[^\]]*\]\s+(.*?)\s*$")
    with open(path) as f:
        for line in f:
            m = line_re.match(line)
            if not m:
                continue
            self_pct = float(m.group(2))  # second column is self
            sym = m.group(3)
            if self_pct > 0:
                rows.append((self_pct, sym))
    return rows


def bucketize(rows):
    pats = [(name, [re.compile(p, re.IGNORECASE) for p in pl]) for name, pl in BUCKETS]
    counts = {name: 0.0 for name, _ in BUCKETS}
    counts["other"] = 0.0
    for self_pct, sym in rows:
        matched = None
        for name, plist in pats:
            if any(p.search(sym) for p in plist):
                matched = name
                break
        counts[matched if matched else "other"] += self_pct
    return counts


def report_counts(report, mean, label):
    rows = parse_report(report)
    counts = bucketize(rows)
    accounted = sum(counts.values())
    print(f"\n=== {label} (DWARF self-time; mean {mean:.1f} us) ===")
    print(f"  {'Operation':<32} {'self%':>7} {'us/handshake':>13}")
    print(f"  {'-'*32} {'-'*7} {'-'*13}")
    for name in [b[0] for b in BUCKETS] + ["other"]:
        pct = counts[name]
        if pct <= 0:
            continue
        display_name = "Framework overhead" if name == "other" else name
        print(f"  {display_name:<32} {pct:6.1f}% {pct/100*mean:11.1f}")
    print(f"  (accounted: {accounted:.1f}% of self-time samples)")
    return {name: counts[name] / 100 * mean for name, _ in BUCKETS}, counts["other"] / 100 * mean


def make_chart(s2n_us, rustls_us, cert_type, out_path, s2n_mean=0, r_mean=0,
               label1="s2n-tls", label2="rustls"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    names = [b[0] for b in BUCKETS] + ["Framework overhead"]
    names = [n for n in names if s2n_us.get(n, 0) > 0.05 or rustls_us.get(n, 0) > 0.05]
    s = [s2n_us.get(n, 0) for n in names]
    r = [rustls_us.get(n, 0) for n in names]
    y = np.arange(len(names))
    h = 0.38
    fig, ax = plt.subplots(figsize=(12, max(6, len(names) * 0.7 + 1)))
    bars_s = ax.barh(y - h / 2, s, h, label=label1, color="#4682b4", edgecolor="black", linewidth=0.4)
    bars_r = ax.barh(y + h / 2, r, h, label=label2, color="#e68c3c", edgecolor="black", linewidth=0.4)
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel("µs per handshake (self-time)", fontsize=11)

    ax.set_title(
        f"Operation-level CPU breakdown — TLS 1.3 {cert_type.upper()} handshake\n"
        f"{label1} {s2n_mean:.0f}µs vs {label2} {r_mean:.0f}µs "
        f"(gap: {s2n_mean - r_mean:.0f}µs, {abs(s2n_mean - r_mean)/r_mean*100:.1f}%)",
        fontsize=12, fontweight='bold')
    ax.legend(loc='lower right', fontsize=10)

    # Add value labels on bars
    for bar in bars_s:
        w = bar.get_width()
        if w > 5:
            ax.text(w - 1, bar.get_y() + bar.get_height()/2, f'{w:.0f}',
                    ha='right', va='center', fontsize=8, color='white', fontweight='bold')
    for bar in bars_r:
        w = bar.get_width()
        if w > 5:
            ax.text(w - 1, bar.get_y() + bar.get_height()/2, f'{w:.0f}',
                    ha='right', va='center', fontsize=8, color='white', fontweight='bold')

    ax.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\n  ✓ wrote {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--mean", type=float, required=True, help="hot-loop mean handshake us")
    ap.add_argument("--label", default="impl")
    # Optional second implementation + chart (produces the comparison PNG).
    ap.add_argument("--report2", help="second implementation's report (for comparison chart)")
    ap.add_argument("--mean2", type=float, help="second implementation's mean us")
    ap.add_argument("--label2", default="rustls")
    ap.add_argument("--cert-type", default="rsa2048")
    ap.add_argument("--chart", help="path to write the comparison PNG")
    args = ap.parse_args()

    us1, other1 = report_counts(args.report, args.mean, args.label)
    us1["Framework overhead"] = other1

    if args.report2 and args.mean2:
        us2, other2 = report_counts(args.report2, args.mean2, args.label2)
        us2["Framework overhead"] = other2
        if args.chart:
            make_chart(us1, us2, args.cert_type, args.chart, s2n_mean=args.mean, r_mean=args.mean2,
                       label1=args.label, label2=args.label2)


if __name__ == "__main__":
    main()
