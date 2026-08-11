#!/usr/bin/env python3
"""
Visualize handshake timing results.

IMPORTANT — methodology (see OPERATION_TIMING_METHODOLOGY.md and
comparison_methodology_decision.md):

  Per-message timings are NOT comparable across implementations. s2n-tls and
  rustls decompose the handshake state machine differently, so the same message
  name measures different work in each. Therefore:

  * Per-message charts (bar / stacked / timeline) are produced SEPARATELY per
    implementation — never overlaid — as WITHIN-implementation profiles only.
  * The cross-implementation comparison is OPERATION-LEVEL, derived from
    flamegraphs (see analyze_fg.py / OPERATION_LEVEL_RESULTS.md), not from
    per-message buckets.

Usage:
    python3 visualize.py results.json [--output-dir ./charts]

Output layout:
    charts/<cert_type>/<implementation>/per_message_*.png
                                        stacked_*.png
                                        timeline_*.png
    charts/<cert_type>/timeline_interactive_*.html   (combined, impl dropdown)
"""

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns


def load_data(json_path: str) -> dict:
    """Load and validate the JSON results file."""
    if not os.path.exists(json_path):
        print(f"ERROR: File not found: {json_path}", file=sys.stderr)
        sys.exit(1)
    try:
        with open(json_path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse {json_path}: {e}", file=sys.stderr)
        sys.exit(1)


def implementations(data: dict) -> list:
    """Distinct implementations present in the measurements."""
    return sorted({m["implementation"] for m in data.get("measurements", [])})


def measurements_for(data: dict, impl: str) -> list:
    """All measurement records for one implementation."""
    return [m for m in data["measurements"] if m["implementation"] == impl]


def make_bar_chart(data: dict, impl: str, output_dir: Path):
    """Per-implementation grouped bar chart: mean duration per message."""
    meta = data["metadata"]
    rows = measurements_for(data, impl)

    dur_map = defaultdict(list)
    for m in rows:
        dur_map[(m["message_name"], m["role"])].append(m["duration_ns"] / 1000.0)

    messages, roles, means = [], [], []
    for (msg, role), vals in dur_map.items():
        messages.append(msg)
        roles.append(role)
        means.append(np.mean(vals))

    df = pd.DataFrame({"Message": messages, "Role": roles, "Mean (µs)": means})
    if df.empty:
        return
    df["sort_key"] = df["Role"].map({"server": 0, "client": 1})
    df = df.sort_values(["sort_key", "Mean (µs)"], ascending=[True, False])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

    server_df = df[df["Role"] == "server"]
    if not server_df.empty:
        ax1.barh(
            server_df["Message"], server_df["Mean (µs)"],
            color=sns.color_palette("Blues_d", len(server_df)),
            edgecolor="black", linewidth=0.5,
        )
    ax1.set_xlabel("Duration (µs)")
    ax1.set_title(f"{impl} — server-side message processing\n{meta['cert_type']} / {meta['cpu_model']}")
    ax1.invert_yaxis()

    client_df = df[df["Role"] == "client"]
    if not client_df.empty:
        ax2.barh(
            client_df["Message"], client_df["Mean (µs)"],
            color=sns.color_palette("Oranges_d", len(client_df)),
            edgecolor="black", linewidth=0.5,
        )
    ax2.set_xlabel("Duration (µs)")
    ax2.set_title(f"{impl} — client-side message processing\n{meta['cert_type']} / {meta['cpu_model']}")
    ax2.invert_yaxis()

    fig.suptitle(
        f"WITHIN-implementation profile ({impl}) — not a cross-impl comparison",
        fontsize=9, style="italic", color="#888", y=1.02,
    )
    plt.tight_layout()
    out_path = output_dir / f"per_message_{meta['cert_type']}.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out_path}")


def make_stacked_chart(data: dict, impl: str, output_dir: Path):
    """Per-implementation stacked bar: cumulative contribution of each message."""
    meta = data["metadata"]
    rows = measurements_for(data, impl)

    dur_map = defaultdict(list)
    for m in rows:
        dur_map[(m["message_name"], m["role"])].append(m["duration_ns"] / 1000.0)
    means = {k: np.mean(v) for k, v in dur_map.items()}

    server_msgs, client_msgs = {}, {}
    for (msg, role), mean_us in means.items():
        (server_msgs if role == "server" else client_msgs)[msg] = mean_us

    if not server_msgs and not client_msgs:
        return

    fig, ax = plt.subplots(figsize=(12, 6))
    all_msgs = sorted(
        set(list(server_msgs) + list(client_msgs)),
        key=lambda m: server_msgs.get(m, 0), reverse=True,
    )
    colors = sns.color_palette("tab10", len(all_msgs))
    bottom_server = bottom_client = 0.0
    for i, msg in enumerate(all_msgs):
        sv = server_msgs.get(msg, 0)
        cl = client_msgs.get(msg, 0)
        ax.bar(0, sv, 0.5, bottom=bottom_server, label=msg, color=colors[i], edgecolor="white")
        ax.bar(1, cl, 0.5, bottom=bottom_client, color=colors[i], edgecolor="white")
        bottom_server += sv
        bottom_client += cl

    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Server", "Client"])
    ax.set_ylabel("Duration (µs)")
    ax.set_title(
        f"{impl} — cumulative per-message time (within-impl profile)\n"
        f"{meta['cert_type']} / {meta['measurement_iterations']} iterations"
    )
    ax.legend(loc="upper right", fontsize=8)

    plt.tight_layout()
    out_path = output_dir / f"stacked_{meta['cert_type']}.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out_path}")


def _ordered_segments(rows):
    """Chronological (name, role) order from iteration 0 plus mean durations."""
    iter0 = [m for m in rows if m["iteration"] == 0]
    durations = defaultdict(list)
    for m in rows:
        durations[(m["message_name"], m["role"])].append(m["duration_ns"])
    means = {k: np.mean(v) for k, v in durations.items()}

    seen, ordered = set(), []
    for m in iter0:
        key = (m["message_name"], m["role"])
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered, means, durations


def make_timeline_chart(data: dict, impl: str, output_dir: Path):
    """Timeline chart: plots each checkpoint at its absolute wall-clock position.

    Shows the true chronological interleaving of client and server checkpoints
    on a shared time axis (T=0 at the start of the handshake). Each checkpoint
    is a vertical marker at its wall_ns position, color-coded by role.
    """
    meta = data["metadata"]
    rows = measurements_for(data, impl)
    if not rows:
        return

    # Use MEAN wall_ns positions (averaged over all iterations) for consistency
    # with the END marker which is also a mean. Plotting a single iteration's
    # positions against a mean END line causes misalignment.
    iter0 = [m for m in rows if m.get("wall_ns", 0) > 0]
    if not iter0:
        return

    # Compute mean wall_ns per (message_name, role, direction).
    wall_map = defaultdict(list)
    for m in iter0:
        key = (m["message_name"], m["role"], m.get("direction", "read"))
        wall_map[key].append(m["wall_ns"])

    # Use iteration 0's order for the sequence.
    iter0_only = sorted(
        [m for m in rows if m["iteration"] == 0 and m.get("wall_ns", 0) > 0],
        key=lambda m: m["wall_ns"],
    )
    if not iter0_only:
        return

    # Compute mean wall positions and normalize to T=0 at handshake start.
    # handshake start = mean position of first checkpoint - its mean duration.
    first_key = (iter0_only[0]["message_name"], iter0_only[0]["role"],
                 iter0_only[0].get("direction", "read"))
    first_mean_wall = np.mean(wall_map[first_key])
    first_mean_dur = np.mean([m["duration_ns"] for m in rows
                              if (m["message_name"], m["role"], m.get("direction", "read")) == first_key])
    t0 = first_mean_wall - first_mean_dur

    # Build checkpoint list in iter 0's chronological order, using mean positions.
    seen = set()
    checkpoints = []
    for m in iter0_only:
        key = (m["message_name"], m["role"], m.get("direction", "read"))
        if key in seen:
            continue
        seen.add(key)
        mean_wall = np.mean(wall_map[key])
        t_us = (mean_wall - t0) / 1000.0
        short_role = "s" if m["role"] == "server" else "c"
        label = f"{m['message_name']}_{short_role}"
        checkpoints.append({
            "t_us": t_us,
            "label": label,
            "role": m["role"],
            "direction": m.get("direction", "read"),
            "duration_us": np.mean([x["duration_ns"] for x in rows
                                    if (x["message_name"], x["role"], x.get("direction", "read")) == key]) / 1000.0,
        })

    fig, ax = plt.subplots(figsize=(18, 4))
    server_color = sns.color_palette("Blues", 3)[1]
    client_color = sns.color_palette("Oranges", 3)[1]

    # Plot each checkpoint as a vertical line + label.
    # Alternate label heights within each role to prevent stacking.
    server_idx = 0
    client_idx = 0
    for i, cp in enumerate(checkpoints):
        color = server_color if cp["role"] == "server" else client_color
        ax.axvline(cp["t_us"], color=color, alpha=0.6, linewidth=1.5)
        # Label (rotated) — skip RECORD_READ/RECORD_WRITE for readability.
        if "RECORD" not in cp["label"]:
            if cp["role"] == "server":
                # Alternate between different heights to avoid overlap.
                offsets = [0.35, 0.6, 0.85]
                y_offset = offsets[server_idx % len(offsets)]
                server_idx += 1
            else:
                offsets = [-0.35, -0.6, -0.85]
                y_offset = offsets[client_idx % len(offsets)]
                client_idx += 1
            ax.text(cp["t_us"], y_offset, cp["label"],
                    rotation=45, ha="left", va="bottom" if y_offset > 0 else "top",
                    fontsize=6, color=color, fontweight="bold")

    ax.set_xlim(-5, checkpoints[-1]["t_us"] * 1.05)
    ax.set_ylim(-1.5, 1.5)
    ax.set_yticks([0.5, -0.5])
    ax.set_yticklabels(["server", "client"], fontsize=9)
    ax.set_xlabel("Time (µs from handshake start)")
    ax.set_title(
        f"{impl} handshake timeline — {meta['cert_type']} / {meta['cpu_model']}\n"
        f"Checkpoints at absolute wall-clock positions (blue=server, orange=client)",
        fontsize=11, fontweight="bold",
    )
    ax.axhline(0, color="gray", linewidth=0.3)

    # End-of-handshake marker (black vertical line at the mean handshake time).
    mean_key = "s2n_mean_us" if impl == "s2n-tls" else "rustls_mean_us"
    end_us = meta.get(mean_key, 0)
    if end_us > 0:
        ax.axvline(end_us, color="black", linewidth=2, linestyle="--")
        ax.text(end_us, 0.8, f"END\n{end_us:.0f}µs", ha="center", va="bottom",
                fontsize=8, fontweight="bold")

    plt.tight_layout()
    out_path = output_dir / f"timeline_{meta['cert_type']}.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ {out_path}")


def _build_checkpoints(data: dict, impl: str):
    """Build the checkpoint list (mean wall positions + duration samples)
    for one implementation. Returns (checkpoints, end_us) or (None, 0)."""
    meta = data["metadata"]
    rows = measurements_for(data, impl)
    if not rows:
        return None, 0

    # Get iteration 0 for ordering; use mean wall_ns for positions.
    iter0 = sorted(
        [m for m in rows if m["iteration"] == 0 and m.get("wall_ns", 0) > 0],
        key=lambda m: m["wall_ns"],
    )
    if not iter0:
        return None, 0

    # Mean wall positions and durations per checkpoint key.
    wall_map = defaultdict(list)
    dur_map = defaultdict(list)
    for m in rows:
        if m.get("wall_ns", 0) > 0:
            key = (m["message_name"], m["role"], m.get("direction", "read"))
            wall_map[key].append(m["wall_ns"])
            dur_map[key].append(m["duration_ns"] / 1000.0)

    first_key = (iter0[0]["message_name"], iter0[0]["role"],
                 iter0[0].get("direction", "read"))
    first_mean_wall = np.mean(wall_map[first_key])
    first_mean_dur = np.mean(dur_map[first_key]) * 1000  # back to ns
    t0 = first_mean_wall - first_mean_dur

    # Build checkpoints in iter 0's order, using mean positions.
    seen = set()
    checkpoints = []
    for m in iter0:
        key = (m["message_name"], m["role"], m.get("direction", "read"))
        if key in seen:
            continue
        seen.add(key)
        if "RECORD" in m["message_name"]:
            continue
        mean_wall = np.mean(wall_map[key])
        t_us = (mean_wall - t0) / 1000.0
        short_role = "s" if m["role"] == "server" else "c"
        label = f"{m['message_name']}_{short_role}"
        checkpoints.append({
            "t_us": round(t_us, 2),
            "label": label,
            "role": m["role"],
            "direction": m.get("direction", "read"),
            "duration_us": round(np.mean(dur_map[key]), 2),
            "values": [round(v, 3) for v in dur_map.get(key, [])],
        })

    # End-of-handshake time from metadata.
    mean_key = "s2n_mean_us" if impl == "s2n-tls" else "rustls_mean_us"
    end_us = meta.get(mean_key, checkpoints[-1]["t_us"] if checkpoints else 0)
    return checkpoints, end_us


def make_interactive_timeline(data: dict, output_dir: Path):
    """Combined interactive HTML timeline for ALL implementations, with a
    dropdown to flip between them. Click a checkpoint to see its duration
    distribution across iterations."""
    import json as _json

    meta = data["metadata"]
    impls = implementations(data)

    impl_data = {}
    for impl in impls:
        checkpoints, end_us = _build_checkpoints(data, impl)
        if checkpoints:
            impl_data[impl] = {"checkpoints": checkpoints, "end_us": round(end_us, 1)}

    if not impl_data:
        return

    cert_type = meta["cert_type"]
    cpu_model = meta["cpu_model"]
    data_json = _json.dumps(impl_data)
    default_impl = next(iter(impl_data))

    impl_options = "\n".join(
        f'        <option value="{impl}">{impl}</option>' for impl in impl_data
    )
    if len(impl_data) > 1:
        impl_options += (
            '\n        <option value="__both__">'
            "both — overlay (not recommended)</option>"
        )

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Handshake Timeline — {cert_type}</title>
    <script src="https://cdn.plot.ly/plotly-2.35.0.min.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background: #fafafa; }}
        h2 {{ margin-bottom: 4px; }}
        .subtitle {{ color: #666; font-size: 14px; margin-bottom: 16px; }}
        .toolbar {{ margin-bottom: 12px; }}
        .toolbar label {{ font-size: 14px; font-weight: 600; margin-right: 8px; }}
        .toolbar select {{ font-size: 14px; padding: 4px 8px; }}
        #timeline {{ width: 100%; height: 300px; cursor: pointer; }}
        #histogram {{ width: 100%; height: 300px; }}
        .hint {{ color: #888; font-size: 12px; margin-top: 4px; }}
    </style>
</head>
<body>
    <h2 id="title">Handshake Timeline — {cert_type}</h2>
    <div class="subtitle">{cpu_model} &nbsp;|&nbsp; Checkpoints at wall-clock positions &nbsp;|&nbsp; Click a point to see its duration distribution</div>
    <div class="toolbar">
        <label for="implSelect">Implementation:</label>
        <select id="implSelect">
{impl_options}
        </select>
    </div>
    <div id="overlay-warning" style="display:none; background:#fff3cd; border:1px solid #ffc107; color:#856404; padding:8px 12px; border-radius:4px; font-size:13px; margin-bottom:8px;">
        Overlay view: message names do NOT measure the same work in each implementation
        (different state-machine decompositions). Use for visual timing context only.
        Don't try to compare individual checkpoint durations across implementations.
        The operation-level comparison chart is the valid cross-impl view.
    </div>
    <div id="timeline"></div>
    <div class="hint">Blue = server, Orange = client. X-axis = time from handshake start (µs). Per-message timings are intended as within-implementation profiles. Not comparable across implementations.</div>
    <div id="histogram"></div>

    <script>
    const implData = {data_json};
    const serverColor = 'rgb(70, 130, 180)';
    const clientColor = 'rgb(230, 140, 60)';
    // Per-impl role colors for overlay mode (impl 0 = solid, impl 1 = lighter).
    const overlayColors = [
        {{ server: 'rgb(70, 130, 180)', client: 'rgb(230, 140, 60)' }},
        {{ server: 'rgb(60, 179, 113)', client: 'rgb(186, 85, 211)' }},
    ];

    // Flat per-trace point lists so the click handler can resolve any
    // curveNumber back to (checkpoint, impl) in both modes.
    let tracePoints = [];

    function render(sel) {{
        if (sel === '__both__') {{ renderOverlay(); return; }}
        document.getElementById('overlay-warning').style.display = 'none';
        const checkpoints = implData[sel].checkpoints;
        const endUs = implData[sel].end_us;
        document.getElementById('title').textContent = sel + ' Handshake Timeline — {cert_type}';

        // Split by role for the scatter plot.
        const serverPts = checkpoints.filter(c => c.role === 'server');
        const clientPts = checkpoints.filter(c => c.role === 'client');
        tracePoints = [
            {{ impl: sel, pts: serverPts }},
            {{ impl: sel, pts: clientPts }},
        ];

        const serverTrace = {{
            x: serverPts.map(c => c.t_us),
            y: serverPts.map(() => 0),
            text: serverPts.map(c => c.label + '<br>dur: ' + c.duration_us + ' µs'),
            mode: 'markers',
            type: 'scatter',
            name: 'server',
            marker: {{ color: serverColor, size: 12, symbol: 'diamond' }},
            hovertemplate: '%{{text}}<br>T=%{{x:.1f}} µs<extra></extra>',
        }};
        const clientTrace = {{
            x: clientPts.map(c => c.t_us),
            y: clientPts.map(() => 0),
            text: clientPts.map(c => c.label + '<br>dur: ' + c.duration_us + ' µs'),
            mode: 'markers',
            type: 'scatter',
            name: 'client',
            marker: {{ color: clientColor, size: 12, symbol: 'circle' }},
            hovertemplate: '%{{text}}<br>T=%{{x:.1f}} µs<extra></extra>',
        }};

        const layout = {{
            xaxis: {{ title: 'Time from handshake start (µs)' }},
            yaxis: {{ showticklabels: false, range: [-2, 2], zeroline: false }},
            margin: {{ t: 20, b: 50, l: 30, r: 20 }},
            height: 280,
            showlegend: true,
            shapes: [{{
                type: 'line', x0: endUs, x1: endUs, y0: -4, y1: 4,
                line: {{ color: 'black', width: 2, dash: 'dash' }}
            }}],
            annotations: [{{
                x: endUs, y: 3.5, text: 'END<br>' + Math.round(endUs) + 'µs',
                showarrow: false, font: {{ size: 10, color: 'black' }}
            }}],
        }};

        Plotly.react('timeline', [serverTrace, clientTrace], layout, {{responsive: true}});

        // Show largest checkpoint's distribution by default.
        let largest = checkpoints[0];
        checkpoints.forEach(c => {{ if (c.duration_us > largest.duration_us) largest = c; }});
        showHistogram(largest, sel);
    }}

    function renderOverlay() {{
        document.getElementById('overlay-warning').style.display = 'block';
        document.getElementById('title').textContent = 'Handshake Timeline (overlay) — {cert_type}';

        const impls = Object.keys(implData);
        const traces = [];
        const shapes = [];
        const annotations = [];
        tracePoints = [];

        impls.forEach((impl, i) => {{
            // Each impl gets its own horizontal lane so points don't collide.
            const lane = impls.length > 1 ? (i === 0 ? 0.7 : -0.7) : 0;
            const colors = overlayColors[i % overlayColors.length];
            const checkpoints = implData[impl].checkpoints;
            const endUs = implData[impl].end_us;

            ['server', 'client'].forEach(role => {{
                const pts = checkpoints.filter(c => c.role === role);
                tracePoints.push({{ impl: impl, pts: pts }});
                traces.push({{
                    x: pts.map(c => c.t_us),
                    y: pts.map(() => lane),
                    text: pts.map(c => impl + ' / ' + c.label + '<br>dur: ' + c.duration_us + ' µs'),
                    mode: 'markers',
                    type: 'scatter',
                    name: impl + ' ' + role,
                    marker: {{
                        color: colors[role], size: 11,
                        symbol: role === 'server' ? 'diamond' : 'circle',
                    }},
                    hovertemplate: '%{{text}}<br>T=%{{x:.1f}} µs<extra></extra>',
                }});
            }});

            shapes.push({{
                type: 'line', x0: endUs, x1: endUs, y0: lane - 0.5, y1: lane + 0.5,
                line: {{ color: colors.server, width: 2, dash: 'dash' }}
            }});
            annotations.push({{
                x: endUs, y: lane + 0.65,
                text: impl + ' END<br>' + Math.round(endUs) + 'µs',
                showarrow: false, font: {{ size: 9, color: colors.server }}
            }});
            annotations.push({{
                x: 0, y: lane + 0.45, xanchor: 'left',
                text: '<b>' + impl + '</b>',
                showarrow: false, font: {{ size: 11, color: colors.server }}
            }});
        }});

        const layout = {{
            xaxis: {{ title: 'Time from handshake start (µs)' }},
            yaxis: {{ showticklabels: false, range: [-2, 2], zeroline: false }},
            margin: {{ t: 20, b: 50, l: 30, r: 20 }},
            height: 280,
            showlegend: true,
            shapes: shapes,
            annotations: annotations,
        }};

        Plotly.react('timeline', traces, layout, {{responsive: true}});
        Plotly.react('histogram', [], {{ height: 280,
            annotations: [{{ text: 'Click a checkpoint above to see its duration distribution',
                             showarrow: false, font: {{ size: 13, color: '#888' }} }}] }});
    }}

    function showHistogram(cp, impl) {{
        const color = cp.role === 'server' ? serverColor : clientColor;
        const trace = {{
            x: cp.values,
            type: 'histogram',
            marker: {{ color: color, opacity: 0.8 }},
        }};
        const layout = {{
            title: {{ text: impl + ' / ' + cp.label + ' — duration distribution (' + cp.values.length + ' samples)', font: {{ size: 14 }} }},
            xaxis: {{ title: 'Duration (µs)' }},
            yaxis: {{ title: 'Count' }},
            margin: {{ t: 50, b: 50, l: 60, r: 20 }},
            height: 280,
        }};
        Plotly.react('histogram', [trace], layout, {{responsive: true}});
    }}

    const select = document.getElementById('implSelect');
    select.addEventListener('change', () => render(select.value));

    render('{default_impl}');

    // Click handler — show duration distribution for clicked checkpoint.
    // (Attached after the first render, once the div is a plotly plot.)
    // tracePoints[curveNumber] maps back to (impl, checkpoint) in both modes.
    document.getElementById('timeline').on('plotly_click', function(eventData) {{
        const pt = eventData.points[0];
        const entry = tracePoints[pt.curveNumber];
        if (!entry) return;
        showHistogram(entry.pts[pt.pointIndex], entry.impl);
    }});
    </script>
</body>
</html>"""

    out_path = output_dir / f"timeline_interactive_{meta['cert_type']}.html"
    out_path.write_text(html)
    print(f"  ✓ {out_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: visualize.py <results.json> [--output-dir <dir>]", file=sys.stderr)
        sys.exit(1)

    json_path = sys.argv[1]
    output_dir = Path("./charts")
    for i, arg in enumerate(sys.argv):
        if arg == "--output-dir" and i + 1 < len(sys.argv):
            output_dir = Path(sys.argv[i + 1])

    print(f"Reading: {json_path}")
    data = load_data(json_path)

    cert_type = data.get("metadata", {}).get("cert_type", "unknown")
    impls = implementations(data)
    if not impls:
        print("ERROR: no measurements found in JSON", file=sys.stderr)
        sys.exit(1)

    print(f"Implementations: {', '.join(impls)}")
    print("NOTE: per-message charts are WITHIN-implementation profiles only.")
    print("      Cross-implementation comparison is operation-level (see analyze_fg.py).")

    # One subfolder per implementation: charts/<cert>/<impl>/
    for impl in impls:
        impl_dir = output_dir / cert_type / impl
        impl_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n[{impl}] -> {impl_dir}/")
        make_bar_chart(data, impl, impl_dir)
        make_stacked_chart(data, impl, impl_dir)
        make_timeline_chart(data, impl, impl_dir)

    # Single combined interactive timeline (dropdown per implementation)
    # at the cert level: charts/<cert>/timeline_interactive_<cert>.html
    cert_dir = output_dir / cert_type
    cert_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n[combined] -> {cert_dir}/")
    make_interactive_timeline(data, cert_dir)

    print("\nDone.")


if __name__ == "__main__":
    main()
