#!/usr/bin/env python3
"""Plot pods -> analysis time (log-log) from results.csv.

usage: plot.py results.csv scaling.png
"""
import csv
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

src, dst = sys.argv[1], sys.argv[2]
rows = [r for r in csv.DictReader(open(src))]
pods = [int(r["pods"]) for r in rows]
wall = [float(r["wall_median_s"]) * 1000 for r in rows]
wmin = [float(r["wall_min_s"]) * 1000 for r in rows]
wmax = [float(r["wall_max_s"]) * 1000 for r in rows]
load = [float(r["load_ms"]) for r in rows]
det = [max(float(r["detect_ms"]), 1e-3) for r in rows]

INK, MUTED, GRID = "#1f2328", "#6e7781", "#e6e8eb"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"  # categorical slots 1-3

fig, ax = plt.subplots(figsize=(8, 5.2), dpi=150)
fig.patch.set_facecolor("white")
ax.set_xscale("log")
ax.set_yscale("log")

# Reference slopes through the detector curve's last point.
xs = [pods[0], pods[-1]]
for k, label in ((1, "O(N)"), (2, "O(N²)")):
    y1 = det[-1]
    ys = [y1 * (x / pods[-1]) ** k for x in xs]
    ax.plot(xs, ys, color=MUTED, lw=1, ls=(0, (4, 3)), zorder=1)
    ax.text(xs[0] * 1.15, ys[0], label, color=MUTED, fontsize=8, va="bottom")

err = [[w - lo for w, lo in zip(wall, wmin)], [hi - w for w, hi in zip(wall, wmax)]]
series = [
    (wall, BLUE, "o", "failopen audit, end to end (median, min–max)"),
    (load, ORANGE, "s", "JSON load (in-process)"),
    (det, AQUA, "^", "detectors: detector.Run (in-process)"),
]
for ys, c, m, label in series:
    ax.plot(pods, ys, color=c, lw=2, marker=m, ms=7, mec="white", mew=1.5, label=label, zorder=3)
ax.errorbar(pods, wall, yerr=err, fmt="none", ecolor=BLUE, elinewidth=1, capsize=3, zorder=2)

for x, y in zip(pods, wall):
    txt = f"{y/1000:.2f} s" if y >= 1000 else f"{y:.0f} ms"
    ax.annotate(txt, (x, y), textcoords="offset points", xytext=(0, 9), ha="center", fontsize=8, color=INK)
def fmt(y):
    return f"{y:.2g} ms" if y < 1 else f"{y:.0f} ms"


for x, y in zip(pods, det):
    ax.annotate(fmt(y), (x, y), textcoords="offset points", xytext=(10, -4), ha="left", fontsize=8, color=MUTED)

ax.set_xlabel("pods in snapshot (services ≈ N/5, policies ≈ N/10, nodes ≈ N/30)", color=INK)
ax.set_ylabel("time (ms, log scale)", color=INK)
ax.set_title("failopen audit --snapshot: analysis time vs cluster size", color=INK, loc="left", fontsize=11)
ax.set_xlim(pods[0] / 1.6, pods[-1] * 1.6)
ax.set_xticks(pods, [f"{p:,}" for p in pods])
ax.minorticks_off()
ax.grid(True, which="major", color=GRID, lw=0.8)
ax.set_axisbelow(True)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
for s in ("left", "bottom"):
    ax.spines[s].set_color(MUTED)
ax.tick_params(colors=MUTED)
ax.legend(frameon=False, fontsize=8, loc="upper left", labelcolor=INK)
fig.tight_layout()
fig.savefig(dst)
print("wrote", dst)
