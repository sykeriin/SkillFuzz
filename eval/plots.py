#!/usr/bin/env python3
"""Plots from a skillfuzz fuzz run's coverage_curve.csv, or from eval/run_eval.py's eval_results.csv.

  python eval/plots.py curve path/to/coverage_curve.csv -o curve.png
  python eval/plots.py ttt eval-out/eval_results.csv -o ttt_cdf.png        # time-to-trigger CDF

Optional (pip install -e '.[plots]'). Kept separate from the main tool so matplotlib is never a hard dependency.
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


def _require_matplotlib():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        return plt
    except ImportError:
        print("pip install -e '.[plots]' (needs matplotlib)", file=sys.stderr)
        sys.exit(1)


def plot_curve(csv_path: str, out: str) -> None:
    plt = _require_matplotlib()
    rows = list(csv.DictReader(open(csv_path)))
    xs = [int(r["run"]) for r in rows]
    ys = [int(r["total_coverage"]) for r in rows]
    taint_x = [int(r["run"]) for r in rows if r["tainted"] == "1"]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(xs, ys, marker=".", linewidth=1)
    for tx in taint_x:
        ax.axvline(tx, color="red", alpha=0.3, linewidth=1)
    if taint_x:
        ax.scatter([taint_x[0]], [ys[xs.index(taint_x[0])]], color="red", zorder=5, label="first taint")
        ax.legend()
    ax.set_xlabel("fuzz run")
    ax.set_ylabel("cumulative coverage (effect triples + script arcs)")
    ax.set_title("Coverage vs. runs")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    print(f"wrote {out}")


def plot_ttt_cdf(csv_path: str, out: str) -> None:
    plt = _require_matplotlib()
    rows = list(csv.DictReader(open(csv_path)))
    hits = sorted(int(r["first_taint_run"]) for r in rows if r.get("kind") == "dormant" and r["first_taint_run"] != "")
    if not hits:
        print("no taint hits in this results file", file=sys.stderr)
        sys.exit(1)
    n = len(hits)
    ys = [(i + 1) / n for i in range(n)]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.step(hits, ys, where="post")
    ax.set_xlabel("fuzz runs until first trigger")
    ax.set_ylabel("fraction of dormant samples triggered")
    ax.set_title(f"Time-to-trigger CDF (n={n})")
    ax.set_ylim(0, 1.05)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    print(f"wrote {out}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["curve", "ttt"])
    ap.add_argument("csv_path")
    ap.add_argument("-o", "--out", default=None)
    a = ap.parse_args()
    out = a.out or (a.kind + ".png")
    if a.kind == "curve":
        plot_curve(a.csv_path, out)
    else:
        plot_ttt_cdf(a.csv_path, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
