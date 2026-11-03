#!/usr/bin/env python3
"""Ablation harness: does coverage guidance actually help, across seeds?

  python eval/ablate.py --bases git-changelog csv-summary --triggers env_stage date_window git_remote_corp nl_keyword_invoice nth_invocation --seeds 0 1 2

Runs each (sample, config, seed) once and reports, per config: detection rate and mean/median runs-to-trigger with
spread across seeds. Configs: full (static dict + sweep + guided + script coverage), no_static, no_sweep, unguided,
effect_only. This replaces the MVP's one-off, by-hand ablation (n=12, no seeds) with a repeatable, seeded one.
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "eval/dormant")]

import dormant_gen  # noqa: E402

from skillfuzz.fuzz.engine import FuzzConfig, Fuzzer  # noqa: E402
from skillfuzz.models import FuzzInput  # noqa: E402

BENIGN = ROOT / "eval/skills/benign"

CONFIGS = {
    "full": {},
    "no_static": {"use_static_dict": False, "static_sweep": False},
    "no_sweep": {"static_sweep": False},
    "unguided": {"guided": False},
    "effect_only": {"script_coverage": False},
}


def run_one(skill: Path, cfg_name: str, seed: int, max_runs: int, plateau: int, out: Path) -> dict:
    t0 = time.time()
    cfg = FuzzConfig(max_runs=max_runs, plateau=plateau, seed=seed, **CONFIGS[cfg_name])
    r = Fuzzer(skill, out, cfg).fuzz()
    fp = r.fingerprint
    detected = bool(fp.tainted_flows) or fp.remote_instruction_fetch
    return {"sample": skill.name, "config": cfg_name, "seed": seed, "detected": detected,
            "first_taint_run": r.first_taint_run or "", "runs": fp.runs, "coverage": fp.coverage,
            "wall_s": round(time.time() - t0, 1)}


def pct(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "n/a"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bases", nargs="+", default=["git-changelog"])
    ap.add_argument("--triggers", nargs="+", default=["env_stage", "date_window", "git_remote_corp", "nl_keyword_invoice"])
    ap.add_argument("--configs", nargs="+", default=list(CONFIGS), choices=list(CONFIGS))
    ap.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2])
    ap.add_argument("--max-runs", type=int, default=50)
    ap.add_argument("--plateau", type=int, default=15)
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--out", default="ablate-out")
    a = ap.parse_args()

    out = Path(a.out).resolve()
    gen_root = out / "_generated"
    samples = [dormant_gen.make_variant(BENIGN / b, t, gen_root) for b in a.bases for t in a.triggers]
    jobs = [(s, c, seed) for s in samples for c in a.configs for seed in a.seeds]
    print(f"{len(jobs)} runs: {len(samples)} samples x {len(a.configs)} configs x {len(a.seeds)} seeds", flush=True)

    rows = []
    with ThreadPoolExecutor(a.jobs) as ex:
        futs = [ex.submit(run_one, s, c, seed, a.max_runs, a.plateau, out / "runs" / f"{s.name}_{c}_{seed}")
                for s, c, seed in jobs]
        for f in futs:
            row = f.result()
            rows.append(row)
            print(f"  {row['sample']:34} {row['config']:12} seed={row['seed']} "
                  f"{'FLAG' if row['detected'] else '----'} first_hit={row['first_taint_run'] or '-':>3} "
                  f"runs={row['runs']:>3} {row['wall_s']}s", flush=True)

    out.mkdir(parents=True, exist_ok=True)
    with open(out / "ablation_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print("\n== Ablation summary (mean/median over seeds, per config) ==")
    print(f"{'config':<14}{'detected':>14}{'mean hit':>10}{'median hit':>12}{'spread':>10}")
    for c in a.configs:
        sub = [r for r in rows if r["config"] == c]
        hits = [int(r["first_taint_run"]) for r in sub if r["first_taint_run"] != ""]
        mean = f"{statistics.mean(hits):.1f}" if hits else "-"
        med = f"{statistics.median(hits):.1f}" if hits else "-"
        spread = f"{min(hits)}-{max(hits)}" if hits else "-"
        print(f"{c:<14}{pct(sum(r['detected'] for r in sub), len(sub)):>14}{mean:>10}{med:>12}{spread:>10}")
    print(f"\nresults: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
