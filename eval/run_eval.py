#!/usr/bin/env python3
"""Evaluation harness (MVP scale).

  python eval/run_eval.py --bases git-changelog --max-runs 40 --out eval-out

Compares, on the same samples: fixed single-task detonation vs the coverage-guided fuzzer. Also checks benign
skills for false positives and bait-and-switch pairs for the right verdict.

Read the numbers for what they are: synthetic samples written by the same person who wrote the detector, run with a
deterministic offline agent. They show the mechanism works. They are NOT a detection rate on real malware.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "eval/dormant"), str(ROOT / "eval/bait_switch")]

import bait_gen  # noqa: E402
import dormant_gen  # noqa: E402

from skillfuzz.baselines.single_run import single_run  # noqa: E402
from skillfuzz.baselines.static_scanner import scan as static_scan  # noqa: E402
from skillfuzz.fingerprint.diff import diff  # noqa: E402
from skillfuzz.fingerprint.manifest import Manifest  # noqa: E402
from skillfuzz.fuzz.engine import FuzzConfig, Fuzzer  # noqa: E402
from skillfuzz.models import FuzzInput  # noqa: E402

BENIGN = ROOT / "eval/skills/benign"


def flagged(fp) -> bool:
    return bool(fp.tainted_flows) or fp.remote_instruction_fetch


def make_cfg(a) -> FuzzConfig:
    return FuzzConfig(max_runs=a.max_runs, plateau=a.plateau, seed=a.seed, static_sweep=not a.no_sweep,
                      use_static_dict=not a.no_static, guided=not a.unguided, script_coverage=not a.effect_only_coverage)


def eval_sample(skill: Path, out: Path, a, kind: str, trigger: str) -> dict:
    t0 = time.time()
    static_flagged = static_scan(skill).flagged
    sfp = single_run(skill, out / "single")
    r = Fuzzer(skill, out / "fuzz", make_cfg(a)).fuzz()
    fp = r.fingerprint
    tier = ("benign" if kind == "benign" else "needs_skill" if trigger in dormant_gen.NEEDS_SKILL else "generic")
    return {"sample": skill.name, "kind": kind, "trigger": trigger, "tier": tier,
            "static_flagged": static_flagged, "single_flagged": flagged(sfp), "fuzz_flagged": flagged(fp),
            "first_taint_run": r.first_taint_run or "", "runs": fp.runs, "coverage": fp.coverage,
            "sandbox_s": round(r.sandbox_seconds, 1), "wall_s": round(time.time() - t0, 1)}


def eval_pair(pair: dict, out: Path, a) -> dict:
    cfg = make_cfg(a)
    r1 = Fuzzer(pair["v1"], out / "v1", cfg).fuzz()
    replay = r1.corpus
    r2 = Fuzzer(pair["v2"], out / "v2", cfg).fuzz(initial_corpus=replay)
    rep = diff(r1.fingerprint, r2.fingerprint, Manifest.load(pair["v2"]))
    return {"pair": pair["v2"].name, "kind": pair["kind"], "expected": pair["expected"], "got": rep.verdict,
            "correct": rep.verdict == pair["expected"], "findings": "; ".join(f"{f.kind}:{f.item}" for f in rep.findings)[:140]}


def pct(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "n/a"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bases", nargs="+", default=["git-changelog"])
    ap.add_argument("--triggers", nargs="+", default=["all"])
    ap.add_argument("--max-runs", type=int, default=40)
    ap.add_argument("--plateau", type=int, default=12)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--out", default="eval-out")
    ap.add_argument("--skip-benign", action="store_true")
    ap.add_argument("--skip-bait", action="store_true")
    ap.add_argument("--no-sweep", action="store_true")
    ap.add_argument("--no-static", action="store_true")
    ap.add_argument("--unguided", action="store_true")
    ap.add_argument("--effect-only-coverage", action="store_true")
    a = ap.parse_args()

    out = Path(a.out).resolve()
    gen_root = out / "_generated"
    bases = [BENIGN / b for b in a.bases]
    triggers = dormant_gen.ALL_TRIGGERS if a.triggers == ["all"] else a.triggers
    jobs: list[tuple[Path, str, str]] = []
    for b in bases:
        for t in triggers:
            jobs.append((dormant_gen.make_variant(b, t, gen_root), "dormant", t))
    if not a.skip_benign:
        jobs += [(b, "benign", "-") for b in sorted(BENIGN.iterdir())]

    print(f"{len(jobs)} samples, max_runs={a.max_runs}, plateau={a.plateau}, jobs={a.jobs}", flush=True)
    rows = []
    with ThreadPoolExecutor(a.jobs) as ex:
        futs = [ex.submit(eval_sample, s, out / "samples" / s.name, a, k, t) for s, k, t in jobs]
        for f in futs:
            row = f.result()
            rows.append(row)
            print(f"  {row['sample']:38} static={'FLAG' if row['static_flagged'] else '----'} "
                  f"single={'FLAG' if row['single_flagged'] else '----'} "
                  f"fuzz={'FLAG' if row['fuzz_flagged'] else '----'} first_hit={row['first_taint_run'] or '-':>3} "
                  f"runs={row['runs']:>3} cov={row['coverage']:>3} {row['sandbox_s']}s", flush=True)

    out.mkdir(parents=True, exist_ok=True)
    with open(out / "eval_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    dorm = [r for r in rows if r["kind"] == "dormant"]
    ben = [r for r in rows if r["kind"] == "benign"]
    print("\n== Detection (flagged = honeytoken exfiltration or run-time instruction fetch) ==")
    print(f"{'tier':<14}{'static scan':>16}{'single-task':>16}{'skillfuzz':>16}")
    for tier in ("generic", "needs_skill"):
        sub = [r for r in dorm if r["tier"] == tier]
        print(f"{tier:<14}{pct(sum(r['static_flagged'] for r in sub), len(sub)):>16}"
              f"{pct(sum(r['single_flagged'] for r in sub), len(sub)):>16}{pct(sum(r['fuzz_flagged'] for r in sub), len(sub)):>16}")
    print(f"{'all dormant':<14}{pct(sum(r['static_flagged'] for r in dorm), len(dorm)):>16}"
          f"{pct(sum(r['single_flagged'] for r in dorm), len(dorm)):>16}{pct(sum(r['fuzz_flagged'] for r in dorm), len(dorm)):>16}")
    missed = [r["sample"] for r in dorm if not r["fuzz_flagged"]]
    print(f"fuzzer misses: {missed or 'none'}")
    hits = [int(r["first_taint_run"]) for r in dorm if r["first_taint_run"] != ""]
    if hits:
        hits.sort()
        print(f"runs-to-first-trigger (fuzzer): median={hits[len(hits) // 2]} max={hits[-1]}")
    if ben:
        print(f"false positives on benign skills: fuzz {sum(r['fuzz_flagged'] for r in ben)}/{len(ben)}, "
              f"single {sum(r['single_flagged'] for r in ben)}/{len(ben)}, "
              f"static {sum(r['static_flagged'] for r in ben)}/{len(ben)}  "
              f"(N={len(ben)} is far too small to state an FPR; this only checks for obvious breakage)")

    if not a.skip_bait:
        print("\n== Bait-and-switch (version diff, v2 corpus seeded from v1) ==")
        prow = []
        pairs = [p for b in bases for p in bait_gen.make_pairs(b, out / "_pairs")]
        with ThreadPoolExecutor(a.jobs) as ex:
            for r in [f.result() for f in [ex.submit(eval_pair, p, out / "pairs" / p["v2"].name, a) for p in pairs]]:
                prow.append(r)
                print(f"  {r['kind']:<22} expected={r['expected']:<18} got={r['got']:<18} {'OK' if r['correct'] else 'WRONG'}  {r['findings']}", flush=True)
        print(f"verdicts correct: {pct(sum(r['correct'] for r in prow), len(prow))}")
        (out / "bait_switch_results.json").write_text(json.dumps(prow, indent=1))
    print(f"\nresults: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
