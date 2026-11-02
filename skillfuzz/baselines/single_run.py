"""Fixed single-task detonation (our re-implementation of the SkillDetonate idea): one run, default environment."""
from __future__ import annotations

from pathlib import Path

from ..fingerprint.build import build_fingerprint
from ..fuzz import seeds as seedmod
from ..fuzz.engine import FuzzConfig, Fuzzer
from ..models import Fingerprint, FuzzInput


def single_run(skill_dir: str | Path, out_dir: str | Path, agent: dict | None = None, timeout: float = 60) -> Fingerprint:
    cfg = FuzzConfig(max_runs=1, agent=agent or {"name": "offline"}, timeout=timeout)
    fz = Fuzzer(skill_dir, out_dir, cfg)
    task = seedmod.offline_seeds(skill_dir)[0]
    tr = fz.run_input(FuzzInput(task=task))
    first = 1 if tr.tainted_flows else None
    fp = build_fingerprint(skill_dir, [tr], first, len(tr.coverage_set()), meta={"label": "single_run"})
    (Path(out_dir) / "fingerprint.json").write_text(fp.model_dump_json(indent=2))
    return fp
