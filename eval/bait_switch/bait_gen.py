"""Version pairs for update-diff evaluation. v1 is a benign base; v2 changes behaviour in a known way."""
from __future__ import annotations

import re
import shutil
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dormant"))
import dormant_gen as dormant  # noqa: E402

MARK = dormant.MARK
TELEMETRY = '''\
try:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request("https://telemetry.vendor-analytics.example/ping", data=b"used"), timeout=5)
except Exception:
    pass
'''
FEATURE = 'subprocess.run(["date", "-u"], capture_output=True)\n'


def _inject(skill: Path, code: str) -> None:
    for script in (skill / "scripts").glob("*.py"):
        src = script.read_text()
        if MARK in src:
            script.write_text(src.replace(MARK, textwrap.indent(code, "    ").lstrip()))


def _declare(skill: Path, key: str, item: str) -> None:
    m = skill / "skillfuzz.toml"
    text = m.read_text()
    if re.search(rf"^{key}\s*=", text, re.M):
        text = re.sub(rf"^({key}\s*=\s*\[)(.*?)(\])", lambda mm: f'{mm.group(1)}{mm.group(2)}{", " if mm.group(2).strip() else ""}"{item}"{mm.group(3)}', text, flags=re.M)
    else:
        text += f'{key} = ["{item}"]\n'
    m.write_text(text)


def make_pairs(base: Path, out_root: Path) -> list[dict]:
    """Returns dicts: kind, v1, v2, expected verdict."""
    out_root = Path(out_root)
    pairs = []

    def fresh(name: str) -> Path:
        d = out_root / f"{base.name}__{name}"
        if d.exists():
            shutil.rmtree(d)
        return d

    def v1_copy(name: str) -> Path:
        d = fresh(name + "__v1")
        shutil.copytree(base, d)
        return d

    # 1. telemetry added, undeclared: capability growth, but not malicious
    v1, v2 = v1_copy("telemetry"), fresh("telemetry__v2")
    shutil.copytree(base, v2)
    _inject(v2, TELEMETRY)
    pairs.append({"kind": "telemetry_undeclared", "v1": v1, "v2": v2, "expected": "undeclared_growth"})

    # 2. legitimate feature (new binary) with the manifest updated
    v1, v2 = v1_copy("feature_declared"), fresh("feature_declared__v2")
    shutil.copytree(base, v2)
    _inject(v2, FEATURE)
    _declare(v2, "exec", "date")
    pairs.append({"kind": "feature_declared", "v1": v1, "v2": v2, "expected": "ok"})

    # 3. same feature, author forgot to declare it: should be flagged (this is the false-positive cost of the design)
    v1, v2 = v1_copy("feature_undeclared"), fresh("feature_undeclared__v2")
    shutil.copytree(base, v2)
    _inject(v2, FEATURE)
    pairs.append({"kind": "feature_undeclared", "v1": v1, "v2": v2, "expected": "undeclared_growth"})

    # 4. malicious update: CI-gated credential exfil
    v1 = v1_copy("malicious")
    v2 = dormant.make_variant(base, "env_ci", out_root)
    final = fresh("malicious__v2")
    v2.rename(final)
    pairs.append({"kind": "malicious_update", "v1": v1, "v2": final, "expected": "malicious"})
    return pairs
