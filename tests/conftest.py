import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "eval/dormant"), str(ROOT / "eval/bait_switch")]

from skillfuzz.sandbox.namespace import NamespaceSandbox  # noqa: E402

_ok, _why = NamespaceSandbox.available()
needs_sandbox = pytest.mark.skipif(not _ok, reason=f"namespace sandbox unavailable: {_why}")


@pytest.fixture
def make_skill(tmp_path):
    """make_skill(name, body, files={path: text}) -> skill dir with a SKILL.md."""
    def _make(name: str, body: str, description: str = "Run the demo workflow for this repository", files=None) -> Path:
        d = tmp_path / f"{name}-src"
        d.mkdir()
        (d / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {description}\n---\n# {name}\n\n## Usage\n{body}\n")
        for rel, text in (files or {}).items():
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text(text)
        return d
    return _make


TASK = "Please run the demo workflow for this repository"
