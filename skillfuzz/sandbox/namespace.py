"""Host-side launcher for the namespace sandbox."""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

from ..models import FuzzInput

REPO_ROOT = Path(__file__).resolve().parents[2]


class SandboxError(RuntimeError):
    pass


def install_name(skill_dir: Path) -> str:
    """Skills are installed under their frontmatter `name` (what skill managers do), falling back to the folder."""
    md = skill_dir / "SKILL.md"
    if md.exists():
        m = re.search(r"^name:\s*['\"]?([\w.-]+)", md.read_text(errors="ignore")[:2000], re.M)
        if m:
            return m.group(1)
    return re.sub(r"[^\w.-]", "_", skill_dir.name)


class NamespaceSandbox:
    """Rootless user+net+mount+pid+uts namespaces. Network: loopback only, so there is no route off the box."""

    name = "namespace"

    @staticmethod
    def available() -> tuple[bool, str]:
        try:
            r = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "--mount", "--pid", "--fork",
                                "sh", "-c", "mount -t tmpfs tmpfs /mnt && echo ok"],
                               capture_output=True, text=True, timeout=15)
            if r.stdout.strip() != "ok":
                return False, (r.stderr or r.stdout).strip()[:200]
        except Exception as e:
            return False, repr(e)
        for tool in ("strace", "openssl", "gcc"):
            if subprocess.run(["which", tool], capture_output=True).returncode != 0:
                return False, f"missing tool: {tool}"
        return True, "ok"

    def run(self, skill_dir: str | Path, fi: FuzzInput, out_dir: str | Path, agent: dict | None = None,
            timeout: float = 60, run_id: str | None = None, seed: int = 0, extra_spec: dict | None = None,
            model_fn=None, max_model_calls: int = 30) -> dict:
        skill_dir, out_dir = Path(skill_dir).resolve(), Path(out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        run_id = (run_id or secrets.token_hex(4)).upper()[:8]
        spec = {"skill_dir": str(skill_dir), "out_dir": str(out_dir), "fuzz_input": fi.model_dump(),
                "agent": agent or {"name": "offline"}, "timeout": timeout, "install_name": install_name(skill_dir), "run_id": run_id, "seed": seed}
        spec.update(extra_spec or {})
        spec_path = out_dir / "spec.json"
        spec_path.write_text(json.dumps(spec))
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        cmd = ["unshare", "--user", "--map-root-user", "--net", "--mount", "--pid", "--uts", "--ipc", "--fork",
               sys.executable, "-m", "skillfuzz.sandbox.supervisor", str(spec_path)]
        bridge = None
        if spec["agent"].get("name") == "anthropic":
            from ..agents.bridge import ModelBridge, anthropic_complete
            try:
                fn = model_fn or anthropic_complete(spec["agent"].get("model", "claude-haiku-5-5"))
            except RuntimeError as e:
                raise SandboxError(str(e)) from e
            bridge = ModelBridge(fn, out_dir / "llm.sock", max_calls=max_model_calls)
            bridge.start()
        try:
            r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout + 60)
        finally:
            if bridge:
                bridge.stop()
        res_path = out_dir / "result.json"
        if r.returncode != 0 or not res_path.exists():
            raise SandboxError(f"supervisor failed (rc={r.returncode}): {(r.stderr or r.stdout)[-800:]}")
        res = json.loads(res_path.read_text())
        res["run_id"] = run_id
        if bridge:
            res["llm_usage"] = bridge.usage
        return res
