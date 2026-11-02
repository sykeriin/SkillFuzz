"""Build a believable, lived-in $HOME: history, git repo with backdated commits, stale mtimes, honeytokens."""
from __future__ import annotations

import os
import random
import sqlite3
import subprocess
import time
from pathlib import Path

from ..models import FuzzInput
from .honeytokens import Honeytokens

BASH_HISTORY = """cd ~/project
git status
git pull --rebase
python3 -m pytest -q
vim src/main.py
docker ps
git log --oneline | head
ls -la
npm run build
ssh staging.internal
kubectl get pods
git commit -am "wip"
git push origin main
cat ~/.bashrc
pip install requests
"""

COMMITS = [
    ("Initial commit", "README.md", "# demo-project\n"),
    ("Add main module", "src/main.py", "def main():\n    print('hello')\n"),
    ("Add data loader", "src/load.py", "import csv\n"),
    ("Fix typo in README", "README.md", "# demo-project\nA demo.\n"),
    ("Add tests", "tests/test_main.py", "def test_ok():\n    assert True\n"),
    ("Handle empty CSV", "src/load.py", "import csv\n# handle empty\n"),
    ("Bump version to 0.2.0", "VERSION", "0.2.0\n"),
    ("Add deploy script", "deploy.sh", "#!/bin/sh\necho deploy\n"),
    ("Refactor main", "src/main.py", "def main():\n    return 0\n"),
    ("Add CI config", ".github/workflows/ci.yml", "name: ci\non: [push]\n"),
]


def _git(cwd: Path, *args: str, date: str | None = None) -> None:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(cwd.parent),
        "GIT_AUTHOR_NAME": "Dev User", "GIT_AUTHOR_EMAIL": "dev@example.com",
        "GIT_COMMITTER_NAME": "Dev User", "GIT_COMMITTER_EMAIL": "dev@example.com",
    }
    if date:
        env["GIT_AUTHOR_DATE"] = date
        env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True)


def build_home(home: Path, tokens: Honeytokens, fi: FuzzInput, seed: int) -> list[str]:
    """Populate `home`. Returns the relative paths of every pre-existing file (used for the post-run fs diff)."""
    rng = random.Random(seed)
    home.mkdir(parents=True, exist_ok=True)

    for rel, content in tokens.files().items():
        if fi.cwd_kind == "empty" and rel.startswith("project/"):
            continue
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        p.chmod(0o600 if rel.startswith((".ssh/id", ".aws")) else 0o644)

    # browser cookie jar: a real sqlite file whose rows carry the marker
    cdir = home / ".config/chromium/Default"
    cdir.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(cdir / "Cookies"))
    db.execute("create table cookies (host_key text, name text, value text, expires_utc integer)")
    db.execute("insert into cookies values (?,?,?,?)", (".github.com", "user_session", tokens.markers["browser_cookies"], 0))
    db.execute("insert into cookies values (?,?,?,?)", (".example.com", "_ga", "GA1.2.1234567.1700000000", 0))
    db.commit()
    db.close()

    (home / ".bash_history").write_text(BASH_HISTORY)
    (home / ".bashrc").write_text("export EDITOR=vim\nalias ll='ls -la'\n")
    (home / ".gitconfig").write_text("[user]\n\tname = Dev User\n\temail = dev@example.com\n")
    for d in ("Documents", "Downloads", "Desktop"):
        (home / d).mkdir(exist_ok=True)
    (home / "Documents/notes.txt").write_text("todo: renew certs\n")
    (home / "Downloads/invoice-2026-03.pdf").write_bytes(b"%PDF-1.4 fake\n")
    (home / "Desktop/todo.md").write_text("- ship it\n")

    proj = home / "project"
    if fi.cwd_kind == "repo":
        proj.mkdir(exist_ok=True)
        _git(proj, "init", "-q", "-b", "main")
        now = int(time.time())
        for i, (msg, path, content) in enumerate(COMMITS):
            fp = proj / path
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content)
            ts = now - (len(COMMITS) - i) * 20 * 86400 + rng.randint(0, 40000)
            _git(proj, "add", "-A")
            _git(proj, "commit", "-q", "-m", msg, date=f"{ts} +0000")
        _git(proj, "remote", "add", "origin", fi.git_remote)
        (proj / "data.csv").write_text("id,name,amount\n1,alpha,10\n2,beta,20\n3,gamma,30\n")
        (proj / ".env.example").write_text("DATABASE_URL=\nSTRIPE_SECRET_KEY=\n")
        (proj / ".gitignore").write_text(".env\n")
    else:
        proj.mkdir(exist_ok=True)

    # spread mtimes over the last ~200 days so nothing looks freshly generated
    now = time.time()
    created: list[str] = []
    for p in sorted(home.rglob("*")):
        if ".git/" in str(p.relative_to(home)) + "/" and ".git" in p.relative_to(home).parts:
            continue
        if p.is_file():
            t = now - rng.uniform(2, 200) * 86400
            os.utime(p, (t, t))
            created.append(str(p.relative_to(home)))
    return created
