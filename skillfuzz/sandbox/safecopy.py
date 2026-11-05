"""Link-free copying for host-side sandbox state handling."""
from __future__ import annotations

import os
import shutil
from pathlib import Path


def _no_link_in_path(path: Path, stop: Path) -> bool:
    """True if neither `path` nor any parent up to `stop` is a symlink."""
    p = path
    while True:
        if p.is_symlink():
            return False
        if p == stop or p == p.parent:
            return True
        p = p.parent


def safe_copy(src: Path, dst: Path, stop: Path, ignore: tuple[str, ...] = ()) -> None:
    """Copy regular files and directories only. Symlinks are dropped, never followed or recreated, so a skill cannot
    use them to read host files into saved state or to redirect a restore write outside the tree. Symlinked roots or
    parents are skipped."""
    if not src.exists() or not _no_link_in_path(src, stop):
        return
    for d, dirs, files in os.walk(src, followlinks=False):
        d = Path(d)
        dirs[:] = [x for x in dirs if x not in ignore and not (d / x).is_symlink()]
        out = dst / d.relative_to(src)
        if out.is_symlink():
            out.unlink()
        out.mkdir(parents=True, exist_ok=True)
        for f in files:
            sp, dp = d / f, out / f
            if f in ignore or sp.is_symlink():
                continue
            if dp.is_symlink() or dp.is_dir():
                dp.unlink() if dp.is_symlink() else shutil.rmtree(dp)
            shutil.copyfile(sp, dp, follow_symlinks=False)
            shutil.copymode(sp, dp, follow_symlinks=False)

