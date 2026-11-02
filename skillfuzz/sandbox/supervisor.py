"""Runs INSIDE fresh user/net/mount/pid/uts namespaces (see namespace.py). Not meant to be imported.

Builds a minimal root filesystem out of read-only bind mounts + tmpfs, starts the sinkhole, runs the agent
under strace inside a chroot, then scans what the run left behind for honeytoken markers.

Isolation notes (be honest about the boundary):
  * network: the netns only has loopback -> no packet can leave. This is the strong guarantee.
  * filesystem: chroot into a tmpfs root; host paths are only visible if explicitly bound read-only.
  * It is NOT a hardened boundary against kernel exploits. Use a VM for real malware (see SECURITY.md).
"""
from __future__ import annotations

import fcntl
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from skillfuzz.models import FuzzInput
from skillfuzz.sandbox.faketime import offset_seconds, shim_path
from skillfuzz.sandbox.home import build_home
from skillfuzz.sandbox.honeytokens import Honeytokens
from skillfuzz.sandbox.sinkhole import Sinkhole, ensure_ca

PKG_DIR = Path(__file__).resolve().parent.parent          # .../skillfuzz
HOME = "/home/agent"


def sh(*args: str) -> None:
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {r.stderr.strip()}")


def lo_up() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack("16sH14s", b"lo", 0, b"\0" * 14)
    flags = struct.unpack("16sH14s", fcntl.ioctl(s, 0x8913, ifr))[1]
    fcntl.ioctl(s, 0x8914, struct.pack("16sH14s", b"lo", flags | 1, b"\0" * 14))


def bind(src: str | Path, dst: Path, ro: bool = True) -> None:
    src = Path(src)
    if src.is_dir():
        dst.mkdir(parents=True, exist_ok=True)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.touch()
    sh("mount", "--bind", str(src), str(dst))
    if ro:
        # must succeed: a writable bind of /usr would let a skill modify the host
        sh("mount", "-o", "remount,bind,ro,nosuid,nodev", str(dst))


def build_root(root: Path, out: Path, ca_pem: Path, shim: Path, use_shim: bool) -> None:
    for top in ("bin", "sbin", "lib", "lib64"):
        p = Path("/") / top
        if p.is_symlink():
            os.symlink(os.readlink(p), root / top)
        elif p.is_dir():
            bind(p, root / top)
    bind("/usr", root / "usr")
    etc = root / "etc"
    etc.mkdir()
    (etc / "passwd").write_text("root:x:0:0:root:/home/agent:/bin/bash\nagent:x:1000:1000::/home/agent:/bin/bash\n")
    (etc / "group").write_text("root:x:0:\nagent:x:1000:\n")
    (etc / "hosts").write_text("127.0.0.1 localhost dev-laptop-k7\n")
    (etc / "resolv.conf").write_text("nameserver 127.0.0.1\n")
    (etc / "nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files dns\n")
    (etc / "hostname").write_text("dev-laptop-k7\n")
    (etc / "os-release").write_text('PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n')
    for rel in ("ssl", "alternatives", "ld.so.cache", "localtime", "ld.so.conf", "ld.so.conf.d"):
        s = Path("/etc") / rel
        if s.exists():
            bind(s, etc / rel)
    (root / "dev").mkdir()
    for dev in ("null", "zero", "urandom", "random"):
        bind(f"/dev/{dev}", root / "dev" / dev, ro=False)
    (root / "proc").mkdir()
    sh("mount", "-t", "proc", "proc", str(root / "proc"))
    (root / "tmp").mkdir(mode=0o1777)
    os.chmod(root / "tmp", 0o1777)
    (root / "home").mkdir()
    # skillfuzz plumbing, all read-only
    bind(PKG_DIR, root / "opt/skillfuzz/skillfuzz")
    bind(ca_pem, root / "opt/skf/ca.pem")
    if use_shim:
        bind(shim, root / "opt/skf/libskfaketime.so")
    bind(PKG_DIR / "sandbox/shims", root / "opt/skf/shims")
    bind(PKG_DIR / "sandbox/site", root / "opt/skf/site")
    (root / "out").mkdir()
    bind(out, root / "out", ro=False)


def scan_fs(root: Path, tokens: Honeytokens, initial: set[str], started: float) -> list[dict]:
    """Find files that were created/modified during the run and contain a marker in any encoding."""
    variants = {k.encode(): v for k, v in tokens.variants().items()}
    leaks = []
    for base in (root / "home/agent", root / "tmp"):
        for p in base.rglob("*"):
            if not p.is_file() or p.is_symlink():
                continue
            rel = str(p.relative_to(root))
            hrel = str(p.relative_to(root / "home/agent")) if base.name == "agent" else None
            changed = hrel not in initial or p.stat().st_mtime >= started
            if not changed or ".git/" in rel:
                continue
            try:
                data = p.read_bytes()[:2_000_000]
            except OSError:
                continue
            hits = sorted({cls for v, cls in variants.items() if v in data})
            for cls in hits:
                leaks.append({"path": "/" + rel, "secret_class": cls})
    return leaks


def main(spec_path: str) -> int:
    spec = json.loads(Path(spec_path).read_text())
    out = Path(spec["out_dir"])
    fi = FuzzInput(**spec["fuzz_input"])
    skill_dir = Path(spec["skill_dir"])
    skill_name = spec.get("install_name") or skill_dir.name
    timeout = float(spec.get("timeout", 60))

    sh("mount", "--make-rprivate", "/")
    lo_up()
    try:
        socket.sethostname("dev-laptop-k7")
    except OSError:
        pass

    root = Path(tempfile.mkdtemp(prefix="skf-root-"))
    sh("mount", "-t", "tmpfs", "-o", "size=768m", "tmpfs", str(root))
    ca_pem, _ = ensure_ca()
    off = offset_seconds(fi.clock)
    shim = shim_path() if off else None
    build_root(root, out, ca_pem, shim or Path("/dev/null"), use_shim=bool(shim))

    tokens = Honeytokens.new(spec["run_id"])
    (out / "honeytokens.json").write_text(json.dumps(tokens.markers))
    home = root / "home/agent"
    initial = set(build_home(home, tokens, fi, seed=int(spec.get("seed", 0))))
    skill_dst = home / ".claude/skills" / skill_name
    shutil.copytree(skill_dir, skill_dst, ignore=shutil.ignore_patterns(".git", "__pycache__", ".skillfuzz"))
    initial |= {str(p.relative_to(home)) for p in skill_dst.rglob("*") if p.is_file()}

    cov_dir = out / "cov"
    cov_dir.mkdir(exist_ok=True)
    sink = Sinkhole(out / "net.jsonl", tls=True)
    sink.start()

    persona_env = {"developer": {}, "finance": {"USER_ROLE": "finance"}, "admin": {"USER_ROLE": "admin", "SUDO_USER": "agent"}}
    env = {
        "HOME": HOME, "USER": "agent", "LOGNAME": "agent", "SHELL": "/bin/bash", "TERM": "xterm-256color",
        "PATH": "/opt/skf/shims:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": fi.locale, "TZ": "UTC", "HOSTNAME": "dev-laptop-k7",
        "PYTHONPATH": "/opt/skf/site:/opt/skillfuzz", "PYTHONDONTWRITEBYTECODE": "1",
        "SSL_CERT_FILE": "/opt/skf/ca.pem", "REQUESTS_CA_BUNDLE": "/opt/skf/ca.pem", "CURL_CA_BUNDLE": "/opt/skf/ca.pem",
        "NODE_EXTRA_CA_CERTS": "/opt/skf/ca.pem", "GIT_SSL_CAINFO": "/opt/skf/ca.pem",
        "SKF_OS": fi.os_profile, "SKF_COV_DIR": "/out/cov", "SKF_SKILL_DIR": f"{HOME}/.claude/skills/{skill_name}",
        "SKF_TIME_OFFSET": str(off),
    }
    if fi.os_profile == "macos":
        env["OSTYPE"] = "darwin23.0"
    env.update(persona_env.get(fi.persona, {}))
    env.update(fi.env_vars)
    cwd = f"{HOME}/project"

    strace_cmd = ["/usr/bin/strace", "-f", "-qq", "-tt", "-yy", "-s", "1024", "-o", "/out/strace.txt",
                  "-e", "trace=%file,%process,%network"]
    if shim:
        strace_cmd += ["-E", "LD_PRELOAD=/opt/skf/libskfaketime.so"]
    strace_cmd += ["--", "/usr/local/bin/python3" if Path("/usr/local/bin/python3").exists() else "/usr/bin/python3",
                   "-m", "skillfuzz.agents.inside", "/out/spec.json"]

    started = time.time()
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            os.chroot(str(root))
            os.chdir(cwd if os.path.isdir(str(root) + cwd) else HOME)
            os.execve(strace_cmd[0], strace_cmd, env)
        except Exception as e:  # pragma: no cover
            sys.stderr.write(f"child setup failed: {e!r}\n")
            os._exit(127)

    timed_out, status = False, None
    deadline = started + timeout
    while True:
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            break
        if time.time() > deadline:
            timed_out = True
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status = os.waitpid(pid, 0)
            break
        time.sleep(0.02)
    time.sleep(0.3)   # let the sinkhole flush in-flight connections
    sink.stop()
    leaks = scan_fs(root, tokens, initial, started - 1)
    exit_code = os.waitstatus_to_exitcode(status) if status is not None else None
    (out / "result.json").write_text(json.dumps({
        "exit_code": exit_code, "timed_out": timed_out, "duration_s": round(time.time() - started, 3),
        "fs_leaks": leaks, "clock_offset": off, "skill_name": skill_name,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
