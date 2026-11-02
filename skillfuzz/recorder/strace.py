"""Parse `strace -f -qq -tt -yy` output into raw syscall events with per-pid exe and cwd tracking."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

LINE = re.compile(r"^(\d+)\s+(\d\d):(\d\d):(\d\d\.\d+)\s+(.*)$")
CALL = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(?:<[^>]*>)?\s*(.*)$")
RESUMED = re.compile(r"^<\.\.\. (\w+) resumed>(.*)\)\s+=\s+(-?\d+|\?)(?:<[^>]*>)?\s*(.*)$")
QSTR = r'"((?:[^"\\]|\\.)*)"'
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
PATH_FIRST = {"stat", "lstat", "access", "readlink", "chdir", "unlink", "rmdir", "mkdir", "chmod", "creat", "truncate"}
PATH_AT = {"newfstatat", "faccessat", "faccessat2", "readlinkat", "unlinkat", "mkdirat", "fchmodat", "statx"}
STAT_CALLS = {"stat", "lstat", "access", "readlink", "newfstatat", "faccessat", "faccessat2", "readlinkat", "statx"}
MUTATE_CALLS = {"unlink", "rmdir", "mkdir", "chmod", "creat", "truncate", "unlinkat", "mkdirat", "fchmodat", "rename", "renameat", "renameat2"}


@dataclass
class RawEvent:
    kind: str                # open | stat | mutate | exec | connect | chdir
    pid: int
    ts: float
    actor: str
    path: str = ""
    write: bool = False
    listing: bool = False
    argv: list[str] = field(default_factory=list)
    ip: str = ""
    port: int = 0
    ok: bool = True


def _unescape(s: str) -> str:
    return s.encode().decode("unicode_escape", errors="replace") if "\\" in s else s


def _abs(path: str, cwd: str, dirfd_path: str | None = None) -> str:
    if path.startswith("/"):
        return path
    base = dirfd_path or cwd
    return (base.rstrip("/") + "/" + path).replace("/./", "/")


def parse(path: str, start_cwd: str = "/home/agent/project") -> list[RawEvent]:
    events: list[RawEvent] = []
    exe: dict[int, str] = {}
    cwd: dict[int, str] = {}
    pending: dict[int, tuple[str, str]] = {}
    root_pid: int | None = None
    root_exec_skipped = False
    try:
        lines = open(path, errors="replace").read().splitlines()
    except FileNotFoundError:
        return events
    for ln in lines:
        m = LINE.match(ln)
        if not m:
            continue
        pid = int(m.group(1))
        ts = int(m.group(2)) * 3600 + int(m.group(3)) * 60 + float(m.group(4))
        rest = m.group(5)
        if root_pid is None:
            root_pid = pid
            exe[pid] = "agent"
            cwd[pid] = start_cwd
        exe.setdefault(pid, "agent")
        cwd.setdefault(pid, start_cwd)
        if rest.startswith("<... "):
            r = RESUMED.match(rest)
            if not r or pid not in pending:
                continue
            name, prefix = pending.pop(pid)
            args, ret, tail = prefix + r.group(2), r.group(3), r.group(4)
        elif rest.endswith("<unfinished ...>"):
            name = rest.split("(", 1)[0]
            pending[pid] = (name, rest[len(name) + 1:-len(" <unfinished ...>")].rstrip())
            continue
        else:
            c = CALL.match(rest)
            if not c:
                continue
            name, args, ret, tail = c.group(1), c.group(2), c.group(3), c.group(4)
        retv = int(ret) if ret not in ("?",) else -1
        ok = retv >= 0
        actor = exe[pid]

        if name in ("clone", "clone3", "fork", "vfork") and ok and retv > 0:
            exe[retv], cwd[retv] = exe[pid], cwd[pid]
            continue
        if name == "chdir":
            q = re.match(QSTR, args)
            if q and ok:
                cwd[pid] = _abs(_unescape(q.group(1)), cwd[pid])
            continue
        if name == "execve":
            q = re.match(QSTR, args)
            if not q:
                continue
            binpath = _unescape(q.group(1))
            argv = re.findall(r'"((?:[^"\\]|\\.)*)"', args.split("], ")[0][len(q.group(0)):] if "[" in args else "")
            if ok:
                if pid == root_pid and not root_exec_skipped:
                    root_exec_skipped = True            # strace -> python driver; not a skill effect
                    exe[pid] = "agent"
                    continue
                events.append(RawEvent("exec", pid, ts, actor, binpath, argv=[_unescape(a) for a in argv]))
                exe[pid] = binpath.rsplit("/", 1)[-1]
            continue
        if name in ("openat", "open", "openat2"):
            if name == "open":
                q = re.match(QSTR + r",\s*([A-Z_|0-9x]+)", args)
                dirfd, p, flags = None, (q.group(1) if q else None), (q.group(2) if q else "")
            else:
                q = re.match(r"([^,]+),\s*" + QSTR + r"(?:\.\.\.)?,\s*([A-Z_|0-9x]+|\{[^}]*\})", args)
                if not q:
                    continue
                d = re.search(r"<([^>]+)>", q.group(1))
                dirfd, p, flags = (d.group(1) if d else None), q.group(2), q.group(3)
            if not p or not ok:
                continue
            full = _abs(_unescape(p), cwd[pid], dirfd)
            events.append(RawEvent("open", pid, ts, actor, full, write=any(f in flags for f in WRITE_FLAGS),
                                   listing="O_DIRECTORY" in flags))
            continue
        if name in STAT_CALLS or name in MUTATE_CALLS or name in PATH_AT:
            if name in ("rename", "renameat", "renameat2"):
                qs = re.findall(QSTR, args)
                for p in qs[:2]:
                    events.append(RawEvent("mutate", pid, ts, actor, _abs(_unescape(p), cwd[pid])))
                continue
            if name in PATH_AT or name.endswith("at"):
                q = re.match(r"([^,]+),\s*" + QSTR, args)
                if not q:
                    continue
                d = re.search(r"<([^>]+)>", q.group(1))
                p = _abs(_unescape(q.group(2)), cwd[pid], d.group(1) if d else None)
            else:
                q = re.match(QSTR, args)
                if not q:
                    continue
                p = _abs(_unescape(q.group(1)), cwd[pid])
            if ok or name in MUTATE_CALLS:
                events.append(RawEvent("stat" if name in STAT_CALLS else "mutate", pid, ts, actor, p, ok=ok))
            continue
        if name == "connect":
            ip = re.search(r'inet_addr\("([\d.]+)"\)', args)
            port = re.search(r"htons\((\d+)\)", args)
            if ip and port:
                events.append(RawEvent("connect", pid, ts, actor, ip=ip.group(1), port=int(port.group(1)),
                                       ok=ok or "EINPROGRESS" in tail))
            else:
                ip6 = re.search(r'inet_pton\(AF_INET6, "([^"]+)"', args)
                if ip6 and port:
                    events.append(RawEvent("connect", pid, ts, actor, ip=ip6.group(1), port=int(port.group(1)),
                                           ok=ok or "EINPROGRESS" in tail))
    return events
