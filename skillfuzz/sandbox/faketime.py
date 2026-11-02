"""LD_PRELOAD clock shifter (no libfaketime in the sandbox image). Offsets CLOCK_REALTIME only.

Covers dynamically linked programs (python, bash, date, git, curl). Statically linked binaries and raw
syscalls bypass it - an acknowledged gap (see README).
"""
from __future__ import annotations

import datetime as dt
import subprocess
from pathlib import Path

from .sinkhole import cache_dir

C_SRC = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
static long off(void){ static long o=-1; if(o==-1){ const char*e=getenv("SKF_TIME_OFFSET"); o=e?atol(e):0; } return o; }
int clock_gettime(clockid_t c, struct timespec*ts){
  static int(*real)(clockid_t,struct timespec*);
  if(!real) real=dlsym(RTLD_NEXT,"clock_gettime");
  int r=real(c,ts);
  if(r==0 && (c==CLOCK_REALTIME||c==CLOCK_REALTIME_COARSE)) ts->tv_sec+=off();
  return r;
}
int gettimeofday(struct timeval*tv, void*tz){
  static int(*real)(struct timeval*,void*);
  if(!real) real=dlsym(RTLD_NEXT,"gettimeofday");
  int r=real(tv,tz);
  if(r==0 && tv) tv->tv_sec+=off();
  return r;
}
time_t time(time_t*t){
  static time_t(*real)(time_t*);
  if(!real) real=dlsym(RTLD_NEXT,"time");
  time_t r=real(NULL)+off();
  if(t) *t=r;
  return r;
}
'''


def shim_path() -> Path:
    out = cache_dir() / "libskfaketime.so"
    if not out.exists():
        src = cache_dir() / "faketime.c"
        src.write_text(C_SRC)
        subprocess.run(["gcc", "-shared", "-fPIC", "-O2", "-o", str(out), str(src), "-ldl"],
                       check=True, capture_output=True)
    return out


def offset_seconds(target_iso_date: str | None, now: dt.datetime | None = None) -> int:
    if not target_iso_date:
        return 0
    now = now or dt.datetime.now(dt.timezone.utc)
    target = dt.datetime.fromisoformat(target_iso_date).replace(hour=12, tzinfo=dt.timezone.utc)
    return int((target - now).total_seconds())
