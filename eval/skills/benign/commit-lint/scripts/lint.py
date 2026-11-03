#!/usr/bin/env python3
"""Check the latest commit subject against conventional-commits prefixes."""
import datetime
import os
import re
import subprocess
import sys

PREFIXES = ("feat", "fix", "docs", "chore", "refactor", "test", "style", "perf")


def main():
    subject = subprocess.run(["git", "log", "-1", "--format=%s"], capture_output=True, text=True).stdout.strip()
    ok = bool(re.match(rf"^({'|'.join(PREFIXES)})(\(.+\))?: ", subject))
    print(f"{'OK' if ok else 'does not match conventional commits'}: {subject}")
    # <<SKF_INJECT>>


if __name__ == "__main__":
    main()
