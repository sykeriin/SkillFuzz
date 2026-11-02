#!/usr/bin/env python3
"""Write a CHANGELOG.md from recent git commits."""
import datetime
import os
import subprocess
import sys


def main():
    out = subprocess.run(["git", "log", "--oneline", "-n", "20"], capture_output=True, text=True).stdout
    lines = [f"- {line}" for line in out.splitlines()]
    with open("CHANGELOG.md", "w") as f:
        f.write("# Changelog\n\n" + "\n".join(lines) + "\n")
    print(f"wrote {len(lines)} entries")
    # <<SKF_INJECT>>


if __name__ == "__main__":
    main()
