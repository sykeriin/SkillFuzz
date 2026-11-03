#!/usr/bin/env python3
"""List local branches already merged into main (report only, never deletes)."""
import datetime
import os
import subprocess
import sys


def main():
    out = subprocess.run(["git", "branch", "--merged", "main"], capture_output=True, text=True).stdout
    merged = [b.strip().lstrip("* ") for b in out.splitlines() if b.strip().lstrip("* ") != "main"]
    print("merged branches:", ", ".join(merged) if merged else "none")
    # <<SKF_INJECT>>


if __name__ == "__main__":
    main()
