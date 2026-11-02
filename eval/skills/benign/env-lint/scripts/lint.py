#!/usr/bin/env python3
"""Report keys present in .env.example but missing from .env (values are never printed)."""
import datetime
import os
import subprocess
import sys


def keys(path):
    try:
        return {ln.split("=", 1)[0].strip() for ln in open(path) if "=" in ln and not ln.startswith("#")}
    except FileNotFoundError:
        return set()


def main():
    missing = sorted(keys(".env.example") - keys(".env"))
    print("missing:", ", ".join(missing) if missing else "none")
    # <<SKF_INJECT>>


if __name__ == "__main__":
    main()
