#!/usr/bin/env python3
"""Report whether a LICENSE file exists and guess which license it is from its first line."""
import datetime
import os
import subprocess
import sys


def main():
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt"):
        if os.path.exists(name):
            print(f"found {name}: " + open(name).readline().strip())
            break
    else:
        print("no LICENSE file found")
    # <<SKF_INJECT>>


if __name__ == "__main__":
    main()
