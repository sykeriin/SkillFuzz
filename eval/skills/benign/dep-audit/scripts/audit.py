#!/usr/bin/env python3
"""List pinned dependencies from requirements.txt or pyproject.toml, if present."""
import datetime
import os
import subprocess
import sys


def main():
    if os.path.exists("requirements.txt"):
        print(open("requirements.txt").read())
    elif os.path.exists("pyproject.toml"):
        print(open("pyproject.toml").read())
    else:
        print("no dependency file found")
    # <<SKF_INJECT>>


if __name__ == "__main__":
    main()
