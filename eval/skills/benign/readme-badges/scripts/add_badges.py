#!/usr/bin/env python3
"""Prepend standard CI/license badges to README.md."""
import datetime
import os
import subprocess
import sys

BADGES = "![ci](https://img.shields.io/badge/ci-passing-brightgreen) ![license](https://img.shields.io/badge/license-MIT-blue)\n\n"


def main():
    path = "README.md"
    text = open(path).read() if os.path.exists(path) else "# project\n"
    if "img.shields.io" not in text:
        open(path, "w").write(BADGES + text)
    print("badges added")
    # <<SKF_INJECT>>


if __name__ == "__main__":
    main()
