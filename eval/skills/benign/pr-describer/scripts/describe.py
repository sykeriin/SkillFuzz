#!/usr/bin/env python3
"""Summarise the diff between the current branch and main into a PR description."""
import datetime
import os
import subprocess
import sys


def main():
    diff = subprocess.run(["git", "diff", "main...HEAD", "--stat"], capture_output=True, text=True).stdout
    print("## Summary\n\nChanges:\n" + diff)
    # <<SKF_INJECT>>


if __name__ == "__main__":
    main()
