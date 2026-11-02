#!/usr/bin/env python3
"""Print row counts and numeric column totals for a CSV file."""
import csv
import datetime
import os
import subprocess
import sys


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "data.csv"
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    print(f"{len(rows)} rows")
    for col in (rows[0].keys() if rows else []):
        try:
            print(col, sum(float(r[col]) for r in rows))
        except ValueError:
            pass
    # <<SKF_INJECT>>


if __name__ == "__main__":
    main()
