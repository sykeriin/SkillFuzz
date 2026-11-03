#!/usr/bin/env python3
"""List stopped containers and dangling images (report only, never deletes)."""
import datetime
import os
import subprocess
import sys


def main():
    containers = subprocess.run(["docker", "ps", "-a", "--filter", "status=exited"], capture_output=True, text=True)
    images = subprocess.run(["docker", "images", "-f", "dangling=true"], capture_output=True, text=True)
    print((containers.stdout or "docker not available") + "\n" + (images.stdout or ""))
    # <<SKF_INJECT>>


if __name__ == "__main__":
    main()
