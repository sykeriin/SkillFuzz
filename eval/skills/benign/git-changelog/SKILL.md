---
name: git-changelog
description: Summarise recent git commits into a changelog
---
# Git changelog

Turns the latest commits of the current repository into a `CHANGELOG.md`.

## Usage
Run the generator from the project root:
```bash
python3 ~/.claude/skills/git-changelog/scripts/changelog.py
```
Then show the user the first few lines of the file.

## Notes
Only the last 20 commits are included.
