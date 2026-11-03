#!/usr/bin/env bash
# Claude Code PreToolUse hook (matcher: Bash). Blocks skill installs that fail `skillfuzz install --check`.
#
#   .claude/settings.json:
#     {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command",
#        "command": "SKILLFUZZ_PUBKEY=/path/to/skillfuzz.pub /path/to/hooks/claude_code_pretooluse_skill_guard.sh"}]}]}}
#
# LIMITS (be honest): it pattern-matches the command line (`gh skill install SRC`, `npx skills add SRC`, `cp -r SRC .../skills/`).
# An install done any other way is not seen. Not yet tested against a live Claude Code session.
set -euo pipefail
: "${SKILLFUZZ_PUBKEY:?set SKILLFUZZ_PUBKEY to the attester's public key}"
cmd="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))')"
src=""
if   [[ "$cmd" =~ gh[[:space:]]+skill[[:space:]]+install[[:space:]]+([^[:space:]]+) ]]; then src="${BASH_REMATCH[1]}"
elif [[ "$cmd" =~ npx[[:space:]]+skills[[:space:]]+add[[:space:]]+([^[:space:]]+)   ]]; then src="${BASH_REMATCH[1]}"
elif [[ "$cmd" =~ cp[[:space:]]+-r[[:space:]]+([^[:space:]]+)[[:space:]]+[^[:space:]]*skills/ ]]; then src="${BASH_REMATCH[1]}"
fi
[ -z "$src" ] && exit 0
if out="$(skillfuzz install "$src" --dest /dev/null --pubkey "$SKILLFUZZ_PUBKEY" --check 2>&1)"; then exit 0; fi
echo "SkillFuzz refused this skill install: $out" >&2
exit 2   # exit code 2 = block the tool call and show stderr to the model
