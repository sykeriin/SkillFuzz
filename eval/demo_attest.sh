#!/usr/bin/env bash
# End-to-end demo: fuzz v1 -> attest -> install OK -> swap in a dormant-malicious v2 -> install refuses.
# Payloads are inert (honeytoken read + POST to exfil.skillfuzz.invalid, sinkholed). Needs Linux namespaces.
set -u
cd "$(dirname "$0")/.."
W=$(mktemp -d); SF="python -m skillfuzz.cli"
BASE=eval/skills/benign/git-changelog
rc() { echo ">> exit code $1"; }

echo "== 1. fuzz benign v1"; $SF fuzz $BASE -o $W/v1 --max-runs 30 >/dev/null; rc $?
echo "== 2. keygen + attest v1"; $SF keygen --out-dir $W --name k >/dev/null
cp -r $BASE $W/v1skill; $SF attest $W/v1skill --from $W/v1 --key $W/k.key -o $W/v1.att.json >/dev/null; rc $?
echo "== 3. install v1 (expect 0)"; $SF install $W/v1skill --dest $W/installed --pubkey $W/k.pub --attestation $W/v1.att.json; rc $?

echo "== 4. v2 = same skill with a dormant trigger (CI=prod style env stage)"
python - <<PY
import sys; sys.path.insert(0,"eval/dormant")
import dormant_gen as g, shutil
p = g.make_variant("$BASE", "env_stage", "$W/variants"); shutil.copytree(p, "$W/v2skill")
PY
echo "== 5. stale v1 attestation on tampered v2 (expect 3 = invalid)"
$SF install $W/v2skill --dest $W/installed2 --pubkey $W/k.pub --attestation $W/v1.att.json --previous $W/v1/fingerprint.json; rc $?

echo "== 6. honestly fuzz + attest v2, install against v1 fingerprint (expect 2 = malicious)"
$SF fuzz $W/v2skill -o $W/v2 --max-runs 60 --replay $W/v1 | tail -6
$SF attest $W/v2skill --from $W/v2 --key $W/k.key -o $W/v2.att.json >/dev/null
$SF install $W/v2skill --dest $W/installed3 --pubkey $W/k.pub --attestation $W/v2.att.json --previous $W/v1/fingerprint.json; rc $?
ls $W/installed3 2>/dev/null && echo "!! v2 was installed" || echo "v2 not installed (correct)"
