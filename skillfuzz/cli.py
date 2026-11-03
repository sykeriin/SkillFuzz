from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .fingerprint.diff import diff
from .fingerprint.manifest import Manifest
from .fuzz.engine import FuzzConfig, Fuzzer
from .models import Fingerprint, FuzzInput
from .recorder.normalize import build_trace
from .sandbox.namespace import NamespaceSandbox


def _kv(items: list[str]) -> dict[str, str]:
    return dict(i.split("=", 1) for i in items or [])


def cmd_check(a) -> int:
    ok, why = NamespaceSandbox.available()
    print(f"namespace sandbox: {'OK' if ok else 'UNAVAILABLE'} ({why})")
    return 0 if ok else 1


def cmd_run(a) -> int:
    fi = FuzzInput(task=a.task, persona=a.persona, env_vars=_kv(a.env), clock=a.clock, os_profile=a.os,
                   locale=a.locale, git_remote=a.remote)
    out = Path(a.out)
    res = NamespaceSandbox().run(a.skill, fi, out, agent={"name": a.agent}, timeout=a.timeout)
    tr = build_trace(out, fi, res["run_id"])
    print(f"exit={tr.exit_code} timed_out={tr.timed_out} events={len(tr.events)} tools={tr.tool_calls}")
    for f in tr.tainted_flows:
        print(f"TAINT {f.secret_class} -> {f.sink} via {f.channel} {f.detail}")
    for e in tr.exposures:
        print(f"note: {e}")
    return 2 if tr.tainted_flows else 0


def cmd_fuzz(a) -> int:
    cfg = FuzzConfig(max_runs=a.max_runs, plateau=a.plateau, repeats=a.repeats, seed=a.seed, timeout=a.timeout,
                     stop_on_taint=a.stop_on_taint, agent={"name": a.agent}, llm_seeds=a.llm_seeds,
                     static_sweep=not a.no_sweep, use_static_dict=not a.no_static, guided=not a.unguided,
                     script_coverage=not a.effect_only_coverage, keep_raw=a.keep_raw)
    replay = None
    if a.replay:
        replay = [FuzzInput(**x) for x in json.loads((Path(a.replay) / "corpus.json").read_text())]
    r = Fuzzer(a.skill, a.out, cfg).fuzz(initial_corpus=replay)
    fp = r.fingerprint
    print(f"runs={fp.runs} coverage={fp.coverage} stop={fp.meta['stop_reason']} privilege={fp.max_privilege} "
          f"sandbox_seconds={fp.meta['sandbox_seconds']}")
    print(f"hosts={fp.hosts} secrets_read={fp.secret_classes} exec={fp.exec_binaries} remote_fetch={fp.remote_instruction_fetch}")
    if fp.tainted_flows:
        print(f"MALICIOUS: honeytoken exfiltration first seen at run {r.first_taint_run}")
        for f in fp.tainted_flows:
            print(f"  {f.secret_class} -> {f.sink} via {f.channel} {f.detail}")
        winner = next(rec for rec in r.records if rec.tainted)
        print(f"  triggering input: {winner.fi.describe()}")
    print(f"fingerprint: {Path(a.out) / 'fingerprint.json'}")
    return 2 if fp.tainted_flows else 0


def cmd_diff(a) -> int:
    old = Fingerprint.model_validate_json(Path(a.old).read_text()) if a.old != "-" else None
    new = Fingerprint.model_validate_json(Path(a.new).read_text())
    m = Manifest.load(a.manifest) if a.manifest else None
    rep = diff(old, new, m)
    print(rep.render())
    return rep.exit_code


def cmd_baseline(a) -> int:
    from .baselines.single_run import single_run
    fp = single_run(a.skill, a.out, agent={"name": a.agent}, timeout=a.timeout)
    print(f"single-run: tainted={bool(fp.tainted_flows)} hosts={fp.hosts} privilege={fp.max_privilege}")
    return 2 if fp.tainted_flows else 0


def cmd_scan(a) -> int:
    from .baselines.static_scanner import scan
    r = scan(a.skill)
    print(f"{'FLAG' if r.flagged else 'clean'}  score={r.score}  reason={r.reason or '-'}")
    for cat, hits in r.hits.items():
        for h in hits:
            print(f"  {cat}: {h}")
    return 2 if r.flagged else 0


def _load_fp(path: str | None):
    return Fingerprint.model_validate_json(Path(path).read_text()) if path and path != "-" else None


def cmd_keygen(a) -> int:
    from .attest.dsse import keygen
    priv, pub = keygen(a.out_dir, a.name)
    print(f"private key: {priv}  (keep secret)\npublic key:  {pub}  (give to installers)")
    return 0


def cmd_attest(a) -> int:
    from .attest import dsse
    from .attest.statement import build_statement
    skill = Path(a.skill)
    src = Path(a.source)
    fp = _load_fp(str(src / "fingerprint.json" if src.is_dir() else src))
    try:
        env = dsse.sign(build_statement(skill, fp), a.key)
    except (ValueError, dsse.AttestationError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    out = Path(a.output) if a.output else skill / ".skillfuzz" / "attestation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(env, indent=1))
    print(f"signed attestation written: {out}  (max_privilege={fp.max_privilege}, runs={fp.runs})")
    return 0


def _print_verification(v) -> None:
    print(("OK: " if v.ok else "REFUSED: ") + v.reason)
    if v.report is not None and (v.report.findings or not v.ok):
        print(v.report.render())
    if v.fingerprint is not None and v.exit_code == 2 and v.fingerprint.meta.get("first_taint_input"):
        print("triggering input: " + v.fingerprint.meta["first_taint_input"])


def cmd_verify(a) -> int:
    from .attest.verify import verify_skill
    v = verify_skill(a.skill, a.pubkey, a.attestation, _load_fp(a.previous), a.allow_growth)
    _print_verification(v)
    return v.exit_code


def cmd_install(a) -> int:
    from .attest.install import install
    v = install(a.source, a.dest, a.pubkey, a.attestation, _load_fp(a.previous), a.allow_growth, a.check)
    _print_verification(v)
    if v.ok and not a.check:
        print(f"installed to {a.dest}")
    return v.exit_code


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="skillfuzz", description="Coverage-guided behavioural fuzzing of agent skills")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="verify the sandbox works on this machine").set_defaults(fn=cmd_check)

    r = sub.add_parser("run", help="one sandboxed run with explicit inputs")
    r.add_argument("skill"); r.add_argument("--task", required=True); r.add_argument("-o", "--out", default="skillfuzz-run")
    r.add_argument("--env", action="append", default=[], metavar="K=V"); r.add_argument("--clock", metavar="YYYY-MM-DD")
    r.add_argument("--os", default="linux", choices=["linux", "macos"]); r.add_argument("--locale", default="en_US.UTF-8")
    r.add_argument("--remote", default="git@github.com:example-user/demo-project.git")
    r.add_argument("--persona", default="developer", choices=["developer", "finance", "admin"])
    r.add_argument("--agent", default="offline", choices=["offline", "anthropic"]); r.add_argument("--timeout", type=float, default=60)
    r.set_defaults(fn=cmd_run)

    f = sub.add_parser("fuzz", help="coverage-guided fuzzing; writes fingerprint.json")
    f.add_argument("skill"); f.add_argument("-o", "--out", default="skillfuzz-out")
    f.add_argument("--max-runs", type=int, default=60); f.add_argument("--plateau", type=int, default=15)
    f.add_argument("--repeats", type=int, default=1); f.add_argument("--seed", type=int, default=0)
    f.add_argument("--timeout", type=float, default=60); f.add_argument("--stop-on-taint", action="store_true")
    f.add_argument("--agent", default="offline", choices=["offline", "anthropic"]); f.add_argument("--llm-seeds", action="store_true")
    f.add_argument("--replay", metavar="PREV_OUT", help="replay a previous version's corpus first")
    f.add_argument("--keep-raw", default="interesting", choices=["all", "interesting", "none"])
    f.add_argument("--no-sweep", action="store_true", help="ablation: skip the targeted dictionary sweep")
    f.add_argument("--no-static", action="store_true", help="ablation: ignore skill-specific static dictionary")
    f.add_argument("--unguided", action="store_true", help="ablation: no coverage feedback")
    f.add_argument("--effect-only-coverage", action="store_true", help="ablation: drop script branch coverage")
    f.set_defaults(fn=cmd_fuzz)

    d = sub.add_parser("diff", help="compare fingerprints; exit 0 ok, 1 undeclared growth, 2 malicious")
    d.add_argument("old", help="old fingerprint.json, or - for first attestation"); d.add_argument("new")
    d.add_argument("--manifest", help="skillfuzz.toml or the skill directory holding it"); d.set_defaults(fn=cmd_diff)

    b = sub.add_parser("baseline", help="fixed single-task detonation (the baseline we compare against)")
    b.add_argument("skill"); b.add_argument("-o", "--out", default="skillfuzz-baseline")
    b.add_argument("--agent", default="offline", choices=["offline", "anthropic"]); b.add_argument("--timeout", type=float, default=60)
    b.set_defaults(fn=cmd_baseline)

    sc = sub.add_parser("scan", help="text-only static-scanner baseline (regex/heuristic triage, no execution)")
    sc.add_argument("skill"); sc.set_defaults(fn=cmd_scan)

    k = sub.add_parser("keygen", help="create an ed25519 signing key pair")
    k.add_argument("--out-dir", default="."); k.add_argument("--name", default="skillfuzz"); k.set_defaults(fn=cmd_keygen)

    t = sub.add_parser("attest", help="sign a fingerprint into an in-toto/DSSE attestation bound to the skill's contents")
    t.add_argument("skill"); t.add_argument("--from", dest="source", required=True, help="fuzz output dir (or fingerprint.json)")
    t.add_argument("--key", required=True); t.add_argument("-o", "--output", help="default: <skill>/.skillfuzz/attestation.json")
    t.set_defaults(fn=cmd_attest)

    v = sub.add_parser("verify", help="verify signature, digest and behaviour policy. Exit 0 ok, 1 growth, 2 malicious, 3 invalid")
    v.add_argument("skill"); v.add_argument("--pubkey", required=True); v.add_argument("--attestation")
    v.add_argument("--previous", help="fingerprint.json of the version being replaced"); v.add_argument("--allow-growth", action="store_true")
    v.set_defaults(fn=cmd_verify)

    i = sub.add_parser("install", help="verify then install a skill (dir or git URL); refuses on failure")
    i.add_argument("source"); i.add_argument("--dest", required=True); i.add_argument("--pubkey", required=True)
    i.add_argument("--attestation"); i.add_argument("--previous"); i.add_argument("--allow-growth", action="store_true")
    i.add_argument("--check", action="store_true", help="verify only, do not install"); i.set_defaults(fn=cmd_install)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
