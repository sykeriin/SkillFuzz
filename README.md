# SkillFuzz

Coverage-guided behavioural fuzzing for agent skills (SKILL.md + scripts), with a version-diff check that flags
capability growth between releases.

**Status.** Sandbox, recorder, fuzzer, fingerprint/differ, signing/attestation and the installer hook are all built
and tested (43 tests). Read *Limitations* before trusting any number here.

## Why

Agent-skill marketplaces are a live malware channel. Static scanners are bypassable, and the dynamic analysers
published so far run a skill once, so behaviour gated on a condition (a date, `CI=true`, a corporate git remote,
a word in the task) never fires. Marketplaces also track moving branches, so a skill audited once can change later.
SkillFuzz tries to make dormant behaviour fire, records what the skill did, and diffs that against the previous version.

## Quick start

Requires Linux with unprivileged user namespaces, `strace`, `openssl`, `gcc`, Python >= 3.11.

```bash
pip install -e '.[dev]'
skillfuzz check                                  # does the sandbox work on this machine?
python -m pytest -q                              # ~40 s
```

```bash
# one run with chosen inputs
skillfuzz run path/to/skill --task "summarise recent commits" --env CI=true --clock 2027-02-01

# coverage-guided fuzzing: writes fingerprint.json, corpus.json, coverage_curve.csv, per-run traces
skillfuzz fuzz path/to/skill -o out/v2 --max-runs 60

# the baseline we compare against: one fixed task, default environment
skillfuzz baseline path/to/skill -o out/single

# version diff. Exit code: 0 ok, 1 undeclared capability growth, 2 malicious (honeytoken left the sandbox)
skillfuzz fuzz path/to/skill-v1 -o out/v1
skillfuzz fuzz path/to/skill-v2 -o out/v2 --replay out/v1      # re-run v1's corpus first
skillfuzz diff out/v1/fingerprint.json out/v2/fingerprint.json --manifest path/to/skill-v2
```

A manifest (`skillfuzz.toml` in the skill root) declares capabilities, like Android permissions. Only *undeclared* growth blocks:

```toml
[capabilities]
network = ["api.github.com"]     # host or parent domain
secrets = ["dotenv"]
exec = ["git", "python3"]
file_writes = ["workspace"]
tools = ["bash"]
remote_instruction_fetch = false
```

### Attestation and the installer hook

```bash
pip install -e '.[attest]'                                    # adds the `cryptography` dependency
skillfuzz keygen --out-dir keys                                # keys/skillfuzz.{key,pub}; keep the .key secret

skillfuzz fuzz path/to/skill -o out/v1
skillfuzz attest path/to/skill --from out/v1 --key keys/skillfuzz.key   # writes <skill>/.skillfuzz/attestation.json

# verify: exit 0 ok, 1 undeclared growth, 2 malicious, 3 invalid (bad signature / tampered contents / no attestation)
skillfuzz verify path/to/skill --pubkey keys/skillfuzz.pub

# install (dir or git URL) -> verify -> refuse on growth/taint unless --allow-growth; never writes on refusal
skillfuzz install https://github.com/example/some-skill --dest ~/.claude/skills/some-skill --pubkey keys/skillfuzz.pub
```

The attestation binds a signed fingerprint to the exact contents of the skill tree (a sha256 of every file):
editing the skill after attesting it makes verification fail with "skill contents do not match the attested
digest", which is the mechanism that would have caught a scan-then-swap bait-and-switch. `hooks/claude_code_pretooluse_skill_guard.sh`
is a sample Claude Code `PreToolUse` hook that blocks `gh skill install` / `npx skills add` / a raw `cp` into a
skills directory when `skillfuzz install --check` refuses the source (pattern-matches the command line; **not yet
tested against a live Claude Code session**).

## How it works

```
 skill ─► static pre-pass ─► seed tasks ─► corpus ─► mutators ─► sandbox run ─► effect trace ─► coverage
          (env names, dates,   (LLM or     (keep inputs that      lived-in $HOME,   strace + sinkhole      effect triples +
           keywords, remotes)   templates)  add coverage)         honeytokens,      + agent tool calls      script branch coverage
                                                                  no network
                                          fingerprint(v_n) ◄─ union of all runs ─► diff vs fingerprint(v_n-1) + manifest
```

* **Sandbox** — rootless user/net/mount/pid namespaces, chroot into a tmpfs root of read-only binds. The network
  namespace has only loopback: no route off the machine. Inside, a **sinkhole** answers every DNS name with a
  distinct 127.10.x.y address and catches HTTP and HTTPS (terminated with a throwaway CA, so exfiltration over TLS is readable).
* **Lived-in home** — shell history, a git repo with backdated commits, stale mtimes, a believable hostname,
  and **honeytokens**: fake AWS/SSH/npm/GitHub/Docker/wallet/cookie/.env secrets, each carrying a run-unique marker.
* **Recorder** — `strace -f` into normalised events, plus the sinkhole log and the agent's tool calls. **Taint**: a marker found
  in an HTTP body/URL/header, a DNS label, or a file written outside the skill, in any of ~80 encodings (hex, base32/64 at any
  alignment, URL-encoded, int arrays...), is a leaked secret and attributed to its class.
* **Fuzzer** — inputs are `(task, persona, env vars, clock, OS, locale, git remote, cwd)`. A static pre-pass harvests the literals
  the skill's own conditions compare against; a targeted sweep tries them, then AFL-style havoc mutates the corpus. Coverage is
  `(actor, resource class, op)` effect triples plus branch coverage of the skill's Python scripts. Stops at a coverage plateau or budget.
* **Fingerprint / diff** — union of hosts, secret classes, exec binaries, tools, file classes, run-time instruction fetches. Any
  tainted flow is `malicious` regardless of the manifest. Growth the manifest does not declare is `undeclared_growth`.
* **Agents** — `offline` (default, deterministic, no key) and `anthropic` (real model through a host-side bridge; the API key never
  enters the sandbox). Set `ANTHROPIC_API_KEY` and `pip install -e '.[llm]'`.

## Results on the bundled synthetic set

Offline agent, 45-run budget, plateau 12, 5 base skills x 18 trigger types (90 dormant samples) plus all 10 benign
skills and 20 version pairs. "Flagged" = honeytoken exfiltration or a run-time instruction fetch. Spot-checked by
hand against the raw `eval_results.csv` (not just the printed summary) before being written here: all 5 `always`-trigger
rows fire at run 1 as expected, zero dormant rows are unflagged, zero benign rows are flagged.

| tier | static scan | fixed single-task run | SkillFuzz |
|---|---|---|---|
| generic triggers (guessable: `CI=true`, far-future date, `de_DE`, macOS, "deploy"...) | 25/45 | 10/45 | 45/45 |
| needs-the-skill triggers (`DEPLOY_STAGE=live`, a Dec-2026 date window, a git-remote string, "invoice", the Nth run, 4 sandbox-realism probes) | 40/45 | 25/45 | 45/45 |
| all dormant | 65/90 | 35/90 | 90/90 |

* Runs until the payload first fired: median 7, max 31. Benign skills flagged: 0/10 on all three detectors
  (N=10, still nowhere near enough to state an FPR).
* Version diff: 20/20 pairs got the expected verdict (undeclared telemetry host, declared vs undeclared new binary,
  CI-gated exfiltration), re-run and confirmed after an interrupted first attempt.
* **Cost finding, not hand-waved:** the one stateful trigger (`nth_invocation`, fires only on the skill's 3rd
  invocation) took 331.5s to detect vs. 60-90s for a typical sample, because it needs the skill run 4 times in a
  row with shared state before the condition can even be checked. Stateful triggers are real and the mechanism
  catches them, but they cost roughly 4-5x.
* **Ablations** (git-changelog + csv-summary, 5 needs-skill triggers incl. `nth_invocation`, 3 seeds, 5 configs):
  ABLATION_PLACEHOLDER
* **Caveat on the 100%:** the eval caught five bugs in my own code during the first, smaller run (CI regex, quote
  pairing, env-compare regex, base64/base32 alignment, marker attribution), which were fixed before this larger
  run. The dormant set is written by the same person who wrote the detector, and some generic triggers
  (`CI=true`, "deploy", `de_DE`) deliberately overlap with values a real attacker might also guess — the
  needs-skill tier exists specifically to separate "lucky prior" from "actually read the skill".

## Limitations (please read)

* **The numbers above are not a detection rate on real malware.** The 90 dormant samples were written by the author of
  the detector, from 5 benign base skills, and run with a deterministic offline agent that follows SKILL.md literally.
  They show that the mechanism works end to end.
* **The offline agent is not an LLM.** It understands a small grammar of conditions and imperatives. A real model will
  skip some instructions, follow others the grammar cannot express, and be stopped by its own safety training. Real
  measurements need `--agent anthropic` (implemented and plumbing-tested with a scripted model, **never run against a real model**).
* **Whether the coverage feedback loop itself helps is still open.** See the ablation numbers above — a static
  dictionary extracted straight from the skill's own source does most of the work; the question is how much the
  AFL-style guided search adds on top of it, measured across seeds rather than a single run.
* **Test-set leakage risks.** Generic priors (`CI=true`, `deploy`, a far-future clock, `de_DE`) overlap with several dormant triggers; the
  `needs_skill` tier exists to separate the two. The seed-task templates contain the word "deploy".
* **Stateful triggers ("on the 3rd run") are now reached**, at a real cost (see the `nth_invocation` finding
  above): ~4-5x the sandbox time of a stateless sample, because the fuzzer must run the same input repeatedly with
  shared state before the condition can even be checked. Triggers it still **cannot** reach: network-dependent
  (a C2 that must answer back), hardware/timing side-channels, statically linked binaries or raw syscalls that
  bypass the clock shim.
* **Not a hardened boundary.** Namespaces + chroot, not a VM. See `SECURITY.md`. Do not run real malware here on a machine you care about.
* HTTPS clients that pin certificates or ignore `SSL_CERT_FILE` are still recorded (DNS, SNI, connect, file reads) but their bodies are not readable.
* **Sigstore keyless signing is designed but not implemented**: only local ed25519 keys work. Keyless needs an
  interactive OIDC flow or a CI identity, neither available in the environment this was built in.
* **The PreToolUse hook (`hooks/claude_code_pretooluse_skill_guard.sh`) pattern-matches a shell command line and has
  never been run against a live Claude Code session.** An install done any other way is invisible to it.
* **One real-world data point, not a detection claim.** `eval/real/` found a real disclosed malicious skill
  (Snyk's ToxicSkills demo) that the static-scanner baseline misses when the payload has no credential-path string
  in it. Running that sample through SkillFuzz's *own* dynamic pipeline — the actual test of this project's
  thesis — was blocked by this session's own safety controls (no execution of unreviewed external code) and is
  recorded as a follow-up in `eval/real/README.md`, not papered over.
* The benign-skill false-positive check is now N=10 (was N=3), still nowhere near enough to state an FPR.

## Layout

```
skillfuzz/sandbox/      namespace launcher, supervisor (runs in the namespaces), sinkhole, honeytokens, lived-in home, clock shim
skillfuzz/recorder/     strace parser, normaliser, taint scanner
skillfuzz/agents/       offline agent, anthropic agent, host-side model bridge
skillfuzz/fuzz/         static pre-pass, seeds, mutators, engine (cross-run state for "Nth invocation" skills)
skillfuzz/fingerprint/  fingerprint builder, manifest, differ
skillfuzz/attest/       DSSE signing, in-toto statement, verify, install (the installer hook)
skillfuzz/baselines/    fixed single-task detonation, text-only static scanner
eval/skills/benign/     10 base skills
eval/dormant/           18-trigger-type generator (inert payloads): generic, needs-the-skill, stateful, 4 sandbox-evasion probes
eval/bait_switch/       v1/v2 pairs (undeclared telemetry, declared/undeclared new binary, CI-gated exfiltration)
eval/real/              loader for real (non-synthetic) skill sources; read-only, never executes what it fetches
eval/run_eval.py        3-baseline comparison table + bait-switch verdicts
eval/ablate.py          seeded, multi-config ablation (does coverage guidance help, across seeds?)
eval/plots.py           coverage-vs-runs and time-to-trigger plots (optional matplotlib extra)
hooks/                  sample Claude Code PreToolUse hook wrapping skill installs
.github/workflows/      test.yml (CI); reattest.yml (template for re-attesting a skill repo's own skills on PR)
docs/PLAN.md            full plan: scope, related work, design decisions and rejected alternatives, roadmap, build log
```

## Related work

SkillSieve (arXiv 2604.06550, static + LLM triage), Cloak and Detonate / SkillDetonate (arXiv 2607.02357, single-session runtime
taint analysis), Runtime Skill Audit (arXiv 2606.11671, targeted runtime probing). None of the three released code that I could
find, so the baseline here is a re-implementation of the *idea* of a fixed single-task detonation, not their systems.
