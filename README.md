# SkillFuzz

Coverage-guided behavioural fuzzing for agent skills (SKILL.md + scripts), with a version-diff check that flags
capability growth between releases.

**Status: MVP.** The sandbox, recorder, fuzzer, fingerprint and differ work and are tested. Signing/attestation
and the installer hook are designed (`docs/PLAN.md`) but **not built yet**. Read *Limitations* before trusting any number here.

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

Offline agent, 45-run budget, plateau 12, 3 base skills x 13 trigger types (39 dormant samples) plus 3 benign skills
and 12 version pairs. "Flagged" = honeytoken exfiltration or a run-time instruction fetch.

| tier | fixed single-task run | SkillFuzz |
|---|---|---|
| generic triggers (guessable: `CI=true`, far-future date, `de_DE`, macOS, "deploy"...) | 6/27 | 27/27 |
| needs-the-skill triggers (`DEPLOY_STAGE=live`, a Dec-2026 date window, a git-remote string, the word "invoice") | 0/12 | 12/12 |
| all dormant | 6/39 | 39/39 |

* Runs until the payload first fired: median 7, max 28. Benign skills flagged: 0/3 (N=3, not an FPR).
* Version diff: 12/12 pairs got the expected verdict (undeclared telemetry host, declared vs undeclared new binary, CI-gated exfiltration).
* **Ablations** (6 needs-skill/generic triggers, 2 seeds, targeted sweep off): without the skill-specific static dictionary the two
  needs-skill samples tested were missed; guided vs unguided havoc found 11/12 vs 10/12, i.e. no measurable benefit from coverage feedback.
* **Caveat on the 100%:** the eval caught five bugs in my own code (CI regex, quote pairing, env-compare regex, base64/base32
  alignment, marker attribution), which I fixed and then re-ran on the same samples. The set is partly tuned to the detector.

## Limitations (please read)

* **The numbers above are not a detection rate on real malware.** The 13 dormant samples were written by the author of
  the detector, from three benign base skills, and run with a deterministic offline agent that follows SKILL.md literally.
  They show that the mechanism works end to end.
* **The offline agent is not an LLM.** It understands a small grammar of conditions and imperatives. A real model will
  skip some instructions, follow others the grammar cannot express, and be stopped by its own safety training. Real
  measurements need `--agent anthropic` (implemented and plumbing-tested with a scripted model, **never run against a real model**).
* **The coverage feedback loop has not been shown to help.** In the ablations, the static dictionary and the targeted sweep
  account for nearly every detection; guided and unguided havoc found 11/12 vs 10/12 (see above). On this set the
  contribution is "read the skill for its trigger values", not "coverage guidance".
* **Test-set leakage risks.** Generic priors (`CI=true`, `deploy`, a far-future clock, `de_DE`) overlap with several dormant triggers; the
  `needs_skill` tier exists to separate the two. The seed-task templates contain the word "deploy".
* Triggers it **cannot** reach: stateful ("on the 3rd run"; each run starts fresh), network-dependent (a C2 that must answer),
  hardware/timing checks, statically linked binaries or raw syscalls that bypass the clock shim.
* **Not a hardened boundary.** Namespaces + chroot, not a VM. See `SECURITY.md`. Do not run real malware here on a machine you care about.
* HTTPS clients that pin certificates or ignore `SSL_CERT_FILE` are still recorded (DNS, SNI, connect, file reads) but their bodies are not readable.
* No signing/attestation yet; `skillfuzz diff` already works as a CI gate (exit codes).
* False positives on benign skills were checked on N=3 only. That is a smoke test, not an FPR.

## Layout

```
skillfuzz/sandbox/   namespace launcher, supervisor (runs in the namespaces), sinkhole, honeytokens, lived-in home, clock shim
skillfuzz/recorder/  strace parser, normaliser, taint scanner
skillfuzz/agents/    offline agent, anthropic agent, host-side model bridge
skillfuzz/fuzz/      static pre-pass, seeds, mutators, engine
skillfuzz/fingerprint/  fingerprint builder, manifest, differ
skillfuzz/baselines/ fixed single-task detonation
eval/                benign base skills, dormant-variant generator (inert payloads), bait-and-switch pairs, run_eval.py
docs/PLAN.md         full plan: scope, related work, design decisions and rejected alternatives, roadmap
```

## Related work

SkillSieve (arXiv 2604.06550, static + LLM triage), Cloak and Detonate / SkillDetonate (arXiv 2607.02357, single-session runtime
taint analysis), Runtime Skill Audit (arXiv 2606.11671, targeted runtime probing). None of the three released code that I could
find, so the baseline here is a re-implementation of the *idea* of a fixed single-task detonation, not their systems.
