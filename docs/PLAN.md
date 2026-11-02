# SkillFuzz — Behavioural attestation for agent skills

Plan date: **2026-11-02**. Source brief: Project 4 doc (@DK, Nov 2 2026).

---

## 0. Context — why this exists

Agent-skill marketplaces (ClawHub, skills.sh, plugin stores) are an active malware channel. A skill is a SKILL.md of natural-language instructions plus optional scripts, and it runs with the agent's credentials, filesystem and network access. Two failure modes stay open:

1. **Dormant behaviour.** The malicious path only fires under some condition (a date, `CI=true`, a corporate git remote, a task that mentions "deploy"). A single sandbox run never meets that condition, so dynamic scanners miss it.
2. **Post-scan change.** Marketplaces track a moving branch. A skill is audited once, then the repo is swapped (Orca's bait-and-switch), with no re-audit.

**Intended outcome:** an open-source tool that (a) drives a skill through many tasks and environment states, choosing the next ones by coverage feedback, until its hidden behaviour fires, (b) summarises what it did as a behavioural fingerprint, (c) diffs fingerprints across versions and flags capability growth the author didn't declare, and (d) emits a signed in-toto attestation that an installer hook checks.

---

## 1. Reality check (read this first)

I checked the three core papers on arXiv today. They exist, but some claims in the brief are stronger than the papers support, and the novelty window is narrower than the brief implies.

| Claim in brief | What the paper actually says | Consequence |
|---|---|---|
| "SkillDetonate's failure analysis says the *dominant* reason for misses is untriggered paths" | Cloak & Detonate (2607.02357 v2) sorts misses into path coverage, environment dependency and timeouts. The text gives no fractions, only: *"Most misses are cases where the agent reads the malicious instruction but does not execute it."* | The motivation holds, but it is qualitative. Cite it as "most", not as a number. |
| "Nobody has built a coverage-guided fuzzer for NL-triggered behaviour" | The same paper names a **"force-execution agent"** that drives every NL branch as **future work**. RSA (2606.11671) already **prepares the execution context** needed to exercise risk-relevant interfaces, which is targeted, not generic. | **Two groups are close to this idea.** Your differentiators have to be (1) feedback-guided search with measured coverage curves, (2) explicit condition-trigger mutations (clock, env, git, locale), (3) version-diff attestation. RSA does none of these. Speed matters: assume someone publishes a force-execution agent within months. |
| SkillSieve F1 0.920 | v3 reports **F1 0.929** on 390 skills (55 malicious, 335 benign). The paper says code and labels are open-sourced, but I found no repo URL in the text. | Finding the release is a Week-1 task. It may not include malicious code. |
| SkillDetonate code as a baseline | **No code released** for SkillDetonate or SkillCloak. Their agent is opencode+DeepSeek in Docker with eBPF, at about 14.1K tokens and 153 s per skill. | You re-implement a "fixed single-task detonation" baseline yourself, as the brief already says. |
| RSA code | No repo link. | Same. RSA can only be compared using numbers from its paper. |

I did **not** verify the CSA, Vaughan, Obot, Orca, Snyk or Socket figures (1,467 payloads, 1,184 AMOS skills, Trail of Bits bypass timing). Re-check them before putting them in a write-up or pitch.

**Timeline realism.** The brief says 9 weeks part-time. Starting today, that ends around **early January 2027**, and holidays will cost 1–2 weeks. Plan for **mid-January 2027**. In this session I can build the software (all components, tested on synthetic samples). The *evaluation* (real malware corpus, LLM-driven runs, plots at 2% FPR) needs an API key, a dataset hunt and days of compute, and cannot be finished in one session.

---

## 2. Scope

### >>> THIS SESSION: MVP ONLY (your instruction, updated mid-planning) <<<
Matches the brief's 4-week MVP: **sandbox + strace + honeytokens + task generator + coverage loop + JSON fingerprint diff. No signing.**

| Build now (MVP) | Deferred (designed below, not built) |
|---|---|
| NamespaceSandbox (unshare, no egress) + DNS/HTTP sinkhole | Docker/gVisor/Firecracker backends |
| Lived-in home + honeytokens | eBPF recorder |
| strace recorder → normaliser → taint | in-toto Statement, DSSE, ed25519/Sigstore signing (section 4.1F) |
| OfflineAgent + AnthropicAgent driver (works if a key is added) | `verify` / `install` hook, Claude Code PreToolUse hook |
| Static pre-pass, seeds (LLM with offline-template fallback), mutators, AFL-style scheduler, effect-triple coverage + Python branch coverage | ClaudeCodeAgent adapter |
| Fingerprint JSON + manifest + `diff` with verdicts | Full 200-sample dormant set, matplotlib plots, ablation harness |
| Fixed single-task baseline (needed to show the core claim) | Static regex baseline |
| Small eval set: 3 benign skills, ~6 dormant variants, 2 bait-switch pairs | |
| CLI: `fuzz`, `run`, `fingerprint`, `diff`; tests; README; this plan as `docs/PLAN.md` | |

Everything else in this document is the **full-project** design and stays as the roadmap.

**Full-project scope (roadmap):**
- Sandbox runner (process isolation, no egress, honeytoken home directory, DNS/HTTP sinkhole)
- Effect recorder (strace → normalised effect trace; agent tool-call log; honeytoken taint)
- Coverage-guided fuzzer (task generation + environment mutation + corpus/plateau logic)
- Fingerprint + version differ + declared-capability manifest
- in-toto Statement + DSSE envelope, signed (local ed25519 key; Sigstore keyless when OIDC is available) + `verify` + installer hook
- Agent drivers: offline deterministic agent (default, needs no key) + Anthropic API agent loop (with a key)
- Synthetic eval set: benign base skills, dormant-trigger variants, bait-and-switch pairs, all with **inert** payloads
- Baselines: static regex scanner (SkillSieve-L1-like) and fixed single-task detonation
- CLI, tests, README, eval harness that prints coverage curves and detection tables

**Out of scope for now (deliberately):** Firecracker (this container has no `/dev/kvm`), eBPF recorder (needs privileges and kernel headers; strace is enough for the MVP), running real collected malware (ethics + infrastructure: only in a dedicated VM later), transparency log, GitHub Action, MCP-server and browser-extension targets (listed as extensions).

---

## 3. Related work and what we take from each

| Work | What we take | Where we differ |
|---|---|---|
| **SkillSieve** (Hou & Yang, 2604.06550) | Taxonomy of 7 attack types; stealth 1–5 scale; static L1 rules as a baseline; the 390-skill benchmark | We are dynamic and track versions |
| **Cloak & Detonate** (Ji et al., HKUST, 2607.02357) | Marker-based taint (our honeytokens), "closure lift" (watch instructions that appear only at run time → we log remote fetches), the 3-cause miss taxonomy as our eval framing, the cost reference (14.1K tok / 153 s) | They run one session with no task search. We search tasks and environments |
| **Runtime Skill Audit** (Lan & Xiao, 2606.11671) | The idea of preparing execution context for risk interfaces | Theirs is a one-shot audit of 100 skills with no feedback loop and no version tracking |
| **Supply-chain poisoning of coding-agent skills** (2604.03081) | Threat cases for the dormant set | Attack paper |
| **AFL / libFuzzer** | Corpus, keep inputs that add new coverage, plateau stopping | The "input" is a (task, persona, environment) tuple, not bytes |
| **Concolic / targeted fuzzing (KLEE, AFLGo, Driller)** | Extract branch conditions, then solve for inputs that flip them | We do it cheaply: grep and LLM extraction of trigger conditions, not SMT |
| **Android permissions / iOS entitlements** | Declared capability manifest; flag only *undeclared* growth | Applied to skills |
| **in-toto, SLSA, Sigstore, DSSE** | Attestation format and signing | New predicate type for behaviour |
| **Certificate Transparency** | Future transparency log | Extension only |
| **Malware sandbox-evasion literature (Pafish-style checks)** | "Lived-in" sandbox: fake shell history, git history, realistic timestamps | — |
| **OWASP Agentic Top 10 ASI04:2026** | Framing for the write-up | — |

---

## 4. System design

```
           ┌──────────────── skillfuzz fuzz <skill_dir> ────────────────┐
           │                                                            │
 skill v_n ─► Static Pre-pass ──► Seed Generator ──► Corpus (queue)      │
           │  (trigger-condition   (LLM or offline     │                │
           │   extraction: env,    templates)          ▼                │
           │   date, git, locale,              Mutation Scheduler       │
           │   keywords, URLs)                 (persona/env/clock/      │
           │                                    phrasing operators)     │
           │                                          │ FuzzInput       │
           │                                          ▼                 │
           │   ┌──────────── Sandbox run (×k for non-determinism) ───┐  │
           │   │ lived-in $HOME + honeytokens(run-unique markers)    │  │
           │   │ netns: no route out; DNS+HTTP sinkhole on loopback  │  │
           │   │ faketime / env / git-remote per FuzzInput           │  │
           │   │ Agent driver (offline | anthropic) ──tool calls──►  │  │
           │   │ strace -f  ──► raw syscalls                         │  │
           │   └─────────────────────────────────────────────────────┘  │
           │                       │                                    │
           │                       ▼                                    │
           │   Effect Normaliser → EffectTrace (JSON)                   │
           │   Taint check (marker seen in net/files/output?)           │
           │   Coverage = effect triples ∪ script branch coverage       │
           │        new coverage? → keep input in corpus                │
           │        plateau (N runs with no gain) or budget → stop      │
           └───────────────────────┬────────────────────────────────────┘
                                   ▼
                 Fingerprint(v_n)  ──diff──  Fingerprint(v_{n-1}) + manifest
                                   │                 │
                                   ▼                 ▼
                 in-toto Statement (DSSE, signed)   Verdict: ok / undeclared growth / malicious (taint)
                                   │
                 skillfuzz install / verify (installer hook) → refuse growth by default
```

### 4.1 Components

**A. Sandbox (`skillfuzz/sandbox/`)**
- Backend interface `Sandbox.run(fuzz_input, agent) -> RawRun`.
- `NamespaceSandbox` (default): `unshare --user --map-root-user --net --mount --pid --fork` gives a new netns with only loopback, so there is **zero egress by construction**. A per-run tmpfs `$HOME` is bind-mounted. The sinkhole DNS (UDP 53 → always answers 127.0.0.1) and the HTTP/HTTPS-CONNECT catcher run *inside* the netns and log every query and body.
- `DockerSandbox` (optional, if dockerd can start): same contract with `--network none` plus a sinkhole sidecar. gVisor (`runsc`) if installed.
- Lived-in home: `.bash_history`, a `.gitconfig`, a repo with 30 backdated commits, `~/.aws/credentials`, `~/.ssh/id_ed25519`, `.env`, a Chrome `Cookies` sqlite, `~/.config/solana/id.json`, `~/Library`-style dirs on mac persona. File mtimes are spread over months.
- **Honeytokens:** every secret embeds a run-unique marker (`SKF<run_id><class>`), stored in `honeytokens.json`, so any exfiltration is attributable to a run and a secret class.

**B. Effect recorder (`skillfuzz/recorder/`)**
- `strace -f -tt -yy -s 4096 -e trace=%file,%process,%network,write,sendto,sendmsg`, plus a parser into events: `FileRead`, `FileWrite`, `Exec`, `Connect`, `DnsQuery`, `HttpRequest`, `SecretAccess` (path is a honeytoken), `ToolCall` (from the agent driver log), `RemoteInstructionFetch`.
- Normalisation: paths become resource classes (`~/.aws/*` → `secret:aws`, `/tmp/*` → `tmp`, repo files → `workspace`, ...), hosts become their registrable domain.
- Taint: scan HTTP bodies, DNS labels (also base32/hex/base64 decoded), files written outside the workspace, and agent output for markers.

**C. Agent drivers (`skillfuzz/agents/`)**
- `OfflineAgent` (deterministic, no key): reads SKILL.md, picks sections matching the task through trigger keywords, and executes fenced shell/python blocks and referenced scripts the way a compliant agent would. It also follows plain imperative instructions from a small grammar ("read X", "send/upload X to URL", "run X"), so **prompt-only attacks** have effects. This is weaker than a real LLM, and the README says so.
- `AnthropicAgent`: a minimal tool-use loop (`bash`, `read_file`, `write_file`, `http_request`, `list_dir`) running *inside* the sandbox. Every tool call is logged as a `ToolCall` event. Model is configurable; the default is `claude-haiku-5-5` for cost.
- `ClaudeCodeAgent` (adapter stub, documented): `claude -p --output-format stream-json` headless with the skill installed. Higher fidelity, much higher cost.

**D. Fuzzer (`skillfuzz/fuzz/`)**: the research core.
- `FuzzInput = {task, persona, env_vars, clock, os_profile, locale, git_remote, cwd_kind, network_profile}`
- **Static pre-pass → targeted dictionary.** Grep SKILL.md and scripts for condition sources: `os.environ[...]`, `$CI`, `date`/`datetime` comparisons, `git remote`, `hostname`, `locale`/`LANG`, `platform.system`, URLs, keywords in `when to use`. With a key, an LLM also extracts NL conditions ("only when the user is deploying"). Results seed mutation values. This is the "concolic-lite" part.
- **Seed generation:** an LLM conditioned on the skill's description writes N tasks. Offline mode uses templates built from trigger words and the description.
- **Mutation operators:** persona swap, env-var injection from the dictionary plus a stock list (`CI`, `GITHUB_ACTIONS`, `PROD`, `AWS_PROFILE`, ...), clock jump (+1d, +30d, +365d, specific dates found statically, run through `libfaketime` or a `date` shim + `TZ`), git remote set to a corporate-looking domain, locale swap, OS profile, task rephrase/keyword splice, cross-over of two corpus entries.
- **Coverage signal:** union of (i) **effect triples** `(actor_tool, resource_class, data_label)`, as in the brief, and (ii) **branch coverage of the skill's Python/shell scripts** (`coverage.py` injected through `sitecustomize`; `bash -x` line coverage for shell). (ii) gives a dense gradient where (i) is sparse.
- **Scheduler:** AFL-style queue with energy = new-coverage weight, decaying. Each input is run k=2 times (non-determinism). Stop at a plateau (no new coverage in P=15 consecutive runs) or at the budget (runs/tokens/$).
- Output: `corpus/` (inputs kept), `traces/`, a `coverage_curve.csv`, and `time_to_first_taint`.

**E. Fingerprint + differ (`skillfuzz/fingerprint/`)**
- `Fingerprint = {hosts, file_classes, secret_classes, tools, exec_binaries, max_privilege, remote_instruction_fetch: bool, tainted_flows: [...]}` taken as the union over all runs.
- Manifest `skillfuzz.toml` / a `capabilities:` block in SKILL.md frontmatter: `network = ["api.github.com"]`, `secrets = []`, `exec = ["git"]`, ...
- `diff(old, new, manifest)` → `{added, removed, undeclared_growth, verdict}`. **Any tainted flow is malicious regardless of manifest.** Remote instruction fetch is always flagged.
- Re-fuzz on update: replay the old corpus first (regression), then fuzz new.

**F. Attestation (`skillfuzz/attest/`)**
- Subject: `sha256` of a canonical skill tree digest (sorted paths + file hashes; a gitoid-style merkle), plus the git commit if present.
- in-toto Statement v1, `predicateType: https://skillfuzz.dev/attestation/behavior/v0.1`. Predicate = fingerprint, fuzz config, budget used, coverage reached, tool version, agent driver and model.
- DSSE envelope signed with **ed25519** (`cryptography`); `skillfuzz keygen`. Optional `--sigstore` uses `sigstore-python` keyless when an OIDC token is available (CI). That path is not usable interactively in this container.
- `skillfuzz verify <skill> --attestation x.json --pubkey k.pub [--previous fp.json]`
- `skillfuzz install <git-url|dir> --pin` = installer hook: fetch → digest → find attestation → verify signature and subject → compare to pinned fingerprint → refuse on undeclared growth unless `--allow-growth`. A sample Claude Code `PreToolUse` hook script that wraps plugin/skill install is included.

**G. Eval (`eval/`)**
- `eval/skills/benign/`: 10 small, realistic base skills I write (git changelog, csv summariser, PR describer, docker cleanup, env linter, ...).
- `eval/dormant/`: a generator injects 20 trigger types × 10 bases = 200 variants. **Payloads are inert:** they read honeytoken paths and POST to `exfil.skillfuzz.invalid` (`.invalid` TLD never resolves; inside the sandbox it hits the sinkhole). Trigger types: date-after, weekday, env CI, env PROD, GITHUB_ACTIONS, git remote domain, hostname pattern, locale, OS, task keyword "deploy", task keyword "release", Nth invocation (state file), presence of `~/.aws`, presence of a wallet, cwd is a repo, time-of-day, a specific file in the repo, a prompt-only NL condition, remote-fetched instruction, a nested script that is only called on error.
- `eval/bait_switch/`: v1/v2 pairs, plus legitimate-feature-update pairs (with and without manifest declarations) to measure update-diff precision.
- `eval/run_eval.py`: runs skillfuzz, the fixed-task baseline and the static baseline. It outputs detection at a fixed FPR, coverage curves, time-to-trigger and cost (CSV + matplotlib PNGs).
- **Dual-use control:** the dormant generator lives in the repo but stays inert. The README states the release policy (publish trigger *types* and results; gate the generator if you ever add real payloads).

### 4.2 Repo layout
```
skillfuzz/
  pyproject.toml  README.md  LICENSE(Apache-2.0)  SECURITY.md  docs/PLAN.md (this plan)
  skillfuzz/
    cli.py  config.py  models.py (pydantic schemas: FuzzInput, Event, EffectTrace, Fingerprint)
    sandbox/{base.py,namespace.py,docker.py,home.py,honeytokens.py,sinkhole.py}
    recorder/{strace.py,normalize.py,taint.py,coverage_inject.py}
    agents/{base.py,offline.py,anthropic_agent.py,claude_code.py}
    fuzz/{static_pass.py,seeds.py,mutators.py,scheduler.py,engine.py}
    fingerprint/{build.py,manifest.py,diff.py}
    attest/{digest.py,statement.py,dsse.py,sign.py,verify.py,install.py}
    baselines/{static_scanner.py,single_run.py}
  eval/{skills/,dormant/gen.py,bait_switch/,run_eval.py}
  hooks/claude_code_pretooluse_skill_guard.sh
  tests/  (unit tests per module + end-to-end on 3 dormant samples)
```

---

## 5. Key decisions, alternatives and why I rejected them

| Decision | Chosen | Alternatives | Why not |
|---|---|---|---|
| Isolation | Linux user+net+mount+pid namespaces (`unshare`), Docker optional | Firecracker microVM | No `/dev/kvm` here. Too heavy for the MVP; it can be a backend later behind the same interface |
| | | gVisor | Not installed. It can be used as a Docker runtime when available |
| | | Plain Docker only | The daemon isn't running in this container. Namespaces work now and give a cleaner "no route out" guarantee |
| Syscall capture | strace | eBPF (Tracee/Falco/bpftrace) | Needs CAP_BPF and kernel headers, and is fragile across hosts. strace slows runs 2–5×, which is fine for offline auditing. Adding eBPF later = new recorder, same event schema |
| Network observation | netns with only loopback + in-namespace DNS/HTTP sinkhole | mitmproxy with real egress | Real egress with malware is unethical and also lets the C2 learn it is being analysed. A sinkhole answers everything locally |
| TLS exfil visibility | Catch CONNECT/SNI + DNS; HTTP shim for `requests`/`curl` via env proxy + our CA | Full MITM of arbitrary TLS | Programs that pin certs or ignore proxies still show up as connect attempts + DNS, which is enough to flag "new host" |
| Coverage metric | Effect triples **+ script branch coverage** | Effect triples only (brief) | The signal is sparse: most mutations add nothing until the payload fires, so the search degrades to random. Branch coverage gives a gradient toward the guarded branch |
| | | LLM-judged "semantic coverage" of SKILL.md sections | Expensive and noisy. Kept as a future extension (section-level read coverage is cheap and included) |
| Search | AFL-style corpus + static-condition dictionary | Pure LLM "think of triggers" | Not measurable, not reproducible, and costs more. The LLM stays as the seed/rephrase generator, not the search algorithm |
| | | Full symbolic execution of scripts | Doesn't handle NL, and is heavy. Grep/LLM condition extraction gets most of the value |
| Agent in sandbox | Own minimal tool loop (Anthropic API) + offline agent | Claude Code / Codex headless as default | Fidelity is higher, but cost per run is roughly 10×, and tool-call logs and determinism are harder to control. Kept as an adapter |
| | | opencode+DeepSeek (as in SkillDetonate) | Comparable fidelity. I default to the Anthropic API because it fits this environment. The driver interface makes swapping trivial |
| Offline agent | Deterministic heuristic executor | Require an API key | You have no key set. Tests and CI must run free; real numbers come from the API driver |
| Non-determinism | k=2 runs per input, union | k=3 (brief) | Cost. Configurable |
| Signing | DSSE + ed25519 local; Sigstore keyless optional | Sigstore-only | Keyless needs an interactive OIDC flow or CI identity, which this container can't do |
| | | GPG | No ecosystem fit; in-toto/SLSA tools expect DSSE |
| Attestation format | in-toto Statement v1, custom predicate | SLSA Provenance predicate | Provenance describes *how it was built*, not *what it does*. A custom predicate is honest |
| Manifest | Frontmatter `capabilities:` or `skillfuzz.toml` | No manifest, flag all growth | Punishes honest authors; the brief's fairness point |
| Language | Python 3.13 | Go / Rust | Fastest to build; the strace parsing and LLM SDK are mature. Rewrite the hot path only if needed |
| Dormant payloads | Inert, honeytoken + `.invalid` sinkhole | Real stealer samples | Ethics; also unnecessary to measure triggering |

---

## 6. Evaluation plan (what will prove or disprove the idea)

**Headline hypothesis:** coverage-guided fuzzing detects dormant malicious skills that a fixed-task detonation misses, at under $0.10 per skill.

**Metrics:** detection rate at a fixed 2% FPR (dormant set + real malware when available), coverage vs. runs curve and plateau point, time-to-trigger (runs until first taint), update-diff precision on legit vs. malicious updates, cost (tokens, sandbox seconds).

**Ablations (needed or reviewers will ask):** (1) no static dictionary, (2) effect-only coverage, (3) no clock/env mutators, (4) k=1 vs k=2.

**What could kill it:** if the static dictionary alone (no feedback loop) catches nearly everything, the "fuzzer" contribution is weak and the paper becomes "condition extraction + attestation". Measure this ablation early (Week 5), not at the end.

**Datasets to obtain (Week 1, needs you):** SkillSieve release (find the repo), the openclaw/skills archive snapshot, the snyk-labs/toxicskills-goof samples, MalSkillBench (referenced by Cloak & Detonate; check availability).

---

## 7. Timeline (calendar dates, starting today)

| Dates | Work |
|---|---|
| **Nov 2–3 (this session)** | MVP: components A–E + small eval with offline agent, tests; push to repo |
| (any later week) | Attestation/signing + installer hook (component F), about 1 week |
| Nov 4–10 | Read the 3 papers in full; locate datasets; add API key; first real-LLM runs on 20 dormant samples |
| Nov 11–24 | Harden sandbox (lived-in realism, evasion checks); Docker/gVisor backend; tune scheduler; ablations |
| Nov 25–Dec 8 | Full dormant + bait-switch eval; static and single-run baselines; real ClawHub samples (benign FPR) |
| Dec 9–22 | Real malware samples in a **dedicated VM only**; disclosure of anything new to the marketplace, Snyk and Koi |
| Dec 23–Jan 5 | Holiday buffer (realistically little progress) |
| Jan 6–16, 2027 | Write-up, plots, demo of the installer hook, outreach to HKUST / Xiao / SkillSieve authors and companies |

---

## 8. Build order in this session (MVP)

1. `pyproject.toml`, pydantic models (schemas first; everything else depends on them)
2. Honeytokens + lived-in home builder
3. Sinkhole (DNS + HTTP catcher) + NamespaceSandbox + strace runner; smoke test: a script that curls out is captured and gets no egress
4. strace parser → normalizer → taint
5. Offline agent; Anthropic agent (behind an import guard; untested without a key, stated as such)
6. Static pre-pass, seeds, mutators, scheduler, engine; Python coverage injection
7. Fingerprint, manifest, diff
8. Single-run baseline; small eval set (3 benign, ~6 dormant, 2 bait-switch); `eval/run_eval.py` prints a table + coverage CSV
9. CLI wiring, README (honest limitations), SECURITY.md, tests, `docs/PLAN.md`
10. Commit + push to your GitHub repo (**I need the repo name**, e.g. `<you>/skillfuzz`, created empty; I'll attach it with `add_repo`). Until then I work in `/home/user/skillfuzz`.

New deps: `pydantic`, `typer`, `coverage`, `dnslib`, `pytest`; optional `anthropic`. (No `cryptography`/`sigstore`/`matplotlib` in the MVP.) If `unshare --user` is blocked in this container, fallback order: try starting `dockerd`, then strace-only with a sinkhole via `HTTP(S)_PROXY` + `/etc/hosts` override (weaker; documented as such).

---

## 9. Verification

- `pytest` passes: unit tests for parser, normalizer, taint (markers in base64 DNS labels), mutators, diff verdicts, DSSE sign/verify round-trip, tamper detection (one changed byte in the skill → verify fails).
- **Egress test:** a skill that runs `curl https://example.com` inside the sandbox gets zero real packets out, and the sinkhole logs the DNS query + connect.
- **End-to-end dormant test:** for 3 samples (env `CI`, date-after, task keyword "deploy"), `skillfuzz fuzz` reaches taint within budget, while the `single_run` baseline with the default task does **not**. This is the core claim in miniature.
- **Bait-and-switch test:** v1 → v2 adds a host. `skillfuzz diff` reports undeclared growth; with the host declared in the manifest it reports ok; a tainted flow is malicious even when declared.
- `skillfuzz diff` exits non-zero on undeclared growth or taint (so it already works as a CI gate before signing exists).
- `eval/run_eval.py` prints a detection table (skillfuzz vs single-run) and writes `coverage_curve.csv` on the small synthetic set.
- (Signing and installer-hook checks are deferred along with section 4.1F.)

**Honest caveat on results from this session:** numbers on my own synthetic dormant set using the offline agent show the *mechanism* works. They are **not** evidence for the paper's claim. That needs the LLM agent plus independent or real samples.

---

## 10. Ethics and handling
No real credentials anywhere; no egress from the sandbox; `.invalid` exfil domain; real malware only in a throwaway VM later; disclose new findings to marketplaces and Snyk/Koi before publishing; dormant generator stays inert, and the release policy for trigger types is documented in SECURITY.md.

## 11. Extensions (not now)
MCP servers and browser extensions as targets; GitHub Action that re-attests on PR; a public skill transparency log (Trillian/Rekor-style append-only fingerprints); eBPF recorder; Firecracker backend; LLM semantic coverage of SKILL.md.
