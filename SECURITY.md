# Security and responsible-use notes

## What the sandbox does and does not guarantee

| Property | Status |
|---|---|
| No packet leaves the sandbox | **Strong.** The network namespace contains only loopback. DNS and HTTP(S) are answered by an in-sandbox sinkhole. Verified by `tests/test_sandbox_e2e.py::test_no_egress_...` |
| Host filesystem is not visible | **Good.** The skill runs in a chroot on a tmpfs root built from read-only bind mounts. Verified by tests (`test_host_files_are_not_visible`, `test_system_paths_are_read_only_on_the_host`). |
| Resistance to kernel / namespace escapes | **None claimed.** This is rootless namespaces plus chroot, not a VM. |
| Hidden from malware that checks for sandboxes | **Partial.** Lived-in home, history, backdated git log, a believable hostname. Samples that check CPU count, DMI strings, uptime or timing will still notice. Not measured yet. |

**Do not run real collected malware in this sandbox on a machine you care about.** Use a throwaway VM with no
credentials and no network (the network guarantee above still applies, but the isolation boundary is weaker than
a hypervisor). A Firecracker/VM backend is on the roadmap behind the same `Sandbox` interface.

## Honeytokens
Every credential in the sandbox is fake and carries a run-unique marker. None is, or resembles, a working secret.

## The dormant-trigger generator is dual use
`eval/dormant/dormant_gen.py` shows how to hide behaviour behind realistic triggers. In this repository every
payload is inert (it reads a honeytoken and POSTs it to `*.invalid`, which never resolves). Release policy:
publish trigger *types* and detection results; if real payloads are ever added, gate the generator.

## Handling real samples later
Sinkhole everything, never use real credentials, report newly found malicious skills to the marketplace and to
Snyk/Koi before publishing anything about them.

## Reporting a vulnerability in SkillFuzz
Open a private security advisory on the GitHub repository.

## Running externally-sourced samples

Loading real skill samples (`eval/real/load_clawhub.py clone`/`manifest`/`scan`) is read-only: it clones, reads
frontmatter, and runs the text-only static scanner. It never executes a downloaded skill. Running a real, unreviewed
sample through the SkillFuzz sandbox (`skillfuzz run`/`fuzz`) is a separate, deliberate step the operator takes —
in an environment whose execution policy they control — not something this loader or any automated pipeline should
do unattended.
