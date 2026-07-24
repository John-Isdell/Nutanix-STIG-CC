# Nutanix STIG Hardening Script Verification Report

Date: July 23, 2026

Reviewed script: `nutanix_stig_harden.py`

Reviewed runbook: `Nutanix_STIG_Hardening_Runbook-ji.docx`
Validated release: script version 1.1

## Executive result

The original script had a sound high-level design, but it was not ready for production apply because successful `ncli` execution was treated as proof of compliance, rollback apply could bypass interactive confirmation, and several missing/failed read paths could fail open.

Version 1.1 corrects those issues. It is safe for a client-controlled dry run and lab/pilot execution. It has been syntax-checked and exercised through a real SSH transport against a stateful mock CVM that implements the required `ncli` command flow.

It has **not** been executed against the client's Nutanix cluster because no target address, approved account, host-key fingerprint, maintenance window, or change authorization was supplied. Production readiness therefore requires the client dry run and acceptance procedure in the accompanying execution guide.

The script automates part of the hardening runbook. It does not, by itself, certify STIG compliance.

## Requirements coverage

| Requirement | Result |
|---|---|
| Dry run by default | Pass. Remote setting commands require `--apply`. |
| No remote changes without administrator agreement | Pass. Interactive apply requires typing `APPLY`; unattended apply requires a recorded `--approval-id`. Rollback apply uses the same gate. |
| Connect from a local admin host to CVM/PCVM | Pass in mock integration test. The script uses Paramiko over TCP/22 (or configured port), opens separate cluster and PCVM sessions, and executes commands through a login shell. |
| Strict SSH identity verification | Pass. Unknown host keys are rejected by default; auto-add is an explicit exception. |
| Baseline before change | Pass. Raw and parsed security state plus supporting cluster output are saved before writes. |
| Apply only a known delta | Pass. Current values are compared with the selected profile and only differences are issued. |
| Release-specific command safety | Pass. Parameter names are discovered from the target's `ncli ... help`; known aliases are selected only when advertised. Unknown discovery fails closed. |
| Confirm changes with tests | Pass. Each successfully issued security parameter is re-read until verified or the verification window expires. Syslog server/module presence is also re-read. |
| Full report | Pass. Each run produces CSV, text, and JSON reports; apply runs also produce post-change snapshots and rollback manifests when settings changed. |
| Report remaining work | Pass. Skipped/unverified items and the manual or externally validated controls are listed. |
| Rollback | Pass for automated security parameters. Reverted values are also read back. Syslog and manual control rollback remain release-specific manual procedures. |

## Material corrections made

1. Added post-change read-back verification and nonzero failure behavior when the requested value is not observed.
2. Added post-change snapshots and persistent text/JSON reports.
3. Applied the interactive confirmation gate to rollback as well as forward changes.
4. Required a CAB/change identifier for all unattended apply runs.
5. Changed SSH host-key handling from automatic trust to strict rejection by default.
6. Made failed version, cluster-service, fault-tolerance, DNS/NTP, NCC, baseline, and parameter-discovery checks fail closed.
7. Prevented writes when the current value cannot be read, because a safe rollback value would be unavailable.
8. Added target and configuration validation so an empty target set cannot report false success.
9. Prevented `REPORT_ONLY` from being combined with `--apply`.
10. Added input validation for syslog server name, IP address, port, protocol, and modules.
11. Added syslog server/module read-back checks.
12. Added SNMPv3-only to the standard STIG profile, matching the runbook.
13. Added release-specific aliases for processor/kernel mitigations and DoDIN naming, selected only from target help.
14. Hardened rollback manifest handling so command names are accepted only from the script's parameter allowlist.
15. Added Paramiko 4 compatibility for private-key loading.
16. Corrected exit-code behavior so preflight failures return code 1 and connection/remote failures still generate reports.

## Validation performed

### Local/static checks

- Python compilation: pass.
- `--version`: pass (`1.1`).
- `--help`: pass.
- Sample INI generation: pass.
- Paramiko 4.0 import and SSH operation in the isolated test environment: pass.

### SSH integration and safety tests

Seven automated tests passed:

1. Unknown current values are never placed in an apply plan.
2. Release-specific CLI aliases are detected and the corresponding output labels are parsed.
3. A real Paramiko SSH dry run reaches a mock CVM, runs discovery/preflight/baseline commands, and sends no setting commands.
4. A real Paramiko SSH apply changes mock CVM/AHV state, records the approval ID, and verifies every applied value by read-back.
5. Unattended apply without an approval ID is rejected before any SSH connection.
6. Failed health preflight blocks every setting command.
7. A setting command that reports success but does not change state produces verification failures and exit code 2.

### Client guide checks

- DOCX structure: valid.
- Heading/list structure: present.
- Exact table geometry: pass for all tables.
- Accessibility audit: 0 high, 0 medium, 0 low findings.
- Visual DOCX rendering could not be performed in this workspace because LibreOffice/Word was unavailable. The client should open the guide in Microsoft Word and perform a final visual review before controlled publication.

## Authoritative command cross-check

The current Nutanix Security Guide documents the CVM, AHV, and PCVM security-parameter command families used by the script, including AIDE, high-strength passwords, the DoD banner, SNMPv3-only, SCMA schedules, core settings, PCVM controls, and release-dependent mitigation labels:

https://www.nutanix.com/content/dam/nutanix/documents/certifications/nutanix-security.pdf

The Nutanix Acropolis Advanced Administration Guide documents the `rsyslog-config` command family, TCP/UDP forwarding, and the TCP requirement for RELP:

https://www.nutanix.com/content/dam/nutanix/documents/certifications/advanced-admin-aos.pdf

Because exact options vary by installed release, the target's own `ncli ... help` output remains the final authority during execution.

## Residual limitations and required client validation

- No live Nutanix target was contacted in this review.
- The client must validate the dry-run output on the exact AOS, AHV, and Prism Central builds in scope.
- The script automates security parameters and optional cluster-side syslog configuration; it does not automate cluster lockdown, default credential rotation, SSH allowlists/security level, LDAPS/RBAC/CAC/PIV, certificate replacement, encryption/KMS, network controls, or external SCAP work.
- Syslog delivery to the SIEM must be tested end to end. The security-parameter rollback manifest does not remove syslog configuration.
- Scale-out Prism Central and per-node/host propagation must be checked on every applicable VM or host.
- Full NCC, SCC/SCAP, STIG Viewer, functional regression, POA&M, evidence-package, and ISSO acceptance activities remain required.
- A zero exit code means the automated run had no operational failure. It is not a compliance certification; skipped and manual items still require disposition.

## Production decision

Approved for:

- client dry run;
- review of baseline, plan, skipped items, and reports;
- lab or pilot apply using the documented approval and recovery controls.

Production apply should occur only after:

- the client dry run is clean and approved;
- target host keys are independently verified;
- NCC/health/recovery prerequisites are satisfied;
- the maintenance window and rollback authority are active;
- the exact profile and residual manual controls are accepted by the ISSO and platform owner.
