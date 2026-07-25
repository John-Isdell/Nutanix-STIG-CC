# Nutanix STIG Control Center 1.2.0 — Supervisor Edition

Release date: July 24, 2026

## Changes from 1.1

- Added a dependency-free supervisor fixed at `http://127.0.0.1:8765`.
- Added browser controls for dependency install/repair, Start, Stop, Restart,
  Open Control Center, live status, and Uninstall.
- Added background job progress polling for install and repair.
- Added per-user automatic startup through Windows Scheduled Task, macOS
  launchd, and Linux `systemd --user`.
- Added a one-time Windows UAC handoff for task registration while keeping the
  installed task at the limited-user run level.
- Reduced lifecycle launchers to one installer per operating system.
- Preserved active-operation stop protection, process identity verification,
  evidence, settings, host trust, and one-cluster isolation.
- Added pull-request CI for pinned-dependency lint, Python tests, and the
  browser regression on supported Python versions.
- Added deterministic Windows, macOS, and Linux release archives with an
  allowlisted inventory and generated SHA-256 checksums.
- Added Dependabot version monitoring, contribution guidance, issue and pull
  request templates, a code of conduct, and a mandatory human copyright review
  gate for bundled documents.
- Cross-referenced the Nutanix Security Guide 7.5 AHV, CVM, and PCVM
  hardening sections in the client guide.
- Added release-discovered AHV iTLB Multihit, Retbleed, and memory-poison
  mitigations to the high-assurance profiles.
- Moved DoDIN additional account-lock behavior and fapolicy to explicit manual
  controls, and documented security Lock Status, SSH restrictions, banner
  content, and the AOS 7.5/AHV 11.0 STIG boundary.
- Made cluster and PCVM dry-run attempts independent so a target-local
  connection or execution failure is reported without suppressing a reachable
  target.
- Added per-target completion/failure cards and exact text, JSON, and CSV
  evidence references while retaining fail-stop Apply behavior.
- Added Prism Central pc.2024.3+ service-account API-key authentication for
  the read-only v4.2 identity check using `X-Ntnx-Api-Key`, alongside existing
  username/password authentication.
- Added inline and client-guide instructions for the service-account, one-time
  key capture, and least-privilege authorization-policy workflow. Persistent
  IAM bootstrap changes remain intentionally manual.

## Portability boundary

One initial installer double-click or launch is required because a local
process must exist before a webpage can be served. After installation, routine
lifecycle actions are available in the supervisor page.
