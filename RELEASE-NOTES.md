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

## Portability boundary

One initial installer double-click or launch is required because a local
process must exist before a webpage can be served. After installation, routine
lifecycle actions are available in the supervisor page.
