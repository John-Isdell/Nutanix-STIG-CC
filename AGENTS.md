# AGENTS.md

Instructions for AI coding agents (Codex, Claude Code, etc.) working in this
repository. This complements, not replaces, `README.md` (for operators),
`CONTRIBUTING.md` (for human contributors), `SECURITY.md`, and
`PUBLIC-RELEASE-CHECKLIST.md`. Read those before large changes. If anything
here conflicts with those files, treat the conflict as a bug and flag it
rather than silently picking one.

## Project overview

Nutanix STIG Control Center is a local, single-workstation tool that hardens
and audits Nutanix CVM/AHV/PCVM configuration against DISA STIG and the
Nutanix Security Guide, over SSH and the v4 Prism Central API. Python
3.10–3.12, FastAPI + paramiko backend, plain HTML/JS frontend, no Node.js or
containers required at runtime. Goal: be genuinely useful to the wider
Nutanix community — secure by default, simple to install, and easy to keep
current as Nutanix ships new AOS/AHV/Prism Central versions.

## Repo map

- `app/core/nutanix_stig_harden.py` — the hardening/audit engine: `PROFILES`
  (automated controls) and `MANUAL_CONTROLS` (deliberately non-automated,
  lockout/data-loss-risk items).
- `app/server.py`, `app/static/` — the Control Center web UI and API.
- `app/docs/Nutanix_Security_Guide_7.5_Control_Crosswalk.md` — maps every
  control to its Security Guide section and to `PROFILES`/`MANUAL_CONTROLS`.
- `control_center.py`, `supervisor.py`, `supervisor_setup.py` — the
  install/start/stop/repair lifecycle and the always-on localhost supervisor.
- `scripts/build_release.py` — builds the three platform archives.
- `tests/`, `.github/` — test suite and CI workflows.

## Build, lint, and test

Run from the repo root (see `CONTRIBUTING.md` for full setup):

```bash
ruff check --no-cache .
yamllint .github
python -m unittest discover -s tests -v
node --test tests/test_fingerprint_ui.js
python scripts/build_release.py --version X.Y.Z --output dist
```

Never point tests at a real Nutanix cluster; the suite uses mocks/local test
servers.

## Versioning and release policy

This project follows **Semantic Versioning 2.0.0** (`MAJOR.MINOR.PATCH`),
the versioning convention used across CNCF-hosted projects. It is tracked in
`control_center.VERSION`, `README.md`, and `RELEASE-NOTES.md`, and tagged as
`vMAJOR.MINOR.PATCH`.

- Bump **patch** for fixes with no behavior change to the public
  install/CLI/API surface, **minor** for backward-compatible additions,
  **major** for anything an existing operator's install/scripts/automation
  would break against.
- Use Conventional Commits (`fix:`, `feat:`, `feat!:`/`BREAKING CHANGE:`) in
  commit messages and PR titles so the version bump can be computed
  automatically instead of guessed.
- **Every PR merged to `main`** must trigger the existing CI (lint + tests)
  **and** a build of the three platform archives
  (`scripts/build_release.py`) so a working Windows/macOS/Linux package is
  produced from every merge, not just from a manually pushed tag. On a
  normal feature/fix merge, publish these as CI/workflow build artifacts.
  A dedicated, deliberate version-bump PR (bot-authored or maintainer-authored,
  e.g. a `release-please`-style flow) is what advances
  `control_center.VERSION`, moves `RELEASE-NOTES.md`'s `# Unreleased` section
  into a numbered release, creates the `vX.Y.Z` tag, and turns that merge's
  archives into a real, checksummed GitHub Release.
- **Non-negotiable:** the existing `PUBLIC-RELEASE-CHECKLIST.md` gate —
  publication fails closed until a human sets the `DOCS_COPYRIGHT_REVIEWED`
  repository variable to `true` — must keep applying to every published
  GitHub Release, no matter how frequently releases are cut. Increasing
  release frequency must never become a way to quietly bypass that human
  review.
- `README.md` must link to `https://github.com/John-Isdell/Nutanix-STIG-CC/releases/latest`
  for downloads (that URL always resolves to the newest release, so it never
  needs a per-release edit) rather than a version-specific link.

## Keeping pace with new AOS, AHV, and Prism Central versions

This is a core value of the project — treat "does this still match the
current Nutanix Security Guide and AOS/AHV/PC behavior" as an ongoing,
first-class task, not a one-time effort:

- When Nutanix publishes a new Security Guide version or a new AOS/AHV/PC
  release changes hardening-relevant behavior, update
  `app/docs/Nutanix_Security_Guide_7.5_Control_Crosswalk.md` first, then
  `PROFILES`/`MANUAL_CONTROLS` in `nutanix_stig_harden.py`.
- Default new or changed controls to `MANUAL_CONTROLS`, not `PROFILES`,
  unless there's clear evidence automating them carries no lockout/data-loss
  risk — this mirrors how existing controls were classified.
- Record every such change in `RELEASE-NOTES.md`, including which Nutanix
  version/guide revision motivated it.

## Security and safety boundaries (do not weaken these)

- Loopback-only (`127.0.0.1`) for both the supervisor and Control Center; no
  remote access, no multi-user hosting.
- One active cluster workspace and one operation at a time.
- No automatic SSH host-key trust; no credential (password, private key,
  passphrase, Prism Central API key) is ever persisted or logged.
- Apply requires a matching successful dry run, change ID, and typed
  confirmation; rollback requires its own preview and authorization.
- Audit log is append-only, hash-chained, and never contains literal
  keystrokes or typed confirmation phrases.
- Dry run treats cluster and PCVM targets independently — one target's
  connection failure must not hide a reachable target's results.

## Contribution workflow for agents

- Never commit or push directly to `main`. Create a branch, open a PR, and
  wait for human review/merge — this applies to every task, release
  automation included.
- Keep each PR focused on one reviewable change (see `CONTRIBUTING.md`).
- Include the exact validation commands you ran and their results in the PR
  description.
- Use only sanitized test data — never real cluster addresses, credentials,
  or customer information, in code, tests, fixtures, or commit messages.
