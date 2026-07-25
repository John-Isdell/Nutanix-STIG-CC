# AGENTS.md

Instructions for AI coding agents (Codex, Claude Code, etc.) in this repo.
Complements `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and
`PUBLIC-RELEASE-CHECKLIST.md` — read those, don't restate them here. Treat
any conflict with those files as a bug to flag, not resolve silently.

## Overview

Local, single-workstation tool that hardens/audits Nutanix CVM/AHV/PCVM
against DISA STIG and the Nutanix Security Guide, over SSH and the Prism
Central v4 API. Python 3.10–3.12, FastAPI + paramiko, plain HTML/JS
frontend, no Node.js or containers at runtime.

## Trademark notice (never weaken)

Not affiliated with, endorsed by, or created by Nutanix, Inc. Canonical text
lives in `NOTICE.md` — quote or link it, never reword it. Short form
required at the top of `README.md`; full form required at the top of
`CLIENT-GUIDE.md`, the Security Guide crosswalk doc, and the bundled
`.docx` guide. Every new user-facing doc needs it too.

## Repo map

- `app/core/nutanix_stig_harden.py` — engine: `PROFILES` (automated) /
  `MANUAL_CONTROLS` (deliberately manual, lockout/data-loss-risk items).
- `app/server.py`, `app/static/` — web UI and API.
- `app/docs/Nutanix_Security_Guide_7.5_Control_Crosswalk.md` — control-to-
  guide mapping.
- `control_center.py`, `supervisor.py`, `supervisor_setup.py` — lifecycle
  and the always-on localhost supervisor.
- `scripts/build_release.py` — platform archive builder.
- `tests/`, `.github/` — tests and CI.

## Build, lint, test

```bash
ruff check --no-cache .
yamllint .github
python -m unittest discover -s tests -v
node --test tests/test_fingerprint_ui.js
python scripts/build_release.py --version X.Y.Z --output dist
```

Never point tests at a real Nutanix cluster.

## Versioning and releases

SemVer 2.0.0 (`vMAJOR.MINOR.PATCH`), tracked in `control_center.VERSION`,
`README.md`, `RELEASE-NOTES.md`. patch = fix, minor = compatible addition,
major = breaking change. Use Conventional Commits (`fix:`, `feat:`,
`feat!:`) so bumps can be computed, not guessed.

`release.yml` only runs on a pushed `v*` tag — a local or CI build alone
publishes nothing. To cut a release: merge a version-bump PR (bumps
`control_center.VERSION`, moves `RELEASE-NOTES.md`'s `Unreleased` section
into a numbered one) → `git tag vX.Y.Z && git push origin vX.Y.Z` → confirm
on GitHub the Actions run succeeded and the Release page lists all three
archives plus `SHA256SUMS.txt` → only then update the README download link.

Non-negotiable: `release.yml` requires the repo variable
`DOCS_COPYRIGHT_REVIEWED=true`, set only by a human after the
`PUBLIC-RELEASE-CHECKLIST.md` review. Never set it yourself; rising release
frequency is never license to bypass it.

## Keeping pace with Nutanix releases

When AOS/AHV/Prism Central or the Security Guide changes, update
`app/docs/Nutanix_Security_Guide_7.5_Control_Crosswalk.md` first, then
`PROFILES`/`MANUAL_CONTROLS`. Default new controls to `MANUAL_CONTROLS`
unless there's clear evidence automating them is safe. Log the change in
`RELEASE-NOTES.md`.

## Safety boundaries (do not weaken)

- Loopback-only; no remote access, no multi-user hosting.
- One active cluster workspace/operation at a time.
- No automatic SSH host-key trust; never persist or log credentials.
- Apply requires a passing dry run, change ID, and typed confirmation;
  rollback requires its own preview and authorization.
- Audit log: append-only, hash-chained, never contains keystrokes or
  confirmation phrases.
- Dry run treats cluster/PCVM targets independently — one target's failure
  must not hide another's results.

## Contribution workflow

- Never push to `main`. Branch → PR → human merge, always.
- A release/package/README task is done only once verified live on GitHub —
  not when a local command exits 0.
- One reviewable change per PR; include exact validation commands and
  results.
- Sanitized test data only — no real hosts, credentials, or customer data
  anywhere in the repo.
