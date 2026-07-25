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

## Trademark and non-affiliation notice (required, do not weaken)

This project is **not** created, reviewed, distributed, endorsed, or
sponsored by Nutanix, Inc. "Nutanix," "AHV," "Prism," "Prism Central," "NCC,"
and other referenced product/service names are trademarks of Nutanix, Inc.,
used here only descriptively to identify what this tool interoperates with.

- The canonical notice text lives in `NOTICE.md` at the repo root. Every
  other file quotes or links it — never restate it in different wording,
  since inconsistent phrasing is itself a risk here.
- `README.md` must carry the short one-line form near the very top, above
  the fold, not buried in a footer.
- `CLIENT-GUIDE.md`, `app/docs/Nutanix_STIG_Hardening_Client_Execution_Guide.docx`,
  and `app/docs/Nutanix_Security_Guide_7.5_Control_Crosswalk.md` must each
  carry the full notice near the top — these are the documents most likely
  to be handed to a client or auditor and mistaken for Nutanix-authored
  material.
- Any new user-facing document must carry the notice before being merged.
- Never remove, soften, or reword this notice, and never write copy
  elsewhere (marketing language, PR descriptions, commit messages) that
  could read as Nutanix affiliation or endorsement.

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

**Current state, so agents don't repeat a known mistake:** `.github/workflows/release.yml`
already exists and works, but it is a `push: tags: "v*"` trigger — it only
runs when a matching tag is pushed to GitHub. As of this writing the repo has
**zero tags**, so it has never run once. Running
`python scripts/build_release.py` locally, or in CI on a normal PR, only
*validates* that the build works — it does not publish anything, does not
create a Release, and gives the README nothing to link to. Do not report a
release task as complete until a tag has actually been pushed and a Release
with all three archives is visible on GitHub.

**One-time human prerequisite (an agent cannot do this step):** `release.yml`
hard-fails unless the repository variable `DOCS_COPYRIGHT_REVIEWED` is set to
`true`. A human repository owner sets this, after completing
`PUBLIC-RELEASE-CHECKLIST.md`'s bundled-document review, at Settings →
Secrets and variables → Actions → Variables. If it isn't set yet, tell the
human that directly instead of trying to work around it.

**To actually cut a release, in order:**
1. Bump `control_center.VERSION`, move `RELEASE-NOTES.md`'s `# Unreleased`
   items into a new numbered section, and open this as its own PR.
2. Once that PR is merged to `main`, tag the merge commit and push the tag —
   this is the step that was skipped before:
   ```bash
   git checkout main && git pull
   git tag -a vX.Y.Z -m "Nutanix STIG Control Center vX.Y.Z"
   git push origin vX.Y.Z
   ```
3. Confirm, via the Actions tab or `gh run list --workflow=release.yml`, that
   the run succeeded, and confirm the tag's Release page actually lists the
   Windows/macOS/Linux archives and `SHA256SUMS.txt`.
4. Only after step 3 is verified, open a second PR updating `README.md` to
   link downloads to `https://github.com/John-Isdell/Nutanix-STIG-CC/releases/latest`
   (this URL always resolves to the newest release, so it never needs a
   per-release edit). Merge it.

- Bump **patch** for fixes with no behavior change to the public
  install/CLI/API surface, **minor** for backward-compatible additions,
  **major** for anything an existing operator's install/scripts/automation
  would break against.
- Use Conventional Commits (`fix:`, `feat:`, `feat!:`/`BREAKING CHANGE:`) in
  commit messages and PR titles so the version bump can be computed
  automatically instead of guessed.
- Longer term, every PR merged to `main` should still trigger CI (lint +
  tests) and a validation build of the three platform archives as workflow
  artifacts, so a working package is proven on every merge — but only a
  pushed tag turns that into a real, checksummed GitHub Release, per the
  steps above.
- **Non-negotiable:** the `DOCS_COPYRIGHT_REVIEWED` gate must keep applying
  to every published Release, no matter how frequently releases are cut.
  Increasing release frequency must never become a way to quietly bypass
  that human review, and an agent must never set that variable itself.

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
- A task involving a package, release, or README link is not done when a
  local command exits successfully. It is done when you have confirmed,
  directly on GitHub (Actions run status, the Release page, or the merged
  file), that the artifact/link actually exists there. State that
  confirmation explicitly when reporting the task as complete.
- Keep each PR focused on one reviewable change (see `CONTRIBUTING.md`).
- Include the exact validation commands you ran and their results in the PR
  description.
- Use only sanitized test data — never real cluster addresses, credentials,
  or customer information, in code, tests, fixtures, or commit messages.
