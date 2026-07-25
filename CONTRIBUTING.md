# Contributing to Nutanix STIG Control Center

Thank you for helping improve the project. Changes to security automation need
to preserve the same fail-closed behavior expected during a production
maintenance window.

## Before opening an issue

- Do not post passwords, private keys, API keys, customer names, cluster
  addresses, host keys, logs containing infrastructure details, or evidence
  archives.
- Use the repository security policy for vulnerabilities.
- Use a sanitized bug report for normal defects and a feature request for
  proposed behavior.

## Development setup

Use a supported 64-bit Python version. Python 3.10 and 3.12 are exercised in
continuous integration.

```text
python -m venv .venv
.venv/bin/python -m pip install -r app/requirements.txt -r requirements-dev.txt
```

On Windows, use `.venv\Scripts\python.exe` in place of `.venv/bin/python`.
Runtime and development dependencies are pinned. Update them intentionally and
include test evidence with dependency changes.

## Required checks

Run these checks from the repository root:

```text
ruff check --no-cache .
yamllint .github
python -m unittest discover -s tests -v
node --test tests/test_fingerprint_ui.js
python scripts/build_release.py --version 1.2.0 --output dist
```

The test suite uses mocks and local test servers. Do not point automated tests
at a real Nutanix cluster. Any authorized live validation must begin with a dry
run and follow the client change-control process.

## Safety expectations

Contributions must preserve these boundaries:

- bind the supervisor and Control Center only to loopback;
- operate on only one active cluster workspace at a time;
- never apply a change without a matching successful dry run and explicit
  authorization;
- verify remote changes through readback;
- refuse normal stop, restart, repair, or uninstall during an active cluster
  operation;
- never persist credentials or include them in logs, reports, tests, or
  fixtures;
- treat unsupported or unknown target state as non-actionable;
- preserve evidence and audit records during repair and uninstall.

Do not add remote access, multi-user hosting, automatic host-key trust,
credential storage, or a bypass for approval gates.

## Pull requests

Keep each pull request focused on one reviewable task. Include:

- new user-facing documents must include the canonical `NOTICE.md` short form
  before merge, and contributions must not add copy that could imply Nutanix
  affiliation, sponsorship, or endorsement;
- the problem and intended operator impact;
- security and failure-mode analysis;
- tests added or updated;
- exact validation commands and results;
- documentation or release-note updates when behavior changes.

Use sanitized test data only. By contributing, you agree that your contribution
is provided under the repository's license.
