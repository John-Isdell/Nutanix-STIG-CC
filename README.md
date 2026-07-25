# Nutanix STIG Control Center — Universal Edition

Version 1.2.0

This distribution runs directly on Windows, macOS, or Linux without Node.js, a
container platform, or a separately installed web server. It uses the
workstation's Python installation to run a lightweight localhost supervisor and
create a private application environment. All cluster operations still run
through the separate Control Center browser interface and verified hardening
engine.

## Requirements

- Windows 10/11 or supported Windows Server, macOS, or a modern Linux
  distribution.
- 64-bit Python 3.10 or newer. Python 3.12 is the tested release.
- On Windows, a local administrator must approve the installer’s one-time UAC
  prompt so Windows can register the per-user Scheduled Task. The registered
  task and Control Center run with limited user privileges.
- Network access from the workstation to the selected Nutanix CVM, optional
  PCVM, and optional Prism API.
- Internet or internal Python-package repository access during first
  installation, unless a compatible `wheelhouse` is supplied.
- A writable, access-controlled local folder. Do not install under a shared
  directory or a system folder such as `Program Files`.

No Python packages are installed globally. The private environment is created
under `.runtime/venv`.

## One-time installation

### Windows

1. Extract the complete package to a protected local folder.
2. Double-click `Install-Control-Center.cmd` once.
3. Approve the one-time Windows UAC prompt. This approval is required only to
   register the per-user login task; the task itself runs with limited
   privileges.
4. The installer creates the private runtime, registers the Scheduled Task,
   starts the supervisor, and opens `http://127.0.0.1:8765`.

### macOS

1. Extract the package.
2. Double-click `Install-Control-Center.command` once.
3. If macOS blocks the downloaded script, right-click it and select **Open**,
   or run `chmod +x Install-Control-Center.command` once from Terminal.
4. The installer registers a per-user launchd agent and opens the supervisor.

### Linux

```bash
chmod +x install.sh
./install.sh
```

The installer registers and starts a `systemd --user` service and opens the
supervisor.

## Release downloads and checksums

Tagged releases publish three source packages:

- `Nutanix-STIG-Control-Center-VERSION-windows.zip`
- `Nutanix-STIG-Control-Center-VERSION-macos.zip`
- `Nutanix-STIG-Control-Center-VERSION-linux.tar.gz`

Download the matching platform package and `SHA256SUMS.txt` from the same
GitHub Release. Verify the archive before extraction. On macOS:

```text
grep "ARCHIVE-NAME" SHA256SUMS.txt | shasum -a 256 -c -
```

On Linux:

```text
grep "ARCHIVE-NAME" SHA256SUMS.txt | sha256sum -c -
```

On Windows:

```powershell
(Get-FileHash .\ARCHIVE-NAME -Algorithm SHA256).Hash.ToLower()
```

Compare the Windows result with the corresponding value in
`SHA256SUMS.txt`. A checksum proves file integrity relative to the release
manifest; it does not replace source review or an approved software-delivery
process.

True zero-click installation is not possible: a local process must be started
before a webpage can be served. Each workstation therefore needs exactly one
initial installer double-click or launch. After that, routine actions remain in
the browser.

## Supervisor controls

The always-on supervisor is fixed at `http://127.0.0.1:8765`. It is separate
from the main STIG Control Center process and provides:

- **Install dependencies** and **Repair dependencies**, with live progress;
- **Start**, **Stop**, and **Restart** for the separate Control Center service;
- **Open Control Center**, using its current verified local URL;
- a live Stopped / Starting / Running / Error status;
- **Uninstall supervisor**, which removes login registration while preserving
  evidence, settings, host trust, and the private runtime.

Stop, Restart, Repair, and Uninstall refuse to interrupt an active cluster
operation. The advanced command-line controller remains available for
diagnostics and an explicitly authorized emergency stop:

```text
python3 control_center.py status
python3 control_center.py doctor
python3 control_center.py stop --force-stop
```

## Security model

- The supervisor binds only to `127.0.0.1:8765`; the Control Center binds only
  to `127.0.0.1` on a separate available port.
- Both services reject non-loopback requests and untrusted Host/Origin values.
- Supervisor actions require a process-random request-verification token.
- A random instance identifier ties status and stop actions to the exact
  supervisor and Control Center processes launched from this package.
- The browser interface uses a local session cookie and request token for
  state-changing calls.
- SSH host keys are independently inspected and stored in the application's
  strict `known_hosts` file.
- Passwords, private keys, passphrases, Prism passwords, and uploaded CA
  material are not stored in configuration, audit history, or evidence.
- One active cluster workspace and one operation are allowed at a time.
- Apply requires a matching successful full-health dry run, change ID,
  acknowledgements, and cluster-specific typed confirmation.
- Rollback requires its own no-change preview and authorization.

The protected local data directory is:

```text
app/data
```

It contains evidence and infrastructure information. Protect and back it up
according to client policy.

## Offline or controlled package installation

For an isolated environment, place compatible Python wheels for the target
operating system and Python version in a folder named `wheelhouse` next to
`control_center.py`. The installer automatically uses:

```text
--no-index --find-links wheelhouse
```

A wheelhouse is platform-specific. Do not reuse Windows wheels on macOS/Linux
or wheels for a different CPU/Python version. In connected enterprises,
standard `PIP_INDEX_URL`, proxy, and certificate environment settings are
honored.

## What remains unchanged

The browser workflow remains:

1. Inspect and independently verify CVM/PCVM SSH host keys.
2. Test authenticated SSH and nCLI access.
3. Optionally verify cluster identity through TLS-validated Nutanix
   Cluster Management v4.2.
4. Select profile, scopes, full NCC, syslog, and verification settings.
5. Activate one cluster configuration.
6. Run dry assessment.
7. Review the plan and evidence.
8. Authorize Apply only after the matching dry run passes.
9. Download evidence and complete manual controls.
10. Preview and authorize rollback only when required.

## Important compliance boundary

The Control Center automates supported security parameters and evidence. It
does not itself confer STIG compliance and deliberately does not automate
cluster lockdown, organization-owned credential rotation, LDAPS/RBAC/CAC/PIV,
certificate replacement, KMS/encryption, upstream network controls, accredited
scanner results, POA&M handling, or ISSO/AO acceptance.

## Logs and troubleshooting

- Local service log: `app/data/control-center-service.log`
- Supervisor log: `.runtime/supervisor.log`
- Supervisor state: `.runtime/supervisor.json`
- Registration record: `.runtime/supervisor-registration.json`
- Controller state: `.runtime/service.json`
- Private Python environment: `.runtime/venv`
- Cluster evidence and settings: `app/data`

Open `http://127.0.0.1:8765` before a maintenance window. The page reports the
real dependency, registration, and Control Center process state without
contacting a Nutanix cluster. For command-line diagnostics, run
`python3 control_center.py doctor`.

If startup fails:

1. Confirm 64-bit Python 3.10+ is available.
2. Move the extracted package to a writable local folder.
3. Confirm package repository/proxy/CA access.
4. Click **Repair dependencies** in the supervisor.
5. Review the service and supervisor logs.

Do not delete `app/data` during troubleshooting unless evidence and cluster
state have been formally exported and destruction is explicitly authorized.

For an authorized emergency interruption only, the controller supports
`stop --force-stop`. This can leave a remote change incomplete and must not be
used as a normal shutdown method.

## Uninstall

Click **Uninstall supervisor** on the localhost supervisor page. This stops the
Control Center and removes the Scheduled Task, launchd user agent, or systemd
user service. It intentionally preserves `.runtime` and `app/data`.

After confirming evidence retention requirements, the extracted application
folder may be deleted manually. Do not delete `app/data` unless evidence
destruction is explicitly authorized.

## Contributing and releases

See [CONTRIBUTING.md](CONTRIBUTING.md) for development checks and safety
requirements, [SECURITY.md](SECURITY.md) for vulnerability handling, and
[PUBLIC-RELEASE-CHECKLIST.md](PUBLIC-RELEASE-CHECKLIST.md) for the mandatory
human and engineering gates before tagging a release.

Pull requests run pinned-dependency lint and tests on Python 3.10 and 3.12.
Version tags build the three platform archives, verify their inventory and
installer permissions, generate `SHA256SUMS.txt`, and attach the results to a
GitHub Release. Publication fails closed until a repository owner records the
required human bundled-document copyright review. Release automation does not
weaken the local-only, single-workstation threat model.

## License

This project is licensed under the [Apache License 2.0](LICENSE), including its
explicit patent grant.
