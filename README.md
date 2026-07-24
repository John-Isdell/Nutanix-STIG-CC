# Nutanix STIG Control Center — Universal Edition

Version 1.1.0

This distribution runs directly on Windows, macOS, or Linux without a
third-party launcher,
Node.js, a web server, or a container platform. It uses the workstation's
Python installation only to create a private application environment. All
cluster operations still run through the same local browser interface and
verified hardening engine.

## Requirements

- Windows 10/11 or supported Windows Server, macOS, or a modern Linux
  distribution.
- 64-bit Python 3.10 or newer. Python 3.12 is the tested release.
- Network access from the workstation to the selected Nutanix CVM, optional
  PCVM, and optional Prism API.
- Internet or internal Python-package repository access during first
  installation, unless a compatible `wheelhouse` is supplied.
- A writable, access-controlled local folder. Do not install under a shared
  directory or a system folder such as `Program Files`.

No Python packages are installed globally. The private environment is created
under `.runtime/venv`.

## Fastest start

### Windows

1. Extract the complete package to a protected local folder.
2. Double-click `Start-Control-Center.cmd`.
3. The first start installs the private runtime, then opens the Control Center
   in the default browser.
4. Use `Stop-Control-Center.cmd` when finished.

`Install-Control-Center.cmd` may be run separately when software installation
must occur before the maintenance window.

### macOS

1. Extract the package.
2. Double-click `Start-Control-Center.command`.
3. If macOS blocks the downloaded script, right-click it and select **Open**,
   or run `chmod +x *.command *.sh` once from Terminal.
4. Use `Stop-Control-Center.command` when finished.

### Linux

```bash
chmod +x *.sh
./start.sh
```

Use `./stop.sh` when finished.

## Included controller actions

The standard-library `control_center.py` controller is the common
cross-platform implementation:

```text
python3 control_center.py install
python3 control_center.py start
python3 control_center.py stop
python3 control_center.py restart
python3 control_center.py open
python3 control_center.py status
python3 control_center.py doctor
python3 control_center.py repair
```

- **Start** automatically installs dependencies when needed.
- **Status** verifies the running service's unique instance identity before
  reporting it.
- **Stop** terminates only the locally verified instance recorded by the
  controller. It refuses to interrupt an active cluster operation.
- **Doctor** checks the local installation without contacting a Nutanix
  cluster.
- **Repair** stops the service and rebuilds only `.runtime/venv`. It preserves
  `app/data`, including evidence, audit history, host trust, and active cluster
  state.

## Security model

- The web service binds only to `127.0.0.1` on an available port.
- The server rejects non-loopback Host and Origin values.
- A random instance identifier ties status and stop actions to the exact
  service launched from this package.
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
- Controller state: `.runtime/service.json`
- Private Python environment: `.runtime/venv`
- Cluster evidence and settings: `app/data`

Run `control_center.py doctor` or double-click
`Status-Control-Center.cmd` on Windows before a maintenance window.

If startup fails:

1. Confirm 64-bit Python 3.10+ is available.
2. Move the extracted package to a writable local folder.
3. Confirm package repository/proxy/CA access.
4. Run Repair.
5. Review the service log.

Do not delete `app/data` during troubleshooting unless evidence and cluster
state have been formally exported and destruction is explicitly authorized.

For an authorized emergency interruption only, the controller supports
`stop --force-stop`. This can leave a remote change incomplete and must not be
used as a normal shutdown method.
