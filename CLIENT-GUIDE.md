# Nutanix STIG Control Center Universal Edition

## Client installation and execution guide

Version 1.2.0 — July 24, 2026

## Purpose

The Universal Edition provides the complete local Nutanix STIG assessment,
hardening, verification, rollback, and reporting interface. The same package
runs on Windows, macOS, and Linux through a standard Python 3.10+ runtime and a
small always-on localhost supervisor.

The application must run on an authorized administrative workstation that can
reach the selected cluster CVM virtual IP. It does not run in a public cloud or
on a remotely accessible web server.

## Prerequisites

- A supported 64-bit operating system and 64-bit Python 3.10 or newer.
- A protected, writable local installation folder.
- Approved management-network access to:

  - CVM cluster virtual IP over TCP 22;
  - PCVM over TCP 22 when that scope is selected;
  - Prism Element or Prism Central over TCP 9440 when optional v4 identity is
    selected.

- Authorized SSH and optional Prism API accounts.
- Independently obtained CVM and PCVM SSH host-key fingerprints.
- Approved change, backup/recovery path, console access, and maintenance
  window.
- Internet/internal package repository access during first installation, or a
  prepared platform-compatible `wheelhouse`.

## Obtain and verify the release

Download the platform-specific archive and `SHA256SUMS.txt` from the same
GitHub Release:

- Windows: `Nutanix-STIG-Control-Center-VERSION-windows.zip`
- macOS: `Nutanix-STIG-Control-Center-VERSION-macos.zip`
- Linux: `Nutanix-STIG-Control-Center-VERSION-linux.tar.gz`

On macOS, verify the selected file with:

```text
grep "ARCHIVE-NAME" SHA256SUMS.txt | shasum -a 256 -c -
```

On Linux, run:

```text
grep "ARCHIVE-NAME" SHA256SUMS.txt | sha256sum -c -
```

On Windows, run:

```powershell
(Get-FileHash .\ARCHIVE-NAME -Algorithm SHA256).Hash.ToLower()
```

Compare the Windows result with the corresponding lowercase value in
`SHA256SUMS.txt`. Use only an archive whose checksum matches exactly.

## Install once

### Windows

1. Verify the delivered package SHA-256.
2. Extract the complete package into a protected user-controlled folder.
3. Double-click `Install-Control-Center.cmd`.
4. Approve the one-time Windows UAC prompt. Windows requires administrator
   approval to register the login task; the resulting task and application run
   with limited user privileges.
5. Wait while the private Python environment is created, pinned dependencies
   are installed, and a per-user Scheduled Task is registered.
6. The browser opens to `http://127.0.0.1:8765`.

### macOS

1. Verify the package SHA-256 and extract it.
2. Double-click `Install-Control-Center.command`.
3. If Gatekeeper blocks the downloaded script, right-click it and select
   **Open**. If executable permissions were not retained by the archive tool,
   run `chmod +x Install-Control-Center.command` once.
4. The installer registers a launchd user agent and opens the supervisor.

### Linux

1. Verify the package SHA-256 and extract it.
2. Run:

   ```bash
   chmod +x install.sh
   ./install.sh
   ```
3. The installer registers a `systemd --user` service and opens the
   supervisor.

The application creates `.runtime/venv` inside its extracted folder. No global
Python packages are installed.

True zero-click installation is not possible because a webpage cannot appear
until a local process serves it. The installer is the one initial double-click
or launch required on each workstation. All routine actions after installation
are available in the supervisor page.

## Pre-maintenance validation

Open `http://127.0.0.1:8765` and confirm:

- the status pill reads **Stopped** or **Running**, not **Error**;
- dependencies read **Ready**;
- automatic login start is registered;
- no cluster operation is currently active.

Diagnostics validate the local installation and service only. They do not
contact a Nutanix cluster. The advanced command
`python3 control_center.py doctor` provides the same local-only diagnostic
detail.

## Cluster workflow

### 1. Establish SSH trust

1. Enter the CVM virtual IP or DNS address, SSH port, and username.
2. Click **Inspect host key**.
3. Compare the SHA-256 fingerprint with the value obtained from the Nutanix
   console or another trusted channel.
4. Type the requested fingerprint suffix and click **Trust this key**.
5. Repeat for PCVM when that scope is used.

Unknown and changed host keys fail closed.

### 2. Test access

1. Select password or private-key authentication.
2. Enter the current credential.
3. Click **Test CVM connection**.
4. If PCVM is selected, choose whether it uses the same or a separate
   credential and test that connection.

The test runs `ncli cluster info` and makes no configuration changes.
Credentials are not saved.

### 3. Optional Nutanix v4 identity

Enable the v4.2 identity option, enter the Prism API information, and supply the
approved CA bundle when system trust does not recognize the Prism certificate.
TLS verification cannot be disabled.

The Control Center uses:

`GET /api/clustermgmt/v4.2/config/clusters`

If Prism Central returns multiple clusters, explicitly select the one cluster
for this workspace. The v4 call is read-only. Security changes remain on the
verified SSH/nCLI path.

### 4. Configure

1. Select STIG Standard, STIG High, DoDIN APL, or Report Only.
2. Select CVM, AHV, and optionally PCVM scopes.
3. Keep the full NCC health check enabled for an Apply-authorizing assessment.
4. Optionally configure syslog planning.
5. Click **Activate configuration**.

Only one cluster may be active. Non-secret settings are saved in `app/data`.

### 5. Dry assessment

1. Click **Run dry assessment**.
2. Review preflight, cluster health, baseline, supported-parameter discovery,
   planned values, skipped values, syslog, lockdown readiness, and remaining
   manual controls.
3. Download the evidence ZIP.

Dry assessment does not send security edit commands. Apply remains locked
unless a full-health dry run succeeds with a change-capable profile.

Changing the target, profile, scope, health, syslog, or verification
configuration invalidates the gate and requires a new dry run.

### 6. Apply

1. Confirm the exact dry-run plan matches the approved change.
2. Click **Review and Apply**.
3. Enter the change/approval ID.
4. Confirm recovery, maintenance-window, and authorization acknowledgements.
5. Type the displayed `APPLY <cluster>` phrase.
6. Approve the operation.
7. Review applied, verified, failed, and skipped counts.
8. Download and retain the evidence package.

Each supported change is read back from the target. A readback mismatch is
reported as failure.

### 7. Rollback

When an Apply operation creates a rollback manifest:

1. Click **Preview rollback** in its Audit row.
2. Review the no-change preview.
3. If authorized, open the rollback approval.
4. Enter the recovery change ID and acknowledgements.
5. Type `ROLLBACK <cluster>`.
6. Download the resulting evidence.

Rollback restores only values captured by the selected manifest. It cannot
undo work performed manually outside the program.

### 8. Manual controls and closure

Track the remaining controls, owner, evidence reference, and status in the
Audit page. Download final evidence, then use **Close workspace** before
selecting another cluster. Closing preserves prior evidence.

## Start, stop, restart, status, repair, and uninstall

Use only the supervisor page at `http://127.0.0.1:8765` for routine lifecycle
actions:

- **Install dependencies** verifies or installs the pinned private environment.
- **Start** launches the separate Control Center service.
- **Stop** stops only the verified Control Center process.
- **Restart** performs the verified stop/start sequence.
- **Open Control Center** opens the currently verified application URL.
- **Repair dependencies** stops the application and rebuilds
  `.runtime/venv`, with progress shown in the page.
- **Uninstall supervisor** removes the OS login registration and stops the
  application while preserving `.runtime` and `app/data`.

The status page polls every few seconds and does not require a page reload.
Stop, Restart, Repair, and Uninstall refuse to interrupt an active cluster
operation.

The command-line `stop --force-stop` option remains available only for an
authorized emergency because interrupting a change can leave partial remote
state.

## Data and evidence

Persistent local information is stored under:

`app/data`

This includes host trust, active non-secret settings, audit history, manual
control notes, run reports, rollback manifests, and evidence. Protect this
folder with workstation access controls, encryption, backup, and approved
retention.

The service log is:

`app/data/control-center-service.log`

The controller's non-secret local process record is:

`.runtime/service.json`

Supervisor state and registration records are:

- `.runtime/supervisor.json`
- `.runtime/supervisor-registration.json`
- `.runtime/supervisor.log`

## What the program automates

- Local CVM/PCVM connection and strict host-key trust.
- Preflight health, DNS, NTP, version, and cluster-state checks.
- Runtime discovery of release-supported security parameters.
- CVM, AHV, and PCVM change planning.
- Approval-gated supported security writes.
- Optional supported syslog configuration.
- Post-change readback.
- Rollback manifests and rollback preview.
- Text, JSON, CSV, baseline, post-change, console, and evidence reports.
- Manual-control tracking.
- Optional read-only Nutanix v4.2 cluster identity.

## What remains manual

- Cluster lockdown and tested key-only recovery.
- Credential rotation, vaulting, and break-glass validation.
- LDAPS, least-privilege RBAC, CAC/PIV, revocation, and identity policy.
- PKI issuance and certificate replacement.
- KMS/encryption decisions and escrow.
- Network segmentation, Flow policy, firewall, and upstream ACL work.
- External SCC/SCAP/STIG Viewer validation.
- Node-wide propagation checks after upgrades and cluster expansion.
- POA&M, ISSO review, and AO acceptance.

These controls remain manual because they depend on client identity systems,
PKI, KMS, network ownership, accredited tools, lockout recovery, or formal
authorization outside the Nutanix cluster.

## Important limitation

The Universal Edition is portable source software, not one compiled binary.
Windows, macOS, Linux, and different CPU architectures require different
native executables, so the package uses the standard Python runtime to stay
auditable and cross-platform.
