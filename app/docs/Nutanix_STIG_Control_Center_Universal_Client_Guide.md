# Nutanix STIG Control Center Universal Edition

## Client installation and execution guide

Version 1.1.0 — July 23, 2026

## Purpose

The Universal Edition provides the complete local Nutanix STIG assessment,
hardening, verification, rollback, and reporting interface without requiring a
third-party launcher. The
same package runs on Windows, macOS, and Linux through a standard Python 3.10+
runtime.

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

## Install and start

### Windows

1. Verify the delivered package SHA-256.
2. Extract the complete package into a protected user-controlled folder.
3. Double-click `Start-Control-Center.cmd`.
4. On first start, wait while the private Python environment is created and the
   pinned dependencies are installed.
5. The default browser opens to a randomized localhost port.

To install before the maintenance window, run
`Install-Control-Center.cmd`, followed later by `Start-Control-Center.cmd`.

### macOS

1. Verify the package SHA-256 and extract it.
2. Double-click `Start-Control-Center.command`.
3. If Gatekeeper blocks the downloaded script, right-click it and select
   **Open**. If executable permissions were not retained by the archive tool,
   run `chmod +x *.command *.sh` once.

### Linux

1. Verify the package SHA-256 and extract it.
2. Run:

   ```bash
   chmod +x *.sh
   ./start.sh
   ```

The application creates `.runtime/venv` inside its extracted folder. No global
Python packages are installed.

## Pre-maintenance validation

Run the Status or diagnostic action:

- Windows: `Status-Control-Center.cmd`
- Any OS: `python3 control_center.py doctor`

Diagnostics validate the local installation and service only. They do not
contact a Nutanix cluster.

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

## Stop, restart, status, and repair

### Windows

- Stop: `Stop-Control-Center.cmd`
- Status: `Status-Control-Center.cmd`
- Repair: `Repair-Control-Center.cmd`

### macOS

- Stop: `Stop-Control-Center.command`
- Start/open again: `Start-Control-Center.command`

### Linux

- Stop: `./stop.sh`
- Status: `./status.sh`
- Start/open again: `./start.sh`

The common controller also supports:

```text
python3 control_center.py start|stop|restart|open|status|doctor|repair
```

Repair rebuilds `.runtime/venv` only. It preserves `app/data`.

Normal Stop and Repair refuse to interrupt an active cluster operation. The
command-line `stop --force-stop` option is reserved for an authorized emergency
because interrupting a change can leave partial remote state.

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
