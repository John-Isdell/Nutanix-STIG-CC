# Nutanix STIG Control Center Universal Edition

## Trademark and non-affiliation

Nutanix STIG Control Center is an independent, community-maintained project.
It is **not** an official Nutanix product or documentation set, is **not**
created, reviewed, or distributed by Nutanix, Inc., and is **not** endorsed,
certified, sponsored, or otherwise approved by Nutanix in any way.

"Nutanix," "AHV," "Prism," "Prism Central," "NCC," and any other Nutanix
product, service, or documentation name referenced in this repository are
trademarks or registered trademarks of Nutanix, Inc. in the United States
and other countries. They are used here solely for descriptive, nominative
purposes — to identify the systems this tool is designed to interoperate
with — and no sponsorship, affiliation, or endorsement by Nutanix is implied
or should be inferred.

References to the "Nutanix Security Guide," DISA STIG identifiers, control
numbers, section names, or summaries are provided for cross-reference and
convenience only. They are not a substitute for, and may not exactly match,
Nutanix's own current official documentation, release notes, or support
guidance — consult those directly for authoritative information.

This project is licensed under the terms in [LICENSE](LICENSE) and is
provided "as is," without warranty of any kind, by its contributors. Nutanix,
Inc. is not a contributor to, and bears no responsibility for, this project.

For Nutanix's official products, documentation, and support channels, visit
[nutanix.com](https://www.nutanix.com) and [portal.nutanix.com](https://portal.nutanix.com).

## Client installation and execution guide

Version 1.3.0 — July 24, 2026

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
4. Wait while the private Python environment is created, pinned dependencies
   are installed, and a per-user Startup-folder shortcut is created. No
   administrator or UAC approval is required.
5. The browser opens to `http://127.0.0.1:8765`.

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

Enable the v4.2 identity option, enter the **Prism Central** address, choose an
authentication method, and supply the approved CA bundle when system trust
does not recognize the Prism Central certificate. TLS verification cannot be
disabled.

The Control Center uses:

`GET /api/clustermgmt/v4.2/config/clusters`

If Prism Central returns multiple clusters, explicitly select the one cluster
for this workspace. The v4 call is read-only. Security changes remain on the
verified SSH/nCLI path.

#### Username and password

Select **Username / Password** to use HTTP Basic Authentication. This is the
compatible choice for Prism Central releases older than pc.2024.3 and remains
available on supported newer releases. The password is held only for the
identity request and is not saved.

#### API key on Prism Central pc.2024.3 or later

Use API-key authentication only with Prism Central pc.2024.3 or later and
supported AOS 7.0 or later clusters. API keys are attached only to dedicated
`SERVICE_ACCOUNT` users. Nutanix does not provide Prism Central UI controls to
create or manage these service accounts and keys, so an authorized Prism
administrator must use the IAM v4 REST API or an approved SDK. Use the exact
IAM schema advertised by the installed Prism Central release; the stable
pc.2024.3 workflow is:

1. Using an existing authorized administrator's Basic Auth credentials, create
   the service account:

   `POST /api/iam/v4.0/authn/users`

   The request identifies a dedicated username and sets
   `userType` to `SERVICE_ACCOUNT`. Record the returned user `extId`.
2. Create an API key for that service-account `extId`:

   `POST /api/iam/v4.0/authn/users/{extId}/keys`

   Give the key an organization-approved name and request the API-key type.
   **Capture and vault the generated key from this response immediately. The
   secret is returned once and cannot be retrieved later.**
3. Resolve the external identifier of a least-privilege role that can view the
   intended cluster inventory, then create an authorization policy:

   `POST /api/iam/v4.0/authz/authorization-policies`

   Bind the service-account identity to that role and only the required
   cluster/entity scope. The installed IAM schema requires the policy's role,
   identities, and entities. A new service account has no permissions until
   this policy exists; without it, the key may authenticate but the inventory
   request is denied.
4. In the Control Center, select **API Key**, enter the saved key, and click
   **Verify v4 identity**. The request sends the key only in:

   `X-Ntnx-Api-Key: <key>`

The API key is treated as an ephemeral credential. It is excluded from saved
configuration, operation metadata, service/audit logs, and evidence packages,
and it is cleared when the cluster workspace is closed. The Control Center
does not include a bootstrap button for the three IAM calls above because that
would create persistent service-account, key, and authorization-policy
objects. Perform that provisioning only through the client's approved IAM
change process.

Authoritative references: [Nutanix IAM API reference][iam-api],
[Cluster Management v4.2 API reference][cluster-api], and
[Cluster Management authentication configuration][cluster-auth].

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

Cluster and PCVM connection attempts are independent during a dry assessment.
If one target is unreachable, rejects authentication, or raises an unexpected
target-local error, the other target is still attempted. The operation
finishes with issues and shows a separate status for each target. The failed
target entry preserves the specific SSH error and points to:

- `reports/stig_report_<run_id>.txt`
- `reports/stig_report_<run_id>.json`
- `logs/stig_run_<run_id>.csv`

These files are inside that operation's local evidence folder and are also
included in the downloadable evidence ZIP. A partial dry assessment never
unlocks Apply.

Apply remains conservative: a connection or remote-execution exception stops
later targets and records them as not attempted. Changing Apply to skip a
failed target requires a separate client-approved safety decision.

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

### 9. Audit ledger

The Audit page records security-relevant actions rather than keyboard input.
It never records literal keystrokes, passwords, private keys, passphrases, API
keys, session cookies, request tokens, or typed confirmation phrases.

Each entry includes a pseudonymous local-session actor ID, UTC timestamp,
source, action, target host, result, sequence number, previous-entry hash, and
entry hash. The ledger covers session creation, host-key inspection and trust,
SSH and v4 connection tests, configuration activation, operation requests and
completion, Apply and rollback approvals, rejected actions, manual-control
updates, audit-setting changes, and workspace closure.

Use the page to filter by target host, action, result, and UTC date range.
**Export JSON** retains the complete structured entries and integrity result;
**Export CSV** provides a review-friendly table. A green **Hash chain
verified** status means the retained entries, sequence, and protected tail
state agree. Stop security work and preserve `app/data` if the page reports an
integrity alert.

The default retention is 3,650 days with monthly file rotation. An authorized
operator can select daily rotation and retention from 365 through 7,300 days.
Rotation does not discard records. Retention removes only expired, completed
rotation files and preserves a chain anchor identifying the pruned prefix.
Each operation evidence ZIP includes the complete retained audit trail for
that target and a separate integrity/settings report.

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

The audit ledger is under `app/data/audit` as rotated `audit-*.jsonl` files,
with `chain-state.json`, optional `chain-anchor.json`, and `settings.json`.
These files form one evidence set; do not edit, truncate, rename, or selectively
restore them. The first access migrates a legacy `app/data/audit.json` array
without applying the former 500-entry cap.

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
- Independent per-target dry-run connection and failure reporting.
- CVM, AHV, and PCVM change planning.
- Approval-gated supported security writes.
- Optional supported syslog configuration.
- Post-change readback.
- Rollback manifests and rollback preview.
- Text, JSON, CSV, baseline, post-change, console, and evidence reports.
- Manual-control tracking.
- Optional read-only Nutanix v4.2 cluster identity.

## Nutanix Security Guide 7.5 control coverage

The following cross-reference is based on the Nutanix Security Guide 7.5
sections for [AHV Security Hardening][ahv75], [CVM Security Hardening][cvm75],
and [PCVM Security Hardening][pcvm75]. The target's own
`ncli ... help` output remains authoritative for the installed release. An
automated profile skips and reports any parameter the target does not
advertise.

| Guide control | Scope | Control Center treatment | Source section |
|---|---|---|---|
| AIDE | AHV, CVM, PCVM | Enabled by STIG Standard, STIG High, and DoDIN APL when supported. | [AHV][ahv75], [CVM][cvm75], [PCVM][pcvm75] |
| User and kernel core dumps | AHV, CVM, PCVM | Disabled by automated profiles to reduce sensitive dump exposure. A Nutanix Support debugging exception must be handled manually. | [AHV][ahv75], [CVM][cvm75], [PCVM][pcvm75] |
| High-strength password policy | AHV, CVM, PCVM | Enabled by automated profiles. Recovery and service-account effects still require client validation. | [AHV][ahv75], [CVM][cvm75], [PCVM][pcvm75] |
| SSH banner parameter | AHV, CVM, PCVM | The parameter is enabled automatically. Banner-file content must be customized and verified manually on every applicable host or VM. | [AHV][ahv75], [CVM][cvm75], [PCVM][pcvm75] |
| iTLB Multihit mitigation | AHV | Enabled by STIG High and DoDIN APL when advertised; performance acceptance remains a client decision. | [AHV][ahv75] |
| Retbleed mitigation | AHV | Enabled by STIG High and DoDIN APL when advertised; performance acceptance remains a client decision. | [AHV][ahv75] |
| Memory poison | AHV | Enabled by STIG High and DoDIN APL when advertised. | [AHV][ahv75] |
| Page poison | CVM, PCVM | Enabled by STIG High and DoDIN APL when advertised. | [CVM][cvm75], [PCVM][pcvm75] |
| Slub debug | CVM, PCVM | Enabled by STIG High and DoDIN APL when advertised; performance must be validated. | [CVM][cvm75], [PCVM][pcvm75] |
| Processor mitigations | CVM, PCVM | Enabled by STIG High and DoDIN APL when advertised; release-specific aliases are discovered at runtime. | [CVM][cvm75], [PCVM][pcvm75] |
| SSH security level, IP restriction, and SSH allowlist | CVM and supported PCVM releases | Manual only. Stage the smallest required allowlist and test console recovery before restricting access. | [CVM][cvm75], [PCVM][pcvm75] |
| DoDIN additional controls | CVM, PCVM | Manual only. The guide states that this mode can permanently lock an account after an incorrect password, so it is not sent by an unattended profile. | [CVM][cvm75], [PCVM][pcvm75] |
| fapolicy | AHV, CVM, PCVM | Manual only. Enable solely under an approved organization policy after workload compatibility and performance testing. | [AHV][ahv75], [CVM][cvm75], [PCVM][pcvm75] |
| Security-configuration Lock Status | CVM, PCVM | Manual finalization only. Enabling this setting requires Nutanix Support to unlock it. | [CVM][cvm75], [PCVM][pcvm75] |
| Enable user core dump field | AHV | Manual disposition. The 7.5 AHV section shows this field in configuration output but does not define a hardening command, so the Control Center records the raw value and does not guess. | [AHV][ahv75] |

The AHV guide also states that AOS 7.5 with AHV 11.0 uses a RHEL 9-based
hypervisor that does not currently meet the RHEL 9 STIG, while the AOS 7.5 CVM
remains RHEL 8-based. The Control Center cannot remove that product-level
boundary. For strict STIG requirements, the platform owner must select a
vendor-supported release combination accepted by the authorizing official.

[ahv75]: https://portal.nutanix.com/page/documents/details?targetId=Nutanix-Security-Guide-v7_5:sec-ahv-configuration-c.html
[cvm75]: https://portal.nutanix.com/page/documents/details?targetId=Nutanix-Security-Guide-v7_5:sec-controller-virtual-machine-t.html
[pcvm75]: https://portal.nutanix.com/page/documents/details?targetId=Nutanix-Security-Guide-v7_5:sec-pcvm-configuration-c.html
[iam-api]: https://developers.nutanix.com/api-reference?namespace=iam&version=v4.0
[cluster-api]: https://developers.nutanix.com/api-reference?namespace=clustermgmt&version=v4.2
[cluster-auth]: https://developers.nutanix.com/api/v1/sdk/namespaces/main/clustermgmt/versions/v4.2/languages/python/configuration.html

## What remains manual

- Cluster lockdown and tested key-only recovery.
- Release eligibility for the required STIG baseline, including the documented
  AOS 7.5/AHV 11.0 RHEL 9 limitation.
- Credential rotation, vaulting, and break-glass validation.
- SSH banner-file content and per-node visual verification.
- SSH security levels, IP restrictions, minimal allowlists, and console
  recovery.
- DoDIN additional account-lock behavior, fapolicy, and final
  security-configuration Lock Status.
- The AHV `Enable user core dump` field when advertised, until the installed
  release's authoritative command reference defines an approved treatment.
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
