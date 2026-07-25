# Security and deployment notes

## Intended deployment

Run one extracted copy on one authorized administrative workstation. The
service is local-only and is not designed for multi-user, shared-server,
internet-facing, reverse-proxy, or cloud-hosted use.

## Workstation controls

- Restrict the package and `app/data` to authorized administrators.
- Use full-disk encryption and endpoint protection.
- Keep Python and the operating system patched.
- Route the workstation through the authorized management network.
- Back up and retain evidence under client policy.
- Validate downloaded-package SHA-256 before installation.

## Release integrity

Each tagged GitHub Release contains separate Windows, macOS, and Linux source
archives plus `SHA256SUMS.txt`. The release workflow builds from the tagged
commit, uses an explicit file allowlist, rejects runtime, evidence, test, and
repository-metadata paths, verifies the installer inventory and permissions,
and computes SHA-256 after archive creation.

Verify the selected archive against the checksum file before extraction. A
matching digest detects a changed or incomplete download relative to that
release; it does not establish that the source is suitable for a particular
environment. Retain the tag, archive, checksum file, and approval record with
the client change evidence.

## Credential handling

Credentials are supplied to the local service for the current test or
operation. The service passes SSH secrets to the short-lived execution process
through its environment or a permission-restricted temporary file and deletes
temporary key/configuration files when the operation finishes. Prism Central
API keys are sent only in the `X-Ntnx-Api-Key` request header for the selected
read-only v4 identity check.

The service log, saved configuration, operation metadata, audit history, and
evidence packages exclude entered passwords, private keys, passphrases, API
keys, and uploaded CA material. The operating system and other processes
running as the same user remain part of the trust boundary.

## Network exposure

The always-on supervisor binds only to `127.0.0.1:8765`. It starts the separate
Control Center service on an available `127.0.0.1` port. Both services validate
loopback clients and Host headers; state-changing calls also validate
request-verification tokens and Origin when present.

The supervisor can install/repair dependencies and control local processes, so
the extracted folder, the operating-system login account, and other processes
running as that user are part of the trust boundary. Do not modify either
service to bind to `0.0.0.0`, publish the ports, place them behind a
remote-access gateway, or weaken the request checks.

The supervisor redacts credentials embedded in package-repository URLs before
showing or saving installation progress.

## Operating-system registration

- Windows uses a least-privilege, interactive per-user Scheduled Task at login.
- macOS uses a per-user launchd agent under `~/Library/LaunchAgents`.
- Linux uses a `systemd --user` service.

Windows requires one administrator-approved UAC prompt during initial
registration. The installed task uses the `LIMITED` run level, and its task ACL
allows the installing user to manage or uninstall it later without granting the
supervisor elevated runtime privileges.

Uninstall removes this registration and stops the application. It preserves
`.runtime` and `app/data` so evidence is not silently destroyed.

## Reporting security issues

Stop the service, preserve the service log and evidence, record the exact
version and operating system, and route the issue through the client's approved
security-response process.

Do not disclose vulnerabilities, exploit details, credentials, customer
information, cluster addresses, host keys, logs, or evidence through a public
issue. Use the repository's private owner contact or private vulnerability
reporting when available, then follow the affected client's disclosure and
incident-response requirements.
