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

## Credential handling

Credentials are supplied to the local service for the current test or
operation. The service passes SSH secrets to the short-lived execution process
through its environment or a permission-restricted temporary file and deletes
temporary key/configuration files when the operation finishes.

The service log, saved configuration, operation metadata, audit history, and
evidence packages exclude entered credentials. The operating system and other
processes running as the same user remain part of the trust boundary.

## Network exposure

The controller starts the service on an available `127.0.0.1` port. The server
also validates Host and Origin headers. Do not modify the package to bind to
`0.0.0.0`, publish the port, or place it behind a remote-access gateway.

## Reporting security issues

Stop the service, preserve the service log and evidence, record the exact
version and operating system, and route the issue through the client's approved
security-response process.
