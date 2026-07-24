# Nutanix STIG Control Center 1.1.0 — Universal Edition

Release date: July 23, 2026

## Changes from 1.0

- Removed the legacy third-party launcher as an installation and runtime
  dependency.
- Added one shared Python controller for Windows, macOS, and Linux.
- Added native click-to-install/start/stop/repair entry points.
- Added automatic first-start installation into an isolated virtual
  environment.
- Added background service startup, automatic browser opening, status,
  restart, diagnostics, and evidence-preserving repair.
- Added a random service-instance identity so status and stop actions target
  only the exact local service started by this package.
- Preserved all existing cluster safety gates, reports, rollback behavior,
  Nutanix v4 identity support, and one-cluster isolation.

## Portability boundary

The source distribution is operating-system agnostic but requires a compatible
64-bit Python 3.10+ installation. A single compiled executable cannot be
universal across Windows, macOS, Linux, and CPU architectures; this package
uses the standard Python runtime to remain portable and auditable.
