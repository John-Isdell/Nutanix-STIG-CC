# Nutanix Security Guide 7.5 Control Crosswalk

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

This project is licensed under the terms in [LICENSE](../../LICENSE) and is
provided "as is," without warranty of any kind, by its contributors. Nutanix,
Inc. is not a contributor to, and bears no responsibility for, this project.

For Nutanix's official products, documentation, and support channels, visit
[nutanix.com](https://www.nutanix.com) and [portal.nutanix.com](https://portal.nutanix.com).

Reviewed: July 24, 2026

This document maps the AHV, CVM, and PCVM hardening controls in the Nutanix
Security Guide 7.5 to the Nutanix STIG Control Center. It is an implementation
crosswalk, not a Nutanix publication and not a compliance certification.

## Authoritative sources

- [AHV Security Hardening][ahv75]
- [CVM Security Hardening][cvm75]
- [PCVM Security Hardening][pcvm75]

The installed target's `ncli ... help` output is the final authority for
release-specific parameter names. The Control Center discovers advertised
parameters before planning a write and reports unsupported controls as
skipped.

## Automated controls

| Control | Scope | Standard | High | DoDIN APL | Implementation |
|---|---|---:|---:|---:|---|
| AIDE | AHV, CVM, PCVM | Enable | Enable | Enable | `enable-aide` |
| User core dumps | AHV, CVM, PCVM | Disable | Disable | Disable | `enable-core` |
| Kernel core dumps | AHV, CVM, PCVM | Disable | Disable | Disable | `enable-kernel-core` |
| High-strength password policy | AHV, CVM, PCVM | Enable | Enable | Enable | `enable-high-strength-password` |
| SSH banner parameter | AHV, CVM, PCVM | Enable | Enable | Enable | `enable-banner`; content remains manual |
| iTLB Multihit mitigation | AHV | — | Enable | Enable | `enable-itlb-multihit-mitigation` |
| Retbleed mitigation | AHV | — | Enable | Enable | `enable-retbleed-mitigation` |
| Memory poison | AHV | — | Enable | Enable | `enable-memory-poison` |
| Page poison | CVM, PCVM | — | Enable | Enable | `enable-page-poison` |
| Slub debug | CVM, PCVM | — | Enable | Enable | `enable-slub-debug` |
| Processor mitigations | CVM, PCVM | — | Enable | Enable | Release-discovered processor/kernel alias |
| SCMA schedule | Supported scopes | Daily | Daily | Hourly | `schedule` |

Every automated change requires a trusted baseline value, explicit Apply
approval, successful command execution, and post-change readback. A parameter
that is absent from target help or baseline output is skipped rather than
guessed.

The profiles disable kernel core dumps even though the guide describes how to
enable them for diagnostics. This is the safer compliance default because
dumps can contain sensitive memory. A temporary support exception must be
authorized and handled outside an unattended profile.

## Manual and approval-gated controls

| Control | Scope | Why it is not automated | Required disposition |
|---|---|---|---|
| SSH banner file content | AHV, CVM, PCVM | The parameter does not create or approve organization-specific notice text on every node. | Back up, customize, and visually verify the applicable banner files before enabling the parameter. |
| SSH security level | CVM, PCVM | An incorrect restriction can remove required administrative privileges or access. | Select the level with the platform owner and test key and console recovery. |
| IP restriction and SSH allowlist | CVM and releases that advertise it | A wrong or stale source address can block SSH access. | Allow only required jump hosts or minimal ranges, then test recovery before restriction. |
| DoDIN additional controls | CVM, PCVM | The guide describes permanent account locking after an incorrect password. | Obtain ISSO approval, validate notification dependencies, and test account recovery before enabling. |
| fapolicy | AHV, CVM, PCVM | The guide reserves it for strict organization policy and warns of performance impact; application allowlisting can also disrupt workloads. | Complete compatibility/performance testing and record explicit approval. |
| Security-configuration Lock Status | CVM, PCVM | The guide states that Nutanix Support is required to unlock it. | Enable only as a final, reviewed action with an active support and recovery plan. |
| Enable user core dump field | AHV | The 7.5 AHV section displays the field but does not define a corresponding hardening command. Guessing a write would violate fail-closed behavior. | Retain the raw baseline value and disposition it against the installed release's authoritative command reference. |
| Per-node propagation | AHV, CVM, PCVM | Cluster-level readback does not prove every host or VM converged. | Validate every applicable node after Apply, upgrade, and cluster expansion. |

The existing manual-control register also retains cluster lockdown,
credential rotation, directory services/RBAC, certificate replacement,
encryption/KMS, network segmentation, external SCAP/STIG Viewer results, and
authorization activities.

## Product-version boundary

The AHV 7.5 guide records that AOS 7.5 with AHV 11.0 uses a RHEL 9-based
hypervisor that does not currently meet the RHEL 9 STIG. It identifies AOS
7.3 with AHV 10.3 as the release combination to consider when both components
must use a RHEL 8 STIG-aligned base.

The Control Center can assess and change advertised Nutanix parameters; it
cannot correct a vendor product's underlying STIG eligibility. The platform
owner and authorizing official must approve the release baseline before
production Apply.

[ahv75]: https://portal.nutanix.com/page/documents/details?targetId=Nutanix-Security-Guide-v7_5:sec-ahv-configuration-c.html
[cvm75]: https://portal.nutanix.com/page/documents/details?targetId=Nutanix-Security-Guide-v7_5:sec-controller-virtual-machine-t.html
[pcvm75]: https://portal.nutanix.com/page/documents/details?targetId=Nutanix-Security-Guide-v7_5:sec-pcvm-configuration-c.html
