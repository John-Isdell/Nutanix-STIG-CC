# Public release checklist

Complete this checklist before creating a version tag or changing repository
visibility. A tag matching `v*` publishes release artifacts automatically.

The repository was already public when this checklist was added. The repository
owner should complete the bundled-document review immediately and before the
next release. If redistribution rights cannot be confirmed, remove the affected
document from the repository and release manifest pending legal review.

## Human approvals

- [ ] A human repository owner has confirmed that every bundled document under
  `app/docs/`, including
  `Nutanix_STIG_Hardening_Client_Execution_Guide.docx`, is original project
  content or is included under documented redistribution rights.
- [ ] The reviewer has confirmed the documents are not verbatim reproductions
  of vendor documentation.
- [ ] The repository owner has confirmed the project license.
- [ ] Confirm `NOTICE.md` exists at the repository root and its short form
  appears in `README.md`, `CLIENT-GUIDE.md`, and
  `app/docs/Nutanix_Security_Guide_7.5_Control_Crosswalk.md`.
- [ ] After completing the bundled-document review, a repository owner has set
  the GitHub Actions repository variable `DOCS_COPYRIGHT_REVIEWED` to the exact
  lowercase value `true`.

The documentation copyright review is a human legal/content review. Automated
tests and AI review cannot complete or attest to it. The release workflow fails
closed until the repository variable records that a human completed this gate.

## Engineering checks

- [ ] The release version matches `control_center.VERSION` and the application
  version.
- [ ] Continuous integration passes on supported Python versions.
- [ ] The complete prohibited-name scan passes in files, filenames, DOCX
  internals, and Git history.
- [ ] No `.runtime`, `app/data`, credentials, keys, customer information,
  evidence, or local configuration is tracked or packaged.
- [ ] The local-only and one-cluster security boundaries remain intact.
- [ ] A dry run against an authorized non-production cluster has been reviewed
  by a human operator when remote behavior changed.

## Artifact checks

- [ ] Build all three platform artifacts with
  `scripts/build_release.py`.
- [ ] Inspect the archive inventory and executable permissions.
- [ ] Verify every value in `SHA256SUMS.txt` independently.
- [ ] Smoke-test installation and uninstall on Windows, macOS, and Linux.
- [ ] Confirm uninstall preserves evidence and removes automatic startup.
- [ ] Review generated release notes before publishing the tag.
