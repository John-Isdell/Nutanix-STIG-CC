## Summary

Describe the problem, the change, and the operator impact.

## Safety and security impact

Explain failure modes and any effect on dry-run gates, approval, verification,
credential handling, host trust, process control, evidence, or one-cluster
isolation.

## Validation

List the exact checks run and their results.

## Checklist

- [ ] This pull request is limited to one reviewable task.
- [ ] Tests cover the changed behavior and failure paths.
- [ ] No credentials, customer data, cluster addresses, host keys, or evidence
      are included.
- [ ] Both web services remain loopback-only; no remote-access path was added.
- [ ] Apply still requires a matching successful dry run and explicit approval.
- [ ] Active cluster operations cannot be interrupted through normal controls.
- [ ] Documentation and release notes are updated where needed.
- [ ] Dependency and GitHub Action versions remain pinned.
- [ ] Bundled-document copyright review is complete if release contents changed.
