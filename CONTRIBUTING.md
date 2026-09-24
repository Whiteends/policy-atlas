# Contributing to Policy Atlas

Contributions that improve evidence quality, scoring transparency, Microsoft
documentation references, accessibility, or test coverage are welcome.

For an incorrect detection, open an issue before changing the scoring model. Include
the control ID, the status Policy Atlas returned, the status you expected, and a
sanitized description of the policy configuration. Never attach a tenant export or
an unredacted report.

## Before submitting a change

1. Use PowerShell 7 or later.
2. Do not add Microsoft Graph write permissions or mutation commands.
3. Do not commit tenant reports, tenant identifiers, policy exports, tokens, or
   reviewed manual-override files.
4. Update the shared assessment model and both scoring implementations when a
   scoring rule changes.
5. Run `pwsh -NoProfile -File ./tests/Run-Tests.ps1` from the project root.
6. Keep pull requests focused. Separate collector, scoring, and visual changes when
   they can be reviewed independently.

For scoring changes, explain the risk rationale, point-weight impact, and any
effect on existing fixture results. The 28 control weights must continue to
total 100 unless the scoring model and documentation are deliberately versioned.
New controls must include a stable ID, domain, evidence rule, point-weight rationale,
implementation order, Microsoft Learn reference, and test coverage.
