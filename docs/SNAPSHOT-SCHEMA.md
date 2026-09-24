# Snapshot schema v1

`schemas/snapshot-schema-v1.json` is the normative contract. A snapshot contains no display names, UPNs, group names, policy names, or raw tenant ID. Tenant and policy identifiers are SHA-256 fingerprints so two runs can be compared without exposing the underlying identifiers.

Every signal has one of six states:

- `detected`: sufficient evidence supports the control.
- `missing`: collection succeeded and the control was not found/enforced.
- `not_applicable`: a reviewed tenant condition makes the control inapplicable.
- `manual_confirmation`: Graph evidence is insufficient; a human must verify it.
- `unknown`: collection did not establish an answer.
- `error`: the check failed unexpectedly.

Unknown, manual, and error states never increase confirmed maturity. Manual overrides require a reason and are recorded with `source: reviewed_manual_override`.

Validate a snapshot locally:

```powershell
.\Validate-Snapshot.ps1 -Path ".\validation-output\<snapshot>.json"
```

PowerShell 7 validates the formal JSON Schema through `Test-Json` and also runs the bundled strict contract and score-recomputation checks.

The browser report renderer accepts only schema `1.0.0`, recalculates maturity from the signals, and rejects a file whose stored score differs.
