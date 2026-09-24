# Policy Atlas

Conditional Access assessment and rollout planner for Microsoft Entra.

[![Test](https://github.com/Whiteends/policy-atlas/actions/workflows/test.yml/badge.svg)](https://github.com/Whiteends/policy-atlas/actions/workflows/test.yml)

Licensed under the [MIT License](LICENSE).

## Site routes

- `/` - overview and trust boundary
- `/assessment/` - script-first assessment instructions
- `/report/` - browser-local snapshot validation and reporting
- `/maturity-model/` - five maturity stages rendered from JSON
- `/policy-library/` - 28 searchable policy patterns, including agentic identities and device code flow protection
- `/methodology/` - evidence, confidence, scoring, and provenance methodology

## Preview locally

Opening the HTML directly will not allow JSON fetch calls. Serve the project root:

```powershell
npx wrangler pages dev .
```

## Offline validation

```powershell
pwsh -NoProfile -File ".\tests\Run-Tests.ps1"
.\Validate-Snapshot.ps1 -Path ".\tests\fixtures\stage-2-complete.json"
```

PowerShell 7 or later is required for the assessor and validation tooling. Formal JSON Schema validation uses PowerShell 7's `Test-Json` support.

## Tenant assessment

Use a development/test tenant first and follow [docs/TENANT-VALIDATION.md](docs/TENANT-VALIDATION.md). The collector requests two read permissions by default:

- `Policy.Read.All`
- `Organization.Read.All`

`AuditLog.Read.All` is requested only when the optional `-IncludeSignInActivity` rollout-context check is selected.

The JSON snapshot is versioned, uses hashed tenant/policy identifiers, records evidence states, and can be loaded into `/report/` without any server upload or persistence.

The design direction is an identity-security field manual and assessment console: dense evidence presentation, restrained status colour, editorial typography, and minimal decorative UI.
