# Policy Atlas

**A Conditional Access assessment and rollout planner for Microsoft Entra.**

[![Test](https://github.com/Whiteends/policy-atlas/actions/workflows/test.yml/badge.svg)](https://github.com/Whiteends/policy-atlas/actions/workflows/test.yml)
[![PowerShell 7](https://img.shields.io/badge/PowerShell-7%2B-2671be)](https://learn.microsoft.com/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Why this exists

Looking at a list of Conditional Access policies does not tell you whether a tenant
is well protected.

A tenant can have dozens of policies and still have important gaps: legacy
authentication may still work, emergency accounts may not be handled safely,
administrators may have weaker protection than expected, or exclusions may have
grown without anyone reviewing them. It is also common to know that improvements
are needed without knowing which one should be tackled first.

Policy Atlas was built to make that review easier. It reads the Conditional Access
configuration, checks it against 28 practical controls, and produces a local report
showing:

- what was found;
- what appears to be missing;
- what the script could not verify automatically;
- how the tenant scored; and
- what should be implemented first.

The aim is not to replace an experienced identity engineer. It is to give that
engineer a useful starting point and a report they can explain to somebody else.

## What you get

Each assessment produces two files on your computer:

```text
<timestamp>.html    The assessment report and recommended rollout order
<timestamp>.json    The evidence snapshot used to produce the result
```

The report covers 28 controls across areas such as:

- users and authentication;
- privileged identities and emergency access;
- devices and applications;
- sessions and tokens;
- guests and external identities;
- workload identities;
- agentic identities; and
- policy operations and governance.

Every control includes a link to relevant Microsoft implementation guidance. The
report also distinguishes between a control that is genuinely missing and one that
still needs a person to confirm it.

## How the score works

The assessment is marked out of 100. The 28 controls do not all carry the same
number of points.

Controls that reduce a large or immediate risk carry more weight. Emergency-access
governance, blocking legacy authentication, administrator MFA, and tenant-wide MFA
therefore contribute more than narrower or advanced controls.

| Result | What happens to the points |
|---|---|
| Detected | The control earns its full points |
| Missing | No points are earned |
| Unknown or collection error | No points are earned until the issue is resolved |
| Manual confirmation | No points are earned until somebody verifies the control |
| Not applicable | The control is removed from the available total |

The calculation is:

```text
score = earned points / applicable points × 100
```

| Score | Stage |
|---:|---|
| 0–24 | Stage 0 — Unmanaged |
| 25–49 | Stage 1 — Foundational |
| 50–69 | Stage 2 — Managed |
| 70–84 | Stage 3 — Adaptive |
| 85–100 | Stage 4 — Optimized |

Scoring and rollout order are related, but they are not the same thing. The score
describes the protection that was found. The rollout order also considers effort,
dependencies, and the damage a badly planned change could cause.

The full point allocation is in [`assessment-model.json`](assessment-model.json).
It is kept in the repository so that the result can be challenged, reviewed, and
improved rather than hidden inside the script.

## Run an assessment

### Requirements

- PowerShell 7 or later;
- the Microsoft Graph PowerShell SDK; and
- a Microsoft Entra account allowed to read the requested configuration.

Windows PowerShell 5.1 is not supported.

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
git clone https://github.com/Whiteends/policy-atlas.git
Set-Location .\policy-atlas
```

Choose the tenant and the folder where you want the results saved:

```powershell
.\Assess-ConditionalAccessMaturity.ps1 `
  -TenantId "<TENANT-GUID>" `
  -OutputPath "C:\CA-Assessment\Results"
```

Before it connects, the script displays the tenant, requested permissions, and
output folder. Check them and type `CONFIRM`. A browser sign-in window may open.

Start with a development or test tenant where possible. The validation steps are in
[`docs/TENANT-VALIDATION.md`](docs/TENANT-VALIDATION.md).

## Permissions

The normal assessment requests two delegated, read-only Microsoft Graph scopes:

| Scope | Why it is needed |
|---|---|
| `Policy.Read.All` | Read Conditional Access policies and related settings |
| `Organization.Read.All` | Read licence information used when interpreting feature availability |

Optional checks request extra read permissions only when you select them:

| Option | Additional scope | What it adds |
|---|---|---|
| `-IncludeSignInActivity` | `AuditLog.Read.All` | Recent sign-in activity for rollout context |
| `-IncludeAgentInventory` | `AgentIdentity.Read.All`, `AgentIdentityBlueprint.Read.All` | Agent identity and blueprint inventory |

For all options and examples, see [`SCRIPT-README.md`](SCRIPT-README.md).

## What the script does not do

Policy Atlas does not request Microsoft Graph write permissions. It does not create,
change, enable, disable, or delete policies.

It also does not upload the assessment to a website. The HTML report and JSON
snapshot are written to the output folder you choose. Tenant and policy identifiers
stored in the snapshot are hashed, and generated tenant reports are excluded from
Git by default.

You should still read the script and review the displayed permissions before signing
in. Read-only does not mean consequence-free: the report contains security
information about the assessed environment and should be handled accordingly.

## What the evidence states mean

- **Detected** — the collected configuration supports the finding.
- **Missing** — collection succeeded, but the expected control was not found.
- **Manual confirmation** — the control needs a person to verify it.
- **Unknown** — the collector could not obtain enough evidence.
- **Not applicable** — the control does not apply to this environment.

Policy Atlas does not turn an uncertain result into a pass. Unknown and manual
results remain visible until they are resolved.

## Optional assessment features

```powershell
# Include recent sign-in context
.\Assess-ConditionalAccessMaturity.ps1 `
  -TenantId "<TENANT-GUID>" `
  -OutputPath ".\results" `
  -IncludeSignInActivity

# Include agent identity inventory
.\Assess-ConditionalAccessMaturity.ps1 `
  -TenantId "<TENANT-GUID>" `
  -OutputPath ".\results" `
  -IncludeAgentInventory

# Review emergency-access exclusions; supplied IDs are not written to the report
.\Assess-ConditionalAccessMaturity.ps1 `
  -TenantId "<TENANT-GUID>" `
  -OutputPath ".\results" `
  -EmergencyAccessObjectId "<OBJECT-ID-1>","<OBJECT-ID-2>"

# Compare the result with an earlier snapshot from the same tenant
.\Assess-ConditionalAccessMaturity.ps1 `
  -TenantId "<TENANT-GUID>" `
  -OutputPath ".\results" `
  -CompareTo ".\previous-results\<timestamp>.json"
```

## About the methodology

Policy Atlas is an independent open-source project. It is not an official Microsoft
assessment and the score is not a Microsoft certification.

The point values are the project's assessment model. They are published, versioned,
and tested so users can see exactly how a result was reached. Feedback from real
assessments and identity practitioners will be used to refine the model over time.
Changes to scoring should include a clear risk-based reason and tests showing the
effect on existing results.

This does not prevent people from using the tool. It explains what the score is—and
what it is not—so that nobody presents a Policy Atlas result as an official Microsoft
rating.

## Repository map

| Path | Contents |
|---|---|
| [`Assess-ConditionalAccessMaturity.ps1`](Assess-ConditionalAccessMaturity.ps1) | Tenant collector and HTML report generator |
| [`assessment-model.json`](assessment-model.json) | Point weights, score bands, and critical controls |
| [`ca-policy-library.json`](ca-policy-library.json) | The 28 assessed controls and implementation guidance |
| [`ca-maturity-model.json`](ca-maturity-model.json) | Maturity-stage descriptions |
| [`src/Assessment.Core.psm1`](src/Assessment.Core.psm1) | PowerShell scoring and snapshot validation |
| [`assets/assessment-core.js`](assets/assessment-core.js) | Browser-side scoring and validation |
| [`schemas/snapshot-schema-v1.json`](schemas/snapshot-schema-v1.json) | JSON snapshot format |
| [`tests/`](tests/) | Safety, scoring, schema, and fixture tests |

## Tests and contributions

```powershell
pwsh -NoProfile -File ".\tests\Run-Tests.ps1"
.\Validate-Snapshot.ps1 -Path ".\tests\fixtures\stage-2-complete.json"
```

Contributions are welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before
opening a pull request. Security issues that could expose tenant data or weaken the
read-only boundary should be reported according to [`SECURITY.md`](SECURITY.md), not
in a public issue.

## License

Policy Atlas is available under the [MIT License](LICENSE).
