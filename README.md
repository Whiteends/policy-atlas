# Policy Atlas

**An evidence-led Conditional Access assessment and rollout planner for Microsoft Entra.**

[![Test](https://github.com/Whiteends/policy-atlas/actions/workflows/test.yml/badge.svg)](https://github.com/Whiteends/policy-atlas/actions/workflows/test.yml)
[![PowerShell 7](https://img.shields.io/badge/PowerShell-7%2B-2671be)](https://learn.microsoft.com/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Conditional Access estates rarely fail because nobody created policies. They fail
because coverage is incomplete, exclusions accumulate, important controls remain in
report-only mode, or nobody can explain which change should happen next.

Policy Atlas reads the configuration that is actually present in a tenant, records
what it can and cannot prove, and turns the result into a prioritized implementation
plan. It is intended for identity engineers, security teams, consultants, and
administrators who need something more defensible than a policy checklist.

> Policy Atlas is diagnostic guidance, not a Microsoft product or a certified audit.
> Review every recommendation before changing production access policy.

## What it delivers

- A local HTML report designed for technical review and stakeholder discussion.
- A versioned JSON evidence snapshot that can be validated and compared over time.
- Coverage across 28 Conditional Access controls, including device code flow,
  workload identities, privileged access, session controls, external identities,
  and agentic identities.
- A weighted maturity score out of 100 instead of treating every control as equal.
- A recommended rollout order informed by security value, prerequisites,
  implementation effort, and potential blast radius.
- Direct implementation guidance from Microsoft Learn for every control.
- Explicit `detected`, `missing`, `unknown`, `manual_confirmation`, and
  `not_applicable` evidence states.

The collector requests read permissions only. It does not create, update, disable,
or delete Conditional Access policies.

## From policy inventory to evidence

Policy Atlas deliberately separates observation from interpretation:

1. **Collect** — query documented Microsoft Graph endpoints using delegated,
   read-only scopes.
2. **Classify** — record whether each control is detected, missing, unresolved,
   manually verifiable, or not applicable.
3. **Score** — apply the published control weights and normalize the applicable
   result to 100.
4. **Plan** — order unresolved controls into a practical rollout sequence and show
   the implementation considerations for each one.

When the collector cannot establish a fact safely, it does not guess. The result is
reported as unknown or requiring manual confirmation and earns no maturity points
until verified.

## How maturity is calculated

The 28 controls collectively carry 100 points. Foundational controls with high
security impact and broad exposure carry more weight than narrower or advanced
capabilities. For example, emergency-access governance, blocking legacy
authentication, administrator MFA, and tenant-wide MFA each carry more weight than
a Terms of Use policy or an advanced integration.

| Evidence result | Scoring treatment |
|---|---|
| Detected | Earns the control's full point value |
| Missing | Earns zero points |
| Unknown or error | Earns zero until collection is resolved |
| Manual confirmation | Earns zero until reviewed evidence is supplied |
| Not applicable | Removed from the available total |

The calculation is:

```text
maturity score = earned weighted points / applicable weighted points × 100
```

| Score | Maturity stage |
|---:|---|
| 0–24 | Stage 0 — Unmanaged |
| 25–49 | Stage 1 — Foundational |
| 50–69 | Stage 2 — Managed |
| 70–84 | Stage 3 — Adaptive |
| 85–100 | Stage 4 — Optimized |

Critical gaps are reported separately as implementation-readiness blockers. The
complete weights, stage bands, and critical-control definitions are published in
[`assessment-model.json`](assessment-model.json); the scoring implementation is
shared between PowerShell and the browser renderer and checked by automated tests.

## Quick start

### Requirements

- PowerShell 7 or later. Windows PowerShell 5.1 is not supported.
- A Microsoft Entra account permitted to read the requested configuration.
- The Microsoft Graph PowerShell SDK.

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
git clone https://github.com/Whiteends/policy-atlas.git
Set-Location .\policy-atlas
```

Run a basic read-only assessment and choose where the report should be written:

```powershell
.\Assess-ConditionalAccessMaturity.ps1 `
  -TenantId "<TENANT-GUID>" `
  -OutputPath "C:\CA-Assessment\Results"
```

The script prints its requested scopes and target output folder before connecting.
Type `CONFIRM` only after checking both. A browser sign-in window may open through
Web Account Manager.

The output folder will contain:

```text
<timestamp>.html    Human-readable assessment and rollout plan
<timestamp>.json    Structured, versioned evidence snapshot
```

Use a development or test tenant first. The controlled validation procedure is in
[`docs/TENANT-VALIDATION.md`](docs/TENANT-VALIDATION.md).

## Permissions and optional evidence

The basic assessment requests:

| Scope | Purpose |
|---|---|
| `Policy.Read.All` | Read Conditional Access policies and related policy configuration |
| `Organization.Read.All` | Read subscribed SKUs used to interpret feature availability |

Optional switches request additional read-only scopes only when selected:

| Option | Additional scope | Purpose |
|---|---|---|
| `-IncludeSignInActivity` | `AuditLog.Read.All` | Add recent sign-in activity as rollout context |
| `-IncludeAgentInventory` | `AgentIdentity.Read.All`, `AgentIdentityBlueprint.Read.All` | Add agent identity and blueprint inventory |

Additional examples:

```powershell
# Include recent sign-in context
.\Assess-ConditionalAccessMaturity.ps1 `
  -TenantId "<TENANT-GUID>" `
  -OutputPath ".\results" `
  -IncludeSignInActivity

# Include agentic identity inventory
.\Assess-ConditionalAccessMaturity.ps1 `
  -TenantId "<TENANT-GUID>" `
  -OutputPath ".\results" `
  -IncludeAgentInventory

# Check emergency-access exclusions without writing object IDs to the report
.\Assess-ConditionalAccessMaturity.ps1 `
  -TenantId "<TENANT-GUID>" `
  -OutputPath ".\results" `
  -EmergencyAccessObjectId "<OBJECT-ID-1>","<OBJECT-ID-2>"

# Compare with an earlier snapshot from the same tenant
.\Assess-ConditionalAccessMaturity.ps1 `
  -TenantId "<TENANT-GUID>" `
  -OutputPath ".\results" `
  -CompareTo ".\previous-results\<timestamp>.json"
```

See [`SCRIPT-README.md`](SCRIPT-README.md) for the full security boundary and usage
notes.

## Privacy and trust boundary

- No Microsoft Graph write scopes are requested.
- No tenant data is uploaded to the Policy Atlas website or another service.
- Reports and snapshots are written to the output folder selected by the operator.
- Tenant and policy identifiers stored in snapshots are hashed.
- Generated reports, raw policy exports, and reviewed override files are excluded
  from Git by default.
- The browser report renderer processes snapshots locally in browser memory.

You should still inspect the script and confirm the displayed scopes before signing
in. Open source makes the collection boundary reviewable; it does not remove the
operator's responsibility to validate it.

## Repository guide

| Path | Purpose |
|---|---|
| [`Assess-ConditionalAccessMaturity.ps1`](Assess-ConditionalAccessMaturity.ps1) | Read-only tenant collector and HTML report generator |
| [`assessment-model.json`](assessment-model.json) | Weighted scoring model and critical-control definitions |
| [`ca-policy-library.json`](ca-policy-library.json) | The 28 control patterns and implementation guidance |
| [`ca-maturity-model.json`](ca-maturity-model.json) | Human-readable maturity-stage descriptions |
| [`src/Assessment.Core.psm1`](src/Assessment.Core.psm1) | PowerShell scoring and snapshot validation logic |
| [`assets/assessment-core.js`](assets/assessment-core.js) | Browser-side scoring and validation logic |
| [`schemas/snapshot-schema-v1.json`](schemas/snapshot-schema-v1.json) | Snapshot contract |
| [`tests/`](tests/) | Safety, scoring, schema, and fixture tests |

The static site also provides an overview, assessment guidance, policy library,
maturity model, methodology, and local snapshot renderer.

## Validate and contribute

```powershell
pwsh -NoProfile -File ".\tests\Run-Tests.ps1"
.\Validate-Snapshot.ps1 -Path ".\tests\fixtures\stage-2-complete.json"
```

Scoring changes must explain their risk rationale and keep the model transparent.
See [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. Please report
sensitive vulnerabilities according to [`SECURITY.md`](SECURITY.md), not in a public
issue.

## Project status

Policy Atlas is in preview. The collection and scoring model are functional and
automatically tested, but the weights are an open, expert-designed methodology—not
a Microsoft-certified standard. Real-tenant validation, peer review, and calibration
against diverse Conditional Access environments are ongoing priorities.

## License

Policy Atlas is available under the [MIT License](LICENSE).
