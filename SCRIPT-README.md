# Conditional Access Maturity Assessment Script

Reads your Microsoft Entra tenant's Conditional Access configuration (read-only) and
scores it against a 5-stage maturity model, producing a local HTML report with
specific next-step policy recommendations.

## Before you run this against a real tenant

This script asks you to sign in and grant it read access to identity configuration
data. You should not run any script like that on trust alone. So:

1. **Read the script.** It's a single file, ~350 lines, organized into clearly named
   functions — one function per thing it checks. There's a `SIGNAL COLLECTION` region
   containing every Graph API call the script makes. That's the entire surface area.
2. **Check the scopes.** The full list of requested permissions, and why each one is
   needed, is printed to your screen before you're asked to confirm, and is also in
   the `$RequiredScopes` block near the top of the script.
3. **Test it on a dev/test tenant first** if you have one available.

## What it does and doesn't do

**Does:**
- Reads your Conditional Access policies, license SKUs, MFA registration campaign
  settings, and recent sign-in logs (legacy auth usage only, last 7 days).
- Scores your tenant against 5 maturity stages and tells you which stage you're at.
- Writes an HTML report and a JSON snapshot to a folder on your own machine.

**Does not:**
- Request or use any write/modify Graph permission, ever.
- Change, create, or delete anything in your tenant.
- Send any tenant data anywhere outside your own Microsoft Graph session and your
  own local disk.
- Require an app registration — it authenticates using the Microsoft Graph
  PowerShell SDK's own pre-consented first-party client via `Connect-MgGraph`.

## Permissions requested (all read-only)

| Scope | Why |
|---|---|
| `Policy.Read.All` | Conditional Access policies, named locations, cross-tenant access settings |
| `AuditLog.Read.All` | Optional: recent legacy-auth sign-in activity when `-IncludeSignInActivity` is supplied |
| `Organization.Read.All` | Subscribed license SKUs, to know which features are even available to you |
| `AgentIdentity.Read.All` | Optional: count enabled and disabled agent identities when `-IncludeAgentInventory` is supplied |
| `AgentIdentityBlueprint.Read.All` | Optional: count agent identity blueprints when `-IncludeAgentInventory` is supplied |

An administrator may need to consent to these scopes on the first run, depending on
your tenant's user-consent policy. The signed-in account also needs a directory role
permitted to read Conditional Access and sign-in logs; use the least-privileged role
that satisfies your tenant's review process.

## Requirements

- PowerShell 7 or later (required; Windows PowerShell 5.1 is not supported)
- Microsoft.Graph PowerShell SDK modules (the script's `#Requires` line lists the
  specific sub-modules needed — install with `Install-Module Microsoft.Graph -Scope CurrentUser`
  if you don't have it)
- `ca-maturity-model.json` and `ca-policy-library.json` in the same folder as the
  script (these define the maturity stages and policy recommendations — the script
  reads them rather than hardcoding that content, so they can be updated
  independently)

## Usage

```powershell
# First run (use a test tenant first and choose where local results are written)
.\Assess-ConditionalAccessMaturity.ps1 -TenantId "<TENANT-GUID>" -OutputPath "C:\CA-Assessment\Results"

# Optional rollout context (requests AuditLog.Read.All)
.\Assess-ConditionalAccessMaturity.ps1 -TenantId "<TENANT-GUID>" -OutputPath ".\validation-output" -IncludeSignInActivity

# Optional agent identity inventory (requests two additional read-only scopes)
.\Assess-ConditionalAccessMaturity.ps1 -TenantId "<TENANT-GUID>" -OutputPath ".\validation-output" -IncludeAgentInventory

# Optional emergency-access safety gate (IDs are hashed/not written to output)
.\Assess-ConditionalAccessMaturity.ps1 -TenantId "<TENANT-GUID>" -OutputPath ".\validation-output" `
  -EmergencyAccessObjectId "<OBJECT-ID-1>","<OBJECT-ID-2>"

# Later run, showing what's changed since a previous report
.\Assess-ConditionalAccessMaturity.ps1 -TenantId "<TENANT-GUID>" -OutputPath ".\validation-output" -CompareTo ".\previous-results\2026-08-01T0900.json"
```

You'll be shown the exact scopes being requested and asked to type `CONFIRM` before
anything connects. Use `-SkipConfirmation` only for re-runs of a tenant/script
combination you've already reviewed — not recommended for first-time use.

## A note on accuracy

A few checks are marked `BEST-EFFORT / VERIFY` in the script's comments — these use
Graph properties or endpoints (token protection, workload identity CA targeting,
guest/external user targeting) where the exact schema has shifted across SDK
versions or is still evolving. If one of these reports "not detected" but you know
the corresponding policy exists in your tenant, that's a sign to verify the
underlying property path against current Microsoft Graph documentation rather than
trust the script blindly — this is a diagnostic aid, not a certified audit tool.

Signals that cannot be proved safely from the current stable SDK shape are reported
as `manual_confirmation`, never guessed. This includes break-glass governance,
complete privileged-role coverage, phishing-resistant strength selection, PIM
step-up, CAE coverage, token protection, complete cross-tenant governance, Global
Secure Access, Defender for Cloud Apps session control, insider-risk integration,
and policy-as-code.

The snapshot follows `schemas/snapshot-schema-v1.json`. It uses hashed tenant and
policy identifiers, structured evidence states, explicit versions, and a
reproducible maturity result. Follow `docs/TENANT-VALIDATION.md` before treating an
assessment as validated.
