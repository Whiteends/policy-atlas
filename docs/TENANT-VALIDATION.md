# Tenant validation runbook

Automated tests validate syntax, safety invariants, snapshot structure, and scoring. They cannot prove that Microsoft Graph represents your tenant exactly as expected. That requires a tenant you control and a human comparison with the Entra admin center.

## Safety boundary

Use a development/test tenant first. The script requests `Policy.Read.All` and `Organization.Read.All` by default. `AuditLog.Read.All` is requested only with `-IncludeSignInActivity`. It contains no Graph mutation cmdlets or mutating raw Graph requests.

## Prerequisites

1. Install and use PowerShell 7 or later. Windows PowerShell 5.1 is not supported.
2. Install the Microsoft Graph SDK: `Install-Module Microsoft.Graph -Scope CurrentUser`.
3. Obtain the test tenant ID from **Entra admin center > Identity > Overview**.
4. Review the script, its three scopes, and `manual-overrides.example.json`.

## First controlled run

```powershell
cd "C:\Users\jimoh\Desktop\Codex Projects\conditional-access-maturity-tool"

.\Assess-ConditionalAccessMaturity.ps1 `
  -TenantId "<TEST-TENANT-GUID>" `
  -OutputPath ".\validation-output"
```

Do not use `-SkipConfirmation`. Confirm that the sign-in prompt names the intended test tenant and requests only the documented read scopes.

```powershell
$snapshot = Get-ChildItem ".\validation-output\*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
.\Validate-Snapshot.ps1 -Path $snapshot.FullName
```

Serve the website and open `/report/`; load the same JSON. PowerShell and browser stage/confidence results must match.

## Known-truth policy matrix

Configure these cases manually in the test tenant. Use report-only mode where appropriate and never weaken production for testing.

| Case | Deliberate configuration | Expected result |
|---|---|---|
| Empty baseline | No custom CA policies | Confirmed Stage 0 |
| Legacy block | Enabled block covers `exchangeActiveSync` and `other` | Legacy signal detected |
| Report-only legacy block | Same scope, report-only | Missing with report-only evidence |
| Partial legacy block | Only one legacy category | Missing |
| MFA baseline | All users + all resources + MFA | MFA signal detected; exclusions remain reviewable |
| Partial MFA | All users but one target app | Missing |
| Admin policy | Directory roles + MFA/auth strength | Manual until complete role coverage is reviewed |
| Device control | Compliant/hybrid grant | Detected; app sensitivity still reviewed manually |
| Guest control | Guest target plus effective control | Detected |
| Empty guest scope | Guest target without control | Missing |
| Risk controls | Enabled sign-in-risk and user-risk policies | Both detected |
| Authentication strength | Any strength policy | Manual until phishing resistance is verified |
| Workload identity | Controlled service-principal target | Detected |
| Missing permission | Required read permission unavailable | Unknown plus warning, never missing |

## Portal comparison

For every signal, compare policy state, identities, resources, conditions, exclusions, grant controls, and session controls in Entra. Record true positive, true negative, false positive, false negative, or unverifiable. Do not claim validation until there are zero false assertions of enforcement.

## Raw-response troubleshooting

```powershell
Connect-MgGraph -TenantId "<TEST-TENANT-GUID>" -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy -All | ConvertTo-Json -Depth 30 | Set-Content -Encoding utf8 ".\raw-ca-policies.json"
Disconnect-MgGraph
```

Never upload or commit `raw-ca-policies.json`; it can contain tenant-sensitive configuration.

## Manual controls

Copy `manual-overrides.example.json`, change only personally verified controls, and provide a precise reason:

```powershell
.\Assess-ConditionalAccessMaturity.ps1 -TenantId "<TEST-TENANT-GUID>" -ManualOverridesPath ".\manual-overrides.reviewed.json"
```

## Release gate

- Zero false claims that an unenforced control is enforced.
- Permission failures remain unknown, never missing.
- Every detected signal has inspectable evidence.
- PowerShell and browser scores match.
- Snapshots pass `Validate-Snapshot.ps1`.
- Script disconnects after success or failure.
- Raw responses and reviewed snapshots remain private.
