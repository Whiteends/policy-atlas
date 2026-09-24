#Requires -Version 7.0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\Assessment.Core.psm1') -Force
$fixtureRoot = Join-Path $PSScriptRoot 'fixtures'
if (-not (Test-Path $fixtureRoot)) { New-Item -ItemType Directory -Path $fixtureRoot | Out-Null }

$definitions = Get-CaStageDefinitions
$allIds = @($definitions.Values.required | Select-Object -Unique)

function New-Fixture([string]$Name, [hashtable]$Statuses) {
    $signals = [ordered]@{}
    foreach ($id in $allIds) {
        $status = if ($Statuses.ContainsKey($id)) { $Statuses[$id] } else { 'unknown' }
        $signals[$id] = New-CaSignalResult -Status $status -Reason "Fixture '$Name' sets $id to $status."
    }
    $signalObject = [pscustomobject]$signals
    $assessment = Get-CaMaturityScore $signalObject
    $snapshot = [pscustomobject][ordered]@{
        schemaVersion = '1.0.0'; scriptVersion = '0.2.0'; modelVersion = '1.0.0'; policyLibraryVersion = '1.0.0'
        generatedAt = '2026-09-21T12:00:00.0000000Z'
        tenant = [pscustomobject]@{ fingerprint = ('a' * 64); cloud = 'Global' }
        collector = [pscustomobject]@{ powerShellVersion = '7.5.0'; graphSdkVersion = '2.0.0'; apiVersion = 'v1.0' }
        context = [pscustomobject]@{ policyCount = 0; enabledPolicyCount = 0; reportOnlyPolicyCount = 0; licensing = [pscustomobject]@{ hasEntraP1 = $false; hasEntraP2 = $false }; signInActivity = [pscustomobject]@{ requested = $false; legacyAuthSignInsLast7Days = $null } }
        assessment = $assessment; signals = $signalObject
        manualChecks = @($signalObject.PSObject.Properties | Where-Object { $_.Value.status -eq 'manual_confirmation' } | ForEach-Object Name)
        warnings = @(); errors = @()
    }
    $snapshot | ConvertTo-Json -Depth 20 | Out-File -Encoding utf8 -LiteralPath (Join-Path $fixtureRoot "$Name.json")
}

$stage1 = @{}; $definitions['1'].required | ForEach-Object { $stage1[$_] = 'detected' }
$stage2 = @{}; foreach ($stage in @('1','2')) { $definitions[$stage].required | ForEach-Object { $stage2[$_] = 'detected' } }
$stage3 = @{}; foreach ($stage in @('1','2','3')) { $definitions[$stage].required | ForEach-Object { $stage3[$_] = 'detected' } }
$stage4Manual = $stage3.Clone(); $stage4Manual['cross-tenant-access-enforcement'] = 'detected'; foreach ($id in @('global-secure-access','defender-cloud-apps-session-control','insider-risk-signal','policy-as-code')) { $stage4Manual[$id] = 'manual_confirmation' }
$missingCritical = $stage1.Clone(); $missingCritical['block-legacy-auth'] = 'missing'
$mostlyUnknown = @{ 'mfa-all-users' = 'detected' }

New-Fixture 'stage-0-empty' @{}
New-Fixture 'stage-1-complete' $stage1
New-Fixture 'stage-2-complete' $stage2
New-Fixture 'stage-3-complete' $stage3
New-Fixture 'mostly-unknown' $mostlyUnknown
New-Fixture 'missing-critical-baseline' $missingCritical
New-Fixture 'stage-4-manual-gaps' $stage4Manual
