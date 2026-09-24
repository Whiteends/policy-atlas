#Requires -Version 7.0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'src\Assessment.Core.psm1') -Force
& (Join-Path $PSScriptRoot 'Generate-Fixtures.ps1')
$failures = New-Object System.Collections.Generic.List[string]
$passes = 0

function Assert-Equal($Actual, $Expected, [string]$Name) {
    if ($Actual -ne $Expected) { $failures.Add("$Name - expected '$Expected', got '$Actual'") } else { $script:passes++ }
}
function Assert-True([bool]$Condition, [string]$Name) {
    if (-not $Condition) { $failures.Add($Name) } else { $script:passes++ }
}
function Read-Fixture([string]$Name) { return Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot "fixtures\$Name.json") | ConvertFrom-Json }

$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Assess-ConditionalAccessMaturity.ps1'), [ref]$null, [ref]$parseErrors) | Out-Null
Assert-Equal @($parseErrors).Count 0 'Main script parses without syntax errors'

$scriptText = Get-Content -Raw -LiteralPath (Join-Path $root 'Assess-ConditionalAccessMaturity.ps1')
Assert-True (-not [regex]::IsMatch($scriptText, '\b(New|Update|Remove|Set)-Mg[A-Z]')) 'No Microsoft Graph mutation cmdlets are present'
Assert-True (-not [regex]::IsMatch($scriptText, 'Invoke-MgGraphRequest[^\r\n]*(POST|PATCH|PUT|DELETE)', 'IgnoreCase')) 'No mutating raw Graph requests are present'
Assert-True ($scriptText.StartsWith('#Requires -Version 7.0')) 'Assessor explicitly requires PowerShell 7'
Assert-True ([regex]::IsMatch($scriptText, '\[Parameter\(Mandatory\)\]\[ValidateNotNullOrEmpty\(\)\]\[string\]\$OutputPath')) 'User must choose an output folder'
Assert-True ($scriptText.Contains('if ($null -eq $Policies) { return @() }')) 'Policy filters safely handle an unavailable Graph response'
Assert-True ($scriptText.Contains('Write-Warning "${Name} could not be collected: $message"')) 'Graph collection failures are displayed before report generation'
Assert-True ($scriptText.Contains('Write-Output -NoEnumerate @(Get-MgIdentityConditionalAccessPolicy -All)')) 'A successful empty policy inventory is distinct from collection failure'
Assert-True ($scriptText.Contains('Implementation guide &#8599;')) 'Report labels Microsoft documentation as implementation guidance'
Assert-True (-not [regex]::IsMatch($scriptText, '@\(\$(Warnings|Errors)\)')) 'Generic message lists use explicit array conversion'
foreach ($unusedScope in @('Directory.Read.All','RoleManagement.Read.Directory','IdentityRiskyUser.Read.All','Agreement.Read.All','Reports.Read.All','DeviceManagementConfiguration.Read.All')) {
    Assert-True (-not $scriptText.Contains("'$unusedScope'")) "Unused scope removed: $unusedScope"
}

$expectations = @{
    'stage-0-empty' = 0
    'stage-1-complete' = 1
    'stage-2-complete' = 2
    'stage-3-complete' = 3
    'mostly-unknown' = 0
    'missing-critical-baseline' = 1
    'stage-4-manual-gaps' = 4
}
foreach ($fixtureName in $expectations.Keys) {
    $fixture = Read-Fixture $fixtureName
    $contract = Test-CaSnapshotContract $fixture
    Assert-True $contract.Valid "$fixtureName satisfies snapshot contract: $($contract.Errors -join '; ')"
    $score = Get-CaMaturityScore $fixture.signals
    Assert-Equal $score.stage $expectations[$fixtureName] "$fixtureName confirmed stage"
    Assert-Equal $fixture.assessment.stage $score.stage "$fixtureName stored score matches recomputed score"
}
Assert-Equal (Get-CaMaturityScore (Read-Fixture 'mostly-unknown').signals).provisionalStage 0 'Unknown signals do not improve provisional maturity'
Assert-Equal (Get-CaMaturityScore (Read-Fixture 'stage-4-manual-gaps').signals).stage 4 'Weighted score can reach Stage 4 while manual gaps remain visible'

$library = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $root 'ca-policy-library.json') | ConvertFrom-Json
$definedIds = @((Get-CaStageDefinitions).Values.required | Select-Object -Unique)
foreach ($id in $definedIds) { Assert-True ($id -in @($library.policies.id)) "Scoring signal exists in policy library: $id" }

$schema = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $root 'schemas\snapshot-schema-v1.json') | ConvertFrom-Json
Assert-Equal $schema.properties.schemaVersion.const '1.0.0' 'JSON Schema version is fixed at 1.0.0'
$emptyContract = Test-CaSnapshotContract ([pscustomobject]@{})
Assert-True (-not $emptyContract.Valid) 'Empty snapshot is rejected without throwing'
$invalidStatus = Read-Fixture 'stage-1-complete'
$invalidStatus.signals.'block-legacy-auth'.status = 'maybe'
Assert-True (-not (Test-CaSnapshotContract $invalidStatus).Valid) 'Unknown signal status is rejected'

$browserModel = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $root 'assessment-model.json') | ConvertFrom-Json
Assert-Equal $browserModel.version '1.0.0' 'Shared assessment model is versioned'
Assert-Equal @($browserModel.weightedScoring.weights.PSObject.Properties).Count 28 'All 28 controls have scoring weights'
Assert-Equal (@($browserModel.weightedScoring.weights.PSObject.Properties).Value | Measure-Object -Sum).Sum 100 'Control weights total 100 points'
foreach ($stageKey in @('1','2','3','4')) {
    $powerShellStage = (Get-CaStageDefinitions)[$stageKey]
    $jsonStage = $browserModel.stages.PSObject.Properties[$stageKey].Value
    Assert-Equal ($powerShellStage.required -join ',') ($jsonStage.required -join ',') "PowerShell and browser requirements match for Stage $stageKey"
    Assert-Equal ($powerShellStage.critical -join ',') ($jsonStage.critical -join ',') "PowerShell and browser critical controls match for Stage $stageKey"
}

if ($failures.Count) {
    Write-Host "FAILED: $($failures.Count) assertion(s)" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
    exit 1
}
Write-Host "PASS: $passes assertions" -ForegroundColor Green
