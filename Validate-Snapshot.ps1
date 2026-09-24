#Requires -Version 7.0

[CmdletBinding()]
param([Parameter(Mandatory)][string]$Path)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src\Assessment.Core.psm1') -Force
if (-not (Test-Path -LiteralPath $Path)) { throw "Snapshot not found: $Path" }
$raw = Get-Content -Raw -Encoding UTF8 -LiteralPath $Path
$snapshot = $raw | ConvertFrom-Json
$contract = Test-CaSnapshotContract $snapshot
if (-not $contract.Valid) {
    $contract.Errors | ForEach-Object { Write-Error $_ }
    exit 1
}
if (Get-Command Test-Json -ErrorAction SilentlyContinue) {
    $schemaPath = Join-Path $PSScriptRoot 'schemas\snapshot-schema-v1.json'
    if (-not ($raw | Test-Json -SchemaFile $schemaPath)) { throw 'Snapshot failed JSON Schema validation.' }
}
$recomputed = Get-CaMaturityScore $snapshot.signals
if ($recomputed.stage -ne $snapshot.assessment.stage -or $recomputed.provisionalStage -ne $snapshot.assessment.provisionalStage) {
    throw 'Stored maturity result does not match a fresh calculation from signals.'
}
Write-Host "Valid Policy Atlas snapshot v$($snapshot.schemaVersion): stage $($snapshot.assessment.stage)." -ForegroundColor Green
