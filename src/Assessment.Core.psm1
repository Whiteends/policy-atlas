Set-StrictMode -Version Latest

$script:ValidStatuses = @('detected', 'missing', 'not_applicable', 'manual_confirmation', 'unknown', 'error')

function Get-CaAssessmentModel {
    $path = Join-Path (Split-Path $PSScriptRoot -Parent) 'assessment-model.json'
    $model = Get-Content -Raw -Encoding UTF8 -LiteralPath $path | ConvertFrom-Json
    $weights = @($model.weightedScoring.weights.PSObject.Properties)
    $weightTotal = ($weights.Value | Measure-Object -Sum).Sum
    if ($weights.Count -ne 28) { throw "Assessment model must define 28 weighted controls; found $($weights.Count)." }
    if ($weightTotal -ne 100) { throw "Assessment model weights must total 100; found $weightTotal." }
    if (@($model.weightedScoring.bands).Count -ne 5) { throw 'Assessment model must define five maturity score bands.' }
    return $model
}

function New-CaSignalResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('detected', 'missing', 'not_applicable', 'manual_confirmation', 'unknown', 'error')][string]$Status,
        [Parameter(Mandatory)][string]$Reason,
        [object[]]$Evidence = @(),
        [string]$ErrorCode
    )

    $result = [ordered]@{
        status    = $Status
        reason    = $Reason
        evidence  = @($Evidence)
        checkedAt = (Get-Date).ToUniversalTime().ToString('o')
    }
    if ($ErrorCode) { $result.errorCode = $ErrorCode }
    return [pscustomobject]$result
}

function Get-CaStageDefinitions {
    $model = Get-CaAssessmentModel
    $definitions = [ordered]@{}
    foreach ($property in $model.stages.PSObject.Properties) { $definitions[$property.Name] = $property.Value }
    return $definitions
}

function Get-CaMaturityScore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Signals)

    $definitions = Get-CaStageDefinitions
    $model = Get-CaAssessmentModel
    $stageResults = [ordered]@{}
    $confirmedStage = 0
    $provisionalStage = 0
    $knownTotal = 0
    $requiredTotal = 0

    foreach ($stageKey in $definitions.Keys) {
        $definition = $definitions[$stageKey]
        $rows = foreach ($id in $definition.required) {
            $signal = $Signals.PSObject.Properties[$id]
            $status = if ($signal) { [string]$signal.Value.status } else { 'unknown' }
            [pscustomobject]@{ id = $id; status = $status; critical = ($id -in $definition.critical) }
        }

        $detected = @($rows | Where-Object status -eq 'detected')
        $unresolved = @($rows | Where-Object { $_.status -in @('unknown', 'manual_confirmation', 'error') })
        $missing = @($rows | Where-Object status -eq 'missing')
        $applicable = @($rows | Where-Object status -ne 'not_applicable')
        $criticalFailed = @($rows | Where-Object { $_.critical -and $_.status -ne 'detected' })
        $percent = if ($applicable.Count) { [math]::Round(($detected.Count / $applicable.Count) * 100) } else { 0 }
        $confirmed = ($percent -ge $model.stageThresholdPercent -and $criticalFailed.Count -eq 0 -and $unresolved.Count -eq 0)
        $provisional = ($percent -ge $model.stageThresholdPercent -and @($criticalFailed | Where-Object status -eq 'missing').Count -eq 0)

        $stageResults[$stageKey] = [pscustomobject][ordered]@{
            stage             = [int]$stageKey
            requiredCount     = $definition.required.Count
            applicableCount   = $applicable.Count
            detectedCount     = $detected.Count
            coveragePercent   = $percent
            confirmed         = $confirmed
            provisional       = $provisional
            missing           = @($missing | ForEach-Object id)
            unresolved        = @($unresolved | ForEach-Object id)
            failedCritical    = @($criticalFailed | ForEach-Object id)
        }

        $knownTotal += @($rows | Where-Object { $_.status -in @('detected', 'missing', 'not_applicable') }).Count
        $requiredTotal += $rows.Count
        if ($confirmed -and $confirmedStage -eq ([int]$stageKey - 1)) { $confirmedStage = [int]$stageKey }
        if ($provisional -and $provisionalStage -eq ([int]$stageKey - 1)) { $provisionalStage = [int]$stageKey }
    }

    $weightedRows = foreach ($weightProperty in $model.weightedScoring.weights.PSObject.Properties) {
        $signalProperty = $Signals.PSObject.Properties[$weightProperty.Name]
        $status = if ($signalProperty) { [string]$signalProperty.Value.status } else { 'unknown' }
        [pscustomobject]@{ id = $weightProperty.Name; weight = [double]$weightProperty.Value; status = $status }
    }
    $applicableWeight = 0.0
    $earnedWeight = 0.0
    $unresolvedWeight = 0.0
    foreach ($row in $weightedRows) {
        if ($row.status -ne 'not_applicable') { $applicableWeight += $row.weight }
        if ($row.status -eq 'detected') { $earnedWeight += $row.weight }
        if ($row.status -in @('unknown', 'manual_confirmation', 'error')) { $unresolvedWeight += $row.weight }
    }
    $maturityScore = if ($applicableWeight) { [math]::Round(($earnedWeight / $applicableWeight) * 100) } else { 0 }

    $scoreStage = 0
    foreach ($band in @($model.weightedScoring.bands | Sort-Object minimum)) {
        if ($maturityScore -ge [int]$band.minimum) { $scoreStage = [int]$band.stage }
    }

    # Keep a separate critical-control ceiling for implementation readiness.
    # The maturity stage itself remains an honest representation of the weighted
    # score; critical gaps are reported rather than silently changing that score.
    $criticalCap = 4
    foreach ($stageNumber in 1..4) {
        $failed = @($definitions[[string]$stageNumber].critical | Where-Object {
            $property = $Signals.PSObject.Properties[$_]
            (-not $property) -or ([string]$property.Value.status -ne 'detected')
        })
        if ($failed.Count) { $criticalCap = $stageNumber - 1; break }
    }
    $confirmedStage = $scoreStage

    $confidence = if ($requiredTotal) { [math]::Round($knownTotal / $requiredTotal, 2) } else { 0 }
    $label = if ($confidence -ge .85) { 'high' } elseif ($confidence -ge .6) { 'moderate' } else { 'low' }
    return [pscustomobject][ordered]@{
        stage            = $confirmedStage
        provisionalStage = $confirmedStage
        maturityScore    = $maturityScore
        earnedPoints     = [math]::Round($earnedWeight, 2)
        availablePoints  = [math]::Round($applicableWeight, 2)
        unresolvedPoints = [math]::Round($unresolvedWeight, 2)
        scoreStage       = $scoreStage
        criticalCap      = $criticalCap
        confidence       = $confidence
        confidenceLabel  = $label
        stageResults     = [pscustomobject]$stageResults
    }
}

function Test-CaSnapshotContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Snapshot)

    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($property in @('schemaVersion', 'scriptVersion', 'modelVersion', 'policyLibraryVersion', 'generatedAt', 'tenant', 'collector', 'context', 'assessment', 'signals', 'manualChecks', 'warnings', 'errors')) {
        if (-not $Snapshot.PSObject.Properties[$property]) { $errors.Add("Missing required property: $property") }
    }
    if ($errors.Count) { return [pscustomobject]@{ Valid = $false; Errors = @($errors) } }
    if ($Snapshot.schemaVersion -ne '1.0.0') { $errors.Add("Unsupported schemaVersion: $($Snapshot.schemaVersion)") }
    try { [datetimeoffset]::Parse([string]$Snapshot.generatedAt) | Out-Null } catch { $errors.Add('generatedAt must be an ISO-8601 timestamp') }
    if (-not $Snapshot.tenant.fingerprint) { $errors.Add('tenant.fingerprint is required') }
    if ($Snapshot.assessment.stage -lt 0 -or $Snapshot.assessment.stage -gt 4) { $errors.Add('assessment.stage must be between 0 and 4') }
    if ($Snapshot.assessment.confidence -lt 0 -or $Snapshot.assessment.confidence -gt 1) { $errors.Add('assessment.confidence must be between 0 and 1') }
    if ($Snapshot.assessment.PSObject.Properties['maturityScore'] -and ($Snapshot.assessment.maturityScore -lt 0 -or $Snapshot.assessment.maturityScore -gt 100)) { $errors.Add('assessment.maturityScore must be between 0 and 100') }
    if ($Snapshot.assessment.PSObject.Properties['earnedPoints'] -and $Snapshot.assessment.PSObject.Properties['availablePoints'] -and $Snapshot.assessment.earnedPoints -gt $Snapshot.assessment.availablePoints) { $errors.Add('assessment.earnedPoints cannot exceed assessment.availablePoints') }
    foreach ($property in $Snapshot.signals.PSObject.Properties) {
        $signal = $property.Value
        if ([string]$signal.status -notin $script:ValidStatuses) { $errors.Add("$($property.Name): invalid status '$($signal.status)'") }
        if (-not [string]$signal.reason) { $errors.Add("$($property.Name): reason is required") }
        if (-not $signal.PSObject.Properties['evidence']) { $errors.Add("$($property.Name): evidence array is required") }
        if (-not $signal.PSObject.Properties['checkedAt']) { $errors.Add("$($property.Name): checkedAt is required") }
        else {
            $checkedAtValue = [datetimeoffset]::MinValue
            if (-not [datetimeoffset]::TryParse([string]$signal.checkedAt, [ref]$checkedAtValue)) { $errors.Add("$($property.Name): checkedAt must be an ISO-8601 timestamp") }
        }
    }
    return [pscustomobject]@{ Valid = ($errors.Count -eq 0); Errors = @($errors) }
}

function Get-CaSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

Export-ModuleMember -Function New-CaSignalResult, Get-CaStageDefinitions, Get-CaMaturityScore, Test-CaSnapshotContract, Get-CaSha256
