#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Reports

<#
.SYNOPSIS
Collects read-only Microsoft Entra Conditional Access signals and produces a local,
versioned JSON snapshot plus an HTML report.

.DESCRIPTION
The script requests only permissions used by its current Graph calls. It never creates,
updates, or deletes tenant data. Detection is conservative: incomplete evidence becomes
unknown or manual_confirmation, never detected. Unknown signals cannot improve maturity.

.PARAMETER TenantId
The explicit Microsoft Entra tenant ID to assess. Required to reduce wrong-tenant risk.

.PARAMETER OutputPath
Required destination folder for the local JSON and HTML outputs. The folder is
created when it does not already exist. Relative and absolute paths are supported.

.PARAMETER ManualOverridesPath
Optional reviewed JSON file containing manual signal outcomes. Use only after a human has
verified the control. See manual-overrides.example.json.

.PARAMETER CompareTo
Optional earlier schema-v1 snapshot from the same tenant fingerprint.

.PARAMETER SkipConfirmation
Skips the interactive consent summary. Do not use on the first run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath,
    [string]$ManualOverridesPath,
    [string]$CompareTo,
    [switch]$IncludeSignInActivity,
    [switch]$IncludeAgentInventory,
    [string[]]$EmergencyAccessObjectId,
    [switch]$SkipConfirmation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src\Assessment.Core.psm1') -Force

$ScriptVersion = '0.2.0'
$SchemaVersion = '1.0.0'
$ModelVersion = '1.0.0'
$PolicyLibraryVersion = '1.0.0'
$RequiredScopes = @('Policy.Read.All', 'Organization.Read.All')
if ($IncludeSignInActivity) { $RequiredScopes += 'AuditLog.Read.All' }
if ($IncludeAgentInventory) { $RequiredScopes += @('AgentIdentity.Read.All', 'AgentIdentityBlueprint.Read.All') }
$Warnings = New-Object System.Collections.Generic.List[object]
$Errors = New-Object System.Collections.Generic.List[object]

function Add-CaMessage {
    param([ValidateSet('warning', 'error')][string]$Kind, [string]$Code, [string]$Message, [string]$SignalId)
    $item = [ordered]@{ code = $Code; message = $Message }
    if ($SignalId) { $item.signalId = $SignalId }
    if ($Kind -eq 'warning') { $Warnings.Add([pscustomobject]$item) } else { $Errors.Add([pscustomobject]$item) }
}

function ConvertTo-HtmlText([object]$Value) {
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Show-ConsentBanner {
    Write-Host ''
    Write-Host 'Conditional Access Maturity Assessment - READ ONLY' -ForegroundColor Cyan
    Write-Host "Tenant: $TenantId"
    Write-Host 'Delegated Microsoft Graph scopes:'
    $RequiredScopes | ForEach-Object { Write-Host "  - $_" }
    Write-Host "Local output: $OutputPath"
    Write-Host 'No tenant data is sent to the website or another service.'
    if (-not $SkipConfirmation) {
        if ((Read-Host 'Type CONFIRM to connect') -cne 'CONFIRM') { throw 'Confirmation not provided; no Graph connection was opened.' }
    }
}

function Invoke-CaGraphCall {
    param([string]$Name, [string]$SignalId, [scriptblock]$Action)
    try { return & $Action }
    catch {
        $message = $_.Exception.Message
        $code = if ($message -match '403|Forbidden|Authorization_RequestDenied|insufficient') { 'permission_or_license' } else { 'graph_call_failed' }
        Add-CaMessage -Kind warning -Code $code -Message "${Name}: $message" -SignalId $SignalId
        Write-Warning "${Name} could not be collected: $message"
        return $null
    }
}

function Get-PolicyEvidence([object]$Policy, [string[]]$ObservedProperties) {
    $id = if ($Policy.Id) { [string]$Policy.Id } else { [string]$Policy.DisplayName }
    return [pscustomobject][ordered]@{
        policyFingerprint  = Get-CaSha256 $id
        policyState        = [string]$Policy.State
        observedProperties = @($ObservedProperties)
    }
}

function Get-CaOperationalAnalysis([object[]]$Policies, [string[]]$EmergencyIds) {
    if($null-eq$Policies){return [pscustomobject][ordered]@{available=$false;policiesWithExclusions=$null;exclusionReferences=$null;overlapPairs=@();emergencyAccess=[pscustomobject]@{supplied=@($EmergencyIds).Count;fullyExcluded=$null;ready=$false}}}
    $active=@($Policies|Where-Object State -in @('enabled','enabledForReportingButNotEnforced'))
    $enforced=@($Policies|Where-Object State -eq 'enabled')
    $withExclusions=@($active|Where-Object{@($_.Conditions.Users.ExcludeUsers).Count+@($_.Conditions.Users.ExcludeGroups).Count+@($_.Conditions.Applications.ExcludeApplications).Count-gt 0})
    $referenceCount=0;foreach($p in $withExclusions){$referenceCount+=@($p.Conditions.Users.ExcludeUsers).Count+@($p.Conditions.Users.ExcludeGroups).Count+@($p.Conditions.Applications.ExcludeApplications).Count}
    $pairs=@()
    for($i=0;$i-lt$active.Count;$i++){for($j=$i+1;$j-lt$active.Count;$j++){
        $a=$active[$i];$b=$active[$j]
        $sameUsers=(@($a.Conditions.Users.IncludeUsers)|Sort-Object)-join',' -eq (@($b.Conditions.Users.IncludeUsers)|Sort-Object)-join','
        $sameApps=(@($a.Conditions.Applications.IncludeApplications)|Sort-Object)-join',' -eq (@($b.Conditions.Applications.IncludeApplications)|Sort-Object)-join','
        if($sameUsers-and$sameApps){$pairs+=,[pscustomobject]@{first=Get-CaSha256([string]$a.Id);second=Get-CaSha256([string]$b.Id);states="$($a.State) / $($b.State)"}}
    }}
    $fullyExcluded=0
    foreach($id in @($EmergencyIds)){if(-not@($enforced|Where-Object{$id-notin@($_.Conditions.Users.ExcludeUsers)}).Count){$fullyExcluded++}}
    return [pscustomobject][ordered]@{available=$true;policiesWithExclusions=$withExclusions.Count;exclusionReferences=$referenceCount;overlapPairs=@($pairs);emergencyAccess=[pscustomobject]@{supplied=@($EmergencyIds).Count;fullyExcluded=$fullyExcluded;ready=(@($EmergencyIds).Count-ge2-and$fullyExcluded-eq@($EmergencyIds).Count)}}
}

function Get-EnabledPolicies([object[]]$Policies) {
    if ($null -eq $Policies) { return @() }
    return @($Policies | Where-Object State -eq 'enabled')
}
function Get-ReportOnlyPolicies([object[]]$Policies) {
    if ($null -eq $Policies) { return @() }
    return @($Policies | Where-Object State -eq 'enabledForReportingButNotEnforced')
}

function Resolve-PolicySignal {
    param([string]$Id, [object[]]$Policies, [scriptblock]$Predicate, [string[]]$EvidenceProperties, [string]$DetectedReason, [string]$MissingReason)
    if ($null -eq $Policies) { return New-CaSignalResult unknown 'Conditional Access policies could not be collected.' @() 'ca_policies_unavailable' }
    $enabled = @(Get-EnabledPolicies $Policies | Where-Object $Predicate)
    if ($enabled.Count) { return New-CaSignalResult detected $DetectedReason @($enabled | ForEach-Object { Get-PolicyEvidence $_ $EvidenceProperties }) }
    $reportOnly = @(Get-ReportOnlyPolicies $Policies | Where-Object $Predicate)
    if ($reportOnly.Count) { return New-CaSignalResult missing 'A matching policy exists only in report-only mode and is not enforced.' @($reportOnly | ForEach-Object { Get-PolicyEvidence $_ $EvidenceProperties }) }
    return New-CaSignalResult missing $MissingReason
}

function Get-CaSignals([object[]]$Policies) {
    $signals = [ordered]@{}
    $signals['block-legacy-auth'] = Resolve-PolicySignal 'block-legacy-auth' $Policies {
        $types = @($_.Conditions.ClientAppTypes)
        ($types -contains 'all' -or (($types -contains 'exchangeActiveSync') -and ($types -contains 'other'))) -and
        ($_.GrantControls.BuiltInControls -contains 'block')
    } @('conditions.clientAppTypes', 'grantControls.builtInControls') 'An enabled blocking policy covers both Exchange ActiveSync and other legacy clients.' 'No enabled policy was found that blocks both legacy client categories.'

    $signals['block-device-code-flow'] = Resolve-PolicySignal 'block-device-code-flow' $Policies {
        ([string]$_.Conditions.AuthenticationFlows.TransferMethods -eq 'deviceCodeFlow') -and ($_.GrantControls.BuiltInControls -contains 'block')
    } @('conditions.authenticationFlows.transferMethods', 'grantControls.builtInControls', 'conditions.applications') 'An enabled policy blocks device code flow; review resource and account exclusions.' 'No enabled policy blocking device code flow was found.'

    $signals['mfa-all-users'] = Resolve-PolicySignal 'mfa-all-users' $Policies {
        ($_.Conditions.Users.IncludeUsers -contains 'All') -and
        ($_.Conditions.Applications.IncludeApplications -contains 'All') -and
        (($_.GrantControls.BuiltInControls -contains 'mfa') -or $null -ne $_.GrantControls.AuthenticationStrength)
    } @('conditions.users', 'conditions.applications', 'grantControls') 'An enabled policy requires MFA or authentication strength for all users and all resources; exclusions still require review.' 'No enabled all-users/all-resources MFA policy was found.'

    $adminCandidates = @((Get-EnabledPolicies $Policies) | Where-Object {
        @($_.Conditions.Users.IncludeRoles).Count -gt 0 -and (($_.GrantControls.BuiltInControls -contains 'mfa') -or $null -ne $_.GrantControls.AuthenticationStrength)
    })
    $signals['mfa-admins-strict'] = if ($null -eq $Policies) { New-CaSignalResult unknown 'Conditional Access policies could not be collected.' }
        elseif ($adminCandidates.Count) { New-CaSignalResult manual_confirmation 'One or more privileged-role policies were found, but complete role coverage and exclusions require human verification.' @($adminCandidates | ForEach-Object { Get-PolicyEvidence $_ @('conditions.users.includeRoles', 'conditions.users.exclusions', 'grantControls') }) }
        else { New-CaSignalResult missing 'No enabled policy targeting directory roles with MFA or authentication strength was found.' }

    $signals['break-glass-exclusion'] = New-CaSignalResult manual_confirmation 'Confirm at least two monitored emergency-access accounts are excluded from every applicable policy and tested regularly.'
    $signals['mfa-registration-enforcement'] = Invoke-CaGraphCall 'Authentication methods registration campaign' 'mfa-registration-enforcement' {
        $policy = Get-MgPolicyAuthenticationMethodPolicy
        $campaign = $policy.RegistrationEnforcement.AuthenticationMethodsRegistrationCampaign
        if ($campaign.State -eq 'enabled' -and @($campaign.IncludeTargets).Count -gt 0) { New-CaSignalResult detected 'The authentication-method registration campaign is enabled with included targets.' @([pscustomobject]@{ observedProperties = @('registrationEnforcement.authenticationMethodsRegistrationCampaign.state', 'includeTargets') }) }
        else { New-CaSignalResult missing 'The authentication-method registration campaign is not enabled with included targets.' }
    }
    if ($null -eq $signals['mfa-registration-enforcement']) { $signals['mfa-registration-enforcement'] = New-CaSignalResult unknown 'Registration campaign configuration could not be read.' }

    $signals['block-unsupported-platforms'] = Resolve-PolicySignal 'block-unsupported-platforms' $Policies {
        $null -ne $_.Conditions.Platforms -and ($_.GrantControls.BuiltInControls -contains 'block')
    } @('conditions.platforms', 'grantControls.builtInControls') 'An enabled blocking policy targets device platforms; supported-platform scope still requires review.' 'No enabled platform blocking policy was found.'

    $signals['device-compliance-sensitive-apps'] = Resolve-PolicySignal 'device-compliance-sensitive-apps' $Policies {
        ($_.GrantControls.BuiltInControls -contains 'compliantDevice') -or ($_.GrantControls.BuiltInControls -contains 'domainJoinedDevice')
    } @('conditions.applications', 'grantControls.builtInControls') 'An enabled policy requires a compliant or hybrid-joined device. Confirm the targeted resources are the intended sensitive applications.' 'No enabled policy requiring device compliance or hybrid join was found.'

    $sessionCandidates = @((Get-EnabledPolicies $Policies) | Where-Object { $null -ne $_.SessionControls.SignInFrequency -or $null -ne $_.SessionControls.PersistentBrowser -or $null -ne $_.SessionControls.ApplicationEnforcedRestrictions })
    $signals['session-controls-unmanaged'] = if ($null -eq $Policies) { New-CaSignalResult unknown 'Conditional Access policies could not be collected.' }
        elseif ($sessionCandidates.Count) { New-CaSignalResult manual_confirmation 'Session controls were found, but the SDK response does not prove they are limited to unmanaged devices.' @($sessionCandidates | ForEach-Object { Get-PolicyEvidence $_ @('conditions.devices', 'sessionControls') }) }
        else { New-CaSignalResult missing 'No enabled sign-in-frequency, persistent-browser, or application-enforced restriction was found.' }

    $signals['guest-access-restriction'] = Resolve-PolicySignal 'guest-access-restriction' $Policies {
        $guestTargeted = ($null -ne $_.Conditions.Users.IncludeGuestsOrExternalUsers) -or ($_.Conditions.Users.IncludeUsers -contains 'GuestsOrExternalUsers')
        $hasControl = @($_.GrantControls.BuiltInControls).Count -gt 0 -or $null -ne $_.GrantControls.AuthenticationStrength -or $null -ne $_.SessionControls
        $guestTargeted -and $hasControl
    } @('conditions.users.includeGuestsOrExternalUsers', 'grantControls', 'sessionControls') 'An enabled policy explicitly targets guests or external users and applies access controls.' 'No enabled controlled policy explicitly targeting guests or external users was found.'

    $signals['app-protection-policy-mam'] = Resolve-PolicySignal 'app-protection-policy-mam' $Policies {
        ($_.GrantControls.BuiltInControls -contains 'approvedApplication') -or ($_.GrantControls.BuiltInControls -contains 'compliantApplication')
    } @('conditions.clientAppTypes', 'grantControls.builtInControls') 'An enabled policy requires an approved or policy-compliant application.' 'No enabled policy requiring an approved or policy-compliant application was found.'

    $azureManagementId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    $signals['azure-management-protection'] = Resolve-PolicySignal 'azure-management-protection' $Policies {
        ($_.Conditions.Applications.IncludeApplications -contains $azureManagementId) -and @($_.GrantControls.BuiltInControls).Count -gt 0
    } @('conditions.applications.includeApplications', 'grantControls') 'An enabled controlled policy explicitly targets Microsoft Azure Management.' 'No enabled controlled policy explicitly targeting Microsoft Azure Management was found.'

    $signals['terms-of-use'] = Resolve-PolicySignal 'terms-of-use' $Policies {
        @($_.GrantControls.TermsOfUse).Count -gt 0
    } @('grantControls.termsOfUse') 'An enabled policy requires Terms of Use.' 'No enabled Conditional Access policy requiring Terms of Use was found.'
    $signals['risk-based-signin'] = Resolve-PolicySignal 'risk-based-signin' $Policies { @($_.Conditions.SignInRiskLevels).Count -gt 0 -and @($_.GrantControls.BuiltInControls).Count -gt 0 } @('conditions.signInRiskLevels', 'grantControls') 'An enabled controlled policy uses sign-in risk.' 'No enabled controlled policy using sign-in risk was found.'
    $signals['risk-based-user'] = Resolve-PolicySignal 'risk-based-user' $Policies { @($_.Conditions.UserRiskLevels).Count -gt 0 -and @($_.GrantControls.BuiltInControls).Count -gt 0 } @('conditions.userRiskLevels', 'grantControls') 'An enabled controlled policy uses user risk.' 'No enabled controlled policy using user risk was found.'

    $strengthCandidates = @((Get-EnabledPolicies $Policies) | Where-Object { $null -ne $_.GrantControls.AuthenticationStrength })
    $signals['auth-strength-phishing-resistant'] = if ($null -eq $Policies) { New-CaSignalResult unknown 'Conditional Access policies could not be collected.' }
        elseif ($strengthCandidates.Count) { New-CaSignalResult manual_confirmation 'Authentication strength is used, but confirm that the selected strength is phishing resistant and correctly scoped.' @($strengthCandidates | ForEach-Object { Get-PolicyEvidence $_ @('grantControls.authenticationStrength', 'conditions') }) }
        else { New-CaSignalResult missing 'No enabled policy using authentication strength was found.' }

    $signals['pim-step-up'] = New-CaSignalResult manual_confirmation 'Confirm PIM activation is connected to a protected authentication context.'
    $signals['cae-enable'] = New-CaSignalResult manual_confirmation 'Continuous Access Evaluation is normally enabled by default; confirm supported app coverage and that no policy disables it.'
    $signals['workload-identity-ca'] = Resolve-PolicySignal 'workload-identity-ca' $Policies {
        @($_.Conditions.ClientApplications.IncludeServicePrincipals).Count -gt 0 -and @($_.GrantControls.BuiltInControls).Count -gt 0
    } @('conditions.clientApplications', 'conditions.servicePrincipalRiskLevels', 'grantControls') 'An enabled controlled policy targets workload identities.' 'No enabled controlled policy targeting workload identities was found.'
    $signals['token-protection'] = New-CaSignalResult manual_confirmation 'Token Protection cannot be asserted from the stable SDK session-control shape without inspecting tenant-specific raw policy data.'
    $signals['cross-tenant-access-enforcement'] = New-CaSignalResult manual_confirmation 'Cross-tenant defaults can be collected, but effective partner-specific trust and CA coverage require human review.'
    $signals['agent-approved-access'] = New-CaSignalResult manual_confirmation 'Confirm a policy blocks unapproved agent identities while excluding reviewed agents or approved agent blueprints.'
    $signals['agent-risk-block'] = New-CaSignalResult manual_confirmation 'Confirm an agent-targeted policy blocks high-risk agent identities across all intended resources.'
    $signals['agent-obo-access'] = New-CaSignalResult manual_confirmation 'Confirm delegated on-behalf-of agent access is covered through user-scoped policies for downstream resources.'
    foreach ($id in @('global-secure-access', 'defender-cloud-apps-session-control', 'insider-risk-signal', 'policy-as-code')) {
        $signals[$id] = New-CaSignalResult manual_confirmation 'This control spans configuration or governance that the current collector cannot safely prove.'
    }
    return [pscustomobject]$signals
}

function Apply-ManualOverrides([object]$Signals, [string]$Path) {
    if (-not $Path) { return }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Manual override file not found: $Path" }
    $overrides = Get-Content -Raw -Encoding UTF8 -LiteralPath $Path | ConvertFrom-Json
    foreach ($entry in $overrides.PSObject.Properties) {
        if (-not $Signals.PSObject.Properties[$entry.Name]) { throw "Unknown manual override signal: $($entry.Name)" }
        if ([string]$entry.Value.status -notin @('detected', 'missing', 'not_applicable', 'manual_confirmation')) { throw "Manual override '$($entry.Name)' has an invalid status." }
        if (-not [string]$entry.Value.reason) { throw "Manual override '$($entry.Name)' requires a reason." }
        $Signals.($entry.Name) = New-CaSignalResult -Status $entry.Value.status -Reason $entry.Value.reason -Evidence @([pscustomobject]@{ source = 'reviewed_manual_override' })
    }
}

function Get-CaHtmlReport([object]$Snapshot, [object]$MaturityModel, [object]$PolicyLibrary, [object]$Diff) {
    $stage = $MaturityModel.stages | Where-Object id -eq $Snapshot.assessment.stage
    $scoreModel = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot 'assessment-model.json') | ConvertFrom-Json
    $labels = @{ detected='Detected'; missing='Missing'; not_applicable='Not applicable'; manual_confirmation='Manual review'; unknown='Unknown'; error='Error' }
    $icons = @{ detected='&#10003;'; missing='&#10005;'; not_applicable='&#8212;'; manual_confirmation='i'; unknown='!'; error='&#10005;' }
    $rank = @{ error=0; missing=1; unknown=2; manual_confirmation=3; detected=4; not_applicable=5 }
    # Deployment sequence, not policy precedence. Microsoft Entra evaluates all
    # matching policies; lower numbers here mean "implement first."
    $priority = @{
        'break-glass-exclusion'=1;'block-legacy-auth'=2;'block-device-code-flow'=3;'mfa-admins-strict'=4;'auth-strength-phishing-resistant'=5;
        'mfa-all-users'=6;'mfa-registration-enforcement'=7;'azure-management-protection'=8;'block-unsupported-platforms'=9;
        'device-compliance-sensitive-apps'=10;'app-protection-policy-mam'=11;'session-controls-unmanaged'=12;'guest-access-restriction'=13;
        'terms-of-use'=14;'risk-based-signin'=15;'risk-based-user'=16;'pim-step-up'=17;'cae-enable'=18;'token-protection'=19;
        'workload-identity-ca'=20;'agent-approved-access'=21;'agent-risk-block'=22;'agent-obo-access'=23;
        'cross-tenant-access-enforcement'=24;'defender-cloud-apps-session-control'=25;
        'global-secure-access'=26;'insider-risk-signal'=27;'policy-as-code'=28
    }
    $domains = @{
        'block-legacy-auth'='Identity protection';'block-device-code-flow'='Identity protection';'mfa-all-users'='Users & authentication';'mfa-admins-strict'='Privileged identity';'break-glass-exclusion'='Privileged identity';'mfa-registration-enforcement'='Users & authentication';
        'block-unsupported-platforms'='Devices & applications';'device-compliance-sensitive-apps'='Devices & applications';'session-controls-unmanaged'='Sessions & tokens';'guest-access-restriction'='External identities';
        'app-protection-policy-mam'='Devices & applications';'azure-management-protection'='Privileged identity';'terms-of-use'='Users & authentication';'risk-based-signin'='Identity protection';'risk-based-user'='Identity protection';
        'auth-strength-phishing-resistant'='Privileged identity';'pim-step-up'='Privileged identity';'cae-enable'='Sessions & tokens';'workload-identity-ca'='Workload identities';'token-protection'='Sessions & tokens';
        'cross-tenant-access-enforcement'='External identities';'agent-approved-access'='Agentic identities';'agent-risk-block'='Agentic identities';'agent-obo-access'='Agentic identities';'global-secure-access'='Network & governance';'defender-cloud-apps-session-control'='Sessions & tokens';'insider-risk-signal'='Identity protection';'policy-as-code'='Network & governance'
    }
    $learn = @{
        'block-legacy-auth'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication';'block-device-code-flow'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows#device-code-flow-policies';'mfa-all-users'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength';
        'mfa-admins-strict'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-require-mfa-admin';'break-glass-exclusion'='https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access';
        'mfa-registration-enforcement'='https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-registration-campaign';'block-unsupported-platforms'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions#device-platforms';
        'device-compliance-sensitive-apps'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance';'session-controls-unmanaged'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-session';
        'guest-access-restriction'='https://learn.microsoft.com/en-us/entra/external-id/authentication-conditional-access';'app-protection-policy-mam'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant#require-app-protection-policy';
        'azure-management-protection'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-mfa-azure-management';'terms-of-use'='https://learn.microsoft.com/en-us/entra/identity-governance/terms-of-use';
        'risk-based-signin'='https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-policies#sign-in-risk-based-conditional-access-policy';'risk-based-user'='https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-policies#user-risk-based-conditional-access-policy';
        'auth-strength-phishing-resistant'='https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strength-how-it-works';'pim-step-up'='https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings';
        'cae-enable'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation';'workload-identity-ca'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity';
        'token-protection'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection';'cross-tenant-access-enforcement'='https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview';
        'global-secure-access'='https://learn.microsoft.com/en-us/entra/global-secure-access/concept-universal-conditional-access';'defender-cloud-apps-session-control'='https://learn.microsoft.com/en-us/defender-cloud-apps/conditional-access-app-control-how-to-overview';
        'insider-risk-signal'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions#insider-risk';'policy-as-code'='https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy';
        'agent-approved-access'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-autonomous-agents#allow-only-specific-agents-to-access-resources';
        'agent-risk-block'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-autonomous-agents#block-high-risk-agents-from-accessing-organizational-resources';
        'agent-obo-access'='https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id#agents-acting-on-behalf-of-a-user'
    }
    $records = foreach ($property in $Snapshot.signals.PSObject.Properties) {
        $policy = $PolicyLibrary.policies | Where-Object id -eq $property.Name | Select-Object -First 1
        $weightProperty = $scoreModel.weightedScoring.weights.PSObject.Properties[$property.Name]
        [pscustomobject]@{Id=$property.Name;Name=if($policy){$policy.name}else{$property.Name};Status=[string]$property.Value.status;Reason=$property.Value.reason;Domain=$domains[$property.Name];Learn=$learn[$property.Name];Priority=$priority[$property.Name];Points=if($weightProperty){[int]$weightProperty.Value}else{0};Conditions=$policy.conditions;Grant=$policy.grant_controls;Why=$policy.why_it_matters;Gotchas=@($policy.gotchas)}
    }
    $tableRows = foreach ($item in @($records | Sort-Object Priority)) {
        $s=ConvertTo-HtmlText $item.Status
        $gotchas=(@($item.Gotchas)|ForEach-Object{"<li>$(ConvertTo-HtmlText $_)</li>"})-join''
        "<tr class=`"finding`" data-status=`"$s`"><td class=`"order`">$($item.Priority)</td><td class=`"points`">$($item.Points)</td><td class=`"control`"><strong>$(ConvertTo-HtmlText $item.Name)</strong><code>$(ConvertTo-HtmlText $item.Id)</code><p>$(ConvertTo-HtmlText $item.Reason)</p><details class=`"runbook`"><summary>Implementation notes</summary><dl><dt>Why</dt><dd>$(ConvertTo-HtmlText $item.Why)</dd><dt>Scope</dt><dd>$(ConvertTo-HtmlText $item.Conditions)</dd><dt>Control</dt><dd>$(ConvertTo-HtmlText $item.Grant)</dd></dl><ul>$gotchas</ul></details></td><td>$(ConvertTo-HtmlText $item.Domain)</td><td><span class=`"status $s`"><b aria-hidden=`"true`">$($icons[$item.Status])</b>$($labels[$item.Status])</span></td><td><a class=`"guide`" href=`"$(ConvertTo-HtmlText $item.Learn)`" target=`"_blank`" rel=`"noopener noreferrer`">Implementation guide &#8599;</a></td></tr>"
    }
    $groups="<div class=`"register`"><table><thead><tr><th scope=`"col`">Order</th><th scope=`"col`">Points</th><th scope=`"col`">Control and finding</th><th scope=`"col`">Domain</th><th scope=`"col`">Status</th><th scope=`"col`">Guidance</th></tr></thead><tbody>$($tableRows -join '')</tbody></table></div>"
    $nextItems=@($records|Where-Object Status -in @('missing','unknown','error','manual_confirmation')|Sort-Object Priority|Select-Object -First 3)
    $nextHtml=if($nextItems.Count){$items=@($nextItems|ForEach-Object{"<li><span>$($_.Priority)</span><div><strong>$(ConvertTo-HtmlText $_.Name)</strong><p>$(ConvertTo-HtmlText $_.Reason)</p></div></li>"})-join'';"<section class=`"next-actions`"><p class=`"section-label`">RECOMMENDED NEXT ACTIONS</p><h2>Start here</h2><ol>$items</ol></section>"}else{''}
    $counts=@{};foreach($key in $labels.Keys){$counts[$key]=@($records|Where-Object Status -eq $key).Count}
    $collectionUnavailable = $null -eq $Snapshot.context.policyCount
    $warningHtml = if (@($Snapshot.warnings).Count -or $collectionUnavailable) { $warningItems=@($Snapshot.warnings|ForEach-Object{"<li><strong>$(ConvertTo-HtmlText $_.code)</strong><span>$(ConvertTo-HtmlText $_.message)</span></li>"})-join''; if($collectionUnavailable -and -not $warningItems){$warningItems='<li><strong>Conditional Access policies unavailable</strong><span>The collector could not read the policy inventory. Treat policy-dependent findings as unknown and rerun the assessment after resolving collection access.</span></li>'}; "<section class=`"alert`" role=`"alert`"><i>!</i><div><small>COLLECTION WARNING</small><h2>Some tenant evidence could not be collected</h2><ul>$warningItems</ul></div></section>" } else { '' }
    $diffHtml = if ($Diff) { "<section class=`"change`"><small>CHANGE SINCE COMPARISON</small><h2>Assessment movement</h2><p>$(ConvertTo-HtmlText $Diff.summary)</p></section>" } else { '' }
    $policyCount=if($null-eq$Snapshot.context.policyCount){'Unavailable'}else{[string]$Snapshot.context.policyCount}
    $enabledCount=if($null-eq$Snapshot.context.enabledPolicyCount){'-'}else{[string]$Snapshot.context.enabledPolicyCount}
    $reportOnlyCount=if($null-eq$Snapshot.context.reportOnlyPolicyCount){'-'}else{[string]$Snapshot.context.reportOnlyPolicyCount}
    $score = if($Snapshot.assessment.PSObject.Properties['maturityScore']){[string]$Snapshot.assessment.maturityScore}else{'-'}
    $earnedPoints = if($Snapshot.assessment.PSObject.Properties['earnedPoints']){[string]$Snapshot.assessment.earnedPoints}else{'-'}
    $availablePoints = if($Snapshot.assessment.PSObject.Properties['availablePoints']){[string]$Snapshot.assessment.availablePoints}else{'-'}
    $gradingHtml="<details class=`"report-disclosure grading`"><summary>How the maturity is calculated</summary><div class=`"disclosure-body`"><ol><li><strong>The assessment is marked out of 100.</strong><span>This tenant earned $earnedPoints of $availablePoints applicable weighted points, producing a maturity score of $score/100.</span></li><li><strong>The 28 controls do not carry equal marks.</strong><span>Controls with greater security impact and broader exposure - such as emergency access, administrator MFA, legacy authentication, and tenant-wide MFA - are worth more than narrower or advanced controls.</span></li><li><strong>Evidence determines the points earned.</strong><span>A detected control earns its full weight. Missing, unknown, errored, and manual-review controls earn zero until verified. Not-applicable controls are removed and the result is normalized back to 100.</span></li><li><strong>Score and rollout order serve different purposes.</strong><span>The score measures protection. Recommended order also considers implementation effort, dependencies, and potential blast radius so high-value changes can be introduced safely. Critical gaps are shown separately as implementation-readiness blockers; they do not alter the numerical score.</span></li></ol><p>Score bands: Stage 0 = 0-24, Stage 1 = 25-49, Stage 2 = 50-69, Stage 3 = 70-84, and Stage 4 = 85-100.</p></div></details>"
    $gradingHtml += $nextHtml
    if($Snapshot.context.PSObject.Properties['broadCoveragePolicyCount']){
        $gradingHtml += "<details class=`"report-disclosure agent-summary`"><summary>Policy scope and rollout</summary><div class=`"disclosure-body`"><dl><div><dt>Broad all-user policies</dt><dd>$($Snapshot.context.broadCoveragePolicyCount)</dd></div><div><dt>Policies with exclusions</dt><dd>$($Snapshot.context.policiesWithExclusions)</dd></div><div><dt>Report-only</dt><dd>$($Snapshot.context.reportOnlyPolicyCount)</dd></div><div><dt>Enforced</dt><dd>$($Snapshot.context.enabledPolicyCount)</dd></div></dl></div></details>"
    }
    if($Snapshot.context.PSObject.Properties['agentInventory'] -and $Snapshot.context.agentInventory.requested){
        $a=$Snapshot.context.agentInventory
        $gradingHtml += "<details class=`"report-disclosure agent-summary`"><summary>Agent identity inventory</summary><div class=`"disclosure-body`"><dl><div><dt>Agent identities</dt><dd>$($a.identityCount)</dd></div><div><dt>Enabled</dt><dd>$($a.enabledCount)</dd></div><div><dt>Disabled</dt><dd>$($a.disabledCount)</dd></div><div><dt>Blueprints</dt><dd>$($a.blueprintCount)</dd></div></dl></div></details>"
    }
    if($Snapshot.context.PSObject.Properties['operationalAnalysis'] -and $Snapshot.context.operationalAnalysis.available){
        $o=$Snapshot.context.operationalAnalysis;$gate=if($o.emergencyAccess.ready){'Ready'}elseif($o.emergencyAccess.supplied-ge2){'Review'}else{'Not assessed'}
        $gradingHtml += "<details class=`"report-disclosure agent-summary`"><summary>Operational risk indicators</summary><div class=`"disclosure-body`"><dl><div><dt>Policies with exclusions</dt><dd>$($o.policiesWithExclusions)</dd></div><div><dt>Exclusion references</dt><dd>$($o.exclusionReferences)</dd></div><div><dt>Overlapping scopes</dt><dd>$(@($o.overlapPairs).Count)</dd></div><div><dt>Emergency-access gate</dt><dd>$gate</dd></div></dl></div></details>"
        if(-not$o.emergencyAccess.ready){$gradingHtml += "<div class=`"notice operational-note`"><strong>Enforcement safety gate not satisfied</strong><p>Supply at least two reviewed emergency-access object IDs and confirm they are excluded from every active policy before treating recommendations as ready to enforce.</p></div>"}
    }
    return @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Policy Atlas assessment report</title><style>
:root{color-scheme:light dark;--bg:#f3f6fa;--surface:#fff;--surface2:#f7f9fc;--text:#172033;--muted:#5e6b82;--line:#dce3ee;--blue:#175cd3;--blue2:#eaf2ff;--green:#16754a;--green2:#e7f6ee;--red:#b42318;--red2:#feeceb;--amber:#946200;--amber2:#fff3d6;--shadow:0 12px 30px rgba(24,39,75,.08)}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 "Segoe UI",system-ui,sans-serif}.shell{width:min(1160px,calc(100% - 40px));margin:auto}.hero{padding:58px 0 72px;background:linear-gradient(135deg,#0d2349,#174ea6 68%,#2878d0);color:#fff}.hero small,.domain small,.alert small,.change small{font-weight:800;letter-spacing:.13em}.hero h1{max-width:800px;margin:8px 0 12px;font-size:clamp(2.4rem,6vw,4.7rem);line-height:1;letter-spacing:-.05em}.hero p{max-width:700px;margin:0;color:#d7e6ff;font-size:1.05rem}.summary{display:grid;grid-template-columns:1.5fr 1fr 1fr;gap:16px;margin-top:-38px}.metric{padding:24px;border:1px solid var(--line);border-radius:16px;background:var(--surface);box-shadow:var(--shadow)}.metric.primary{background:#121d2e;color:#fff;border:0}.metric span{display:block;color:var(--muted);font-size:.78rem}.metric.primary span{color:#b8c6da}.metric strong{display:block;margin:8px 0 4px;font-size:1.9rem;letter-spacing:-.035em}.meta{display:flex;gap:20px;flex-wrap:wrap;padding:18px 0 30px;color:var(--muted);font-size:.8rem}.alert,.change{display:grid;grid-template-columns:auto 1fr;gap:18px;margin-bottom:28px;padding:22px;border:1px solid #f0bbb7;border-radius:14px;background:var(--red2)}.alert i{display:grid;place-items:center;width:38px;height:38px;border-radius:50%;background:var(--red);color:#fff;font-style:normal;font-weight:800}.alert h2,.change h2{margin:2px 0 8px;font-size:1.15rem}.alert ul{margin:0;padding:0;list-style:none}.alert li{display:grid;margin-top:8px}.alert li span{color:var(--muted);overflow-wrap:anywhere}.toolbar{position:sticky;top:0;z-index:5;padding:14px 0;border-block:1px solid var(--line);background:color-mix(in srgb,var(--bg) 92%,transparent);backdrop-filter:blur(10px)}.toolbar .shell{display:flex;align-items:center;justify-content:space-between;gap:16px}.toolbar h2{margin:0;font-size:1rem}.filters{display:flex;gap:7px;flex-wrap:wrap}.filter{padding:7px 11px;border:1px solid var(--line);border-radius:999px;background:var(--surface);color:var(--text);font:700 .78rem inherit;cursor:pointer}.filter[aria-pressed=true]{border-color:var(--blue);background:var(--blue2);color:var(--blue)}.evidence{padding-top:34px}.domain{margin-bottom:42px}.domain>header{display:flex;align-items:end;justify-content:space-between;margin-bottom:12px}.domain h2{margin:3px 0 0;font-size:1.5rem;letter-spacing:-.025em}.domain>header span{color:var(--muted);font-size:.8rem}.findings{overflow:hidden;border:1px solid var(--line);border-radius:16px;background:var(--surface);box-shadow:var(--shadow)}.finding{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:22px;padding:21px 22px;border-bottom:1px solid var(--line)}.finding:last-child{border:0}.finding[hidden],.domain[hidden]{display:none}.finding-head{display:flex;align-items:center;justify-content:space-between;gap:18px}.finding h3{margin:0;font-size:1rem}.finding code{display:inline-block;margin-top:8px;padding:3px 7px;border:1px solid var(--line);border-radius:6px;background:var(--surface2);color:var(--muted);font:600 .73rem ui-monospace,Consolas,monospace}.finding p{max-width:850px;margin:10px 0 0;color:var(--muted);font-size:.91rem}.finding>a{align-self:center;color:var(--blue);font-size:.82rem;font-weight:750;text-decoration:none;white-space:nowrap}.finding>a:hover{text-decoration:underline}.status{display:inline-flex;align-items:center;gap:6px;padding:5px 9px;border-radius:999px;font-size:.72rem;font-weight:800;white-space:nowrap}.status b{display:grid;place-items:center;width:16px;height:16px;border:1px solid;border-radius:50%;font-size:.65rem}.detected{color:var(--green);background:var(--green2)}.missing,.error{color:var(--red);background:var(--red2)}.unknown{color:var(--amber);background:var(--amber2)}.manual_confirmation{color:var(--blue);background:var(--blue2)}.not_applicable{color:var(--muted);background:var(--surface2)}footer{padding:2px 0 45px}.notice{padding:20px 22px;border-left:4px solid var(--amber);border-radius:5px 12px 12px 5px;background:var(--amber2)}.notice strong{color:var(--amber)}.notice p{margin:4px 0 0;color:var(--muted);font-size:.88rem}@media(max-width:760px){.shell{width:calc(100% - 24px)}.summary{grid-template-columns:1fr}.toolbar{position:static}.toolbar .shell,.finding-head{align-items:flex-start;flex-direction:column}.finding{grid-template-columns:1fr}.finding>a{justify-self:start}.meta{display:grid;gap:3px}}@media(prefers-color-scheme:dark){:root{--bg:#0d1420;--surface:#141e2d;--surface2:#0e1724;--text:#edf3fc;--muted:#9eacc2;--line:#29364a;--blue:#8bbaff;--blue2:#17345e;--green:#6fd6a3;--green2:#123c2c;--red:#ff9189;--red2:#461e21;--amber:#f7c65d;--amber2:#3d3015;--shadow:0 14px 34px rgba(0,0,0,.22)}}
/* Deliberately restrained report treatment: flat surfaces, compact hierarchy,
   and print-like spacing instead of landing-page effects. */
:root{color-scheme:light;--bg:#f7f8fa;--surface:#fff;--surface2:#f2f4f7;--text:#182230;--muted:#5f6b7a;--line:#d9dee7;--blue:#175cd3;--blue2:#eef4ff;--green:#067647;--green2:#ecfdf3;--red:#b42318;--red2:#fef3f2;--amber:#93370d;--amber2:#fffaeb;--shadow:none}body{background:var(--bg);color:var(--text);font-family:Arial,"Segoe UI",sans-serif}.hero{padding:34px 0 26px;border-top:5px solid #193b68;border-bottom:1px solid var(--line);background:var(--surface);color:var(--text)}.hero small{color:#315b8c;font-size:.7rem}.hero h1{margin:9px 0 8px;font-size:clamp(2rem,4vw,3rem);font-weight:650;letter-spacing:-.035em}.hero p{color:var(--muted);font-size:1rem}.summary{grid-template-columns:1.2fr 1fr;margin-top:24px;gap:0;border:1px solid var(--line);border-radius:6px;background:var(--surface)}.metric,.metric.primary{min-height:116px;padding:22px 24px;border:0;border-right:1px solid var(--line);border-radius:0;background:transparent;color:var(--text);box-shadow:none}.metric:last-child{border-right:0}.metric span,.metric.primary span{color:var(--muted);font-size:.72rem}.metric strong{font-size:1.65rem}.metric dl{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin:12px 0 0}.metric dt{color:var(--muted);font-size:.68rem;text-transform:uppercase}.metric dd{margin:2px 0 0;font-size:1.15rem;font-weight:700}.meta{padding:14px 2px 18px}.grading{margin:0 0 26px;border:1px solid var(--line);border-radius:6px;background:var(--surface)}.grading summary{padding:13px 16px;font-weight:700;cursor:pointer}.grading>div{padding:0 16px 14px;color:var(--muted);font-size:.9rem}.grading p{margin:4px 0 9px}.grading ul{margin:0 0 10px;padding-left:20px}.priority{display:inline-grid;place-items:center;width:25px;height:25px;margin-right:9px;border:1px solid #a8b2c1;border-radius:50%;color:#42526a;font-size:.72rem;font-weight:700;vertical-align:middle}.alert,.change{border-color:#f0b6b2;border-radius:6px;background:#fff7f6}.alert i{border-radius:4px}.toolbar{position:static;background:var(--surface);backdrop-filter:none}.filter{border-radius:4px}.filter[aria-pressed=true]{background:#edf4ff}.evidence{padding-top:30px}.domain{margin-bottom:34px}.domain h2{font-size:1.25rem}.findings{border-radius:6px;box-shadow:none}.finding{padding:18px 20px}.finding h3{font-weight:650}.status{border-radius:4px}.finding code{border:0;background:var(--surface2)}.finding>a{padding:7px 9px;border:1px solid var(--line);border-radius:4px;background:var(--surface);font-weight:650}.notice{border-radius:4px;background:#fffaf0}@media(prefers-color-scheme:dark){:root{color-scheme:light;--bg:#f7f8fa;--surface:#fff;--surface2:#f2f4f7;--text:#182230;--muted:#5f6b7a;--line:#d9dee7;--blue:#175cd3;--blue2:#eef4ff;--green:#067647;--green2:#ecfdf3;--red:#b42318;--red2:#fef3f2;--amber:#93370d;--amber2:#fffaeb;--shadow:none}}@media(max-width:760px){.summary{grid-template-columns:1fr}.metric,.metric.primary{min-height:auto;border-right:0;border-bottom:1px solid var(--line)}.metric:last-child{border-bottom:0}.metric dl{gap:10px}}
.register{overflow-x:auto;margin-bottom:34px;border:1px solid var(--line);border-radius:6px;background:var(--surface)}.register table{width:100%;min-width:940px;border-collapse:collapse}.register th{padding:11px 14px;border-bottom:1px solid var(--line);background:var(--surface2);color:var(--muted);font-size:.7rem;letter-spacing:.05em;text-align:left;text-transform:uppercase}.register td{padding:15px 14px;border-bottom:1px solid var(--line);vertical-align:top}.register tr:last-child td{border-bottom:0}.register tr.finding{display:table-row}.register tr.finding[hidden]{display:none}.register .order{width:62px;color:var(--muted);font-weight:700;text-align:center}.register .control{width:44%}.register .control strong{display:block;font-size:.94rem}.register .control code{display:inline-block;margin-top:5px;padding:2px 5px;border:0;border-radius:3px;background:var(--surface2);color:var(--muted);font:600 .7rem ui-monospace,Consolas,monospace}.register .control p{margin:7px 0 0;color:var(--muted);font-size:.85rem}.guide{display:inline-block;padding:6px 8px;border:1px solid var(--line);border-radius:4px;color:var(--blue);font-size:.78rem;font-weight:650;text-decoration:none;white-space:nowrap}.guide:hover{text-decoration:underline}
.next-actions,.agent-summary{margin:0 0 26px;padding:20px;border:1px solid var(--line);border-radius:6px;background:var(--surface)}.section-label{margin:0;color:var(--blue);font-size:.68rem;font-weight:800;letter-spacing:.09em}.next-actions h2,.agent-summary h2{margin:3px 0 14px;font-size:1.2rem}.next-actions ol{margin:0;padding:0;list-style:none}.next-actions li{display:grid;grid-template-columns:30px 1fr;gap:10px;padding:10px 0;border-top:1px solid var(--line)}.next-actions li>span{font-weight:800}.next-actions li p{margin:2px 0 0;color:var(--muted);font-size:.84rem}.agent-summary dl{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:0}.agent-summary dt{color:var(--muted);font-size:.72rem}.agent-summary dd{margin:2px 0;font-size:1.25rem;font-weight:700}.runbook{margin-top:9px}.runbook summary{color:var(--blue);font-size:.78rem;font-weight:700;cursor:pointer}.runbook dl{display:grid;grid-template-columns:60px 1fr;gap:5px 10px;margin:10px 0 0}.runbook dt{font-size:.75rem;font-weight:700}.runbook dd{margin:0;color:var(--muted);font-size:.8rem}.runbook ul{margin:8px 0 0;padding-left:18px;color:var(--muted);font-size:.8rem}@media(max-width:760px){.agent-summary dl{grid-template-columns:repeat(2,1fr)}}
/* Report typography follows an audit memo: quiet surfaces, rules instead of cards,
   and colour reserved for findings that need attention. */
body{background:#fff;color:#20242b;font-family:"Segoe UI",Arial,sans-serif}.shell{width:min(1080px,calc(100% - 48px))}.hero{padding:30px 0 24px;border-top:4px solid #23466d;background:#fff}.hero h1{max-width:none;margin:7px 0 5px;font-size:2.25rem;font-weight:600;letter-spacing:-.025em}.hero p{font-size:.95rem}.summary{margin-top:20px;border-width:1px 0;border-radius:0}.metric,.metric.primary{min-height:104px;padding:20px 0}.metric:first-child{padding-right:30px}.metric:last-child{padding-left:30px}.metric strong{font-weight:600}.meta{border-bottom:1px solid var(--line);padding:12px 0 24px}.grading{margin:30px 0 38px;border:0;border-radius:0;background:transparent}.grading-intro{max-width:720px}.eyebrow{margin:0 0 5px;color:#315b8c;font-size:.7rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}.grading h2{margin:0 0 8px;font-size:1.45rem;font-weight:600;letter-spacing:-.015em}.grading-intro>p:last-child{margin:0;color:var(--muted)}.grading-rules{display:grid;grid-template-columns:190px 1fr;gap:24px;margin:25px 0;padding-top:20px;border-top:1px solid var(--line)}.grading-rules h3{margin:0;font-size:.9rem;font-weight:600}.grading-rules ol{margin:0;padding-left:22px}.grading-rules li{margin:0 0 9px;padding-left:5px;color:var(--muted)}.grading-rules strong{color:var(--text);font-weight:600}.stage-table{overflow-x:auto;border-block:1px solid var(--line)}.stage-table table{width:100%;min-width:720px;border-collapse:collapse}.stage-table th,.stage-table td{padding:11px 12px;border-bottom:1px solid var(--line);font-size:.82rem;text-align:left}.stage-table thead th{background:#f7f8fa;color:var(--muted);font-size:.68rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase}.stage-table tbody tr:last-child>*{border-bottom:0}.stage-table tbody th{font-weight:600}.stage-decision{font-weight:600}.stage-decision.meets{color:var(--green)}.stage-decision.blocked{color:var(--red)}.grading-note{margin:13px 0 0;color:var(--muted);font-size:.8rem}.grading-note strong{color:var(--text);font-weight:600}.next-actions,.agent-summary{padding:19px 0;border-width:1px 0;border-radius:0}.toolbar{border-top:1px solid var(--line)}.filter,.status,.guide{border-radius:2px}.register,.findings{border-radius:0}.notice{border-radius:0}@media(max-width:760px){.shell{width:calc(100% - 28px)}.metric:first-child,.metric:last-child{padding:18px 0}.grading-rules{grid-template-columns:1fr;gap:9px}.hero h1{font-size:1.85rem}}
.summary{grid-template-columns:1.15fr .8fr 1fr}.metric.score-metric{padding-inline:30px}.report-disclosure{margin:0;border:0;border-bottom:1px solid var(--line);background:transparent}.report-disclosure:first-of-type{border-top:1px solid var(--line)}.report-disclosure summary{position:relative;padding:16px 34px 16px 0;color:var(--text);font-size:.95rem;font-weight:600;cursor:pointer;list-style:none}.report-disclosure summary::-webkit-details-marker{display:none}.report-disclosure summary::after{content:"+";position:absolute;right:4px;top:12px;color:var(--muted);font-size:1.25rem;font-weight:400}.report-disclosure[open] summary::after{content:"−"}.disclosure-body{padding:0 0 19px;max-width:900px}.grading.report-disclosure{margin:0}.grading .disclosure-body ol{margin:0;padding:0;list-style:none;counter-reset:rule}.grading .disclosure-body li{display:grid;grid-template-columns:24px 1fr;column-gap:10px;margin:0;padding:10px 0;border-top:1px solid #edf0f4;counter-increment:rule}.grading .disclosure-body li::before{content:counter(rule);grid-row:1 / span 2;color:var(--muted);font-size:.78rem}.grading .disclosure-body li strong{font-size:.88rem;font-weight:600}.grading .disclosure-body li span{grid-column:2;color:var(--muted);font-size:.84rem}.grading .disclosure-body p{margin:12px 0 0;color:var(--muted);font-size:.8rem}.agent-summary{padding:0}.agent-summary .disclosure-body{max-width:none}.agent-summary dl{padding:2px 0 4px}@media(max-width:760px){.summary{grid-template-columns:1fr}.metric.score-metric{padding-inline:0}.report-disclosure summary{padding-right:30px}.grading .disclosure-body li{grid-template-columns:20px 1fr}}
.register .points{width:64px;color:var(--text);font-weight:700;text-align:center}
</style></head><body><header class="hero"><div class="shell"><small>POLICY ATLAS / MICROSOFT ENTRA</small><h1>Conditional Access assessment</h1><p>Evidence-led posture analysis and rollout planning for Conditional Access.</p></div></header><main><div class="shell"><section class="summary"><article class="metric primary"><span>ASSESSED MATURITY</span><strong>Stage $($Snapshot.assessment.stage) &middot; $(ConvertTo-HtmlText $stage.name)</strong><span>Stage derived from the weighted score band</span></article><article class="metric score-metric"><span>WEIGHTED SCORE</span><strong>$score / 100</strong><span>$earnedPoints of $availablePoints applicable points earned</span></article><article class="metric"><span>POLICY INVENTORY</span><dl><div><dt>Total</dt><dd>$policyCount</dd></div><div><dt>Enabled</dt><dd>$enabledCount</dd></div><div><dt>Report-only</dt><dd>$reportOnlyCount</dd></div></dl></article></section><div class="meta"><span>Generated $(ConvertTo-HtmlText $Snapshot.generatedAt)</span><span>Schema $(ConvertTo-HtmlText $Snapshot.schemaVersion)</span><span>Collector $(ConvertTo-HtmlText $Snapshot.scriptVersion)</span></div>$gradingHtml$warningHtml$diffHtml</div><div class="toolbar"><div class="shell"><h2>Control evidence</h2><div class="filters"><button class="filter" data-filter="all" aria-pressed="true">All &middot; $($records.Count)</button><button class="filter" data-filter="missing" aria-pressed="false">Missing &middot; $($counts.missing)</button><button class="filter" data-filter="unknown" aria-pressed="false">Unknown &middot; $($counts.unknown)</button><button class="filter" data-filter="manual_confirmation" aria-pressed="false">Manual review &middot; $($counts.manual_confirmation)</button><button class="filter" data-filter="detected" aria-pressed="false">Detected &middot; $($counts.detected)</button></div></div></div><div class="shell evidence">$($groups -join '')<footer><div class="notice"><strong>Important</strong><p>This is a diagnostic assessment, not a certified audit. Review each finding and its implementation guide before changing a production policy.</p></div></footer></div></main><script>(function(){var b=document.querySelectorAll('[data-filter]');b.forEach(function(x){x.addEventListener('click',function(){var f=x.getAttribute('data-filter');b.forEach(function(y){y.setAttribute('aria-pressed',String(y===x))});document.querySelectorAll('.finding').forEach(function(r){r.hidden=f!=='all'&&r.getAttribute('data-status')!==f});document.querySelectorAll('.domain').forEach(function(g){g.hidden=!g.querySelector('.finding:not([hidden])')})})})})();</script></body></html>
"@
}

function Get-CaDiff([object]$Previous, [object]$Current) {
    if ($Previous.schemaVersion -ne $Current.schemaVersion) { throw 'Snapshots use different schema versions.' }
    if ($Previous.tenant.fingerprint -ne $Current.tenant.fingerprint) { throw 'Snapshots belong to different tenant fingerprints.' }
    $changes = @()
    foreach ($property in $Current.signals.PSObject.Properties) {
        $old = $Previous.signals.PSObject.Properties[$property.Name]
        if ($old -and $old.Value.status -ne $property.Value.status) { $changes += "$($property.Name): $($old.Value.status) -> $($property.Value.status)" }
    }
    return [pscustomobject]@{ summary = if ($changes.Count) { $changes -join '; ' } else { 'No signal-status changes detected.' }; changes = $changes }
}

$connected = $false
try {
    Show-ConsentBanner
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    Connect-MgGraph -TenantId $TenantId -Scopes $RequiredScopes -NoWelcome
    $connected = $true
    $context = Get-MgContext
    if ([string]$context.TenantId -ne $TenantId) { throw "Connected tenant '$($context.TenantId)' does not match requested tenant '$TenantId'." }

    # Preserve a successful empty collection as @(). Without -NoEnumerate,
    # PowerShell emits no pipeline object and the caller receives $null, which
    # is reserved here for collection failure.
    $policies = Invoke-CaGraphCall 'Conditional Access policies' $null {
        Write-Output -NoEnumerate @(Get-MgIdentityConditionalAccessPolicy -All)
    }
    $agentInventory = [pscustomobject][ordered]@{ requested=[bool]$IncludeAgentInventory; available=$false; identityCount=$null; enabledCount=$null; disabledCount=$null; blueprintCount=$null }
    if ($IncludeAgentInventory) {
        $agents = Invoke-CaGraphCall 'Agent identities' $null { Write-Output -NoEnumerate @((Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity').value) }
        $blueprints = Invoke-CaGraphCall 'Agent identity blueprints' $null { Write-Output -NoEnumerate @((Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/applications/microsoft.graph.agentIdentityBlueprint').value) }
        if ($null -ne $agents -and $null -ne $blueprints) {
            $agentInventory.available=$true
            $agentInventory.identityCount=@($agents).Count
            $agentInventory.enabledCount=@($agents|Where-Object accountEnabled -eq $true).Count
            $agentInventory.disabledCount=@($agents|Where-Object accountEnabled -eq $false).Count
            $agentInventory.blueprintCount=@($blueprints).Count
        }
    }
    $signals = Get-CaSignals $policies
    $operationalAnalysis=Get-CaOperationalAnalysis $policies $EmergencyAccessObjectId
    if($agentInventory.available -and $agentInventory.identityCount -eq 0){
        foreach($id in @('agent-approved-access','agent-risk-block','agent-obo-access')){
            $signals.$id=New-CaSignalResult not_applicable 'No Microsoft Entra agent identities were found in the optional agent inventory.'
        }
    }
    Apply-ManualOverrides $signals $ManualOverridesPath
    $score = Get-CaMaturityScore $signals
    $skus = Invoke-CaGraphCall 'Subscribed SKUs' $null { @(Get-MgSubscribedSku -All | Select-Object -ExpandProperty SkuPartNumber) }
    $legacySignIns = $null
    if ($IncludeSignInActivity) {
        $legacySignIns = Invoke-CaGraphCall 'Legacy authentication sign-ins' $null {
            $since = (Get-Date).ToUniversalTime().AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')
            @(Get-MgAuditLogSignIn -Filter "createdDateTime ge $since and clientAppUsed eq 'Other clients'" -Top 50).Count
        }
    }
    $hasP1 = if ($null -eq $skus) { $null } else { [bool](@($skus | Where-Object { $_ -match 'AAD_PREMIUM$|EMS$|SPE_' }).Count) }
    $hasP2 = if ($null -eq $skus) { $null } else { [bool](@($skus | Where-Object { $_ -match 'AAD_PREMIUM_P2|SPE_E5|IDENTITY_THREAT_PROTECTION' }).Count) }
    $enabledPolicies=@(Get-EnabledPolicies $policies)
    $broadCoverageCount=if($null-eq$policies){@($enabledPolicies|Where-Object{($_.Conditions.Users.IncludeUsers -contains 'All')-and($_.Conditions.Applications.IncludeApplications -contains 'All')}).Count}else{$null}
    $excludedPolicyCount=if($null-eq$policies){@($enabledPolicies|Where-Object{@($_.Conditions.Users.ExcludeUsers).Count+@($_.Conditions.Users.ExcludeGroups).Count-gt 0}).Count}else{$null}
    $sdk = Get-Module Microsoft.Graph.Authentication -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    $snapshot = [pscustomobject][ordered]@{
        schemaVersion       = $SchemaVersion
        scriptVersion       = $ScriptVersion
        modelVersion        = $ModelVersion
        policyLibraryVersion = $PolicyLibraryVersion
        generatedAt         = (Get-Date).ToUniversalTime().ToString('o')
        tenant              = [pscustomobject][ordered]@{ fingerprint = Get-CaSha256 ([string]$context.TenantId); cloud = [string]$context.Environment }
        collector           = [pscustomobject][ordered]@{ powerShellVersion = $PSVersionTable.PSVersion.ToString(); graphSdkVersion = if ($sdk) { $sdk.Version.ToString() } else { 'unknown' }; apiVersion = 'v1.0' }
        context             = [pscustomobject][ordered]@{
            policyCount           = if ($null -eq $policies) { $null } else { @($policies).Count }
            enabledPolicyCount    = if ($null -eq $policies) { $null } else { @(Get-EnabledPolicies $policies).Count }
            reportOnlyPolicyCount = if ($null -eq $policies) { $null } else { @(Get-ReportOnlyPolicies $policies).Count }
            broadCoveragePolicyCount = $broadCoverageCount
            policiesWithExclusions = $excludedPolicyCount
            licensing             = [pscustomobject][ordered]@{ hasEntraP1 = $hasP1; hasEntraP2 = $hasP2 }
            signInActivity        = [pscustomobject][ordered]@{ requested = [bool]$IncludeSignInActivity; legacyAuthSignInsLast7Days = $legacySignIns }
            agentInventory        = $agentInventory
            operationalAnalysis   = $operationalAnalysis
        }
        assessment          = $score
        signals             = $signals
        manualChecks        = @($signals.PSObject.Properties | Where-Object { $_.Value.status -eq 'manual_confirmation' } | ForEach-Object Name)
        warnings            = $Warnings.ToArray()
        errors              = $Errors.ToArray()
    }

    $contract = Test-CaSnapshotContract $snapshot
    if (-not $contract.Valid) { throw "Generated snapshot failed contract validation: $($contract.Errors -join '; ')" }
    $model = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot 'ca-maturity-model.json') | ConvertFrom-Json
    $library = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot 'ca-policy-library.json') | ConvertFrom-Json
    $diff = if ($CompareTo) { Get-CaDiff (Get-Content -Raw -Encoding UTF8 -LiteralPath $CompareTo | ConvertFrom-Json) $snapshot } else { $null }
    $slug = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHHmmssZ')
    $jsonPath = Join-Path $OutputPath "$slug.json"
    $htmlPath = Join-Path $OutputPath "$slug.html"
    $snapshot | ConvertTo-Json -Depth 20 | Out-File -Encoding utf8 -LiteralPath $jsonPath
    Get-CaHtmlReport $snapshot $model $library $diff | Out-File -Encoding utf8 -LiteralPath $htmlPath
    Write-Host "Confirmed stage: $($score.stage); provisional stage: $($score.provisionalStage); confidence: $($score.confidenceLabel)" -ForegroundColor Green
    Write-Host "Snapshot: $jsonPath"
    Write-Host "Report: $htmlPath"
}
finally {
    if ($connected) { Disconnect-MgGraph | Out-Null }
}
