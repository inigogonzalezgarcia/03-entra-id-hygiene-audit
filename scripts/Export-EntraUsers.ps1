<#
.SYNOPSIS
    Exports Entra ID users, last sign-in and MFA registration to JSON for identity_audit.py.

.DESCRIPTION
    Reads users (including signInActivity) and the authentication methods
    registration report from Microsoft Graph, joins them by user id and writes
    one JSON record per user.

    Requires the Microsoft Graph PowerShell SDK:
        Install-Module Microsoft.Graph.Users, Microsoft.Graph.Reports -Scope CurrentUser

    Permissions used (delegated, read-only): User.Read.All, AuditLog.Read.All
    Sign-in activity and the registration report need Entra ID P1 or P2, and your
    account needs a role that can read them (for example Reports Reader or
    Global Reader).

.PARAMETER OutputPath
    Where to write the JSON file. Default: .\entra_users.json

.PARAMETER TenantId
    Optional tenant ID or domain, if your account has access to more than one tenant.

.EXAMPLE
    .\Export-EntraUsers.ps1 -OutputPath .\entra_users.json
    python identity_audit.py .\entra_users.json
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\entra_users.json",
    [string]$TenantId
)

$ErrorActionPreference = "Stop"

foreach ($module in "Microsoft.Graph.Users", "Microsoft.Graph.Reports") {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "$module is not installed. Run: Install-Module $module -Scope CurrentUser"
    }
    Import-Module $module
}

$connectParams = @{ Scopes = "User.Read.All", "AuditLog.Read.All"; NoWelcome = $true }
if ($TenantId) { $connectParams.TenantId = $TenantId }
Connect-MgGraph @connectParams

Write-Host "Reading users..."
$users = Get-MgUser -All -Property "id,displayName,userPrincipalName,userType,accountEnabled,department,createdDateTime,signInActivity"

Write-Host "Reading MFA registration details..."
$registration = @{}
Get-MgReportAuthenticationMethodUserRegistrationDetail -All | ForEach-Object {
    $registration[$_.Id] = $_
}

function Format-Date($value) {
    if ($null -eq $value) { return $null }
    return ([datetime]$value).ToUniversalTime().ToString("o")
}

$export = foreach ($u in $users) {
    $reg = $registration[$u.Id]
    [ordered]@{
        id                 = $u.Id
        displayName        = $u.DisplayName
        userPrincipalName  = $u.UserPrincipalName
        userType           = $u.UserType
        accountEnabled     = $u.AccountEnabled
        department         = $u.Department
        createdDateTime    = Format-Date $u.CreatedDateTime
        lastSignInDateTime = Format-Date $u.SignInActivity.LastSignInDateTime
        isMfaRegistered    = if ($reg) { [bool]$reg.IsMfaRegistered } else { $null }
        isAdmin            = if ($reg) { [bool]$reg.IsAdmin } else { $false }
    }
}

# Always write a JSON array, even for a single user.
ConvertTo-Json -InputObject @($export) -Depth 3 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Exported $(@($export).Count) users to $OutputPath"

Disconnect-MgGraph | Out-Null
