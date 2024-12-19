#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Get MFA status and authentication methods for Office 365 users using Microsoft Graph
.DESCRIPTION
    Retrieves user accounts and their MFA configuration, authentication methods, and password information
.NOTES
    Requires Microsoft Graph PowerShell SDK
#>

$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.SignIns"
)

foreach ($module in $requiredModules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Install-Module -Name $module -Force
    }
}

Connect-MgGraph -Scopes @(
    "User.Read.All",
    "UserAuthenticationMethod.Read.All"
)

Function Get-UserMFAStatus {
    param (
        [string]$AccountStatus = "All"  # Can be "All", "Enabled", or "Disabled"
    )

    $filter = switch ($AccountStatus) {
        "Enabled" { "accountEnabled eq true" }
        "Disabled" { "accountEnabled eq false" }
        default { $null }
    }

    $users = Get-MgUser -Filter $filter -All -Property id, displayName, userPrincipalName, 
        accountEnabled, passwordPolicies, lastPasswordChangeDateTime, 
        assignedLicenses, createdDateTime

    $results = @()

    foreach ($user in $users) {
        Write-Host "Processing user: $($user.UserPrincipalName)"

        $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
        
        $defaultMethod = "Not Enabled"
        $phoneNumber = ""

        foreach ($method in $authMethods) {
            $methodType = $method.AdditionalProperties["@odata.type"]
            switch ($methodType) {
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                    $defaultMethod = "Authenticator App"
                }
                "#microsoft.graph.phoneAuthenticationMethod" {
                    $phoneDetails = Get-MgUserAuthenticationPhoneMethod -UserId $user.Id -PhoneAuthenticationMethodId $method.Id
                    $phoneNumber = $phoneDetails.PhoneNumber
                    if ($defaultMethod -eq "Not Enabled") {
                        $defaultMethod = if ($phoneDetails.PhoneType -eq "mobile") { "SMS Text Message" } else { "Call to Phone" }
                    }
                }
                "#microsoft.graph.softwareOathAuthenticationMethod" {
                    if ($defaultMethod -eq "Not Enabled") {
                        $defaultMethod = "TOTP"
                    }
                }
            }
        }

        $pwdLastSet = $user.LastPasswordChangeDateTime
        $pwdSinceLastSet = if ($pwdLastSet) {
            ((Get-Date) - $pwdLastSet).Days
        } else {
            "Never"
        }

        $results += [PSCustomObject]@{
            'Display Name' = $user.DisplayName
            'User Principal Name' = $user.UserPrincipalName
            'Account Status' = if ($user.AccountEnabled) { "Enabled" } else { "Disabled" }
            'Strong Auth Method' = $defaultMethod
            'MFA Phone Number' = $phoneNumber
            'Last Password Change' = if ($pwdLastSet) { $pwdLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            'Days Since Password Change' = $pwdSinceLastSet
            'License Status' = ($user.AssignedLicenses.Count -gt 0)
            'Password Never Expires' = ($user.PasswordPolicies -contains "DisablePasswordExpiration")
            'Created Date' = $user.CreatedDateTime.ToString("yyyy-MM-dd HH:mm:ss")
        }
    }

    $results | Export-Csv -Path "MFA-Status-Report.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "Report exported to MFA-Status-Report.csv"
}

Get-UserMFAStatus -AccountStatus "All"

Disconnect-MgGraph
