<#
.SYNOPSIS
    Exports AD group and user data from a specified domain to CSV files, ready for multi-domain analysis.

.DESCRIPTION
    This script connects to a specific domain controller to export all security groups, users, and Foreign Security Principals (FSPs).
    It adds a 'Domain' column to each export, which is crucial for resolving cross-domain memberships later.
    Run this script for each domain in your forest.

.PARAMETER Server
    The fully qualified domain name (FQDN) of a domain controller in the target domain (e.g., 'dc1.corp.example.com').

.PARAMETER FilePath
    The directory path where the CSV files will be saved. A subdirectory for the domain will be created.

.EXAMPLE
    # Run for the CORP domain
    .\Export-ADForestData.ps1 -Server 'dc1.corp.example.com' -FilePath "C:\temp\AD_Forest_Export"
#>
param (
    [Parameter(Mandatory = $true)]
    [string]$Server,

    [Parameter(Mandatory = $true)]
    [string]$FilePath
)

# --- Setup and Validation ---
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory module not found."
    return
}

try {
    $adDomain = (Get-ADDomainController -Server $Server).Domain
    Write-Host "Successfully connected. Target domain is: $adDomain"
}
catch {
    Write-Error "Could not connect to server '$Server'. Please check the FQDN and network connectivity. Error: $_"
    return
}

$domainFilePath = Join-Path -Path $FilePath -ChildPath $adDomain
if (-not (Test-Path -Path $domainFilePath)) {
    New-Item -ItemType Directory -Path $domainFilePath | Out-Null
}

$groupsCsvPath = Join-Path -Path $domainFilePath -ChildPath "AllGroups.csv"
$objectsCsvPath = Join-Path -Path $domainFilePath -ChildPath "AllObjects.csv"

# --- Step 1: Export All Groups and Their Members ---
Write-Host "Exporting security groups from '$adDomain'..."
try {
    Get-ADGroup -Server $Server -Filter 'GroupCategory -eq "Security"' -Properties member | ForEach-Object {
        $group = $_
        if ($null -ne $group.member) {
            foreach ($memberDN in $group.member) {
                [PSCustomObject]@{
                    Domain    = $adDomain
                    GroupName = $group.Name
                    GroupDN   = $group.DistinguishedName
                    MemberDN  = $memberDN
                }
            }
        } else {
            [PSCustomObject]@{
                Domain    = $adDomain
                GroupName = $group.Name
                GroupDN   = $group.DistinguishedName
                MemberDN  = $null
            }
        }
    } | Export-Csv -Path $groupsCsvPath -NoTypeInformation
    Write-Host "Successfully exported groups to: $groupsCsvPath"
}
catch {
    Write-Error "Failed to export groups from '$adDomain'. Error: $_"
    return
}

# --- Step 2: Export All Users, Groups, and FSPs with their SIDs ---
Write-Host "Exporting all users, groups, and FSPs from '$adDomain'..."
try {
    # FINAL FIX: This version simplifies the command to be completely unambiguous.
    # The filter is a simple string, and the properties are passed directly to the command.
    
    $ldapFilter = '(|(objectClass=user)(objectClass=group)(objectClass=foreignSecurityPrincipal))'
    
    Get-ADObject -Server $Server -LDAPFilter $ldapFilter -Properties sAMAccountName, DistinguishedName, Name, objectSid, objectClass | 
        Select-Object @{N='Domain';E={$adDomain}}, sAMAccountName, DistinguishedName, Name, objectSid, objectClass |
        Export-Csv -Path $objectsCsvPath -NoTypeInformation
        
    Write-Host "Successfully exported objects to: $objectsCsvPath"
}
catch {
    Write-Error "Failed to export objects from '$adDomain'. Error: $_"
    return
}

Write-Host "---"
Write-Host "Data export for domain '$adDomain' complete."
