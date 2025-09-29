<#
.SYNOPSIS
    The simplest possible AD export script, designed to avoid all previous errors by removing the problematic parameter.
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

# --- Step 1: Export All Groups and Their Members (This part has been working) ---
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

# --- Step 2: Export All Objects (SIMPLEST METHOD - NO -Properties PARAMETER) ---
Write-Host "Exporting all user, group, and FSP objects from '$adDomain'..."
try {
    $allObjects = [System.Collections.Generic.List[pscustomobject]]::new()

    # Get Users (default properties only)
    Write-Host "  - Getting users..."
    Get-ADUser -Server $Server -Filter * | ForEach-Object {
        $allObjects.Add(
            [pscustomobject]@{
                Domain = $adDomain
                DistinguishedName = $_.DistinguishedName
                Name = $_.Name
                objectClass = $_.ObjectClass
                sAMAccountName = $_.sAMAccountName
                ObjectGUID = $_.ObjectGUID # Using GUID as a fallback identifier
            }
        )
    }

    # Get Groups (default properties only)
    Write-Host "  - Getting groups..."
    Get-ADGroup -Server $Server -Filter * | ForEach-Object {
        $allObjects.Add(
            [pscustomobject]@{
                Domain = $adDomain
                DistinguishedName = $_.DistinguishedName
                Name = $_.Name
                objectClass = $_.ObjectClass
                sAMAccountName = $_.sAMAccountName
                ObjectGUID = $_.ObjectGUID
            }
        )
    }

    # Get FSPs (default properties only)
    Write-Host "  - Getting Foreign Security Principals..."
    Get-ADObject -Server $Server -Filter 'objectClass -eq "foreignSecurityPrincipal"' | ForEach-Object {
         $allObjects.Add(
            [pscustomobject]@{
                Domain = $adDomain
                DistinguishedName = $_.DistinguishedName
                Name = $_.Name
                objectClass = $_.ObjectClass
                sAMAccountName = $_.sAMAccountName
                ObjectGUID = $_.ObjectGUID
            }
        )
    }
    
    $allObjects | Export-Csv -Path $objectsCsvPath -NoTypeInformation
    Write-Host "Successfully exported all objects to: $objectsCsvPath"
}
catch {
    Write-Error "A failure occurred during object export from '$adDomain'. Error: $_"
    return
}

Write-Host "---"
Write-Host "Data export for domain '$adDomain' complete."
