<#
.SYNOPSIS
    A failsafe script to export AD data, designed to bypass persistent parameter errors.

.DESCRIPTION
    This script uses the most basic and robust methods to export AD data, avoiding the specific
    parameter bug that has been causing repeated failures. It fetches all properties and then
    selects the required ones, which is a more reliable process.
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

# --- Step 1: Export All Groups and Their Members (No Change, this part was working) ---
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

# --- Step 2: Export All Objects (FAILSAFE METHOD) ---
Write-Host "Exporting all user, group, and FSP objects from '$adDomain'..."
try {
    # This is the list of properties we will select AFTER getting the objects.
    $propertiesToSelect = @('Domain', 'sAMAccountName', 'DistinguishedName', 'Name', 'objectSid', 'objectClass')

    # Create an empty list to hold all the objects
    $allObjects = [System.Collections.Generic.List[pscustomobject]]::new()

    # FAILSAFE METHOD 1: Get ALL Users
    Write-Host "  - Getting users..."
    $users = Get-ADUser -Server $Server -Filter * -Properties * | Select-Object $propertiesToSelect -ExcludeProperty Domain
    foreach($user in $users) {
        $allObjects.Add(
            [pscustomobject]@{
                Domain = $adDomain
                sAMAccountName = $user.sAMAccountName
                DistinguishedName = $user.DistinguishedName
                Name = $user.Name
                objectSid = $user.objectSid
                objectClass = $user.objectClass
            }
        )
    }

    # FAILSAFE METHOD 2: Get ALL Groups
    Write-Host "  - Getting groups..."
    $groups = Get-ADGroup -Server $Server -Filter * -Properties * | Select-Object $propertiesToSelect -ExcludeProperty Domain
    foreach($group in $groups) {
        $allObjects.Add(
            [pscustomobject]@{
                Domain = $adDomain
                sAMAccountName = $group.sAMAccountName
                DistinguishedName = $group.DistinguishedName
                Name = $group.Name
                objectSid = $group.objectSid
                objectClass = $group.objectClass
            }
        )
    }

    # FAILSAFE METHOD 3: Get ALL Foreign Security Principals
    Write-Host "  - Getting Foreign Security Principals..."
    $fsps = Get-ADObject -Server $Server -Filter 'objectClass -eq "foreignSecurityPrincipal"' -Properties * | Select-Object $propertiesToSelect -ExcludeProperty Domain
    foreach($fsp in $fsps) {
        $allObjects.Add(
            [pscustomobject]@{
                Domain = $adDomain
                sAMAccountName = $fsp.sAMAccountName
                DistinguishedName = $fsp.DistinguishedName
                Name = $fsp.Name
                objectSid = $fsp.objectSid
                objectClass = $fsp.objectClass
            }
        )
    }
    
    # Export the consolidated list to the CSV file at the very end
    $allObjects | Export-Csv -Path $objectsCsvPath -NoTypeInformation
    Write-Host "Successfully exported all objects to: $objectsCsvPath"
}
catch {
    Write-Error "A failure occurred during object export from '$adDomain'. Error: $_"
    return
}

Write-Host "---"
Write-Host "Data export for domain '$adDomain' complete."
