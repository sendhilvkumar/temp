<#
.SYNOPSIS
    Exports AD group and user data from a specified domain to CSV files. This version uses a more robust method to avoid previous errors.

.PARAMETER Server
    The fully qualified domain name (FQDN) of a domain controller in the target domain.

.PARAMETER FilePath
    The directory path where the CSV files will be saved.
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

# --- Step 1: Export All Groups and Their Members (No Change) ---
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

# --- Step 2: Export All Users, Groups, and FSPs (NEW RELIABLE METHOD) ---
Write-Host "Exporting all user, group, and FSP objects from '$adDomain'..."
try {
    # Define the properties we need for all object types
    $properties = @('sAMAccountName', 'DistinguishedName', 'Name', 'objectSid', 'objectClass')

    # Create the CSV file and add headers first
    $initialExport = @()
    $initialExport | Export-Csv -Path $objectsCsvPath -NoTypeInformation

    # Get ALL Users and append to the CSV
    Write-Host "  - Getting users..."
    Get-ADUser -Server $Server -Filter * -Properties $properties | 
        Select-Object @{N='Domain';E={$adDomain}}, $properties | 
        Export-Csv -Path $objectsCsvPath -Append -NoTypeInformation

    # Get ALL Groups and append to the CSV
    Write-Host "  - Getting groups..."
    Get-ADGroup -Server $Server -Filter * -Properties $properties | 
        Select-Object @{N='Domain';E={$adDomain}}, $properties | 
        Export-Csv -Path $objectsCsvPath -Append -NoTypeInformation

    # Get ALL Foreign Security Principals and append to the CSV
    Write-Host "  - Getting Foreign Security Principals..."
    Get-ADObject -Server $Server -Filter 'objectClass -eq "foreignSecurityPrincipal"' -Properties $properties | 
        Select-Object @{N='Domain';E={$adDomain}}, $properties | 
        Export-Csv -Path $objectsCsvPath -Append -NoTypeInformation
        
    Write-Host "Successfully exported all objects to: $objectsCsvPath"
}
catch {
    Write-Error "A failure occurred during object export from '$adDomain'. Error: $_"
    return
}

Write-Host "---"
Write-Host "Data export for domain '$adDomain' complete."
