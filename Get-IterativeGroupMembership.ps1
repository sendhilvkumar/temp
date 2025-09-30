<#
.SYNOPSIS
    Interactively discovers all nested members of a specific AD group, level by level,
    exporting each level of membership to a separate CSV file for parallel analysis.

.DESCRIPTION
    This script is designed for very large and complex Active Directory environments.
    It first asks for the server and the target group name. It then begins a breadth-first
    search of the group's membership.

    - Level 1: Finds the direct members of the target group.
    - Level 2: Finds the members of all groups found in Level 1.
    - And so on.

    For each level, it outputs two files:
    1. A CSV with just the USERS found at that level.
    2. A summary file listing the groups it will query for the next level.

    This allows an administrator to see results immediately and analyze user memberships
    while the script continues to drill down into deeper levels of nesting. It also handles
    circular references to prevent infinite loops.
#>

# --- Script Configuration ---
$ErrorActionPreference = "Stop" # Stop the script on any error

# --- User Interaction ---
try {
    $server = Read-Host -Prompt "Enter the FQDN of a domain controller in the target domain (e.g., dc1.corp.com)"
    Write-Host "Connecting to $server..."
    $domainName = (Get-ADDomainController -Server $server).Domain
    Write-Host "Successfully connected to domain: $domainName"
}
catch {
    Write-Error "Could not connect to server '$server'. Please check the name and your network connection. Error: $_"
    # Pause before exiting to allow user to read the error
    Read-Host "Press Enter to exit."
    exit
}

$startGroupName = Read-Host -Prompt "Enter the name (sAMAccountName) of the group you want to query"

# --- Setup Output Directory ---
# **FIXED**: Sanitize the group name to remove illegal characters for the folder path.
$safeGroupName = $startGroupName -replace '[\\/:*?"<>|]', '_'
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFolder = ".\Report_$($safeGroupName)_$timestamp"
New-Item -ItemType Directory -Path $outputFolder
Write-Host "Report files will be saved in: $outputFolder"

# --- Initialization ---
$level = 1
$processedGroupDNs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$groupsToQuery = [System.Collections.Generic.List[string]]::new()

# --- Find the Starting Group ---
try {
    # Use the original group name for the query
    $startGroup = Get-ADGroup -Server $server -Identity $startGroupName
    $groupsToQuery.Add($startGroup.DistinguishedName)
    $processedGroupDNs.Add($startGroup.DistinguishedName) | Out-Null
    Write-Host "Successfully found starting group: $($startGroup.DistinguishedName)"
}
catch {
    Write-Error "Failed to find group '$startGroupName' on server '$server'. Please check the group name. Error: $_"
    Read-Host "Press Enter to exit."
    exit
}

# --- Main Discovery Loop ---
while ($groupsToQuery.Count -gt 0) {
    Write-Host -ForegroundColor Yellow "`n--- Processing Level $level ---"
    Write-Host "Querying $($groupsToQuery.Count) groups found at the previous level."

    $nextLevelGroups = [System.Collections.Generic.List[string]]::new()
    $levelUsers = [System.Collections.Generic.List[object]]::new()
    
    # Save the list of groups being queried at this level for reference
    $groupsToQuery | Set-Content -Path (Join-Path $outputFolder "Level_$($level)_GroupsToQuery.txt")

    foreach ($groupDN in $groupsToQuery) {
        try {
            # Get direct members of the current group
            $members = Get-ADGroupMember -Identity $groupDN -Server $server

            foreach ($member in $members) {
                # Case 1: The member is a User
                if ($member.objectClass -eq 'user') {
                    $levelUsers.Add($member)
                }
                # Case 2: The member is another Group
                elseif ($member.objectClass -eq 'group') {
                    # Check for circular loops. If we haven't processed this group yet, add it to the list for the next level.
                    if (-not $processedGroupDNs.Contains($member.DistinguishedName)) {
                        $nextLevelGroups.Add($member.DistinguishedName)
                        $processedGroupDNs.Add($member.DistinguishedName) | Out-Null
                    }
                }
            }
        }
        catch {
            Write-Warning "Could not query group '$groupDN'. It may be in another domain or you may lack permissions. Error: $_"
        }
    }

    # --- Output Results for the Current Level ---
    if ($levelUsers.Count -gt 0) {
        # Remove duplicate users found at this level before exporting
        $uniqueUsers = $levelUsers | Sort-Object -Property DistinguishedName -Unique
        $csvPath = Join-Path $outputFolder "Level_$($level)_Users.csv"
        $uniqueUsers | Select-Object Name, SamAccountName, DistinguishedName | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host -ForegroundColor Green "SUCCESS: Found $($uniqueUsers.Count) unique users at this level. Report saved to:`n$csvPath"
    } else {
        Write-Host "No direct user members found at this level."
    }

    # --- Prepare for Next Iteration ---
    $groupsToQuery = $nextLevelGroups
    $level++
}

Write-Host -ForegroundColor Cyan "`n--- Discovery Complete ---"
Write-Host "Processed a total of $($level - 1) levels of nesting."
Write-Host "All report files are located in: $outputFolder"
Read-Host "Press Enter to exit."
