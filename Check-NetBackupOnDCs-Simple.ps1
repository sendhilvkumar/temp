<#
.SYNOPSIS
    Scans all domain controllers in a specified domain for Symantec/Veritas NetBackup installation.

.DESCRIPTION
    This script enumerates all domain controllers in the specified domain and checks each one
    for the presence of Symantec NetBackup or Veritas NetBackup backup agent by querying the
    installed applications (same as Add/Remove Programs). The script continues execution even
    if it cannot connect to specific domain controllers.

.PARAMETER DomainName
    The fully qualified domain name (FQDN) of the domain to scan. If not specified, uses the current domain.

.EXAMPLE
    .\Check-NetBackupOnDCs-Simple.ps1
    Scans all domain controllers in the current domain.

.EXAMPLE
    .\Check-NetBackupOnDCs-Simple.ps1 -DomainName "contoso.com"
    Scans all domain controllers in the contoso.com domain.

.NOTES
    Author: PowerShell Script
    Version: 4.0 (Simplified)
    Requires: Active Directory PowerShell module
    Requires: Appropriate permissions to query remote systems
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName
)

# Function to check NetBackup installation on a remote computer
function Test-NetBackupInstallation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $ComputerName
        IsOnline = $false
        NetBackupInstalled = $false
        Vendor = "N/A"
        ProductName = "N/A"
        Version = "N/A"
        InstallDate = "N/A"
        ErrorMessage = ""
    }
    
    # Test if computer is reachable
    Write-Verbose "Testing connectivity to $ComputerName..."
    if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        $result.ErrorMessage = "Computer is not reachable (ping failed)"
        Write-Warning "$ComputerName is not reachable"
        return $result
    }
    
    $result.IsOnline = $true
    
    try {
        # Query installed applications from registry (same as Add/Remove Programs)
        Write-Verbose "Checking installed applications on $ComputerName..."
        $installedApps = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $apps = @()
            
            # Check both 64-bit and 32-bit registry locations
            $registryPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            
            foreach ($path in $registryPaths) {
                try {
                    $programs = Get-ItemProperty $path -ErrorAction SilentlyContinue | 
                        Where-Object { 
                            $_.DisplayName -like "*NetBackup*" -and 
                            $_.DisplayName -notlike "*Self Service*" -and
                            $_.DisplayName -notlike "*OpsCenter*"
                        }
                    
                    foreach ($program in $programs) {
                        # Determine vendor from display name
                        $vendor = "Unknown"
                        if ($program.DisplayName -match "Symantec") {
                            $vendor = "Symantec"
                        } elseif ($program.DisplayName -match "Veritas") {
                            $vendor = "Veritas"
                        }
                        
                        # If vendor not in name, check publisher
                        if ($vendor -eq "Unknown" -and $program.Publisher) {
                            if ($program.Publisher -match "Symantec") {
                                $vendor = "Symantec"
                            } elseif ($program.Publisher -match "Veritas") {
                                $vendor = "Veritas"
                            }
                        }
                        
                        $apps += [PSCustomObject]@{
                            DisplayName = $program.DisplayName
                            Vendor = $vendor
                            Version = if ($program.DisplayVersion) { $program.DisplayVersion } else { "N/A" }
                            Publisher = if ($program.Publisher) { $program.Publisher } else { "N/A" }
                            InstallDate = if ($program.InstallDate) { $program.InstallDate } else { "N/A" }
                            InstallLocation = if ($program.InstallLocation) { $program.InstallLocation } else { "N/A" }
                        }
                    }
                } catch {
                    # Continue to next path
                }
            }
            
            # Return unique applications (in case found in both 32-bit and 64-bit registry)
            return $apps | Sort-Object -Property DisplayName -Unique
        } -ErrorAction Stop
        
        if ($installedApps -and $installedApps.Count -gt 0) {
            $result.NetBackupInstalled = $true
            
            # Use the first NetBackup application found (usually the main client)
            $mainApp = $installedApps | Where-Object { $_.DisplayName -match "Client" } | Select-Object -First 1
            if (-not $mainApp) {
                $mainApp = $installedApps | Select-Object -First 1
            }
            
            $result.Vendor = $mainApp.Vendor
            $result.ProductName = $mainApp.DisplayName
            $result.Version = $mainApp.Version
            $result.InstallDate = $mainApp.InstallDate
        }
        
    } catch {
        $result.ErrorMessage = $_.Exception.Message
        Write-Warning "Error checking $ComputerName : $($_.Exception.Message)"
    }
    
    return $result
}

# Main script execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NetBackup Domain Controller Scanner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Import Active Directory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "[OK] Active Directory module loaded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to load Active Directory module. Please ensure RSAT-AD-PowerShell is installed."
    Write-Error $_.Exception.Message
    exit 1
}

# Get domain controllers
try {
    if ($DomainName) {
        Write-Host "Retrieving domain controllers from domain: $DomainName" -ForegroundColor Yellow
        $domainControllers = Get-ADDomainController -Filter * -Server $DomainName | Select-Object -ExpandProperty HostName
    } else {
        Write-Host "Retrieving domain controllers from current domain..." -ForegroundColor Yellow
        $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
        $DomainName = (Get-ADDomain).DNSRoot
    }
    
    Write-Host "[OK] Found $($domainControllers.Count) domain controller(s) in domain: $DomainName" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Error "Failed to retrieve domain controllers: $($_.Exception.Message)"
    exit 1
}

# Scan each domain controller
$results = @()
$counter = 0

foreach ($dc in $domainControllers) {
    $counter++
    Write-Host "[$counter/$($domainControllers.Count)] Scanning: $dc" -ForegroundColor Cyan
    
    $scanResult = Test-NetBackupInstallation -ComputerName $dc
    $results += $scanResult
    
    if ($scanResult.NetBackupInstalled) {
        Write-Host "  [FOUND] $($scanResult.ProductName)" -ForegroundColor Green
        Write-Host "  Vendor: $($scanResult.Vendor)" -ForegroundColor Magenta
        if ($scanResult.Version -ne "N/A") {
            Write-Host "  Version: $($scanResult.Version)" -ForegroundColor Gray
        }
        if ($scanResult.InstallDate -ne "N/A") {
            Write-Host "  Install Date: $($scanResult.InstallDate)" -ForegroundColor Gray
        }
    } elseif ($scanResult.IsOnline) {
        Write-Host "  [NOT FOUND] NetBackup is not installed" -ForegroundColor Yellow
    } else {
        Write-Host "  [ERROR] $($scanResult.ErrorMessage)" -ForegroundColor Red
    }
    
    Write-Host ""
}

# Display summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$onlineCount = ($results | Where-Object { $_.IsOnline }).Count
$offlineCount = ($results | Where-Object { -not $_.IsOnline }).Count
$installedCount = ($results | Where-Object { $_.NetBackupInstalled }).Count
$notInstalledCount = ($results | Where-Object { $_.IsOnline -and -not $_.NetBackupInstalled }).Count

$symantecCount = ($results | Where-Object { $_.Vendor -eq "Symantec" }).Count
$veritasCount = ($results | Where-Object { $_.Vendor -eq "Veritas" }).Count

Write-Host "Domain: $DomainName" -ForegroundColor White
Write-Host "Total Domain Controllers: $($domainControllers.Count)" -ForegroundColor White
Write-Host "  Online: $onlineCount" -ForegroundColor Green
Write-Host "  Offline/Unreachable: $offlineCount" -ForegroundColor Red
Write-Host ""
Write-Host "NetBackup Installation Status:" -ForegroundColor White
Write-Host "  Installed: $installedCount" -ForegroundColor Green
Write-Host "    - Symantec NetBackup: $symantecCount" -ForegroundColor Cyan
Write-Host "    - Veritas NetBackup: $veritasCount" -ForegroundColor Cyan
Write-Host "  Not Installed: $notInstalledCount" -ForegroundColor Yellow
Write-Host ""

# Display detailed results table
Write-Host "Detailed Results:" -ForegroundColor Cyan
Write-Host ""

$results | Format-Table -AutoSize -Wrap -Property @(
    @{Label="Domain Controller"; Expression={$_.ComputerName}; Width=30},
    @{Label="Status"; Expression={
        if(-not $_.IsOnline){"Offline"}
        elseif($_.NetBackupInstalled){"Installed"}
        else{"Not Installed"}
    }; Width=13},
    @{Label="Vendor"; Expression={$_.Vendor}; Width=10},
    @{Label="Product Name"; Expression={$_.ProductName}; Width=35},
    @{Label="Version"; Expression={$_.Version}; Width=10}
)

# Export results to CSV
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = ".\NetBackup_DC_Scan_$timestamp.csv"

try {
    $exportData = $results | Select-Object ComputerName, IsOnline, NetBackupInstalled, Vendor, ProductName, Version, InstallDate, ErrorMessage
    
    $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $csvPath" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export results to CSV: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Scan completed!" -ForegroundColor Cyan

