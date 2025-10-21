<#
.SYNOPSIS
    Scans all domain controllers in a specified domain for Symantec/Veritas NetBackup installation.

.DESCRIPTION
    This script enumerates all domain controllers in the specified domain and checks each one
    for the presence of Symantec NetBackup or Veritas NetBackup backup agent. It checks both
    registry keys and services to determine if NetBackup is installed. The script continues
    execution even if it cannot connect to specific domain controllers.

.PARAMETER DomainName
    The fully qualified domain name (FQDN) of the domain to scan. If not specified, uses the current domain.

.EXAMPLE
    .\Check-NetBackupOnDCs.ps1
    Scans all domain controllers in the current domain.

.EXAMPLE
    .\Check-NetBackupOnDCs.ps1 -DomainName "contoso.com"
    Scans all domain controllers in the contoso.com domain.

.NOTES
    Author: PowerShell Script
    Version: 1.0
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
        Version = "N/A"
        InstallPath = "N/A"
        Services = @()
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
        # Check registry for NetBackup installation
        Write-Verbose "Checking registry on $ComputerName..."
        $registryCheck = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $netbackupKey = "HKLM:\SOFTWARE\Veritas\NetBackup\CurrentVersion"
            $installInfo = @{
                Installed = $false
                Version = "N/A"
                InstallPath = "N/A"
            }
            
            if (Test-Path $netbackupKey) {
                $installInfo.Installed = $true
                try {
                    $regData = Get-ItemProperty -Path $netbackupKey -ErrorAction SilentlyContinue
                    if ($regData.Version) {
                        $installInfo.Version = $regData.Version
                    }
                    if ($regData.InstallPath) {
                        $installInfo.InstallPath = $regData.InstallPath
                    } elseif ($regData.Install) {
                        $installInfo.InstallPath = $regData.Install
                    }
                } catch {
                    # Registry key exists but couldn't read properties
                }
            }
            
            return $installInfo
        } -ErrorAction Stop
        
        $result.NetBackupInstalled = $registryCheck.Installed
        $result.Version = $registryCheck.Version
        $result.InstallPath = $registryCheck.InstallPath
        
        # Check for NetBackup services
        Write-Verbose "Checking services on $ComputerName..."
        $services = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $netbackupServices = @('bpcd', 'nbrmms', 'nbsl')
            $foundServices = @()
            
            foreach ($svcName in $netbackupServices) {
                $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($service) {
                    $foundServices += [PSCustomObject]@{
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        Status = $service.Status.ToString()
                    }
                }
            }
            
            return $foundServices
        } -ErrorAction Stop
        
        $result.Services = $services
        
        # If services found but registry check failed, still mark as installed
        if ($services.Count -gt 0 -and -not $result.NetBackupInstalled) {
            $result.NetBackupInstalled = $true
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
        Write-Host "  [FOUND] NetBackup is installed" -ForegroundColor Green
        if ($scanResult.Version -ne "N/A") {
            Write-Host "  Version: $($scanResult.Version)" -ForegroundColor Gray
        }
        if ($scanResult.InstallPath -ne "N/A") {
            Write-Host "  Path: $($scanResult.InstallPath)" -ForegroundColor Gray
        }
        if ($scanResult.Services.Count -gt 0) {
            Write-Host "  Services: $($scanResult.Services.Name -join ', ')" -ForegroundColor Gray
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

Write-Host "Domain: $DomainName" -ForegroundColor White
Write-Host "Total Domain Controllers: $($domainControllers.Count)" -ForegroundColor White
Write-Host "  Online: $onlineCount" -ForegroundColor Green
Write-Host "  Offline/Unreachable: $offlineCount" -ForegroundColor Red
Write-Host ""
Write-Host "NetBackup Installation Status:" -ForegroundColor White
Write-Host "  Installed: $installedCount" -ForegroundColor Green
Write-Host "  Not Installed: $notInstalledCount" -ForegroundColor Yellow
Write-Host ""

# Display detailed results table
Write-Host "Detailed Results:" -ForegroundColor Cyan
Write-Host ""

$results | Format-Table -AutoSize -Property @(
    @{Label="Domain Controller"; Expression={$_.ComputerName}},
    @{Label="Online"; Expression={if($_.IsOnline){"Yes"}else{"No"}}},
    @{Label="NetBackup"; Expression={if($_.NetBackupInstalled){"Installed"}else{"Not Installed"}}},
    @{Label="Version"; Expression={$_.Version}},
    @{Label="Services"; Expression={if($_.Services.Count -gt 0){$_.Services.Name -join ", "}else{"None"}}},
    @{Label="Error"; Expression={$_.ErrorMessage}}
)

# Export results to CSV
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = ".\NetBackup_DC_Scan_$timestamp.csv"

try {
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $csvPath" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export results to CSV: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Scan completed!" -ForegroundColor Cyan

