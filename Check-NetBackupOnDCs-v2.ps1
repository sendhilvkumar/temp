<#
.SYNOPSIS
    Scans all domain controllers in a specified domain for Symantec/Veritas NetBackup installation.

.DESCRIPTION
    This script enumerates all domain controllers in the specified domain and checks each one
    for the presence of Symantec NetBackup or Veritas NetBackup backup agent. It uses multiple
    detection methods including registry keys, services, and installed programs to ensure
    accurate detection. The script continues execution even if it cannot connect to specific
    domain controllers.

.PARAMETER DomainName
    The fully qualified domain name (FQDN) of the domain to scan. If not specified, uses the current domain.

.EXAMPLE
    .\Check-NetBackupOnDCs-v2.ps1
    Scans all domain controllers in the current domain.

.EXAMPLE
    .\Check-NetBackupOnDCs-v2.ps1 -DomainName "contoso.com"
    Scans all domain controllers in the contoso.com domain.

.NOTES
    Author: PowerShell Script
    Version: 2.0
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
        DetectionMethod = "None"
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
        # Check for NetBackup using multiple methods
        Write-Verbose "Checking for NetBackup on $ComputerName..."
        $detectionResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $installInfo = @{
                Installed = $false
                Version = "N/A"
                InstallPath = "N/A"
                DetectionMethod = "None"
                Services = @()
            }
            
            # Method 1: Check registry - standard path
            $registryPaths = @(
                "HKLM:\SOFTWARE\Veritas\NetBackup\CurrentVersion",
                "HKLM:\SOFTWARE\Veritas\NetBackup",
                "HKLM:\SOFTWARE\Wow6432Node\Veritas\NetBackup\CurrentVersion",
                "HKLM:\SOFTWARE\Wow6432Node\Veritas\NetBackup"
            )
            
            foreach ($regPath in $registryPaths) {
                if (Test-Path $regPath) {
                    $installInfo.Installed = $true
                    $installInfo.DetectionMethod = "Registry: $regPath"
                    
                    try {
                        $regData = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                        
                        # Try different version property names
                        if ($regData.Version) {
                            $installInfo.Version = $regData.Version
                        } elseif ($regData.PSObject.Properties['Version']) {
                            $installInfo.Version = $regData.Version
                        }
                        
                        # Try different install path property names
                        if ($regData.InstallPath) {
                            $installInfo.InstallPath = $regData.InstallPath
                        } elseif ($regData.Install) {
                            $installInfo.InstallPath = $regData.Install
                        } elseif ($regData.Path) {
                            $installInfo.InstallPath = $regData.Path
                        }
                    } catch {
                        # Registry key exists but couldn't read properties
                    }
                    break
                }
            }
            
            # Method 2: Check for NetBackup services (even if registry not found)
            $netbackupServiceNames = @(
                'bpcd',           # NetBackup Client Service
                'bpinetd',        # NetBackup Legacy Client Service  
                'nbrmms',         # NetBackup Remote Manager and Monitor Service
                'nbsl',           # NetBackup Service Layer
                'NetBackup*'      # Any service starting with NetBackup
            )
            
            $foundServices = @()
            foreach ($svcPattern in $netbackupServiceNames) {
                try {
                    $services = Get-Service -Name $svcPattern -ErrorAction SilentlyContinue
                    if ($services) {
                        foreach ($service in $services) {
                            $foundServices += [PSCustomObject]@{
                                Name = $service.Name
                                DisplayName = $service.DisplayName
                                Status = $service.Status.ToString()
                            }
                        }
                    }
                } catch {
                    # Service not found, continue
                }
            }
            
            # Remove duplicates
            $foundServices = $foundServices | Sort-Object -Property Name -Unique
            $installInfo.Services = $foundServices
            
            if ($foundServices.Count -gt 0 -and -not $installInfo.Installed) {
                $installInfo.Installed = $true
                $installInfo.DetectionMethod = "Services: $($foundServices.Name -join ', ')"
            }
            
            # Method 3: Check installed programs via registry Uninstall keys
            if (-not $installInfo.Installed) {
                $uninstallPaths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )
                
                foreach ($uninstallPath in $uninstallPaths) {
                    try {
                        $programs = Get-ItemProperty $uninstallPath -ErrorAction SilentlyContinue | 
                            Where-Object { $_.DisplayName -like "*NetBackup*" -or $_.DisplayName -like "*Veritas*" }
                        
                        foreach ($program in $programs) {
                            if ($program.DisplayName -match "NetBackup") {
                                $installInfo.Installed = $true
                                $installInfo.DetectionMethod = "Installed Programs"
                                
                                if ($program.DisplayVersion) {
                                    $installInfo.Version = $program.DisplayVersion
                                }
                                if ($program.InstallLocation) {
                                    $installInfo.InstallPath = $program.InstallLocation
                                }
                                break
                            }
                        }
                        
                        if ($installInfo.Installed) { break }
                    } catch {
                        # Continue to next method
                    }
                }
            }
            
            # Method 4: Check for common NetBackup installation directories
            if (-not $installInfo.Installed) {
                $commonPaths = @(
                    "C:\Program Files\Veritas\NetBackup",
                    "C:\Program Files (x86)\Veritas\NetBackup",
                    "C:\Veritas\NetBackup"
                )
                
                foreach ($path in $commonPaths) {
                    if (Test-Path $path) {
                        $installInfo.Installed = $true
                        $installInfo.InstallPath = $path
                        $installInfo.DetectionMethod = "File System: $path"
                        
                        # Try to get version from bpcd.exe or version.txt
                        $versionFile = Join-Path $path "version.txt"
                        if (Test-Path $versionFile) {
                            try {
                                $versionContent = Get-Content $versionFile -First 1 -ErrorAction SilentlyContinue
                                if ($versionContent) {
                                    $installInfo.Version = $versionContent.Trim()
                                }
                            } catch {}
                        }
                        break
                    }
                }
            }
            
            return $installInfo
        } -ErrorAction Stop
        
        $result.NetBackupInstalled = $detectionResult.Installed
        $result.Version = $detectionResult.Version
        $result.InstallPath = $detectionResult.InstallPath
        $result.DetectionMethod = $detectionResult.DetectionMethod
        $result.Services = $detectionResult.Services
        
    } catch {
        $result.ErrorMessage = $_.Exception.Message
        Write-Warning "Error checking $ComputerName : $($_.Exception.Message)"
    }
    
    return $result
}

# Main script execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NetBackup Domain Controller Scanner v2" -ForegroundColor Cyan
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
        Write-Host "  Detection: $($scanResult.DetectionMethod)" -ForegroundColor Gray
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

$results | Format-Table -AutoSize -Wrap -Property @(
    @{Label="Domain Controller"; Expression={$_.ComputerName}; Width=30},
    @{Label="Online"; Expression={if($_.IsOnline){"Yes"}else{"No"}}; Width=6},
    @{Label="NetBackup"; Expression={if($_.NetBackupInstalled){"Installed"}else{"Not Installed"}}; Width=13},
    @{Label="Version"; Expression={$_.Version}; Width=10},
    @{Label="Detection Method"; Expression={$_.DetectionMethod}; Width=25},
    @{Label="Services"; Expression={if($_.Services.Count -gt 0){($_.Services.Name | Select-Object -First 3) -join ", "}else{"None"}}; Width=20}
)

# Export results to CSV
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = ".\NetBackup_DC_Scan_$timestamp.csv"

try {
    $exportData = $results | Select-Object ComputerName, IsOnline, NetBackupInstalled, Version, InstallPath, DetectionMethod, 
        @{Name="Services"; Expression={$_.Services.Name -join "; "}}, ErrorMessage
    
    $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $csvPath" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export results to CSV: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Scan completed!" -ForegroundColor Cyan

