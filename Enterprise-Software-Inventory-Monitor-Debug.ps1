#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Enterprise Software & Patch Inventory Monitor - Diagnostic Version
    
.DESCRIPTION
    Diagnostic version with enhanced error reporting to identify data collection issues.
    
.AUTHOR
    Enterprise IT Team
    
.VERSION
    2.2 (Diagnostic)
#>

# Script Configuration
$ScriptVersion = "2.2"
$ScriptName = "Enterprise Software & Patch Inventory Monitor (Diagnostic)"
$OutputPath = "$PSScriptRoot\InventoryReports"
$LogPath = "$PSScriptRoot\Logs"

# Critical agents to highlight
$CriticalAgents = @(
    "Netbackup", "NetBackup", "Veritas",
    "Qualys", "QualysAgent",
    "Flexera", "ManageSoft",
    "Defender", "Windows Defender", "Microsoft Defender",
    "AATP", "Azure Advanced Threat Protection", "Defender for Identity",
    "Tripwire", "TripwireAgent"
)

# Initialize logging
function Initialize-Logging {
    if (!(Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    $global:LogFile = "$LogPath\InventoryMonitor_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Write-Log "=== $ScriptName v$ScriptVersion Started ===" -Level "INFO"
}

# Enhanced logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp [$Level] $Message"
    
    # Write to console with color coding
    switch ($Level) {
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
        "WARN"  { Write-Host $LogEntry -ForegroundColor Yellow }
        "INFO"  { Write-Host $LogEntry -ForegroundColor Green }
        "DEBUG" { Write-Host $LogEntry -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Magenta }
    }
    
    # Write to log file
    Add-Content -Path $global:LogFile -Value $LogEntry
}

# Discover Domain Controllers
function Get-DomainControllers {
    Write-Log "Starting domain controller discovery..." -Level "INFO"
    
    try {
        # Get current domain
        $Domain = Get-ADDomain -Current LocalComputer
        Write-Log "Current domain: $($Domain.DNSRoot)" -Level "INFO"
        
        # Get all domain controllers
        $DomainControllers = Get-ADDomainController -Filter * -Server $Domain.DNSRoot | Select-Object @{
            Name = "ServerName"
            Expression = { $_.Name }
        }, @{
            Name = "FQDN"
            Expression = { $_.HostName }
        }, @{
            Name = "IPAddress"
            Expression = { $_.IPv4Address }
        }, @{
            Name = "Site"
            Expression = { $_.Site }
        }, @{
            Name = "OperatingSystem"
            Expression = { $_.OperatingSystem }
        }, @{
            Name = "OSVersion"
            Expression = { $_.OperatingSystemVersion }
        }, @{
            Name = "IsGlobalCatalog"
            Expression = { $_.IsGlobalCatalog }
        }, @{
            Name = "IsReadOnly"
            Expression = { $_.IsReadOnly }
        }, @{
            Name = "LastDiscovered"
            Expression = { Get-Date -Format "yyyy-MM-dd HH:mm:ss" }
        }
        
        Write-Log "Discovered $($DomainControllers.Count) domain controllers" -Level "SUCCESS"
        foreach ($DC in $DomainControllers) {
            Write-Log "  - $($DC.ServerName) ($($DC.FQDN)) - $($DC.IPAddress)" -Level "DEBUG"
        }
        return $DomainControllers
        
    } catch {
        Write-Log "Error discovering domain controllers: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

# Diagnostic function to test basic system access
function Test-SystemAccess {
    param(
        [string]$ComputerName
    )
    
    Write-Log "=== DIAGNOSTIC TEST FOR $ComputerName ===" -Level "INFO"
    
    # Test 1: Local computer detection
    $LocalComputer = $env:COMPUTERNAME
    $IsLocal = ($ComputerName -eq $LocalComputer -or $ComputerName -eq "localhost" -or $ComputerName -eq ".")
    Write-Log "Local computer: $LocalComputer | Target: $ComputerName | IsLocal: $IsLocal" -Level "DEBUG"
    
    # Test 2: Basic WMI access
    try {
        Write-Log "Testing basic WMI access..." -Level "DEBUG"
        if ($IsLocal) {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        } else {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
        }
        Write-Log "✅ WMI Access: SUCCESS - OS: $($OS.Caption)" -Level "SUCCESS"
    } catch {
        Write-Log "❌ WMI Access: FAILED - $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    
    # Test 3: Win32_Product access
    try {
        Write-Log "Testing Win32_Product access..." -Level "DEBUG"
        if ($IsLocal) {
            $Products = Get-CimInstance -ClassName Win32_Product -ErrorAction Stop | Select-Object -First 5
        } else {
            $Products = Get-CimInstance -ClassName Win32_Product -ComputerName $ComputerName -ErrorAction Stop | Select-Object -First 5
        }
        Write-Log "✅ Win32_Product: SUCCESS - Found $($Products.Count) sample products" -Level "SUCCESS"
        foreach ($Product in $Products) {
            Write-Log "    - $($Product.Name) v$($Product.Version)" -Level "DEBUG"
        }
    } catch {
        Write-Log "❌ Win32_Product: FAILED - $($_.Exception.Message)" -Level "ERROR"
    }
    
    # Test 4: Registry access
    try {
        Write-Log "Testing Registry access..." -Level "DEBUG"
        if ($IsLocal) {
            $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        } else {
            $RemoteKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $RegKey = $RemoteKey.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        }
        
        if ($RegKey) {
            $SubKeys = $RegKey.GetSubKeyNames() | Select-Object -First 5
            Write-Log "✅ Registry Access: SUCCESS - Found $($SubKeys.Count) sample registry keys" -Level "SUCCESS"
            $RegKey.Close()
            if (!$IsLocal) { $RemoteKey.Close() }
        } else {
            Write-Log "❌ Registry Access: FAILED - Could not open registry key" -Level "ERROR"
        }
    } catch {
        Write-Log "❌ Registry Access: FAILED - $($_.Exception.Message)" -Level "ERROR"
    }
    
    # Test 5: Hotfix access
    try {
        Write-Log "Testing Hotfix access..." -Level "DEBUG"
        if ($IsLocal) {
            $Hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop | Select-Object -First 5
        } else {
            $Hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ComputerName $ComputerName -ErrorAction Stop | Select-Object -First 5
        }
        Write-Log "✅ Hotfix Access: SUCCESS - Found $($Hotfixes.Count) sample hotfixes" -Level "SUCCESS"
        foreach ($Hotfix in $Hotfixes) {
            Write-Log "    - $($Hotfix.HotFixID): $($Hotfix.Description)" -Level "DEBUG"
        }
    } catch {
        Write-Log "❌ Hotfix Access: FAILED - $($_.Exception.Message)" -Level "ERROR"
    }
    
    Write-Log "=== END DIAGNOSTIC TEST ===" -Level "INFO"
    return $true
}

# Simplified software collection with detailed logging
function Get-InstalledSoftware-Debug {
    param(
        [string]$ComputerName
    )
    
    Write-Log "🔍 Starting software collection for $ComputerName..." -Level "INFO"
    $AllSoftware = @()
    $LocalComputer = $env:COMPUTERNAME
    $IsLocal = ($ComputerName -eq $LocalComputer -or $ComputerName -eq "localhost" -or $ComputerName -eq ".")
    
    Write-Log "Local detection: IsLocal=$IsLocal (LocalComputer=$LocalComputer, Target=$ComputerName)" -Level "DEBUG"
    
    # Method 1: Win32_Product
    try {
        Write-Log "Attempting Win32_Product collection..." -Level "DEBUG"
        if ($IsLocal) {
            Write-Log "Using local Win32_Product query..." -Level "DEBUG"
            $Products = Get-CimInstance -ClassName Win32_Product -ErrorAction Stop
        } else {
            Write-Log "Using remote Win32_Product query for $ComputerName..." -Level "DEBUG"
            $Products = Get-CimInstance -ClassName Win32_Product -ComputerName $ComputerName -ErrorAction Stop
        }
        
        Write-Log "Win32_Product returned $($Products.Count) products" -Level "SUCCESS"
        
        foreach ($Product in $Products) {
            if ($Product.Name) {
                $InstallDateFormatted = "Unknown"
                if ($Product.InstallDate) {
                    try {
                        $InstallDateFormatted = [datetime]::ParseExact($Product.InstallDate, "yyyyMMdd", $null).ToString("yyyy-MM-dd")
                    } catch {
                        $InstallDateFormatted = $Product.InstallDate
                    }
                }
                
                $AllSoftware += [PSCustomObject]@{
                    ServerName = $ComputerName
                    SoftwareName = $Product.Name
                    Version = $Product.Version
                    Publisher = $Product.Vendor
                    InstallDate = $InstallDateFormatted
                    InstallSource = "MSI Package"
                    IsCriticalAgent = ($CriticalAgents | Where-Object { $Product.Name -like "*$_*" }) -ne $null
                    CollectionMethod = "Win32_Product"
                    CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
        Write-Log "Added $($Products.Count) products from Win32_Product" -Level "SUCCESS"
        
    } catch {
        Write-Log "Win32_Product collection failed: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Exception details: $($_.Exception.GetType().FullName)" -Level "ERROR"
    }
    
    # Method 2: Registry (simplified)
    try {
        Write-Log "Attempting Registry collection..." -Level "DEBUG"
        $UninstallKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        
        if ($IsLocal) {
            Write-Log "Using local registry access..." -Level "DEBUG"
            $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($UninstallKey)
        } else {
            Write-Log "Using remote registry access for $ComputerName..." -Level "DEBUG"
            $RemoteKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $RegKey = $RemoteKey.OpenSubKey($UninstallKey)
        }
        
        if ($RegKey) {
            $SubKeyNames = $RegKey.GetSubKeyNames()
            Write-Log "Registry returned $($SubKeyNames.Count) subkeys" -Level "SUCCESS"
            
            $RegistryCount = 0
            foreach ($SubKeyName in $SubKeyNames) {
                try {
                    $ProductKey = $RegKey.OpenSubKey($SubKeyName)
                    if ($ProductKey) {
                        $DisplayName = $ProductKey.GetValue("DisplayName")
                        $DisplayVersion = $ProductKey.GetValue("DisplayVersion")
                        $Publisher = $ProductKey.GetValue("Publisher")
                        $InstallDate = $ProductKey.GetValue("InstallDate")
                        $SystemComponent = $ProductKey.GetValue("SystemComponent")
                        
                        if ($DisplayName -and $SystemComponent -ne 1) {
                            $InstallDateFormatted = "Unknown"
                            if ($InstallDate) {
                                try {
                                    $InstallDateFormatted = [datetime]::ParseExact($InstallDate, "yyyyMMdd", $null).ToString("yyyy-MM-dd")
                                } catch {
                                    $InstallDateFormatted = $InstallDate
                                }
                            }
                            
                            $AllSoftware += [PSCustomObject]@{
                                ServerName = $ComputerName
                                SoftwareName = $DisplayName
                                Version = $DisplayVersion
                                Publisher = $Publisher
                                InstallDate = $InstallDateFormatted
                                InstallSource = "Registry (64-bit)"
                                IsCriticalAgent = ($CriticalAgents | Where-Object { $DisplayName -like "*$_*" }) -ne $null
                                CollectionMethod = "Registry"
                                CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                            $RegistryCount++
                        }
                        $ProductKey.Close()
                    }
                } catch {
                    Write-Log "Error processing registry subkey $SubKeyName : $($_.Exception.Message)" -Level "WARN"
                }
            }
            
            Write-Log "Added $RegistryCount products from Registry" -Level "SUCCESS"
            $RegKey.Close()
            if (!$IsLocal) { $RemoteKey.Close() }
        } else {
            Write-Log "Could not open registry key" -Level "ERROR"
        }
        
    } catch {
        Write-Log "Registry collection failed: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Exception details: $($_.Exception.GetType().FullName)" -Level "ERROR"
    }
    
    Write-Log "Total software packages collected: $($AllSoftware.Count)" -Level "SUCCESS"
    
    # Show sample of collected data
    if ($AllSoftware.Count -gt 0) {
        Write-Log "Sample of collected software:" -Level "DEBUG"
        $AllSoftware | Select-Object -First 5 | ForEach-Object {
            Write-Log "  - $($_.SoftwareName) v$($_.Version) [$($_.CollectionMethod)]" -Level "DEBUG"
        }
    }
    
    return $AllSoftware
}

# Simplified patch collection with detailed logging
function Get-InstalledPatches-Debug {
    param(
        [string]$ComputerName
    )
    
    Write-Log "🔍 Starting patch collection for $ComputerName..." -Level "INFO"
    $AllPatches = @()
    $LocalComputer = $env:COMPUTERNAME
    $IsLocal = ($ComputerName -eq $LocalComputer -or $ComputerName -eq "localhost" -or $ComputerName -eq ".")
    
    try {
        Write-Log "Attempting hotfix collection..." -Level "DEBUG"
        if ($IsLocal) {
            $Hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop
        } else {
            $Hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ComputerName $ComputerName -ErrorAction Stop
        }
        
        Write-Log "Hotfix query returned $($Hotfixes.Count) hotfixes" -Level "SUCCESS"
        
        foreach ($Hotfix in $Hotfixes) {
            $InstallDateFormatted = "Unknown"
            if ($Hotfix.InstalledOn) {
                try {
                    $InstallDateFormatted = $Hotfix.InstalledOn.ToString("yyyy-MM-dd")
                } catch {
                    $InstallDateFormatted = $Hotfix.InstalledOn.ToString()
                }
            }
            
            $AllPatches += [PSCustomObject]@{
                ServerName = $ComputerName
                PatchID = $Hotfix.HotFixID
                Description = $Hotfix.Description
                PatchType = "Hotfix"
                InstallDate = $InstallDateFormatted
                InstalledBy = $Hotfix.InstalledBy
                ServicePackInEffect = $Hotfix.ServicePackInEffect
                CollectionMethod = "Win32_QuickFixEngineering"
                CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        Write-Log "Added $($Hotfixes.Count) hotfixes" -Level "SUCCESS"
        
    } catch {
        Write-Log "Hotfix collection failed: $($_.Exception.Message)" -Level "ERROR"
    }
    
    Write-Log "Total patches collected: $($AllPatches.Count)" -Level "SUCCESS"
    return $AllPatches
}

# Main execution function
function Start-DiagnosticCollection {
    Write-Log "=== Starting Diagnostic Inventory Collection ===" -Level "INFO"
    
    # Discover Domain Controllers
    $DomainControllers = Get-DomainControllers
    if ($DomainControllers.Count -eq 0) {
        Write-Log "No domain controllers found. Exiting." -Level "ERROR"
        return
    }
    
    # Initialize data collections
    $AllSoftwareData = @()
    $AllPatchData = @()
    
    # Process each domain controller
    foreach ($DC in $DomainControllers) {
        Write-Log "🖥️ Processing server: $($DC.ServerName)" -Level "INFO"
        
        # Run diagnostic tests
        Test-SystemAccess -ComputerName $DC.ServerName
        
        # Collect data with detailed logging
        $SoftwareData = Get-InstalledSoftware-Debug -ComputerName $DC.ServerName
        $PatchData = Get-InstalledPatches-Debug -ComputerName $DC.ServerName
        
        if ($SoftwareData.Count -gt 0) {
            $AllSoftwareData += $SoftwareData
            Write-Log "✅ Successfully collected $($SoftwareData.Count) software packages from $($DC.ServerName)" -Level "SUCCESS"
        } else {
            Write-Log "❌ No software data collected from $($DC.ServerName)" -Level "ERROR"
        }
        
        if ($PatchData.Count -gt 0) {
            $AllPatchData += $PatchData
            Write-Log "✅ Successfully collected $($PatchData.Count) patches from $($DC.ServerName)" -Level "SUCCESS"
        } else {
            Write-Log "❌ No patch data collected from $($DC.ServerName)" -Level "ERROR"
        }
        
        Write-Log "Server $($DC.ServerName) summary: $($SoftwareData.Count) software, $($PatchData.Count) patches" -Level "INFO"
    }
    
    # Create output directory
    if (!(Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Export results
    Write-Log "Exporting diagnostic results..." -Level "INFO"
    
    if ($AllSoftwareData.Count -gt 0) {
        $SoftwareExportPath = "$OutputPath\SoftwareInventory_Debug_$Timestamp.csv"
        $AllSoftwareData | Export-Csv -Path $SoftwareExportPath -NoTypeInformation
        Write-Log "✅ Software data exported: $SoftwareExportPath ($($AllSoftwareData.Count) records)" -Level "SUCCESS"
    } else {
        Write-Log "❌ No software data to export" -Level "ERROR"
    }
    
    if ($AllPatchData.Count -gt 0) {
        $PatchExportPath = "$OutputPath\PatchInventory_Debug_$Timestamp.csv"
        $AllPatchData | Export-Csv -Path $PatchExportPath -NoTypeInformation
        Write-Log "✅ Patch data exported: $PatchExportPath ($($AllPatchData.Count) records)" -Level "SUCCESS"
    } else {
        Write-Log "❌ No patch data to export" -Level "ERROR"
    }
    
    # Final summary
    Write-Log "=== DIAGNOSTIC COLLECTION SUMMARY ===" -Level "INFO"
    Write-Log "Total Software Packages: $($AllSoftwareData.Count)" -Level "INFO"
    Write-Log "Total Patches: $($AllPatchData.Count)" -Level "INFO"
    
    if ($AllSoftwareData.Count -eq 0 -and $AllPatchData.Count -eq 0) {
        Write-Log "❌ NO DATA COLLECTED - Check the diagnostic messages above for specific errors" -Level "ERROR"
    } else {
        Write-Log "✅ Data collection partially or fully successful" -Level "SUCCESS"
    }
    
    Write-Log "=== Diagnostic Collection Completed ===" -Level "INFO"
}

# Script entry point
try {
    Initialize-Logging
    Start-DiagnosticCollection
    
} catch {
    Write-Log "Critical error in main execution: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}

