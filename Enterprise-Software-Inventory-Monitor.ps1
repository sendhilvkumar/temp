#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Enterprise Software & Patch Inventory Monitor - PowerShell Backend
    
.DESCRIPTION
    Comprehensive script to collect complete software inventory and patch information across domain controllers.
    Collects:
    - All installed software/agents with versions and install dates
    - All patches, hotfixes, and service packs with versions and install dates
    - System information and compliance status
    
.AUTHOR
    Enterprise IT Team
    
.VERSION
    2.0
    
.NOTES
    Requires Active Directory PowerShell module and appropriate permissions
    Requires WMI/CIM access to target servers
#>

# Script Configuration
$ScriptVersion = "2.0"
$ScriptName = "Enterprise Software & Patch Inventory Monitor"
$OutputPath = "$PSScriptRoot\InventoryReports"
$LogPath = "$PSScriptRoot\Logs"

# Critical agents to highlight (for dashboard focus)
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

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
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
        
        Write-Log "Discovered $($DomainControllers.Count) domain controllers" -Level "INFO"
        return $DomainControllers
        
    } catch {
        Write-Log "Error discovering domain controllers: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

# Test remote connectivity
function Test-RemoteConnectivity {
    param(
        [string]$ComputerName,
        [int]$TimeoutSeconds = 10
    )
    
    try {
        $Result = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -TimeoutSeconds $TimeoutSeconds
        return $Result
    } catch {
        return $false
    }
}

# Get all installed software from multiple sources
function Get-InstalledSoftware {
    param(
        [string]$ComputerName
    )
    
    Write-Log "  Collecting installed software for $ComputerName..." -Level "DEBUG"
    $AllSoftware = @()
    
    try {
        # Method 1: Win32_Product (slower but more reliable for MSI packages)
        try {
            Write-Log "    Querying Win32_Product..." -Level "DEBUG"
            $Win32Products = Get-CimInstance -ClassName Win32_Product -ComputerName $ComputerName -ErrorAction SilentlyContinue | 
                Select-Object Name, Version, Vendor, InstallDate, @{
                    Name = "InstallSource"
                    Expression = { "Win32_Product" }
                }
            
            foreach ($Product in $Win32Products) {
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
        } catch {
            Write-Log "    Error querying Win32_Product: $($_.Exception.Message)" -Level "WARN"
        }
        
        # Method 2: Registry - Uninstall keys (faster, more comprehensive)
        try {
            Write-Log "    Querying Registry Uninstall keys..." -Level "DEBUG"
            
            $UninstallKeys = @(
                "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )
            
            foreach ($UninstallKey in $UninstallKeys) {
                $RegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                $SubKey = $RegKey.OpenSubKey($UninstallKey)
                
                if ($SubKey) {
                    foreach ($SubKeyName in $SubKey.GetSubKeyNames()) {
                        $ProductKey = $SubKey.OpenSubKey($SubKeyName)
                        if ($ProductKey) {
                            $DisplayName = $ProductKey.GetValue("DisplayName")
                            $DisplayVersion = $ProductKey.GetValue("DisplayVersion")
                            $Publisher = $ProductKey.GetValue("Publisher")
                            $InstallDate = $ProductKey.GetValue("InstallDate")
                            $SystemComponent = $ProductKey.GetValue("SystemComponent")
                            
                            # Skip system components and entries without display names
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
                                    InstallSource = if ($UninstallKey -like "*WOW6432Node*") { "Registry (32-bit)" } else { "Registry (64-bit)" }
                                    IsCriticalAgent = ($CriticalAgents | Where-Object { $DisplayName -like "*$_*" }) -ne $null
                                    CollectionMethod = "Registry"
                                    CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                }
                            }
                            $ProductKey.Close()
                        }
                    }
                    $SubKey.Close()
                }
                $RegKey.Close()
            }
        } catch {
            Write-Log "    Error querying Registry: $($_.Exception.Message)" -Level "WARN"
        }
        
        # Remove duplicates based on name and version
        $UniqueSoftware = $AllSoftware | Sort-Object SoftwareName, Version | 
            Group-Object SoftwareName, Version | 
            ForEach-Object { $_.Group | Select-Object -First 1 }
        
        Write-Log "    Found $($UniqueSoftware.Count) unique software packages" -Level "DEBUG"
        return $UniqueSoftware
        
    } catch {
        Write-Log "    Error collecting software inventory: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

# Get all installed patches and hotfixes
function Get-InstalledPatches {
    param(
        [string]$ComputerName
    )
    
    Write-Log "  Collecting installed patches for $ComputerName..." -Level "DEBUG"
    $AllPatches = @()
    
    try {
        # Method 1: Win32_QuickFixEngineering (Hotfixes)
        try {
            Write-Log "    Querying Win32_QuickFixEngineering..." -Level "DEBUG"
            $Hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ComputerName $ComputerName -ErrorAction SilentlyContinue
            
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
        } catch {
            Write-Log "    Error querying Win32_QuickFixEngineering: $($_.Exception.Message)" -Level "WARN"
        }
        
        # Method 2: Windows Update History via Registry
        try {
            Write-Log "    Querying Windows Update Registry..." -Level "DEBUG"
            
            $UpdateKeys = @(
                "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install",
                "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Download"
            )
            
            foreach ($UpdateKey in $UpdateKeys) {
                $RegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                $SubKey = $RegKey.OpenSubKey($UpdateKey)
                
                if ($SubKey) {
                    $LastSuccessTime = $SubKey.GetValue("LastSuccessTime")
                    $LastError = $SubKey.GetValue("LastError")
                    
                    if ($LastSuccessTime) {
                        $AllPatches += [PSCustomObject]@{
                            ServerName = $ComputerName
                            PatchID = "Windows Update"
                            Description = "Windows Update - $($UpdateKey.Split('\')[-1])"
                            PatchType = "Windows Update"
                            InstallDate = $LastSuccessTime
                            InstalledBy = "System"
                            ServicePackInEffect = ""
                            CollectionMethod = "Registry"
                            CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        }
                    }
                    $SubKey.Close()
                }
                $RegKey.Close()
            }
        } catch {
            Write-Log "    Error querying Windows Update Registry: $($_.Exception.Message)" -Level "WARN"
        }
        
        # Method 3: Get Windows Features and Optional Features
        try {
            Write-Log "    Querying Windows Features..." -Level "DEBUG"
            $Features = Get-CimInstance -ClassName Win32_OptionalFeature -ComputerName $ComputerName -ErrorAction SilentlyContinue | 
                Where-Object { $_.InstallState -eq 1 }  # Only installed features
            
            foreach ($Feature in $Features) {
                $AllPatches += [PSCustomObject]@{
                    ServerName = $ComputerName
                    PatchID = $Feature.Name
                    Description = $Feature.Caption
                    PatchType = "Windows Feature"
                    InstallDate = "Unknown"
                    InstalledBy = "System"
                    ServicePackInEffect = ""
                    CollectionMethod = "Win32_OptionalFeature"
                    CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        } catch {
            Write-Log "    Error querying Windows Features: $($_.Exception.Message)" -Level "WARN"
        }
        
        Write-Log "    Found $($AllPatches.Count) patches and updates" -Level "DEBUG"
        return $AllPatches
        
    } catch {
        Write-Log "    Error collecting patch inventory: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

# Get system information
function Get-SystemInformation {
    param(
        [string]$ComputerName
    )
    
    Write-Log "  Collecting system information for $ComputerName..." -Level "DEBUG"
    
    try {
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction SilentlyContinue
        $OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction SilentlyContinue
        $Processor = Get-CimInstance -ClassName Win32_Processor -ComputerName $ComputerName -ErrorAction SilentlyContinue | Select-Object -First 1
        
        $SystemInfo = [PSCustomObject]@{
            ServerName = $ComputerName
            Manufacturer = $ComputerSystem.Manufacturer
            Model = $ComputerSystem.Model
            TotalPhysicalMemory = [math]::Round($ComputerSystem.TotalPhysicalMemory / 1GB, 2)
            ProcessorName = $Processor.Name
            ProcessorCores = $Processor.NumberOfCores
            ProcessorLogicalProcessors = $Processor.NumberOfLogicalProcessors
            OSName = $OperatingSystem.Caption
            OSVersion = $OperatingSystem.Version
            OSBuildNumber = $OperatingSystem.BuildNumber
            OSServicePack = $OperatingSystem.ServicePackMajorVersion
            OSInstallDate = $OperatingSystem.InstallDate.ToString("yyyy-MM-dd HH:mm:ss")
            OSLastBootUpTime = $OperatingSystem.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
            CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        return $SystemInfo
        
    } catch {
        Write-Log "    Error collecting system information: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# Generate comprehensive inventory summary
function Get-InventorySummary {
    param(
        [array]$AllSoftwareData,
        [array]$AllPatchData,
        [array]$AllSystemData
    )
    
    $Summary = @{
        TotalServers = ($AllSoftwareData | Select-Object -Unique ServerName).Count
        TotalSoftwarePackages = $AllSoftwareData.Count
        TotalPatches = $AllPatchData.Count
        CriticalAgentsFound = ($AllSoftwareData | Where-Object { $_.IsCriticalAgent -eq $true }).Count
        UniquePublishers = ($AllSoftwareData | Select-Object -Unique Publisher | Where-Object { $_.Publisher }).Count
        RecentInstalls = ($AllSoftwareData | Where-Object { 
            $_.InstallDate -ne "Unknown" -and 
            $_.InstallDate -ne "" -and 
            ([datetime]$_.InstallDate) -gt (Get-Date).AddDays(-30) 
        }).Count
        RecentPatches = ($AllPatchData | Where-Object { 
            $_.InstallDate -ne "Unknown" -and 
            $_.InstallDate -ne "" -and 
            ([datetime]$_.InstallDate) -gt (Get-Date).AddDays(-30) 
        }).Count
        GeneratedTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    return $Summary
}

# Export comprehensive inventory data
function Export-InventoryData {
    param(
        [array]$DomainControllers,
        [array]$SoftwareData,
        [array]$PatchData,
        [array]$SystemData,
        [hashtable]$Summary
    )
    
    # Create output directory
    if (!(Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Export Domain Controllers
    $DCExportPath = "$OutputPath\DomainControllers_$Timestamp.csv"
    $DomainControllers | Export-Csv -Path $DCExportPath -NoTypeInformation
    Write-Log "Domain Controllers exported to: $DCExportPath" -Level "INFO"
    
    # Export Software Inventory
    $SoftwareExportPath = "$OutputPath\SoftwareInventory_$Timestamp.csv"
    $SoftwareData | Export-Csv -Path $SoftwareExportPath -NoTypeInformation
    Write-Log "Software inventory exported to: $SoftwareExportPath" -Level "INFO"
    
    # Export Patch Inventory
    $PatchExportPath = "$OutputPath\PatchInventory_$Timestamp.csv"
    $PatchData | Export-Csv -Path $PatchExportPath -NoTypeInformation
    Write-Log "Patch inventory exported to: $PatchExportPath" -Level "INFO"
    
    # Export System Information
    $SystemExportPath = "$OutputPath\SystemInformation_$Timestamp.csv"
    $SystemData | Export-Csv -Path $SystemExportPath -NoTypeInformation
    Write-Log "System information exported to: $SystemExportPath" -Level "INFO"
    
    # Export Critical Agents Summary
    $CriticalAgentsPath = "$OutputPath\CriticalAgents_$Timestamp.csv"
    $CriticalAgentsData = $SoftwareData | Where-Object { $_.IsCriticalAgent -eq $true }
    $CriticalAgentsData | Export-Csv -Path $CriticalAgentsPath -NoTypeInformation
    Write-Log "Critical agents exported to: $CriticalAgentsPath" -Level "INFO"
    
    # Export Summary
    $SummaryExportPath = "$OutputPath\InventorySummary_$Timestamp.csv"
    $SummaryObject = [PSCustomObject]$Summary
    $SummaryObject | Export-Csv -Path $SummaryExportPath -NoTypeInformation
    Write-Log "Inventory summary exported to: $SummaryExportPath" -Level "INFO"
    
    # Export JSON for dashboard consumption
    $JsonExportPath = "$OutputPath\InventoryData_$Timestamp.json"
    $JsonData = @{
        DomainControllers = $DomainControllers
        SoftwareInventory = $SoftwareData
        PatchInventory = $PatchData
        SystemInformation = $SystemData
        CriticalAgents = $CriticalAgentsData
        Summary = $Summary
        CriticalAgentsList = $CriticalAgents
        GeneratedBy = $ScriptName
        Version = $ScriptVersion
    }
    $JsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonExportPath -Encoding UTF8
    Write-Log "JSON data exported to: $JsonExportPath" -Level "INFO"
    
    return @{
        DCExport = $DCExportPath
        SoftwareExport = $SoftwareExportPath
        PatchExport = $PatchExportPath
        SystemExport = $SystemExportPath
        CriticalAgentsExport = $CriticalAgentsPath
        SummaryExport = $SummaryExportPath
        JsonExport = $JsonExportPath
    }
}

# Main execution function
function Start-InventoryCollection {
    Write-Log "=== Starting Enterprise Software & Patch Inventory Collection ===" -Level "INFO"
    
    # Discover Domain Controllers
    $DomainControllers = Get-DomainControllers
    if ($DomainControllers.Count -eq 0) {
        Write-Log "No domain controllers found. Exiting." -Level "ERROR"
        return
    }
    
    # Initialize data collections
    $AllSoftwareData = @()
    $AllPatchData = @()
    $AllSystemData = @()
    $TotalOperations = $DomainControllers.Count * 3  # 3 operations per server
    $CurrentOperation = 0
    
    Write-Log "Starting inventory collection for $($DomainControllers.Count) servers..." -Level "INFO"
    
    # Collect inventory from each domain controller
    foreach ($DC in $DomainControllers) {
        Write-Log "Processing server: $($DC.ServerName)" -Level "INFO"
        
        # Test connectivity first
        if (!(Test-RemoteConnectivity -ComputerName $DC.ServerName)) {
            Write-Log "  Server $($DC.ServerName) is unreachable. Skipping." -Level "WARN"
            continue
        }
        
        # Collect Software Inventory
        $CurrentOperation++
        $ProgressPercent = [math]::Round(($CurrentOperation / $TotalOperations) * 100, 1)
        Write-Progress -Activity "Collecting Inventory Data" -Status "Server: $($DC.ServerName) | Software Inventory" -PercentComplete $ProgressPercent
        
        $SoftwareData = Get-InstalledSoftware -ComputerName $DC.ServerName
        $AllSoftwareData += $SoftwareData
        
        # Collect Patch Inventory
        $CurrentOperation++
        $ProgressPercent = [math]::Round(($CurrentOperation / $TotalOperations) * 100, 1)
        Write-Progress -Activity "Collecting Inventory Data" -Status "Server: $($DC.ServerName) | Patch Inventory" -PercentComplete $ProgressPercent
        
        $PatchData = Get-InstalledPatches -ComputerName $DC.ServerName
        $AllPatchData += $PatchData
        
        # Collect System Information
        $CurrentOperation++
        $ProgressPercent = [math]::Round(($CurrentOperation / $TotalOperations) * 100, 1)
        Write-Progress -Activity "Collecting Inventory Data" -Status "Server: $($DC.ServerName) | System Information" -PercentComplete $ProgressPercent
        
        $SystemData = Get-SystemInformation -ComputerName $DC.ServerName
        if ($SystemData) {
            $AllSystemData += $SystemData
        }
        
        Write-Log "  Completed inventory for $($DC.ServerName): $($SoftwareData.Count) software, $($PatchData.Count) patches" -Level "INFO"
    }
    
    Write-Progress -Activity "Collecting Inventory Data" -Completed
    
    # Generate inventory summary
    Write-Log "Generating inventory summary..." -Level "INFO"
    $InventorySummary = Get-InventorySummary -AllSoftwareData $AllSoftwareData -AllPatchData $AllPatchData -AllSystemData $AllSystemData
    
    # Export all data
    Write-Log "Exporting inventory data..." -Level "INFO"
    $ExportPaths = Export-InventoryData -DomainControllers $DomainControllers -SoftwareData $AllSoftwareData -PatchData $AllPatchData -SystemData $AllSystemData -Summary $InventorySummary
    
    # Display summary
    Write-Log "=== INVENTORY COLLECTION SUMMARY ===" -Level "INFO"
    Write-Log "Total Servers Processed: $($InventorySummary.TotalServers)" -Level "INFO"
    Write-Log "Total Software Packages: $($InventorySummary.TotalSoftwarePackages)" -Level "INFO"
    Write-Log "Total Patches/Updates: $($InventorySummary.TotalPatches)" -Level "INFO"
    Write-Log "Critical Agents Found: $($InventorySummary.CriticalAgentsFound)" -Level "INFO"
    Write-Log "Unique Publishers: $($InventorySummary.UniquePublishers)" -Level "INFO"
    Write-Log "Recent Installs (30 days): $($InventorySummary.RecentInstalls)" -Level "INFO"
    Write-Log "Recent Patches (30 days): $($InventorySummary.RecentPatches)" -Level "INFO"
    
    Write-Log "=== $ScriptName Completed Successfully ===" -Level "INFO"
    
    return @{
        DomainControllers = $DomainControllers
        SoftwareData = $AllSoftwareData
        PatchData = $AllPatchData
        SystemData = $AllSystemData
        Summary = $InventorySummary
        ExportPaths = $ExportPaths
    }
}

# Script entry point
try {
    Initialize-Logging
    $Results = Start-InventoryCollection
    
    # Return results for potential pipeline usage
    return $Results
    
} catch {
    Write-Log "Critical error in main execution: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}

