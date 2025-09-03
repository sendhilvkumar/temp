#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Enterprise Software & Patch Inventory Monitor - Enhanced with OS & Hardware Info
    
.DESCRIPTION
    Comprehensive script to collect complete software inventory, patch information, 
    operating system details, and hardware configuration across domain controllers.
    
.AUTHOR
    Enterprise IT Team
    
.VERSION
    2.3 (Enhanced with OS & Hardware)
#>

# Script Configuration
$ScriptVersion = "2.3"
$ScriptName = "Enterprise Software & Patch Inventory Monitor (Enhanced)"
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
        return $DomainControllers
        
    } catch {
        Write-Log "Error discovering domain controllers: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

# Get comprehensive operating system information
function Get-OperatingSystemInfo {
    param(
        [string]$ComputerName
    )
    
    Write-Log "  Collecting operating system information for $ComputerName..." -Level "DEBUG"
    $LocalComputer = $env:COMPUTERNAME
    $IsLocal = ($ComputerName -eq $LocalComputer -or $ComputerName -eq "localhost" -or $ComputerName -eq ".")
    
    try {
        # Get OS information
        if ($IsLocal) {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $TimeZone = Get-CimInstance -ClassName Win32_TimeZone -ErrorAction Stop
        } else {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction Stop
            $TimeZone = Get-CimInstance -ClassName Win32_TimeZone -ComputerName $ComputerName -ErrorAction Stop
        }
        
        # Calculate uptime
        $Uptime = (Get-Date) - $OS.LastBootUpTime
        $UptimeString = "$($Uptime.Days) days, $($Uptime.Hours) hours, $($Uptime.Minutes) minutes"
        
        # Calculate memory usage
        $TotalMemoryGB = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
        $FreeMemoryGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)
        $UsedMemoryGB = [math]::Round($TotalMemoryGB - $FreeMemoryGB, 2)
        $MemoryUsagePercent = [math]::Round(($UsedMemoryGB / $TotalMemoryGB) * 100, 1)
        
        $OSInfo = [PSCustomObject]@{
            ServerName = $ComputerName
            OSName = $OS.Caption
            OSVersion = $OS.Version
            OSBuildNumber = $OS.BuildNumber
            OSArchitecture = $OS.OSArchitecture
            OSLanguage = $OS.OSLanguage
            OSServicePack = $OS.ServicePackMajorVersion
            OSInstallDate = $OS.InstallDate.ToString("yyyy-MM-dd HH:mm:ss")
            OSLastBootUpTime = $OS.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
            SystemUptime = $UptimeString
            SystemDirectory = $OS.SystemDirectory
            WindowsDirectory = $OS.WindowsDirectory
            BootDevice = $OS.BootDevice
            SystemDevice = $OS.SystemDevice
            TotalMemoryGB = $TotalMemoryGB
            FreeMemoryGB = $FreeMemoryGB
            UsedMemoryGB = $UsedMemoryGB
            MemoryUsagePercent = $MemoryUsagePercent
            VirtualMemoryTotalGB = [math]::Round($OS.TotalVirtualMemorySize / 1MB, 2)
            VirtualMemoryFreeGB = [math]::Round($OS.FreeVirtualMemory / 1MB, 2)
            PageFileSpaceGB = [math]::Round($OS.SizeStoredInPagingFiles / 1MB, 2)
            SystemType = $ComputerSystem.SystemType
            Domain = $ComputerSystem.Domain
            Workgroup = $ComputerSystem.Workgroup
            PartOfDomain = $ComputerSystem.PartOfDomain
            TimeZone = $TimeZone.StandardName
            TimeZoneBias = $TimeZone.Bias
            CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        Write-Log "    Successfully collected OS information" -Level "SUCCESS"
        return $OSInfo
        
    } catch {
        Write-Log "    Error collecting OS information: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# Get comprehensive hardware configuration information
function Get-HardwareInfo {
    param(
        [string]$ComputerName
    )
    
    Write-Log "  Collecting hardware information for $ComputerName..." -Level "DEBUG"
    $LocalComputer = $env:COMPUTERNAME
    $IsLocal = ($ComputerName -eq $LocalComputer -or $ComputerName -eq "localhost" -or $ComputerName -eq ".")
    
    try {
        # Get hardware information
        if ($IsLocal) {
            $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $Processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
            $BIOS = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
            $BaseBoard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop
            $PhysicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop
            $LogicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 }
            $NetworkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop | Where-Object { $_.NetConnectionStatus -eq 2 }
        } else {
            $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction Stop
            $Processor = Get-CimInstance -ClassName Win32_Processor -ComputerName $ComputerName -ErrorAction Stop | Select-Object -First 1
            $BIOS = Get-CimInstance -ClassName Win32_BIOS -ComputerName $ComputerName -ErrorAction Stop
            $BaseBoard = Get-CimInstance -ClassName Win32_BaseBoard -ComputerName $ComputerName -ErrorAction Stop
            $PhysicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory -ComputerName $ComputerName -ErrorAction Stop
            $LogicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $ComputerName -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 }
            $NetworkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter -ComputerName $ComputerName -ErrorAction Stop | Where-Object { $_.NetConnectionStatus -eq 2 }
        }
        
        # Process memory information
        $MemorySlots = $PhysicalMemory.Count
        $TotalPhysicalMemoryGB = [math]::Round(($PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
        $MemoryDetails = ($PhysicalMemory | ForEach-Object { 
            "$([math]::Round($_.Capacity / 1GB, 2))GB $($_.MemoryType) @ $($_.Speed)MHz" 
        }) -join "; "
        
        # Process disk information
        $DiskInfo = ($LogicalDisks | ForEach-Object {
            $SizeGB = [math]::Round($_.Size / 1GB, 2)
            $FreeGB = [math]::Round($_.FreeSpace / 1GB, 2)
            $UsedPercent = [math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 1)
            "$($_.DeviceID) ${SizeGB}GB (${UsedPercent}% used)"
        }) -join "; "
        
        # Process network adapter information
        $NetworkInfo = ($NetworkAdapters | ForEach-Object {
            "$($_.Name) [$($_.MACAddress)]"
        }) -join "; "
        
        $HardwareInfo = [PSCustomObject]@{
            ServerName = $ComputerName
            Manufacturer = $ComputerSystem.Manufacturer
            Model = $ComputerSystem.Model
            SystemFamily = $ComputerSystem.SystemFamily
            SystemSKUNumber = $ComputerSystem.SystemSKUNumber
            SerialNumber = $BIOS.SerialNumber
            BIOSVersion = $BIOS.SMBIOSBIOSVersion
            BIOSReleaseDate = if ($BIOS.ReleaseDate) { $BIOS.ReleaseDate.ToString("yyyy-MM-dd") } else { "Unknown" }
            MotherboardManufacturer = $BaseBoard.Manufacturer
            MotherboardProduct = $BaseBoard.Product
            MotherboardVersion = $BaseBoard.Version
            ProcessorName = $Processor.Name
            ProcessorManufacturer = $Processor.Manufacturer
            ProcessorFamily = $Processor.Family
            ProcessorCores = $Processor.NumberOfCores
            ProcessorLogicalProcessors = $Processor.NumberOfLogicalProcessors
            ProcessorMaxClockSpeed = $Processor.MaxClockSpeed
            ProcessorCurrentClockSpeed = $Processor.CurrentClockSpeed
            ProcessorArchitecture = switch ($Processor.Architecture) {
                0 { "x86" }
                1 { "MIPS" }
                2 { "Alpha" }
                3 { "PowerPC" }
                6 { "Intel Itanium" }
                9 { "x64" }
                default { "Unknown" }
            }
            TotalPhysicalMemoryGB = $TotalPhysicalMemoryGB
            MemorySlots = $MemorySlots
            MemoryDetails = $MemoryDetails
            DiskInformation = $DiskInfo
            NetworkAdapters = $NetworkInfo
            SystemType = $ComputerSystem.SystemType
            ThermalState = $ComputerSystem.ThermalState
            PowerState = $ComputerSystem.PowerState
            WakeUpType = $ComputerSystem.WakeUpType
            CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        Write-Log "    Successfully collected hardware information" -Level "SUCCESS"
        return $HardwareInfo
        
    } catch {
        Write-Log "    Error collecting hardware information: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# Get installed software (using working method from diagnostic version)
function Get-InstalledSoftware {
    param(
        [string]$ComputerName
    )
    
    Write-Log "  Collecting installed software for $ComputerName..." -Level "DEBUG"
    $AllSoftware = @()
    $LocalComputer = $env:COMPUTERNAME
    $IsLocal = ($ComputerName -eq $LocalComputer -or $ComputerName -eq "localhost" -or $ComputerName -eq ".")
    
    # Method 1: Win32_Product
    try {
        if ($IsLocal) {
            $Products = Get-CimInstance -ClassName Win32_Product -ErrorAction Stop
        } else {
            $Products = Get-CimInstance -ClassName Win32_Product -ComputerName $ComputerName -ErrorAction Stop
        }
        
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
    } catch {
        Write-Log "    Win32_Product collection failed: $($_.Exception.Message)" -Level "WARN"
    }
    
    # Method 2: Registry
    try {
        $UninstallKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        
        if ($IsLocal) {
            $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($UninstallKey)
        } else {
            $RemoteKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $RegKey = $RemoteKey.OpenSubKey($UninstallKey)
        }
        
        if ($RegKey) {
            foreach ($SubKeyName in $RegKey.GetSubKeyNames()) {
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
                        }
                        $ProductKey.Close()
                    }
                } catch {
                    # Skip individual registry errors
                }
            }
            $RegKey.Close()
            if (!$IsLocal) { $RemoteKey.Close() }
        }
    } catch {
        Write-Log "    Registry collection failed: $($_.Exception.Message)" -Level "WARN"
    }
    
    # Remove duplicates
    $UniqueSoftware = $AllSoftware | Sort-Object SoftwareName, Version | 
        Group-Object SoftwareName, Version | 
        ForEach-Object { $_.Group | Select-Object -First 1 }
    
    Write-Log "    Found $($UniqueSoftware.Count) unique software packages" -Level "SUCCESS"
    return $UniqueSoftware
}

# Get installed patches (using working method from diagnostic version)
function Get-InstalledPatches {
    param(
        [string]$ComputerName
    )
    
    Write-Log "  Collecting installed patches for $ComputerName..." -Level "DEBUG"
    $AllPatches = @()
    $LocalComputer = $env:COMPUTERNAME
    $IsLocal = ($ComputerName -eq $LocalComputer -or $ComputerName -eq "localhost" -or $ComputerName -eq ".")
    
    try {
        if ($IsLocal) {
            $Hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop
        } else {
            $Hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ComputerName $ComputerName -ErrorAction Stop
        }
        
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
        
        Write-Log "    Found $($AllPatches.Count) patches" -Level "SUCCESS"
        
    } catch {
        Write-Log "    Patch collection failed: $($_.Exception.Message)" -Level "ERROR"
    }
    
    return $AllPatches
}

# Generate comprehensive inventory summary
function Get-InventorySummary {
    param(
        [array]$AllSoftwareData,
        [array]$AllPatchData,
        [array]$AllOSData,
        [array]$AllHardwareData
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
        TotalMemoryGB = ($AllHardwareData | Measure-Object -Property TotalPhysicalMemoryGB -Sum).Sum
        TotalProcessorCores = ($AllHardwareData | Measure-Object -Property ProcessorCores -Sum).Sum
        UniqueManufacturers = ($AllHardwareData | Select-Object -Unique Manufacturer | Where-Object { $_.Manufacturer }).Count
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
        [array]$OSData,
        [array]$HardwareData,
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
    
    # Export Operating System Information
    $OSExportPath = "$OutputPath\OperatingSystemInfo_$Timestamp.csv"
    $OSData | Export-Csv -Path $OSExportPath -NoTypeInformation
    Write-Log "Operating System information exported to: $OSExportPath" -Level "INFO"
    
    # Export Hardware Information
    $HardwareExportPath = "$OutputPath\HardwareInfo_$Timestamp.csv"
    $HardwareData | Export-Csv -Path $HardwareExportPath -NoTypeInformation
    Write-Log "Hardware information exported to: $HardwareExportPath" -Level "INFO"
    
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
        OperatingSystemInfo = $OSData
        HardwareInfo = $HardwareData
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
        OSExport = $OSExportPath
        HardwareExport = $HardwareExportPath
        CriticalAgentsExport = $CriticalAgentsPath
        SummaryExport = $SummaryExportPath
        JsonExport = $JsonExportPath
    }
}

# Main execution function
function Start-EnhancedInventoryCollection {
    Write-Log "=== Starting Enhanced Inventory Collection (Software + OS + Hardware) ===" -Level "INFO"
    
    # Discover Domain Controllers
    $DomainControllers = Get-DomainControllers
    if ($DomainControllers.Count -eq 0) {
        Write-Log "No domain controllers found. Exiting." -Level "ERROR"
        return
    }
    
    # Initialize data collections
    $AllSoftwareData = @()
    $AllPatchData = @()
    $AllOSData = @()
    $AllHardwareData = @()
    $TotalOperations = $DomainControllers.Count * 4  # 4 operations per server
    $CurrentOperation = 0
    
    Write-Log "Starting enhanced inventory collection for $($DomainControllers.Count) servers..." -Level "INFO"
    
    # Collect inventory from each domain controller
    foreach ($DC in $DomainControllers) {
        Write-Log "🖥️ Processing server: $($DC.ServerName)" -Level "INFO"
        
        # Collect Software Inventory
        $CurrentOperation++
        $ProgressPercent = [math]::Round(($CurrentOperation / $TotalOperations) * 100, 1)
        Write-Progress -Activity "Collecting Enhanced Inventory Data" -Status "Server: $($DC.ServerName) | Software Inventory" -PercentComplete $ProgressPercent
        
        $SoftwareData = Get-InstalledSoftware -ComputerName $DC.ServerName
        if ($SoftwareData.Count -gt 0) {
            $AllSoftwareData += $SoftwareData
        }
        
        # Collect Patch Inventory
        $CurrentOperation++
        $ProgressPercent = [math]::Round(($CurrentOperation / $TotalOperations) * 100, 1)
        Write-Progress -Activity "Collecting Enhanced Inventory Data" -Status "Server: $($DC.ServerName) | Patch Inventory" -PercentComplete $ProgressPercent
        
        $PatchData = Get-InstalledPatches -ComputerName $DC.ServerName
        if ($PatchData.Count -gt 0) {
            $AllPatchData += $PatchData
        }
        
        # Collect Operating System Information
        $CurrentOperation++
        $ProgressPercent = [math]::Round(($CurrentOperation / $TotalOperations) * 100, 1)
        Write-Progress -Activity "Collecting Enhanced Inventory Data" -Status "Server: $($DC.ServerName) | Operating System Info" -PercentComplete $ProgressPercent
        
        $OSData = Get-OperatingSystemInfo -ComputerName $DC.ServerName
        if ($OSData) {
            $AllOSData += $OSData
        }
        
        # Collect Hardware Information
        $CurrentOperation++
        $ProgressPercent = [math]::Round(($CurrentOperation / $TotalOperations) * 100, 1)
        Write-Progress -Activity "Collecting Enhanced Inventory Data" -Status "Server: $($DC.ServerName) | Hardware Configuration" -PercentComplete $ProgressPercent
        
        $HardwareData = Get-HardwareInfo -ComputerName $DC.ServerName
        if ($HardwareData) {
            $AllHardwareData += $HardwareData
        }
        
        Write-Log "✅ Completed inventory for $($DC.ServerName): $($SoftwareData.Count) software, $($PatchData.Count) patches, OS & Hardware info collected" -Level "SUCCESS"
    }
    
    Write-Progress -Activity "Collecting Enhanced Inventory Data" -Completed
    
    # Generate inventory summary
    Write-Log "Generating comprehensive inventory summary..." -Level "INFO"
    $InventorySummary = Get-InventorySummary -AllSoftwareData $AllSoftwareData -AllPatchData $AllPatchData -AllOSData $AllOSData -AllHardwareData $AllHardwareData
    
    # Export all data
    Write-Log "Exporting enhanced inventory data..." -Level "INFO"
    $ExportPaths = Export-InventoryData -DomainControllers $DomainControllers -SoftwareData $AllSoftwareData -PatchData $AllPatchData -OSData $AllOSData -HardwareData $AllHardwareData -Summary $InventorySummary
    
    # Display summary
    Write-Log "=== ENHANCED INVENTORY COLLECTION SUMMARY ===" -Level "INFO"
    Write-Log "Total Servers Processed: $($InventorySummary.TotalServers)" -Level "INFO"
    Write-Log "Total Software Packages: $($InventorySummary.TotalSoftwarePackages)" -Level "INFO"
    Write-Log "Total Patches/Updates: $($InventorySummary.TotalPatches)" -Level "INFO"
    Write-Log "Critical Agents Found: $($InventorySummary.CriticalAgentsFound)" -Level "INFO"
    Write-Log "Total Memory (All Servers): $($InventorySummary.TotalMemoryGB) GB" -Level "INFO"
    Write-Log "Total CPU Cores (All Servers): $($InventorySummary.TotalProcessorCores)" -Level "INFO"
    Write-Log "Unique Hardware Manufacturers: $($InventorySummary.UniqueManufacturers)" -Level "INFO"
    
    Write-Log "=== $ScriptName Completed Successfully ===" -Level "INFO"
    
    return @{
        DomainControllers = $DomainControllers
        SoftwareData = $AllSoftwareData
        PatchData = $AllPatchData
        OSData = $AllOSData
        HardwareData = $AllHardwareData
        Summary = $InventorySummary
        ExportPaths = $ExportPaths
    }
}

# Script entry point
try {
    Initialize-Logging
    $Results = Start-EnhancedInventoryCollection
    
    # Return results for potential pipeline usage
    return $Results
    
} catch {
    Write-Log "Critical error in main execution: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}

