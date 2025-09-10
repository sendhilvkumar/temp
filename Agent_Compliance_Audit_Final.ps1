# Enterprise Agent Compliance Monitor v3.0
# Comprehensive inventory collection for domain controllers
# Multi-domain support with separate report folders

# Script Parameters
param (
    [Parameter(Mandatory=$false)]
    [string[]]$Domains,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\Inventory",
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeCrossDomainSummary = $false,
    
    [Parameter(Mandatory=$false)]
    [bool]$GenerateDashboard = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$OpenDashboard = $true
)

# Script Variables
$ScriptVersion = "3.0"
$StartTime = Get-Date
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDate = Get-Date -Format "yyyyMMdd"
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$ComputerName = $env:COMPUTERNAME
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFolder = Join-Path -Path $OutputPath -ChildPath "Logs"
$ReportsFolder = Join-Path -Path $OutputPath -ChildPath "InventoryReports"
$DashboardFolder = Join-Path -Path $OutputPath -ChildPath "Dashboard"
$LogFile = Join-Path -Path $LogFolder -ChildPath "InventoryMonitor_$LogDate.log"

# Critical Agents to Monitor
$CriticalAgents = @(
    @{Name = "Netbackup"; ServiceNames = @("NetBackup Client Service", "nbclient", "NetBackup Legacy Client Service"); ProcessNames = @("nbclient.exe", "bpcd.exe"); RegistryPaths = @("HKLM:\SOFTWARE\Veritas\NetBackup\CurrentVersion", "HKLM:\SOFTWARE\Veritas\NetBackup") },
    @{Name = "Qualys"; ServiceNames = @("QualysAgent", "qualys-cloud-agent"); ProcessNames = @("QualysAgent.exe"); RegistryPaths = @("HKLM:\SOFTWARE\Qualys", "HKLM:\SOFTWARE\Qualys\QualysAgent") },
    @{Name = "Flexera"; ServiceNames = @("FlexNet Inventory Agent", "FlexeraInventoryAgent"); ProcessNames = @("FlexNetInventoryAgent.exe", "ndtrack.exe"); RegistryPaths = @("HKLM:\SOFTWARE\Flexera Software", "HKLM:\SOFTWARE\Wow6432Node\Flexera Software") },
    @{Name = "Defender"; ServiceNames = @("WinDefend", "WdNisSvc", "Sense"); ProcessNames = @("MsMpEng.exe", "MsSense.exe"); RegistryPaths = @("HKLM:\SOFTWARE\Microsoft\Windows Defender", "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection") },
    @{Name = "Defender for Identity"; ServiceNames = @("AATPSensor", "AATPSensorUpdater"); ProcessNames = @("Microsoft.Tri.Sensor.exe"); RegistryPaths = @("HKLM:\SOFTWARE\Microsoft\Azure Advanced Threat Protection", "HKLM:\SOFTWARE\Microsoft\Microsoft Defender for Identity") },
    @{Name = "Tripwire"; ServiceNames = @("TripwireServices", "TripwireAxonAgent"); ProcessNames = @("twagent.exe", "twdaemon.exe"); RegistryPaths = @("HKLM:\SOFTWARE\Tripwire", "HKLM:\SOFTWARE\Wow6432Node\Tripwire") }
)

# Create necessary folders
function Create-Folders {
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    
    if (-not (Test-Path -Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }
    
    if (-not (Test-Path -Path $ReportsFolder)) {
        New-Item -Path $ReportsFolder -ItemType Directory -Force | Out-Null
    }
    
    if ($GenerateDashboard -and (-not (Test-Path -Path $DashboardFolder))) {
        New-Item -Path $DashboardFolder -ItemType Directory -Force | Out-Null
    }
}

# Write colored output to console and log file
function Write-ColorOutput {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [string]$Color = "White",
        
        [Parameter(Mandatory=$false)]
        [string]$LogLevel = "INFO"
    )
    
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$TimeStamp] [$LogLevel] $Message"
    
    # Write to console with color
    Write-Host $LogMessage -ForegroundColor $Color
    
    # Write to log file
    Add-Content -Path $LogFile -Value $LogMessage
}

# Test connectivity to a remote server
function Test-RemoteConnectivity {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServerName
    )
    
    try {
        Write-ColorOutput "Testing connectivity to $ServerName..." -Color Cyan
        
        # Test if server responds to ping
        $PingResult = Test-Connection -ComputerName $ServerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        
        if ($PingResult) {
            Write-ColorOutput "Server $ServerName is reachable." -Color Green
            return $true
        } else {
            Write-ColorOutput "Server $ServerName is unreachable. Skipping." -Color Yellow -LogLevel "WARN"
            return $false
        }
    } catch {
        Write-ColorOutput "Error testing connectivity to $ServerName. $_" -Color Red -LogLevel "ERROR"
        return $false
    }
}

# Get domain controllers for a specific domain
function Get-DomainControllers {
    param (
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    
    $DomainControllers = @()
    
    try {
        # Try using Active Directory module first
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $DCs = Get-ADDomainController -Filter * -Server $DomainName -ErrorAction SilentlyContinue
            
            if ($DCs) {
                foreach ($DC in $DCs) {
                    $DomainControllers += [PSCustomObject]@{
                        Name = $DC.Name
                        HostName = $DC.HostName
                        IPv4Address = $DC.IPv4Address
                        Site = $DC.Site
                        OperatingSystem = $DC.OperatingSystem
                        OperatingSystemVersion = $DC.OperatingSystemVersion
                    }
                }
            }
        }
        
        # If no DCs found, try using .NET Directory Services
        if ($DomainControllers.Count -eq 0) {
            $Context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName)
            $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($Context)
            
            foreach ($DC in $Domain.DomainControllers) {
                $DomainControllers += [PSCustomObject]@{
                    Name = $DC.Name
                    HostName = $DC.Name
                    IPv4Address = [System.Net.Dns]::GetHostAddresses($DC.Name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -ExpandProperty IPAddressToString -First 1
                    Site = $DC.SiteName
                    OperatingSystem = "Unknown"
                    OperatingSystemVersion = "Unknown"
                }
            }
        }
        
        return $DomainControllers
    } catch {
        Write-ColorOutput "Error discovering domain controllers for domain $DomainName. $_" -Color Red -LogLevel "ERROR"
        return @()
    }
}

# Get software inventory from a server
function Get-SoftwareInventory {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServerName
    )
    
    $SoftwareList = @()
    
    try {
        # Get software from Win32_Product
        $Win32Products = Get-WmiObject -Class Win32_Product -ComputerName $ServerName -ErrorAction SilentlyContinue
        
        if ($Win32Products) {
            foreach ($Product in $Win32Products) {
                $SoftwareList += [PSCustomObject]@{
                    Name = $Product.Name
                    Version = $Product.Version
                    Publisher = $Product.Vendor
                    InstallDate = if ($Product.InstallDate) { 
                        [DateTime]::ParseExact($Product.InstallDate, "yyyyMMdd", $null).ToString("yyyy-MM-dd") 
                    } else { 
                        "Unknown" 
                    }
                    InstallLocation = $Product.InstallLocation
                    Source = "Win32_Product"
                }
            }
        }
        
        # Get software from registry (64-bit)
        $RegPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ServerName)
        $RegKey = $Reg.OpenSubKey($RegPath)
        
        if ($RegKey) {
            foreach ($SubKey in $RegKey.GetSubKeyNames()) {
                $ThisKey = $RegKey.OpenSubKey($SubKey)
                $DisplayName = $ThisKey.GetValue("DisplayName")
                
                if ($DisplayName) {
                    $SoftwareList += [PSCustomObject]@{
                        Name = $DisplayName
                        Version = $ThisKey.GetValue("DisplayVersion")
                        Publisher = $ThisKey.GetValue("Publisher")
                        InstallDate = if ($ThisKey.GetValue("InstallDate")) {
                            try {
                                [DateTime]::ParseExact($ThisKey.GetValue("InstallDate"), "yyyyMMdd", $null).ToString("yyyy-MM-dd")
                            } catch {
                                $ThisKey.GetValue("InstallDate")
                            }
                        } else {
                            "Unknown"
                        }
                        InstallLocation = $ThisKey.GetValue("InstallLocation")
                        Source = "Registry64"
                    }
                }
            }
        }
        
        # Get software from registry (32-bit)
        $RegPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        $RegKey = $Reg.OpenSubKey($RegPath)
        
        if ($RegKey) {
            foreach ($SubKey in $RegKey.GetSubKeyNames()) {
                $ThisKey = $RegKey.OpenSubKey($SubKey)
                $DisplayName = $ThisKey.GetValue("DisplayName")
                
                if ($DisplayName) {
                    $SoftwareList += [PSCustomObject]@{
                        Name = $DisplayName
                        Version = $ThisKey.GetValue("DisplayVersion")
                        Publisher = $ThisKey.GetValue("Publisher")
                        InstallDate = if ($ThisKey.GetValue("InstallDate")) {
                            try {
                                [DateTime]::ParseExact($ThisKey.GetValue("InstallDate"), "yyyyMMdd", $null).ToString("yyyy-MM-dd")
                            } catch {
                                $ThisKey.GetValue("InstallDate")
                            }
                        } else {
                            "Unknown"
                        }
                        InstallLocation = $ThisKey.GetValue("InstallLocation")
                        Source = "Registry32"
                    }
                }
            }
        }
        
        # Remove duplicates
        $SoftwareList = $SoftwareList | Sort-Object Name, Version -Unique
        
        return $SoftwareList
    } catch {
        Write-ColorOutput "Error collecting software inventory from $ServerName. $_" -Color Red -LogLevel "ERROR"
        return @()
    }
}

# Get patch inventory from a server
function Get-PatchInventory {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServerName
    )
    
    $PatchList = @()
    
    try {
        # Get hotfixes
        $Hotfixes = Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName $ServerName -ErrorAction SilentlyContinue
        
        if ($Hotfixes) {
            foreach ($Hotfix in $Hotfixes) {
                $PatchList += [PSCustomObject]@{
                    HotfixID = $Hotfix.HotfixID
                    Description = $Hotfix.Description
                    InstalledBy = $Hotfix.InstalledBy
                    InstallDate = if ($Hotfix.InstalledOn) { $Hotfix.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
                    Source = "Win32_QuickFixEngineering"
                }
            }
        }
        
        return $PatchList
    } catch {
        Write-ColorOutput "Error collecting patch inventory from $ServerName. $_" -Color Red -LogLevel "ERROR"
        return @()
    }
}

# Get system information from a server
function Get-SystemInformation {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServerName
    )
    
    try {
        # Get operating system information
        $OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ServerName -ErrorAction SilentlyContinue
        
        if ($OS) {
            $LastBootTime = [Management.ManagementDateTimeConverter]::ToDateTime($OS.LastBootUpTime)
            $Uptime = (Get-Date) - $LastBootTime
            $UptimeString = "{0} days, {1} hours, {2} minutes" -f $Uptime.Days, $Uptime.Hours, $Uptime.Minutes
            
            $TotalMemoryGB = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
            $FreeMemoryGB = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)
            $UsedMemoryGB = [math]::Round($TotalMemoryGB - $FreeMemoryGB, 2)
            $MemoryUsagePercent = [math]::Round(($UsedMemoryGB / $TotalMemoryGB) * 100, 2)
            
            $SystemInfo = [PSCustomObject]@{
                ComputerName = $ServerName
                OSName = $OS.Caption
                OSVersion = $OS.Version
                OSBuildNumber = $OS.BuildNumber
                OSArchitecture = $OS.OSArchitecture
                OSLanguage = $OS.OSLanguage
                InstallDate = [Management.ManagementDateTimeConverter]::ToDateTime($OS.InstallDate).ToString("yyyy-MM-dd")
                LastBootTime = $LastBootTime.ToString("yyyy-MM-dd HH:mm:ss")
                Uptime = $UptimeString
                TotalMemoryGB = $TotalMemoryGB
                UsedMemoryGB = $UsedMemoryGB
                FreeMemoryGB = $FreeMemoryGB
                MemoryUsagePercent = $MemoryUsagePercent
                SystemDirectory = $OS.SystemDirectory
                WindowsDirectory = $OS.WindowsDirectory
                BootDevice = $OS.BootDevice
                SystemDrive = $OS.SystemDrive
                Domain = $OS.Domain
                TimeZone = $OS.CurrentTimeZone
            }
            
            return $SystemInfo
        } else {
            Write-ColorOutput "Could not retrieve system information from $ServerName." -Color Yellow -LogLevel "WARN"
            return $null
        }
    } catch {
        Write-ColorOutput "Error collecting system information from $ServerName. $_" -Color Red -LogLevel "ERROR"
        return $null
    }
}

# Get hardware information from a server
function Get-HardwareInformation {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServerName
    )
    
    try {
        # Get computer system information
        $ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ServerName -ErrorAction SilentlyContinue
        $BIOS = Get-WmiObject -Class Win32_BIOS -ComputerName $ServerName -ErrorAction SilentlyContinue
        $Processor = Get-WmiObject -Class Win32_Processor -ComputerName $ServerName -ErrorAction SilentlyContinue | Select-Object -First 1
        $PhysicalMemory = Get-WmiObject -Class Win32_PhysicalMemory -ComputerName $ServerName -ErrorAction SilentlyContinue
        $DiskDrives = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $ServerName -Filter "DriveType=3" -ErrorAction SilentlyContinue
        $NetworkAdapters = Get-WmiObject -Class Win32_NetworkAdapter -ComputerName $ServerName -Filter "PhysicalAdapter=True AND MACAddress IS NOT NULL" -ErrorAction SilentlyContinue
        
        if ($ComputerSystem) {
            # Calculate total memory from physical memory modules
            $TotalMemoryGB = 0
            $MemorySlots = 0
            $MemoryType = "Unknown"
            $MemorySpeed = "Unknown"
            
            if ($PhysicalMemory) {
                $TotalMemoryGB = [math]::Round(($PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
                $MemorySlots = $PhysicalMemory.Count
                $MemoryType = $PhysicalMemory[0].SMBIOSMemoryType
                $MemorySpeed = $PhysicalMemory[0].Speed
            }
            
            # Calculate total disk space
            $TotalDiskSpaceGB = 0
            $UsedDiskSpaceGB = 0
            $DiskInfo = @()
            
            if ($DiskDrives) {
                foreach ($Disk in $DiskDrives) {
                    $SizeGB = [math]::Round($Disk.Size / 1GB, 2)
                    $FreeSpaceGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
                    $UsedSpaceGB = [math]::Round($SizeGB - $FreeSpaceGB, 2)
                    $UsedPercent = [math]::Round(($UsedSpaceGB / $SizeGB) * 100, 2)
                    
                    $TotalDiskSpaceGB += $SizeGB
                    $UsedDiskSpaceGB += $UsedSpaceGB
                    
                    $DiskInfo += [PSCustomObject]@{
                        Drive = $Disk.DeviceID
                        SizeGB = $SizeGB
                        FreeSpaceGB = $FreeSpaceGB
                        UsedSpaceGB = $UsedSpaceGB
                        UsedPercent = $UsedPercent
                    }
                }
            }
            
            # Create hardware information object
            $HardwareInfo = [PSCustomObject]@{
                ComputerName = $ServerName
                Manufacturer = $ComputerSystem.Manufacturer
                Model = $ComputerSystem.Model
                SystemFamily = $ComputerSystem.SystemFamily
                SystemSKU = $ComputerSystem.SystemSKUNumber
                SerialNumber = $BIOS.SerialNumber
                BIOSVersion = $BIOS.SMBIOSBIOSVersion
                BIOSReleaseDate = if ($BIOS.ReleaseDate) { [Management.ManagementDateTimeConverter]::ToDateTime($BIOS.ReleaseDate).ToString("yyyy-MM-dd") } else { "Unknown" }
                BIOSManufacturer = $BIOS.Manufacturer
                ProcessorName = $Processor.Name
                ProcessorManufacturer = $Processor.Manufacturer
                ProcessorCores = $Processor.NumberOfCores
                ProcessorLogicalProcessors = $Processor.NumberOfLogicalProcessors
                ProcessorClockSpeed = $Processor.MaxClockSpeed
                ProcessorArchitecture = $Processor.Architecture
                TotalMemoryGB = $TotalMemoryGB
                MemorySlots = $MemorySlots
                MemoryType = $MemoryType
                MemorySpeed = $MemorySpeed
                TotalDiskSpaceGB = $TotalDiskSpaceGB
                UsedDiskSpaceGB = $UsedDiskSpaceGB
                DiskUsagePercent = if ($TotalDiskSpaceGB -gt 0) { [math]::Round(($UsedDiskSpaceGB / $TotalDiskSpaceGB) * 100, 2) } else { 0 }
                NetworkAdapters = ($NetworkAdapters | Select-Object -Property Name, MACAddress, AdapterType | ConvertTo-Json -Compress)
                DiskDrives = ($DiskInfo | ConvertTo-Json -Compress)
            }
            
            return $HardwareInfo
        } else {
            Write-ColorOutput "Could not retrieve hardware information from $ServerName." -Color Yellow -LogLevel "WARN"
            return $null
        }
    } catch {
        Write-ColorOutput "Error collecting hardware information from $ServerName. $_" -Color Red -LogLevel "ERROR"
        return $null
    }
}

# Check critical agent status on a server
function Get-CriticalAgentStatus {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServerName,
        
        [Parameter(Mandatory=$true)]
        [array]$SoftwareInventory
    )
    
    $AgentStatus = @()
    
    try {
        foreach ($Agent in $CriticalAgents) {
            $Status = "Not Installed"
            $Version = "N/A"
            $InstallDate = "N/A"
            $InstallLocation = "N/A"
            $IsRunning = $false
            $ServiceStatus = "Not Found"
            $RegistryFound = $false
            
            # Check if agent is installed based on software inventory
            $AgentSoftware = $SoftwareInventory | Where-Object { $_.Name -like "*$($Agent.Name)*" } | Select-Object -First 1
            
            if ($AgentSoftware) {
                $Status = "Installed"
                $Version = $AgentSoftware.Version
                $InstallDate = $AgentSoftware.InstallDate
                $InstallLocation = $AgentSoftware.InstallLocation
            }
            
            # Check if agent service is running
            foreach ($ServiceName in $Agent.ServiceNames) {
                $Service = Get-Service -ComputerName $ServerName -Name $ServiceName -ErrorAction SilentlyContinue
                
                if ($Service) {
                    $ServiceStatus = $Service.Status
                    
                    if ($Service.Status -eq "Running") {
                        $IsRunning = $true
                        break
                    }
                }
            }
            
            # Check if agent process is running
            if (-not $IsRunning) {
                foreach ($ProcessName in $Agent.ProcessNames) {
                    $Process = Get-Process -ComputerName $ServerName -Name ($ProcessName -replace '\.exe$', '') -ErrorAction SilentlyContinue
                    
                    if ($Process) {
                        $IsRunning = $true
                        break
                    }
                }
            }
            
            # Check registry for agent information
            foreach ($RegistryPath in $Agent.RegistryPaths) {
                try {
                    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ServerName)
                    $RegPath = $RegistryPath -replace 'HKLM:\\', ''
                    $RegKey = $Reg.OpenSubKey($RegPath)
                    
                    if ($RegKey) {
                        $RegistryFound = $true
                        
                        # Try to get version from registry if not found in software inventory
                        if ($Version -eq "N/A") {
                            $RegVersion = $RegKey.GetValue("Version")
                            if ($RegVersion) {
                                $Version = $RegVersion
                            }
                        }
                        
                        break
                    }
                } catch {
                    # Registry access error, continue to next path
                    continue
                }
            }
            
            # Determine overall health status
            $HealthStatus = "Critical"
            
            if ($Status -eq "Installed") {
                if ($IsRunning) {
                    $HealthStatus = "Healthy"
                } else {
                    $HealthStatus = "Warning"
                }
            }
            
            # Add agent status to results
            $AgentStatus += [PSCustomObject]@{
                AgentName = $Agent.Name
                Status = $Status
                Version = $Version
                InstallDate = $InstallDate
                InstallLocation = $InstallLocation
                IsRunning = $IsRunning
                ServiceStatus = $ServiceStatus
                RegistryFound = $RegistryFound
                HealthStatus = $HealthStatus
                LastChecked = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
        
        return $AgentStatus
    } catch {
        Write-ColorOutput "Error checking critical agent status on $ServerName. $_" -Color Red -LogLevel "ERROR"
        return @()
    }
}

# Process a single domain
function Process-Domain {
    param (
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    
    Write-ColorOutput "=== Starting domain controller discovery..." -Color Green
    Write-ColorOutput "Current domain: $DomainName" -Color Green
    
    # Create domain-specific folder
    $DomainFolder = Join-Path -Path $ReportsFolder -ChildPath $DomainName
    if (-not (Test-Path -Path $DomainFolder)) {
        New-Item -Path $DomainFolder -ItemType Directory -Force | Out-Null
    }
    
    # Get domain controllers
    $DomainControllers = Get-DomainControllers -DomainName $DomainName
    Write-ColorOutput "Discovered $($DomainControllers.Count) domain controllers" -Color Green
    
    if ($DomainControllers.Count -eq 0) {
        Write-ColorOutput "No domain controllers found for domain $DomainName. Skipping." -Color Yellow -LogLevel "WARN"
        return $null
    }
    
    # Export domain controllers to CSV
    $DCsExportPath = Join-Path -Path $DomainFolder -ChildPath "DomainControllers_$Timestamp.csv"
    $DomainControllers | Export-Csv -Path $DCsExportPath -NoTypeInformation
    Write-ColorOutput "Domain Controllers exported to: $DCsExportPath" -Color Green
    
    # Initialize data collections
    $AllSoftware = @()
    $AllPatches = @()
    $AllSystemInfo = @()
    $AllHardwareInfo = @()
    $AllCriticalAgents = @()
    $ServersProcessed = 0
    $TotalServers = $DomainControllers.Count
    
    Write-ColorOutput "Starting inventory collection for $TotalServers servers..." -Color Green
    
    # Process each domain controller
    foreach ($DC in $DomainControllers) {
        $ServerName = $DC.Name
        if ($ServerName -notlike "*.*") {
            $ServerName = "$ServerName.$DomainName"
        }
        
        Write-ColorOutput "Processing server: $ServerName" -Color Cyan
        
        # Test connectivity
        $IsReachable = Test-RemoteConnectivity -ServerName $ServerName
        
        if (-not $IsReachable) {
            Write-ColorOutput "Server $ServerName is unreachable. Skipping." -Color Yellow -LogLevel "WARN"
            continue
        }
        
        # Get software inventory
        Write-ColorOutput "Collecting software inventory..." -Color Cyan
        $SoftwareInventory = Get-SoftwareInventory -ServerName $ServerName
        
        foreach ($Software in $SoftwareInventory) {
            $AllSoftware += [PSCustomObject]@{
                ServerName = $ServerName
                Name = $Software.Name
                Version = $Software.Version
                Publisher = $Software.Publisher
                InstallDate = $Software.InstallDate
                InstallLocation = $Software.InstallLocation
                Source = $Software.Source
            }
        }
        
        # Get patch inventory
        Write-ColorOutput "Collecting patch inventory..." -Color Cyan
        $PatchInventory = Get-PatchInventory -ServerName $ServerName
        
        foreach ($Patch in $PatchInventory) {
            $AllPatches += [PSCustomObject]@{
                ServerName = $ServerName
                HotfixID = $Patch.HotfixID
                Description = $Patch.Description
                InstalledBy = $Patch.InstalledBy
                InstallDate = $Patch.InstallDate
                Source = $Patch.Source
            }
        }
        
        # Get system information
        Write-ColorOutput "Collecting system information..." -Color Cyan
        $SystemInfo = Get-SystemInformation -ServerName $ServerName
        
        if ($SystemInfo) {
            $AllSystemInfo += $SystemInfo
        }
        
        # Get hardware information
        Write-ColorOutput "Collecting hardware information..." -Color Cyan
        $HardwareInfo = Get-HardwareInformation -ServerName $ServerName
        
        if ($HardwareInfo) {
            $AllHardwareInfo += $HardwareInfo
        }
        
        # Get critical agent status
        Write-ColorOutput "Checking critical agent status..." -Color Cyan
        $CriticalAgentStatus = Get-CriticalAgentStatus -ServerName $ServerName -SoftwareInventory $SoftwareInventory
        
        foreach ($Agent in $CriticalAgentStatus) {
            $AllCriticalAgents += [PSCustomObject]@{
                ServerName = $ServerName
                AgentName = $Agent.AgentName
                Status = $Agent.Status
                Version = $Agent.Version
                InstallDate = $Agent.InstallDate
                IsRunning = $Agent.IsRunning
                ServiceStatus = $Agent.ServiceStatus
                RegistryFound = $Agent.RegistryFound
                HealthStatus = $Agent.HealthStatus
                LastChecked = $Agent.LastChecked
            }
        }
        
        $ServersProcessed++
        Write-ColorOutput "Completed processing server $ServerName ($ServersProcessed of $TotalServers)" -Color Green
    }
    
    # Export inventory data to CSV files
    Write-ColorOutput "Exporting inventory data..." -Color Green
    
    $SoftwareExportPath = Join-Path -Path $DomainFolder -ChildPath "SoftwareInventory_$Timestamp.csv"
    $AllSoftware | Export-Csv -Path $SoftwareExportPath -NoTypeInformation
    Write-ColorOutput "Software inventory exported to: $SoftwareExportPath" -Color Green
    
    $PatchExportPath = Join-Path -Path $DomainFolder -ChildPath "PatchInventory_$Timestamp.csv"
    $AllPatches | Export-Csv -Path $PatchExportPath -NoTypeInformation
    Write-ColorOutput "Patch inventory exported to: $PatchExportPath" -Color Green
    
    $SystemInfoExportPath = Join-Path -Path $DomainFolder -ChildPath "SystemInformation_$Timestamp.csv"
    $AllSystemInfo | Export-Csv -Path $SystemInfoExportPath -NoTypeInformation
    Write-ColorOutput "System information exported to: $SystemInfoExportPath" -Color Green
    
    $HardwareInfoExportPath = Join-Path -Path $DomainFolder -ChildPath "HardwareInfo_$Timestamp.csv"
    $AllHardwareInfo | Export-Csv -Path $HardwareInfoExportPath -NoTypeInformation
    Write-ColorOutput "Hardware information exported to: $HardwareInfoExportPath" -Color Green
    
    $CriticalAgentsExportPath = Join-Path -Path $DomainFolder -ChildPath "CriticalAgents_$Timestamp.csv"
    $AllCriticalAgents | Export-Csv -Path $CriticalAgentsExportPath -NoTypeInformation
    Write-ColorOutput "Critical agents exported to: $CriticalAgentsExportPath" -Color Green
    
    # Calculate summary metrics
    $TotalSoftwarePackages = ($AllSoftware | Select-Object -Property Name, Version -Unique).Count
    $TotalPatches = ($AllPatches | Select-Object -Property HotfixID -Unique).Count
    $TotalCriticalAgents = $CriticalAgents.Count * $ServersProcessed
    $HealthyCriticalAgents = ($AllCriticalAgents | Where-Object { $_.HealthStatus -eq "Healthy" }).Count
    $CriticalAgentCompliance = if ($TotalCriticalAgents -gt 0) { [math]::Round(($HealthyCriticalAgents / $TotalCriticalAgents) * 100, 2) } else { 0 }
    
    $RecentInstalls = ($AllSoftware | Where-Object { 
        try { 
            [DateTime]::ParseExact($_.InstallDate, "yyyy-MM-dd", $null) -gt (Get-Date).AddDays(-30) 
        } catch { 
            $false 
        } 
    }).Count
    
    $RecentPatches = ($AllPatches | Where-Object { 
        try { 
            [DateTime]::ParseExact($_.InstallDate, "yyyy-MM-dd", $null) -gt (Get-Date).AddDays(-30) 
        } catch { 
            $false 
        } 
    }).Count
    
    $UniquePublishers = ($AllSoftware | Select-Object -Property Publisher -Unique).Count
    
    # Create summary object
    $Summary = [PSCustomObject]@{
        DomainName = $DomainName
        ServersProcessed = $ServersProcessed
        TotalSoftwarePackages = $TotalSoftwarePackages
        TotalPatches = $TotalPatches
        CriticalAgentCompliance = $CriticalAgentCompliance
        RecentInstalls = $RecentInstalls
        RecentPatches = $RecentPatches
        UniquePublishers = $UniquePublishers
        CollectionDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    
    # Export summary to CSV
    $SummaryExportPath = Join-Path -Path $DomainFolder -ChildPath "InventorySummary_$Timestamp.csv"
    $Summary | Export-Csv -Path $SummaryExportPath -NoTypeInformation
    Write-ColorOutput "Inventory summary exported to: $SummaryExportPath" -Color Green
    
    # Create JSON data for dashboard
    $JsonData = [PSCustomObject]@{
        DomainName = $DomainName
        CollectionDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Summary = $Summary
        DomainControllers = $DomainControllers
        SoftwareData = $AllSoftware
        PatchData = $AllPatches
        SystemData = $AllSystemInfo
        HardwareData = $AllHardwareInfo
        CriticalAgents = $AllCriticalAgents
    }
    
    # Export JSON data
    $JsonExportPath = Join-Path -Path $DomainFolder -ChildPath "InventoryData_$Timestamp.json"
    $JsonData | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonExportPath -Encoding UTF8
    Write-ColorOutput "JSON data exported to: $JsonExportPath" -Color Green
    
    Write-ColorOutput "=== INVENTORY COLLECTION SUMMARY ===" -Color Green
    Write-ColorOutput "Total Servers Processed: $ServersProcessed" -Color Green
    Write-ColorOutput "Total Software Packages: $TotalSoftwarePackages" -Color Green
    Write-ColorOutput "Total Patches/Updates: $TotalPatches" -Color Green
    Write-ColorOutput "Critical Agent Compliance: $CriticalAgentCompliance%" -Color Green
    Write-ColorOutput "Unique Publishers: $UniquePublishers" -Color Green
    Write-ColorOutput "Recent Installs (30 days): $RecentInstalls" -Color Green
    Write-ColorOutput "Recent Patches (30 days): $RecentPatches" -Color Green
    
    return $JsonData
}

# Generate HTML dashboard
function Generate-Dashboard {
    param (
        [Parameter(Mandatory=$true)]
        [array]$DomainData
    )
    
    Write-ColorOutput "Generating HTML dashboard..." -Color Green
    
    # Convert domain data to JSON for embedding in HTML
    # Fix: Use proper string escaping for JSON in HTML
    $DomainDataJson = $DomainData | ConvertTo-Json -Depth 5 -Compress
    $DomainDataJson = $DomainDataJson.Replace('"', '\"').Replace("`n", " ").Replace("`r", " ")
    
    # Dashboard HTML template
    $DashboardHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Agent Compliance Monitor</title>
    <style>
        /* Reset and base styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background-color: #f0f0f0;
            color: #333;
            line-height: 1.6;
        }
        
        /* Header styles */
        header {
            background-color: #0078d4;
            color: white;
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        header h1 {
            font-size: 1.5rem;
            font-weight: 500;
        }
        
        .header-right {
            display: flex;
            align-items: center;
        }
        
        .domain-selector {
            margin-right: 1rem;
            padding: 0.5rem;
            border: none;
            border-radius: 4px;
            background-color: white;
            color: #333;
            font-size: 0.9rem;
        }
        
        .last-updated {
            font-size: 0.8rem;
            opacity: 0.9;
        }
        
        /* Navigation styles */
        nav {
            background-color: white;
            border-bottom: 1px solid #ddd;
        }
        
        .nav-tabs {
            display: flex;
            list-style: none;
            overflow-x: auto;
        }
        
        .nav-tabs li {
            padding: 1rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            white-space: nowrap;
        }
        
        .nav-tabs li.active {
            border-bottom: 2px solid #0078d4;
            color: #0078d4;
        }
        
        .nav-tabs li:hover:not(.active) {
            background-color: #f5f5f5;
        }
        
        /* Content styles */
        .content {
            padding: 1rem;
        }
        
        .tab-content {
            display: none;
            background-color: white;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        .tab-content.active {
            display: block;
        }
        
        h2 {
            font-size: 1.2rem;
            margin-bottom: 1rem;
            color: #333;
            font-weight: 500;
        }
        
        /* Metrics styles */
        .metrics-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .metric-card {
            background-color: white;
            border-radius: 4px;
            padding: 1rem;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        .metric-value {
            font-size: 2rem;
            font-weight: 500;
            color: #0078d4;
            margin-bottom: 0.5rem;
        }
        
        .metric-label {
            font-size: 0.9rem;
            color: #666;
        }
        
        /* Chart styles */
        .charts-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .chart-container {
            background-color: white;
            border-radius: 4px;
            padding: 1rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            height: 300px;
            position: relative;
        }
        
        /* Table styles */
        .table-container {
            overflow-x: auto;
            margin-bottom: 1rem;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background-color: #f5f5f5;
            font-weight: 500;
        }
        
        tr:hover {
            background-color: #f9f9f9;
        }
        
        /* Status indicators */
        .status-healthy {
            color: #107c10;
            font-weight: 500;
        }
        
        .status-warning {
            color: #ff8c00;
            font-weight: 500;
        }
        
        .status-critical {
            color: #d13438;
            font-weight: 500;
        }
        
        /* Search and filter */
        .filter-container {
            margin-bottom: 1rem;
            display: flex;
            gap: 0.5rem;
        }
        
        .filter-input {
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            flex-grow: 1;
        }
        
        /* Responsive styles */
        @media (max-width: 768px) {
            .charts-container {
                grid-template-columns: 1fr;
            }
            
            .metrics-container {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        /* Loading spinner */
        .loading-spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-left-color: #0078d4;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* Donut chart specific styles */
        .donut-chart {
            position: relative;
            width: 200px;
            height: 200px;
            margin: 0 auto;
        }
        
        .donut-hole {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }
        
        .donut-percent {
            font-size: 2rem;
            font-weight: 500;
            color: #0078d4;
        }
        
        .donut-label {
            font-size: 0.9rem;
            color: #666;
        }
    </style>
</head>
<body>
    <header>
        <h1>Enterprise Agent Compliance Monitor</h1>
        <div class="header-right">
            <select id="domainSelector" class="domain-selector">
                <!-- Domains will be populated by JavaScript -->
            </select>
            <div class="last-updated" id="lastUpdated">Last updated: --</div>
        </div>
    </header>
    
    <nav>
        <ul class="nav-tabs">
            <li class="active" data-tab="executive-summary">Executive Summary</li>
            <li data-tab="software-inventory">Software Inventory</li>
            <li data-tab="patch-management">Patch Management</li>
            <li data-tab="system-information">System Information</li>
            <li data-tab="hardware-inventory">Hardware Inventory</li>
            <li data-tab="domain-controllers">Domain Controllers</li>
        </ul>
    </nav>
    
    <div class="content">
        <!-- Executive Summary Tab -->
        <div id="executive-summary" class="tab-content active">
            <h2>Compliance Overview</h2>
            <div class="metrics-container">
                <div class="metric-card">
                    <div class="metric-value" id="compliance-percentage">--</div>
                    <div class="metric-label">Critical agents properly installed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="domain-controllers-count">--</div>
                    <div class="metric-label">Domain controllers</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="software-count">--</div>
                    <div class="metric-label">Total installed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="patch-count">--</div>
                    <div class="metric-label">Total installed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="recent-installs">--</div>
                    <div class="metric-label">Last 30 days</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="recent-patches">--</div>
                    <div class="metric-label">Last 30 days</div>
                </div>
            </div>
            
            <div class="charts-container">
                <div class="chart-container">
                    <h2>Compliance Status</h2>
                    <div id="compliance-chart" class="donut-chart">
                        <canvas id="compliance-canvas" width="200" height="200"></canvas>
                        <div class="donut-hole">
                            <div class="donut-percent" id="donut-percent">--</div>
                            <div class="donut-label">Compliance</div>
                        </div>
                    </div>
                </div>
                <div class="chart-container">
                    <h2>Operating System Distribution</h2>
                    <canvas id="os-distribution-chart"></canvas>
                </div>
            </div>
            
            <h2>Critical Agents Status</h2>
            <div class="table-container">
                <table id="critical-agents-table">
                    <thead>
                        <tr>
                            <th>Agent Name</th>
                            <th>Compliance</th>
                            <th>Installed</th>
                            <th>Running</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Data will be populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Software Inventory Tab -->
        <div id="software-inventory" class="tab-content">
            <h2>Software Inventory</h2>
            <div class="filter-container">
                <input type="text" id="software-filter" class="filter-input" placeholder="Filter software...">
            </div>
            <div class="table-container">
                <table id="software-table">
                    <thead>
                        <tr>
                            <th>Server Name</th>
                            <th>Software Name</th>
                            <th>Version</th>
                            <th>Publisher</th>
                            <th>Install Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Data will be populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Patch Management Tab -->
        <div id="patch-management" class="tab-content">
            <h2>Patch Inventory</h2>
            <div class="filter-container">
                <input type="text" id="patch-filter" class="filter-input" placeholder="Filter patches...">
            </div>
            <div class="table-container">
                <table id="patch-table">
                    <thead>
                        <tr>
                            <th>Server Name</th>
                            <th>Hotfix ID</th>
                            <th>Description</th>
                            <th>Installed By</th>
                            <th>Install Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Data will be populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- System Information Tab -->
        <div id="system-information" class="tab-content">
            <h2>System Information</h2>
            <div class="filter-container">
                <input type="text" id="system-filter" class="filter-input" placeholder="Filter servers...">
            </div>
            <div class="table-container">
                <table id="system-table">
                    <thead>
                        <tr>
                            <th>Server Name</th>
                            <th>OS Name</th>
                            <th>OS Version</th>
                            <th>Install Date</th>
                            <th>Last Boot Time</th>
                            <th>Uptime</th>
                            <th>Memory Usage</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Data will be populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Hardware Inventory Tab -->
        <div id="hardware-inventory" class="tab-content">
            <h2>Hardware Inventory</h2>
            <div class="filter-container">
                <input type="text" id="hardware-filter" class="filter-input" placeholder="Filter servers...">
            </div>
            <div class="table-container">
                <table id="hardware-table">
                    <thead>
                        <tr>
                            <th>Server Name</th>
                            <th>Manufacturer</th>
                            <th>Model</th>
                            <th>Processor</th>
                            <th>Cores</th>
                            <th>Memory (GB)</th>
                            <th>Disk Space (GB)</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Data will be populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Domain Controllers Tab -->
        <div id="domain-controllers" class="tab-content">
            <h2>Domain Controllers</h2>
            <div class="filter-container">
                <input type="text" id="dc-filter" class="filter-input" placeholder="Filter domain controllers...">
            </div>
            <div class="table-container">
                <table id="dc-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>FQDN</th>
                            <th>IP Address</th>
                            <th>Site</th>
                            <th>Operating System</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Data will be populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script>
        // Dashboard data - properly escaped JSON string
        const dashboardData = JSON.parse("$DomainDataJson");
        
        // Current domain
        let currentDomain = '';
        
        // Initialize the dashboard
        function initDashboard() {
            // Populate domain selector
            const domainSelector = document.getElementById('domainSelector');
            
            if (dashboardData && dashboardData.length > 0) {
                dashboardData.forEach(domain => {
                    const option = document.createElement('option');
                    option.value = domain.DomainName;
                    option.textContent = domain.DomainName;
                    domainSelector.appendChild(option);
                });
                
                // Set current domain to first domain
                currentDomain = dashboardData[0].DomainName;
                domainSelector.value = currentDomain;
                
                // Load data for current domain
                loadDomainData(currentDomain);
                
                // Add event listener for domain change
                domainSelector.addEventListener('change', function() {
                    currentDomain = this.value;
                    loadDomainData(currentDomain);
                });
            } else {
                // No data available
                const option = document.createElement('option');
                option.value = '';
                option.textContent = 'No domains available';
                domainSelector.appendChild(option);
                
                document.getElementById('lastUpdated').textContent = 'Last updated: No data';
            }
            
            // Add event listeners for tab switching
            const tabLinks = document.querySelectorAll('.nav-tabs li');
            tabLinks.forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabId = this.getAttribute('data-tab');
                    
                    // Remove active class from all tabs
                    tabLinks.forEach(t => t.classList.remove('active'));
                    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
                    
                    // Add active class to clicked tab
                    this.classList.add('active');
                    document.getElementById(tabId).classList.add('active');
                });
            });
            
            // Add event listeners for filters
            document.getElementById('software-filter').addEventListener('input', filterSoftwareTable);
            document.getElementById('patch-filter').addEventListener('input', filterPatchTable);
            document.getElementById('system-filter').addEventListener('input', filterSystemTable);
            document.getElementById('hardware-filter').addEventListener('input', filterHardwareTable);
            document.getElementById('dc-filter').addEventListener('input', filterDCTable);
        }
        
        // Load data for a specific domain
        function loadDomainData(domainName) {
            const domainData = dashboardData.find(d => d.DomainName === domainName);
            
            if (!domainData) {
                console.error('Domain data not found for:', domainName);
                return;
            }
            
            // Update last updated timestamp
            document.getElementById('lastUpdated').textContent = `Last updated: ${domainData.CollectionDate}`;
            
            // Update executive summary metrics
            document.getElementById('compliance-percentage').textContent = `${domainData.Summary.CriticalAgentCompliance}%`;
            document.getElementById('domain-controllers-count').textContent = domainData.Summary.ServersProcessed;
            document.getElementById('software-count').textContent = domainData.Summary.TotalSoftwarePackages;
            document.getElementById('patch-count').textContent = domainData.Summary.TotalPatches;
            document.getElementById('recent-installs').textContent = domainData.Summary.RecentInstalls;
            document.getElementById('recent-patches').textContent = domainData.Summary.RecentPatches;
            
            // Update donut chart
            document.getElementById('donut-percent').textContent = `${domainData.Summary.CriticalAgentCompliance}%`;
            drawDonutChart('compliance-canvas', domainData.Summary.CriticalAgentCompliance);
            
            // Update OS distribution chart
            drawOSDistributionChart('os-distribution-chart', domainData.SystemData);
            
            // Update critical agents table
            updateCriticalAgentsTable(domainData.CriticalAgents);
            
            // Update software inventory table
            updateSoftwareTable(domainData.SoftwareData);
            
            // Update patch inventory table
            updatePatchTable(domainData.PatchData);
            
            // Update system information table
            updateSystemTable(domainData.SystemData);
            
            // Update hardware inventory table
            updateHardwareTable(domainData.HardwareData);
            
            // Update domain controllers table
            updateDCTable(domainData.DomainControllers);
        }
        
        // Draw donut chart
        function drawDonutChart(canvasId, compliancePercentage) {
            const canvas = document.getElementById(canvasId);
            const ctx = canvas.getContext('2d');
            const centerX = canvas.width / 2;
            const centerY = canvas.height / 2;
            const radius = 80;
            const innerRadius = 50;
            const compliantAngle = (compliancePercentage / 100) * 2 * Math.PI;
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Draw non-compliant portion (red)
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
            ctx.fillStyle = '#d13438';
            ctx.fill();
            
            // Draw compliant portion (green)
            ctx.beginPath();
            ctx.moveTo(centerX, centerY);
            ctx.arc(centerX, centerY, radius, -Math.PI / 2, compliantAngle - Math.PI / 2);
            ctx.lineTo(centerX, centerY);
            ctx.fillStyle = '#107c10';
            ctx.fill();
            
            // Draw inner circle (white)
            ctx.beginPath();
            ctx.arc(centerX, centerY, innerRadius, 0, 2 * Math.PI);
            ctx.fillStyle = 'white';
            ctx.fill();
        }
        
        // Draw OS distribution chart
        function drawOSDistributionChart(canvasId, systemData) {
            const canvas = document.getElementById(canvasId);
            const ctx = canvas.getContext('2d');
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Count OS versions
            const osCount = {};
            systemData.forEach(system => {
                const osName = system.OSName || 'Unknown';
                osCount[osName] = (osCount[osName] || 0) + 1;
            });
            
            // Convert to array for sorting
            const osData = Object.entries(osCount).map(([name, count]) => ({ name, count }));
            osData.sort((a, b) => b.count - a.count);
            
            // Chart dimensions
            const chartWidth = canvas.width - 60;
            const chartHeight = canvas.height - 60;
            const barWidth = Math.min(40, chartWidth / osData.length - 10);
            const maxCount = Math.max(...osData.map(os => os.count));
            
            // Draw axes
            ctx.beginPath();
            ctx.moveTo(40, 20);
            ctx.lineTo(40, chartHeight + 20);
            ctx.lineTo(chartWidth + 40, chartHeight + 20);
            ctx.strokeStyle = '#666';
            ctx.stroke();
            
            // Draw bars
            osData.forEach((os, index) => {
                const x = 60 + index * (chartWidth / osData.length);
                const barHeight = (os.count / maxCount) * chartHeight;
                const y = chartHeight + 20 - barHeight;
                
                // Draw bar
                ctx.fillStyle = '#0078d4';
                ctx.fillRect(x, y, barWidth, barHeight);
                
                // Draw label
                ctx.fillStyle = '#333';
                ctx.font = '10px Segoe UI';
                ctx.textAlign = 'center';
                
                // Truncate long OS names
                let displayName = os.name;
                if (displayName.length > 15) {
                    displayName = displayName.substring(0, 12) + '...';
                }
                
                ctx.fillText(displayName, x + barWidth / 2, chartHeight + 35);
                
                // Draw count
                ctx.fillText(os.count.toString(), x + barWidth / 2, y - 5);
            });
            
            // Draw y-axis labels
            ctx.fillStyle = '#666';
            ctx.font = '10px Segoe UI';
            ctx.textAlign = 'right';
            
            // Draw y-axis label (Count)
            ctx.save();
            ctx.translate(15, chartHeight / 2 + 20);
            ctx.rotate(-Math.PI / 2);
            ctx.textAlign = 'center';
            ctx.fillText('Count', 0, 0);
            ctx.restore();
        }
        
        // Update critical agents table
        function updateCriticalAgentsTable(agentData) {
            const table = document.getElementById('critical-agents-table').getElementsByTagName('tbody')[0];
            table.innerHTML = '';
            
            // Group by agent name
            const agentGroups = {};
            agentData.forEach(agent => {
                if (!agentGroups[agent.AgentName]) {
                    agentGroups[agent.AgentName] = [];
                }
                agentGroups[agent.AgentName].push(agent);
            });
            
            // Calculate stats for each agent
            Object.entries(agentGroups).forEach(([agentName, agents]) => {
                const totalServers = agents.length;
                const installedCount = agents.filter(a => a.Status === 'Installed').length;
                const runningCount = agents.filter(a => a.IsRunning).length;
                const healthyCount = agents.filter(a => a.HealthStatus === 'Healthy').length;
                
                const compliancePercent = Math.round((healthyCount / totalServers) * 100);
                const installedPercent = Math.round((installedCount / totalServers) * 100);
                const runningPercent = Math.round((runningCount / totalServers) * 100);
                
                let statusClass = 'status-critical';
                if (compliancePercent >= 90) {
                    statusClass = 'status-healthy';
                } else if (compliancePercent >= 70) {
                    statusClass = 'status-warning';
                }
                
                const row = table.insertRow();
                row.innerHTML = `
                    <td>${agentName}</td>
                    <td class="${statusClass}">${compliancePercent}%</td>
                    <td>${installedPercent}%</td>
                    <td>${runningPercent}%</td>
                    <td class="${statusClass}">${healthyCount} of ${totalServers} healthy</td>
                `;
            });
        }
        
        // Update software inventory table
        function updateSoftwareTable(softwareData) {
            const table = document.getElementById('software-table').getElementsByTagName('tbody')[0];
            table.innerHTML = '';
            
            // Sort by server name and software name
            softwareData.sort((a, b) => {
                if (a.ServerName === b.ServerName) {
                    return a.Name.localeCompare(b.Name);
                }
                return a.ServerName.localeCompare(b.ServerName);
            });
            
            // Add rows
            softwareData.forEach(software => {
                const row = table.insertRow();
                row.innerHTML = `
                    <td>${software.ServerName}</td>
                    <td>${software.Name}</td>
                    <td>${software.Version || 'N/A'}</td>
                    <td>${software.Publisher || 'N/A'}</td>
                    <td>${software.InstallDate || 'N/A'}</td>
                `;
            });
        }
        
        // Update patch inventory table
        function updatePatchTable(patchData) {
            const table = document.getElementById('patch-table').getElementsByTagName('tbody')[0];
            table.innerHTML = '';
            
            // Sort by server name and hotfix ID
            patchData.sort((a, b) => {
                if (a.ServerName === b.ServerName) {
                    return a.HotfixID.localeCompare(b.HotfixID);
                }
                return a.ServerName.localeCompare(b.ServerName);
            });
            
            // Add rows
            patchData.forEach(patch => {
                const row = table.insertRow();
                row.innerHTML = `
                    <td>${patch.ServerName}</td>
                    <td>${patch.HotfixID}</td>
                    <td>${patch.Description || 'N/A'}</td>
                    <td>${patch.InstalledBy || 'N/A'}</td>
                    <td>${patch.InstallDate || 'N/A'}</td>
                `;
            });
        }
        
        // Update system information table
        function updateSystemTable(systemData) {
            const table = document.getElementById('system-table').getElementsByTagName('tbody')[0];
            table.innerHTML = '';
            
            // Sort by server name
            systemData.sort((a, b) => a.ComputerName.localeCompare(b.ComputerName));
            
            // Add rows
            systemData.forEach(system => {
                const row = table.insertRow();
                row.innerHTML = `
                    <td>${system.ComputerName}</td>
                    <td>${system.OSName}</td>
                    <td>${system.OSVersion} (Build ${system.OSBuildNumber})</td>
                    <td>${system.InstallDate}</td>
                    <td>${system.LastBootTime}</td>
                    <td>${system.Uptime}</td>
                    <td>${system.MemoryUsagePercent}% (${system.UsedMemoryGB}/${system.TotalMemoryGB} GB)</td>
                `;
            });
        }
        
        // Update hardware inventory table
        function updateHardwareTable(hardwareData) {
            const table = document.getElementById('hardware-table').getElementsByTagName('tbody')[0];
            table.innerHTML = '';
            
            // Sort by server name
            hardwareData.sort((a, b) => a.ComputerName.localeCompare(b.ComputerName));
            
            // Add rows
            hardwareData.forEach(hardware => {
                const row = table.insertRow();
                row.innerHTML = `
                    <td>${hardware.ComputerName}</td>
                    <td>${hardware.Manufacturer}</td>
                    <td>${hardware.Model}</td>
                    <td>${hardware.ProcessorName}</td>
                    <td>${hardware.ProcessorCores} (${hardware.ProcessorLogicalProcessors} logical)</td>
                    <td>${hardware.TotalMemoryGB}</td>
                    <td>${hardware.TotalDiskSpaceGB} (${hardware.DiskUsagePercent}% used)</td>
                `;
            });
        }
        
        // Update domain controllers table
        function updateDCTable(dcData) {
            const table = document.getElementById('dc-table').getElementsByTagName('tbody')[0];
            table.innerHTML = '';
            
            // Sort by name
            dcData.sort((a, b) => a.Name.localeCompare(b.Name));
            
            // Add rows
            dcData.forEach(dc => {
                const row = table.insertRow();
                row.innerHTML = `
                    <td>${dc.Name}</td>
                    <td>${dc.HostName}</td>
                    <td>${dc.IPv4Address}</td>
                    <td>${dc.Site}</td>
                    <td>${dc.OperatingSystem} (${dc.OperatingSystemVersion})</td>
                `;
            });
        }
        
        // Filter software table
        function filterSoftwareTable() {
            const filter = document.getElementById('software-filter').value.toLowerCase();
            const table = document.getElementById('software-table');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const serverName = rows[i].cells[0].textContent.toLowerCase();
                const softwareName = rows[i].cells[1].textContent.toLowerCase();
                const version = rows[i].cells[2].textContent.toLowerCase();
                const publisher = rows[i].cells[3].textContent.toLowerCase();
                
                if (serverName.includes(filter) || softwareName.includes(filter) || 
                    version.includes(filter) || publisher.includes(filter)) {
                    rows[i].style.display = '';
                } else {
                    rows[i].style.display = 'none';
                }
            }
        }
        
        // Filter patch table
        function filterPatchTable() {
            const filter = document.getElementById('patch-filter').value.toLowerCase();
            const table = document.getElementById('patch-table');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const serverName = rows[i].cells[0].textContent.toLowerCase();
                const hotfixId = rows[i].cells[1].textContent.toLowerCase();
                const description = rows[i].cells[2].textContent.toLowerCase();
                
                if (serverName.includes(filter) || hotfixId.includes(filter) || description.includes(filter)) {
                    rows[i].style.display = '';
                } else {
                    rows[i].style.display = 'none';
                }
            }
        }
        
        // Filter system table
        function filterSystemTable() {
            const filter = document.getElementById('system-filter').value.toLowerCase();
            const table = document.getElementById('system-table');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const serverName = rows[i].cells[0].textContent.toLowerCase();
                const osName = rows[i].cells[1].textContent.toLowerCase();
                
                if (serverName.includes(filter) || osName.includes(filter)) {
                    rows[i].style.display = '';
                } else {
                    rows[i].style.display = 'none';
                }
            }
        }
        
        // Filter hardware table
        function filterHardwareTable() {
            const filter = document.getElementById('hardware-filter').value.toLowerCase();
            const table = document.getElementById('hardware-table');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const serverName = rows[i].cells[0].textContent.toLowerCase();
                const manufacturer = rows[i].cells[1].textContent.toLowerCase();
                const model = rows[i].cells[2].textContent.toLowerCase();
                
                if (serverName.includes(filter) || manufacturer.includes(filter) || model.includes(filter)) {
                    rows[i].style.display = '';
                } else {
                    rows[i].style.display = 'none';
                }
            }
        }
        
        // Filter domain controllers table
        function filterDCTable() {
            const filter = document.getElementById('dc-filter').value.toLowerCase();
            const table = document.getElementById('dc-table');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const name = rows[i].cells[0].textContent.toLowerCase();
                const fqdn = rows[i].cells[1].textContent.toLowerCase();
                const ip = rows[i].cells[2].textContent.toLowerCase();
                
                if (name.includes(filter) || fqdn.includes(filter) || ip.includes(filter)) {
                    rows[i].style.display = '';
                } else {
                    rows[i].style.display = 'none';
                }
            }
        }
        
        // Initialize the dashboard when the DOM is loaded
        document.addEventListener('DOMContentLoaded', initDashboard);
    </script>
</body>
</html>
"@
    
    # Save dashboard to file
    $DashboardPath = Join-Path -Path $DashboardFolder -ChildPath "Enterprise-Agent-Compliance-Dashboard_$Timestamp.html"
    $DashboardHtml | Out-File -FilePath $DashboardPath -Encoding UTF8
    
    Write-ColorOutput "Dashboard generated at: $DashboardPath" -Color Green
    
    return $DashboardPath
}

# Main script execution
try {
    Write-ColorOutput "=== Enterprise Software & Patch Inventory Monitor v$ScriptVersion Started ===" -Color Green
    Write-ColorOutput "=== Starting Enterprise Software & Patch Inventory Collection ===" -Color Green
    
    # Create necessary folders
    Create-Folders
    
    # Determine domains to process
    $DomainsToProcess = @()
    
    if ($Domains -and $Domains.Count -gt 0) {
        $DomainsToProcess = $Domains
    } else {
        # Use current domain if none specified
        $CurrentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
        $DomainsToProcess = @($CurrentDomain)
    }
    
    # Process each domain
    $AllDomainData = @()
    
    foreach ($Domain in $DomainsToProcess) {
        $DomainData = Process-Domain -DomainName $Domain
        
        if ($DomainData) {
            $AllDomainData += $DomainData
        }
    }
    
    # Generate cross-domain summary if requested
    if ($IncludeCrossDomainSummary -and $AllDomainData.Count -gt 1) {
        Write-ColorOutput "Generating cross-domain summary..." -Color Green
        
        $CrossDomainFolder = Join-Path -Path $ReportsFolder -ChildPath "CrossDomainSummary"
        if (-not (Test-Path -Path $CrossDomainFolder)) {
            New-Item -Path $CrossDomainFolder -ItemType Directory -Force | Out-Null
        }
        
        # Create domain summaries
        $DomainSummaries = @()
        
        foreach ($Domain in $AllDomainData) {
            $DomainSummaries += [PSCustomObject]@{
                DomainName = $Domain.DomainName
                ServersProcessed = $Domain.Summary.ServersProcessed
                TotalSoftwarePackages = $Domain.Summary.TotalSoftwarePackages
                TotalPatches = $Domain.Summary.TotalPatches
                CriticalAgentCompliance = $Domain.Summary.CriticalAgentCompliance
                RecentInstalls = $Domain.Summary.RecentInstalls
                RecentPatches = $Domain.Summary.RecentPatches
                CollectionDate = $Domain.Summary.CollectionDate
            }
        }
        
        # Export domain summaries
        $DomainSummariesPath = Join-Path -Path $CrossDomainFolder -ChildPath "AllDomains_DomainSummaries_$Timestamp.csv"
        $DomainSummaries | Export-Csv -Path $DomainSummariesPath -NoTypeInformation
        Write-ColorOutput "Domain summaries exported to: $DomainSummariesPath" -Color Green
        
        # Calculate overall summary
        $TotalServers = ($DomainSummaries | Measure-Object -Property ServersProcessed -Sum).Sum
        $TotalSoftware = ($DomainSummaries | Measure-Object -Property TotalSoftwarePackages -Sum).Sum
        $TotalPatches = ($DomainSummaries | Measure-Object -Property TotalPatches -Sum).Sum
        $TotalRecentInstalls = ($DomainSummaries | Measure-Object -Property RecentInstalls -Sum).Sum
        $TotalRecentPatches = ($DomainSummaries | Measure-Object -Property RecentPatches -Sum).Sum
        
        # Calculate weighted average compliance
        $WeightedCompliance = 0
        $TotalWeight = 0
        
        foreach ($Domain in $DomainSummaries) {
            $Weight = $Domain.ServersProcessed
            $WeightedCompliance += $Domain.CriticalAgentCompliance * $Weight
            $TotalWeight += $Weight
        }
        
        $OverallCompliance = if ($TotalWeight -gt 0) { [math]::Round($WeightedCompliance / $TotalWeight, 2) } else { 0 }
        
        # Create overall summary
        $OverallSummary = [PSCustomObject]@{
            TotalDomains = $DomainSummaries.Count
            TotalServers = $TotalServers
            TotalSoftwarePackages = $TotalSoftware
            TotalPatches = $TotalPatches
            OverallCriticalAgentCompliance = $OverallCompliance
            TotalRecentInstalls = $TotalRecentInstalls
            TotalRecentPatches = $TotalRecentPatches
            CollectionDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        # Export overall summary
        $OverallSummaryPath = Join-Path -Path $CrossDomainFolder -ChildPath "AllDomains_Summary_$Timestamp.csv"
        $OverallSummary | Export-Csv -Path $OverallSummaryPath -NoTypeInformation
        Write-ColorOutput "Overall summary exported to: $OverallSummaryPath" -Color Green
        
        # Export cross-domain JSON data
        $CrossDomainJson = [PSCustomObject]@{
            OverallSummary = $OverallSummary
            DomainSummaries = $DomainSummaries
            CollectionDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        $CrossDomainJsonPath = Join-Path -Path $CrossDomainFolder -ChildPath "AllDomains_Data_$Timestamp.json"
        $CrossDomainJson | ConvertTo-Json -Depth 5 | Out-File -FilePath $CrossDomainJsonPath -Encoding UTF8
        Write-ColorOutput "Cross-domain JSON data exported to: $CrossDomainJsonPath" -Color Green
    }
    
    # Generate dashboard if requested
    if ($GenerateDashboard -and $AllDomainData.Count -gt 0) {
        $DashboardPath = Generate-Dashboard -DomainData $AllDomainData
        
        # Open dashboard in browser if requested
        if ($OpenDashboard) {
            Write-ColorOutput "Opening dashboard in default browser..." -Color Green
            Start-Process $DashboardPath
        }
    }
    
    $EndTime = Get-Date
    $Duration = $EndTime - $StartTime
    $DurationString = "{0:D2}:{1:D2}:{2:D2}" -f $Duration.Hours, $Duration.Minutes, $Duration.Seconds
    
    Write-ColorOutput "=== Enterprise Software & Patch Inventory Monitor Completed Successfully ===" -Color Green
    Write-ColorOutput "Execution time: $DurationString" -Color Green
    
} catch {
    Write-ColorOutput "Error in main script execution: $_" -Color Red -LogLevel "ERROR"
    Write-ColorOutput "Stack trace: $($_.ScriptStackTrace)" -Color Red -LogLevel "ERROR"
}

