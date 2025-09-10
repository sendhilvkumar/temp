#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Enterprise Agent Compliance Monitor - Complete Solution
.DESCRIPTION
    Comprehensive script that discovers domain controllers, collects software inventory,
    patch information, OS details, and hardware configuration, then generates a complete
    dashboard-ready dataset for the Enterprise Agent Compliance Monitor dashboard.
.PARAMETER Domains
    Optional array of domain names to scan. If not specified, the current domain is used.
.PARAMETER OutputPath
    Optional path where reports will be saved. Defaults to "C:\InventoryReports".
.PARAMETER IncludeCrossDomainSummary
    Optional switch to generate cross-domain summary reports.
.EXAMPLE
    .\Enterprise-Agent-Compliance-Monitor-Complete.ps1
    Scans the current domain and generates reports in the default location.
.EXAMPLE
    .\Enterprise-Agent-Compliance-Monitor-Complete.ps1 -Domains "domain1.com","domain2.com" -OutputPath "D:\Reports"
    Scans the specified domains and saves reports to the specified location.
.NOTES
    Version:        2.0
    Author:         Manus
    Creation Date:  September 10, 2025
    Purpose/Change: Complete solution with dashboard integration
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string[]]$Domains,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\InventoryReports",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeCrossDomainSummary
)

#region Functions

function Write-ColorOutput {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Type = "INFO",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoNewline
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $coloredMessage = ""
    
    switch ($Type) {
        "INFO" {
            $color = "Cyan"
            $coloredMessage = "[$timestamp] [INFO] $Message"
        }
        "WARNING" {
            $color = "Yellow"
            $coloredMessage = "[$timestamp] [WARNING] $Message"
        }
        "ERROR" {
            $color = "Red"
            $coloredMessage = "[$timestamp] [ERROR] $Message"
        }
        "SUCCESS" {
            $color = "Green"
            $coloredMessage = "[$timestamp] [SUCCESS] $Message"
        }
    }
    
    # Write to console
    if ($NoNewline) {
        Write-Host $coloredMessage -ForegroundColor $color -NoNewline
    } else {
        Write-Host $coloredMessage -ForegroundColor $color
    }
    
    # Also write to log file
    $logFolder = Join-Path -Path $OutputPath -ChildPath "Logs"
    if (-not (Test-Path -Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }
    
    $logFile = Join-Path -Path $logFolder -ChildPath "InventoryMonitor_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $coloredMessage
}

function Get-DomainControllers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    
    try {
        Write-ColorOutput "Starting domain controller discovery..."
        Write-ColorOutput "Current domain: $DomainName"
        
        # Get all domain controllers in the domain
        $domainControllers = Get-ADDomainController -Filter * -Server $DomainName | Select-Object `
            @{Name="ServerName"; Expression={$_.Name}},
            @{Name="FQDN"; Expression={$_.HostName}},
            @{Name="IPAddress"; Expression={$_.IPv4Address}},
            @{Name="Site"; Expression={$_.Site}},
            @{Name="OperatingSystem"; Expression={$_.OperatingSystem}},
            @{Name="Roles"; Expression={
                $roles = @()
                if ($_.IsGlobalCatalog) { $roles += "GC" }
                if ($_.IsReadOnly) { $roles += "RODC" }
                if ($_.PDCEmulator) { $roles += "PDC" }
                if ($_.RIDMaster) { $roles += "RID" }
                if ($_.InfrastructureMaster) { $roles += "Infrastructure" }
                if ($_.SchemaMaster) { $roles += "Schema" }
                if ($_.DomainNamingMaster) { $roles += "DomainNaming" }
                $roles -join ", "
            }}
        
        Write-ColorOutput "Discovered $($domainControllers.Count) domain controllers"
        return $domainControllers
    }
    catch {
        Write-ColorOutput "Error discovering domain controllers: $_" -Type "ERROR"
        return @()
    }
}

function Test-RemoteConnectivity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    try {
        # First check if this is the local computer
        $localComputer = $env:COMPUTERNAME
        if ($ComputerName -eq $localComputer -or $ComputerName -eq "localhost" -or $ComputerName -eq ".") {
            Write-ColorOutput "Server $ComputerName is the local computer" -Type "INFO"
            return $true
        }
        
        # Try multiple connectivity methods
        # Method 1: Test-Connection (ping)
        $pingResult = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        
        # Method 2: Try WMI connectivity
        $wmiResult = $false
        try {
            $wmiResult = [bool](Get-WmiObject -Class Win32_BIOS -ComputerName $ComputerName -ErrorAction SilentlyContinue)
        } catch {
            $wmiResult = $false
        }
        
        # Method 3: Try CIM connectivity
        $cimResult = $false
        try {
            $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction SilentlyContinue
            if ($cimSession) {
                $cimResult = $true
                Remove-CimSession -CimSession $cimSession
            }
        } catch {
            $cimResult = $false
        }
        
        # If any method succeeds, consider the server reachable
        $isReachable = $pingResult -or $wmiResult -or $cimResult
        
        if ($isReachable) {
            Write-ColorOutput "Server $ComputerName is reachable" -Type "INFO"
        } else {
            Write-ColorOutput "Server $ComputerName is unreachable. Skipping." -Type "WARNING"
        }
        
        return $isReachable
    }
    catch {
        Write-ColorOutput "Error testing connectivity to $ComputerName: $_" -Type "ERROR"
        return $false
    }
}

function Get-SoftwareInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    try {
        Write-ColorOutput "Collecting software inventory from $ComputerName..."
        
        $softwareList = @()
        
        # Check if this is the local computer
        $isLocal = ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost" -or $ComputerName -eq ".")
        
        # Method 1: Get software from Win32_Product (MSI packages)
        try {
            if ($isLocal) {
                $msiProducts = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate
            } else {
                $msiProducts = Get-WmiObject -Class Win32_Product -ComputerName $ComputerName | Select-Object Name, Version, Vendor, InstallDate
            }
            
            foreach ($product in $msiProducts) {
                # Format install date
                $installDate = if ($product.InstallDate) {
                    $dateString = $product.InstallDate
                    try {
                        # Try to parse the date in YYYYMMDD format
                        [datetime]::ParseExact($dateString, "yyyyMMdd", $null).ToString("yyyy-MM-dd")
                    } catch {
                        $dateString
                    }
                } else {
                    "Unknown"
                }
                
                # Check if this is a critical agent
                $isCritical = $false
                $criticalAgents = @("Netbackup", "Qualys", "Flexera", "Microsoft Defender", "Defender for Identity", "Tripwire")
                foreach ($agent in $criticalAgents) {
                    if ($product.Name -like "*$agent*") {
                        $isCritical = $true
                        break
                    }
                }
                
                $softwareList += [PSCustomObject]@{
                    ServerName = $ComputerName
                    Name = $product.Name
                    Version = $product.Version
                    Publisher = $product.Vendor
                    InstallDate = $installDate
                    Source = "MSI"
                    IsCritical = $isCritical
                }
            }
        } catch {
            Write-ColorOutput "Error collecting MSI software from $ComputerName`: $_" -Type "WARNING"
        }
        
        # Method 2: Get software from registry (more comprehensive)
        try {
            $registryPaths = @(
                "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )
            
            foreach ($registryPath in $registryPaths) {
                if ($isLocal) {
                    $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                } else {
                    $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                }
                
                $regSubKey = $regKey.OpenSubKey($registryPath)
                if ($regSubKey) {
                    foreach ($keyName in $regSubKey.GetSubKeyNames()) {
                        $subKey = $regSubKey.OpenSubKey($keyName)
                        $displayName = $subKey.GetValue("DisplayName")
                        
                        if ($displayName) {
                            # Check if this software is already in the list (from MSI)
                            $exists = $softwareList | Where-Object { $_.Name -eq $displayName }
                            
                            if (-not $exists) {
                                $displayVersion = $subKey.GetValue("DisplayVersion")
                                $publisher = $subKey.GetValue("Publisher")
                                $installDate = $subKey.GetValue("InstallDate")
                                
                                # Format install date
                                if ($installDate) {
                                    try {
                                        # Try to parse the date in YYYYMMDD format
                                        $installDate = [datetime]::ParseExact($installDate, "yyyyMMdd", $null).ToString("yyyy-MM-dd")
                                    } catch {
                                        # Keep as is if parsing fails
                                    }
                                } else {
                                    $installDate = "Unknown"
                                }
                                
                                # Check if this is a critical agent
                                $isCritical = $false
                                $criticalAgents = @("Netbackup", "Qualys", "Flexera", "Microsoft Defender", "Defender for Identity", "Tripwire")
                                foreach ($agent in $criticalAgents) {
                                    if ($displayName -like "*$agent*") {
                                        $isCritical = $true
                                        break
                                    }
                                }
                                
                                $softwareList += [PSCustomObject]@{
                                    ServerName = $ComputerName
                                    Name = $displayName
                                    Version = $displayVersion
                                    Publisher = $publisher
                                    InstallDate = $installDate
                                    Source = "Registry"
                                    IsCritical = $isCritical
                                }
                            }
                        }
                    }
                }
            }
        } catch {
            Write-ColorOutput "Error collecting registry software from $ComputerName`: $_" -Type "WARNING"
        }
        
        Write-ColorOutput "Collected $($softwareList.Count) software packages from $ComputerName"
        return $softwareList
    }
    catch {
        Write-ColorOutput "Error collecting software inventory from $ComputerName`: $_" -Type "ERROR"
        return @()
    }
}

function Get-PatchInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    try {
        Write-ColorOutput "Collecting patch inventory from $ComputerName..."
        
        $patchList = @()
        
        # Check if this is the local computer
        $isLocal = ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost" -or $ComputerName -eq ".")
        
        # Get hotfixes
        try {
            if ($isLocal) {
                $hotfixes = Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy
            } else {
                $hotfixes = Get-HotFix -ComputerName $ComputerName | Select-Object HotFixID, Description, InstalledOn, InstalledBy
            }
            
            foreach ($hotfix in $hotfixes) {
                $patchList += [PSCustomObject]@{
                    ServerName = $ComputerName
                    PatchID = $hotfix.HotFixID
                    Description = $hotfix.Description
                    Type = if ($hotfix.Description -like "*Security*") { "Security Update" } else { "Update" }
                    InstallDate = if ($hotfix.InstalledOn) { $hotfix.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
                    InstalledBy = $hotfix.InstalledBy
                }
            }
        } catch {
            Write-ColorOutput "Error collecting hotfixes from $ComputerName`: $_" -Type "WARNING"
        }
        
        Write-ColorOutput "Collected $($patchList.Count) patches from $ComputerName"
        return $patchList
    }
    catch {
        Write-ColorOutput "Error collecting patch inventory from $ComputerName`: $_" -Type "ERROR"
        return @()
    }
}

function Get-SystemInformation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    try {
        Write-ColorOutput "Collecting system information from $ComputerName..."
        
        # Check if this is the local computer
        $isLocal = ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost" -or $ComputerName -eq ".")
        
        # Get operating system information
        try {
            if ($isLocal) {
                $os = Get-WmiObject -Class Win32_OperatingSystem
                $cs = Get-WmiObject -Class Win32_ComputerSystem
            } else {
                $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
                $cs = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName
            }
            
            # Calculate uptime
            $lastBootTime = $os.ConvertToDateTime($os.LastBootUpTime)
            $uptime = (Get-Date) - $lastBootTime
            $uptimeString = "{0} days, {1} hours, {2} minutes" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
            
            # Calculate memory usage
            $totalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            $freeMemoryGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
            $usedMemoryGB = [math]::Round($totalMemoryGB - $freeMemoryGB, 2)
            $memoryUsagePercent = [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 0)
            
            $systemInfo = [PSCustomObject]@{
                ServerName = $ComputerName
                OSName = $os.Caption
                OSVersion = "$($os.Version) (Build $($os.BuildNumber))"
                Architecture = $os.OSArchitecture
                TotalMemoryGB = $totalMemoryGB
                UsedMemoryGB = $usedMemoryGB
                FreeMemoryGB = $freeMemoryGB
                MemoryUsagePercent = $memoryUsagePercent
                Uptime = $uptimeString
                LastBoot = $lastBootTime.ToString("yyyy-MM-dd HH:mm:ss")
                InstallDate = $os.ConvertToDateTime($os.InstallDate).ToString("yyyy-MM-dd")
                Domain = $cs.Domain
                TimeZone = (Get-TimeZone).DisplayName
            }
            
            Write-ColorOutput "Collected system information from $ComputerName"
            return $systemInfo
        } catch {
            Write-ColorOutput "Error collecting system information from $ComputerName`: $_" -Type "WARNING"
            return $null
        }
    }
    catch {
        Write-ColorOutput "Error collecting system information from $ComputerName`: $_" -Type "ERROR"
        return $null
    }
}

function Get-HardwareInformation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    try {
        Write-ColorOutput "Collecting hardware information from $ComputerName..."
        
        # Check if this is the local computer
        $isLocal = ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost" -or $ComputerName -eq ".")
        
        # Get hardware information
        try {
            if ($isLocal) {
                $cs = Get-WmiObject -Class Win32_ComputerSystem
                $bios = Get-WmiObject -Class Win32_BIOS
                $processor = Get-WmiObject -Class Win32_Processor
                $memory = Get-WmiObject -Class Win32_PhysicalMemory
                $disks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
                $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND NetEnabled=True"
            } else {
                $cs = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName
                $bios = Get-WmiObject -Class Win32_BIOS -ComputerName $ComputerName
                $processor = Get-WmiObject -Class Win32_Processor -ComputerName $ComputerName
                $memory = Get-WmiObject -Class Win32_PhysicalMemory -ComputerName $ComputerName
                $disks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $ComputerName
                $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapter -Filter "PhysicalAdapter=True AND NetEnabled=True" -ComputerName $ComputerName
            }
            
            # Process processor information
            $processorInfo = if ($processor -is [array]) {
                $processor[0].Name
            } else {
                $processor.Name
            }
            
            $processorCores = if ($processor -is [array]) {
                ($processor | Measure-Object -Property NumberOfCores -Sum).Sum
            } else {
                $processor.NumberOfCores
            }
            
            # Process memory information
            $totalMemoryGB = [math]::Round(($memory | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
            $memoryModules = ($memory | Measure-Object).Count
            $memoryType = switch ($memory[0].MemoryType) {
                21 { "DDR2" }
                24 { "DDR3" }
                26 { "DDR4" }
                default { "Unknown" }
            }
            
            # Process disk information
            $diskInfo = @()
            foreach ($disk in $disks) {
                $sizeGB = [math]::Round($disk.Size / 1GB, 2)
                $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                $usedPercent = [math]::Round(($sizeGB - $freeGB) / $sizeGB * 100, 0)
                $diskInfo += "$($disk.DeviceID) $sizeGB GB ($usedPercent% used)"
            }
            $diskString = $diskInfo -join ", "
            
            $hardwareInfo = [PSCustomObject]@{
                ServerName = $ComputerName
                Manufacturer = $cs.Manufacturer
                Model = $cs.Model
                SerialNumber = $bios.SerialNumber
                BIOSVersion = $bios.SMBIOSBIOSVersion
                BIOSDate = $bios.ReleaseDate
                Processor = $processorInfo
                ProcessorCores = $processorCores
                MemoryGB = $totalMemoryGB
                MemoryModules = $memoryModules
                MemoryType = $memoryType
                Disks = $diskString
                NetworkAdapters = ($networkAdapters | Select-Object -ExpandProperty Name) -join ", "
            }
            
            Write-ColorOutput "Collected hardware information from $ComputerName"
            return $hardwareInfo
        } catch {
            Write-ColorOutput "Error collecting hardware information from $ComputerName`: $_" -Type "WARNING"
            return $null
        }
    }
    catch {
        Write-ColorOutput "Error collecting hardware information from $ComputerName`: $_" -Type "ERROR"
        return $null
    }
}

function Get-CriticalAgentStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$SoftwareInventory,
        
        [Parameter(Mandatory=$true)]
        [array]$DomainControllers
    )
    
    try {
        Write-ColorOutput "Analyzing critical agent status..."
        
        # Define critical agents to monitor
        $criticalAgents = @(
            @{Name = "Netbackup Agent"; Pattern = "*Netbackup*"; LatestVersion = "8.3.0.1"},
            @{Name = "Qualys Cloud Agent"; Pattern = "*Qualys*"; LatestVersion = "4.8.0.32"},
            @{Name = "Flexera Agent"; Pattern = "*Flexera*"; LatestVersion = "2022 R1"},
            @{Name = "Microsoft Defender Antivirus"; Pattern = "*Defender*Antivirus*"; LatestVersion = "4.18.2203.5"},
            @{Name = "Microsoft Defender for Identity"; Pattern = "*Defender*Identity*"; LatestVersion = "2.186"},
            @{Name = "Tripwire Enterprise Agent"; Pattern = "*Tripwire*"; LatestVersion = "8.9.1"}
        )
        
        $agentStatus = @()
        
        foreach ($agent in $criticalAgents) {
            # Find all instances of this agent across all servers
            $agentInstances = $SoftwareInventory | Where-Object { $_.Name -like $agent.Pattern }
            
            # Count servers with this agent installed
            $serversWithAgent = $agentInstances | Select-Object -ExpandProperty ServerName -Unique
            $serverCount = $serversWithAgent.Count
            $totalServers = $DomainControllers.Count
            
            # Check versions
            $outdatedCount = 0
            $outdatedServers = @()
            foreach ($instance in $agentInstances) {
                if ($instance.Version -ne $agent.LatestVersion) {
                    $outdatedCount++
                    $outdatedServers += $instance.ServerName
                }
            }
            
            # Determine status
            $status = if ($serverCount -eq $totalServers -and $outdatedCount -eq 0) {
                "Healthy"
            } elseif ($serverCount -lt $totalServers) {
                "Warning"
            } elseif ($outdatedCount -gt 0) {
                "Warning"
            } else {
                "Error"
            }
            
            # Format version info
            $versionInfo = $agent.LatestVersion
            if ($outdatedCount -gt 0) {
                $versionInfo += " ($outdatedCount outdated)"
            }
            
            $agentStatus += [PSCustomObject]@{
                Agent = $agent.Name
                Status = $status
                Servers = "$serverCount/$totalServers"
                Version = $versionInfo
                OutdatedServers = $outdatedServers -join ", "
            }
        }
        
        Write-ColorOutput "Analyzed status for $($criticalAgents.Count) critical agents"
        return $agentStatus
    }
    catch {
        Write-ColorOutput "Error analyzing critical agent status: $_" -Type "ERROR"
        return @()
    }
}

function Get-RecentActivity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$SoftwareInventory,
        
        [Parameter(Mandatory=$true)]
        [array]$PatchInventory
    )
    
    try {
        Write-ColorOutput "Analyzing recent activity..."
        
        $recentActivity = @()
        $thirtyDaysAgo = (Get-Date).AddDays(-30)
        
        # Get recent software installations
        $recentSoftware = $SoftwareInventory | Where-Object {
            try {
                if ($_.InstallDate -ne "Unknown") {
                    [datetime]::Parse($_.InstallDate) -gt $thirtyDaysAgo
                } else {
                    $false
                }
            } catch {
                $false
            }
        }
        
        foreach ($software in $recentSoftware) {
            $recentActivity += [PSCustomObject]@{
                ServerName = $software.ServerName
                Activity = "Installed $($software.Name) $($software.Version)"
                Date = $software.InstallDate
                Type = "Software"
            }
        }
        
        # Get recent patch installations
        $recentPatches = $PatchInventory | Where-Object {
            try {
                if ($_.InstallDate -ne "Unknown") {
                    [datetime]::Parse($_.InstallDate) -gt $thirtyDaysAgo
                } else {
                    $false
                }
            } catch {
                $false
            }
        }
        
        foreach ($patch in $recentPatches) {
            $recentActivity += [PSCustomObject]@{
                ServerName = $patch.ServerName
                Activity = "Installed $($patch.PatchID) ($($patch.Type))"
                Date = $patch.InstallDate
                Type = "Patch"
            }
        }
        
        # Sort by date (most recent first)
        $recentActivity = $recentActivity | Sort-Object -Property Date -Descending
        
        Write-ColorOutput "Found $($recentActivity.Count) recent activities in the last 30 days"
        return $recentActivity
    }
    catch {
        Write-ColorOutput "Error analyzing recent activity: $_" -Type "ERROR"
        return @()
    }
}

function Get-InventorySummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [array]$DomainControllers,
        
        [Parameter(Mandatory=$true)]
        [array]$SoftwareInventory,
        
        [Parameter(Mandatory=$true)]
        [array]$PatchInventory,
        
        [Parameter(Mandatory=$true)]
        [array]$CriticalAgentStatus,
        
        [Parameter(Mandatory=$true)]
        [array]$RecentActivity
    )
    
    try {
        Write-ColorOutput "Generating inventory summary..."
        
        # Calculate compliance percentage
        $totalAgents = $CriticalAgentStatus.Count * $DomainControllers.Count
        $installedAgents = 0
        foreach ($agent in $CriticalAgentStatus) {
            $serversCount = [int]($agent.Servers.Split('/')[0])
            $installedAgents += $serversCount
        }
        $compliancePercentage = [math]::Round(($installedAgents / $totalAgents) * 100, 0)
        
        # Count recent installations
        $recentSoftware = ($RecentActivity | Where-Object { $_.Type -eq "Software" }).Count
        $recentPatches = ($RecentActivity | Where-Object { $_.Type -eq "Patch" }).Count
        
        # Count unique software and publishers
        $uniqueSoftware = ($SoftwareInventory | Select-Object -ExpandProperty Name -Unique).Count
        $uniquePublishers = ($SoftwareInventory | Select-Object -ExpandProperty Publisher -Unique).Count
        
        # Count patches by type
        $securityPatches = ($PatchInventory | Where-Object { $_.Type -eq "Security Update" }).Count
        $otherPatches = $PatchInventory.Count - $securityPatches
        
        # Create summary object
        $summary = [PSCustomObject]@{
            TotalServers = $DomainControllers.Count
            CompliancePercentage = $compliancePercentage
            TotalSoftwarePackages = $uniqueSoftware
            TotalPatches = $PatchInventory.Count
            SecurityPatches = $securityPatches
            OtherPatches = $otherPatches
            UniquePublishers = $uniquePublishers
            RecentSoftwareInstalls = $recentSoftware
            RecentPatchInstalls = $recentPatches
            CriticalAgentsFound = ($SoftwareInventory | Where-Object { $_.IsCritical -eq $true } | Select-Object -ExpandProperty Name -Unique).Count
            GeneratedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        Write-ColorOutput "Generated inventory summary"
        return $summary
    }
    catch {
        Write-ColorOutput "Error generating inventory summary: $_" -Type "ERROR"
        return $null
    }
}

function Export-InventoryData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [array]$DomainControllers,
        
        [Parameter(Mandatory=$true)]
        [array]$SoftwareInventory,
        
        [Parameter(Mandatory=$true)]
        [array]$PatchInventory,
        
        [Parameter(Mandatory=$true)]
        [array]$SystemInformation,
        
        [Parameter(Mandatory=$true)]
        [array]$HardwareInformation,
        
        [Parameter(Mandatory=$true)]
        [array]$CriticalAgentStatus,
        
        [Parameter(Mandatory=$true)]
        [array]$RecentActivity,
        
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$InventorySummary,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    try {
        Write-ColorOutput "Exporting inventory data..."
        
        # Create domain-specific output folder
        $domainFolder = Join-Path -Path $OutputPath -ChildPath $DomainName
        if (-not (Test-Path -Path $domainFolder)) {
            New-Item -Path $domainFolder -ItemType Directory -Force | Out-Null
        }
        
        # Generate timestamp for filenames
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        # Export CSV files
        $DomainControllers | Export-Csv -Path "$domainFolder\DomainControllers_$timestamp.csv" -NoTypeInformation
        $SoftwareInventory | Export-Csv -Path "$domainFolder\SoftwareInventory_$timestamp.csv" -NoTypeInformation
        $PatchInventory | Export-Csv -Path "$domainFolder\PatchInventory_$timestamp.csv" -NoTypeInformation
        $SystemInformation | Export-Csv -Path "$domainFolder\SystemInformation_$timestamp.csv" -NoTypeInformation
        $HardwareInformation | Export-Csv -Path "$domainFolder\HardwareInformation_$timestamp.csv" -NoTypeInformation
        $CriticalAgentStatus | Export-Csv -Path "$domainFolder\CriticalAgents_$timestamp.csv" -NoTypeInformation
        $RecentActivity | Export-Csv -Path "$domainFolder\RecentActivity_$timestamp.csv" -NoTypeInformation
        $InventorySummary | Export-Csv -Path "$domainFolder\InventorySummary_$timestamp.csv" -NoTypeInformation
        
        # Create JSON data for dashboard
        $dashboardData = @{
            domain = $DomainName
            lastUpdated = Get-Date -Format "MM/dd/yyyy, HH:mm:ss tt"
            summary = $InventorySummary
            domainControllers = $DomainControllers
            softwareInventory = $SoftwareInventory
            patchInventory = $PatchInventory
            systemInformation = $SystemInformation
            hardwareInformation = $HardwareInformation
            criticalAgents = $CriticalAgentStatus
            recentActivity = $RecentActivity
            osDistribution = $SystemInformation | Group-Object -Property OSName | ForEach-Object {
                @{
                    name = $_.Name
                    count = $_.Count
                }
            }
            hardwareManufacturers = $HardwareInformation | Group-Object -Property Manufacturer | ForEach-Object {
                @{
                    name = $_.Name
                    count = $_.Count
                }
            }
            processorTypes = $HardwareInformation | Group-Object -Property Processor | ForEach-Object {
                @{
                    name = $_.Name
                    count = $_.Count
                }
            }
        }
        
        # Convert to JSON and save
        $dashboardData | ConvertTo-Json -Depth 5 | Out-File -FilePath "$domainFolder\DashboardData_$timestamp.json" -Encoding UTF8
        
        # Create a copy with a fixed filename for the dashboard to load
        $dashboardData | ConvertTo-Json -Depth 5 | Out-File -FilePath "$domainFolder\dashboard_data.json" -Encoding UTF8
        
        Write-ColorOutput "Exported inventory data to $domainFolder" -Type "SUCCESS"
        
        # Return export paths for reference
        return @{
            DomainControllers = "$domainFolder\DomainControllers_$timestamp.csv"
            SoftwareInventory = "$domainFolder\SoftwareInventory_$timestamp.csv"
            PatchInventory = "$domainFolder\PatchInventory_$timestamp.csv"
            SystemInformation = "$domainFolder\SystemInformation_$timestamp.csv"
            HardwareInformation = "$domainFolder\HardwareInformation_$timestamp.csv"
            CriticalAgents = "$domainFolder\CriticalAgents_$timestamp.csv"
            RecentActivity = "$domainFolder\RecentActivity_$timestamp.csv"
            InventorySummary = "$domainFolder\InventorySummary_$timestamp.csv"
            DashboardData = "$domainFolder\DashboardData_$timestamp.json"
            DashboardDataFixed = "$domainFolder\dashboard_data.json"
        }
    }
    catch {
        Write-ColorOutput "Error exporting inventory data: $_" -Type "ERROR"
        return $null
    }
}

function Export-CrossDomainSummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$DomainData,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    try {
        Write-ColorOutput "Generating cross-domain summary..."
        
        # Create cross-domain summary folder
        $summaryFolder = Join-Path -Path $OutputPath -ChildPath "CrossDomainSummary"
        if (-not (Test-Path -Path $summaryFolder)) {
            New-Item -Path $summaryFolder -ItemType Directory -Force | Out-Null
        }
        
        # Generate timestamp for filenames
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        # Combine domain controllers from all domains
        $allDomainControllers = @()
        foreach ($domain in $DomainData.Keys) {
            $domainControllers = $DomainData[$domain].DomainControllers
            foreach ($dc in $domainControllers) {
                $dc | Add-Member -NotePropertyName Domain -NotePropertyValue $domain -Force
                $allDomainControllers += $dc
            }
        }
        
        # Create domain summaries
        $domainSummaries = @()
        foreach ($domain in $DomainData.Keys) {
            $summary = $DomainData[$domain].InventorySummary
            $summary | Add-Member -NotePropertyName Domain -NotePropertyValue $domain -Force
            $domainSummaries += $summary
        }
        
        # Calculate overall summary
        $overallSummary = [PSCustomObject]@{
            TotalDomains = $DomainData.Keys.Count
            TotalServers = ($domainSummaries | Measure-Object -Property TotalServers -Sum).Sum
            AverageCompliance = [math]::Round(($domainSummaries | Measure-Object -Property CompliancePercentage -Average).Average, 0)
            TotalSoftwarePackages = ($domainSummaries | Measure-Object -Property TotalSoftwarePackages -Sum).Sum
            TotalPatches = ($domainSummaries | Measure-Object -Property TotalPatches -Sum).Sum
            TotalSecurityPatches = ($domainSummaries | Measure-Object -Property SecurityPatches -Sum).Sum
            TotalRecentSoftwareInstalls = ($domainSummaries | Measure-Object -Property RecentSoftwareInstalls -Sum).Sum
            TotalRecentPatchInstalls = ($domainSummaries | Measure-Object -Property RecentPatchInstalls -Sum).Sum
            GeneratedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        # Export CSV files
        $allDomainControllers | Export-Csv -Path "$summaryFolder\AllDomains_DomainControllers_$timestamp.csv" -NoTypeInformation
        $domainSummaries | Export-Csv -Path "$summaryFolder\AllDomains_DomainSummaries_$timestamp.csv" -NoTypeInformation
        $overallSummary | Export-Csv -Path "$summaryFolder\AllDomains_Summary_$timestamp.csv" -NoTypeInformation
        
        # Create JSON data for dashboard
        $dashboardData = @{
            domains = $DomainData.Keys
            lastUpdated = Get-Date -Format "MM/dd/yyyy, HH:mm:ss tt"
            overallSummary = $overallSummary
            domainSummaries = $domainSummaries
            allDomainControllers = $allDomainControllers
        }
        
        # Convert to JSON and save
        $dashboardData | ConvertTo-Json -Depth 5 | Out-File -FilePath "$summaryFolder\AllDomains_Data_$timestamp.json" -Encoding UTF8
        
        # Create a copy with a fixed filename for the dashboard to load
        $dashboardData | ConvertTo-Json -Depth 5 | Out-File -FilePath "$summaryFolder\cross_domain_data.json" -Encoding UTF8
        
        Write-ColorOutput "Exported cross-domain summary to $summaryFolder" -Type "SUCCESS"
        
        # Return export paths for reference
        return @{
            AllDomainControllers = "$summaryFolder\AllDomains_DomainControllers_$timestamp.csv"
            DomainSummaries = "$summaryFolder\AllDomains_DomainSummaries_$timestamp.csv"
            OverallSummary = "$summaryFolder\AllDomains_Summary_$timestamp.csv"
            DashboardData = "$summaryFolder\AllDomains_Data_$timestamp.json"
            DashboardDataFixed = "$summaryFolder\cross_domain_data.json"
        }
    }
    catch {
        Write-ColorOutput "Error generating cross-domain summary: $_" -Type "ERROR"
        return $null
    }
}

function Copy-DashboardFiles {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    try {
        Write-ColorOutput "Setting up dashboard files..."
        
        # Define the HTML content for the dashboard
        $dashboardHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Agent Compliance Monitor</title>
    <style>
        /* Base styles */
        :root {
            --primary-color: #0078D4;
            --primary-dark: #106EBE;
            --primary-light: #DEECF9;
            --success-color: #107C10;
            --warning-color: #FFB900;
            --error-color: #E81123;
            --neutral-dark: #201F1E;
            --neutral: #605E5C;
            --neutral-light: #EDEBE9;
            --neutral-lighter: #F3F2F1;
            --white: #FFFFFF;
            --font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Roboto', 'Helvetica Neue', sans-serif;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-family);
            font-size: 14px;
            line-height: 1.5;
            color: var(--neutral-dark);
            background-color: var(--neutral-lighter);
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }

        /* Header */
        .header {
            background-color: var(--primary-color);
            color: var(--white);
            padding: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .header h1 {
            font-size: 24px;
            font-weight: 600;
            margin: 0;
        }

        .domain-selector {
            display: flex;
            align-items: center;
        }

        .domain-selector select {
            padding: 8px 12px;
            border: none;
            border-radius: 2px;
            background-color: var(--white);
            color: var(--neutral-dark);
            font-family: var(--font-family);
            font-size: 14px;
            cursor: pointer;
            outline: none;
        }

        .last-updated {
            color: var(--white);
            font-size: 12px;
            opacity: 0.9;
        }

        /* Navigation */
        .nav {
            background-color: var(--white);
            border-bottom: 1px solid var(--neutral-light);
            display: flex;
            overflow-x: auto;
            white-space: nowrap;
        }

        .nav-tab {
            padding: 12px 16px;
            color: var(--neutral);
            font-weight: 600;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
        }

        .nav-tab:hover {
            color: var(--primary-color);
            background-color: var(--primary-light);
        }

        .nav-tab.active {
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
        }

        /* Content */
        .content {
            padding: 16px;
            max-width: 1600px;
            margin: 0 auto;
        }

        .content-section {
            display: none;
        }

        .content-section.active {
            display: block;
        }

        /* Cards */
        .card {
            background-color: var(--white);
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 16px;
            overflow: hidden;
        }

        .card-header {
            padding: 16px;
            border-bottom: 1px solid var(--neutral-light);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .card-header h2 {
            font-size: 18px;
            font-weight: 600;
            margin: 0;
        }

        .card-body {
            padding: 16px;
        }

        .card-footer {
            padding: 12px 16px;
            border-top: 1px solid var(--neutral-light);
            background-color: var(--neutral-lighter);
            font-size: 12px;
            color: var(--neutral);
        }

        /* Metrics */
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 16px;
        }

        .metric {
            background-color: var(--white);
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            padding: 16px;
            text-align: center;
        }

        .metric-value {
            font-size: 32px;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 8px;
        }

        .metric-label {
            font-size: 14px;
            color: var(--neutral);
        }

        /* Charts */
        .charts {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 16px;
            margin-bottom: 16px;
        }

        .chart-container {
            background-color: var(--white);
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            padding: 16px;
            height: 300px;
            position: relative;
        }

        .chart-title {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 16px;
            text-align: center;
        }

        /* Tables */
        .table-container {
            overflow-x: auto;
            margin-bottom: 16px;
        }

        .table-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .table-title {
            font-size: 16px;
            font-weight: 600;
        }

        .table-actions {
            display: flex;
            gap: 8px;
        }

        .table-filter {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .table-filter select,
        .table-filter input {
            padding: 8px 12px;
            border: 1px solid var(--neutral-light);
            border-radius: 2px;
            background-color: var(--white);
            color: var(--neutral-dark);
            font-family: var(--font-family);
            font-size: 14px;
            outline: none;
        }

        .table-filter input {
            min-width: 200px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--neutral-light);
        }

        th {
            background-color: var(--neutral-lighter);
            font-weight: 600;
            color: var(--neutral);
            white-space: nowrap;
        }

        tr:hover {
            background-color: var(--primary-light);
        }

        /* Status indicators */
        .status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 2px;
            font-size: 12px;
            font-weight: 600;
        }

        .status-success {
            background-color: var(--success-color);
            color: var(--white);
        }

        .status-warning {
            background-color: var(--warning-color);
            color: var(--neutral-dark);
        }

        .status-error {
            background-color: var(--error-color);
            color: var(--white);
        }

        /* Loading */
        .loading {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(255, 255, 255, 0.8);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 100;
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid var(--neutral-light);
            border-top: 4px solid var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Responsive */
        @media (max-width: 768px) {
            .metrics {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }
            
            .charts {
                grid-template-columns: 1fr;
            }
            
            .metric-value {
                font-size: 24px;
            }
            
            .metric-label {
                font-size: 12px;
            }
            
            .header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .domain-selector {
                margin-top: 12px;
            }
            
            .last-updated {
                margin-top: 8px;
            }
            
            .nav-tab {
                padding: 8px 12px;
                font-size: 12px;
            }
            
            .table-filter {
                flex-direction: column;
            }
        }

        /* Chart tooltip */
        .chart-tooltip {
            position: absolute;
            background-color: rgba(0, 0, 0, 0.8);
            color: var(--white);
            padding: 8px;
            border-radius: 4px;
            font-size: 12px;
            pointer-events: none;
            z-index: 1000;
        }

        /* Print styles */
        @media print {
            .header, .nav {
                position: static;
            }
            
            .content-section {
                display: block !important;
                page-break-after: always;
            }
            
            .card {
                break-inside: avoid;
            }
            
            .table-filter, .table-actions {
                display: none;
            }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <h1>Enterprise Agent Compliance Monitor</h1>
        <div class="domain-selector">
            <select id="domainSelect">
                <option value="">Loading domains...</option>
            </select>
        </div>
        <div class="last-updated">
            Last updated: <span id="lastUpdated">--</span>
        </div>
    </header>

    <!-- Navigation -->
    <nav class="nav">
        <div class="nav-tab active" data-tab="executiveSummary">Executive Summary</div>
        <div class="nav-tab" data-tab="softwareInventory">Software Inventory</div>
        <div class="nav-tab" data-tab="patchManagement">Patch Management</div>
        <div class="nav-tab" data-tab="systemInformation">System Information</div>
        <div class="nav-tab" data-tab="hardwareInventory">Hardware Inventory</div>
        <div class="nav-tab" data-tab="domainControllers">Domain Controllers</div>
    </nav>

    <!-- Content -->
    <main class="content">
        <!-- Executive Summary -->
        <section id="executiveSummary" class="content-section active">
            <div class="card">
                <div class="card-header">
                    <h2>Compliance Overview</h2>
                </div>
                <div class="card-body">
                    <div class="metrics">
                        <div class="metric">
                            <div class="metric-value" id="overallCompliance">--</div>
                            <div class="metric-label">Critical agents properly installed</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value" id="serversMonitored">--</div>
                            <div class="metric-label">Domain controllers</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value" id="softwarePackages">--</div>
                            <div class="metric-label">Total installed</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value" id="patchesInstalled">--</div>
                            <div class="metric-label">Total installed</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value" id="recentInstalls">--</div>
                            <div class="metric-label">Last 30 days</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value" id="recentPatches">--</div>
                            <div class="metric-label">Last 30 days</div>
                        </div>
                    </div>
                    
                    <div class="charts">
                        <div class="chart-container">
                            <div class="chart-title">Compliance Status</div>
                            <canvas id="complianceChart" width="400" height="250"></canvas>
                        </div>
                        <div class="chart-container">
                            <div class="chart-title">Operating System Distribution</div>
                            <canvas id="osDistributionChart" width="400" height="250"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2>Critical Agents Status</h2>
                </div>
                <div class="card-body">
                    <div class="table-container">
                        <table id="criticalAgentsTable">
                            <thead>
                                <tr>
                                    <th>Agent</th>
                                    <th>Status</th>
                                    <th>Servers</th>
                                    <th>Version</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="4">Loading critical agents data...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2>Recent Activity</h2>
                </div>
                <div class="card-body">
                    <div class="table-container">
                        <table id="recentActivityTable">
                            <thead>
                                <tr>
                                    <th>Server</th>
                                    <th>Activity</th>
                                    <th>Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="3">Loading recent activity...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>

        <!-- Software Inventory -->
        <section id="softwareInventory" class="content-section">
            <div class="card">
                <div class="card-header">
                    <h2>Software Inventory</h2>
                </div>
                <div class="card-body">
                    <div class="table-header">
                        <div class="table-title">Software Packages</div>
                        <div class="table-filter">
                            <select id="softwareServerFilter">
                                <option value="">All Servers</option>
                            </select>
                            <select id="softwarePublisherFilter">
                                <option value="">All Publishers</option>
                            </select>
                            <select id="softwareCriticalFilter">
                                <option value="">All Software</option>
                                <option value="critical">Critical Agents Only</option>
                            </select>
                            <input type="text" id="softwareSearch" placeholder="Search software...">
                        </div>
                    </div>
                    <div class="table-container">
                        <table id="softwareTable">
                            <thead>
                                <tr>
                                    <th>Server</th>
                                    <th>Software Name</th>
                                    <th>Version</th>
                                    <th>Publisher</th>
                                    <th>Install Date</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="6">Loading software inventory...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>

        <!-- Patch Management -->
        <section id="patchManagement" class="content-section">
            <div class="card">
                <div class="card-header">
                    <h2>Patch Inventory</h2>
                </div>
                <div class="card-body">
                    <div class="table-header">
                        <div class="table-title">Patches and Updates</div>
                        <div class="table-filter">
                            <select id="patchServerFilter">
                                <option value="">All Servers</option>
                            </select>
                            <select id="patchTypeFilter">
                                <option value="">All Patch Types</option>
                                <option value="Security Update">Security Update</option>
                                <option value="Update">Update</option>
                            </select>
                            <input type="text" id="patchSearch" placeholder="Search patches...">
                        </div>
                    </div>
                    <div class="table-container">
                        <table id="patchTable">
                            <thead>
                                <tr>
                                    <th>Server</th>
                                    <th>Patch ID</th>
                                    <th>Description</th>
                                    <th>Type</th>
                                    <th>Install Date</th>
                                    <th>Installed By</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="6">Loading patch inventory...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>

        <!-- System Information -->
        <section id="systemInformation" class="content-section">
            <div class="card">
                <div class="card-header">
                    <h2>Operating System Information</h2>
                </div>
                <div class="card-body">
                    <div class="charts">
                        <div class="chart-container">
                            <div class="chart-title">Memory Usage by Server</div>
                            <canvas id="memoryUsageChart" width="400" height="250"></canvas>
                        </div>
                    </div>
                    
                    <div class="table-header">
                        <div class="table-title">System Details</div>
                        <div class="table-filter">
                            <select id="systemServerFilter">
                                <option value="">All Servers</option>
                            </select>
                            <input type="text" id="systemSearch" placeholder="Search systems...">
                        </div>
                    </div>
                    <div class="table-container">
                        <table id="systemTable">
                            <thead>
                                <tr>
                                    <th>Server</th>
                                    <th>OS Name</th>
                                    <th>OS Version</th>
                                    <th>Memory (GB)</th>
                                    <th>Uptime</th>
                                    <th>Last Boot</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="6">Loading system information...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>

        <!-- Hardware Inventory -->
        <section id="hardwareInventory" class="content-section">
            <div class="card">
                <div class="card-header">
                    <h2>Hardware Information</h2>
                </div>
                <div class="card-body">
                    <div class="charts">
                        <div class="chart-container">
                            <div class="chart-title">Hardware Manufacturers</div>
                            <canvas id="manufacturersChart" width="400" height="250"></canvas>
                        </div>
                        <div class="chart-container">
                            <div class="chart-title">Processor Types</div>
                            <canvas id="processorsChart" width="400" height="250"></canvas>
                        </div>
                    </div>
                    
                    <div class="table-header">
                        <div class="table-title">Hardware Details</div>
                        <div class="table-filter">
                            <select id="hardwareServerFilter">
                                <option value="">All Servers</option>
                            </select>
                            <select id="hardwareManufacturerFilter">
                                <option value="">All Manufacturers</option>
                            </select>
                            <input type="text" id="hardwareSearch" placeholder="Search hardware...">
                        </div>
                    </div>
                    <div class="table-container">
                        <table id="hardwareTable">
                            <thead>
                                <tr>
                                    <th>Server</th>
                                    <th>Manufacturer</th>
                                    <th>Model</th>
                                    <th>Processor</th>
                                    <th>Cores</th>
                                    <th>Memory</th>
                                    <th>Disks</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="7">Loading hardware information...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>

        <!-- Domain Controllers -->
        <section id="domainControllers" class="content-section">
            <div class="card">
                <div class="card-header">
                    <h2>Domain Controllers</h2>
                </div>
                <div class="card-body">
                    <div class="table-header">
                        <div class="table-title">Domain Controller Details</div>
                        <div class="table-filter">
                            <select id="dcSiteFilter">
                                <option value="">All Sites</option>
                            </select>
                            <select id="dcRoleFilter">
                                <option value="">All Roles</option>
                                <option value="gc">Global Catalog</option>
                                <option value="rodc">Read-Only DC</option>
                            </select>
                            <input type="text" id="dcSearch" placeholder="Search domain controllers...">
                        </div>
                    </div>
                    <div class="table-container">
                        <table id="dcTable">
                            <thead>
                                <tr>
                                    <th>Server Name</th>
                                    <th>FQDN</th>
                                    <th>IP Address</th>
                                    <th>Site</th>
                                    <th>OS</th>
                                    <th>Roles</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="7">Loading domain controllers...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <script>
        // Global variables
        let dashboardData = null;
        let availableDomains = [];
        let currentDomain = '';

        // Initialize the dashboard
        document.addEventListener('DOMContentLoaded', function() {
            // Set up tab navigation
            setupTabNavigation();
            
            // Set up filter event listeners
            setupFilterEventListeners();
            
            // Load available domains
            loadAvailableDomains();
            
            // Set up domain selection change event
            setupDomainSelection();
        });

        // Set up tab navigation
        function setupTabNavigation() {
            const navTabs = document.querySelectorAll('.nav-tab');
            const contentSections = document.querySelectorAll('.content-section');
            
            navTabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    const tabId = tab.getAttribute('data-tab');
                    
                    // Update active tab
                    navTabs.forEach(t => t.classList.remove('active'));
                    tab.classList.add('active');
                    
                    // Update active content section
                    contentSections.forEach(section => {
                        section.classList.remove('active');
                        if (section.id === tabId) {
                            section.classList.add('active');
                        }
                    });
                });
            });
        }

        // Set up filter event listeners
        function setupFilterEventListeners() {
            // Software filters
            const softwareServerFilter = document.getElementById('softwareServerFilter');
            const softwarePublisherFilter = document.getElementById('softwarePublisherFilter');
            const softwareCriticalFilter = document.getElementById('softwareCriticalFilter');
            const softwareSearch = document.getElementById('softwareSearch');
            
            if (softwareServerFilter) {
                softwareServerFilter.addEventListener('change', () => filterTable('softwareTable', getFilters('software')));
            }
            
            if (softwarePublisherFilter) {
                softwarePublisherFilter.addEventListener('change', () => filterTable('softwareTable', getFilters('software')));
            }
            
            if (softwareCriticalFilter) {
                softwareCriticalFilter.addEventListener('change', () => filterTable('softwareTable', getFilters('software')));
            }
            
            if (softwareSearch) {
                softwareSearch.addEventListener('input', () => filterTable('softwareTable', getFilters('software')));
            }
            
            // Patch filters
            const patchServerFilter = document.getElementById('patchServerFilter');
            const patchTypeFilter = document.getElementById('patchTypeFilter');
            const patchSearch = document.getElementById('patchSearch');
            
            if (patchServerFilter) {
                patchServerFilter.addEventListener('change', () => filterTable('patchTable', getFilters('patch')));
            }
            
            if (patchTypeFilter) {
                patchTypeFilter.addEventListener('change', () => filterTable('patchTable', getFilters('patch')));
            }
            
            if (patchSearch) {
                patchSearch.addEventListener('input', () => filterTable('patchTable', getFilters('patch')));
            }
            
            // System filters
            const systemServerFilter = document.getElementById('systemServerFilter');
            const systemSearch = document.getElementById('systemSearch');
            
            if (systemServerFilter) {
                systemServerFilter.addEventListener('change', () => filterTable('systemTable', getFilters('system')));
            }
            
            if (systemSearch) {
                systemSearch.addEventListener('input', () => filterTable('systemTable', getFilters('system')));
            }
            
            // Hardware filters
            const hardwareServerFilter = document.getElementById('hardwareServerFilter');
            const hardwareManufacturerFilter = document.getElementById('hardwareManufacturerFilter');
            const hardwareSearch = document.getElementById('hardwareSearch');
            
            if (hardwareServerFilter) {
                hardwareServerFilter.addEventListener('change', () => filterTable('hardwareTable', getFilters('hardware')));
            }
            
            if (hardwareManufacturerFilter) {
                hardwareManufacturerFilter.addEventListener('change', () => filterTable('hardwareTable', getFilters('hardware')));
            }
            
            if (hardwareSearch) {
                hardwareSearch.addEventListener('input', () => filterTable('hardwareTable', getFilters('hardware')));
            }
            
            // Domain controller filters
            const dcSiteFilter = document.getElementById('dcSiteFilter');
            const dcRoleFilter = document.getElementById('dcRoleFilter');
            const dcSearch = document.getElementById('dcSearch');
            
            if (dcSiteFilter) {
                dcSiteFilter.addEventListener('change', () => filterTable('dcTable', getFilters('dc')));
            }
            
            if (dcRoleFilter) {
                dcRoleFilter.addEventListener('change', () => filterTable('dcTable', getFilters('dc')));
            }
            
            if (dcSearch) {
                dcSearch.addEventListener('input', () => filterTable('dcTable', getFilters('dc')));
            }
        }

        // Get filters for a specific table
        function getFilters(tableType) {
            const filters = {};
            
            switch (tableType) {
                case 'software':
                    filters.server = document.getElementById('softwareServerFilter').value;
                    filters.publisher = document.getElementById('softwarePublisherFilter').value;
                    filters.critical = document.getElementById('softwareCriticalFilter').value;
                    filters.search = document.getElementById('softwareSearch').value.toLowerCase();
                    break;
                case 'patch':
                    filters.server = document.getElementById('patchServerFilter').value;
                    filters.type = document.getElementById('patchTypeFilter').value;
                    filters.search = document.getElementById('patchSearch').value.toLowerCase();
                    break;
                case 'system':
                    filters.server = document.getElementById('systemServerFilter').value;
                    filters.search = document.getElementById('systemSearch').value.toLowerCase();
                    break;
                case 'hardware':
                    filters.server = document.getElementById('hardwareServerFilter').value;
                    filters.manufacturer = document.getElementById('hardwareManufacturerFilter').value;
                    filters.search = document.getElementById('hardwareSearch').value.toLowerCase();
                    break;
                case 'dc':
                    filters.site = document.getElementById('dcSiteFilter').value;
                    filters.role = document.getElementById('dcRoleFilter').value;
                    filters.search = document.getElementById('dcSearch').value.toLowerCase();
                    break;
            }
            
            return filters;
        }

        // Filter table based on filters
        function filterTable(tableId, filters) {
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                let shouldShow = true;
                
                // Apply filters based on table type
                switch (tableId) {
                    case 'softwareTable':
                        // Server filter
                        if (filters.server && row.cells[0].textContent !== filters.server) {
                            shouldShow = false;
                        }
                        
                        // Publisher filter
                        if (filters.publisher && row.cells[3].textContent !== filters.publisher) {
                            shouldShow = false;
                        }
                        
                        // Critical filter
                        if (filters.critical === 'critical' && !row.cells[5].textContent.includes('Critical')) {
                            shouldShow = false;
                        }
                        
                        // Search filter
                        if (filters.search && !row.textContent.toLowerCase().includes(filters.search)) {
                            shouldShow = false;
                        }
                        break;
                    
                    case 'patchTable':
                        // Server filter
                        if (filters.server && row.cells[0].textContent !== filters.server) {
                            shouldShow = false;
                        }
                        
                        // Type filter
                        if (filters.type && row.cells[3].textContent !== filters.type) {
                            shouldShow = false;
                        }
                        
                        // Search filter
                        if (filters.search && !row.textContent.toLowerCase().includes(filters.search)) {
                            shouldShow = false;
                        }
                        break;
                    
                    case 'systemTable':
                        // Server filter
                        if (filters.server && row.cells[0].textContent !== filters.server) {
                            shouldShow = false;
                        }
                        
                        // Search filter
                        if (filters.search && !row.textContent.toLowerCase().includes(filters.search)) {
                            shouldShow = false;
                        }
                        break;
                    
                    case 'hardwareTable':
                        // Server filter
                        if (filters.server && row.cells[0].textContent !== filters.server) {
                            shouldShow = false;
                        }
                        
                        // Manufacturer filter
                        if (filters.manufacturer && row.cells[1].textContent !== filters.manufacturer) {
                            shouldShow = false;
                        }
                        
                        // Search filter
                        if (filters.search && !row.textContent.toLowerCase().includes(filters.search)) {
                            shouldShow = false;
                        }
                        break;
                    
                    case 'dcTable':
                        // Site filter
                        if (filters.site && row.cells[3].textContent !== filters.site) {
                            shouldShow = false;
                        }
                        
                        // Role filter
                        if (filters.role) {
                            const roles = row.cells[5].textContent;
                            if (filters.role === 'gc' && !roles.includes('GC')) {
                                shouldShow = false;
                            } else if (filters.role === 'rodc' && !roles.includes('RODC')) {
                                shouldShow = false;
                            }
                        }
                        
                        // Search filter
                        if (filters.search && !row.textContent.toLowerCase().includes(filters.search)) {
                            shouldShow = false;
                        }
                        break;
                }
                
                row.style.display = shouldShow ? '' : 'none';
            });
        }

        // Load available domains
        function loadAvailableDomains() {
            // Check for domains in the current directory
            fetch('domains.json')
                .then(response => {
                    if (!response.ok) {
                        throw new Error('No domains.json file found');
                    }
                    return response.json();
                })
                .then(data => {
                    availableDomains = data.domains;
                    populateDomainSelector();
                    
                    // Load the first domain by default
                    if (availableDomains.length > 0) {
                        loadDomainData(availableDomains[0]);
                    }
                })
                .catch(error => {
                    console.error('Error loading domains:', error);
                    
                    // Fallback: Check for domain folders
                    checkForDomainFolders();
                });
        }

        // Check for domain folders
        function checkForDomainFolders() {
            // This is a simple check for domain folders
            // In a real environment, you might need to use server-side code to list directories
            
            // For now, we'll just check if dashboard_data.json exists in the current directory
            fetch('dashboard_data.json')
                .then(response => {
                    if (!response.ok) {
                        throw new Error('No dashboard_data.json file found');
                    }
                    return response.json();
                })
                .then(data => {
                    // If we found dashboard_data.json in the current directory,
                    // assume we're in a domain-specific folder
                    availableDomains = [data.domain];
                    populateDomainSelector();
                    loadDomainData(data.domain);
                })
                .catch(error => {
                    console.error('Error loading domain data:', error);
                    
                    // Final fallback: Check for cross-domain data
                    checkForCrossDomainData();
                });
        }

        // Check for cross-domain data
        function checkForCrossDomainData() {
            fetch('CrossDomainSummary/cross_domain_data.json')
                .then(response => {
                    if (!response.ok) {
                        throw new Error('No cross_domain_data.json file found');
                    }
                    return response.json();
                })
                .then(data => {
                    availableDomains = data.domains;
                    populateDomainSelector();
                    
                    // Load the first domain by default
                    if (availableDomains.length > 0) {
                        loadDomainData(availableDomains[0]);
                    }
                })
                .catch(error => {
                    console.error('Error loading cross-domain data:', error);
                    
                    // Final fallback: Show error message
                    document.getElementById('lastUpdated').textContent = 'No data found';
                });
        }

        // Populate domain selector
        function populateDomainSelector() {
            const domainSelect = document.getElementById('domainSelect');
            domainSelect.innerHTML = '';
            
            availableDomains.forEach(domain => {
                const option = document.createElement('option');
                option.value = domain;
                option.textContent = domain;
                domainSelect.appendChild(option);
            });
        }

        // Set up domain selection change event
        function setupDomainSelection() {
            const domainSelect = document.getElementById('domainSelect');
            domainSelect.addEventListener('change', () => {
                const selectedDomain = domainSelect.value;
                if (selectedDomain && selectedDomain !== currentDomain) {
                    loadDomainData(selectedDomain);
                }
            });
        }

        // Load domain data
        function loadDomainData(domain) {
            currentDomain = domain;
            
            // Try to load from domain-specific folder first
            fetch(`${domain}/dashboard_data.json`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`No dashboard_data.json found for domain ${domain}`);
                    }
                    return response.json();
                })
                .then(data => {
                    dashboardData = data;
                    updateDashboard();
                })
                .catch(error => {
                    console.error(`Error loading data for domain ${domain}:`, error);
                    
                    // Fallback: Try to load from current directory
                    fetch('dashboard_data.json')
                        .then(response => {
                            if (!response.ok) {
                                throw new Error('No dashboard_data.json found in current directory');
                            }
                            return response.json();
                        })
                        .then(data => {
                            dashboardData = data;
                            updateDashboard();
                        })
                        .catch(error => {
                            console.error('Error loading dashboard data:', error);
                            document.getElementById('lastUpdated').textContent = 'Error loading data';
                        });
                });
        }

        // Update dashboard with loaded data
        function updateDashboard() {
            if (!dashboardData) return;
            
            // Update last updated timestamp
            document.getElementById('lastUpdated').textContent = dashboardData.lastUpdated;
            
            // Update metrics
            document.getElementById('overallCompliance').textContent = `${dashboardData.summary.CompliancePercentage}%`;
            document.getElementById('serversMonitored').textContent = dashboardData.summary.TotalServers;
            document.getElementById('softwarePackages').textContent = dashboardData.summary.TotalSoftwarePackages;
            document.getElementById('patchesInstalled').textContent = dashboardData.summary.TotalPatches;
            document.getElementById('recentInstalls').textContent = dashboardData.summary.RecentSoftwareInstalls;
            document.getElementById('recentPatches').textContent = dashboardData.summary.RecentPatchInstalls;
            
            // Update charts
            updateComplianceChart();
            updateOSDistributionChart();
            updateMemoryUsageChart();
            updateManufacturersChart();
            updateProcessorsChart();
            
            // Update tables
            updateCriticalAgentsTable();
            updateRecentActivityTable();
            updateSoftwareTable();
            updatePatchTable();
            updateSystemTable();
            updateHardwareTable();
            updateDCTable();
            
            // Update filters
            updateFilters();
        }

        // Update compliance chart
        function updateComplianceChart() {
            const canvas = document.getElementById('complianceChart');
            const ctx = canvas.getContext('2d');
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Get compliance percentage
            const compliance = dashboardData.summary.CompliancePercentage;
            const nonCompliance = 100 - compliance;
            
            // Draw donut chart
            const centerX = canvas.width / 2;
            const centerY = canvas.height / 2;
            const radius = Math.min(centerX, centerY) - 10;
            const innerRadius = radius * 0.6;
            
            // Draw compliance segment (green)
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, -Math.PI / 2, -Math.PI / 2 + (compliance / 100) * Math.PI * 2);
            ctx.arc(centerX, centerY, innerRadius, -Math.PI / 2 + (compliance / 100) * Math.PI * 2, -Math.PI / 2, true);
            ctx.closePath();
            ctx.fillStyle = '#107C10';
            ctx.fill();
            
            // Draw non-compliance segment (red)
            if (nonCompliance > 0) {
                ctx.beginPath();
                ctx.arc(centerX, centerY, radius, -Math.PI / 2 + (compliance / 100) * Math.PI * 2, -Math.PI / 2 + Math.PI * 2);
                ctx.arc(centerX, centerY, innerRadius, -Math.PI / 2 + Math.PI * 2, -Math.PI / 2 + (compliance / 100) * Math.PI * 2, true);
                ctx.closePath();
                ctx.fillStyle = '#E81123';
                ctx.fill();
            }
            
            // Draw center text
            ctx.fillStyle = '#0078D4';
            ctx.font = 'bold 24px "Segoe UI", sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(`${compliance}%`, centerX, centerY - 10);
            
            ctx.fillStyle = '#605E5C';
            ctx.font = '12px "Segoe UI", sans-serif';
            ctx.fillText('Compliance', centerX, centerY + 10);
            
            // Draw legend
            const legendY = canvas.height - 30;
            
            // Compliant legend
            ctx.fillStyle = '#107C10';
            ctx.fillRect(20, legendY, 12, 12);
            
            ctx.fillStyle = '#000000';
            ctx.font = '12px "Segoe UI", sans-serif';
            ctx.textAlign = 'left';
            ctx.textBaseline = 'middle';
            ctx.fillText(`Compliant (${compliance}%)`, 40, legendY + 6);
            
            // Non-compliant legend
            ctx.fillStyle = '#E81123';
            ctx.fillRect(150, legendY, 12, 12);
            
            ctx.fillStyle = '#000000';
            ctx.fillText(`Non-Compliant (${nonCompliance}%)`, 170, legendY + 6);
        }

        // Update OS distribution chart
        function updateOSDistributionChart() {
            const canvas = document.getElementById('osDistributionChart');
            const ctx = canvas.getContext('2d');
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Get OS distribution data
            const osDistribution = dashboardData.osDistribution || [];
            
            // Sort by count (descending)
            osDistribution.sort((a, b) => b.count - a.count);
            
            // Calculate chart dimensions
            const chartWidth = canvas.width - 60;
            const chartHeight = canvas.height - 60;
            const barWidth = chartWidth / (osDistribution.length * 2);
            const barSpacing = barWidth;
            const maxCount = Math.max(...osDistribution.map(os => os.count));
            
            // Draw axes
            ctx.beginPath();
            ctx.moveTo(40, 20);
            ctx.lineTo(40, chartHeight + 20);
            ctx.lineTo(chartWidth + 40, chartHeight + 20);
            ctx.strokeStyle = '#605E5C';
            ctx.lineWidth = 1;
            ctx.stroke();
            
            // Draw y-axis labels
            ctx.fillStyle = '#605E5C';
            ctx.font = '10px "Segoe UI", sans-serif';
            ctx.textAlign = 'right';
            ctx.textBaseline = 'middle';
            
            for (let i = 0; i <= maxCount; i++) {
                if (i % Math.ceil(maxCount / 5) === 0 || i === maxCount) {
                    const y = chartHeight + 20 - (i / maxCount) * chartHeight;
                    ctx.fillText(i.toString(), 35, y);
                    
                    // Draw horizontal grid line
                    ctx.beginPath();
                    ctx.moveTo(40, y);
                    ctx.lineTo(chartWidth + 40, y);
                    ctx.strokeStyle = '#EDEBE9';
                    ctx.stroke();
                }
            }
            
            // Draw bars and x-axis labels
            osDistribution.forEach((os, index) => {
                const x = 40 + (index * 2 + 1) * barWidth;
                const barHeight = (os.count / maxCount) * chartHeight;
                const y = chartHeight + 20 - barHeight;
                
                // Draw bar
                ctx.fillStyle = `hsl(200, 100%, ${50 - index * 5}%)`;
                ctx.fillRect(x, y, barWidth, barHeight);
                
                // Draw bar value
                ctx.fillStyle = '#000000';
                ctx.font = '10px "Segoe UI", sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'bottom';
                ctx.fillText(os.count.toString(), x + barWidth / 2, y - 5);
                
                // Draw x-axis label
                ctx.fillStyle = '#605E5C';
                ctx.font = '10px "Segoe UI", sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'top';
                
                // Truncate long OS names
                let osName = os.name;
                if (osName.length > 20) {
                    osName = osName.substring(0, 17) + '...';
                }
                
                ctx.fillText(osName, x + barWidth / 2, chartHeight + 25);
            });
        }

        // Update memory usage chart
        function updateMemoryUsageChart() {
            const canvas = document.getElementById('memoryUsageChart');
            const ctx = canvas.getContext('2d');
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Get system information data
            const systemInfo = dashboardData.systemInformation || [];
            
            // Sort by server name
            systemInfo.sort((a, b) => a.ServerName.localeCompare(b.ServerName));
            
            // Calculate chart dimensions
            const chartWidth = canvas.width - 60;
            const chartHeight = canvas.height - 60;
            const barWidth = chartWidth / (systemInfo.length * 2);
            const barSpacing = barWidth;
            const maxMemory = Math.max(...systemInfo.map(sys => sys.TotalMemoryGB));
            
            // Draw axes
            ctx.beginPath();
            ctx.moveTo(40, 20);
            ctx.lineTo(40, chartHeight + 20);
            ctx.lineTo(chartWidth + 40, chartHeight + 20);
            ctx.strokeStyle = '#605E5C';
            ctx.lineWidth = 1;
            ctx.stroke();
            
            // Draw y-axis labels
            ctx.fillStyle = '#605E5C';
            ctx.font = '10px "Segoe UI", sans-serif';
            ctx.textAlign = 'right';
            ctx.textBaseline = 'middle';
            
            for (let i = 0; i <= maxMemory; i += Math.ceil(maxMemory / 5)) {
                const y = chartHeight + 20 - (i / maxMemory) * chartHeight;
                ctx.fillText(i.toString(), 35, y);
                
                // Draw horizontal grid line
                ctx.beginPath();
                ctx.moveTo(40, y);
                ctx.lineTo(chartWidth + 40, y);
                ctx.strokeStyle = '#EDEBE9';
                ctx.stroke();
            }
            
            // Draw bars and x-axis labels
            systemInfo.forEach((sys, index) => {
                const x = 40 + (index * 2 + 1) * barWidth;
                const totalBarHeight = (sys.TotalMemoryGB / maxMemory) * chartHeight;
                const usedBarHeight = (sys.UsedMemoryGB / maxMemory) * chartHeight;
                const totalY = chartHeight + 20 - totalBarHeight;
                const usedY = chartHeight + 20 - usedBarHeight;
                
                // Draw total memory bar (light blue)
                ctx.fillStyle = '#DEECF9';
                ctx.fillRect(x, totalY, barWidth, totalBarHeight);
                
                // Draw used memory bar (dark blue)
                ctx.fillStyle = '#0078D4';
                ctx.fillRect(x, usedY, barWidth, usedBarHeight);
                
                // Draw memory value
                ctx.fillStyle = '#000000';
                ctx.font = '10px "Segoe UI", sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'bottom';
                ctx.fillText(`${sys.UsedMemoryGB}/${sys.TotalMemoryGB}`, x + barWidth / 2, totalY - 5);
                
                // Draw x-axis label
                ctx.fillStyle = '#605E5C';
                ctx.font = '10px "Segoe UI", sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'top';
                ctx.fillText(sys.ServerName, x + barWidth / 2, chartHeight + 25);
            });
            
            // Draw legend
            const legendY = 20;
            
            // Used memory legend
            ctx.fillStyle = '#0078D4';
            ctx.fillRect(chartWidth - 120, legendY, 12, 12);
            
            ctx.fillStyle = '#000000';
            ctx.font = '12px "Segoe UI", sans-serif';
            ctx.textAlign = 'left';
            ctx.textBaseline = 'middle';
            ctx.fillText('Used Memory', chartWidth - 100, legendY + 6);
            
            // Total memory legend
            ctx.fillStyle = '#DEECF9';
            ctx.fillRect(chartWidth - 120, legendY + 20, 12, 12);
            
            ctx.fillStyle = '#000000';
            ctx.fillText('Total Memory', chartWidth - 100, legendY + 26);
        }

        // Update manufacturers chart
        function updateManufacturersChart() {
            const canvas = document.getElementById('manufacturersChart');
            const ctx = canvas.getContext('2d');
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Get hardware manufacturers data
            const hardwareManufacturers = dashboardData.hardwareManufacturers || [];
            
            // Sort by count (descending)
            hardwareManufacturers.sort((a, b) => b.count - a.count);
            
            // Calculate total count
            const totalCount = hardwareManufacturers.reduce((sum, item) => sum + item.count, 0);
            
            // Calculate chart dimensions
            const centerX = canvas.width / 2;
            const centerY = canvas.height / 2 - 20;
            const radius = Math.min(centerX, centerY) - 20;
            const innerRadius = radius * 0.6;
            
            // Draw donut chart
            let startAngle = -Math.PI / 2;
            
            hardwareManufacturers.forEach((manufacturer, index) => {
                const percentage = manufacturer.count / totalCount;
                const endAngle = startAngle + percentage * Math.PI * 2;
                
                // Draw segment
                ctx.beginPath();
                ctx.arc(centerX, centerY, radius, startAngle, endAngle);
                ctx.arc(centerX, centerY, innerRadius, endAngle, startAngle, true);
                ctx.closePath();
                ctx.fillStyle = `hsl(${index * 30}, 70%, 50%)`;
                ctx.fill();
                
                startAngle = endAngle;
            });
            
            // Draw legend
            const legendY = canvas.height - 50;
            const legendItemsPerRow = 2;
            const legendItemWidth = canvas.width / legendItemsPerRow;
            
            hardwareManufacturers.forEach((manufacturer, index) => {
                const row = Math.floor(index / legendItemsPerRow);
                const col = index % legendItemsPerRow;
                const x = 20 + col * legendItemWidth;
                const y = legendY + row * 20;
                
                // Draw color box
                ctx.fillStyle = `hsl(${index * 30}, 70%, 50%)`;
                ctx.fillRect(x, y, 12, 12);
                
                // Draw label
                ctx.fillStyle = '#000000';
                ctx.font = '12px "Segoe UI", sans-serif';
                ctx.textAlign = 'left';
                ctx.textBaseline = 'middle';
                const percentage = Math.round((manufacturer.count / totalCount) * 100);
                ctx.fillText(`${manufacturer.name} (${percentage}%)`, x + 20, y + 6);
            });
        }

        // Update processors chart
        function updateProcessorsChart() {
            const canvas = document.getElementById('processorsChart');
            const ctx = canvas.getContext('2d');
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Get processor types data
            const processorTypes = dashboardData.processorTypes || [];
            
            // Sort by count (descending)
            processorTypes.sort((a, b) => b.count - a.count);
            
            // Calculate chart dimensions
            const chartWidth = canvas.width - 60;
            const chartHeight = canvas.height - 60;
            const barWidth = chartWidth / (processorTypes.length * 2);
            const barSpacing = barWidth;
            const maxCount = Math.max(...processorTypes.map(proc => proc.count));
            
            // Draw axes
            ctx.beginPath();
            ctx.moveTo(40, 20);
            ctx.lineTo(40, chartHeight + 20);
            ctx.lineTo(chartWidth + 40, chartHeight + 20);
            ctx.strokeStyle = '#605E5C';
            ctx.lineWidth = 1;
            ctx.stroke();
            
            // Draw y-axis labels
            ctx.fillStyle = '#605E5C';
            ctx.font = '10px "Segoe UI", sans-serif';
            ctx.textAlign = 'right';
            ctx.textBaseline = 'middle';
            
            for (let i = 0; i <= maxCount; i++) {
                if (i % Math.ceil(maxCount / 5) === 0 || i === maxCount) {
                    const y = chartHeight + 20 - (i / maxCount) * chartHeight;
                    ctx.fillText(i.toString(), 35, y);
                    
                    // Draw horizontal grid line
                    ctx.beginPath();
                    ctx.moveTo(40, y);
                    ctx.lineTo(chartWidth + 40, y);
                    ctx.strokeStyle = '#EDEBE9';
                    ctx.stroke();
                }
            }
            
            // Draw bars and x-axis labels
            processorTypes.forEach((proc, index) => {
                const x = 40 + (index * 2 + 1) * barWidth;
                const barHeight = (proc.count / maxCount) * chartHeight;
                const y = chartHeight + 20 - barHeight;
                
                // Draw bar
                ctx.fillStyle = `hsl(220, 100%, ${50 - index * 5}%)`;
                ctx.fillRect(x, y, barWidth, barHeight);
                
                // Draw bar value
                ctx.fillStyle = '#000000';
                ctx.font = '10px "Segoe UI", sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'bottom';
                ctx.fillText(proc.count.toString(), x + barWidth / 2, y - 5);
                
                // Draw x-axis label
                ctx.fillStyle = '#605E5C';
                ctx.font = '10px "Segoe UI", sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'top';
                ctx.save();
                ctx.translate(x + barWidth / 2, chartHeight + 25);
                ctx.rotate(Math.PI / 6);
                
                // Truncate long processor names
                let procName = proc.name;
                if (procName.length > 30) {
                    procName = procName.substring(0, 27) + '...';
                }
                
                ctx.fillText(procName, 0, 0);
                ctx.restore();
            });
        }

        // Update critical agents table
        function updateCriticalAgentsTable() {
            const table = document.getElementById('criticalAgentsTable');
            const tbody = table.querySelector('tbody');
            tbody.innerHTML = '';
            
            const criticalAgents = dashboardData.criticalAgents || [];
            
            criticalAgents.forEach(agent => {
                const row = document.createElement('tr');
                
                // Agent name
                const nameCell = document.createElement('td');
                nameCell.textContent = agent.Agent;
                row.appendChild(nameCell);
                
                // Status
                const statusCell = document.createElement('td');
                const statusSpan = document.createElement('span');
                statusSpan.textContent = agent.Status;
                statusSpan.className = `status status-${agent.Status.toLowerCase() === 'healthy' ? 'success' : agent.Status.toLowerCase() === 'warning' ? 'warning' : 'error'}`;
                statusCell.appendChild(statusSpan);
                row.appendChild(statusCell);
                
                // Servers
                const serversCell = document.createElement('td');
                serversCell.textContent = agent.Servers;
                row.appendChild(serversCell);
                
                // Version
                const versionCell = document.createElement('td');
                versionCell.textContent = agent.Version;
                row.appendChild(versionCell);
                
                tbody.appendChild(row);
            });
        }

        // Update recent activity table
        function updateRecentActivityTable() {
            const table = document.getElementById('recentActivityTable');
            const tbody = table.querySelector('tbody');
            tbody.innerHTML = '';
            
            const recentActivity = dashboardData.recentActivity || [];
            
            // Sort by date (most recent first)
            recentActivity.sort((a, b) => new Date(b.Date) - new Date(a.Date));
            
            // Take only the first 10 activities
            const recentActivities = recentActivity.slice(0, 10);
            
            recentActivities.forEach(activity => {
                const row = document.createElement('tr');
                
                // Server
                const serverCell = document.createElement('td');
                serverCell.textContent = activity.ServerName;
                row.appendChild(serverCell);
                
                // Activity
                const activityCell = document.createElement('td');
                activityCell.textContent = activity.Activity;
                row.appendChild(activityCell);
                
                // Date
                const dateCell = document.createElement('td');
                dateCell.textContent = activity.Date;
                row.appendChild(dateCell);
                
                tbody.appendChild(row);
            });
        }

        // Update software table
        function updateSoftwareTable() {
            const table = document.getElementById('softwareTable');
            const tbody = table.querySelector('tbody');
            tbody.innerHTML = '';
            
            const softwareInventory = dashboardData.softwareInventory || [];
            
            softwareInventory.forEach(software => {
                const row = document.createElement('tr');
                
                // Server
                const serverCell = document.createElement('td');
                serverCell.textContent = software.ServerName;
                row.appendChild(serverCell);
                
                // Software Name
                const nameCell = document.createElement('td');
                nameCell.textContent = software.Name;
                row.appendChild(nameCell);
                
                // Version
                const versionCell = document.createElement('td');
                versionCell.textContent = software.Version;
                row.appendChild(versionCell);
                
                // Publisher
                const publisherCell = document.createElement('td');
                publisherCell.textContent = software.Publisher;
                row.appendChild(publisherCell);
                
                // Install Date
                const dateCell = document.createElement('td');
                dateCell.textContent = software.InstallDate;
                row.appendChild(dateCell);
                
                // Status
                const statusCell = document.createElement('td');
                if (software.IsCritical) {
                    const statusSpan = document.createElement('span');
                    statusSpan.textContent = 'Critical';
                    statusSpan.className = 'status status-success';
                    statusCell.appendChild(statusSpan);
                }
                row.appendChild(statusCell);
                
                tbody.appendChild(row);
            });
        }

        // Update patch table
        function updatePatchTable() {
            const table = document.getElementById('patchTable');
            const tbody = table.querySelector('tbody');
            tbody.innerHTML = '';
            
            const patchInventory = dashboardData.patchInventory || [];
            
            patchInventory.forEach(patch => {
                const row = document.createElement('tr');
                
                // Server
                const serverCell = document.createElement('td');
                serverCell.textContent = patch.ServerName;
                row.appendChild(serverCell);
                
                // Patch ID
                const idCell = document.createElement('td');
                idCell.textContent = patch.PatchID;
                row.appendChild(idCell);
                
                // Description
                const descCell = document.createElement('td');
                descCell.textContent = patch.Description;
                row.appendChild(descCell);
                
                // Type
                const typeCell = document.createElement('td');
                typeCell.textContent = patch.Type;
                row.appendChild(typeCell);
                
                // Install Date
                const dateCell = document.createElement('td');
                dateCell.textContent = patch.InstallDate;
                row.appendChild(dateCell);
                
                // Installed By
                const byCell = document.createElement('td');
                byCell.textContent = patch.InstalledBy;
                row.appendChild(byCell);
                
                tbody.appendChild(row);
            });
        }

        // Update system table
        function updateSystemTable() {
            const table = document.getElementById('systemTable');
            const tbody = table.querySelector('tbody');
            tbody.innerHTML = '';
            
            const systemInformation = dashboardData.systemInformation || [];
            
            systemInformation.forEach(system => {
                const row = document.createElement('tr');
                
                // Server
                const serverCell = document.createElement('td');
                serverCell.textContent = system.ServerName;
                row.appendChild(serverCell);
                
                // OS Name
                const osNameCell = document.createElement('td');
                osNameCell.textContent = system.OSName;
                row.appendChild(osNameCell);
                
                // OS Version
                const osVersionCell = document.createElement('td');
                osVersionCell.textContent = system.OSVersion;
                row.appendChild(osVersionCell);
                
                // Memory
                const memoryCell = document.createElement('td');
                memoryCell.textContent = `${system.TotalMemoryGB} GB (${system.MemoryUsagePercent}% used)`;
                row.appendChild(memoryCell);
                
                // Uptime
                const uptimeCell = document.createElement('td');
                uptimeCell.textContent = system.Uptime;
                row.appendChild(uptimeCell);
                
                // Last Boot
                const bootCell = document.createElement('td');
                bootCell.textContent = system.LastBoot;
                row.appendChild(bootCell);
                
                tbody.appendChild(row);
            });
        }

        // Update hardware table
        function updateHardwareTable() {
            const table = document.getElementById('hardwareTable');
            const tbody = table.querySelector('tbody');
            tbody.innerHTML = '';
            
            const hardwareInformation = dashboardData.hardwareInformation || [];
            
            hardwareInformation.forEach(hardware => {
                const row = document.createElement('tr');
                
                // Server
                const serverCell = document.createElement('td');
                serverCell.textContent = hardware.ServerName;
                row.appendChild(serverCell);
                
                // Manufacturer
                const manufacturerCell = document.createElement('td');
                manufacturerCell.textContent = hardware.Manufacturer;
                row.appendChild(manufacturerCell);
                
                // Model
                const modelCell = document.createElement('td');
                modelCell.textContent = hardware.Model;
                row.appendChild(modelCell);
                
                // Processor
                const processorCell = document.createElement('td');
                processorCell.textContent = hardware.Processor;
                row.appendChild(processorCell);
                
                // Cores
                const coresCell = document.createElement('td');
                coresCell.textContent = hardware.ProcessorCores;
                row.appendChild(coresCell);
                
                // Memory
                const memoryCell = document.createElement('td');
                memoryCell.textContent = `${hardware.MemoryGB} GB (${hardware.MemoryModules} modules)`;
                row.appendChild(memoryCell);
                
                // Disks
                const disksCell = document.createElement('td');
                disksCell.textContent = hardware.Disks;
                row.appendChild(disksCell);
                
                tbody.appendChild(row);
            });
        }

        // Update domain controllers table
        function updateDCTable() {
            const table = document.getElementById('dcTable');
            const tbody = table.querySelector('tbody');
            tbody.innerHTML = '';
            
            const domainControllers = dashboardData.domainControllers || [];
            
            domainControllers.forEach(dc => {
                const row = document.createElement('tr');
                
                // Server Name
                const nameCell = document.createElement('td');
                nameCell.textContent = dc.ServerName;
                row.appendChild(nameCell);
                
                // FQDN
                const fqdnCell = document.createElement('td');
                fqdnCell.textContent = dc.FQDN;
                row.appendChild(fqdnCell);
                
                // IP Address
                const ipCell = document.createElement('td');
                ipCell.textContent = dc.IPAddress;
                row.appendChild(ipCell);
                
                // Site
                const siteCell = document.createElement('td');
                siteCell.textContent = dc.Site;
                row.appendChild(siteCell);
                
                // OS
                const osCell = document.createElement('td');
                osCell.textContent = dc.OperatingSystem;
                row.appendChild(osCell);
                
                // Roles
                const rolesCell = document.createElement('td');
                rolesCell.textContent = dc.Roles;
                row.appendChild(rolesCell);
                
                // Status
                const statusCell = document.createElement('td');
                const statusSpan = document.createElement('span');
                statusSpan.textContent = 'Online';
                statusSpan.className = 'status status-success';
                statusCell.appendChild(statusSpan);
                row.appendChild(statusCell);
                
                tbody.appendChild(row);
            });
        }

        // Update filters
        function updateFilters() {
            // Software server filter
            const softwareServerFilter = document.getElementById('softwareServerFilter');
            softwareServerFilter.innerHTML = '<option value="">All Servers</option>';
            
            const softwareServers = [...new Set(dashboardData.softwareInventory.map(s => s.ServerName))];
            softwareServers.forEach(server => {
                const option = document.createElement('option');
                option.value = server;
                option.textContent = server;
                softwareServerFilter.appendChild(option);
            });
            
            // Software publisher filter
            const softwarePublisherFilter = document.getElementById('softwarePublisherFilter');
            softwarePublisherFilter.innerHTML = '<option value="">All Publishers</option>';
            
            const softwarePublishers = [...new Set(dashboardData.softwareInventory.map(s => s.Publisher))];
            softwarePublishers.forEach(publisher => {
                if (publisher) {
                    const option = document.createElement('option');
                    option.value = publisher;
                    option.textContent = publisher;
                    softwarePublisherFilter.appendChild(option);
                }
            });
            
            // Patch server filter
            const patchServerFilter = document.getElementById('patchServerFilter');
            patchServerFilter.innerHTML = '<option value="">All Servers</option>';
            
            const patchServers = [...new Set(dashboardData.patchInventory.map(p => p.ServerName))];
            patchServers.forEach(server => {
                const option = document.createElement('option');
                option.value = server;
                option.textContent = server;
                patchServerFilter.appendChild(option);
            });
            
            // System server filter
            const systemServerFilter = document.getElementById('systemServerFilter');
            systemServerFilter.innerHTML = '<option value="">All Servers</option>';
            
            const systemServers = [...new Set(dashboardData.systemInformation.map(s => s.ServerName))];
            systemServers.forEach(server => {
                const option = document.createElement('option');
                option.value = server;
                option.textContent = server;
                systemServerFilter.appendChild(option);
            });
            
            // Hardware server filter
            const hardwareServerFilter = document.getElementById('hardwareServerFilter');
            hardwareServerFilter.innerHTML = '<option value="">All Servers</option>';
            
            const hardwareServers = [...new Set(dashboardData.hardwareInformation.map(h => h.ServerName))];
            hardwareServers.forEach(server => {
                const option = document.createElement('option');
                option.value = server;
                option.textContent = server;
                hardwareServerFilter.appendChild(option);
            });
            
            // Hardware manufacturer filter
            const hardwareManufacturerFilter = document.getElementById('hardwareManufacturerFilter');
            hardwareManufacturerFilter.innerHTML = '<option value="">All Manufacturers</option>';
            
            const hardwareManufacturers = [...new Set(dashboardData.hardwareInformation.map(h => h.Manufacturer))];
            hardwareManufacturers.forEach(manufacturer => {
                if (manufacturer) {
                    const option = document.createElement('option');
                    option.value = manufacturer;
                    option.textContent = manufacturer;
                    hardwareManufacturerFilter.appendChild(option);
                }
            });
            
            // DC site filter
            const dcSiteFilter = document.getElementById('dcSiteFilter');
            dcSiteFilter.innerHTML = '<option value="">All Sites</option>';
            
            const dcSites = [...new Set(dashboardData.domainControllers.map(dc => dc.Site))];
            dcSites.forEach(site => {
                if (site) {
                    const option = document.createElement('option');
                    option.value = site;
                    option.textContent = site;
                    dcSiteFilter.appendChild(option);
                }
            });
        }
    </script>
</body>
</html>
'@
        
        # Create domains.json file
        $domainsJson = @{
            domains = @()
        }
        
        # Check for domain folders
        $domainFolders = Get-ChildItem -Path $OutputPath -Directory | Where-Object { $_.Name -ne "Logs" -and $_.Name -ne "CrossDomainSummary" }
        
        foreach ($folder in $domainFolders) {
            $domainsJson.domains += $folder.Name
        }
        
        # Save domains.json
        $domainsJson | ConvertTo-Json | Out-File -FilePath "$OutputPath\domains.json" -Encoding UTF8
        
        # Save dashboard HTML
        $dashboardHtml | Out-File -FilePath "$OutputPath\Enterprise-Agent-Compliance-Dashboard.html" -Encoding UTF8
        
        Write-ColorOutput "Dashboard files set up successfully at $OutputPath\Enterprise-Agent-Compliance-Dashboard.html" -Type "SUCCESS"
        
        return "$OutputPath\Enterprise-Agent-Compliance-Dashboard.html"
    }
    catch {
        Write-ColorOutput "Error setting up dashboard files: $_" -Type "ERROR"
        return $null
    }
}

#endregion

#region Main Script

# Create output directory if it doesn't exist
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Display script header
Write-ColorOutput "=== Enterprise Software & Patch Inventory Monitor v2.0 Started ===" -Type "INFO"
Write-ColorOutput "=== Starting Enterprise Software & Patch Inventory Collection ===" -Type "INFO"

# If no domains specified, use the current domain
if (-not $Domains -or $Domains.Count -eq 0) {
    $Domains = @((Get-WmiObject Win32_ComputerSystem).Domain)
}

# Store domain data for cross-domain summary
$domainData = @{}

# Process each domain
foreach ($domain in $Domains) {
    Write-ColorOutput "Starting domain controller discovery..." -Type "INFO"
    Write-ColorOutput "Current domain: $domain" -Type "INFO"
    
    # Get domain controllers
    $domainControllers = Get-DomainControllers -DomainName $domain
    
    if ($domainControllers.Count -eq 0) {
        Write-ColorOutput "No domain controllers found in domain $domain. Skipping." -Type "WARNING"
        continue
    }
    
    Write-ColorOutput "Discovered $($domainControllers.Count) domain controllers" -Type "INFO"
    
    # Initialize data arrays
    $softwareInventory = @()
    $patchInventory = @()
    $systemInformation = @()
    $hardwareInformation = @()
    
    # Process each domain controller
    Write-ColorOutput "Starting inventory collection for $($domainControllers.Count) servers..." -Type "INFO"
    
    foreach ($dc in $domainControllers) {
        Write-ColorOutput "Processing server: $($dc.ServerName)..." -Type "INFO"
        
        # Check if server is reachable
        if (Test-RemoteConnectivity -ComputerName $dc.ServerName) {
            # Collect software inventory
            $software = Get-SoftwareInventory -ComputerName $dc.ServerName
            $softwareInventory += $software
            
            # Collect patch inventory
            $patches = Get-PatchInventory -ComputerName $dc.ServerName
            $patchInventory += $patches
            
            # Collect system information
            $sysInfo = Get-SystemInformation -ComputerName $dc.ServerName
            if ($sysInfo) {
                $systemInformation += $sysInfo
            }
            
            # Collect hardware information
            $hwInfo = Get-HardwareInformation -ComputerName $dc.ServerName
            if ($hwInfo) {
                $hardwareInformation += $hwInfo
            }
        } else {
            Write-ColorOutput "Server $($dc.ServerName) is unreachable. Skipping." -Type "WARNING"
        }
    }
    
    # Generate reports
    Write-ColorOutput "Generating inventory reports..." -Type "INFO"
    
    # Analyze critical agent status
    $criticalAgentStatus = Get-CriticalAgentStatus -SoftwareInventory $softwareInventory -DomainControllers $domainControllers
    
    # Analyze recent activity
    $recentActivity = Get-RecentActivity -SoftwareInventory $softwareInventory -PatchInventory $patchInventory
    
    # Generate inventory summary
    $inventorySummary = Get-InventorySummary -DomainControllers $domainControllers -SoftwareInventory $softwareInventory -PatchInventory $patchInventory -CriticalAgentStatus $criticalAgentStatus -RecentActivity $recentActivity
    
    # Export data
    $exportPaths = Export-InventoryData -DomainName $domain -DomainControllers $domainControllers -SoftwareInventory $softwareInventory -PatchInventory $patchInventory -SystemInformation $systemInformation -HardwareInformation $hardwareInformation -CriticalAgentStatus $criticalAgentStatus -RecentActivity $recentActivity -InventorySummary $inventorySummary -OutputPath $OutputPath
    
    # Store domain data for cross-domain summary
    $domainData[$domain] = @{
        DomainControllers = $domainControllers
        SoftwareInventory = $softwareInventory
        PatchInventory = $patchInventory
        SystemInformation = $systemInformation
        HardwareInformation = $hardwareInformation
        CriticalAgentStatus = $criticalAgentStatus
        RecentActivity = $recentActivity
        InventorySummary = $inventorySummary
        ExportPaths = $exportPaths
    }
    
    # Display summary
    Write-ColorOutput "=== INVENTORY COLLECTION SUMMARY ===" -Type "INFO"
    Write-ColorOutput "Total Servers Processed: $($domainControllers.Count)" -Type "INFO"
    Write-ColorOutput "Total Software Packages: $($softwareInventory.Count)" -Type "INFO"
    Write-ColorOutput "Total Patches/Updates: $($patchInventory.Count)" -Type "INFO"
    Write-ColorOutput "Critical Agents Found: $($softwareInventory | Where-Object { $_.IsCritical -eq $true } | Select-Object -ExpandProperty Name -Unique | Measure-Object).Count" -Type "INFO"
    Write-ColorOutput "Unique Publishers: $($softwareInventory | Select-Object -ExpandProperty Publisher -Unique | Measure-Object).Count" -Type "INFO"
    Write-ColorOutput "Recent Installs (30 days): $($recentActivity | Where-Object { $_.Type -eq "Software" } | Measure-Object).Count" -Type "INFO"
    Write-ColorOutput "Recent Patches (30 days): $($recentActivity | Where-Object { $_.Type -eq "Patch" } | Measure-Object).Count" -Type "INFO"
}

# Generate cross-domain summary if requested
if ($IncludeCrossDomainSummary -and $domainData.Keys.Count -gt 1) {
    Write-ColorOutput "Generating cross-domain summary..." -Type "INFO"
    $crossDomainPaths = Export-CrossDomainSummary -DomainData $domainData -OutputPath $OutputPath
}

# Set up dashboard files
$dashboardPath = Copy-DashboardFiles -OutputPath $OutputPath

Write-ColorOutput "=== Enterprise Software & Patch Inventory Monitor Completed Successfully ===" -Type "SUCCESS"
Write-ColorOutput "Dashboard available at: $dashboardPath" -Type "SUCCESS"

# Return summary information
return @{
    DomainsProcessed = $domainData.Keys
    TotalServers = ($domainData.Values | ForEach-Object { $_.DomainControllers.Count } | Measure-Object -Sum).Sum
    TotalSoftwarePackages = ($domainData.Values | ForEach-Object { $_.SoftwareInventory.Count } | Measure-Object -Sum).Sum
    TotalPatches = ($domainData.Values | ForEach-Object { $_.PatchInventory.Count } | Measure-Object -Sum).Sum
    DashboardPath = $dashboardPath
}

#endregion

