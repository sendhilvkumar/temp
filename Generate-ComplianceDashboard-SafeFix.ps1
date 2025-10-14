# Enterprise Compliance Dashboard Generator - Final Version with CSV Downloads, Easter Egg & Charts
# Scans CSV reports and generates static HTML dashboard with search, sorting, CSV downloads, easter egg, and charts
# Version: 8.2
# Author: Enterprise IT Team

param (
    [Parameter(Mandatory=$false)]
    [string]$ReportsPath = "C:\Inventory\InventoryReports",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\Inventory\Dashboard",
    
    [Parameter(Mandatory=$false)]
    [string]$DashboardName = "Enterprise-Compliance-Dashboard.html",
    
    [Parameter(Mandatory=$false)]
    [bool]$OpenDashboard = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxRecordsPerTable = 1000,
    
    [Parameter(Mandatory=$false)]
    [bool]$CreateDownloadLinks = $true
)

# Script Variables
$ScriptVersion = "8.2"
$StartTime = Get-Date
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$ComputerName = $env:COMPUTERNAME

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $LogMessage -ForegroundColor Red }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
        default { Write-Host $LogMessage -ForegroundColor White }
    }
}

# Function to escape HTML content
function Escape-HTML {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "N/A" }
    return $Text -replace "&", "&amp;" -replace "<", "&lt;" -replace ">", "&gt;" -replace '"', "&quot;" -replace "'", "&#39;"
}

# Function to clean and validate data
function Clean-DataValue {
    param([string]$Value)
    
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq "Unknown" -or $Value -eq "" -or $Value -eq "N/A") {
        return "N/A"
    }
    return $Value.Trim()
}

# Function to get safe property value
function Get-SafeProperty {
    param(
        [object]$Object,
        [string]$PropertyName,
        [string]$DefaultValue = "N/A"
    )
    
    try {
        if ($Object.PSObject.Properties.Name -contains $PropertyName) {
            $Value = $Object.$PropertyName
            if ([string]::IsNullOrWhiteSpace($Value)) {
                return $DefaultValue
            }
            return $Value.ToString().Trim()
        }
        return $DefaultValue
    } catch {
        return $DefaultValue
    }
}

# Function to get relative path for download links
function Get-RelativePath {
    param(
        [string]$FromPath,
        [string]$ToPath
    )
    
    try {
        $FromUri = New-Object System.Uri($FromPath)
        $ToUri = New-Object System.Uri($ToPath)
        $RelativeUri = $FromUri.MakeRelativeUri($ToUri)
        return $RelativeUri.ToString().Replace('/', '\')
    } catch {
        return $ToPath
    }
}

# Function to scan for domain folders
function Get-DomainFolders {
    param([string]$BasePath)
    
    Write-Log "Scanning for domain folders in: $BasePath"
    
    if (-not (Test-Path -Path $BasePath)) {
        Write-Log "Reports path does not exist: $BasePath" -Level "ERROR"
        return @()
    }
    
    $DomainFolders = Get-ChildItem -Path $BasePath -Directory | Where-Object {
        $_.Name -notmatch "^(CrossDomainSummary|Logs|Dashboard)$"
    }
    
    Write-Log "Found $($DomainFolders.Count) domain folders: $($DomainFolders.Name -join ', ')" -Level "SUCCESS"
    return $DomainFolders
}

# Function to get latest CSV files for a domain
function Get-LatestCSVFiles {
    param(
        [string]$DomainPath,
        [string]$DomainName
    )
    
    Write-Log "Processing domain: $DomainName"
    
    $CSVTypes = @(
        "DomainControllers",
        "SoftwareInventory", 
        "PatchInventory",
        "SystemInformation",
        "HardwareInfo",
        "CriticalAgents",
        "InventorySummary"
    )
    
    $DomainData = @{
        DomainName = $DomainName
        Files = @{}
        Data = @{}
        LastUpdated = $null
        DownloadLinks = @{}
    }
    
    foreach ($CSVType in $CSVTypes) {
        $CSVFiles = Get-ChildItem -Path $DomainPath -Filter "$CSVType*.csv" | Sort-Object LastWriteTime -Descending
        
        if ($CSVFiles.Count -gt 0) {
            $LatestFile = $CSVFiles[0]
            $DomainData.Files[$CSVType] = $LatestFile.FullName
            $DomainData.DownloadLinks[$CSVType] = $LatestFile.FullName
            
            # Update last updated time
            if (-not $DomainData.LastUpdated -or $LatestFile.LastWriteTime -gt $DomainData.LastUpdated) {
                $DomainData.LastUpdated = $LatestFile.LastWriteTime
            }
            
            Write-Log "Found $CSVType file: $($LatestFile.Name)"
        } else {
            Write-Log "No $CSVType files found for domain $DomainName" -Level "WARNING"
        }
    }
    
    return $DomainData
}

# Function to load CSV data with proper column mapping for real data structure
function Load-CSVData {
    param([hashtable]$DomainData)
    
    Write-Log "Loading CSV data for domain: $($DomainData.DomainName)"
    
    foreach ($CSVType in $DomainData.Files.Keys) {
        $FilePath = $DomainData.Files[$CSVType]
        
        try {
            $RawData = Import-Csv -Path $FilePath -ErrorAction Stop
            
            # Clean and validate data with proper column mapping for real CSV structure
            $CleanedData = @()
            foreach ($Record in $RawData) {
                $CleanedRecord = [PSCustomObject]@{}
                
                # Add domain name to each record
                $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Domain" -Value $DomainData.DomainName
                
                # Map columns based on CSV type with real column names
                switch ($CSVType) {
                    "DomainControllers" {
                        # Real columns: Name, HostName, IPv4Address, Site, OperatingSystem, OperatingSystemVersion
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Get-SafeProperty $Record "Name")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "HostName" -Value (Get-SafeProperty $Record "HostName")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value (Get-SafeProperty $Record "IPv4Address")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Site" -Value (Get-SafeProperty $Record "Site")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "OSVersion" -Value (Get-SafeProperty $Record "OperatingSystem")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "OSVersionNumber" -Value (Get-SafeProperty $Record "OperatingSystemVersion")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Role" -Value "Domain Controller"
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Status" -Value "Online"
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "LastSeen" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    }
                    "SoftwareInventory" {
                        # Real columns: ServerName, Name, Version, Publisher, InstallDate, InstallLocation, Source
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Get-SafeProperty $Record "ServerName")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value (Get-SafeProperty $Record "Name")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value (Get-SafeProperty $Record "Version")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Publisher" -Value (Get-SafeProperty $Record "Publisher")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value (Get-SafeProperty $Record "InstallDate")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value (Get-SafeProperty $Record "InstallLocation")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Source" -Value (Get-SafeProperty $Record "Source")
                    }
                    "PatchInventory" {
                        # Real columns: ServerName, HotfixID, Description, InstalledBy, InstallDate, Source
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Get-SafeProperty $Record "ServerName")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "HotFixID" -Value (Get-SafeProperty $Record "HotfixID")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Description" -Value (Get-SafeProperty $Record "Description")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Classification" -Value (Get-SafeProperty $Record "Source")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "InstalledOn" -Value (Get-SafeProperty $Record "InstallDate")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "InstalledBy" -Value (Get-SafeProperty $Record "InstalledBy")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Title" -Value (Get-SafeProperty $Record "Description")
                    }
                    "SystemInformation" {
                        # Real columns: ComputerName, OSName, OSVersion, OSBuildNumber, OSArchitecture, OSLanguage, InstallDate, LastBootTime, Uptime, TotalMemoryGB, UsedMemoryGB, FreeMemoryGB, MemoryUsagePercent, SystemDirectory, WindowsDirectory, BootDevice, SystemDrive, Domain, TimeZone
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Get-SafeProperty $Record "ComputerName")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "OSName" -Value (Get-SafeProperty $Record "OSName")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "OSVersion" -Value (Get-SafeProperty $Record "OSVersion")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "OSBuildNumber" -Value (Get-SafeProperty $Record "OSBuildNumber")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Architecture" -Value (Get-SafeProperty $Record "OSArchitecture")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "TotalPhysicalMemoryGB" -Value (Get-SafeProperty $Record "TotalMemoryGB")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "UsedMemoryGB" -Value (Get-SafeProperty $Record "UsedMemoryGB")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "FreeMemoryGB" -Value (Get-SafeProperty $Record "FreeMemoryGB")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ProcessorCount" -Value "N/A"
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "LogicalProcessors" -Value "N/A"
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "LastBootUpTime" -Value (Get-SafeProperty $Record "LastBootTime")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "SystemType" -Value (Get-SafeProperty $Record "OSArchitecture")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "SystemDrive" -Value (Get-SafeProperty $Record "SystemDrive")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Uptime" -Value (Get-SafeProperty $Record "Uptime")
                    }
                    "HardwareInfo" {
                        # Real columns: ComputerName, Manufacturer, Model, SystemFamily, SystemSKU, SerialNumber, BIOSVersion, BIOSReleaseDate, BIOSManufacturer, ProcessorName, ProcessorManufacturer, ProcessorCores, ProcessorLogicalProcessors, ProcessorClockSpeed, ProcessorArchitecture, TotalMemoryGB, MemorySlots, MemoryType, MemorySpeed, TotalDiskSpaceGB, UsedDiskSpaceGB, DiskUsagePercent, NetworkAdapters, DiskDrives
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Get-SafeProperty $Record "ComputerName")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value (Get-SafeProperty $Record "Manufacturer")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Model" -Value (Get-SafeProperty $Record "Model")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "SystemFamily" -Value (Get-SafeProperty $Record "SystemFamily")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ProcessorName" -Value (Get-SafeProperty $Record "ProcessorName")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ProcessorCores" -Value (Get-SafeProperty $Record "ProcessorCores")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ProcessorLogicalProcessors" -Value (Get-SafeProperty $Record "ProcessorLogicalProcessors")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ProcessorClockSpeed" -Value (Get-SafeProperty $Record "ProcessorClockSpeed")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "TotalPhysicalMemoryGB" -Value (Get-SafeProperty $Record "TotalMemoryGB")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "TotalDiskSpaceGB" -Value (Get-SafeProperty $Record "TotalDiskSpaceGB")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "UsedDiskSpaceGB" -Value (Get-SafeProperty $Record "UsedDiskSpaceGB")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "DiskUsagePercent" -Value (Get-SafeProperty $Record "DiskUsagePercent")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "NetworkAdapters" -Value (Get-SafeProperty $Record "NetworkAdapters")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value (Get-SafeProperty $Record "SerialNumber")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "BIOSVersion" -Value (Get-SafeProperty $Record "BIOSVersion")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "BIOSDate" -Value (Get-SafeProperty $Record "BIOSReleaseDate")
                    }
                    "CriticalAgents" {
                        # Real columns: ServerName, AgentName, Status, Version, InstallDate, IsRunning, ServiceStatus, RegistryFound, HealthStatus, LastChecked
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Get-SafeProperty $Record "ServerName")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "AgentName" -Value (Get-SafeProperty $Record "AgentName")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Status" -Value (Get-SafeProperty $Record "Status")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "IsInstalled" -Value (Get-SafeProperty $Record "Status")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Version" -Value (Get-SafeProperty $Record "Version")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "LastCheck" -Value (Get-SafeProperty $Record "LastChecked")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value (Get-SafeProperty $Record "InstallDate")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ServiceStatus" -Value (Get-SafeProperty $Record "ServiceStatus")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "RegistryFound" -Value (Get-SafeProperty $Record "RegistryFound")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "HealthStatus" -Value (Get-SafeProperty $Record "HealthStatus")
                    }
                    "InventorySummary" {
                        # Real columns: DomainName, ServersProcessed, TotalSoftwarePackages, TotalPatches, CriticalAgentCompliance, RecentInstalls, RecentPatches, UniquePublishers, CollectionDate
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "DomainName" -Value (Get-SafeProperty $Record "DomainName")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ServersProcessed" -Value (Get-SafeProperty $Record "ServersProcessed")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "TotalSoftwarePackages" -Value (Get-SafeProperty $Record "TotalSoftwarePackages")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "TotalPatches" -Value (Get-SafeProperty $Record "TotalPatches")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "CriticalAgentCompliance" -Value (Get-SafeProperty $Record "CriticalAgentCompliance")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "RecentInstalls" -Value (Get-SafeProperty $Record "RecentInstalls")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "RecentPatches" -Value (Get-SafeProperty $Record "RecentPatches")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "UniquePublishers" -Value (Get-SafeProperty $Record "UniquePublishers")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "CollectionDate" -Value (Get-SafeProperty $Record "CollectionDate")
                    }
                }
                
                $CleanedData += $CleanedRecord
            }
            
            $DomainData.Data[$CSVType] = $CleanedData
            Write-Log "Loaded $($CleanedData.Count) records from $CSVType" -Level "SUCCESS"
            
        } catch {
            Write-Log "Error loading $CSVType for domain $($DomainData.DomainName): $_" -Level "ERROR"
            $DomainData.Data[$CSVType] = @()
        }
    }
}

# Function to calculate summary statistics
function Calculate-SummaryStats {
    param([array]$AllDomainData)
    
    Write-Log "Calculating summary statistics..."
    
    $Stats = @{
        TotalDomains = $AllDomainData.Count
        TotalServers = 0
        TotalSoftwarePackages = 0
        TotalPatches = 0
        TotalCriticalAgents = 0
        CompliancePercentage = 0
        LastUpdated = "N/A"
    }
    
    $AllServers = @()
    $AllSoftware = @()
    $AllPatches = @()
    $AllAgents = @()
    $CompliantAgents = 0
    $TotalAgents = 0
    
    foreach ($Domain in $AllDomainData) {
        # Count unique servers from DomainControllers (most reliable source)
        if ($Domain.Data.ContainsKey("DomainControllers") -and $Domain.Data["DomainControllers"].Count -gt 0) {
            $DomainServers = $Domain.Data["DomainControllers"] | ForEach-Object {
                $ServerName = $_.ComputerName
                if ([string]::IsNullOrEmpty($ServerName) -or $ServerName -eq "N/A") {
                    $ServerName = $_.HostName
                }
                if (-not [string]::IsNullOrEmpty($ServerName) -and $ServerName -ne "N/A") {
                    # Clean server name (remove domain suffix and normalize)
                    $CleanName = $ServerName.Split('.')[0].ToUpper()
                    return $CleanName
                }
            } | Where-Object { -not [string]::IsNullOrEmpty($_) } | Sort-Object -Unique
            
            $AllServers += $DomainServers
        }
        # Fallback to SystemInformation if DomainControllers is empty
        elseif ($Domain.Data.ContainsKey("SystemInformation") -and $Domain.Data["SystemInformation"].Count -gt 0) {
            $DomainServers = $Domain.Data["SystemInformation"] | ForEach-Object {
                $ServerName = $_.ComputerName
                if (-not [string]::IsNullOrEmpty($ServerName) -and $ServerName -ne "N/A") {
                    $CleanName = $ServerName.Split('.')[0].ToUpper()
                    return $CleanName
                }
            } | Where-Object { -not [string]::IsNullOrEmpty($_) } | Sort-Object -Unique
            
            $AllServers += $DomainServers
        }
        # Final fallback to HardwareInfo
        elseif ($Domain.Data.ContainsKey("HardwareInfo") -and $Domain.Data["HardwareInfo"].Count -gt 0) {
            $DomainServers = $Domain.Data["HardwareInfo"] | ForEach-Object {
                $ServerName = $_.ComputerName
                if (-not [string]::IsNullOrEmpty($ServerName) -and $ServerName -ne "N/A") {
                    $CleanName = $ServerName.Split('.')[0].ToUpper()
                    return $CleanName
                }
            } | Where-Object { -not [string]::IsNullOrEmpty($_) } | Sort-Object -Unique
            
            $AllServers += $DomainServers
        }
        
        # Count software packages
        if ($Domain.Data.ContainsKey("SoftwareInventory")) {
            $AllSoftware += $Domain.Data["SoftwareInventory"]
        }
        
        # Count patches
        if ($Domain.Data.ContainsKey("PatchInventory")) {
            $AllPatches += $Domain.Data["PatchInventory"]
        }
        
        # Count critical agents and compliance
        if ($Domain.Data.ContainsKey("CriticalAgents")) {
            $DomainAgents = $Domain.Data["CriticalAgents"]
            $AllAgents += $DomainAgents
            $TotalAgents += $DomainAgents.Count
            $CompliantAgents += ($DomainAgents | Where-Object { $_.Status -eq "Installed" -or $_.IsInstalled -eq "True" -or $_.IsInstalled -eq "Installed" }).Count
        }
        
        # Update last updated time
        if ($Domain.LastUpdated) {
            if ($Stats.LastUpdated -eq "N/A" -or $Domain.LastUpdated -gt [DateTime]$Stats.LastUpdated) {
                $Stats.LastUpdated = $Domain.LastUpdated.ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
    }
    
    # Calculate final statistics
    $Stats.TotalServers = ($AllServers | Sort-Object -Unique).Count
    $Stats.TotalSoftwarePackages = $AllSoftware.Count
    $Stats.TotalPatches = $AllPatches.Count
    $Stats.TotalCriticalAgents = $TotalAgents
    
    # Calculate compliance percentage
    if ($TotalAgents -gt 0) {
        $Stats.CompliancePercentage = [Math]::Round(($CompliantAgents / $TotalAgents) * 100, 2)
    }
    
    Write-Log "Summary Statistics:" -Level "SUCCESS"
    Write-Log "  Total Domains: $($Stats.TotalDomains)"
    Write-Log "  Total Servers: $($Stats.TotalServers)"
    Write-Log "  Total Software Packages: $($Stats.TotalSoftwarePackages)"
    Write-Log "  Total Patches: $($Stats.TotalPatches)"
    Write-Log "  Compliance Percentage: $($Stats.CompliancePercentage)%"
    
    return $Stats
}

# Function to generate HTML dashboard
function Generate-HTMLDashboard {
    param(
        [array]$AllDomainData,
        [hashtable]$SummaryStats,
        [string]$OutputFilePath
    )
    
    Write-Log "Generating HTML dashboard..."
    
    # Generate domain options for filter
    $DomainOptions = "<option value='all'>All Domains</option>"
    foreach ($Domain in $AllDomainData) {
        $DomainOptions += "<option value='$($Domain.DomainName)'>$($Domain.DomainName)</option>"
    }
    
    # Generate domain summary rows for overview
    $DomainSummaryRows = ""
    foreach ($Domain in $AllDomainData) {
        $DomainServers = 0
        $DomainSoftware = 0
        $DomainPatches = 0
        $DomainCompliance = 0
        
        # Count servers for this domain
        if ($Domain.Data.ContainsKey("DomainControllers")) {
            $DomainServers = ($Domain.Data["DomainControllers"] | Where-Object { $_.ComputerName -ne "N/A" }).Count
        }
        
        # Count software for this domain
        if ($Domain.Data.ContainsKey("SoftwareInventory")) {
            $DomainSoftware = $Domain.Data["SoftwareInventory"].Count
        }
        
        # Count patches for this domain
        if ($Domain.Data.ContainsKey("PatchInventory")) {
            $DomainPatches = $Domain.Data["PatchInventory"].Count
        }
        
        # Calculate compliance for this domain
        if ($Domain.Data.ContainsKey("CriticalAgents")) {
            $DomainAgents = $Domain.Data["CriticalAgents"]
            if ($DomainAgents.Count -gt 0) {
                $CompliantCount = ($DomainAgents | Where-Object { $_.Status -eq "Installed" -or $_.IsInstalled -eq "True" -or $_.IsInstalled -eq "Installed" }).Count
                $DomainCompliance = [Math]::Round(($CompliantCount / $DomainAgents.Count) * 100, 1)
            }
        }
        
        $LastUpdated = if ($Domain.LastUpdated) { $Domain.LastUpdated.ToString("yyyy-MM-dd HH:mm") } else { "N/A" }
        
        $DomainSummaryRows += @"
        <tr data-domain="$($Domain.DomainName)">
            <td>$(Escape-HTML $Domain.DomainName)</td>
            <td>$DomainServers</td>
            <td>$DomainSoftware</td>
            <td>$DomainPatches</td>
            <td><span class="$(if ($DomainCompliance -ge 80) { 'status-compliant' } elseif ($DomainCompliance -ge 60) { 'status-warning' } else { 'status-non-compliant' })">$DomainCompliance%</span></td>
            <td>$LastUpdated</td>
        </tr>
"@
    }
    
    # Generate table headers and rows for each section
    $DomainControllersHeaders = @"
        <th class="sortable" onclick="sortTable('domain-controllers-table', 0)">Domain <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('domain-controllers-table', 1)">Server Name <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('domain-controllers-table', 2)">Host Name <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('domain-controllers-table', 3)">IP Address <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('domain-controllers-table', 4)">Site <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('domain-controllers-table', 5)">OS Version <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('domain-controllers-table', 6)">OS Version Number <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('domain-controllers-table', 7)">Role <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('domain-controllers-table', 8)">Status <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('domain-controllers-table', 9)">Last Seen <span class="sort-arrow"></span></th>
"@
    
    $DomainControllersRows = ""
    foreach ($Domain in $AllDomainData) {
        if ($Domain.Data.ContainsKey("DomainControllers")) {
            foreach ($DC in $Domain.Data["DomainControllers"]) {
                $StatusClass = switch ($DC.Status) {
                    "Online" { "status-compliant" }
                    "Offline" { "status-non-compliant" }
                    default { "status-unknown" }
                }
                
                $DomainControllersRows += @"
        <tr data-domain="$($Domain.DomainName)">
            <td>$(Escape-HTML $Domain.DomainName)</td>
            <td>$(Escape-HTML $DC.ComputerName)</td>
            <td>$(Escape-HTML $DC.HostName)</td>
            <td>$(Escape-HTML $DC.IPAddress)</td>
            <td>$(Escape-HTML $DC.Site)</td>
            <td>$(Escape-HTML $DC.OSVersion)</td>
            <td>$(Escape-HTML $DC.OSVersionNumber)</td>
            <td>$(Escape-HTML $DC.Role)</td>
            <td><span class="$StatusClass">$(Escape-HTML $DC.Status)</span></td>
            <td>$(Escape-HTML $DC.LastSeen)</td>
        </tr>
"@
            }
        }
    }
    
    # Generate Software Inventory table
    $SoftwareHeaders = @"
        <th class="sortable" onclick="sortTable('software-table', 0)">Domain <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('software-table', 1)">Server <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('software-table', 2)">Software Name <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('software-table', 3)">Version <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('software-table', 4)">Publisher <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('software-table', 5)">Install Date <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('software-table', 6)">Install Location <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('software-table', 7)">Source <span class="sort-arrow"></span></th>
"@
    
    $SoftwareRows = ""
    $SoftwareCount = 0
    foreach ($Domain in $AllDomainData) {
        if ($Domain.Data.ContainsKey("SoftwareInventory")) {
            foreach ($Software in $Domain.Data["SoftwareInventory"]) {
                if ($SoftwareCount -ge $MaxRecordsPerTable) { break }
                
                $SoftwareRows += @"
        <tr data-domain="$($Domain.DomainName)">
            <td>$(Escape-HTML $Domain.DomainName)</td>
            <td>$(Escape-HTML $Software.ComputerName)</td>
            <td>$(Escape-HTML $Software.DisplayName)</td>
            <td>$(Escape-HTML $Software.DisplayVersion)</td>
            <td>$(Escape-HTML $Software.Publisher)</td>
            <td>$(Escape-HTML $Software.InstallDate)</td>
            <td>$(Escape-HTML $Software.InstallLocation)</td>
            <td>$(Escape-HTML $Software.Source)</td>
        </tr>
"@
                $SoftwareCount++
            }
        }
    }
    
    # Generate Patch Inventory table
    $PatchHeaders = @"
        <th class="sortable" onclick="sortTable('patches-table', 0)">Domain <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('patches-table', 1)">Server <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('patches-table', 2)">Patch ID <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('patches-table', 3)">Description <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('patches-table', 4)">Classification <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('patches-table', 5)">Install Date <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('patches-table', 6)">Installed By <span class="sort-arrow"></span></th>
"@
    
    $PatchRows = ""
    $PatchCount = 0
    foreach ($Domain in $AllDomainData) {
        if ($Domain.Data.ContainsKey("PatchInventory")) {
            foreach ($Patch in $Domain.Data["PatchInventory"]) {
                if ($PatchCount -ge $MaxRecordsPerTable) { break }
                
                $PatchRows += @"
        <tr data-domain="$($Domain.DomainName)">
            <td>$(Escape-HTML $Domain.DomainName)</td>
            <td>$(Escape-HTML $Patch.ComputerName)</td>
            <td>$(Escape-HTML $Patch.HotFixID)</td>
            <td>$(Escape-HTML $Patch.Description)</td>
            <td>$(Escape-HTML $Patch.Classification)</td>
            <td>$(Escape-HTML $Patch.InstalledOn)</td>
            <td>$(Escape-HTML $Patch.InstalledBy)</td>
        </tr>
"@
                $PatchCount++
            }
        }
    }
    
    # Generate Critical Agents table
    $AgentsHeaders = @"
        <th class="sortable" onclick="sortTable('agents-table', 0)">Domain <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('agents-table', 1)">Server <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('agents-table', 2)">Agent Name <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('agents-table', 3)">Status <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('agents-table', 4)">Installed <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('agents-table', 5)">Version <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('agents-table', 6)">Service Status <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('agents-table', 7)">Health Status <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('agents-table', 8)">Last Check <span class="sort-arrow"></span></th>
"@
    
    $AgentsRows = ""
    foreach ($Domain in $AllDomainData) {
        if ($Domain.Data.ContainsKey("CriticalAgents")) {
            foreach ($Agent in $Domain.Data["CriticalAgents"]) {
                $StatusClass = switch ($Agent.Status) {
                    "Installed" { "status-compliant" }
                    "Not Installed" { "status-non-compliant" }
                    default { "status-unknown" }
                }
                
                $AgentsRows += @"
        <tr data-domain="$($Domain.DomainName)">
            <td>$(Escape-HTML $Domain.DomainName)</td>
            <td>$(Escape-HTML $Agent.ComputerName)</td>
            <td>$(Escape-HTML $Agent.AgentName)</td>
            <td><span class="$StatusClass">$(Escape-HTML $Agent.Status)</span></td>
            <td>$(Escape-HTML $Agent.IsInstalled)</td>
            <td>$(Escape-HTML $Agent.Version)</td>
            <td>$(Escape-HTML $Agent.ServiceStatus)</td>
            <td>$(Escape-HTML $Agent.HealthStatus)</td>
            <td>$(Escape-HTML $Agent.LastCheck)</td>
        </tr>
"@
            }
        }
    }
    
    # Generate System Information table
    $SystemInfoHeaders = @"
        <th class="sortable" onclick="sortTable('system-info-table', 0)">Domain <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('system-info-table', 1)">Server Name <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('system-info-table', 2)">OS Name <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('system-info-table', 3)">OS Version <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('system-info-table', 4)">Build Number <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('system-info-table', 5)">Architecture <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('system-info-table', 6)">Memory (GB) <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('system-info-table', 7)">Used Memory (GB) <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('system-info-table', 8)">Last Boot <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('system-info-table', 9)">Uptime <span class="sort-arrow"></span></th>
"@
    
    $SystemInfoRows = ""
    foreach ($Domain in $AllDomainData) {
        if ($Domain.Data.ContainsKey("SystemInformation")) {
            foreach ($System in $Domain.Data["SystemInformation"]) {
                $SystemInfoRows += @"
        <tr data-domain="$($Domain.DomainName)">
            <td>$(Escape-HTML $Domain.DomainName)</td>
            <td>$(Escape-HTML $System.ComputerName)</td>
            <td>$(Escape-HTML $System.OSName)</td>
            <td>$(Escape-HTML $System.OSVersion)</td>
            <td>$(Escape-HTML $System.OSBuildNumber)</td>
            <td>$(Escape-HTML $System.Architecture)</td>
            <td>$(Escape-HTML $System.TotalPhysicalMemoryGB)</td>
            <td>$(Escape-HTML $System.UsedMemoryGB)</td>
            <td>$(Escape-HTML $System.LastBootUpTime)</td>
            <td>$(Escape-HTML $System.Uptime)</td>
        </tr>
"@
            }
        }
    }
    
    # Generate Hardware Information table
    $HardwareHeaders = @"
        <th class="sortable" onclick="sortTable('hardware-table', 0)">Domain <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('hardware-table', 1)">Server Name <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('hardware-table', 2)">Manufacturer <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('hardware-table', 3)">Model <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('hardware-table', 4)">System Family <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('hardware-table', 5)">CPU <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('hardware-table', 6)">CPU Cores <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('hardware-table', 7)">Memory (GB) <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('hardware-table', 8)">Disk Space (GB) <span class="sort-arrow"></span></th>
        <th class="sortable" onclick="sortTable('hardware-table', 9)">Disk Usage % <span class="sort-arrow"></span></th>
"@
    
    $HardwareRows = ""
    foreach ($Domain in $AllDomainData) {
        if ($Domain.Data.ContainsKey("HardwareInfo")) {
            foreach ($Hardware in $Domain.Data["HardwareInfo"]) {
                $HardwareRows += @"
        <tr data-domain="$($Domain.DomainName)">
            <td>$(Escape-HTML $Domain.DomainName)</td>
            <td>$(Escape-HTML $Hardware.ComputerName)</td>
            <td>$(Escape-HTML $Hardware.Manufacturer)</td>
            <td>$(Escape-HTML $Hardware.Model)</td>
            <td>$(Escape-HTML $Hardware.SystemFamily)</td>
            <td>$(Escape-HTML $Hardware.ProcessorName)</td>
            <td>$(Escape-HTML $Hardware.ProcessorCores)</td>
            <td>$(Escape-HTML $Hardware.TotalPhysicalMemoryGB)</td>
            <td>$(Escape-HTML $Hardware.TotalDiskSpaceGB)</td>
            <td>$(Escape-HTML $Hardware.DiskUsagePercent)</td>
        </tr>
"@
            }
        }
    }
    
    # Generate CSV Downloads section if enabled
    $DownloadsTab = ""
    $DownloadsContent = ""
    
    if ($CreateDownloadLinks) {
        $DownloadsTab = '<div class="nav-tab" onclick="showTab(''csv-downloads'')">CSV Downloads</div>'
        
        $DownloadRows = ""
        foreach ($Domain in $AllDomainData) {
            foreach ($CSVType in $Domain.DownloadLinks.Keys) {
                $FilePath = $Domain.DownloadLinks[$CSVType]
                $FileName = Split-Path -Path $FilePath -Leaf
                $FileSize = if (Test-Path -Path $FilePath) { 
                    [Math]::Round((Get-Item -Path $FilePath).Length / 1KB, 1) 
                } else { 
                    "N/A" 
                }
                $LastModified = if (Test-Path -Path $FilePath) { 
                    (Get-Item -Path $FilePath).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") 
                } else { 
                    "N/A" 
                }
                
                $ReportTypeName = switch ($CSVType) {
                    "DomainControllers" { "Domain Controllers" }
                    "SoftwareInventory" { "Software Inventory" }
                    "PatchInventory" { "Patch Inventory" }
                    "SystemInformation" { "System Information" }
                    "HardwareInfo" { "Hardware Information" }
                    "CriticalAgents" { "Critical Agents" }
                    "InventorySummary" { "Inventory Summary" }
                    default { $CSVType }
                }
                
                $DownloadRows += @"
        <tr data-domain="$($Domain.DomainName)">
            <td>$(Escape-HTML $Domain.DomainName)</td>
            <td>$ReportTypeName</td>
            <td>$FileName</td>
            <td>$FileSize KB</td>
            <td>$LastModified</td>
            <td><a href="file:///$($FilePath.Replace('\', '/'))" class="download-link" target="_blank">📥 Download</a></td>
        </tr>
"@
            }
        }
        
        $DownloadsContent = @"
        <!-- CSV Downloads Tab -->
        <div id="csv-downloads" class="tab-content">
            <div class="section-header">
                <span>CSV Downloads</span>
                <div class="search-container">
                    <input type="text" id="csv-downloads-search" placeholder="Search downloads..." onkeyup="searchTable('csv-downloads-table')">
                    <button onclick="clearSearch('csv-downloads-search')">Clear</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="csv-downloads-table">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('csv-downloads-table', 0)">Domain <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('csv-downloads-table', 1)">Report Type <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('csv-downloads-table', 2)">File Name <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('csv-downloads-table', 3)">File Size <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('csv-downloads-table', 4)">Last Modified <span class="sort-arrow"></span></th>
                            <th>Download</th>
                        </tr>
                    </thead>
                    <tbody>
                        $DownloadRows
                    </tbody>
                </table>
            </div>
            <div style="margin-top: 1rem; padding: 1rem; background: #f8f9fa; border-radius: 8px; color: #6c757d;">
                <strong>Note:</strong> CSV files are linked directly from the original domain folders. If download links don't work in your browser, you can manually navigate to the file paths shown above.
            </div>
        </div>
"@
    }

    # Generate chart data for visualization
    $ChartData = @{
        ComplianceScore = $SummaryStats.CompliancePercentage
        DomainStats = @()
        OSVersions = @{}
        TopSoftware = @{}
        AgentStatus = @{
            Installed = 0
            NotInstalled = 0
        }
        PatchStatus = @{
            Last30Days = 0
            Last60Days = 0
            Last90Days = 0
            Older = 0
            Unknown = 0
        }
    }

    # Calculate domain statistics for charts
    foreach ($Domain in $AllDomainData) {
        $DomainStat = @{
            Name = $Domain.DomainName
            Servers = 0
            Software = 0
            Patches = 0
        }
        
        if ($Domain.Data.ContainsKey("DomainControllers")) {
            $DomainStat.Servers = ($Domain.Data["DomainControllers"] | Where-Object { $_.ComputerName -ne "N/A" }).Count
        }
        
        if ($Domain.Data.ContainsKey("SoftwareInventory")) {
            $DomainStat.Software = $Domain.Data["SoftwareInventory"].Count
        }
        
        if ($Domain.Data.ContainsKey("PatchInventory")) {
            $DomainStat.Patches = $Domain.Data["PatchInventory"].Count
        }
        
        $ChartData.DomainStats += $DomainStat
    }

    # Calculate OS version distribution
    foreach ($Domain in $AllDomainData) {
        if ($Domain.Data.ContainsKey("DomainControllers")) {
            foreach ($DC in $Domain.Data["DomainControllers"]) {
                $OSVersion = $DC.OSVersion
                if ($OSVersion -ne "N/A" -and -not [string]::IsNullOrEmpty($OSVersion)) {
                    if ($ChartData.OSVersions.ContainsKey($OSVersion)) {
                        $ChartData.OSVersions[$OSVersion]++
                    } else {
                        $ChartData.OSVersions[$OSVersion] = 1
                    }
                }
            }
        }
    }

    # Calculate top software packages
    $SoftwareCount = @{}
    foreach ($Domain in $AllDomainData) {
        if ($Domain.Data.ContainsKey("SoftwareInventory")) {
            foreach ($Software in $Domain.Data["SoftwareInventory"]) {
                $SoftwareName = $Software.DisplayName
                if ($SoftwareName -ne "N/A" -and -not [string]::IsNullOrEmpty($SoftwareName)) {
                    if ($SoftwareCount.ContainsKey($SoftwareName)) {
                        $SoftwareCount[$SoftwareName]++
                    } else {
                        $SoftwareCount[$SoftwareName] = 1
                    }
                }
            }
        }
    }
    
    # Get top 10 software packages
    $TopSoftwareList = $SoftwareCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    foreach ($Software in $TopSoftwareList) {
        $ChartData.TopSoftware[$Software.Key] = $Software.Value
    }

    # Calculate agent status
    foreach ($Domain in $AllDomainData) {
        if ($Domain.Data.ContainsKey("CriticalAgents")) {
            foreach ($Agent in $Domain.Data["CriticalAgents"]) {
                if ($Agent.Status -eq "Installed" -or $Agent.IsInstalled -eq "True" -or $Agent.IsInstalled -eq "Installed") {
                    $ChartData.AgentStatus.Installed++
                } else {
                    $ChartData.AgentStatus.NotInstalled++
                }
            }
        }
    }

    # Generate chart HTML and JavaScript
    $ChartsHTML = @"
        <!-- Charts Section -->
        <div class="charts-section" style="margin: 2rem 0;">
            <div class="charts-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; margin-bottom: 2rem;">
                
                <!-- Compliance Gauge Chart -->
                <div class="chart-container" style="background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h4 style="margin: 0 0 1rem 0; color: #333; text-align: center;">Compliance Score</h4>
                    <div class="gauge-chart" style="position: relative; width: 200px; height: 200px; margin: 0 auto;">
                        <div class="gauge-background" style="width: 200px; height: 200px; border-radius: 50%; background: conic-gradient(from 0deg, #e9ecef 0deg, #e9ecef 360deg); position: relative;">
                            <div class="gauge-fill" style="width: 200px; height: 200px; border-radius: 50%; background: conic-gradient(from 0deg, #28a745 0deg, #28a745 $([Math]::Round($ChartData.ComplianceScore * 3.6, 1))deg, #e9ecef $([Math]::Round($ChartData.ComplianceScore * 3.6, 1))deg, #e9ecef 360deg); position: absolute; top: 0; left: 0;"></div>
                            <div class="gauge-inner" style="width: 140px; height: 140px; border-radius: 50%; background: white; position: absolute; top: 30px; left: 30px; display: flex; align-items: center; justify-content: center; flex-direction: column;">
                                <div style="font-size: 2rem; font-weight: bold; color: #333;">$($ChartData.ComplianceScore)%</div>
                                <div style="font-size: 0.9rem; color: #666;">Compliance</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Domain Comparison Chart -->
                <div class="chart-container" style="background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h4 style="margin: 0 0 1rem 0; color: #333; text-align: center;">Domain Comparison</h4>
                    <div class="bar-chart" style="height: 200px; display: flex; align-items: end; gap: 1rem; padding: 1rem 0;">
"@

    # Add domain bars
    $MaxValue = ($ChartData.DomainStats | ForEach-Object { [Math]::Max($_.Servers, [Math]::Max($_.Software, $_.Patches)) } | Measure-Object -Maximum).Maximum
    if ($MaxValue -eq 0) { $MaxValue = 1 }

    foreach ($DomainStat in $ChartData.DomainStats) {
        $ServersHeight = [Math]::Round(($DomainStat.Servers / $MaxValue) * 150, 1)
        $SoftwareHeight = [Math]::Round(($DomainStat.Software / $MaxValue) * 150, 1)
        $PatchesHeight = [Math]::Round(($DomainStat.Patches / $MaxValue) * 150, 1)
        
        $ChartsHTML += @"
                        <div class="domain-bar-group" style="display: flex; flex-direction: column; align-items: center; gap: 0.5rem;">
                            <div style="display: flex; gap: 2px; align-items: end;">
                                <div style="width: 20px; height: $($ServersHeight)px; background: #007bff; border-radius: 2px;" title="Servers: $($DomainStat.Servers)"></div>
                                <div style="width: 20px; height: $($SoftwareHeight)px; background: #28a745; border-radius: 2px;" title="Software: $($DomainStat.Software)"></div>
                                <div style="width: 20px; height: $($PatchesHeight)px; background: #ffc107; border-radius: 2px;" title="Patches: $($DomainStat.Patches)"></div>
                            </div>
                            <div style="font-size: 0.8rem; color: #666; text-align: center; max-width: 80px; word-wrap: break-word;">$($DomainStat.Name)</div>
                        </div>
"@
    }

    $ChartsHTML += @"
                    </div>
                    <div style="display: flex; justify-content: center; gap: 1rem; margin-top: 1rem; font-size: 0.8rem;">
                        <div style="display: flex; align-items: center; gap: 0.5rem;"><div style="width: 12px; height: 12px; background: #007bff; border-radius: 2px;"></div>Servers</div>
                        <div style="display: flex; align-items: center; gap: 0.5rem;"><div style="width: 12px; height: 12px; background: #28a745; border-radius: 2px;"></div>Software</div>
                        <div style="display: flex; align-items: center; gap: 0.5rem;"><div style="width: 12px; height: 12px; background: #ffc107; border-radius: 2px;"></div>Patches</div>
                    </div>
                </div>

                <!-- OS Version Distribution -->
                <div class="chart-container" style="background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h4 style="margin: 0 0 1rem 0; color: #333; text-align: center;">OS Version Distribution</h4>
                    <div class="pie-chart" style="position: relative; width: 200px; height: 200px; margin: 0 auto;">
"@

    # Generate pie chart for OS versions
    $OSTotal = ($ChartData.OSVersions.Values | Measure-Object -Sum).Sum
    if ($OSTotal -gt 0) {
        $StartAngle = 0
        $Colors = @("#007bff", "#28a745", "#ffc107", "#dc3545", "#6f42c1", "#fd7e14", "#20c997")
        $ColorIndex = 0
        
        foreach ($OS in $ChartData.OSVersions.GetEnumerator()) {
            $Percentage = ($OS.Value / $OSTotal) * 100
            $Angle = ($OS.Value / $OSTotal) * 360
            $EndAngle = $StartAngle + $Angle
            
            $Color = $Colors[$ColorIndex % $Colors.Length]
            $ColorIndex++
            
            $ChartsHTML += @"
                        <div class="pie-slice" style="position: absolute; width: 200px; height: 200px; border-radius: 50%; background: conic-gradient(from ${StartAngle}deg, $Color 0deg, $Color ${Angle}deg, transparent ${Angle}deg); clip-path: polygon(50% 50%, 50% 0%, 100% 0%, 100% 100%, 0% 100%, 0% 0%, 50% 0%);"></div>
"@
            $StartAngle = $EndAngle
        }
        
        $ChartsHTML += @"
                        <div class="pie-center" style="position: absolute; top: 60px; left: 60px; width: 80px; height: 80px; border-radius: 50%; background: white; display: flex; align-items: center; justify-content: center; font-size: 0.8rem; color: #666;">OS Versions</div>
"@
    }

    $ChartsHTML += @"
                    </div>
                    <div class="pie-legend" style="margin-top: 1rem; font-size: 0.8rem;">
"@

    # Add OS version legend
    $ColorIndex = 0
    foreach ($OS in $ChartData.OSVersions.GetEnumerator()) {
        $Color = $Colors[$ColorIndex % $Colors.Length]
        $ColorIndex++
        $ChartsHTML += @"
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
                            <div style="width: 12px; height: 12px; background: $Color; border-radius: 2px;"></div>
                            <span>$($OS.Key) ($($OS.Value))</span>
                        </div>
"@
    }

    $ChartsHTML += @"
                    </div>
                </div>

                <!-- Agent Status Donut Chart -->
                <div class="chart-container" style="background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h4 style="margin: 0 0 1rem 0; color: #333; text-align: center;">Critical Agents Status</h4>
                    <div class="donut-chart" style="position: relative; width: 200px; height: 200px; margin: 0 auto;">
"@

    # Generate donut chart for agent status
    $AgentTotal = $ChartData.AgentStatus.Installed + $ChartData.AgentStatus.NotInstalled
    if ($AgentTotal -gt 0) {
        $InstalledPercentage = ($ChartData.AgentStatus.Installed / $AgentTotal) * 360
        $NotInstalledPercentage = ($ChartData.AgentStatus.NotInstalled / $AgentTotal) * 360
        
        $ChartsHTML += @"
                        <div class="donut-background" style="width: 200px; height: 200px; border-radius: 50%; background: conic-gradient(from 0deg, #28a745 0deg, #28a745 ${InstalledPercentage}deg, #dc3545 ${InstalledPercentage}deg, #dc3545 360deg); position: relative;">
                            <div class="donut-inner" style="width: 120px; height: 120px; border-radius: 50%; background: white; position: absolute; top: 40px; left: 40px; display: flex; align-items: center; justify-content: center; flex-direction: column;">
                                <div style="font-size: 1.5rem; font-weight: bold; color: #333;">$AgentTotal</div>
                                <div style="font-size: 0.8rem; color: #666;">Total Agents</div>
                            </div>
                        </div>
"@
    }

    $ChartsHTML += @"
                    </div>
                    <div style="display: flex; justify-content: center; gap: 1rem; margin-top: 1rem; font-size: 0.8rem;">
                        <div style="display: flex; align-items: center; gap: 0.5rem;"><div style="width: 12px; height: 12px; background: #28a745; border-radius: 2px;"></div>Installed ($($ChartData.AgentStatus.Installed))</div>
                        <div style="display: flex; align-items: center; gap: 0.5rem;"><div style="width: 12px; height: 12px; background: #dc3545; border-radius: 2px;"></div>Not Installed ($($ChartData.AgentStatus.NotInstalled))</div>
                    </div>
                </div>

            </div>
        </div>
"@

    # Generate the complete HTML content
    $HTMLContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Compliance Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        
        .header {
            background: linear-gradient(135deg, #0078d4, #106ebe);
            color: white;
            padding: 2rem;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            font-weight: 300;
        }
        
        .header-info {
            display: flex;
            justify-content: center;
            gap: 2rem;
            flex-wrap: wrap;
        }
        
        .header-badge {
            background: rgba(255, 255, 255, 0.2);
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.9rem;
            backdrop-filter: blur(10px);
        }
        
        .summary-section {
            padding: 2rem;
            background: white;
            margin: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .summary-card {
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #0078d4;
            transition: transform 0.2s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-2px);
        }
        
        .summary-card h3 {
            color: #0078d4;
            font-size: 1rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .summary-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            color: #333;
            margin-bottom: 0.5rem;
        }
        
        .summary-card .label {
            color: #6c757d;
            font-size: 0.9rem;
        }
        
        .compliance-score {
            text-align: center;
            padding: 2rem;
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            border-radius: 8px;
            border-left: 4px solid #28a745;
        }
        
        .compliance-value {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .compliance-good { color: #28a745; }
        .compliance-warning { color: #ffc107; }
        .compliance-danger { color: #dc3545; }
        
        .filter-section {
            margin: 2rem;
            padding: 1rem 1.5rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .filter-section label {
            font-weight: 600;
            color: #495057;
        }
        
        .filter-section select {
            padding: 0.5rem 1rem;
            border: 1px solid #ced4da;
            border-radius: 4px;
            background: white;
            font-size: 1rem;
            min-width: 200px;
        }
        
        .filter-section button {
            padding: 0.5rem 1rem;
            background: #6c757d;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
            transition: background-color 0.2s ease;
        }
        
        .filter-section button:hover {
            background: #5a6268;
        }
        
        .nav-tabs {
            display: flex;
            background: white;
            margin: 0 2rem;
            border-radius: 8px 8px 0 0;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            overflow-x: auto;
        }
        
        .nav-tab {
            padding: 1rem 1.5rem;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.3s ease;
            white-space: nowrap;
            font-weight: 500;
            color: #6c757d;
        }
        
        .nav-tab:hover {
            background: #f8f9fa;
            color: #495057;
        }
        
        .nav-tab.active {
            color: #0078d4;
            border-bottom-color: #0078d4;
            background: #f8f9fa;
        }
        
        .content {
            background: white;
            margin: 0 2rem 2rem 2rem;
            border-radius: 0 0 8px 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            min-height: 500px;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .table-container {
            overflow-x: auto;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        
        .data-table th {
            background: #f8f9fa;
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        .data-table th.sortable {
            cursor: pointer;
            user-select: none;
            position: relative;
        }
        
        .data-table th.sortable:hover {
            background: #e9ecef;
        }
        
        .sort-arrow {
            margin-left: 0.5rem;
            font-size: 0.8rem;
            color: #6c757d;
        }
        
        .sort-arrow.asc::after {
            content: "▲";
            color: #0078d4;
        }
        
        .sort-arrow.desc::after {
            content: "▼";
            color: #0078d4;
        }
        
        .data-table td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid #dee2e6;
            vertical-align: top;
        }
        
        .data-table tr:hover {
            background: #f8f9fa;
        }
        
        .data-table tr.filtered-out {
            display: none;
        }
        
        .data-table tr.search-hidden {
            display: none;
        }
        
        .status-compliant {
            color: #28a745;
            font-weight: 600;
        }
        
        .status-non-compliant {
            color: #dc3545;
            font-weight: 600;
        }
        
        .status-warning {
            color: #ffc107;
            font-weight: 600;
        }
        
        .status-unknown {
            color: #6c757d;
            font-weight: 600;
        }
        
        /* Download links */
        .download-link {
            color: #0078d4;
            text-decoration: none;
            font-weight: 600;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            transition: background-color 0.2s ease;
        }
        
        .download-link:hover {
            background-color: #f8f9fa;
            text-decoration: underline;
        }
        
        /* Section headers */
        .section-header {
            background: #f8f9fa;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #dee2e6;
            font-weight: 600;
            color: #495057;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .search-container {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .search-container input {
            padding: 0.5rem;
            border: 1px solid #ced4da;
            border-radius: 4px;
            font-size: 0.9rem;
            width: 250px;
        }
        
        .search-container button {
            padding: 0.5rem 1rem;
            background: #6c757d;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
        }
        
        .search-container button:hover {
            background: #5a6268;
        }
        
        /* Easter Egg Modal */
        .easter-egg-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 10000;
            justify-content: center;
            align-items: center;
        }
        
        .easter-egg-content {
            background: linear-gradient(135deg, #6a4c93, #9b59b6, #8e44ad);
            border-radius: 20px;
            padding: 3rem;
            text-align: center;
            color: white;
            max-width: 500px;
            width: 90%;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            animation: easterEggFadeIn 0.5s ease-out;
        }
        
        @keyframes easterEggFadeIn {
            from {
                opacity: 0;
                transform: scale(0.8) translateY(-50px);
            }
            to {
                opacity: 1;
                transform: scale(1) translateY(0);
            }
        }
        
        .easter-egg-title {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 2rem;
            color: #00d4ff;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        
        .easter-egg-building {
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        
        .easter-egg-section {
            margin-bottom: 1.5rem;
        }
        
        .easter-egg-label {
            font-size: 1rem;
            font-weight: 600;
            color: #00ff88;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }
        
        .easter-egg-value {
            font-size: 1.2rem;
            font-weight: 400;
            color: white;
        }
        
        .easter-egg-close {
            background: linear-gradient(135deg, #00ff88, #00d4ff);
            color: #333;
            border: none;
            padding: 1rem 2rem;
            border-radius: 25px;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
            margin-top: 2rem;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);
        }
        
        .easter-egg-close:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 212, 255, 0.4);
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .header {
                padding: 1rem;
            }
            
            .header h1 {
                font-size: 1.5rem;
            }
            
            .header-info {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .summary-cards {
                grid-template-columns: 1fr;
            }
            
            .nav-tabs {
                margin: 0.5rem;
            }
            
            .content {
                margin: 0.5rem;
            }
            
            .filter-section {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }
            
            .search-container {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .search-container input {
                width: 100%;
            }
            
            .easter-egg-content {
                padding: 2rem;
                margin: 1rem;
            }
            
            .easter-egg-title {
                font-size: 2rem;
            }
            
            .charts-grid {
                grid-template-columns: 1fr !important;
            }
        }
    </style>
</head>
<body>
    <!-- Easter Egg Modal -->
    <div id="easterEggModal" class="easter-egg-modal">
        <div class="easter-egg-content">
            <div class="easter-egg-building">🏢</div>
            <div class="easter-egg-title">AD DASHBOARD</div>
            
            <div class="easter-egg-section">
                <div class="easter-egg-label">💻 Solution Developed By:</div>
                <div class="easter-egg-value">Sendhil Kumar V</div>
            </div>
            
            <div class="easter-egg-section">
                <div class="easter-egg-label">👨‍💼 Product Owner:</div>
                <div class="easter-egg-value">Graeme Lorimer</div>
            </div>
            
            <div class="easter-egg-section">
                <div class="easter-egg-label">👔 Team Manager:</div>
                <div class="easter-egg-value">Richard Anderson</div>
            </div>
            
            <div class="easter-egg-section">
                <div class="easter-egg-label">📧 Contact:</div>
                <div class="easter-egg-value">SecurityServicesDirectoryServicesAll@rbos.co.uk</div>
            </div>
            
            <button class="easter-egg-close" onclick="closeEasterEgg()">✨ CLOSE</button>
        </div>
    </div>

    <div class="header">
        <h1>Enterprise Compliance Dashboard</h1>
        <div class="header-info">
            <div class="header-badge">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
            <div class="header-badge">Last Updated: $($SummaryStats.LastUpdated)</div>
            <div class="header-badge">Domains: $($SummaryStats.TotalDomains)</div>
            <div class="header-badge">Version: $ScriptVersion</div>
        </div>
    </div>

    <div class="summary-section">
        <div class="summary-cards">
            <div class="summary-card">
                <h3>Total Domains</h3>
                <div class="value">$($SummaryStats.TotalDomains)</div>
                <div class="label">Active Domains</div>
            </div>
            <div class="summary-card">
                <h3>Total Servers</h3>
                <div class="value">$($SummaryStats.TotalServers)</div>
                <div class="label">Domain Controllers</div>
            </div>
            <div class="summary-card">
                <h3>Software Packages</h3>
                <div class="value">$($SummaryStats.TotalSoftwarePackages)</div>
                <div class="label">Installed Applications</div>
            </div>
            <div class="summary-card">
                <h3>Patches</h3>
                <div class="value">$($SummaryStats.TotalPatches)</div>
                <div class="label">Security Updates</div>
            </div>
        </div>
        
        <div class="compliance-score">
            <h3 style="margin-bottom: 1rem; color: #0078d4;">Overall Compliance Score</h3>
            <div class="compliance-value $(if ($SummaryStats.CompliancePercentage -ge 80) { 'compliance-good' } elseif ($SummaryStats.CompliancePercentage -ge 60) { 'compliance-warning' } else { 'compliance-danger' })">$($SummaryStats.CompliancePercentage)%</div>
        </div>
        
        $ChartsHTML
    </div>

    <div class="filter-section">
        <label for="domainFilter">Filter by Domain:</label>
        <select id="domainFilter" onchange="filterByDomain()">
            $DomainOptions
        </select>
        <button onclick="clearFilter()">🔄 Show All</button>
    </div>

    <div class="nav-tabs">
        <div class="nav-tab active" onclick="showTab('overview')">Overview</div>
        <div class="nav-tab" onclick="showTab('domain-controllers')">Domain Controllers</div>
        <div class="nav-tab" onclick="showTab('software')">Software Inventory</div>
        <div class="nav-tab" onclick="showTab('patches')">Patch Status</div>
        <div class="nav-tab" onclick="showTab('agents')">Critical Agents</div>
        <div class="nav-tab" onclick="showTab('system-info')">System Information</div>
        <div class="nav-tab" onclick="showTab('hardware')">Hardware</div>
        $DownloadsTab
    </div>

    <div class="content">
        <!-- Overview Tab -->
        <div id="overview" class="tab-content active">
            <div class="section-header">
                <span>Domain Summary</span>
                <div class="search-container">
                    <input type="text" id="overview-search" placeholder="Search domains..." onkeyup="searchTable('overview-table')">
                    <button onclick="clearSearch('overview-search')">Clear</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="overview-table">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('overview-table', 0)">Domain Name <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('overview-table', 1)">Servers <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('overview-table', 2)">Software Packages <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('overview-table', 3)">Patches <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('overview-table', 4)">Compliance Score <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('overview-table', 5)">Last Updated <span class="sort-arrow"></span></th>
                        </tr>
                    </thead>
                    <tbody>
                        $DomainSummaryRows
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Domain Controllers Tab -->
        <div id="domain-controllers" class="tab-content">
            <div class="section-header">
                <span>Domain Controllers</span>
                <div class="search-container">
                    <input type="text" id="domain-controllers-search" placeholder="Search domain controllers..." onkeyup="searchTable('domain-controllers-table')">
                    <button onclick="clearSearch('domain-controllers-search')">Clear</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="domain-controllers-table">
                    <thead>
                        <tr>
                            $DomainControllersHeaders
                        </tr>
                    </thead>
                    <tbody>
                        $DomainControllersRows
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Software Inventory Tab -->
        <div id="software" class="tab-content">
            <div class="section-header">
                <span>Software Inventory</span>
                <div class="search-container">
                    <input type="text" id="software-search" placeholder="Search software..." onkeyup="searchTable('software-table')">
                    <button onclick="clearSearch('software-search')">Clear</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="software-table">
                    <thead>
                        <tr>
                            $SoftwareHeaders
                        </tr>
                    </thead>
                    <tbody>
                        $SoftwareRows
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Patches Tab -->
        <div id="patches" class="tab-content">
            <div class="section-header">
                <span>Patch Status</span>
                <div class="search-container">
                    <input type="text" id="patches-search" placeholder="Search patches..." onkeyup="searchTable('patches-table')">
                    <button onclick="clearSearch('patches-search')">Clear</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="patches-table">
                    <thead>
                        <tr>
                            $PatchHeaders
                        </tr>
                    </thead>
                    <tbody>
                        $PatchRows
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Critical Agents Tab -->
        <div id="agents" class="tab-content">
            <div class="section-header">
                <span>Critical Agents</span>
                <div class="search-container">
                    <input type="text" id="agents-search" placeholder="Search agents..." onkeyup="searchTable('agents-table')">
                    <button onclick="clearSearch('agents-search')">Clear</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="agents-table">
                    <thead>
                        <tr>
                            $AgentsHeaders
                        </tr>
                    </thead>
                    <tbody>
                        $AgentsRows
                    </tbody>
                </table>
            </div>
        </div>

        <!-- System Information Tab -->
        <div id="system-info" class="tab-content">
            <div class="section-header">
                <span>System Information</span>
                <div class="search-container">
                    <input type="text" id="system-info-search" placeholder="Search system info..." onkeyup="searchTable('system-info-table')">
                    <button onclick="clearSearch('system-info-search')">Clear</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="system-info-table">
                    <thead>
                        <tr>
                            $SystemInfoHeaders
                        </tr>
                    </thead>
                    <tbody>
                        $SystemInfoRows
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Hardware Tab -->
        <div id="hardware" class="tab-content">
            <div class="section-header">
                <span>Hardware Information</span>
                <div class="search-container">
                    <input type="text" id="hardware-search" placeholder="Search hardware..." onkeyup="searchTable('hardware-table')">
                    <button onclick="clearSearch('hardware-search')">Clear</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="hardware-table">
                    <thead>
                        <tr>
                            $HardwareHeaders
                        </tr>
                    </thead>
                    <tbody>
                        $HardwareRows
                    </tbody>
                </table>
            </div>
        </div>

        $DownloadsContent
    </div>

    <script>
        // Global variables
        let sortDirections = {};
        let easterEggSequence = '';
        let easterEggTimeout;
        
        // Tab functionality
        function showTab(tabName) {
            // Hide all tab contents
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.nav-tab');
            tabs.forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            const selectedTab = document.getElementById(tabName);
            if (selectedTab) {
                selectedTab.classList.add('active');
            }
            
            // Add active class to clicked tab
            const clickedTab = event.target;
            clickedTab.classList.add('active');
        }
        
        // Domain filtering
        function filterByDomain() {
            const selectedDomain = document.getElementById('domainFilter').value;
            const allRows = document.querySelectorAll('[data-domain]');
            
            allRows.forEach(row => {
                if (selectedDomain === 'all' || row.getAttribute('data-domain') === selectedDomain) {
                    row.classList.remove('filtered-out');
                } else {
                    row.classList.add('filtered-out');
                }
            });
        }
        
        function clearFilter() {
            document.getElementById('domainFilter').value = 'all';
            filterByDomain();
        }
        
        // Table sorting
        function sortTable(tableId, columnIndex) {
            const table = document.getElementById(tableId);
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const header = table.querySelectorAll('th')[columnIndex];
            const sortArrow = header.querySelector('.sort-arrow');
            
            // Clear all other sort arrows
            table.querySelectorAll('.sort-arrow').forEach(arrow => {
                if (arrow !== sortArrow) {
                    arrow.className = 'sort-arrow';
                }
            });
            
            // Determine sort direction
            const currentDirection = sortDirections[tableId + '-' + columnIndex] || 'asc';
            const newDirection = currentDirection === 'asc' ? 'desc' : 'asc';
            sortDirections[tableId + '-' + columnIndex] = newDirection;
            
            // Update sort arrow
            sortArrow.className = 'sort-arrow ' + newDirection;
            
            // Sort rows
            rows.sort((a, b) => {
                const aCell = a.cells[columnIndex];
                const bCell = b.cells[columnIndex];
                
                if (!aCell || !bCell) return 0;
                
                let aValue = aCell.textContent.trim();
                let bValue = bCell.textContent.trim();
                
                // Handle numeric values
                const aNum = parseFloat(aValue.replace(/[^0-9.-]/g, ''));
                const bNum = parseFloat(bValue.replace(/[^0-9.-]/g, ''));
                
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return newDirection === 'asc' ? aNum - bNum : bNum - aNum;
                }
                
                // Handle date values
                const aDate = new Date(aValue);
                const bDate = new Date(bValue);
                
                if (!isNaN(aDate.getTime()) && !isNaN(bDate.getTime())) {
                    return newDirection === 'asc' ? aDate - bDate : bDate - aDate;
                }
                
                // Handle text values
                const comparison = aValue.localeCompare(bValue);
                return newDirection === 'asc' ? comparison : -comparison;
            });
            
            // Reorder rows in DOM
            rows.forEach(row => tbody.appendChild(row));
        }
        
        // Table searching
        function searchTable(tableId) {
            const searchId = tableId.replace('-table', '-search');
            const searchInput = document.getElementById(searchId);
            const table = document.getElementById(tableId);
            const rows = table.querySelectorAll('tbody tr');
            const searchTerm = searchInput.value.toLowerCase();
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    row.classList.remove('search-hidden');
                } else {
                    row.classList.add('search-hidden');
                }
            });
        }
        
        function clearSearch(searchId) {
            const searchInput = document.getElementById(searchId);
            searchInput.value = '';
            
            const tableId = searchId.replace('-search', '-table');
            const table = document.getElementById(tableId);
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                row.classList.remove('search-hidden');
            });
        }
        
        // Easter egg functionality
        function showEasterEgg() {
            const modal = document.getElementById('easterEggModal');
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
        
        function closeEasterEgg() {
            const modal = document.getElementById('easterEggModal');
            modal.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
        
        // Easter egg keypress detection
        document.addEventListener('keypress', function(e) {
            const char = e.key.toLowerCase();
            easterEggSequence += char;
            
            // Clear timeout if exists
            if (easterEggTimeout) {
                clearTimeout(easterEggTimeout);
            }
            
            // Set timeout to reset sequence after 2 seconds of inactivity
            easterEggTimeout = setTimeout(() => {
                easterEggSequence = '';
            }, 2000);
            
            // Check if sequence contains "ad"
            if (easterEggSequence.includes('ad')) {
                showEasterEgg();
                easterEggSequence = ''; // Reset sequence
            }
            
            // Keep sequence length manageable
            if (easterEggSequence.length > 10) {
                easterEggSequence = easterEggSequence.slice(-10);
            }
        });
        
        // Close easter egg when clicking outside
        document.getElementById('easterEggModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeEasterEgg();
            }
        });
        
        // Close easter egg with Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeEasterEgg();
            }
        });
        
        // Initialize search functionality
        document.addEventListener('DOMContentLoaded', function() {
            // Add event listeners for Enter key on search boxes
            const searchBoxes = document.querySelectorAll('input[id$="-search"]');
            searchBoxes.forEach(box => {
                box.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        const tableId = this.id.replace('-search', '-table');
                        searchTable(tableId);
                    }
                });
            });
        });
    </script>
</body>
</html>
"@

    # Write HTML file
    try {
        $HTMLContent | Out-File -FilePath $OutputFilePath -Encoding UTF8
        Write-Log "HTML dashboard generated: $OutputFilePath" -Level "SUCCESS"
        return $OutputFilePath
    } catch {
        Write-Log "Error writing HTML file: $_" -Level "ERROR"
        throw
    }
}

# Main execution
try {
    Write-Log "=== Enterprise Compliance Dashboard Generator (Final with CSV Downloads, Easter Egg & Charts) Started ===" -Level "SUCCESS"
    Write-Log "Script Version: $ScriptVersion"
    Write-Log "User: $CurrentUser"
    Write-Log "Computer: $ComputerName"
    Write-Log "Reports Path: $ReportsPath"
    Write-Log "Output Path: $OutputPath"
    Write-Log "CSV Downloads: $CreateDownloadLinks"
    
    # Create output directory
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Log "Created output directory: $OutputPath" -Level "SUCCESS"
    }
    
    # Scan for domain folders
    $DomainFolders = Get-DomainFolders -BasePath $ReportsPath
    
    if ($DomainFolders.Count -eq 0) {
        Write-Log "No domain folders found in $ReportsPath" -Level "ERROR"
        Write-Log "Please ensure the data collection script has been run and CSV files exist." -Level "ERROR"
        exit 1
    }
    
    # Process each domain
    $AllDomainData = @()
    
    foreach ($DomainFolder in $DomainFolders) {
        $DomainData = Get-LatestCSVFiles -DomainPath $DomainFolder.FullName -DomainName $DomainFolder.Name
        
        if ($DomainData.Files.Count -gt 0) {
            Load-CSVData -DomainData $DomainData
            $AllDomainData += $DomainData
        } else {
            Write-Log "No CSV files found for domain: $($DomainFolder.Name)" -Level "WARNING"
        }
    }
    
    if ($AllDomainData.Count -eq 0) {
        Write-Log "No valid domain data found" -Level "ERROR"
        exit 1
    }
    
    # Calculate summary statistics
    $SummaryStats = Calculate-SummaryStats -AllDomainData $AllDomainData
    
    # Generate HTML dashboard
    $DashboardPath = Join-Path -Path $OutputPath -ChildPath $DashboardName
    $GeneratedDashboard = Generate-HTMLDashboard -AllDomainData $AllDomainData -SummaryStats $SummaryStats -OutputFilePath $DashboardPath
    
    # Open dashboard if requested
    if ($OpenDashboard -and (Test-Path -Path $GeneratedDashboard)) {
        Write-Log "Opening dashboard in default browser..." -Level "SUCCESS"
        try {
            Start-Process $GeneratedDashboard
        } catch {
            Write-Log "Could not auto-open browser. Please manually open: $GeneratedDashboard" -Level "WARNING"
        }
    }
    
    $EndTime = Get-Date
    $Duration = $EndTime - $StartTime
    $DurationString = "{0:D2}:{1:D2}:{2:D2}" -f $Duration.Hours, $Duration.Minutes, $Duration.Seconds
    
    Write-Log "=== Dashboard Generation Completed Successfully ===" -Level "SUCCESS"
    Write-Log "Dashboard saved to: $GeneratedDashboard" -Level "SUCCESS"
    Write-Log "CSV Downloads enabled: $CreateDownloadLinks" -Level "SUCCESS"
    Write-Log "Easter egg included: Type 'AD' anywhere on the dashboard! 🎉" -Level "SUCCESS"
    Write-Log "Charts included: Compliance gauge, domain comparison, OS distribution, agent status" -Level "SUCCESS"
    Write-Log "Execution time: $DurationString"
    Write-Log "Domains processed: $($AllDomainData.Count)"
    Write-Log "Total servers: $($SummaryStats.TotalServers)"
    Write-Log "Total software packages: $($SummaryStats.TotalSoftwarePackages)"
    Write-Log "Total patches: $($SummaryStats.TotalPatches)"
    Write-Log "Overall compliance: $($SummaryStats.CompliancePercentage)%"
    
} catch {
    Write-Log "Error in dashboard generation: $_" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}
