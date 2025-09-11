# Enterprise Compliance Dashboard Generator - Final Version with CSV Downloads
# Scans CSV reports and generates static HTML dashboard with search, sorting, and CSV download capabilities
# Version: 8.0
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
$ScriptVersion = "8.0"
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
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "IsRunning" -Value (Get-SafeProperty $Record "IsRunning")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "RegistryFound" -Value (Get-SafeProperty $Record "RegistryFound")
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "HealthStatus" -Value (Get-SafeProperty $Record "HealthStatus")
                    }
                    default {
                        # For other CSV types, copy all properties
                        foreach ($Property in $Record.PSObject.Properties) {
                            $CleanedRecord | Add-Member -MemberType NoteProperty -Name $Property.Name -Value (Get-SafeProperty $Record $Property.Name)
                        }
                    }
                }
                
                $CleanedData += $CleanedRecord
            }
            
            # Limit records if specified
            if ($MaxRecordsPerTable -gt 0 -and $CleanedData.Count -gt $MaxRecordsPerTable) {
                $CleanedData = $CleanedData | Select-Object -First $MaxRecordsPerTable
                Write-Log "Limited to $MaxRecordsPerTable records for $CSVType" -Level "WARNING"
            }
            
            $DomainData.Data[$CSVType] = $CleanedData
            Write-Log "Loaded $($CleanedData.Count) records from $CSVType" -Level "SUCCESS"
            
        } catch {
            Write-Log "Error loading $CSVType data: $_" -Level "ERROR"
            $DomainData.Data[$CSVType] = @()
        }
    }
}

# Function to calculate summary statistics
function Calculate-SummaryStats {
    param([array]$AllDomainData)
    
    Write-Log "Calculating summary statistics"
    
    $Stats = @{
        TotalDomains = $AllDomainData.Count
        TotalServers = 0
        TotalSoftwarePackages = 0
        TotalPatches = 0
        TotalCriticalAgents = 0
        CompliancePercentage = 0
        LastUpdated = $null
        DomainStats = @()
        DomainList = @()
    }
    
    foreach ($Domain in $AllDomainData) {
        $DomainStat = [PSCustomObject]@{
            DomainName = $Domain.DomainName
            ServerCount = 0
            SoftwareCount = 0
            PatchCount = 0
            AgentCount = 0
            ComplianceScore = 0
            LastUpdated = if ($Domain.LastUpdated) { $Domain.LastUpdated.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
        }
        
        # Add to domain list for dropdown
        $Stats.DomainList += $Domain.DomainName
        
        # Count unique servers - prioritize DomainControllers as the primary source
        $ServerNames = @()
        
        # First, get servers from DomainControllers (most reliable source)
        if ($Domain.Data.ContainsKey("DomainControllers") -and $Domain.Data["DomainControllers"].Count -gt 0) {
            $ServerNames += $Domain.Data["DomainControllers"] | ForEach-Object { 
                $name = $_.ComputerName
                if ([string]::IsNullOrWhiteSpace($name) -or $name -eq "N/A") {
                    $_.HostName  # Fallback to HostName if ComputerName is empty
                } else {
                    $name
                }
            }
        }
        
        # If no domain controllers found, try SystemInformation
        if ($ServerNames.Count -eq 0 -and $Domain.Data.ContainsKey("SystemInformation")) {
            $ServerNames += $Domain.Data["SystemInformation"] | ForEach-Object { $_.ComputerName }
        }
        
        # If still no servers, try HardwareInfo
        if ($ServerNames.Count -eq 0 -and $Domain.Data.ContainsKey("HardwareInfo")) {
            $ServerNames += $Domain.Data["HardwareInfo"] | ForEach-Object { $_.ComputerName }
        }
        
        # Clean and normalize server names for proper uniqueness
        $CleanServerNames = @()
        foreach ($name in $ServerNames) {
            if (-not [string]::IsNullOrWhiteSpace($name) -and $name -ne "N/A") {
                # Normalize the name (remove domain suffix, convert to uppercase for comparison)
                $cleanName = $name.Trim().Split('.')[0].ToUpper()
                $CleanServerNames += $cleanName
            }
        }
        
        $UniqueServers = $CleanServerNames | Sort-Object -Unique
        $DomainStat.ServerCount = $UniqueServers.Count
        
        # Count software packages
        if ($Domain.Data.ContainsKey("SoftwareInventory")) {
            $DomainStat.SoftwareCount = $Domain.Data["SoftwareInventory"].Count
        }
        
        # Count patches
        if ($Domain.Data.ContainsKey("PatchInventory")) {
            $DomainStat.PatchCount = $Domain.Data["PatchInventory"].Count
        }
        
        # Count critical agents and calculate compliance
        if ($Domain.Data.ContainsKey("CriticalAgents")) {
            $DomainStat.AgentCount = $Domain.Data["CriticalAgents"].Count
            
            # Calculate compliance score based on installed agents
            $CompliantAgents = $Domain.Data["CriticalAgents"] | Where-Object { 
                $_.Status -eq "Installed" -or $_.IsInstalled -eq "Installed" -or $_.Status -eq "Running" -or $_.HealthStatus -eq "Healthy"
            }
            if ($Domain.Data["CriticalAgents"].Count -gt 0) {
                $DomainStat.ComplianceScore = [math]::Round(($CompliantAgents.Count / $Domain.Data["CriticalAgents"].Count) * 100, 2)
            }
        }
        
        # Update totals
        $Stats.TotalServers += $DomainStat.ServerCount
        $Stats.TotalSoftwarePackages += $DomainStat.SoftwareCount
        $Stats.TotalPatches += $DomainStat.PatchCount
        $Stats.TotalCriticalAgents += $DomainStat.AgentCount
        
        # Update last updated time
        if (-not $Stats.LastUpdated -or ($Domain.LastUpdated -and $Domain.LastUpdated -gt $Stats.LastUpdated)) {
            $Stats.LastUpdated = $Domain.LastUpdated
        }
        
        $Stats.DomainStats += $DomainStat
    }
    
    # Calculate overall compliance percentage
    if ($Stats.DomainStats.Count -gt 0) {
        $WeightedCompliance = 0
        $TotalWeight = 0
        
        foreach ($DomainStat in $Stats.DomainStats) {
            if ($DomainStat.AgentCount -gt 0) {
                $Weight = $DomainStat.AgentCount
                $WeightedCompliance += $DomainStat.ComplianceScore * $Weight
                $TotalWeight += $Weight
            }
        }
        
        if ($TotalWeight -gt 0) {
            $Stats.CompliancePercentage = [math]::Round($WeightedCompliance / $TotalWeight, 2)
        }
    }
    
    return $Stats
}

# Function to generate download links section
function Generate-DownloadLinksSection {
    param(
        [array]$AllDomainData,
        [string]$DashboardPath
    )
    
    if (-not $CreateDownloadLinks) {
        return ""
    }
    
    Write-Log "Generating CSV download links"
    
    $DownloadSection = @"
        <!-- CSV Downloads Tab -->
        <div id="downloads" class="tab-content">
            <div class="section-header">
                <span>CSV Downloads</span>
                <div class="search-container">
                    <input type="text" id="downloads-search" placeholder="Search downloads..." onkeyup="searchTable('downloads-table')">
                    <button onclick="clearSearch('downloads-search')">Clear</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="downloads-table">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('downloads-table', 0)">Domain <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('downloads-table', 1)">Report Type <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('downloads-table', 2)">File Name <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('downloads-table', 3)">File Size <span class="sort-arrow"></span></th>
                            <th class="sortable" onclick="sortTable('downloads-table', 4)">Last Modified <span class="sort-arrow"></span></th>
                            <th>Download</th>
                        </tr>
                    </thead>
                    <tbody>
"@
    
    foreach ($Domain in $AllDomainData) {
        foreach ($CSVType in $Domain.DownloadLinks.Keys) {
            $FilePath = $Domain.DownloadLinks[$CSVType]
            
            if (Test-Path -Path $FilePath) {
                $FileInfo = Get-Item -Path $FilePath
                $RelativePath = Get-RelativePath -FromPath $DashboardPath -ToPath $FilePath
                $FileSize = [math]::Round($FileInfo.Length / 1KB, 2)
                $LastModified = $FileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                
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
                
                $DownloadSection += @"
                        <tr data-domain="$(Escape-HTML $Domain.DomainName)">
                            <td>$(Escape-HTML $Domain.DomainName)</td>
                            <td>$ReportTypeName</td>
                            <td>$(Escape-HTML $FileInfo.Name)</td>
                            <td>$FileSize KB</td>
                            <td>$LastModified</td>
                            <td><a href="file:///$($FilePath.Replace('\', '/'))" class="download-link" title="Download $(Escape-HTML $FileInfo.Name)">📥 Download</a></td>
                        </tr>
"@
            }
        }
    }
    
    $DownloadSection += @"
                    </tbody>
                </table>
            </div>
            <div style="padding: 1rem; background: #f8f9fa; border-top: 1px solid #dee2e6;">
                <p><strong>Note:</strong> CSV files are downloaded directly from the original source folders. If download links don't work in your browser, you can manually navigate to the file paths shown above.</p>
                <p><strong>Alternative:</strong> Copy the file path and open it directly in Windows Explorer or your preferred file manager.</p>
            </div>
        </div>
"@
    
    return $DownloadSection
}

# Function to generate HTML table with domain filtering and sorting
function Generate-HTMLTable {
    param(
        [array]$Data,
        [string]$TableId,
        [array]$Columns,
        [bool]$IncludeDomainColumn = $true
    )
    
    if ($Data.Count -eq 0) {
        return "<tr><td colspan=`"$($Columns.Count + $(if($IncludeDomainColumn){1}else{0}))`" style=`"text-align: center; padding: 2rem; color: #6c757d;`">No data available</td></tr>"
    }
    
    $TableRows = ""
    
    foreach ($Record in $Data) {
        $TableRows += "<tr data-domain=`"$(Escape-HTML $Record.Domain)`">"
        
        # Add domain column if specified
        if ($IncludeDomainColumn) {
            $TableRows += "<td>$(Escape-HTML $Record.Domain)</td>"
        }
        
        foreach ($Column in $Columns) {
            $Value = Get-SafeProperty $Record $Column
            
            # Apply status styling
            $CellClass = ""
            if ($Column -eq "Status" -or $Column -eq "IsInstalled" -or $Column -eq "ServiceStatus" -or $Column -eq "HealthStatus") {
                if ($Value -match "Online|Installed|Running|True|Compliant|Healthy") {
                    $CellClass = " class=`"status-compliant`""
                } elseif ($Value -match "Offline|Not Installed|Stopped|False|Non-Compliant|Maintenance|Critical") {
                    $CellClass = " class=`"status-non-compliant`""
                } else {
                    $CellClass = " class=`"status-unknown`""
                }
            }
            
            $TableRows += "<td$CellClass>$(Escape-HTML $Value)</td>"
        }
        
        $TableRows += "</tr>"
    }
    
    return $TableRows
}

# Function to generate sortable table headers
function Generate-SortableHeaders {
    param(
        [array]$Columns,
        [string]$TableId,
        [bool]$IncludeDomainColumn = $true
    )
    
    $Headers = ""
    
    if ($IncludeDomainColumn) {
        $Headers += "<th class=`"sortable`" onclick=`"sortTable('$TableId', 0)`">Domain <span class=`"sort-arrow`"></span></th>"
        $ColIndex = 1
    } else {
        $ColIndex = 0
    }
    
    foreach ($Column in $Columns) {
        $DisplayName = switch ($Column) {
            "ComputerName" { "Server Name" }
            "HostName" { "Host Name" }
            "IPAddress" { "IP Address" }
            "OSVersion" { "OS Version" }
            "OSVersionNumber" { "OS Version Number" }
            "DisplayName" { "Software Name" }
            "DisplayVersion" { "Version" }
            "InstallDate" { "Install Date" }
            "HotFixID" { "Patch ID" }
            "InstalledOn" { "Install Date" }
            "InstalledBy" { "Installed By" }
            "AgentName" { "Agent Name" }
            "IsInstalled" { "Installed" }
            "LastCheck" { "Last Check" }
            "ServiceStatus" { "Service Status" }
            "OSName" { "OS Name" }
            "TotalPhysicalMemoryGB" { "Memory (GB)" }
            "LastBootUpTime" { "Last Boot" }
            "ProcessorName" { "CPU" }
            "TotalDiskSpaceGB" { "Disk Space (GB)" }
            "DiskUsagePercent" { "Disk Usage %" }
            default { $Column }
        }
        
        $Headers += "<th class=`"sortable`" onclick=`"sortTable('$TableId', $ColIndex)`">$DisplayName <span class=`"sort-arrow`"></span></th>"
        $ColIndex++
    }
    
    return $Headers
}

# Function to generate HTML dashboard with search, sorting, and CSV downloads
function Generate-HTMLDashboard {
    param(
        [array]$AllDomainData,
        [hashtable]$SummaryStats,
        [string]$OutputFilePath
    )
    
    Write-Log "Generating HTML dashboard with search, sorting, and CSV download capabilities"
    
    # Generate domain options for dropdown
    $DomainOptions = "<option value=`"all`">All Domains</option>"
    foreach ($Domain in $SummaryStats.DomainList) {
        $DomainOptions += "<option value=`"$(Escape-HTML $Domain)`">$(Escape-HTML $Domain)</option>"
    }
    
    # Generate domain summary table
    $DomainSummaryRows = ""
    foreach ($DomainStat in $SummaryStats.DomainStats) {
        $ComplianceClass = if ($DomainStat.ComplianceScore -ge 80) { "status-compliant" } 
                          elseif ($DomainStat.ComplianceScore -ge 60) { "status-unknown" } 
                          else { "status-non-compliant" }
        
        $DomainSummaryRows += @"
<tr data-domain="$(Escape-HTML $DomainStat.DomainName)">
    <td>$(Escape-HTML $DomainStat.DomainName)</td>
    <td>$($DomainStat.ServerCount)</td>
    <td>$($DomainStat.SoftwareCount)</td>
    <td>$($DomainStat.PatchCount)</td>
    <td><span class="$ComplianceClass">$($DomainStat.ComplianceScore)%</span></td>
    <td>$(Escape-HTML $DomainStat.LastUpdated)</td>
</tr>
"@
    }
    
    # Combine all data for each table type
    $AllDomainControllers = @()
    $AllSoftware = @()
    $AllPatches = @()
    $AllAgents = @()
    $AllSystemInfo = @()
    $AllHardware = @()
    
    foreach ($Domain in $AllDomainData) {
        if ($Domain.Data.ContainsKey("DomainControllers")) {
            $AllDomainControllers += $Domain.Data["DomainControllers"]
        }
        if ($Domain.Data.ContainsKey("SoftwareInventory")) {
            $AllSoftware += $Domain.Data["SoftwareInventory"]
        }
        if ($Domain.Data.ContainsKey("PatchInventory")) {
            $AllPatches += $Domain.Data["PatchInventory"]
        }
        if ($Domain.Data.ContainsKey("CriticalAgents")) {
            $AllAgents += $Domain.Data["CriticalAgents"]
        }
        if ($Domain.Data.ContainsKey("SystemInformation")) {
            $AllSystemInfo += $Domain.Data["SystemInformation"]
        }
        if ($Domain.Data.ContainsKey("HardwareInfo")) {
            $AllHardware += $Domain.Data["HardwareInfo"]
        }
    }
    
    # Generate table headers and rows with sorting
    $DomainControllersHeaders = Generate-SortableHeaders -Columns @("ComputerName", "HostName", "IPAddress", "Site", "OSVersion", "OSVersionNumber") -TableId "domain-controllers-table"
    $SoftwareHeaders = Generate-SortableHeaders -Columns @("ComputerName", "DisplayName", "DisplayVersion", "Publisher", "InstallDate", "Source") -TableId "software-table"
    $PatchHeaders = Generate-SortableHeaders -Columns @("ComputerName", "HotFixID", "Description", "Classification", "InstalledOn", "InstalledBy") -TableId "patches-table"
    $AgentsHeaders = Generate-SortableHeaders -Columns @("ComputerName", "AgentName", "Status", "IsInstalled", "Version", "LastCheck", "ServiceStatus") -TableId "agents-table"
    $SystemInfoHeaders = Generate-SortableHeaders -Columns @("ComputerName", "OSName", "OSVersion", "Architecture", "TotalPhysicalMemoryGB", "LastBootUpTime", "Uptime") -TableId "system-info-table"
    $HardwareHeaders = Generate-SortableHeaders -Columns @("ComputerName", "Manufacturer", "Model", "ProcessorName", "TotalPhysicalMemoryGB", "TotalDiskSpaceGB", "DiskUsagePercent") -TableId "hardware-table"
    
    $DomainControllersRows = Generate-HTMLTable -Data $AllDomainControllers -TableId "domain-controllers" -Columns @("ComputerName", "HostName", "IPAddress", "Site", "OSVersion", "OSVersionNumber")
    $SoftwareRows = Generate-HTMLTable -Data $AllSoftware -TableId "software" -Columns @("ComputerName", "DisplayName", "DisplayVersion", "Publisher", "InstallDate", "Source")
    $PatchRows = Generate-HTMLTable -Data $AllPatches -TableId "patches" -Columns @("ComputerName", "HotFixID", "Description", "Classification", "InstalledOn", "InstalledBy")
    $AgentsRows = Generate-HTMLTable -Data $AllAgents -TableId "agents" -Columns @("ComputerName", "AgentName", "Status", "IsInstalled", "Version", "LastCheck", "ServiceStatus")
    $SystemInfoRows = Generate-HTMLTable -Data $AllSystemInfo -TableId "system-info" -Columns @("ComputerName", "OSName", "OSVersion", "Architecture", "TotalPhysicalMemoryGB", "LastBootUpTime", "Uptime")
    $HardwareRows = Generate-HTMLTable -Data $AllHardware -TableId "hardware" -Columns @("ComputerName", "Manufacturer", "Model", "ProcessorName", "TotalPhysicalMemoryGB", "TotalDiskSpaceGB", "DiskUsagePercent")
    
    # Generate CSV downloads section
    $DownloadsSection = Generate-DownloadLinksSection -AllDomainData $AllDomainData -DashboardPath $OutputFilePath
    $DownloadsTab = if ($CreateDownloadLinks) { '<div class="nav-tab" onclick="showTab(''downloads'')">CSV Downloads</div>' } else { '' }
    
    $HTMLContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Compliance Dashboard</title>
    <style>
        /* Reset and Base Styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background-color: #f0f2f5;
            color: #333;
            line-height: 1.6;
        }
        
        /* Header Styles */
        .header {
            background: linear-gradient(135deg, #0078d4, #106ebe);
            color: white;
            padding: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2rem;
            font-weight: 300;
            margin-bottom: 0.5rem;
        }
        
        .header-info {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            font-size: 0.9rem;
            opacity: 0.9;
        }
        
        .header-badge {
            background: rgba(255,255,255,0.2);
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.8rem;
        }
        
        /* Summary Cards */
        .summary-section {
            padding: 2rem;
            background: white;
            margin: 1rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
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
            border-left: 4px solid #0078d4;
            transition: transform 0.2s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .summary-card h3 {
            color: #0078d4;
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.5rem;
        }
        
        .summary-card .value {
            font-size: 2rem;
            font-weight: 700;
            color: #333;
            margin-bottom: 0.25rem;
        }
        
        .summary-card .label {
            color: #666;
            font-size: 0.85rem;
        }
        
        /* Compliance Score */
        .compliance-score {
            text-align: center;
            padding: 2rem;
        }
        
        .compliance-value {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .compliance-good { color: #28a745; }
        .compliance-warning { color: #ffc107; }
        .compliance-danger { color: #dc3545; }
        
        /* Filter and Search Section */
        .filter-section {
            background: white;
            margin: 1rem;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .filter-section label {
            font-weight: 600;
            color: #495057;
        }
        
        .filter-section select, .filter-section input {
            padding: 0.5rem 1rem;
            border: 1px solid #ced4da;
            border-radius: 4px;
            background: white;
            font-size: 0.9rem;
            min-width: 200px;
        }
        
        .filter-section button {
            padding: 0.5rem 1rem;
            background: #0078d4;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: background 0.2s ease;
        }
        
        .filter-section button:hover {
            background: #106ebe;
        }
        
        .search-box {
            position: relative;
        }
        
        .search-box input {
            padding-left: 2.5rem;
        }
        
        .search-box::before {
            content: "🔍";
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            color: #6c757d;
        }
        
        /* Navigation */
        .nav-tabs {
            display: flex;
            background: white;
            margin: 1rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow-x: auto;
        }
        
        .nav-tab {
            padding: 1rem 1.5rem;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            white-space: nowrap;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .nav-tab:hover {
            background-color: #f8f9fa;
        }
        
        .nav-tab.active {
            border-bottom: 3px solid #0078d4;
            color: #0078d4;
            background-color: #f8f9fa;
        }
        
        /* Content */
        .content {
            margin: 1rem;
        }
        
        .tab-content {
            display: none;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .tab-content.active {
            display: block;
        }
        
        /* Tables */
        .table-container {
            padding: 1.5rem;
            overflow-x: auto;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        
        .data-table th {
            background: #f8f9fa;
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            position: sticky;
            top: 0;
            z-index: 10;
            user-select: none;
        }
        
        .data-table th.sortable {
            cursor: pointer;
            transition: background-color 0.2s ease;
        }
        
        .data-table th.sortable:hover {
            background-color: #e9ecef;
        }
        
        .sort-arrow {
            margin-left: 0.5rem;
            font-size: 0.8rem;
            color: #6c757d;
        }
        
        .sort-arrow.asc::after {
            content: "▲";
        }
        
        .sort-arrow.desc::after {
            content: "▼";
        }
        
        .data-table td {
            padding: 0.75rem;
            border-bottom: 1px solid #dee2e6;
            vertical-align: top;
        }
        
        .data-table tr:hover {
            background-color: #f8f9fa;
        }
        
        .data-table tr.filtered-out {
            display: none;
        }
        
        .data-table tr.search-hidden {
            display: none;
        }
        
        /* Status indicators */
        .status-compliant {
            color: #28a745;
            font-weight: 600;
        }
        
        .status-non-compliant {
            color: #dc3545;
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
        }
    </style>
</head>
<body>
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

        $DownloadsSection
    </div>

    <script>
        // Global variables for sorting
        let sortDirections = {};
        
        // Tab navigation
        function showTab(tabName) {
            // Hide all tab contents
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(tab => tab.classList.remove('active'));
            
            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.nav-tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab content
            const selectedTab = document.getElementById(tabName);
            if (selectedTab) {
                selectedTab.classList.add('active');
            }
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }
        
        // Domain filtering
        function filterByDomain() {
            const selectedDomain = document.getElementById('domainFilter').value;
            const allRows = document.querySelectorAll('tbody tr[data-domain]');
            
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
    Write-Log "=== Enterprise Compliance Dashboard Generator (Final with CSV Downloads) Started ===" -Level "SUCCESS"
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
