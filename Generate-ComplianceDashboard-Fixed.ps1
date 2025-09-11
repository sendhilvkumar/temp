# Enterprise Compliance Dashboard Generator - Fixed Version
# Scans CSV reports and generates static HTML dashboard with proper column mapping
# Version: 5.0
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
    [int]$MaxRecordsPerTable = 1000
)

# Script Variables
$ScriptVersion = "5.0"
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
    
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq "Unknown" -or $Value -eq "") {
        return "N/A"
    }
    return $Value.Trim()
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
    }
    
    foreach ($CSVType in $CSVTypes) {
        $CSVFiles = Get-ChildItem -Path $DomainPath -Filter "$CSVType*.csv" | Sort-Object LastWriteTime -Descending
        
        if ($CSVFiles.Count -gt 0) {
            $LatestFile = $CSVFiles[0]
            $DomainData.Files[$CSVType] = $LatestFile.FullName
            
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

# Function to load CSV data with proper column mapping
function Load-CSVData {
    param([hashtable]$DomainData)
    
    Write-Log "Loading CSV data for domain: $($DomainData.DomainName)"
    
    foreach ($CSVType in $DomainData.Files.Keys) {
        $FilePath = $DomainData.Files[$CSVType]
        
        try {
            $RawData = Import-Csv -Path $FilePath -ErrorAction Stop
            
            # Clean and validate data with proper column mapping
            $CleanedData = @()
            foreach ($Record in $RawData) {
                $CleanedRecord = [PSCustomObject]@{}
                
                # Add domain name to each record
                $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Domain" -Value $DomainData.DomainName
                
                # Map columns based on CSV type with proper cleaning
                switch ($CSVType) {
                    "DomainControllers" {
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Clean-DataValue $Record.ComputerName)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value (Clean-DataValue $Record.IPAddress)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "OSVersion" -Value (Clean-DataValue $Record.OSVersion)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Role" -Value (Clean-DataValue $Record.Role)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Status" -Value (Clean-DataValue $Record.Status)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "LastSeen" -Value (Clean-DataValue $Record.LastSeen)
                    }
                    "SoftwareInventory" {
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Clean-DataValue $Record.ComputerName)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value (Clean-DataValue $Record.DisplayName)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value (Clean-DataValue $Record.DisplayVersion)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Publisher" -Value (Clean-DataValue $Record.Publisher)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value (Clean-DataValue $Record.InstallDate)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value (Clean-DataValue $Record.InstallLocation)
                    }
                    "PatchInventory" {
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Clean-DataValue $Record.ComputerName)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "HotFixID" -Value (Clean-DataValue $Record.HotFixID)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Description" -Value (Clean-DataValue $Record.Description)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Classification" -Value (Clean-DataValue $Record.Classification)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "InstalledOn" -Value (Clean-DataValue $Record.InstalledOn)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "InstalledBy" -Value (Clean-DataValue $Record.InstalledBy)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Title" -Value (Clean-DataValue $Record.Title)
                    }
                    "SystemInformation" {
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Clean-DataValue $Record.ComputerName)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "OSName" -Value (Clean-DataValue $Record.OSName)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "OSVersion" -Value (Clean-DataValue $Record.OSVersion)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Architecture" -Value (Clean-DataValue $Record.Architecture)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "TotalPhysicalMemoryGB" -Value (Clean-DataValue $Record.TotalPhysicalMemoryGB)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ProcessorCount" -Value (Clean-DataValue $Record.ProcessorCount)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "LogicalProcessors" -Value (Clean-DataValue $Record.LogicalProcessors)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "LastBootUpTime" -Value (Clean-DataValue $Record.LastBootUpTime)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "SystemType" -Value (Clean-DataValue $Record.SystemType)
                    }
                    "HardwareInfo" {
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Clean-DataValue $Record.ComputerName)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value (Clean-DataValue $Record.Manufacturer)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Model" -Value (Clean-DataValue $Record.Model)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ProcessorName" -Value (Clean-DataValue $Record.ProcessorName)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "TotalPhysicalMemoryGB" -Value (Clean-DataValue $Record.TotalPhysicalMemoryGB)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "TotalDiskSpaceGB" -Value (Clean-DataValue $Record.TotalDiskSpaceGB)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "NetworkAdapters" -Value (Clean-DataValue $Record.NetworkAdapters)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value (Clean-DataValue $Record.SerialNumber)
                    }
                    "CriticalAgents" {
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value (Clean-DataValue $Record.ComputerName)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "AgentName" -Value (Clean-DataValue $Record.AgentName)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Status" -Value (Clean-DataValue $Record.Status)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "IsInstalled" -Value (Clean-DataValue $Record.IsInstalled)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "Version" -Value (Clean-DataValue $Record.Version)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "LastCheck" -Value (Clean-DataValue $Record.LastCheck)
                        $CleanedRecord | Add-Member -MemberType NoteProperty -Name "ServiceStatus" -Value (Clean-DataValue $Record.ServiceStatus)
                    }
                    default {
                        # For other CSV types, copy all properties
                        foreach ($Property in $Record.PSObject.Properties) {
                            $CleanedRecord | Add-Member -MemberType NoteProperty -Name $Property.Name -Value (Clean-DataValue $Property.Value)
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
        
        # Count unique servers from multiple sources
        $ServerNames = @()
        if ($Domain.Data.ContainsKey("DomainControllers")) {
            $ServerNames += $Domain.Data["DomainControllers"] | ForEach-Object { $_.ComputerName }
        }
        if ($Domain.Data.ContainsKey("SystemInformation")) {
            $ServerNames += $Domain.Data["SystemInformation"] | ForEach-Object { $_.ComputerName }
        }
        
        $UniqueServers = $ServerNames | Where-Object { $_ -and $_ -ne "N/A" } | Sort-Object -Unique
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
                $_.Status -eq "Installed" -or $_.IsInstalled -eq "True" -or $_.Status -eq "Running"
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

# Function to generate HTML table with domain filtering
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
            $Value = $Record.$Column
            if ([string]::IsNullOrEmpty($Value)) { $Value = "N/A" }
            
            # Apply status styling
            $CellClass = ""
            if ($Column -eq "Status" -or $Column -eq "IsInstalled" -or $Column -eq "ServiceStatus") {
                if ($Value -match "Online|Installed|Running|True|Compliant") {
                    $CellClass = " class=`"status-compliant`""
                } elseif ($Value -match "Offline|Not Installed|Stopped|False|Non-Compliant|Maintenance") {
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

# Function to generate HTML dashboard with domain filtering
function Generate-HTMLDashboard {
    param(
        [array]$AllDomainData,
        [hashtable]$SummaryStats,
        [string]$OutputFilePath
    )
    
    Write-Log "Generating HTML dashboard with domain filtering"
    
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
    
    # Generate table rows
    $DomainControllersRows = Generate-HTMLTable -Data $AllDomainControllers -TableId "domain-controllers" -Columns @("ComputerName", "IPAddress", "OSVersion", "Role", "Status", "LastSeen")
    $SoftwareRows = Generate-HTMLTable -Data $AllSoftware -TableId "software" -Columns @("ComputerName", "DisplayName", "DisplayVersion", "Publisher", "InstallDate")
    $PatchRows = Generate-HTMLTable -Data $AllPatches -TableId "patches" -Columns @("ComputerName", "HotFixID", "Description", "Classification", "InstalledOn")
    $AgentsRows = Generate-HTMLTable -Data $AllAgents -TableId "agents" -Columns @("ComputerName", "AgentName", "Status", "IsInstalled", "Version", "LastCheck")
    $SystemInfoRows = Generate-HTMLTable -Data $AllSystemInfo -TableId "system-info" -Columns @("ComputerName", "OSName", "OSVersion", "Architecture", "TotalPhysicalMemoryGB", "LastBootUpTime")
    $HardwareRows = Generate-HTMLTable -Data $AllHardware -TableId "hardware" -Columns @("ComputerName", "Manufacturer", "Model", "ProcessorName", "TotalPhysicalMemoryGB", "TotalDiskSpaceGB")
    
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
        
        /* Domain Filter */
        .filter-section {
            background: white;
            margin: 1rem;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            gap: 1rem;
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
        
        /* Section headers */
        .section-header {
            background: #f8f9fa;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #dee2e6;
            font-weight: 600;
            color: #495057;
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
    </div>

    <div class="content">
        <!-- Overview Tab -->
        <div id="overview" class="tab-content active">
            <div class="section-header">Domain Summary</div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Domain Name</th>
                            <th>Servers</th>
                            <th>Software Packages</th>
                            <th>Patches</th>
                            <th>Compliance Score</th>
                            <th>Last Updated</th>
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
            <div class="section-header">Domain Controllers</div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Server Name</th>
                            <th>IP Address</th>
                            <th>OS Version</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Last Seen</th>
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
            <div class="section-header">Software Inventory</div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Server</th>
                            <th>Software Name</th>
                            <th>Version</th>
                            <th>Publisher</th>
                            <th>Install Date</th>
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
            <div class="section-header">Patch Status</div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Server</th>
                            <th>Patch ID</th>
                            <th>Description</th>
                            <th>Classification</th>
                            <th>Install Date</th>
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
            <div class="section-header">Critical Agents</div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Server</th>
                            <th>Agent Name</th>
                            <th>Status</th>
                            <th>Installed</th>
                            <th>Version</th>
                            <th>Last Check</th>
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
            <div class="section-header">System Information</div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Server Name</th>
                            <th>OS Name</th>
                            <th>OS Version</th>
                            <th>Architecture</th>
                            <th>Memory (GB)</th>
                            <th>Last Boot</th>
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
            <div class="section-header">Hardware Information</div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Server Name</th>
                            <th>Manufacturer</th>
                            <th>Model</th>
                            <th>CPU</th>
                            <th>Memory (GB)</th>
                            <th>Disk Space (GB)</th>
                        </tr>
                    </thead>
                    <tbody>
                        $HardwareRows
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
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
    Write-Log "=== Enterprise Compliance Dashboard Generator (Fixed Version) Started ===" -Level "SUCCESS"
    Write-Log "Script Version: $ScriptVersion"
    Write-Log "User: $CurrentUser"
    Write-Log "Computer: $ComputerName"
    Write-Log "Reports Path: $ReportsPath"
    Write-Log "Output Path: $OutputPath"
    
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
