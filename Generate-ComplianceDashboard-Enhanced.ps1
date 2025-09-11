# Enterprise Compliance Dashboard Generator - Enhanced Version
# Scans CSV reports from domain folders and generates comprehensive HTML dashboard
# Version: 2.0
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
    [bool]$IncludeDetailedData = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxRecordsPerTable = 1000,
    
    [Parameter(Mandatory=$false)]
    [bool]$CreateBackup = $true
)

# Script Variables
$ScriptVersion = "2.0"
$StartTime = Get-Date
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$ComputerName = $env:COMPUTERNAME

# Logging function with color support
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Color = "White"
    )
    
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $LogMessage -ForegroundColor Red }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
        default { Write-Host $LogMessage -ForegroundColor $Color }
    }
}

# Function to scan for domain folders
function Get-DomainFolders {
    param([string]$BasePath)
    
    Write-Log "Scanning for domain folders in: $BasePath" -Color Cyan
    
    if (-not (Test-Path -Path $BasePath)) {
        Write-Log "Reports path does not exist: $BasePath" -Level "ERROR"
        return @()
    }
    
    $DomainFolders = Get-ChildItem -Path $BasePath -Directory | Where-Object {
        $_.Name -notmatch "^(CrossDomainSummary|Logs|Dashboard)$"
    }
    
    Write-Log "Found $($DomainFolders.Count) domain folders" -Level "SUCCESS"
    return $DomainFolders
}

# Function to get latest CSV files for a domain
function Get-LatestCSVFiles {
    param(
        [string]$DomainPath,
        [string]$DomainName
    )
    
    Write-Log "Processing domain: $DomainName" -Color Cyan
    
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
        FileInfo = @{}
    }
    
    foreach ($CSVType in $CSVTypes) {
        $CSVFiles = Get-ChildItem -Path $DomainPath -Filter "$CSVType*.csv" | Sort-Object LastWriteTime -Descending
        
        if ($CSVFiles.Count -gt 0) {
            $LatestFile = $CSVFiles[0]
            $DomainData.Files[$CSVType] = $LatestFile.FullName
            $DomainData.FileInfo[$CSVType] = @{
                Name = $LatestFile.Name
                Size = [math]::Round($LatestFile.Length / 1KB, 2)
                LastModified = $LatestFile.LastWriteTime
            }
            
            # Update last updated time
            if (-not $DomainData.LastUpdated -or $LatestFile.LastWriteTime -gt $DomainData.LastUpdated) {
                $DomainData.LastUpdated = $LatestFile.LastWriteTime
            }
            
            Write-Log "Found $CSVType file: $($LatestFile.Name) ($([math]::Round($LatestFile.Length / 1KB, 2)) KB)"
        } else {
            Write-Log "No $CSVType files found for domain $DomainName" -Level "WARNING"
        }
    }
    
    return $DomainData
}

# Function to load CSV data with error handling
function Load-CSVData {
    param(
        [hashtable]$DomainData
    )
    
    Write-Log "Loading CSV data for domain: $($DomainData.DomainName)" -Color Cyan
    
    foreach ($CSVType in $DomainData.Files.Keys) {
        $FilePath = $DomainData.Files[$CSVType]
        
        try {
            $Data = Import-Csv -Path $FilePath -ErrorAction Stop
            
            # Clean and validate data
            $CleanedData = @()
            foreach ($Record in $Data) {
                $CleanedRecord = @{}
                foreach ($Property in $Record.PSObject.Properties) {
                    $Value = $Property.Value
                    if ([string]::IsNullOrWhiteSpace($Value)) {
                        $Value = "Unknown"
                    }
                    $CleanedRecord[$Property.Name] = $Value
                }
                $CleanedData += [PSCustomObject]$CleanedRecord
            }
            
            $DomainData.Data[$CSVType] = $CleanedData
            Write-Log "Loaded $($CleanedData.Count) records from $CSVType" -Level "SUCCESS"
            
            # Limit records if specified
            if ($MaxRecordsPerTable -gt 0 -and $CleanedData.Count -gt $MaxRecordsPerTable) {
                $DomainData.Data[$CSVType] = $CleanedData | Select-Object -First $MaxRecordsPerTable
                Write-Log "Limited to $MaxRecordsPerTable records for $CSVType" -Level "WARNING"
            }
            
        } catch {
            Write-Log "Error loading $CSVType data: $_" -Level "ERROR"
            $DomainData.Data[$CSVType] = @()
        }
    }
}

# Function to calculate comprehensive summary statistics
function Calculate-SummaryStats {
    param([array]$AllDomainData)
    
    Write-Log "Calculating comprehensive summary statistics" -Color Cyan
    
    $Stats = @{
        TotalDomains = $AllDomainData.Count
        TotalServers = 0
        TotalSoftwarePackages = 0
        TotalPatches = 0
        TotalCriticalAgents = 0
        CompliancePercentage = 0
        LastUpdated = $null
        DomainStats = @()
        TopSoftware = @()
        RecentPatches = @()
        OSDistribution = @()
    }
    
    $AllSoftware = @{}
    $AllPatches = @()
    $OSCounts = @{}
    
    foreach ($Domain in $AllDomainData) {
        $DomainStat = @{
            DomainName = $Domain.DomainName
            ServerCount = 0
            SoftwareCount = 0
            PatchCount = 0
            AgentCount = 0
            ComplianceScore = 0
            LastUpdated = if ($Domain.LastUpdated) { $Domain.LastUpdated.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
            UniqueServers = @()
        }
        
        # Count servers from multiple sources
        $ServerNames = @()
        if ($Domain.Data.ContainsKey("DomainControllers")) {
            $ServerNames += $Domain.Data["DomainControllers"] | ForEach-Object { $_.ComputerName -or $_.ServerName }
        }
        if ($Domain.Data.ContainsKey("SystemInformation")) {
            $ServerNames += $Domain.Data["SystemInformation"] | ForEach-Object { $_.ComputerName -or $_.ServerName }
        }
        
        $UniqueServers = $ServerNames | Where-Object { $_ -and $_ -ne "Unknown" } | Sort-Object -Unique
        $DomainStat.ServerCount = $UniqueServers.Count
        $DomainStat.UniqueServers = $UniqueServers
        
        # Count software packages
        if ($Domain.Data.ContainsKey("SoftwareInventory")) {
            $DomainStat.SoftwareCount = $Domain.Data["SoftwareInventory"].Count
            
            # Track software for top software analysis
            foreach ($Software in $Domain.Data["SoftwareInventory"]) {
                $SoftwareName = $Software.DisplayName -or $Software.Name
                if ($SoftwareName -and $SoftwareName -ne "Unknown") {
                    if (-not $AllSoftware.ContainsKey($SoftwareName)) {
                        $AllSoftware[$SoftwareName] = 0
                    }
                    $AllSoftware[$SoftwareName]++
                }
            }
        }
        
        # Count patches
        if ($Domain.Data.ContainsKey("PatchInventory")) {
            $DomainStat.PatchCount = $Domain.Data["PatchInventory"].Count
            $AllPatches += $Domain.Data["PatchInventory"]
        }
        
        # Count critical agents and calculate compliance
        if ($Domain.Data.ContainsKey("CriticalAgents")) {
            $DomainStat.AgentCount = $Domain.Data["CriticalAgents"].Count
            
            # Calculate compliance score
            $CompliantAgents = $Domain.Data["CriticalAgents"] | Where-Object { 
                $_.Status -eq "Compliant" -or $_.Status -eq "Installed" -or $_.IsInstalled -eq "True" 
            }
            if ($Domain.Data["CriticalAgents"].Count -gt 0) {
                $DomainStat.ComplianceScore = [math]::Round(($CompliantAgents.Count / $Domain.Data["CriticalAgents"].Count) * 100, 2)
            }
        }
        
        # Track OS distribution
        if ($Domain.Data.ContainsKey("SystemInformation")) {
            foreach ($System in $Domain.Data["SystemInformation"]) {
                $OSName = $System.OSName -or $System.OperatingSystem -or "Unknown"
                if (-not $OSCounts.ContainsKey($OSName)) {
                    $OSCounts[$OSName] = 0
                }
                $OSCounts[$OSName]++
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
    
    # Get top 10 most common software
    $Stats.TopSoftware = $AllSoftware.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object {
        @{ Name = $_.Key; Count = $_.Value }
    }
    
    # Get recent patches (last 30 days)
    $RecentDate = (Get-Date).AddDays(-30)
    $Stats.RecentPatches = $AllPatches | Where-Object {
        $InstallDate = $_.InstalledOn -or $_.InstallDate
        if ($InstallDate -and $InstallDate -ne "Unknown") {
            try {
                $ParsedDate = [DateTime]::Parse($InstallDate)
                return $ParsedDate -gt $RecentDate
            } catch {
                return $false
            }
        }
        return $false
    } | Select-Object -First 20
    
    # OS Distribution - Convert to array of objects for JSON serialization
    $Stats.OSDistribution = $OSCounts.GetEnumerator() | ForEach-Object { 
        [PSCustomObject]@{ Name = $_.Key; Count = $_.Value } 
    }
    
    return $Stats
}

# Function to convert data to JSON for embedding
function Convert-DataToJSON {
    param([array]$AllDomainData, [hashtable]$SummaryStats)
    
    Write-Log "Converting data to JSON format" -Color Cyan
    
    # Convert hashtables to PSCustomObjects for proper JSON serialization
    $JSONData = [PSCustomObject]@{
        metadata = [PSCustomObject]@{
            generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            generatedBy = $CurrentUser
            scriptVersion = $ScriptVersion
            totalDomains = $SummaryStats.TotalDomains
            lastUpdated = if ($SummaryStats.LastUpdated) { $SummaryStats.LastUpdated.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
            maxRecordsPerTable = $MaxRecordsPerTable
        }
        summary = [PSCustomObject]$SummaryStats
        domains = @()
    }
    
    foreach ($Domain in $AllDomainData) {
        $DomainJSON = [PSCustomObject]@{
            name = $Domain.DomainName
            lastUpdated = if ($Domain.LastUpdated) { $Domain.LastUpdated.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
            fileInfo = [PSCustomObject]$Domain.FileInfo
            data = [PSCustomObject]@{}
        }
        
        # Add data for each CSV type
        foreach ($CSVType in $Domain.Data.Keys) {
            $DomainJSON.data | Add-Member -MemberType NoteProperty -Name $CSVType -Value $Domain.Data[$CSVType]
        }
        
        $JSONData.domains += $DomainJSON
    }
    
    # Convert to JSON with proper escaping
    try {
        $JsonString = $JSONData | ConvertTo-Json -Depth 15 -Compress
        # Escape single quotes for JavaScript embedding
        $JsonString = $JsonString -replace "'", "\'"
        return $JsonString
    } catch {
        Write-Log "Error converting to JSON: $_" -Level "ERROR"
        return "{}"
    }
}

# Function to generate enhanced HTML dashboard
function Generate-HTMLDashboard {
    param(
        [string]$JSONData,
        [hashtable]$SummaryStats,
        [string]$OutputFilePath
    )
    
    Write-Log "Generating enhanced HTML dashboard" -Color Cyan
    
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
            overflow-x: hidden;
        }
        
        /* Header Styles */
        .header {
            background: linear-gradient(135deg, #0078d4, #106ebe);
            color: white;
            padding: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            position: sticky;
            top: 0;
            z-index: 1000;
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
        
        /* Summary Section */
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
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 40px;
            height: 40px;
            background: rgba(0,120,212,0.1);
            border-radius: 0 8px 0 40px;
        }
        
        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            border-left-color: #106ebe;
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
        
        /* Compliance Gauge */
        .compliance-section {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-top: 2rem;
        }
        
        .compliance-gauge {
            text-align: center;
            padding: 2rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .gauge-container {
            position: relative;
            display: inline-block;
            margin-bottom: 1rem;
        }
        
        .gauge-canvas {
            border-radius: 50%;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .gauge-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 1.5rem;
            font-weight: 700;
            color: #333;
        }
        
        .gauge-title {
            color: #0078d4;
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }
        
        /* Charts */
        .chart-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 2rem;
        }
        
        .chart-title {
            color: #0078d4;
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1rem;
            text-align: center;
        }
        
        .chart-canvas {
            max-width: 100%;
            height: auto;
        }
        
        /* Navigation */
        .nav-tabs {
            display: flex;
            background: white;
            margin: 1rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow-x: auto;
            position: sticky;
            top: 120px;
            z-index: 100;
        }
        
        .nav-tab {
            padding: 1rem 1.5rem;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            white-space: nowrap;
            transition: all 0.3s ease;
            font-weight: 500;
            position: relative;
        }
        
        .nav-tab:hover {
            background-color: #f8f9fa;
        }
        
        .nav-tab.active {
            border-bottom: 3px solid #0078d4;
            color: #0078d4;
            background-color: #f8f9fa;
        }
        
        .nav-tab.active::after {
            content: '';
            position: absolute;
            bottom: -3px;
            left: 50%;
            transform: translateX(-50%);
            width: 6px;
            height: 6px;
            background: #0078d4;
            border-radius: 50%;
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
            animation: fadeIn 0.3s ease-in-out;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* Domain Controls */
        .domain-controls {
            padding: 1.5rem;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .control-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .control-group label {
            font-weight: 500;
            color: #495057;
        }
        
        .domain-selector, .search-input {
            padding: 0.5rem 1rem;
            border: 1px solid #ced4da;
            border-radius: 4px;
            background: white;
            font-size: 0.9rem;
            min-width: 200px;
            transition: border-color 0.2s ease;
        }
        
        .domain-selector:focus, .search-input:focus {
            outline: none;
            border-color: #0078d4;
            box-shadow: 0 0 0 2px rgba(0,120,212,0.2);
        }
        
        .refresh-btn, .export-btn {
            padding: 0.5rem 1rem;
            background: #0078d4;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: background-color 0.2s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .refresh-btn:hover, .export-btn:hover {
            background: #106ebe;
        }
        
        .export-btn {
            background: #28a745;
        }
        
        .export-btn:hover {
            background: #218838;
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
            cursor: pointer;
            transition: background-color 0.2s ease;
        }
        
        .data-table th:hover {
            background: #e9ecef;
        }
        
        .data-table th.sortable::after {
            content: ' ↕';
            opacity: 0.5;
        }
        
        .data-table th.sort-asc::after {
            content: ' ↑';
            opacity: 1;
            color: #0078d4;
        }
        
        .data-table th.sort-desc::after {
            content: ' ↓';
            opacity: 1;
            color: #0078d4;
        }
        
        .data-table td {
            padding: 0.75rem;
            border-bottom: 1px solid #dee2e6;
            vertical-align: top;
        }
        
        .data-table tr:hover {
            background-color: #f8f9fa;
        }
        
        .data-table tr:nth-child(even) {
            background-color: #fdfdfd;
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
        
        .status-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status-badge.compliant {
            background: #d4edda;
            color: #155724;
        }
        
        .status-badge.non-compliant {
            background: #f8d7da;
            color: #721c24;
        }
        
        .status-badge.unknown {
            background: #e2e3e5;
            color: #383d41;
        }
        
        /* Loading and Error States */
        .loading {
            text-align: center;
            padding: 3rem;
            color: #6c757d;
        }
        
        .loading::before {
            content: '';
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid #f3f3f3;
            border-top: 2px solid #0078d4;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 0.5rem;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .error {
            text-align: center;
            padding: 3rem;
            color: #dc3545;
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            margin: 1rem;
        }
        
        .no-data {
            text-align: center;
            padding: 3rem;
            color: #6c757d;
            font-style: italic;
        }
        
        /* Statistics Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: white;
            padding: 1rem;
            border-radius: 6px;
            border-left: 3px solid #0078d4;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .stat-card h4 {
            color: #0078d4;
            font-size: 0.8rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
        }
        
        .stat-card .stat-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: #333;
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
            
            .compliance-section {
                grid-template-columns: 1fr;
            }
            
            .nav-tabs {
                margin: 0.5rem;
            }
            
            .content {
                margin: 0.5rem;
            }
            
            .domain-controls {
                flex-direction: column;
                align-items: stretch;
            }
            
            .control-group {
                justify-content: space-between;
            }
            
            .domain-selector, .search-input {
                min-width: auto;
                flex: 1;
            }
        }
        
        /* Print Styles */
        @media print {
            .nav-tabs, .domain-controls {
                display: none;
            }
            
            .tab-content {
                display: block !important;
                page-break-inside: avoid;
            }
            
            .summary-card {
                break-inside: avoid;
            }
            
            .header {
                position: static;
            }
        }
        
        /* Utility Classes */
        .text-center { text-align: center; }
        .text-right { text-align: right; }
        .font-weight-bold { font-weight: 700; }
        .text-muted { color: #6c757d; }
        .mb-1 { margin-bottom: 0.25rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .mb-3 { margin-bottom: 1rem; }
        .mt-1 { margin-top: 0.25rem; }
        .mt-2 { margin-top: 0.5rem; }
        .mt-3 { margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Enterprise Compliance Dashboard</h1>
        <div class="header-info">
            <div class="header-badge">Generated: <span id="generated-time">Loading...</span></div>
            <div class="header-badge">Last Updated: <span id="last-updated">Loading...</span></div>
            <div class="header-badge">Domains: <span id="domain-count">Loading...</span></div>
            <div class="header-badge">Version: $ScriptVersion</div>
        </div>
    </div>

    <div class="summary-section">
        <div class="summary-cards">
            <div class="summary-card">
                <h3>Total Domains</h3>
                <div class="value" id="total-domains">0</div>
                <div class="label">Active Domains</div>
            </div>
            <div class="summary-card">
                <h3>Total Servers</h3>
                <div class="value" id="total-servers">0</div>
                <div class="label">Domain Controllers</div>
            </div>
            <div class="summary-card">
                <h3>Software Packages</h3>
                <div class="value" id="total-software">0</div>
                <div class="label">Installed Applications</div>
            </div>
            <div class="summary-card">
                <h3>Patches</h3>
                <div class="value" id="total-patches">0</div>
                <div class="label">Security Updates</div>
            </div>
        </div>
        
        <div class="compliance-section">
            <div class="compliance-gauge">
                <div class="gauge-title">Overall Compliance Score</div>
                <div class="gauge-container">
                    <canvas id="compliance-gauge" width="200" height="200" class="gauge-canvas"></canvas>
                    <div class="gauge-text" id="compliance-percentage">0%</div>
                </div>
            </div>
            
            <div class="chart-container">
                <div class="chart-title">Top Software Applications</div>
                <canvas id="software-chart" width="400" height="200" class="chart-canvas"></canvas>
            </div>
        </div>
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
            <div class="domain-controls">
                <div class="control-group">
                    <label for="domain-filter">Filter by Domain:</label>
                    <select id="domain-filter" class="domain-selector" onchange="filterByDomain()">
                        <option value="">All Domains</option>
                    </select>
                </div>
                <div class="control-group">
                    <button class="refresh-btn" onclick="refreshData()">🔄 Refresh</button>
                    <button class="export-btn" onclick="exportData('overview')">📊 Export</button>
                </div>
            </div>
            <div class="table-container">
                <h3 style="margin-bottom: 1rem;">Domain Summary</h3>
                <table class="data-table" id="domain-summary-table">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('domain-summary-table', 0)">Domain Name</th>
                            <th class="sortable" onclick="sortTable('domain-summary-table', 1)">Servers</th>
                            <th class="sortable" onclick="sortTable('domain-summary-table', 2)">Software Packages</th>
                            <th class="sortable" onclick="sortTable('domain-summary-table', 3)">Patches</th>
                            <th class="sortable" onclick="sortTable('domain-summary-table', 4)">Compliance Score</th>
                            <th class="sortable" onclick="sortTable('domain-summary-table', 5)">Last Updated</th>
                        </tr>
                    </thead>
                    <tbody id="domain-summary-body">
                        <tr><td colspan="6" class="loading">Loading data...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Domain Controllers Tab -->
        <div id="domain-controllers" class="tab-content">
            <div class="domain-controls">
                <div class="control-group">
                    <label for="dc-domain-filter">Filter by Domain:</label>
                    <select id="dc-domain-filter" class="domain-selector" onchange="filterDomainControllers()">
                        <option value="">All Domains</option>
                    </select>
                </div>
                <div class="control-group">
                    <input type="text" id="dc-search" class="search-input" placeholder="Search servers..." onkeyup="searchTable('domain-controllers-body')">
                    <button class="export-btn" onclick="exportData('domain-controllers')">📊 Export</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="domain-controllers-table">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('domain-controllers-table', 0)">Domain</th>
                            <th class="sortable" onclick="sortTable('domain-controllers-table', 1)">Server Name</th>
                            <th class="sortable" onclick="sortTable('domain-controllers-table', 2)">IP Address</th>
                            <th class="sortable" onclick="sortTable('domain-controllers-table', 3)">OS Version</th>
                            <th class="sortable" onclick="sortTable('domain-controllers-table', 4)">Role</th>
                            <th class="sortable" onclick="sortTable('domain-controllers-table', 5)">Status</th>
                        </tr>
                    </thead>
                    <tbody id="domain-controllers-body">
                        <tr><td colspan="6" class="loading">Loading data...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Software Inventory Tab -->
        <div id="software" class="tab-content">
            <div class="domain-controls">
                <div class="control-group">
                    <label for="software-domain-filter">Filter by Domain:</label>
                    <select id="software-domain-filter" class="domain-selector" onchange="filterSoftware()">
                        <option value="">All Domains</option>
                    </select>
                </div>
                <div class="control-group">
                    <input type="text" id="software-search" class="search-input" placeholder="Search software..." onkeyup="searchTable('software-body')">
                    <button class="export-btn" onclick="exportData('software')">📊 Export</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="software-table">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('software-table', 0)">Domain</th>
                            <th class="sortable" onclick="sortTable('software-table', 1)">Server</th>
                            <th class="sortable" onclick="sortTable('software-table', 2)">Software Name</th>
                            <th class="sortable" onclick="sortTable('software-table', 3)">Version</th>
                            <th class="sortable" onclick="sortTable('software-table', 4)">Publisher</th>
                            <th class="sortable" onclick="sortTable('software-table', 5)">Install Date</th>
                        </tr>
                    </thead>
                    <tbody id="software-body">
                        <tr><td colspan="6" class="loading">Loading data...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Patches Tab -->
        <div id="patches" class="tab-content">
            <div class="domain-controls">
                <div class="control-group">
                    <label for="patch-domain-filter">Filter by Domain:</label>
                    <select id="patch-domain-filter" class="domain-selector" onchange="filterPatches()">
                        <option value="">All Domains</option>
                    </select>
                </div>
                <div class="control-group">
                    <input type="text" id="patch-search" class="search-input" placeholder="Search patches..." onkeyup="searchTable('patches-body')">
                    <button class="export-btn" onclick="exportData('patches')">📊 Export</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="patches-table">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('patches-table', 0)">Domain</th>
                            <th class="sortable" onclick="sortTable('patches-table', 1)">Server</th>
                            <th class="sortable" onclick="sortTable('patches-table', 2)">Patch ID</th>
                            <th class="sortable" onclick="sortTable('patches-table', 3)">Title</th>
                            <th class="sortable" onclick="sortTable('patches-table', 4)">Classification</th>
                            <th class="sortable" onclick="sortTable('patches-table', 5)">Install Date</th>
                        </tr>
                    </thead>
                    <tbody id="patches-body">
                        <tr><td colspan="6" class="loading">Loading data...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Critical Agents Tab -->
        <div id="agents" class="tab-content">
            <div class="domain-controls">
                <div class="control-group">
                    <label for="agent-domain-filter">Filter by Domain:</label>
                    <select id="agent-domain-filter" class="domain-selector" onchange="filterAgents()">
                        <option value="">All Domains</option>
                    </select>
                </div>
                <div class="control-group">
                    <input type="text" id="agent-search" class="search-input" placeholder="Search agents..." onkeyup="searchTable('agents-body')">
                    <button class="export-btn" onclick="exportData('agents')">📊 Export</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="agents-table">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('agents-table', 0)">Domain</th>
                            <th class="sortable" onclick="sortTable('agents-table', 1)">Server</th>
                            <th class="sortable" onclick="sortTable('agents-table', 2)">Agent Name</th>
                            <th class="sortable" onclick="sortTable('agents-table', 3)">Status</th>
                            <th class="sortable" onclick="sortTable('agents-table', 4)">Version</th>
                            <th class="sortable" onclick="sortTable('agents-table', 5)">Last Check</th>
                        </tr>
                    </thead>
                    <tbody id="agents-body">
                        <tr><td colspan="6" class="loading">Loading data...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- System Information Tab -->
        <div id="system-info" class="tab-content">
            <div class="domain-controls">
                <div class="control-group">
                    <label for="system-domain-filter">Filter by Domain:</label>
                    <select id="system-domain-filter" class="domain-selector" onchange="filterSystemInfo()">
                        <option value="">All Domains</option>
                    </select>
                </div>
                <div class="control-group">
                    <input type="text" id="system-search" class="search-input" placeholder="Search systems..." onkeyup="searchTable('system-info-body')">
                    <button class="export-btn" onclick="exportData('system-info')">📊 Export</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="system-info-table">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('system-info-table', 0)">Domain</th>
                            <th class="sortable" onclick="sortTable('system-info-table', 1)">Server Name</th>
                            <th class="sortable" onclick="sortTable('system-info-table', 2)">OS Name</th>
                            <th class="sortable" onclick="sortTable('system-info-table', 3)">OS Version</th>
                            <th class="sortable" onclick="sortTable('system-info-table', 4)">Architecture</th>
                            <th class="sortable" onclick="sortTable('system-info-table', 5)">Memory (GB)</th>
                            <th class="sortable" onclick="sortTable('system-info-table', 6)">Last Boot</th>
                        </tr>
                    </thead>
                    <tbody id="system-info-body">
                        <tr><td colspan="7" class="loading">Loading data...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Hardware Tab -->
        <div id="hardware" class="tab-content">
            <div class="domain-controls">
                <div class="control-group">
                    <label for="hardware-domain-filter">Filter by Domain:</label>
                    <select id="hardware-domain-filter" class="domain-selector" onchange="filterHardware()">
                        <option value="">All Domains</option>
                    </select>
                </div>
                <div class="control-group">
                    <input type="text" id="hardware-search" class="search-input" placeholder="Search hardware..." onkeyup="searchTable('hardware-body')">
                    <button class="export-btn" onclick="exportData('hardware')">📊 Export</button>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table" id="hardware-table">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable('hardware-table', 0)">Domain</th>
                            <th class="sortable" onclick="sortTable('hardware-table', 1)">Server Name</th>
                            <th class="sortable" onclick="sortTable('hardware-table', 2)">Manufacturer</th>
                            <th class="sortable" onclick="sortTable('hardware-table', 3)">Model</th>
                            <th class="sortable" onclick="sortTable('hardware-table', 4)">CPU</th>
                            <th class="sortable" onclick="sortTable('hardware-table', 5)">Memory (GB)</th>
                            <th class="sortable" onclick="sortTable('hardware-table', 6)">Disk Space (GB)</th>
                        </tr>
                    </thead>
                    <tbody id="hardware-body">
                        <tr><td colspan="7" class="loading">Loading data...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // Embedded data
        const dashboardData = $JSONData;
        
        // Global variables
        let currentDomain = '';
        let allData = {};
        let sortDirections = {};
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            try {
                loadDashboardData();
                updateSummaryCards();
                updateComplianceGauge();
                drawSoftwareChart();
                populateDomainFilters();
                loadOverviewData();
                loadDomainControllers();
                loadSoftwareInventory();
                loadPatchInventory();
                loadCriticalAgents();
                loadSystemInformation();
                loadHardwareInformation();
            } catch (error) {
                console.error('Error initializing dashboard:', error);
                showError('Failed to load dashboard data: ' + error.message);
            }
        });
        
        // Load dashboard data
        function loadDashboardData() {
            allData = dashboardData;
            
            // Update header information
            document.getElementById('generated-time').textContent = allData.metadata.generatedAt;
            document.getElementById('last-updated').textContent = allData.metadata.lastUpdated;
            document.getElementById('domain-count').textContent = allData.metadata.totalDomains;
        }
        
        // Update summary cards
        function updateSummaryCards() {
            document.getElementById('total-domains').textContent = allData.summary.TotalDomains || 0;
            document.getElementById('total-servers').textContent = allData.summary.TotalServers || 0;
            document.getElementById('total-software').textContent = allData.summary.TotalSoftwarePackages || 0;
            document.getElementById('total-patches').textContent = allData.summary.TotalPatches || 0;
        }
        
        // Update compliance gauge
        function updateComplianceGauge() {
            const percentage = allData.summary.CompliancePercentage || 0;
            document.getElementById('compliance-percentage').textContent = percentage + '%';
            drawComplianceGauge('compliance-gauge', percentage);
        }
        
        // Draw compliance gauge
        function drawComplianceGauge(canvasId, percentage) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) return;
            
            const ctx = canvas.getContext('2d');
            const centerX = canvas.width / 2;
            const centerY = canvas.height / 2;
            const radius = 80;
            const innerRadius = 50;
            const compliantAngle = (percentage / 100) * 2 * Math.PI;
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Draw background circle
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
            ctx.fillStyle = '#e9ecef';
            ctx.fill();
            
            // Draw compliant portion
            if (percentage > 0) {
                ctx.beginPath();
                ctx.moveTo(centerX, centerY);
                ctx.arc(centerX, centerY, radius, -Math.PI / 2, compliantAngle - Math.PI / 2);
                ctx.lineTo(centerX, centerY);
                ctx.fillStyle = percentage >= 80 ? '#28a745' : percentage >= 60 ? '#ffc107' : '#dc3545';
                ctx.fill();
            }
            
            // Draw inner circle
            ctx.beginPath();
            ctx.arc(centerX, centerY, innerRadius, 0, 2 * Math.PI);
            ctx.fillStyle = 'white';
            ctx.fill();
        }
        
        // Draw software chart
        function drawSoftwareChart() {
            const canvas = document.getElementById('software-chart');
            if (!canvas || !allData.summary.TopSoftware) return;
            
            const ctx = canvas.getContext('2d');
            const topSoftware = allData.summary.TopSoftware.slice(0, 5); // Top 5
            
            if (topSoftware.length === 0) return;
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Chart dimensions
            const chartWidth = canvas.width - 80;
            const chartHeight = canvas.height - 60;
            const barHeight = 25;
            const maxCount = Math.max(...topSoftware.map(s => s.Count));
            
            // Draw bars
            topSoftware.forEach((software, index) => {
                const y = 30 + index * (barHeight + 10);
                const barWidth = (software.Count / maxCount) * chartWidth;
                
                // Draw bar
                ctx.fillStyle = '#0078d4';
                ctx.fillRect(40, y, barWidth, barHeight);
                
                // Draw label
                ctx.fillStyle = '#333';
                ctx.font = '12px Segoe UI';
                ctx.textAlign = 'left';
                
                // Truncate long names
                let displayName = software.Name;
                if (displayName.length > 25) {
                    displayName = displayName.substring(0, 22) + '...';
                }
                
                ctx.fillText(displayName, 45, y + 17);
                
                // Draw count
                ctx.textAlign = 'right';
                ctx.fillText(software.Count.toString(), canvas.width - 10, y + 17);
            });
        }
        
        // Populate domain filters
        function populateDomainFilters() {
            const domains = allData.domains.map(d => d.name).sort();
            const selectors = [
                'domain-filter', 'dc-domain-filter', 'software-domain-filter', 
                'patch-domain-filter', 'agent-domain-filter', 'system-domain-filter', 
                'hardware-domain-filter'
            ];
            
            selectors.forEach(selectorId => {
                const selector = document.getElementById(selectorId);
                if (selector) {
                    selector.innerHTML = '<option value="">All Domains</option>';
                    domains.forEach(domain => {
                        const option = document.createElement('option');
                        option.value = domain;
                        option.textContent = domain;
                        selector.appendChild(option);
                    });
                }
            });
        }
        
        // Load overview data
        function loadOverviewData() {
            const tbody = document.getElementById('domain-summary-body');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            
            const filteredStats = currentDomain ? 
                allData.summary.DomainStats.filter(d => d.DomainName === currentDomain) : 
                allData.summary.DomainStats;
            
            if (filteredStats.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="no-data">No data available for selected domain</td></tr>';
                return;
            }
            
            filteredStats.forEach(domain => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${domain.DomainName}</td>
                    <td>${domain.ServerCount}</td>
                    <td>${domain.SoftwareCount}</td>
                    <td>${domain.PatchCount}</td>
                    <td><span class="status-badge ${getComplianceClass(domain.ComplianceScore)}">${domain.ComplianceScore}%</span></td>
                    <td>${domain.LastUpdated || 'Unknown'}</td>
                `;
                tbody.appendChild(row);
            });
        }
        
        // Load domain controllers
        function loadDomainControllers() {
            const tbody = document.getElementById('domain-controllers-body');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            
            const filteredDomains = currentDomain ? 
                allData.domains.filter(d => d.name === currentDomain) : 
                allData.domains;
            
            let hasData = false;
            
            filteredDomains.forEach(domain => {
                if (domain.data.DomainControllers) {
                    domain.data.DomainControllers.forEach(dc => {
                        hasData = true;
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${domain.name}</td>
                            <td>${dc.ComputerName || dc.ServerName || 'Unknown'}</td>
                            <td>${dc.IPAddress || 'Unknown'}</td>
                            <td>${dc.OSVersion || dc.OperatingSystem || 'Unknown'}</td>
                            <td>${dc.Role || 'Domain Controller'}</td>
                            <td><span class="status-badge ${getStatusClass(dc.Status || 'Online')}">${dc.Status || 'Online'}</span></td>
                        `;
                        tbody.appendChild(row);
                    });
                }
            });
            
            if (!hasData) {
                tbody.innerHTML = '<tr><td colspan="6" class="no-data">No domain controller data available</td></tr>';
            }
        }
        
        // Load software inventory
        function loadSoftwareInventory() {
            const tbody = document.getElementById('software-body');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            
            const filteredDomains = currentDomain ? 
                allData.domains.filter(d => d.name === currentDomain) : 
                allData.domains;
            
            let hasData = false;
            
            filteredDomains.forEach(domain => {
                if (domain.data.SoftwareInventory) {
                    domain.data.SoftwareInventory.forEach(software => {
                        hasData = true;
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${domain.name}</td>
                            <td>${software.ComputerName || software.ServerName || 'Unknown'}</td>
                            <td>${software.DisplayName || software.Name || 'Unknown'}</td>
                            <td>${software.DisplayVersion || software.Version || 'Unknown'}</td>
                            <td>${software.Publisher || 'Unknown'}</td>
                            <td>${software.InstallDate || 'Unknown'}</td>
                        `;
                        tbody.appendChild(row);
                    });
                }
            });
            
            if (!hasData) {
                tbody.innerHTML = '<tr><td colspan="6" class="no-data">No software inventory data available</td></tr>';
            }
        }
        
        // Load patch inventory
        function loadPatchInventory() {
            const tbody = document.getElementById('patches-body');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            
            const filteredDomains = currentDomain ? 
                allData.domains.filter(d => d.name === currentDomain) : 
                allData.domains;
            
            let hasData = false;
            
            filteredDomains.forEach(domain => {
                if (domain.data.PatchInventory) {
                    domain.data.PatchInventory.forEach(patch => {
                        hasData = true;
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${domain.name}</td>
                            <td>${patch.ComputerName || patch.ServerName || 'Unknown'}</td>
                            <td>${patch.HotFixID || patch.PatchID || 'Unknown'}</td>
                            <td>${patch.Description || patch.Title || 'Unknown'}</td>
                            <td>${patch.Classification || 'Unknown'}</td>
                            <td>${patch.InstalledOn || patch.InstallDate || 'Unknown'}</td>
                        `;
                        tbody.appendChild(row);
                    });
                }
            });
            
            if (!hasData) {
                tbody.innerHTML = '<tr><td colspan="6" class="no-data">No patch inventory data available</td></tr>';
            }
        }
        
        // Load critical agents
        function loadCriticalAgents() {
            const tbody = document.getElementById('agents-body');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            
            const filteredDomains = currentDomain ? 
                allData.domains.filter(d => d.name === currentDomain) : 
                allData.domains;
            
            let hasData = false;
            
            filteredDomains.forEach(domain => {
                if (domain.data.CriticalAgents) {
                    domain.data.CriticalAgents.forEach(agent => {
                        hasData = true;
                        const status = agent.Status || (agent.IsInstalled === 'True' ? 'Installed' : 'Not Installed');
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${domain.name}</td>
                            <td>${agent.ComputerName || agent.ServerName || 'Unknown'}</td>
                            <td>${agent.AgentName || agent.Name || 'Unknown'}</td>
                            <td><span class="status-badge ${getStatusClass(status)}">${status}</span></td>
                            <td>${agent.Version || 'Unknown'}</td>
                            <td>${agent.LastCheck || agent.CheckDate || 'Unknown'}</td>
                        `;
                        tbody.appendChild(row);
                    });
                }
            });
            
            if (!hasData) {
                tbody.innerHTML = '<tr><td colspan="6" class="no-data">No critical agent data available</td></tr>';
            }
        }
        
        // Load system information
        function loadSystemInformation() {
            const tbody = document.getElementById('system-info-body');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            
            const filteredDomains = currentDomain ? 
                allData.domains.filter(d => d.name === currentDomain) : 
                allData.domains;
            
            let hasData = false;
            
            filteredDomains.forEach(domain => {
                if (domain.data.SystemInformation) {
                    domain.data.SystemInformation.forEach(system => {
                        hasData = true;
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${domain.name}</td>
                            <td>${system.ComputerName || system.ServerName || 'Unknown'}</td>
                            <td>${system.OSName || system.OperatingSystem || 'Unknown'}</td>
                            <td>${system.OSVersion || system.Version || 'Unknown'}</td>
                            <td>${system.Architecture || 'Unknown'}</td>
                            <td>${system.TotalPhysicalMemoryGB || system.MemoryGB || 'Unknown'}</td>
                            <td>${system.LastBootUpTime || system.LastBoot || 'Unknown'}</td>
                        `;
                        tbody.appendChild(row);
                    });
                }
            });
            
            if (!hasData) {
                tbody.innerHTML = '<tr><td colspan="7" class="no-data">No system information data available</td></tr>';
            }
        }
        
        // Load hardware information
        function loadHardwareInformation() {
            const tbody = document.getElementById('hardware-body');
            if (!tbody) return;
            
            tbody.innerHTML = '';
            
            const filteredDomains = currentDomain ? 
                allData.domains.filter(d => d.name === currentDomain) : 
                allData.domains;
            
            let hasData = false;
            
            filteredDomains.forEach(domain => {
                if (domain.data.HardwareInfo) {
                    domain.data.HardwareInfo.forEach(hardware => {
                        hasData = true;
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${domain.name}</td>
                            <td>${hardware.ComputerName || hardware.ServerName || 'Unknown'}</td>
                            <td>${hardware.Manufacturer || 'Unknown'}</td>
                            <td>${hardware.Model || 'Unknown'}</td>
                            <td>${hardware.ProcessorName || hardware.CPU || 'Unknown'}</td>
                            <td>${hardware.TotalPhysicalMemoryGB || hardware.MemoryGB || 'Unknown'}</td>
                            <td>${hardware.TotalDiskSpaceGB || hardware.DiskSpaceGB || 'Unknown'}</td>
                        `;
                        tbody.appendChild(row);
                    });
                }
            });
            
            if (!hasData) {
                tbody.innerHTML = '<tr><td colspan="7" class="no-data">No hardware information data available</td></tr>';
            }
        }
        
        // Helper functions
        function getComplianceClass(score) {
            if (score >= 80) return 'compliant';
            if (score >= 60) return 'unknown';
            return 'non-compliant';
        }
        
        function getStatusClass(status) {
            if (typeof status === 'string') {
                const lowerStatus = status.toLowerCase();
                if (lowerStatus.includes('compliant') || lowerStatus.includes('installed') || lowerStatus.includes('online') || lowerStatus === 'true') {
                    return 'compliant';
                }
                if (lowerStatus.includes('not') || lowerStatus.includes('offline') || lowerStatus === 'false') {
                    return 'non-compliant';
                }
            }
            return 'unknown';
        }
        
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
        
        // Filter functions
        function filterByDomain() {
            currentDomain = document.getElementById('domain-filter').value;
            loadOverviewData();
        }
        
        function filterDomainControllers() {
            currentDomain = document.getElementById('dc-domain-filter').value;
            loadDomainControllers();
        }
        
        function filterSoftware() {
            currentDomain = document.getElementById('software-domain-filter').value;
            loadSoftwareInventory();
        }
        
        function filterPatches() {
            currentDomain = document.getElementById('patch-domain-filter').value;
            loadPatchInventory();
        }
        
        function filterAgents() {
            currentDomain = document.getElementById('agent-domain-filter').value;
            loadCriticalAgents();
        }
        
        function filterSystemInfo() {
            currentDomain = document.getElementById('system-domain-filter').value;
            loadSystemInformation();
        }
        
        function filterHardware() {
            currentDomain = document.getElementById('hardware-domain-filter').value;
            loadHardwareInformation();
        }
        
        // Search function
        function searchTable(tbodyId) {
            const searchInput = event.target;
            const searchTerm = searchInput.value.toLowerCase();
            const tbody = document.getElementById(tbodyId);
            
            if (!tbody) return;
            
            const rows = tbody.querySelectorAll('tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        }
        
        // Sort table function
        function sortTable(tableId, columnIndex) {
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const header = table.querySelectorAll('th')[columnIndex];
            
            // Determine sort direction
            const currentDirection = sortDirections[tableId + '-' + columnIndex] || 'asc';
            const newDirection = currentDirection === 'asc' ? 'desc' : 'asc';
            sortDirections[tableId + '-' + columnIndex] = newDirection;
            
            // Clear all sort indicators
            table.querySelectorAll('th').forEach(th => {
                th.classList.remove('sort-asc', 'sort-desc');
            });
            
            // Add sort indicator to current column
            header.classList.add(newDirection === 'asc' ? 'sort-asc' : 'sort-desc');
            
            // Sort rows
            rows.sort((a, b) => {
                const aText = a.cells[columnIndex].textContent.trim();
                const bText = b.cells[columnIndex].textContent.trim();
                
                // Try to parse as numbers
                const aNum = parseFloat(aText.replace(/[^0-9.-]/g, ''));
                const bNum = parseFloat(bText.replace(/[^0-9.-]/g, ''));
                
                let comparison = 0;
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    comparison = aNum - bNum;
                } else {
                    comparison = aText.localeCompare(bText);
                }
                
                return newDirection === 'asc' ? comparison : -comparison;
            });
            
            // Re-append sorted rows
            rows.forEach(row => tbody.appendChild(row));
        }
        
        // Export data function
        function exportData(tabName) {
            const table = document.querySelector(`#${tabName} table`);
            if (!table) return;
            
            let csv = '';
            
            // Add headers
            const headers = Array.from(table.querySelectorAll('th')).map(th => th.textContent.trim());
            csv += headers.join(',') + '\n';
            
            // Add data rows
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                if (row.style.display !== 'none') {
                    const cells = Array.from(row.cells).map(cell => {
                        let text = cell.textContent.trim();
                        // Escape commas and quotes
                        if (text.includes(',') || text.includes('"')) {
                            text = '"' + text.replace(/"/g, '""') + '"';
                        }
                        return text;
                    });
                    csv += cells.join(',') + '\n';
                }
            });
            
            // Download CSV
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${tabName}-export-${new Date().toISOString().split('T')[0]}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }
        
        // Refresh data
        function refreshData() {
            location.reload();
        }
        
        // Error handling
        function showError(message) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error';
            errorDiv.textContent = message;
            document.body.insertBefore(errorDiv, document.body.firstChild);
            
            // Auto-remove error after 10 seconds
            setTimeout(() => {
                if (errorDiv.parentNode) {
                    errorDiv.parentNode.removeChild(errorDiv);
                }
            }, 10000);
        }
    </script>
</body>
</html>
"@

    # Write HTML file
    try {
        $HTMLContent | Out-File -FilePath $OutputFilePath -Encoding UTF8
        Write-Log "Enhanced HTML dashboard generated: $OutputFilePath" -Level "SUCCESS"
        return $OutputFilePath
    } catch {
        Write-Log "Error writing HTML file: $_" -Level "ERROR"
        throw
    }
}

# Main execution
try {
    Write-Log "=== Enterprise Compliance Dashboard Generator (Enhanced) Started ===" -Color Green
    Write-Log "Script Version: $ScriptVersion" -Color Cyan
    Write-Log "User: $CurrentUser" -Color Cyan
    Write-Log "Computer: $ComputerName" -Color Cyan
    Write-Log "Reports Path: $ReportsPath" -Color Cyan
    Write-Log "Output Path: $OutputPath" -Color Cyan
    
    # Create output directory
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Log "Created output directory: $OutputPath" -Level "SUCCESS"
    }
    
    # Create backup if requested
    if ($CreateBackup) {
        $ExistingDashboard = Join-Path -Path $OutputPath -ChildPath $DashboardName
        if (Test-Path -Path $ExistingDashboard) {
            $BackupName = "Enterprise-Compliance-Dashboard-Backup-$Timestamp.html"
            $BackupPath = Join-Path -Path $OutputPath -ChildPath $BackupName
            Copy-Item -Path $ExistingDashboard -Destination $BackupPath
            Write-Log "Created backup: $BackupName" -Level "SUCCESS"
        }
    }
    
    # Scan for domain folders
    $DomainFolders = Get-DomainFolders -BasePath $ReportsPath
    
    if ($DomainFolders.Count -eq 0) {
        Write-Log "No domain folders found in $ReportsPath" -Level "ERROR"
        Write-Log "Please ensure the data collection script has been run and CSV files exist." -Level "ERROR"
        Write-Log "Expected folder structure: $ReportsPath\[DomainName]\*.csv" -Level "ERROR"
        exit 1
    }
    
    # Process each domain
    $AllDomainData = @()
    
    foreach ($DomainFolder in $DomainFolders) {
        Write-Log "Processing domain folder: $($DomainFolder.Name)" -Color Yellow
        
        $DomainData = Get-LatestCSVFiles -DomainPath $DomainFolder.FullName -DomainName $DomainFolder.Name
        
        if ($DomainData.Files.Count -gt 0) {
            Load-CSVData -DomainData $DomainData
            $AllDomainData += $DomainData
            Write-Log "Successfully processed domain: $($DomainFolder.Name)" -Level "SUCCESS"
        } else {
            Write-Log "No CSV files found for domain: $($DomainFolder.Name)" -Level "WARNING"
        }
    }
    
    if ($AllDomainData.Count -eq 0) {
        Write-Log "No valid domain data found" -Level "ERROR"
        Write-Log "Please check that CSV files exist in the domain folders" -Level "ERROR"
        exit 1
    }
    
    # Calculate summary statistics
    Write-Log "Calculating comprehensive statistics..." -Color Cyan
    $SummaryStats = Calculate-SummaryStats -AllDomainData $AllDomainData
    
    # Convert data to JSON
    Write-Log "Converting data to JSON format..." -Color Cyan
    $JSONData = Convert-DataToJSON -AllDomainData $AllDomainData -SummaryStats $SummaryStats
    
    # Generate HTML dashboard
    Write-Log "Generating enhanced HTML dashboard..." -Color Cyan
    $DashboardPath = Join-Path -Path $OutputPath -ChildPath $DashboardName
    $GeneratedDashboard = Generate-HTMLDashboard -JSONData $JSONData -SummaryStats $SummaryStats -OutputFilePath $DashboardPath
    
    # Open dashboard if requested
    if ($OpenDashboard -and (Test-Path -Path $GeneratedDashboard)) {
        Write-Log "Opening dashboard in default browser..." -Color Green
        Start-Process $GeneratedDashboard
    }
    
    $EndTime = Get-Date
    $Duration = $EndTime - $StartTime
    $DurationString = "{0:D2}:{1:D2}:{2:D2}" -f $Duration.Hours, $Duration.Minutes, $Duration.Seconds
    
    Write-Log "=== Dashboard Generation Completed Successfully ===" -Level "SUCCESS"
    Write-Log "Dashboard saved to: $GeneratedDashboard" -Level "SUCCESS"
    Write-Log "Execution time: $DurationString" -Color Green
    Write-Log "Domains processed: $($AllDomainData.Count)" -Color Green
    Write-Log "Total servers: $($SummaryStats.TotalServers)" -Color Green
    Write-Log "Total software packages: $($SummaryStats.TotalSoftwarePackages)" -Color Green
    Write-Log "Total patches: $($SummaryStats.TotalPatches)" -Color Green
    Write-Log "Overall compliance: $($SummaryStats.CompliancePercentage)%" -Color Green
    
    Write-Log "" 
    Write-Log "Dashboard Features:" -Color Cyan
    Write-Log "- Multi-domain support with filtering" -Color White
    Write-Log "- Interactive tables with sorting and search" -Color White
    Write-Log "- Compliance gauge and software charts" -Color White
    Write-Log "- Export functionality for all data" -Color White
    Write-Log "- Responsive design for mobile devices" -Color White
    Write-Log "- Completely offline operation" -Color White
    
} catch {
    Write-Log "Error in dashboard generation: $_" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}
