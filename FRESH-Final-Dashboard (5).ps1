# FRESH Final Dashboard - Completely new version to eliminate caching issues
# Corrected group counting + updated terminology for password issues

param(
    [string]$ReportsPath = ".\AD_Housekeeping_Reports",
    [string]$OutputFile = ".\AD-Dashboard-FRESH-Final.html"
)

Write-Host "AD Housekeeping Dashboard - FRESH Final Version" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# Check if reports directory exists
if (-not (Test-Path $ReportsPath)) {
    Write-Host "ERROR: Reports directory not found: $ReportsPath" -ForegroundColor Red
    exit 1
}

# Function to count CSV records safely
function Get-CSVCount {
    param([string]$CsvPath)
    
    if (-not (Test-Path $CsvPath)) {
        return 0
    }
    
    try {
        $csvData = Import-Csv $CsvPath -ErrorAction Stop
        return $csvData.Count
    }
    catch {
        Write-Host "Warning: Could not process $CsvPath - $($_.Exception.Message)" -ForegroundColor Yellow
        return 0
    }
}

# Function to check if CSV file exists
function Test-CSVExists {
    param([string]$CsvPath)
    return (Test-Path $CsvPath) -and ((Get-Item $CsvPath).Length -gt 0)
}

# Discover domains
Write-Host "Discovering domains..." -ForegroundColor Green
$domains = Get-ChildItem -Path $ReportsPath -Directory | Select-Object -ExpandProperty Name
Write-Host "Found domains: $($domains -join ', ')" -ForegroundColor White

if ($domains.Count -eq 0) {
    Write-Host "ERROR: No domain directories found in $ReportsPath" -ForegroundColor Red
    exit 1
}

# Build summary data structure
$summaryData = @{
    lastUpdated = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    totalDomains = $domains.Count
    domains = @{}
    grandTotal = @{
        staleComputers = 0
        oldPasswords = 0
        dormantUsers = 0
        emptyGroups = 0
        emptyOUs = 0
        totalIssues = 0
    }
}

foreach ($domain in $domains) {
    Write-Host "Processing domain: $domain" -ForegroundColor Yellow
    
    $domainPath = Join-Path $ReportsPath $domain
    
    # Define CSV file paths
    $staleComputersPath = Join-Path $domainPath "StaleComputers_Detailed.csv"
    $oldPwdComputersPath = Join-Path $domainPath "OldPwdComputers_Detailed.csv"
    $dormantUsersPath = Join-Path $domainPath "DormantUsers_Detailed.csv"
    $emptyGroupsPath = Join-Path $domainPath "EmptyGroups_NeverUsed.csv"
    $emptySecGroupsPath = Join-Path $domainPath "EmptySecurityGroups_CurrentlyEmpty.csv"
    $emptyOUsPath = Join-Path $domainPath "EmptyOUs.csv"
    
    # Count records
    $staleCount = Get-CSVCount $staleComputersPath
    $oldPwdCount = Get-CSVCount $oldPwdComputersPath
    $dormantCount = Get-CSVCount $dormantUsersPath
    $emptyGroupsCount = Get-CSVCount $emptyGroupsPath
    $emptySecGroupsCount = Get-CSVCount $emptySecGroupsPath
    $emptyOUsCount = Get-CSVCount $emptyOUsPath
    
    # CORRECTED: Only count EmptyGroups_NeverUsed.csv for "Unused Security Groups"
    $totalIssues = $staleCount + $oldPwdCount + $dormantCount + $emptyGroupsCount + $emptyOUsCount
    
    # Store domain summary
    $summaryData.domains[$domain] = @{
        name = $domain
        staleComputers = $staleCount
        oldPasswords = $oldPwdCount
        dormantUsers = $dormantCount
        emptyGroups = $emptyGroupsCount  # Only never-used groups
        emptyOUs = $emptyOUsCount
        totalIssues = $totalIssues
        filesAvailable = @{
            staleComputers = Test-CSVExists $staleComputersPath
            oldPwdComputers = Test-CSVExists $oldPwdComputersPath
            dormantUsers = Test-CSVExists $dormantUsersPath
            emptyGroups = Test-CSVExists $emptyGroupsPath
            emptyOUs = Test-CSVExists $emptyOUsPath
        }
    }
    
    # Add to grand totals
    $summaryData.grandTotal.staleComputers += $staleCount
    $summaryData.grandTotal.oldPasswords += $oldPwdCount
    $summaryData.grandTotal.dormantUsers += $dormantCount
    $summaryData.grandTotal.emptyGroups += $emptyGroupsCount
    $summaryData.grandTotal.emptyOUs += $emptyOUsCount
    $summaryData.grandTotal.totalIssues += $totalIssues
    
    Write-Host "  - Inactive Computers: $staleCount" -ForegroundColor Gray
    Write-Host "  - Computers with Expired Passwords: $oldPwdCount" -ForegroundColor Gray
    Write-Host "  - Inactive Users: $dormantCount" -ForegroundColor Gray
    Write-Host "  - Unused Security Groups (Never Used): $emptyGroupsCount" -ForegroundColor Gray
    Write-Host "  - Empty OUs: $emptyOUsCount" -ForegroundColor Gray
    Write-Host "  - Total Issues: $totalIssues" -ForegroundColor White
}

# Convert summary data to JavaScript
Write-Host ""
Write-Host "Generating FRESH final dashboard..." -ForegroundColor Green
$summaryDataJson = $summaryData | ConvertTo-Json -Depth 5 -Compress

# Complete HTML with corrected terminology
$completeHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Housekeeping Dashboard - FRESH Final</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }
        .header h1 {
            color: #2d3748;
            font-size: 3rem;
            margin-bottom: 15px;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .header p { color: #718096; font-size: 1.2rem; margin-bottom: 25px; }
        .controls {
            display: flex;
            gap: 30px;
            align-items: center;
            flex-wrap: wrap;
        }
        .domain-selector {
            display: flex;
            align-items: center;
            gap: 15px;
            background: rgba(102, 126, 234, 0.1);
            padding: 15px 25px;
            border-radius: 15px;
        }
        .domain-selector label { font-weight: 700; color: #4a5568; font-size: 1.1rem; }
        .domain-selector select {
            padding: 12px 20px;
            border: 2px solid #e2e8f0;
            border-radius: 12px;
            background: white;
            font-size: 1.1rem;
            color: #4a5568;
            cursor: pointer;
            font-weight: 600;
            min-width: 200px;
        }
        .status-info { margin-left: auto; text-align: right; color: #718096; }
        .status-info strong { color: #4a5568; font-weight: 700; }
        .dashboard-content {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }
        .current-domain-title {
            font-size: 1.8rem;
            font-weight: 700;
            color: #4a5568;
            margin-bottom: 30px;
            text-align: center;
            padding: 15px;
            background: linear-gradient(135deg, #f7fafc, #edf2f7);
            border-radius: 15px;
            border-left: 5px solid #667eea;
        }
        .overview-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }
        .card {
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            border-radius: 20px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
            position: relative;
        }
        .card:hover { transform: translateY(-5px); box-shadow: 0 20px 50px rgba(0, 0, 0, 0.15); }
        .card-icon { font-size: 3.5rem; margin-bottom: 20px; }
        .card-title {
            font-size: 1.1rem;
            color: #4a5568;
            margin-bottom: 15px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .card-value {
            font-size: 2.8rem;
            font-weight: 900;
            color: #2d3748;
            margin-bottom: 10px;
        }
        .card-subtitle { 
            font-size: 1rem; 
            color: #718096; 
            font-weight: 500; 
            margin-bottom: 15px;
        }
        .download-link {
            display: inline-block;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            text-decoration: none;
            font-size: 0.85rem;
            font-weight: 600;
            transition: all 0.3s ease;
            margin-top: 10px;
        }
        .download-link:hover {
            background: linear-gradient(135deg, #5a67d8, #6b46c1);
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }
        .download-link.disabled {
            background: #e2e8f0;
            color: #a0aec0;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
            pointer-events: none;
        }
        .risk-indicator {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 25px;
            font-size: 0.85rem;
            font-weight: 800;
            text-transform: uppercase;
        }
        .risk-low { background: #c6f6d5; color: #22543d; }
        .risk-medium { background: #fed7aa; color: #9c4221; }
        .risk-high { background: #fed7d7; color: #742a2a; }
        .risk-critical { background: #feb2b2; color: #742a2a; }
        .domain-comparison {
            margin-top: 40px;
            padding: 30px;
            background: linear-gradient(135deg, #f8fafc, #edf2f7);
            border-radius: 20px;
        }
        .success-message {
            padding: 20px;
            border-radius: 15px;
            margin: 20px 0;
            background: #c6f6d5;
            color: #22543d;
            border-left: 5px solid #38a169;
        }
        .simple-charts {
            margin-top: 30px;
            padding: 20px;
            background: #f8fafc;
            border-radius: 15px;
            border: 1px solid #e2e8f0;
        }
        .chart-title {
            font-size: 1.2rem;
            font-weight: 700;
            color: #4a5568;
            margin-bottom: 15px;
            text-align: center;
        }
        .simple-bar {
            display: flex;
            align-items: center;
            margin: 10px 0;
            gap: 10px;
        }
        .bar-label {
            min-width: 80px;
            font-size: 0.9rem;
            font-weight: 600;
        }
        .bar-visual {
            flex: 1;
            height: 20px;
            background: #e2e8f0;
            border-radius: 10px;
            overflow: hidden;
        }
        .bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            border-radius: 10px;
            transition: width 1s ease;
        }
        .bar-value {
            min-width: 60px;
            text-align: right;
            font-size: 0.9rem;
            font-weight: 600;
        }
        .fresh-badge {
            background: #38a169;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-left: 10px;
        }
        
        /* DOMAIN BREAKDOWN CHART STYLES - VERTICAL LAYOUT */
        .domain-breakdown-charts {
            margin-top: 30px;
            padding: 20px;
            background: #f8fafc;
            border-radius: 15px;
            border: 1px solid #e2e8f0;
        }
        .breakdown-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }
        .domain-breakdown-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            border-left: 4px solid #667eea;
        }
        .breakdown-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #e2e8f0;
        }
        .breakdown-domain-name {
            font-size: 1.1rem;
            font-weight: 700;
            color: #4a5568;
        }
        .breakdown-total {
            font-size: 0.9rem;
            color: #718096;
            font-weight: 600;
        }
        .breakdown-vertical-bars {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-top: 10px;
        }
        .breakdown-vertical-bar {
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
        }
        .breakdown-bar-container {
            width: 100%;
            height: 120px;
            background: #f1f5f9;
            border-radius: 8px;
            display: flex;
            flex-direction: column;
            justify-content: flex-end;
            padding: 4px;
            margin-bottom: 8px;
            position: relative;
        }
        .breakdown-vertical-fill {
            width: 100%;
            border-radius: 4px;
            transition: height 1s ease;
            min-height: 2px;
        }
        .breakdown-vertical-fill.stale-computers { background: linear-gradient(180deg, #3b82f6, #1d4ed8); }
        .breakdown-vertical-fill.expired-passwords { background: linear-gradient(180deg, #f59e0b, #d97706); }
        .breakdown-vertical-fill.inactive-users { background: linear-gradient(180deg, #8b5cf6, #7c3aed); }
        .breakdown-vertical-fill.unused-groups { background: linear-gradient(180deg, #10b981, #059669); }
        .breakdown-icon-label {
            font-size: 1.2rem;
            margin-bottom: 4px;
        }
        .breakdown-short-label {
            font-size: 0.75rem;
            font-weight: 600;
            color: #4a5568;
            line-height: 1.2;
            margin-bottom: 4px;
        }
        .breakdown-value {
            font-size: 0.8rem;
            font-weight: 700;
            color: #374151;
        }
        
        @media (max-width: 768px) {
            .container { padding: 15px; }
            .header { padding: 25px; }
            .header h1 { font-size: 2.2rem; }
            .overview-cards { grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
            .card { padding: 25px; }
            .card-value { font-size: 2.3rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏢 AD Housekeeping Dashboard <span class="fresh-badge">FRESH</span></h1>
            <p>Enterprise Active Directory housekeeping analysis - corrected terminology and group counting</p>
            <div class="controls">
                <div class="domain-selector">
                    <label for="domainSelect">🌐 Domain:</label>
                    <select id="domainSelect">
                        <option value="">All Domains Summary</option>
                    </select>
                </div>
                <div class="status-info">
                    <div>Last Updated: <strong id="lastUpdated">-</strong></div>
                </div>
            </div>
        </div>

        <div class="dashboard-content">
            <div id="messageContainer"></div>
            <div class="current-domain-title" id="currentDomainTitle">All Domains Summary</div>
            
            <div class="overview-cards">
                <div class="card">
                    <div class="card-icon">📊</div>
                    <div class="card-title">Total Issues</div>
                    <div class="card-value" id="totalIssues">0</div>
                    <div class="card-subtitle">
                        Overall Risk Level: <span id="overallRisk" class="risk-indicator risk-low">LOW</span>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-icon">💻</div>
                    <div class="card-title">Inactive Computer Accounts</div>
                    <div class="card-value" id="staleComputersCount">0</div>
                    <div class="card-subtitle">Computers not communicating with domain</div>
                    <a href="#" class="download-link disabled" id="downloadStaleComputers">📥 Download Complete Report</a>
                </div>
                
                <div class="card">
                    <div class="card-icon">🔐</div>
                    <div class="card-title">Computers with Expired Passwords</div>
                    <div class="card-value" id="oldPasswordsCount">0</div>
                    <div class="card-subtitle">Computers with outdated password credentials</div>
                    <a href="#" class="download-link disabled" id="downloadOldPasswords">📥 Download Complete Report</a>
                </div>
                
                <div class="card">
                    <div class="card-icon">👤</div>
                    <div class="card-title">Inactive User Accounts</div>
                    <div class="card-value" id="dormantUsersCount">0</div>
                    <div class="card-subtitle">User accounts with no recent activity</div>
                    <a href="#" class="download-link disabled" id="downloadDormantUsers">📥 Download Complete Report</a>
                </div>
                
                <div class="card">
                    <div class="card-icon">👥</div>
                    <div class="card-title">Unused Security Groups</div>
                    <div class="card-value" id="emptyGroupsCount">0</div>
                    <div class="card-subtitle">Groups unused for extended periods (never-used only)</div>
                    <a href="#" class="download-link disabled" id="downloadEmptyGroups">📥 Download Complete Report</a>
                </div>
                
                <div class="card">
                    <div class="card-icon">📁</div>
                    <div class="card-title">Empty Organizational Units</div>
                    <div class="card-value" id="emptyOUsCount">0</div>
                    <div class="card-subtitle">Unused OU containers</div>
                    <a href="#" class="download-link disabled" id="downloadEmptyOUs">📥 Download Complete Report</a>
                </div>
            </div>

            <div class="simple-charts" id="simpleCharts">
                <div class="chart-title">📊 Domain Issue Comparison</div>
                <div id="domainBars">
                    <!-- Simple bars will be generated here -->
                </div>
            </div>

            <!-- NEW DOMAIN BREAKDOWN CHART -->
            <div class="domain-breakdown-charts" id="domainBreakdownCharts">
                <div class="chart-title">📈 Domain Issue Breakdown</div>
                <div class="breakdown-grid" id="breakdownGrid">
                    <!-- Domain breakdown cards will be generated here -->
                </div>
            </div>

            <div class="domain-comparison" id="domainComparison">
                <h3 style="margin-bottom: 20px; color: #4a5568;">📊 Loading domain data...</h3>
            </div>
        </div>
    </div>

    <script>
        const summaryData = $summaryDataJson;
        let currentDomain = '';
        
        document.addEventListener('DOMContentLoaded', function() {
            console.log('FRESH Final AD Dashboard initialized');
            initializeDashboard();
        });
        
        function initializeDashboard() {
            const domainSelect = document.getElementById('domainSelect');
            const domains = Object.keys(summaryData.domains);
            
            domains.forEach(domain => {
                const option = document.createElement('option');
                option.value = domain;
                option.textContent = domain;
                domainSelect.appendChild(option);
            });
            
            document.getElementById('lastUpdated').textContent = new Date(summaryData.lastUpdated).toLocaleString();
            
            updateGrandTotals();
            updateSimpleCharts();
            updateDomainBreakdownCharts();
            
            domainSelect.addEventListener('change', function() {
                currentDomain = this.value;
                if (this.value) {
                    updateDomainView(this.value);
                } else {
                    updateGrandTotals();
                }
                updateSimpleCharts();
                updateDomainBreakdownCharts();
            });
            
            showMessage('Loaded ' + summaryData.totalDomains + ' domains with corrected terminology', 'success');
        }
        
        function updateGrandTotals() {
            const data = summaryData.grandTotal;
            currentDomain = '';
            
            document.getElementById('totalIssues').textContent = data.totalIssues.toLocaleString();
            document.getElementById('staleComputersCount').textContent = data.staleComputers.toLocaleString();
            document.getElementById('oldPasswordsCount').textContent = data.oldPasswords.toLocaleString();
            document.getElementById('dormantUsersCount').textContent = data.dormantUsers.toLocaleString();
            document.getElementById('emptyGroupsCount').textContent = data.emptyGroups.toLocaleString();
            document.getElementById('emptyOUsCount').textContent = data.emptyOUs.toLocaleString();
            
            updateRiskIndicator(data.totalIssues);
            updateDomainComparison();
            updateDownloadLinks();
            
            document.getElementById('currentDomainTitle').textContent = 'All Domains Summary';
        }
        
        function updateDomainView(domainName) {
            const data = summaryData.domains[domainName];
            
            document.getElementById('totalIssues').textContent = data.totalIssues.toLocaleString();
            document.getElementById('staleComputersCount').textContent = data.staleComputers.toLocaleString();
            document.getElementById('oldPasswordsCount').textContent = data.oldPasswords.toLocaleString();
            document.getElementById('dormantUsersCount').textContent = data.dormantUsers.toLocaleString();
            document.getElementById('emptyGroupsCount').textContent = data.emptyGroups.toLocaleString();
            document.getElementById('emptyOUsCount').textContent = data.emptyOUs.toLocaleString();
            
            updateRiskIndicator(data.totalIssues);
            updateDownloadLinks();
            
            document.getElementById('currentDomainTitle').textContent = 'Domain: ' + domainName;
        }
        
        function updateDownloadLinks() {
            const links = [
                { id: 'downloadStaleComputers', type: 'staleComputers', filename: 'StaleComputers_Detailed.csv' },
                { id: 'downloadOldPasswords', type: 'oldPwdComputers', filename: 'OldPwdComputers_Detailed.csv' },
                { id: 'downloadDormantUsers', type: 'dormantUsers', filename: 'DormantUsers_Detailed.csv' },
                { id: 'downloadEmptyGroups', type: 'emptyGroups', filename: 'EmptyGroups_NeverUsed.csv' },
                { id: 'downloadEmptyOUs', type: 'emptyOUs', filename: 'EmptyOUs.csv' }
            ];
            
            links.forEach(link => {
                const element = document.getElementById(link.id);
                if (currentDomain && summaryData.domains[currentDomain] && summaryData.domains[currentDomain].filesAvailable[link.type]) {
                    element.classList.remove('disabled');
                    element.href = './AD_Housekeeping_Reports/' + currentDomain + '/' + link.filename;
                    element.download = link.filename.replace('.csv', '_' + currentDomain + '_' + new Date().toISOString().slice(0, 10) + '.csv');
                } else {
                    element.classList.add('disabled');
                    element.href = '#';
                    element.removeAttribute('download');
                }
            });
        }
        
        function updateRiskIndicator(totalIssues) {
            const riskElement = document.getElementById('overallRisk');
            
            if (totalIssues > 50000) {
                riskElement.textContent = 'CRITICAL';
                riskElement.className = 'risk-indicator risk-critical';
            } else if (totalIssues > 10000) {
                riskElement.textContent = 'HIGH';
                riskElement.className = 'risk-indicator risk-high';
            } else if (totalIssues > 1000) {
                riskElement.textContent = 'MEDIUM';
                riskElement.className = 'risk-indicator risk-medium';
            } else {
                riskElement.textContent = 'LOW';
                riskElement.className = 'risk-indicator risk-low';
            }
        }
        
        function updateDomainComparison() {
            const container = document.getElementById('domainComparison');
            const domains = Object.keys(summaryData.domains);
            
            let html = '<h3 style="margin-bottom: 20px; color: #4a5568;">📊 Domain Comparison</h3>';
            html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 15px;">';
            
            domains.forEach(function(domainName) {
                const data = summaryData.domains[domainName];
                const riskClass = data.totalIssues > 50000 ? 'risk-critical' : 
                                 data.totalIssues > 10000 ? 'risk-high' : 
                                 data.totalIssues > 1000 ? 'risk-medium' : 'risk-low';
                
                html += '<div style="background: #f7fafc; border-radius: 8px; padding: 15px; border-left: 4px solid #667eea;">';
                html += '<h4 style="color: #4a5568; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;">';
                html += domainName;
                html += '<span class="risk-indicator ' + riskClass + '" style="font-size: 0.7rem;">' + (data.totalIssues > 50000 ? 'CRITICAL' : data.totalIssues > 10000 ? 'HIGH' : data.totalIssues > 1000 ? 'MEDIUM' : 'LOW') + '</span>';
                html += '</h4>';
                html += '<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.9rem;">';
                html += '<div>💻 Stale Computers: <strong>' + data.staleComputers.toLocaleString() + '</strong></div>';
                html += '<div>🔐 Computers with Expired Passwords: <strong>' + data.oldPasswords.toLocaleString() + '</strong></div>';
                html += '<div>👤 Inactive Users: <strong>' + data.dormantUsers.toLocaleString() + '</strong></div>';
                html += '<div>👥 Never-Used Groups: <strong>' + data.emptyGroups.toLocaleString() + '</strong></div>';
                html += '</div>';
                html += '<div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #e2e8f0; font-weight: 600; color: #2d3748;">';
                html += 'Total Issues: ' + data.totalIssues.toLocaleString();
                html += '</div></div>';
            });
            
            html += '</div>';
            container.innerHTML = html;
        }
        
        function updateSimpleCharts() {
            const container = document.getElementById('domainBars');
            const domains = Object.keys(summaryData.domains);
            
            let maxIssues = 0;
            domains.forEach(domain => {
                const issues = summaryData.domains[domain].totalIssues;
                if (issues > maxIssues) maxIssues = issues;
            });
            
            let html = '';
            domains.forEach(domain => {
                const data = summaryData.domains[domain];
                const percentage = maxIssues > 0 ? (data.totalIssues / maxIssues) * 100 : 0;
                
                html += '<div class="simple-bar">';
                html += '<div class="bar-label">' + domain + '</div>';
                html += '<div class="bar-visual">';
                html += '<div class="bar-fill" style="width: ' + percentage + '%;"></div>';
                html += '</div>';
                html += '<div class="bar-value">' + data.totalIssues.toLocaleString() + '</div>';
                html += '</div>';
            });
            
            container.innerHTML = html;
        }
        
        // NEW DOMAIN BREAKDOWN CHARTS FUNCTION - VERTICAL BARS
        function updateDomainBreakdownCharts() {
            const container = document.getElementById('breakdownGrid');
            const domains = Object.keys(summaryData.domains);
            
            let html = '';
            domains.forEach(domain => {
                const data = summaryData.domains[domain];
                
                // Find max value for scaling within this domain
                const maxValue = Math.max(data.staleComputers, data.oldPasswords, data.dormantUsers, data.emptyGroups);
                
                // Risk class for border color
                const riskClass = data.totalIssues > 50000 ? 'risk-critical' : 
                                 data.totalIssues > 10000 ? 'risk-high' : 
                                 data.totalIssues > 1000 ? 'risk-medium' : 'risk-low';
                
                const borderColor = riskClass === 'risk-critical' ? '#dc2626' :
                                   riskClass === 'risk-high' ? '#ea580c' :
                                   riskClass === 'risk-medium' ? '#d97706' : '#059669';
                
                html += '<div class="domain-breakdown-card" style="border-left-color: ' + borderColor + ';">';
                html += '<div class="breakdown-header">';
                html += '<div class="breakdown-domain-name">' + domain + '</div>';
                html += '<div class="breakdown-total">Total: ' + data.totalIssues.toLocaleString() + '</div>';
                html += '</div>';
                
                html += '<div class="breakdown-vertical-bars">';
                
                // Stale Computers
                const staleComputersPct = maxValue > 0 ? (data.staleComputers / maxValue) * 100 : 0;
                html += '<div class="breakdown-vertical-bar">';
                html += '<div class="breakdown-bar-container">';
                html += '<div class="breakdown-vertical-fill stale-computers" style="height: ' + staleComputersPct + '%;"></div>';
                html += '</div>';
                html += '<div class="breakdown-icon-label">💻</div>';
                html += '<div class="breakdown-short-label">Stale<br>Computers</div>';
                html += '<div class="breakdown-value">' + data.staleComputers.toLocaleString() + '</div>';
                html += '</div>';
                
                // Computers with Expired Passwords
                const expiredPwdPct = maxValue > 0 ? (data.oldPasswords / maxValue) * 100 : 0;
                html += '<div class="breakdown-vertical-bar">';
                html += '<div class="breakdown-bar-container">';
                html += '<div class="breakdown-vertical-fill expired-passwords" style="height: ' + expiredPwdPct + '%;"></div>';
                html += '</div>';
                html += '<div class="breakdown-icon-label">🔐</div>';
                html += '<div class="breakdown-short-label">Expired<br>Passwords (Computers)</div>';
                html += '<div class="breakdown-value">' + data.oldPasswords.toLocaleString() + '</div>';
                html += '</div>';
                
                // Inactive Users
                const inactiveUsersPct = maxValue > 0 ? (data.dormantUsers / maxValue) * 100 : 0;
                html += '<div class="breakdown-vertical-bar">';
                html += '<div class="breakdown-bar-container">';
                html += '<div class="breakdown-vertical-fill inactive-users" style="height: ' + inactiveUsersPct + '%;"></div>';
                html += '</div>';
                html += '<div class="breakdown-icon-label">👤</div>';
                html += '<div class="breakdown-short-label">Inactive<br>Users</div>';
                html += '<div class="breakdown-value">' + data.dormantUsers.toLocaleString() + '</div>';
                html += '</div>';
                
                // Never-Used Groups
                const unusedGroupsPct = maxValue > 0 ? (data.emptyGroups / maxValue) * 100 : 0;
                html += '<div class="breakdown-vertical-bar">';
                html += '<div class="breakdown-bar-container">';
                html += '<div class="breakdown-vertical-fill unused-groups" style="height: ' + unusedGroupsPct + '%;"></div>';
                html += '</div>';
                html += '<div class="breakdown-icon-label">👥</div>';
                html += '<div class="breakdown-short-label">Never-Used<br>Groups</div>';
                html += '<div class="breakdown-value">' + data.emptyGroups.toLocaleString() + '</div>';
                html += '</div>';
                
                html += '</div>'; // Close breakdown-vertical-bars
                html += '</div>'; // Close domain-breakdown-card
            });
            
            container.innerHTML = html;
        }
        
        function showMessage(message, type) {
            const container = document.getElementById('messageContainer');
            container.innerHTML = '<div class="success-message">✅ ' + message + '</div>';
            setTimeout(function() {
                container.innerHTML = '';
            }, 3000);
        }
    </script>
</body>
</html>
"@

# Write the fresh dashboard
Write-Host "Writing FRESH final dashboard to: $OutputFile" -ForegroundColor Green
[System.IO.File]::WriteAllText($OutputFile, $completeHtml, [System.Text.Encoding]::UTF8)

Write-Host ""
Write-Host "SUCCESS: FRESH final dashboard created!" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green
Write-Host ""
Write-Host "File created: $OutputFile" -ForegroundColor White
Write-Host "Total domains: $($summaryData.totalDomains)" -ForegroundColor White
Write-Host "Grand total issues: $($summaryData.grandTotal.totalIssues)" -ForegroundColor White
Write-Host "Last updated: $($summaryData.lastUpdated)" -ForegroundColor White
Write-Host ""
Write-Host "FRESH CORRECTED FEATURES:" -ForegroundColor Green
Write-Host "- Domain comparison shows: 'Computers with Expired Passwords' for clarity" -ForegroundColor White
Write-Host "- Card title: 'Computers with Expired Passwords'" -ForegroundColor White
Write-Host "- 'Unused Security Groups' only counts never-used groups" -ForegroundColor White
Write-Host "- Vertical bar charts for better visual clarity and space efficiency" -ForegroundColor White
Write-Host "- Completely fresh version to eliminate caching issues" -ForegroundColor White

