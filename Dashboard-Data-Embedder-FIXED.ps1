# Dashboard Data Embedder Script
# Integrates collected AD data into the HTML dashboard
# Version: 3.1 - Syntax Fixed

param(
    [string]$DataPath = "data",
    [string]$DashboardPath = "dashboard",
    [string]$ConsolidatedDataFile = "",
    [switch]$Verbose
)

if ($Verbose) {
    $VerbosePreference = "Continue"
}

Write-Host "🔄 Dashboard Data Embedder v3.1 (Syntax Fixed)" -ForegroundColor Cyan
Write-Host "📅 Started: $(Get-Date)" -ForegroundColor Gray
Write-Host "=" * 60 -ForegroundColor DarkGray

# Determine consolidated data file path
if ($ConsolidatedDataFile -eq "") {
    $ConsolidatedDataFile = Join-Path $DataPath "consolidated\consolidated-data.json"
}

# Verify input files exist
if (-not (Test-Path $ConsolidatedDataFile)) {
    Write-Host "❌ Consolidated data file not found: $ConsolidatedDataFile" -ForegroundColor Red
    Write-Host "💡 Please run data collection first to generate the consolidated data file." -ForegroundColor Yellow
    exit 1
}

# Create dashboard directory if it doesn't exist
if (-not (Test-Path $DashboardPath)) {
    try {
        New-Item -ItemType Directory -Path $DashboardPath -Force | Out-Null
        Write-Host "📁 Created dashboard directory: $DashboardPath" -ForegroundColor Green
    } catch {
        Write-Host "❌ Error creating dashboard directory: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Read consolidated data
Write-Host "📊 Reading consolidated data..." -ForegroundColor Yellow
try {
    $consolidatedJson = Get-Content $ConsolidatedDataFile -Raw -Encoding UTF8
    $consolidatedData = $consolidatedJson | ConvertFrom-Json
    Write-Host "✅ Consolidated data loaded successfully" -ForegroundColor Green
    Write-Host "📈 Data includes $($consolidatedData.metadata.totalDomains) domains with $($consolidatedData.metadata.successfulCollections) successful collections" -ForegroundColor Gray
} catch {
    Write-Host "❌ Error reading consolidated data: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Create enhanced JavaScript file with embedded data
Write-Host "📝 Creating enhanced dashboard script..." -ForegroundColor Yellow

try {
    $scriptContent = @"
// Enhanced Multi-Domain Active Directory Dashboard
// Version: 3.1 - Enterprise Edition (Syntax Fixed)
// Generated: $(Get-Date)
// Data Collection: $($consolidatedData.metadata.generatedOn)

// Embedded consolidated data
window.embeddedConsolidatedData = $consolidatedJson;

// Dashboard configuration
const DASHBOARD_CONFIG = {
    version: '3.1',
    title: 'Enhanced Multi-Domain Active Directory Dashboard',
    refreshInterval: 30000, // 30 seconds
    maxDisplayItems: 1000,
    enableAnimations: true,
    enableNotifications: true,
    defaultView: 'overview',
    domainColors: {
        'europa': '#3498db',
        'fm': '#9b59b6',
        'rbsgretail': '#e67e22',
        'rbsgrp': '#1abc9c',
        'rbsres01': '#e74c3c',
        'dsdom02': '#f1c40f'
    }
};

// Dashboard state management
let dashboardState = {
    currentDomain: 'all',
    currentTab: 'overview',
    consolidatedData: null,
    lastUpdate: null,
    isLoading: false,
    notifications: []
};

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Enhanced Multi-Domain AD Dashboard Starting...');
    console.log('📊 Dashboard Version:', DASHBOARD_CONFIG.version);
    
    // Use embedded data
    dashboardState.consolidatedData = window.embeddedConsolidatedData;
    dashboardState.lastUpdate = new Date(dashboardState.consolidatedData.metadata.generatedOn);
    
    console.log('✅ Using embedded data, generated:', dashboardState.lastUpdate.toLocaleString());
    console.log('📈 Data summary:', {
        domains: dashboardState.consolidatedData.metadata.totalDomains,
        successful: dashboardState.consolidatedData.metadata.successfulCollections,
        failed: dashboardState.consolidatedData.metadata.failedCollections
    });
    
    // Initialize dashboard
    initializeEnhancedDashboard();
});

// Initialize the enhanced dashboard
function initializeEnhancedDashboard() {
    try {
        console.log('📊 Initializing enhanced dashboard...');
        
        // Update page title
        document.title = DASHBOARD_CONFIG.title;
        
        // Initialize domain selector
        initializeDomainSelector();
        
        // Update metrics
        updateEnhancedMetrics();
        
        // Initialize tabs
        initializeTabSystem();
        
        // Update last refresh time
        updateLastRefreshTime();
        
        // Show success notification
        showNotification('Dashboard loaded successfully with real AD data from ' + 
            dashboardState.consolidatedData.metadata.successfulCollections + ' domains!', 'success');
        
        console.log('✅ Enhanced dashboard initialization complete!');
        
    } catch (error) {
        console.error('❌ Error initializing enhanced dashboard:', error);
        showNotification('Error loading dashboard: ' + error.message, 'error');
        showErrorState();
    }
}

// Initialize domain selector
function initializeDomainSelector() {
    const domainSelector = document.getElementById('domainSelector');
    if (!domainSelector) return;
    
    // Clear existing options
    domainSelector.innerHTML = '';
    
    // Add "All Domains" option
    const allOption = document.createElement('option');
    allOption.value = 'all';
    allOption.textContent = 'All Domains';
    domainSelector.appendChild(allOption);
    
    // Add individual domain options
    if (dashboardState.consolidatedData.domainData) {
        Object.values(dashboardState.consolidatedData.domainData).forEach(domain => {
            if (domain.status === 'Completed') {
                const option = document.createElement('option');
                option.value = domain.info.id;
                option.textContent = domain.info.name;
                domainSelector.appendChild(option);
            }
        });
    }
    
    // Set up change handler
    domainSelector.addEventListener('change', function() {
        switchDomain(this.value);
    });
}

// Switch domain view
function switchDomain(domainId) {
    console.log('🔄 Switching to domain:', domainId);
    dashboardState.currentDomain = domainId;
    
    // Update metrics for selected domain
    updateEnhancedMetrics();
    
    // Update tab content
    updateTabContent(dashboardState.currentTab);
    
    // Update domain indicator
    updateDomainIndicator();
}

// Update enhanced metric cards
function updateEnhancedMetrics() {
    if (!dashboardState.consolidatedData) {
        console.error('No consolidated data available');
        showErrorState();
        return;
    }
    
    let metricsData;
    
    if (dashboardState.currentDomain === 'all') {
        // Use aggregated summary for all domains
        metricsData = dashboardState.consolidatedData.aggregatedSummary;
    } else {
        // Use specific domain data
        const domainData = dashboardState.consolidatedData.domainData[dashboardState.currentDomain];
        if (domainData && domainData.status === 'Completed') {
            metricsData = domainData.summary;
        } else {
            showNotification('Domain data not available or collection failed', 'warning');
            return;
        }
    }
    
    console.log('📈 Updating metrics for domain:', dashboardState.currentDomain, metricsData);
    
    // Update each metric card with enhanced data
    updateMetricCard('totalUsers', metricsData.totalUsers || 0);
    updateMetricCard('activeComputers', metricsData.activeComputers || 0);
    updateMetricCard('securityGroups', metricsData.securityGroups || 0);
    updateMetricCard('domainControllers', metricsData.domainControllers || 0);
}

// Update individual metric card
function updateMetricCard(cardId, primaryValue) {
    const card = document.getElementById(cardId);
    if (!card) {
        console.warn('Metric card not found:', cardId);
        return;
    }
    
    const valueElement = card.querySelector('.metric-value');
    
    if (valueElement) {
        valueElement.textContent = formatNumber(primaryValue);
        valueElement.classList.remove('loading', 'error');
    }
    
    console.log('✅ Updated', cardId + ':', primaryValue);
}

// Format numbers with commas
function formatNumber(num) {
    if (typeof num !== 'number') return '0';
    return num.toLocaleString();
}

// Initialize tab system
function initializeTabSystem() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');
            if (tabName) {
                switchTab(tabName);
            }
        });
    });
    
    // Initialize with overview tab
    switchTab('overview');
}

// Enhanced tab switching
function switchTab(tabName) {
    console.log('🔄 Switching to tab:', tabName);
    dashboardState.currentTab = tabName;
    
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Find and activate the clicked tab
    const activeTab = document.querySelector('[data-tab="' + tabName + '"]');
    if (activeTab) {
        activeTab.classList.add('active');
    }
    
    // Update tab content
    updateTabContent(tabName);
}

// Update tab content
function updateTabContent(tabName) {
    const tabContent = document.getElementById('tabContent');
    if (!tabContent) return;
    
    let content = '';
    
    switch (tabName) {
        case 'overview':
            content = generateOverviewContent();
            break;
        case 'users':
            content = generateUsersContent();
            break;
        case 'computers':
            content = generateComputersContent();
            break;
        case 'security':
            content = generateSecurityContent();
            break;
        case 'domains':
            content = generateDomainsContent();
            break;
        case 'reports':
            content = generateReportsContent();
            break;
        default:
            content = '<div>Tab content not available</div>';
    }
    
    tabContent.innerHTML = content;
}

// Generate overview content
function generateOverviewContent() {
    if (!dashboardState.consolidatedData) return '<div>No data available</div>';
    
    const metadata = dashboardState.consolidatedData.metadata || {};
    const summary = dashboardState.consolidatedData.aggregatedSummary || {};
    
    return '<div id="overview-content">' +
        '<h3>📊 Multi-Domain Overview</h3>' +
        '<div class="overview-stats">' +
            '<div class="stat-card">' +
                '<h4>📈 Collection Summary</h4>' +
                '<p><strong>Total Domains:</strong> ' + (metadata.totalDomains || 0) + '</p>' +
                '<p><strong>Successful Collections:</strong> ' + (metadata.successfulCollections || 0) + '</p>' +
                '<p><strong>Failed Collections:</strong> ' + (metadata.failedCollections || 0) + '</p>' +
                '<p><strong>Collection Duration:</strong> ' + (metadata.collectionDuration || 0) + ' minutes</p>' +
            '</div>' +
            '<div class="stat-card">' +
                '<h4>👥 User Statistics</h4>' +
                '<p><strong>Total Users:</strong> ' + formatNumber(summary.totalUsers || 0) + '</p>' +
                '<p><strong>Active Users:</strong> ' + formatNumber(summary.activeUsers || 0) + '</p>' +
                '<p><strong>Disabled Users:</strong> ' + formatNumber(summary.disabledUsers || 0) + '</p>' +
            '</div>' +
            '<div class="stat-card">' +
                '<h4>💻 Computer Statistics</h4>' +
                '<p><strong>Total Computers:</strong> ' + formatNumber(summary.totalComputers || 0) + '</p>' +
                '<p><strong>Active Computers:</strong> ' + formatNumber(summary.activeComputers || 0) + '</p>' +
            '</div>' +
        '</div>' +
    '</div>';
}

// Generate users content
function generateUsersContent() {
    return '<div><h3>👥 User Management</h3><p>User details and management interface will be displayed here.</p></div>';
}

// Generate computers content
function generateComputersContent() {
    return '<div><h3>💻 Computer Management</h3><p>Computer inventory and status information will be displayed here.</p></div>';
}

// Generate security content
function generateSecurityContent() {
    return '<div><h3>🛡️ Security Overview</h3><p>Security groups, permissions, and compliance information will be displayed here.</p></div>';
}

// Generate domains content
function generateDomainsContent() {
    return '<div><h3>🌐 Domain Information</h3><p>Detailed domain configuration and status information will be displayed here.</p></div>';
}

// Generate reports content
function generateReportsContent() {
    return '<div><h3>📊 Reports</h3><p>Comprehensive reports and analytics will be displayed here.</p></div>';
}

// Show notification
function showNotification(message, type) {
    console.log('📢 Notification (' + type + '):', message);
}

// Show error state
function showErrorState() {
    console.error('❌ Dashboard in error state');
}

// Update last refresh time
function updateLastRefreshTime() {
    const lastUpdateElement = document.getElementById('lastUpdate');
    if (lastUpdateElement && dashboardState.lastUpdate) {
        lastUpdateElement.textContent = 'Last updated: ' + dashboardState.lastUpdate.toLocaleString();
    }
}

// Update domain indicator
function updateDomainIndicator() {
    const domainIndicator = document.getElementById('currentDomain');
    if (domainIndicator) {
        if (dashboardState.currentDomain === 'all') {
            domainIndicator.textContent = 'All Domains';
        } else {
            const domainData = dashboardState.consolidatedData.domainData[dashboardState.currentDomain];
            if (domainData && domainData.info) {
                domainIndicator.textContent = domainData.info.name;
            }
        }
    }
}

console.log('✅ Enhanced dashboard script loaded successfully');
"@

    # Write the enhanced script to the dashboard directory
    $scriptPath = Join-Path $DashboardPath "enhanced-dashboard-data.js"
    $scriptContent | Set-Content -Path $scriptPath -Encoding UTF8
    Write-Host "✅ Enhanced dashboard script created: $scriptPath" -ForegroundColor Green

    # Update the main dashboard HTML file to use the embedded data
    $dashboardHtmlPath = Join-Path $DashboardPath "index.html"
    if (Test-Path $dashboardHtmlPath) {
        Write-Host "🔄 Updating dashboard HTML file..." -ForegroundColor Yellow
        
        $htmlContent = Get-Content $dashboardHtmlPath -Raw -Encoding UTF8
        
        # Add reference to the enhanced script if not already present
        if ($htmlContent -notmatch "enhanced-dashboard-data\.js") {
            $scriptTag = "`n    <script src=`"enhanced-dashboard-data.js`"></script>"
            $htmlContent = $htmlContent -replace "(<\/body>)", "$scriptTag`n`$1"
            $htmlContent | Set-Content -Path $dashboardHtmlPath -Encoding UTF8
            Write-Host "✅ Dashboard HTML updated with enhanced script reference" -ForegroundColor Green
        } else {
            Write-Host "ℹ️ Dashboard HTML already includes enhanced script reference" -ForegroundColor Cyan
        }
    } else {
        Write-Host "⚠️ Dashboard HTML file not found at: $dashboardHtmlPath" -ForegroundColor Yellow
        Write-Host "💡 Please ensure the dashboard HTML file is present in the dashboard directory" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "✅ Dashboard Data Embedder completed successfully!" -ForegroundColor Green
    Write-Host "📊 Embedded data from $($consolidatedData.metadata.successfulCollections) domains" -ForegroundColor Cyan
    Write-Host "📈 Total statistics embedded:" -ForegroundColor Cyan
    Write-Host "   👥 Users: $($consolidatedData.aggregatedSummary.totalUsers)" -ForegroundColor Gray
    Write-Host "   💻 Computers: $($consolidatedData.aggregatedSummary.totalComputers)" -ForegroundColor Gray
    Write-Host "   🛡️ Groups: $($consolidatedData.aggregatedSummary.totalGroups)" -ForegroundColor Gray
    Write-Host "   🖥️ Domain Controllers: $($consolidatedData.aggregatedSummary.domainControllers)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "🎯 Next steps:" -ForegroundColor Magenta
    Write-Host "   1. Open the dashboard HTML file in a web browser" -ForegroundColor Gray
    Write-Host "   2. Verify that all data is displaying correctly" -ForegroundColor Gray
    Write-Host "   3. Use the domain selector to view individual domain data" -ForegroundColor Gray
    Write-Host ""

} catch {
    Write-Host "❌ Error creating dashboard script: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "📝 Error details: $($_.Exception.StackTrace)" -ForegroundColor Gray
    exit 1
}

