// Enhanced Multi-Domain Active Directory Dashboard - JavaScript Engine
// Version: 3.1 - Fully Offline Edition
// NO EXTERNAL DEPENDENCIES - Works in completely locked-down environments
// Comprehensive functionality for data processing, visualization, and interaction

// Dashboard Configuration and Constants
const DASHBOARD_CONFIG = {
    version: '3.1',
    title: 'Enhanced Multi-Domain Active Directory Dashboard',
    refreshInterval: 30000, // 30 seconds
    maxDisplayItems: 1000,
    enableAnimations: true,
    enableNotifications: true,
    defaultView: 'overview',
    autoSave: true,
    
    // Domain color mapping
    domainColors: {
        'corp-hq': '#3498db',
        'sales-region': '#9b59b6',
        'dev-environment': '#e67e22',
        'manufacturing': '#1abc9c',
        'finance-dept': '#e74c3c',
        'research-lab': '#f1c40f'
    },
    
    // Animation settings
    animations: {
        cardHover: 'transform 0.3s ease-in-out',
        tabSwitch: 'opacity 0.3s ease-in-out',
        notification: 'all 0.3s ease-in-out'
    },
    
    // Data refresh settings
    dataRefresh: {
        enabled: true,
        interval: 300000, // 5 minutes
        maxRetries: 3,
        retryDelay: 5000
    }
};

// Global Dashboard State Management
let dashboardState = {
    // Core state
    currentDomain: 'all',
    currentTab: 'overview',
    consolidatedData: null,
    lastUpdate: null,
    isLoading: false,
    
    // UI state
    notifications: [],
    activeFilters: {},
    sortOrder: 'asc',
    sortField: 'name',
    
    // Data state
    dataCache: new Map(),
    errorCount: 0,
    retryCount: 0,
    
    // User preferences
    preferences: {
        theme: 'light',
        compactView: false,
        showAnimations: true,
        autoRefresh: true
    }
};

// Utility Functions
const Utils = {
    // Number formatting with locale support
    formatNumber: function(num, options = {}) {
        if (num === null || num === undefined || isNaN(num)) return '0';
        
        const defaults = {
            minimumFractionDigits: 0,
            maximumFractionDigits: 0
        };
        
        const config = { ...defaults, ...options };
        
        try {
            return new Intl.NumberFormat('en-US', config).format(num);
        } catch (e) {
            // Fallback for older browsers
            return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        }
    },
    
    // Date formatting
    formatDate: function(date, options = {}) {
        if (!date) return 'Never';
        
        const dateObj = typeof date === 'string' ? new Date(date) : date;
        if (isNaN(dateObj.getTime())) return 'Invalid Date';
        
        const defaults = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        };
        
        const config = { ...defaults, ...options };
        
        try {
            return new Intl.DateTimeFormat('en-US', config).format(dateObj);
        } catch (e) {
            return dateObj.toLocaleString();
        }
    },
    
    // Percentage calculation
    calculatePercentage: function(part, total, decimals = 1) {
        if (!total || total === 0) return 0;
        return Math.round((part / total) * 100 * Math.pow(10, decimals)) / Math.pow(10, decimals);
    },
    
    // Debounce function for performance
    debounce: function(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    // Deep clone object
    deepClone: function(obj) {
        if (obj === null || typeof obj !== 'object') return obj;
        if (obj instanceof Date) return new Date(obj.getTime());
        if (obj instanceof Array) return obj.map(item => this.deepClone(item));
        if (typeof obj === 'object') {
            const clonedObj = {};
            for (const key in obj) {
                if (obj.hasOwnProperty(key)) {
                    clonedObj[key] = this.deepClone(obj[key]);
                }
            }
            return clonedObj;
        }
    },
    
    // Generate unique ID
    generateId: function() {
        return 'id_' + Math.random().toString(36).substr(2, 9);
    },
    
    // Sanitize HTML to prevent XSS
    sanitizeHtml: function(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
};

// Data Management Module
const DataManager = {
    // Load data from embedded source or external file
    loadData: async function() {
        try {
            dashboardState.isLoading = true;
            this.updateLoadingState(true);
            
            // Check for embedded data first
            if (window.embeddedConsolidatedData) {
                console.log('📊 Loading embedded data...');
                dashboardState.consolidatedData = window.embeddedConsolidatedData;
                dashboardState.lastUpdate = new Date(dashboardState.consolidatedData.metadata.generatedOn);
                return dashboardState.consolidatedData;
            }
            
            // Try to load from external file
            console.log('📊 Loading data from external file...');
            const response = await fetch('data/consolidated/consolidated-data.json');
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            dashboardState.consolidatedData = data;
            dashboardState.lastUpdate = new Date(data.metadata.generatedOn);
            
            // Cache the data
            dashboardState.dataCache.set('consolidated', data);
            
            return data;
            
        } catch (error) {
            console.error('❌ Error loading data:', error);
            this.handleDataError(error);
            // Don't re-throw error to allow graceful degradation
            return null;
        } finally {
            dashboardState.isLoading = false;
            this.updateLoadingState(false);
        }
    },
    
    // Handle data loading errors
    handleDataError: function(error) {
        dashboardState.errorCount++;
        
        const errorMessage = error.message || 'Unknown error occurred';
        console.error('Data loading error:', errorMessage);
        
        // Show user-friendly error message
        if (errorMessage.includes('fetch')) {
            NotificationManager.show(
                'Unable to load data. Please ensure the data files are available and run data collection.',
                'error'
            );
        } else {
            NotificationManager.show(
                'Error processing data: ' + errorMessage,
                'error'
            );
        }
        
        // Show error state in UI
        this.showErrorState();
    },
    
    // Update loading state in UI
    updateLoadingState: function(isLoading) {
        const metricCards = document.querySelectorAll('.metric-value');
        metricCards.forEach(card => {
            if (isLoading) {
                card.classList.add('loading');
                card.textContent = 'Loading...';
            } else {
                card.classList.remove('loading');
            }
        });
    },
    
    // Show error state in UI
    showErrorState: function() {
        const metricCards = document.querySelectorAll('.metric-value');
        metricCards.forEach(card => {
            card.textContent = 'Error';
            card.classList.remove('loading');
            card.classList.add('error');
        });
    },
    
    // Get domain-specific data
    getDomainData: function(domainId) {
        if (!dashboardState.consolidatedData) return null;
        
        if (domainId === 'all') {
            return {
                summary: dashboardState.consolidatedData.aggregatedSummary,
                metadata: dashboardState.consolidatedData.metadata
            };
        }
        
        return dashboardState.consolidatedData.domainData[domainId] || null;
    },
    
    // Get available domains
    getAvailableDomains: function() {
        // First try to load configured domains from localStorage
        try {
            const savedConfig = localStorage.getItem('adDashboardConfig');
            if (savedConfig) {
                const config = JSON.parse(savedConfig);
                if (config.domains && config.domains.length > 0) {
                    console.log('📊 Loading domains from configuration:', config.domains.length, 'domains found');
                    return config.domains
                        .filter(domain => domain.enabled)
                        .map(domain => ({
                            id: domain.id,
                            name: domain.name,
                            fqdn: domain.fqdn,
                            color: domain.color || '#3498db',
                            description: domain.description || '',
                            configured: true
                        }));
                }
            }
        } catch (error) {
            console.warn('⚠️ Error loading domains from configuration:', error);
        }
        
        // Fallback to data-based domains if no configuration found
        if (!dashboardState.consolidatedData || !dashboardState.consolidatedData.domainData) {
            console.log('📊 No domain configuration or data found, using empty list');
            return [];
        }
        
        return Object.values(dashboardState.consolidatedData.domainData)
            .filter(domain => domain.status === 'Completed')
            .map(domain => ({
                id: domain.info.id,
                name: domain.info.name,
                fqdn: domain.info.fqdn,
                color: DASHBOARD_CONFIG.domainColors[domain.info.id] || '#3498db',
                configured: false
            }));
    },
    
    // Validate data integrity
    validateData: function(data) {
        if (!data || typeof data !== 'object') {
            throw new Error('Invalid data format');
        }
        
        if (!data.metadata) {
            throw new Error('Missing metadata');
        }
        
        if (!data.aggregatedSummary) {
            throw new Error('Missing aggregated summary');
        }
        
        return true;
    }
};

// UI Management Module
const UIManager = {
    // Initialize the dashboard UI
    initialize: function() {
        console.log('🎨 Initializing UI components...');
        
        try {
            // Set up domain selector
            this.initializeDomainSelector();
            
            // Set up tab system
            this.initializeTabSystem();
            
            // Set up event listeners
            this.setupEventListeners();
            
            // Initialize keyboard navigation
            this.initializeKeyboardNavigation();
            
            // Set up responsive handlers
            this.setupResponsiveHandlers();
            
            console.log('✅ UI initialization complete');
            
        } catch (error) {
            console.error('❌ UI initialization error:', error);
            NotificationManager.show('Error initializing user interface', 'error');
        }
    },
    
    // Initialize domain selector dropdown
    initializeDomainSelector: function() {
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
        const domains = DataManager.getAvailableDomains();
        domains.forEach(domain => {
            const option = document.createElement('option');
            option.value = domain.id;
            option.textContent = domain.name;
            option.setAttribute('data-color', domain.color);
            domainSelector.appendChild(option);
        });
        
        // Set up change handler
        domainSelector.addEventListener('change', (e) => {
            this.switchDomain(e.target.value);
        });
        
        console.log('✅ Domain selector initialized with', domains.length, 'domains');
    },
    
    // Initialize tab system
    initializeTabSystem: function() {
        const tabButtons = document.querySelectorAll('.tab-btn');
        
        tabButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                const tabName = button.getAttribute('data-tab');
                if (tabName) {
                    this.switchTab(tabName);
                }
            });
            
            // Add keyboard support
            button.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    button.click();
                }
            });
        });
        
        // Initialize with overview tab
        this.switchTab('overview');
        
        console.log('✅ Tab system initialized');
    },
    
    // Set up global event listeners
    setupEventListeners: function() {
        // Window resize handler
        window.addEventListener('resize', Utils.debounce(() => {
            this.handleResize();
        }, 250));
        
        // Visibility change handler for auto-refresh
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible' && dashboardState.preferences.autoRefresh) {
                this.checkForUpdates();
            }
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            this.handleKeyboardShortcuts(e);
        });
        
        console.log('✅ Event listeners set up');
    },
    
    // Initialize keyboard navigation
    initializeKeyboardNavigation: function() {
        // Add tabindex to interactive elements
        const interactiveElements = document.querySelectorAll('.tab-btn, .refresh-btn, .domain-selector');
        interactiveElements.forEach((element, index) => {
            element.setAttribute('tabindex', index + 1);
        });
    },
    
    // Set up responsive handlers
    setupResponsiveHandlers: function() {
        // Check initial screen size
        this.handleResize();
        
        // Set up media query listeners
        const mediaQueries = [
            window.matchMedia('(max-width: 768px)'),
            window.matchMedia('(max-width: 480px)')
        ];
        
        mediaQueries.forEach(mq => {
            mq.addListener(() => this.handleResize());
        });
    },
    
    // Handle window resize
    handleResize: function() {
        const width = window.innerWidth;
        
        // Adjust layout for mobile
        if (width <= 768) {
            document.body.classList.add('mobile-layout');
        } else {
            document.body.classList.remove('mobile-layout');
        }
        
        // Adjust metric cards layout
        const metricsGrid = document.querySelector('.metrics-grid');
        if (metricsGrid) {
            if (width <= 480) {
                metricsGrid.style.gridTemplateColumns = '1fr';
            } else if (width <= 768) {
                metricsGrid.style.gridTemplateColumns = 'repeat(2, 1fr)';
            } else {
                metricsGrid.style.gridTemplateColumns = 'repeat(auto-fit, minmax(280px, 1fr))';
            }
        }
    },
    
    // Handle keyboard shortcuts
    handleKeyboardShortcuts: function(e) {
        // Ctrl/Cmd + R: Refresh data
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            e.preventDefault();
            DashboardController.refreshData();
        }
        
        // Number keys 1-6: Switch tabs
        if (e.key >= '1' && e.key <= '6') {
            const tabIndex = parseInt(e.key) - 1;
            const tabs = ['overview', 'users', 'computers', 'security', 'domains', 'reports'];
            if (tabs[tabIndex]) {
                this.switchTab(tabs[tabIndex]);
            }
        }
        
        // Escape: Close notifications
        if (e.key === 'Escape') {
            NotificationManager.clearAll();
        }
    },
    
    // Switch domain view
    switchDomain: function(domainId) {
        console.log('🔄 Switching to domain:', domainId);
        
        const previousDomain = dashboardState.currentDomain;
        dashboardState.currentDomain = domainId;
        
        // Update domain selector
        const domainSelector = document.getElementById('domainSelector');
        if (domainSelector) {
            domainSelector.value = domainId;
        }
        
        // Update metrics for selected domain
        MetricsManager.updateMetrics();
        
        // Update tab content
        this.updateTabContent(dashboardState.currentTab);
        
        // Update domain indicator
        this.updateDomainIndicator();
        
        // Show notification if domain changed
        if (previousDomain !== domainId) {
            const domainName = domainId === 'all' ? 'All Domains' : 
                DataManager.getDomainData(domainId)?.info?.name || domainId;
            NotificationManager.show(`Switched to ${domainName}`, 'info', 2000);
        }
    },
    
    // Switch tab
    switchTab: function(tabName) {
        console.log('🔄 Switching to tab:', tabName);
        
        const previousTab = dashboardState.currentTab;
        dashboardState.currentTab = tabName;
        
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
            btn.setAttribute('aria-selected', 'false');
        });
        
        // Activate current tab
        const activeTab = document.querySelector(`[data-tab="${tabName}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
            activeTab.setAttribute('aria-selected', 'true');
        }
        
        // Update tab content
        this.updateTabContent(tabName);
        
        // Analytics tracking (if needed)
        if (previousTab !== tabName) {
            console.log('📊 Tab switched:', previousTab, '->', tabName);
        }
    },
    
    // Update tab content
    updateTabContent: function(tabName) {
        const tabContent = document.getElementById('tabContent');
        if (!tabContent) return;
        
        // Add loading state
        tabContent.style.opacity = '0.5';
        
        setTimeout(() => {
            let content = '';
            
            switch (tabName) {
                case 'overview':
                    content = ContentGenerator.generateOverviewContent();
                    break;
                case 'users':
                    content = ContentGenerator.generateUsersContent();
                    break;
                case 'computers':
                    content = ContentGenerator.generateComputersContent();
                    break;
                case 'security':
                    content = ContentGenerator.generateSecurityContent();
                    break;
                case 'domains':
                    content = ContentGenerator.generateDomainsContent();
                    break;
                case 'reports':
                    content = ContentGenerator.generateReportsContent();
                    break;
                default:
                    content = '<div>Tab content not available</div>';
            }
            
            tabContent.innerHTML = content;
            tabContent.style.opacity = '1';
            
            // Initialize any interactive elements in the new content
            this.initializeTabInteractions(tabName);
            
        }, 150);
    },
    
    // Initialize tab-specific interactions
    initializeTabInteractions: function(tabName) {
        // Add any tab-specific event listeners or interactive elements
        console.log('Initializing interactions for tab:', tabName);
        
        // Example: Add click handlers for domain cards in overview
        if (tabName === 'overview') {
            const domainCards = document.querySelectorAll('.domain-card');
            domainCards.forEach(card => {
                const domainId = card.getAttribute('data-domain-id');
                if (domainId) {
                    card.addEventListener('click', () => {
                        this.switchDomain(domainId);
                    });
                    card.style.cursor = 'pointer';
                }
            });
        }
    },
    
    // Update domain indicator
    updateDomainIndicator: function() {
        const indicator = document.getElementById('domainIndicator');
        if (!indicator) return;
        
        if (dashboardState.currentDomain === 'all') {
            indicator.textContent = 'All Domains';
            indicator.style.color = '#3498db';
        } else {
            const domainData = DataManager.getDomainData(dashboardState.currentDomain);
            if (domainData && domainData.info) {
                indicator.textContent = domainData.info.name;
                indicator.style.color = DASHBOARD_CONFIG.domainColors[domainData.info.id] || '#3498db';
            }
        }
    },
    
    // Check for data updates
    checkForUpdates: function() {
        // This would check for updated data files in a real implementation
        console.log('🔍 Checking for data updates...');
        
        // For now, just show a notification
        NotificationManager.show('Checking for updates...', 'info', 2000);
    }
};

// Metrics Management Module
const MetricsManager = {
    // Update all metric cards
    updateMetrics: function() {
        // Check if we have configured domains but no data yet
        const configuredDomains = DataManager.getAvailableDomains();
        
        if (!dashboardState.consolidatedData) {
            if (configuredDomains.length > 0) {
                console.log('📊 Domains configured but no data collected yet');
                this.showNoDataState(configuredDomains);
                return;
            } else {
                console.log('📊 No domains configured and no data available');
                this.showConfigurationNeeded();
                return;
            }
        }
        
        const domainData = DataManager.getDomainData(dashboardState.currentDomain);
        if (!domainData || !domainData.summary) {
            console.warn('No summary data available for domain:', dashboardState.currentDomain);
            if (configuredDomains.length > 0) {
                this.showNoDataState(configuredDomains);
            } else {
                this.showConfigurationNeeded();
            }
            return;
        }
        
        const summary = domainData.summary;
        
        console.log('📈 Updating metrics for domain:', dashboardState.currentDomain, summary);
        
        // Update each metric card with enhanced data
        this.updateMetricCard('totalUsers', summary.totalUsers || 0, {
            active: summary.activeUsers || 0,
            disabled: summary.disabledUsers || 0,
            locked: summary.lockedUsers || 0
        });
        
        this.updateMetricCard('activeComputers', summary.activeComputers || 0, {
            total: summary.totalComputers || 0,
            inactive: summary.inactiveComputers || 0
        });
        
        this.updateMetricCard('securityGroups', summary.securityGroups || 0, {
            total: summary.totalGroups || 0,
            distribution: summary.distributionGroups || 0
        });
        
        this.updateMetricCard('domainControllers', summary.domainControllers || 0, {
            globalCatalogs: summary.globalCatalogs || 0,
            readOnly: summary.readOnlyDCs || 0
        });
    },
    
    // Update individual metric card
    updateMetricCard: function(cardId, primaryValue, additionalData = {}) {
        const card = document.getElementById(cardId);
        if (!card) {
            console.warn('Metric card not found:', cardId);
            return;
        }
        
        const valueElement = card.querySelector('.metric-value');
        const changeElement = card.querySelector('.metric-change');
        
        if (valueElement) {
            // Update primary value - handle both numbers and text
            if (typeof primaryValue === 'string') {
                valueElement.textContent = primaryValue;
                valueElement.classList.add('text-state');
            } else {
                valueElement.textContent = Utils.formatNumber(primaryValue);
                valueElement.classList.remove('text-state');
            }
            valueElement.classList.remove('loading', 'error');
            
            // Add animation effect if enabled
            if (DASHBOARD_CONFIG.enableAnimations) {
                valueElement.style.transform = 'scale(1.1)';
                setTimeout(() => {
                    valueElement.style.transform = 'scale(1)';
                }, 200);
            }
        }
        
        if (changeElement && Object.keys(additionalData).length > 0) {
            // Create detailed breakdown
            const breakdown = Object.entries(additionalData)
                .map(([key, value]) => `${key}: ${Utils.formatNumber(value)}`)
                .join(' | ');
            changeElement.textContent = breakdown;
            changeElement.style.fontSize = '10px';
            changeElement.style.color = '#7f8c8d';
        }
        
        console.log('✅ Updated', cardId + ':', primaryValue, additionalData);
    },
    
    // Show state when domains are configured but no data collected yet
    showNoDataState: function(configuredDomains) {
        console.log('📊 Showing no data state for', configuredDomains.length, 'configured domains');
        
        // Update metric cards to show "waiting for data" state
        this.updateMetricCard('totalUsers', 'Waiting for data...', {});
        this.updateMetricCard('activeComputers', 'Waiting for data...', {});
        this.updateMetricCard('securityGroups', 'Waiting for data...', {});
        this.updateMetricCard('domainControllers', 'Waiting for data...', {});
        
        // Show helpful message
        const overviewContent = document.querySelector('.overview-content');
        if (overviewContent) {
            overviewContent.innerHTML = `
                <div class="no-data-state">
                    <div class="info-card">
                        <h3>🎯 Domains Configured Successfully!</h3>
                        <p>You have configured <strong>${configuredDomains.length} domain(s)</strong>:</p>
                        <ul>
                            ${configuredDomains.map(domain => 
                                `<li><strong>${domain.name}</strong> (${domain.fqdn})</li>`
                            ).join('')}
                        </ul>
                        <div class="next-steps">
                            <h4>📋 Next Steps:</h4>
                            <ol>
                                <li>Run the PowerShell data collection script: <code>Run-Enhanced-AD-Dashboard.bat</code></li>
                                <li>Wait for data collection to complete</li>
                                <li>Refresh this dashboard to see your domain data</li>
                            </ol>
                        </div>
                        <button onclick="location.reload()" class="refresh-btn">🔄 Refresh Dashboard</button>
                    </div>
                </div>
            `;
        }
    },
    
    // Show state when no domains are configured
    showConfigurationNeeded: function() {
        console.log('📊 Showing configuration needed state');
        
        // Update metric cards to show "configuration needed" state
        this.updateMetricCard('totalUsers', 'Configure domains first', {});
        this.updateMetricCard('activeComputers', 'Configure domains first', {});
        this.updateMetricCard('securityGroups', 'Configure domains first', {});
        this.updateMetricCard('domainControllers', 'Configure domains first', {});
        
        // Show configuration prompt
        const overviewContent = document.querySelector('.overview-content');
        if (overviewContent) {
            overviewContent.innerHTML = `
                <div class="configuration-needed">
                    <div class="info-card">
                        <h3>⚙️ Configuration Required</h3>
                        <p>No domains have been configured yet. To get started:</p>
                        <div class="setup-steps">
                            <ol>
                                <li>Click the <strong>Configuration</strong> button below</li>
                                <li>Add your Active Directory domains</li>
                                <li>Test connectivity and save configuration</li>
                                <li>Run the PowerShell data collection script</li>
                            </ol>
                        </div>
                        <a href="config.html" class="config-btn">⚙️ Configure Domains</a>
                    </div>
                </div>
            `;
        }
    }
};

// Content Generation Module
const ContentGenerator = {
    // Generate overview content
    generateOverviewContent: function() {
        if (!dashboardState.consolidatedData) {
            return '<div>No data available</div>';
        }
        
        const metadata = dashboardState.consolidatedData.metadata || {};
        const summary = dashboardState.consolidatedData.aggregatedSummary || {};
        const domainData = dashboardState.consolidatedData.domainData || {};
        
        // Generate domain cards
        let domainCards = '';
        Object.values(domainData).forEach(domain => {
            if (domain.info) {
                const statusIcon = domain.status === 'Completed' ? '✅' : '❌';
                const statusColor = domain.status === 'Completed' ? '#27ae60' : '#e74c3c';
                const domainColor = DASHBOARD_CONFIG.domainColors[domain.info.id] || '#3498db';
                
                domainCards += `
                    <div class="domain-card" data-domain-id="${domain.info.id}" style="border-left: 4px solid ${domainColor};">
                        <div class="domain-header">
                            <h4>${statusIcon} ${Utils.sanitizeHtml(domain.info.name)}</h4>
                            <span class="domain-status" style="color: ${statusColor};">${domain.status}</span>
                        </div>
                        <div class="domain-details">
                            <p><strong>FQDN:</strong> ${Utils.sanitizeHtml(domain.info.fqdn)}</p>
                            <p><strong>Location:</strong> ${Utils.sanitizeHtml(domain.info.location || 'Not specified')}</p>
                            <p><strong>Contact:</strong> ${Utils.sanitizeHtml(domain.info.contact || 'Not specified')}</p>
                        </div>`;
                
                if (domain.status === 'Completed' && domain.summary) {
                    domainCards += `
                        <div class="domain-metrics">
                            <span>👥 ${Utils.formatNumber(domain.summary.totalUsers)} users</span>
                            <span>💻 ${Utils.formatNumber(domain.summary.totalComputers)} computers</span>
                            <span>🛡️ ${Utils.formatNumber(domain.summary.totalGroups)} groups</span>
                            <span>🖥️ ${Utils.formatNumber(domain.summary.domainControllers)} DCs</span>
                        </div>`;
                }
                
                domainCards += '</div>';
            }
        });
        
        return `
            <div id="overview-content">
                <h3>📊 Multi-Domain Overview</h3>
                <div class="overview-stats">
                    <div class="stat-card">
                        <h4>📈 Collection Summary</h4>
                        <p><strong>Total Domains:</strong> ${metadata.totalDomains || 0}</p>
                        <p><strong>Successful Collections:</strong> ${metadata.successfulCollections || 0}</p>
                        <p><strong>Failed Collections:</strong> ${metadata.failedCollections || 0}</p>
                        <p><strong>Collection Duration:</strong> ${metadata.collectionDuration || 0} minutes</p>
                    </div>
                    <div class="stat-card">
                        <h4>👥 User Statistics</h4>
                        <p><strong>Total Users:</strong> ${Utils.formatNumber(summary.totalUsers || 0)}</p>
                        <p><strong>Active Users:</strong> ${Utils.formatNumber(summary.activeUsers || 0)}</p>
                        <p><strong>Disabled Users:</strong> ${Utils.formatNumber(summary.disabledUsers || 0)}</p>
                        <p><strong>Locked Users:</strong> ${Utils.formatNumber(summary.lockedUsers || 0)}</p>
                    </div>
                    <div class="stat-card">
                        <h4>💻 Computer Statistics</h4>
                        <p><strong>Total Computers:</strong> ${Utils.formatNumber(summary.totalComputers || 0)}</p>
                        <p><strong>Active Computers:</strong> ${Utils.formatNumber(summary.activeComputers || 0)}</p>
                        <p><strong>Inactive Computers:</strong> ${Utils.formatNumber(summary.inactiveComputers || 0)}</p>
                    </div>
                    <div class="stat-card">
                        <h4>🛡️ Security Overview</h4>
                        <p><strong>Security Groups:</strong> ${Utils.formatNumber(summary.securityGroups || 0)}</p>
                        <p><strong>Distribution Groups:</strong> ${Utils.formatNumber(summary.distributionGroups || 0)}</p>
                        <p><strong>Domain Controllers:</strong> ${Utils.formatNumber(summary.domainControllers || 0)}</p>
                        <p><strong>Global Catalogs:</strong> ${Utils.formatNumber(summary.globalCatalogs || 0)}</p>
                    </div>
                </div>
                <h3>🏢 Domain Status</h3>
                <div class="domains-grid">${domainCards}</div>
                <div class="last-refresh">Last updated: ${Utils.formatDate(metadata.generatedOn)}</div>
            </div>`;
    },
    
    // Generate users content
    generateUsersContent: function() {
        const domainData = DataManager.getDomainData(dashboardState.currentDomain);
        if (!domainData || !domainData.summary) {
            return '<div>No user data available</div>';
        }
        
        const summary = domainData.summary;
        const activePercentage = Utils.calculatePercentage(summary.activeUsers, summary.totalUsers);
        const disabledPercentage = Utils.calculatePercentage(summary.disabledUsers, summary.totalUsers);
        
        return `
            <div>
                <h3>👥 User Management</h3>
                <div class="user-stats-grid">
                    <div class="user-stat-card">
                        <div class="stat-icon">👥</div>
                        <div class="stat-info">
                            <h4>${Utils.formatNumber(summary.totalUsers || 0)}</h4>
                            <p>Total Users</p>
                        </div>
                    </div>
                    <div class="user-stat-card active">
                        <div class="stat-icon">✅</div>
                        <div class="stat-info">
                            <h4>${Utils.formatNumber(summary.activeUsers || 0)}</h4>
                            <p>Active Users</p>
                        </div>
                    </div>
                    <div class="user-stat-card disabled">
                        <div class="stat-icon">❌</div>
                        <div class="stat-info">
                            <h4>${Utils.formatNumber(summary.disabledUsers || 0)}</h4>
                            <p>Disabled Users</p>
                        </div>
                    </div>
                    <div class="user-stat-card locked">
                        <div class="stat-icon">🔒</div>
                        <div class="stat-info">
                            <h4>${Utils.formatNumber(summary.lockedUsers || 0)}</h4>
                            <p>Locked Users</p>
                        </div>
                    </div>
                </div>
                <div class="content-section">
                    <h4>📊 User Analysis</h4>
                    <p>Active user percentage: <strong>${activePercentage}%</strong></p>
                    <p>Disabled user percentage: <strong>${disabledPercentage}%</strong></p>
                    <div class="info-box">
                        <p><em>Detailed user information, password policies, and account management tools would be displayed here in a production environment.</em></p>
                    </div>
                </div>
            </div>`;
    },
    
    // Generate computers content
    generateComputersContent: function() {
        const domainData = DataManager.getDomainData(dashboardState.currentDomain);
        if (!domainData || !domainData.summary) {
            return '<div>No computer data available</div>';
        }
        
        const summary = domainData.summary;
        const activePercentage = Utils.calculatePercentage(summary.activeComputers, summary.totalComputers);
        
        return `
            <div>
                <h3>💻 Computer Management</h3>
                <div class="computer-stats-grid">
                    <div class="computer-stat-card">
                        <div class="stat-icon">💻</div>
                        <div class="stat-info">
                            <h4>${Utils.formatNumber(summary.totalComputers || 0)}</h4>
                            <p>Total Computers</p>
                        </div>
                    </div>
                    <div class="computer-stat-card active">
                        <div class="stat-icon">🟢</div>
                        <div class="stat-info">
                            <h4>${Utils.formatNumber(summary.activeComputers || 0)}</h4>
                            <p>Active Computers</p>
                        </div>
                    </div>
                    <div class="computer-stat-card inactive">
                        <div class="stat-icon">🔴</div>
                        <div class="stat-info">
                            <h4>${Utils.formatNumber(summary.inactiveComputers || 0)}</h4>
                            <p>Inactive Computers</p>
                        </div>
                    </div>
                </div>
                <div class="content-section">
                    <h4>📊 Computer Analysis</h4>
                    <p>Active computer percentage: <strong>${activePercentage}%</strong></p>
                    <div class="info-box">
                        <p><em>Computer inventory, operating system distribution, patch status, and hardware management tools would be displayed here.</em></p>
                    </div>
                </div>
            </div>`;
    },
    
    // Generate security content
    generateSecurityContent: function() {
        const domainData = DataManager.getDomainData(dashboardState.currentDomain);
        if (!domainData || !domainData.summary) {
            return '<div>No security data available</div>';
        }
        
        const summary = domainData.summary;
        const securityGroupsPercentage = Utils.calculatePercentage(summary.securityGroups, summary.totalGroups);
        
        return `
            <div>
                <h3>🔒 Security Overview</h3>
                <div class="security-stats-grid">
                    <div class="security-stat-card">
                        <div class="stat-icon">🛡️</div>
                        <div class="stat-info">
                            <h4>${Utils.formatNumber(summary.securityGroups || 0)}</h4>
                            <p>Security Groups</p>
                        </div>
                    </div>
                    <div class="security-stat-card">
                        <div class="stat-icon">📧</div>
                        <div class="stat-info">
                            <h4>${Utils.formatNumber(summary.distributionGroups || 0)}</h4>
                            <p>Distribution Groups</p>
                        </div>
                    </div>
                    <div class="security-stat-card">
                        <div class="stat-icon">🖥️</div>
                        <div class="stat-info">
                            <h4>${Utils.formatNumber(summary.domainControllers || 0)}</h4>
                            <p>Domain Controllers</p>
                        </div>
                    </div>
                    <div class="security-stat-card">
                        <div class="stat-icon">🌐</div>
                        <div class="stat-info">
                            <h4>${Utils.formatNumber(summary.globalCatalogs || 0)}</h4>
                            <p>Global Catalogs</p>
                        </div>
                    </div>
                </div>
                <div class="content-section">
                    <h4>🔐 Security Analysis</h4>
                    <p>Security groups ratio: <strong>${securityGroupsPercentage}%</strong></p>
                    <div class="info-box">
                        <p><em>Security policies, compliance reports, audit logs, and access control management would be displayed here.</em></p>
                    </div>
                </div>
            </div>`;
    },
    
    // Generate domains content
    generateDomainsContent: function() {
        if (!dashboardState.consolidatedData || !dashboardState.consolidatedData.domainData) {
            return '<div>No domain data available</div>';
        }
        
        const domains = Object.values(dashboardState.consolidatedData.domainData);
        
        let domainsContent = `
            <div>
                <h3>🏢 Domain Management</h3>
                <div class="domains-overview">
                    <p>Managing ${domains.length} configured domains across the enterprise infrastructure.</p>
                </div>
                <div class="domains-grid">`;
        
        domains.forEach(domain => {
            if (domain.info) {
                const statusIcon = domain.status === 'Completed' ? '✅' : '❌';
                const statusColor = domain.status === 'Completed' ? '#27ae60' : '#e74c3c';
                const domainColor = DASHBOARD_CONFIG.domainColors[domain.info.id] || '#3498db';
                
                domainsContent += `
                    <div class="domain-card detailed" style="border-left: 4px solid ${domainColor};">
                        <div class="domain-header">
                            <h4>${statusIcon} ${Utils.sanitizeHtml(domain.info.name)}</h4>
                            <span class="domain-status" style="color: ${statusColor};">${domain.status}</span>
                        </div>
                        <div class="domain-details">
                            <p><strong>ID:</strong> ${Utils.sanitizeHtml(domain.info.id)}</p>
                            <p><strong>FQDN:</strong> ${Utils.sanitizeHtml(domain.info.fqdn)}</p>
                            <p><strong>Description:</strong> ${Utils.sanitizeHtml(domain.info.description || 'No description')}</p>
                            <p><strong>Location:</strong> ${Utils.sanitizeHtml(domain.info.location || 'Not specified')}</p>
                            <p><strong>Contact:</strong> ${Utils.sanitizeHtml(domain.info.contact || 'Not specified')}</p>
                            <p><strong>Priority:</strong> ${domain.info.priority || 'Not set'}</p>
                        </div>`;
                
                if (domain.status === 'Completed' && domain.summary) {
                    domainsContent += `
                        <div class="domain-metrics detailed">
                            <div class="metric-row">
                                <span>👥 Users: ${Utils.formatNumber(domain.summary.totalUsers)}</span>
                                <span>💻 Computers: ${Utils.formatNumber(domain.summary.totalComputers)}</span>
                            </div>
                            <div class="metric-row">
                                <span>🛡️ Groups: ${Utils.formatNumber(domain.summary.totalGroups)}</span>
                                <span>🖥️ DCs: ${Utils.formatNumber(domain.summary.domainControllers)}</span>
                            </div>
                        </div>`;
                }
                
                if (domain.connectivity) {
                    const connectivityStatus = domain.connectivity.overallStatus ? '🟢 Connected' : '🔴 Disconnected';
                    domainsContent += `
                        <div class="connectivity-status">
                            <p><strong>Connectivity:</strong> ${connectivityStatus}</p>
                        </div>`;
                }
                
                domainsContent += '</div>';
            }
        });
        
        domainsContent += `
                </div>
                <div class="info-box">
                    <p><em>Domain configuration, connectivity testing, and management tools would be available here in a production environment.</em></p>
                </div>
            </div>`;
        
        return domainsContent;
    },
    
    // Generate reports content
    generateReportsContent: function() {
        const metadata = dashboardState.consolidatedData?.metadata || {};
        const summary = dashboardState.consolidatedData?.aggregatedSummary || {};
        
        return `
            <div>
                <h3>📋 Reports and Analytics</h3>
                <div class="reports-section">
                    <div class="report-card">
                        <h4>📊 Executive Summary</h4>
                        <p>Comprehensive overview of Active Directory infrastructure across all domains.</p>
                        <ul>
                            <li>Total Users: ${Utils.formatNumber(summary.totalUsers || 0)}</li>
                            <li>Total Computers: ${Utils.formatNumber(summary.totalComputers || 0)}</li>
                            <li>Total Groups: ${Utils.formatNumber(summary.totalGroups || 0)}</li>
                            <li>Domain Controllers: ${Utils.formatNumber(summary.domainControllers || 0)}</li>
                        </ul>
                    </div>
                    <div class="report-card">
                        <h4>🔍 Collection Report</h4>
                        <p>Details about the data collection process and results.</p>
                        <ul>
                            <li>Collection Date: ${Utils.formatDate(metadata.generatedOn)}</li>
                            <li>Duration: ${metadata.collectionDuration || 0} minutes</li>
                            <li>Successful Domains: ${metadata.successfulCollections || 0}</li>
                            <li>Failed Domains: ${metadata.failedCollections || 0}</li>
                        </ul>
                    </div>
                    <div class="report-card">
                        <h4>⚠️ Issues and Recommendations</h4>
                        <p>Identified issues and recommended actions for improvement.</p>
                        <div class="info-box">
                            <p><em>Automated analysis, security recommendations, and compliance reports would be generated here.</em></p>
                        </div>
                    </div>
                </div>
            </div>`;
    }
};

// Notification Management Module
const NotificationManager = {
    notifications: [],
    
    // Show notification
    show: function(message, type = 'info', duration = 5000) {
        const notification = {
            id: Utils.generateId(),
            message: Utils.sanitizeHtml(message),
            type: type,
            timestamp: new Date(),
            duration: duration
        };
        
        this.notifications.push(notification);
        this.render(notification);
        
        // Auto-remove after duration
        if (duration > 0) {
            setTimeout(() => {
                this.remove(notification.id);
            }, duration);
        }
        
        return notification.id;
    },
    
    // Render notification
    render: function(notification) {
        const container = this.getContainer();
        
        const element = document.createElement('div');
        element.className = `notification notification-${notification.type}`;
        element.setAttribute('data-notification-id', notification.id);
        
        // Add icon based on type
        const icons = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        };
        
        element.innerHTML = `
            <span class="notification-icon">${icons[notification.type] || icons.info}</span>
            <span class="notification-message">${notification.message}</span>
            <button class="notification-close" onclick="NotificationManager.remove('${notification.id}')">×</button>
        `;
        
        // Add to container
        container.appendChild(element);
        
        // Animate in
        setTimeout(() => {
            element.style.opacity = '1';
            element.style.transform = 'translateX(0)';
        }, 10);
    },
    
    // Remove notification
    remove: function(notificationId) {
        const element = document.querySelector(`[data-notification-id="${notificationId}"]`);
        if (element) {
            element.style.opacity = '0';
            element.style.transform = 'translateX(100%)';
            
            setTimeout(() => {
                if (element.parentNode) {
                    element.parentNode.removeChild(element);
                }
            }, 300);
        }
        
        // Remove from array
        this.notifications = this.notifications.filter(n => n.id !== notificationId);
    },
    
    // Clear all notifications
    clearAll: function() {
        this.notifications.forEach(notification => {
            this.remove(notification.id);
        });
    },
    
    // Get or create notification container
    getContainer: function() {
        let container = document.getElementById('notification-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'notification-container';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 1000;
                pointer-events: none;
            `;
            document.body.appendChild(container);
        }
        return container;
    }
};

// Main Dashboard Controller
const DashboardController = {
    // Initialize the entire dashboard
    initialize: async function() {
        try {
            console.log('🚀 Enhanced Multi-Domain AD Dashboard Starting...');
            console.log('📊 Dashboard Version:', DASHBOARD_CONFIG.version);
            
            // Check for embedded data first
            if (window.embeddedConsolidatedData) {
                console.log('✅ Found embedded data, using it directly');
                dashboardState.consolidatedData = window.embeddedConsolidatedData;
                dashboardState.lastUpdate = new Date(dashboardState.consolidatedData.metadata.generatedOn);
                console.log('📈 Embedded data summary:', {
                    domains: dashboardState.consolidatedData.metadata.totalDomains,
                    successful: dashboardState.consolidatedData.metadata.successfulCollections,
                    failed: dashboardState.consolidatedData.metadata.failedCollections
                });
            }
            
            // Always initialize UI first (this loads configured domains)
            UIManager.initialize();
            
            // If no embedded data, try to load from files
            if (!dashboardState.consolidatedData) {
                const loadedData = await DataManager.loadData();
                if (loadedData) {
                    console.log('✅ Data loaded from files successfully');
                } else {
                    console.warn('⚠️ No data available, showing empty dashboard');
                }
            }
            
            // Update metrics (this will handle the no-data case gracefully)
            MetricsManager.updateMetrics();
            
            // Update last refresh time
            this.updateLastRefreshTime();
            
            // Show appropriate notification
            if (dashboardState.consolidatedData && dashboardState.consolidatedData.metadata) {
                NotificationManager.show(
                    `Dashboard loaded successfully with real AD data from ${dashboardState.consolidatedData.metadata.successfulCollections} domains!`,
                    'success'
                );
            } else {
                const configuredDomains = DataManager.getAvailableDomains();
                if (configuredDomains.length > 0) {
                    NotificationManager.show(
                        `Dashboard initialized with ${configuredDomains.length} configured domain(s). Run data collection to see metrics.`,
                        'info'
                    );
                } else {
                    NotificationManager.show(
                        'Dashboard initialized. Please configure domains to get started.',
                        'info'
                    );
                }
            }
            
            // Set up auto-refresh if enabled
            if (DASHBOARD_CONFIG.dataRefresh.enabled) {
                setInterval(() => {
                    this.checkForDataUpdates();
                }, DASHBOARD_CONFIG.dataRefresh.interval);
            }
            
            console.log('✅ Enhanced dashboard initialization complete!');
            
        } catch (error) {
            console.error('❌ Error initializing enhanced dashboard:', error);
            NotificationManager.show('Error loading dashboard: ' + error.message, 'error');
        }
    },
    
    // Refresh data
    refreshData: function() {
        console.log('🔄 Refresh requested');
        NotificationManager.show(
            'To refresh data, please run the data collection script to gather new AD information.',
            'info'
        );
    },
    
    // Update last refresh time
    updateLastRefreshTime: function() {
        const refreshElements = document.querySelectorAll('.last-refresh');
        const timestamp = dashboardState.lastUpdate || new Date();
        const formattedTime = Utils.formatDate(timestamp);
        
        refreshElements.forEach(element => {
            element.textContent = 'Last updated: ' + formattedTime;
        });
    },
    
    // Check for data updates
    checkForDataUpdates: function() {
        console.log('🔍 Checking for data updates...');
        // This would implement actual update checking in a real environment
    }
};

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    DashboardController.initialize();
});

// Global functions for backward compatibility
function refreshData() {
    DashboardController.refreshData();
}

function switchTab(tabName) {
    UIManager.switchTab(tabName);
}

function switchDomain(domainId) {
    UIManager.switchDomain(domainId);
}

// Export for module systems (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        DashboardController,
        UIManager,
        DataManager,
        MetricsManager,
        NotificationManager,
        Utils
    };
}

console.log('📊 Enhanced Multi-Domain AD Dashboard Script Loaded - Ready!');
console.log('🎯 Dashboard Configuration:', DASHBOARD_CONFIG);

