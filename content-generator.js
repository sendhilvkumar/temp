// Standalone Content Generator for Enhanced Multi-Domain AD Dashboard
// Version: 3.1 - Standalone Module
// Ensures ContentGenerator is always available for tab content generation

// Content Generation Module
const ContentGenerator = {
    // Generate overview content
    generateOverviewContent: function() {
        console.log('🎯 Generating overview content...');
        
        // Try multiple data sources
        let data = null;
        
        if (window.embeddedConsolidatedData) {
            console.log('✅ Using embeddedConsolidatedData directly');
            data = window.embeddedConsolidatedData;
        } else if (window.dashboardState && window.dashboardState.consolidatedData) {
            console.log('✅ Using dashboardState.consolidatedData');
            data = window.dashboardState.consolidatedData;
        } else {
            console.warn('⚠️ No data source found');
            return '<div class="info-box"><p>No data available. Please run data collection first.</p></div>';
        }
        
        const metadata = data.metadata || {};
        const summary = data.aggregatedSummary || {};
        const domainData = data.domainData || {};
        
        console.log('📊 Data summary:', {
            totalDomains: metadata.totalDomains,
            totalUsers: summary.totalUsers,
            totalComputers: summary.totalComputers,
            domainsCount: Object.keys(domainData).length
        });
        
        // Generate domain cards
        let domainCards = '';
        Object.values(domainData).forEach(domain => {
            if (domain.info) {
                const statusIcon = domain.status === 'Completed' ? '✅' : '❌';
                const statusColor = domain.status === 'Completed' ? '#27ae60' : '#e74c3c';
                const domainColor = '#3498db'; // Default blue color
                
                domainCards += `
                    <div class="domain-card" data-domain-id="${domain.info.id}" style="border-left: 4px solid ${domainColor};">
                        <div class="domain-header">
                            <h4>${statusIcon} ${this.sanitizeHtml(domain.info.name)}</h4>
                            <span class="domain-status" style="color: ${statusColor};">${domain.status}</span>
                        </div>
                        <div class="domain-details">
                            <p><strong>FQDN:</strong> ${this.sanitizeHtml(domain.info.fqdn)}</p>
                            <p><strong>Location:</strong> ${this.sanitizeHtml(domain.info.location || 'Not specified')}</p>
                            <p><strong>Contact:</strong> ${this.sanitizeHtml(domain.info.contact || 'Not specified')}</p>
                        </div>`;
                
                if (domain.status === 'Completed' && domain.summary) {
                    domainCards += `
                        <div class="domain-metrics">
                            <span>👥 ${this.formatNumber(domain.summary.totalUsers)} users</span>
                            <span>💻 ${this.formatNumber(domain.summary.totalComputers)} computers</span>
                            <span>🛡️ ${this.formatNumber(domain.summary.totalGroups)} groups</span>
                            <span>🖥️ ${this.formatNumber(domain.summary.domainControllers)} DCs</span>
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
                        <p><strong>Total Users:</strong> ${this.formatNumber(summary.totalUsers || 0)}</p>
                        <p><strong>Active Users:</strong> ${this.formatNumber(summary.activeUsers || 0)}</p>
                        <p><strong>Disabled Users:</strong> ${this.formatNumber(summary.disabledUsers || 0)}</p>
                        <p><strong>Locked Users:</strong> ${this.formatNumber(summary.lockedUsers || 0)}</p>
                    </div>
                    <div class="stat-card">
                        <h4>💻 Computer Statistics</h4>
                        <p><strong>Total Computers:</strong> ${this.formatNumber(summary.totalComputers || 0)}</p>
                        <p><strong>Active Computers:</strong> ${this.formatNumber(summary.activeComputers || 0)}</p>
                        <p><strong>Inactive Computers:</strong> ${this.formatNumber(summary.inactiveComputers || 0)}</p>
                    </div>
                    <div class="stat-card">
                        <h4>🛡️ Security Overview</h4>
                        <p><strong>Security Groups:</strong> ${this.formatNumber(summary.securityGroups || 0)}</p>
                        <p><strong>Distribution Groups:</strong> ${this.formatNumber(summary.distributionGroups || 0)}</p>
                        <p><strong>Domain Controllers:</strong> ${this.formatNumber(summary.domainControllers || 0)}</p>
                        <p><strong>Global Catalogs:</strong> ${this.formatNumber(summary.globalCatalogs || 0)}</p>
                    </div>
                </div>
                <h3>🏢 Domain Status</h3>
                <div class="domains-grid">${domainCards}</div>
                <div class="last-refresh">Last updated: ${this.formatDate(metadata.generatedOn)}</div>
            </div>`;
    },
    
    // Generate users content
    generateUsersContent: function() {
        console.log('🎯 Generating users content...');
        
        // Get data from embedded source
        let data = null;
        if (window.embeddedConsolidatedData) {
            data = window.embeddedConsolidatedData;
        } else if (window.dashboardState && window.dashboardState.consolidatedData) {
            data = window.dashboardState.consolidatedData;
        }
        
        if (!data) {
            return '<div class="info-box"><p>No user data available for the selected domain.</p></div>';
        }
        
        const currentDomain = window.dashboardState?.currentDomain || 'all';
        const domainData = this.getDomainData(currentDomain, data);
        
        if (!domainData || !domainData.summary) {
            return '<div class="info-box"><p>No user data available for the selected domain.</p></div>';
        }
        
        const summary = domainData.summary;
        const activePercentage = this.calculatePercentage(summary.activeUsers, summary.totalUsers);
        const disabledPercentage = this.calculatePercentage(summary.disabledUsers, summary.totalUsers);
        
        return `
            <div>
                <h3>👥 User Management</h3>
                <div class="user-stats-grid">
                    <div class="user-stat-card">
                        <div class="stat-icon">👥</div>
                        <div class="stat-info">
                            <h4>${this.formatNumber(summary.totalUsers || 0)}</h4>
                            <p>Total Users</p>
                        </div>
                    </div>
                    <div class="user-stat-card active">
                        <div class="stat-icon">✅</div>
                        <div class="stat-info">
                            <h4>${this.formatNumber(summary.activeUsers || 0)}</h4>
                            <p>Active Users</p>
                        </div>
                    </div>
                    <div class="user-stat-card disabled">
                        <div class="stat-icon">❌</div>
                        <div class="stat-info">
                            <h4>${this.formatNumber(summary.disabledUsers || 0)}</h4>
                            <p>Disabled Users</p>
                        </div>
                    </div>
                    <div class="user-stat-card locked">
                        <div class="stat-icon">🔒</div>
                        <div class="stat-info">
                            <h4>${this.formatNumber(summary.lockedUsers || 0)}</h4>
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
        console.log('🎯 Generating computers content...');
        
        // Get data from embedded source
        let data = null;
        if (window.embeddedConsolidatedData) {
            data = window.embeddedConsolidatedData;
        } else if (window.dashboardState && window.dashboardState.consolidatedData) {
            data = window.dashboardState.consolidatedData;
        }
        
        if (!data) {
            return '<div class="info-box"><p>No computer data available for the selected domain.</p></div>';
        }
        
        const currentDomain = window.dashboardState?.currentDomain || 'all';
        const domainData = this.getDomainData(currentDomain, data);
        
        if (!domainData || !domainData.summary) {
            return '<div class="info-box"><p>No computer data available for the selected domain.</p></div>';
        }
        
        const summary = domainData.summary;
        const activePercentage = this.calculatePercentage(summary.activeComputers, summary.totalComputers);
        
        return `
            <div>
                <h3>💻 Computer Management</h3>
                <div class="computer-stats-grid">
                    <div class="computer-stat-card">
                        <div class="stat-icon">💻</div>
                        <div class="stat-info">
                            <h4>${this.formatNumber(summary.totalComputers || 0)}</h4>
                            <p>Total Computers</p>
                        </div>
                    </div>
                    <div class="computer-stat-card active">
                        <div class="stat-icon">🟢</div>
                        <div class="stat-info">
                            <h4>${this.formatNumber(summary.activeComputers || 0)}</h4>
                            <p>Active Computers</p>
                        </div>
                    </div>
                    <div class="computer-stat-card inactive">
                        <div class="stat-icon">🔴</div>
                        <div class="stat-info">
                            <h4>${this.formatNumber(summary.inactiveComputers || 0)}</h4>
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
        console.log('🎯 Generating security content...');
        
        // Get data from embedded source
        let data = null;
        if (window.embeddedConsolidatedData) {
            data = window.embeddedConsolidatedData;
        } else if (window.dashboardState && window.dashboardState.consolidatedData) {
            data = window.dashboardState.consolidatedData;
        }
        
        if (!data) {
            return '<div class="info-box"><p>No security data available for the selected domain.</p></div>';
        }
        
        const currentDomain = window.dashboardState?.currentDomain || 'all';
        const domainData = this.getDomainData(currentDomain, data);
        
        if (!domainData || !domainData.summary) {
            return '<div class="info-box"><p>No security data available for the selected domain.</p></div>';
        }
        
        const summary = domainData.summary;
        const securityGroupsPercentage = this.calculatePercentage(summary.securityGroups, summary.totalGroups);
        
        return `
            <div>
                <h3>🔒 Security Overview</h3>
                <div class="security-stats-grid">
                    <div class="security-stat-card">
                        <div class="stat-icon">🛡️</div>
                        <div class="stat-info">
                            <h4>${this.formatNumber(summary.securityGroups || 0)}</h4>
                            <p>Security Groups</p>
                        </div>
                    </div>
                    <div class="security-stat-card">
                        <div class="stat-icon">📧</div>
                        <div class="stat-info">
                            <h4>${this.formatNumber(summary.distributionGroups || 0)}</h4>
                            <p>Distribution Groups</p>
                        </div>
                    </div>
                    <div class="security-stat-card">
                        <div class="stat-icon">🖥️</div>
                        <div class="stat-info">
                            <h4>${this.formatNumber(summary.domainControllers || 0)}</h4>
                            <p>Domain Controllers</p>
                        </div>
                    </div>
                    <div class="security-stat-card">
                        <div class="stat-icon">🌐</div>
                        <div class="stat-info">
                            <h4>${this.formatNumber(summary.globalCatalogs || 0)}</h4>
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
        console.log('🎯 Generating domains content...');
        
        // Get data from embedded source
        let data = null;
        if (window.embeddedConsolidatedData) {
            data = window.embeddedConsolidatedData;
        } else if (window.dashboardState && window.dashboardState.consolidatedData) {
            data = window.dashboardState.consolidatedData;
        }
        
        if (!data || !data.domainData) {
            return '<div class="info-box"><p>No domain data available.</p></div>';
        }
        
        const domains = Object.values(data.domainData);
        
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
                const domainColor = '#3498db'; // Default blue color
                
                domainsContent += `
                    <div class="domain-card detailed" style="border-left: 4px solid ${domainColor};">
                        <div class="domain-header">
                            <h4>${statusIcon} ${this.sanitizeHtml(domain.info.name)}</h4>
                            <span class="domain-status" style="color: ${statusColor};">${domain.status}</span>
                        </div>
                        <div class="domain-details">
                            <p><strong>ID:</strong> ${this.sanitizeHtml(domain.info.id)}</p>
                            <p><strong>FQDN:</strong> ${this.sanitizeHtml(domain.info.fqdn)}</p>
                            <p><strong>Description:</strong> ${this.sanitizeHtml(domain.info.description || 'No description')}</p>
                            <p><strong>Location:</strong> ${this.sanitizeHtml(domain.info.location || 'Not specified')}</p>
                            <p><strong>Contact:</strong> ${this.sanitizeHtml(domain.info.contact || 'Not specified')}</p>
                            <p><strong>Priority:</strong> ${domain.info.priority || 'Not set'}</p>
                        </div>`;
                
                if (domain.status === 'Completed' && domain.summary) {
                    domainsContent += `
                        <div class="domain-metrics detailed">
                            <div class="metric-row">
                                <span>👥 Users: ${this.formatNumber(domain.summary.totalUsers)}</span>
                                <span>💻 Computers: ${this.formatNumber(domain.summary.totalComputers)}</span>
                            </div>
                            <div class="metric-row">
                                <span>🛡️ Groups: ${this.formatNumber(domain.summary.totalGroups)}</span>
                                <span>🖥️ DCs: ${this.formatNumber(domain.summary.domainControllers)}</span>
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
        console.log('🎯 Generating reports content...');
        
        // Get data from embedded source
        let data = null;
        if (window.embeddedConsolidatedData) {
            data = window.embeddedConsolidatedData;
        } else if (window.dashboardState && window.dashboardState.consolidatedData) {
            data = window.dashboardState.consolidatedData;
        }
        
        if (!data) {
            return '<div class="info-box"><p>No report data available.</p></div>';
        }
        
        const metadata = data.metadata || {};
        const summary = data.aggregatedSummary || {};
        
        return `
            <div>
                <h3>📋 Reports and Analytics</h3>
                <div class="reports-section">
                    <div class="report-card">
                        <h4>📊 Executive Summary</h4>
                        <p>Comprehensive overview of Active Directory infrastructure across all domains.</p>
                        <ul>
                            <li>Total Users: ${this.formatNumber(summary.totalUsers || 0)}</li>
                            <li>Total Computers: ${this.formatNumber(summary.totalComputers || 0)}</li>
                            <li>Total Groups: ${this.formatNumber(summary.totalGroups || 0)}</li>
                            <li>Domain Controllers: ${this.formatNumber(summary.domainControllers || 0)}</li>
                        </ul>
                    </div>
                    <div class="report-card">
                        <h4>🔍 Collection Report</h4>
                        <p>Details about the data collection process and results.</p>
                        <ul>
                            <li>Collection Date: ${this.formatDate(metadata.generatedOn)}</li>
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
    },
    
    // Utility functions
    formatNumber: function(num) {
        if (num === null || num === undefined || isNaN(num)) return '0';
        return new Intl.NumberFormat('en-US').format(num);
    },
    
    formatDate: function(date) {
        if (!date) return 'Never';
        const dateObj = typeof date === 'string' ? new Date(date) : date;
        if (isNaN(dateObj.getTime())) return 'Invalid Date';
        return dateObj.toLocaleString();
    },
    
    calculatePercentage: function(part, total, decimals = 1) {
        if (!total || total === 0) return 0;
        return Math.round((part / total) * 100 * Math.pow(10, decimals)) / Math.pow(10, decimals);
    },
    
    sanitizeHtml: function(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },
    
    getDomainData: function(domainId, data = null) {
        // Use provided data or try to get from global sources
        if (!data) {
            if (window.embeddedConsolidatedData) {
                data = window.embeddedConsolidatedData;
            } else if (window.dashboardState?.consolidatedData) {
                data = window.dashboardState.consolidatedData;
            } else {
                return null;
            }
        }
        
        if (domainId === 'all') {
            return {
                summary: data.aggregatedSummary,
                metadata: data.metadata
            };
        }
        
        return data.domainData[domainId] || null;
    }
};

// Ensure ContentGenerator is available globally
window.ContentGenerator = ContentGenerator;

console.log('✅ ContentGenerator module loaded successfully');

