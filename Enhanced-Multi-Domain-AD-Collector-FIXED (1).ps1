# Enhanced Multi-Domain Active Directory Data Collection Script
# Version: 3.1 - Enterprise Edition (Syntax Fixed)
# Supports up to 6 domains with advanced error handling and reporting

param(
    [string]$ConfigFile = "domain-config.json",
    [string]$OutputPath = "data",
    [string]$SpecificDomain = "",
    [switch]$CollectAll,
    [switch]$GenerateConsolidated,
    [switch]$Verbose,
    [switch]$TestConnectivity,
    [int]$TimeoutSeconds = 300,
    [int]$RetryAttempts = 3
)

# Enhanced logging and error handling
$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"

if ($Verbose) {
    $VerbosePreference = "Continue"
}

# Script metadata
$ScriptVersion = "3.1"
$ScriptStartTime = Get-Date

Write-Host "🚀 Enhanced Multi-Domain Active Directory Data Collection Script v$ScriptVersion" -ForegroundColor Cyan
Write-Host "📅 Started: $($ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host "=" * 80 -ForegroundColor DarkGray

# Import required modules with enhanced error handling
function Import-RequiredModules {
    $requiredModules = @("ActiveDirectory")
    $importErrors = @()
    
    foreach ($module in $requiredModules) {
        try {
            Write-Host "📦 Importing module: $module" -ForegroundColor Yellow
            Import-Module $module -ErrorAction Stop -Force
            Write-Host "✅ Module $module imported successfully" -ForegroundColor Green
        } catch {
            $error = "Failed to import module $module`: $($_.Exception.Message)"
            $importErrors += $error
            Write-Host "❌ $error" -ForegroundColor Red
        }
    }
    
    if ($importErrors.Count -gt 0) {
        Write-Host "`n❌ Critical Error: Required modules could not be imported" -ForegroundColor Red
        Write-Host "💡 Please install RSAT tools or run on a domain controller" -ForegroundColor Yellow
        $importErrors | ForEach-Object { Write-Host "   • $_" -ForegroundColor Red }
        exit 1
    }
}

# Enhanced directory creation with error handling
function Initialize-OutputDirectory {
    param([string]$Path)
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            Write-Host "📁 Created output directory: $Path" -ForegroundColor Green
        } else {
            Write-Host "📁 Using existing output directory: $Path" -ForegroundColor Gray
        }
        
        # Create subdirectories
        $subDirs = @("individual", "consolidated", "logs", "temp")
        foreach ($subDir in $subDirs) {
            $fullPath = Join-Path $Path $subDir
            if (-not (Test-Path $fullPath)) {
                New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
            }
        }
        
        return $true
    } catch {
        Write-Host "❌ Failed to create output directory: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Enhanced domain connectivity testing
function Test-DomainConnectivity {
    param(
        [object]$DomainConfig,
        [int]$TimeoutSeconds = 30
    )
    
    $testResults = @{
        domain = $DomainConfig.name
        fqdn = $DomainConfig.fqdn
        dnsResolution = $false
        adConnectivity = $false
        dcReachability = $false
        overallStatus = $false
        errors = @()
        testDuration = 0
    }
    
    $testStartTime = Get-Date
    
    try {
        Write-Host "🔍 Testing connectivity to domain: $($DomainConfig.name) ($($DomainConfig.fqdn))" -ForegroundColor Cyan
        
        # Test 1: DNS Resolution
        try {
            Write-Host "   🌐 Testing DNS resolution..." -ForegroundColor Gray
            $dnsResult = Resolve-DnsName $DomainConfig.fqdn -ErrorAction Stop -Type A
            $testResults.dnsResolution = $true
            Write-Host "   ✅ DNS resolution successful" -ForegroundColor Green
        } catch {
            $testResults.errors += "DNS resolution failed: $($_.Exception.Message)"
            Write-Host "   ❌ DNS resolution failed" -ForegroundColor Red
        }
        
        # Test 2: Active Directory Connectivity
        if ($testResults.dnsResolution) {
            try {
                Write-Host "   🏢 Testing AD connectivity..." -ForegroundColor Gray
                $adDomain = Get-ADDomain -Server $DomainConfig.fqdn -ErrorAction Stop
                $testResults.adConnectivity = $true
                Write-Host "   ✅ AD connectivity successful" -ForegroundColor Green
            } catch {
                $testResults.errors += "AD connectivity failed: $($_.Exception.Message)"
                Write-Host "   ❌ AD connectivity failed" -ForegroundColor Red
            }
        }
        
        # Test 3: Domain Controller Reachability
        if ($testResults.adConnectivity) {
            try {
                Write-Host "   🖥️ Testing domain controller reachability..." -ForegroundColor Gray
                $domainControllers = Get-ADDomainController -Filter * -Server $DomainConfig.fqdn -ErrorAction Stop
                if ($domainControllers.Count -gt 0) {
                    $testResults.dcReachability = $true
                    Write-Host "   ✅ Found $($domainControllers.Count) domain controller(s)" -ForegroundColor Green
                }
            } catch {
                $testResults.errors += "DC reachability test failed: $($_.Exception.Message)"
                Write-Host "   ❌ Domain controller reachability test failed" -ForegroundColor Red
            }
        }
        
        # Overall status
        $testResults.overallStatus = $testResults.dnsResolution -and $testResults.adConnectivity -and $testResults.dcReachability
        $testResults.testDuration = (Get-Date) - $testStartTime
        
        if ($testResults.overallStatus) {
            Write-Host "✅ Domain connectivity test PASSED for $($DomainConfig.name)" -ForegroundColor Green
        } else {
            Write-Host "❌ Domain connectivity test FAILED for $($DomainConfig.name)" -ForegroundColor Red
        }
        
        return $testResults
        
    } catch {
        $testResults.errors += "Connectivity test exception: $($_.Exception.Message)"
        $testResults.testDuration = (Get-Date) - $testStartTime
        Write-Host "❌ Connectivity test exception for $($DomainConfig.name): $($_.Exception.Message)" -ForegroundColor Red
        return $testResults
    }
}

# Enhanced data collection functions with retry logic
function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 5,
        [string]$OperationName = "Operation"
    )
    
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Write-Verbose "Attempting $OperationName (attempt $attempt of $MaxAttempts)"
            $result = & $ScriptBlock
            Write-Verbose "$OperationName succeeded on attempt $attempt"
            return $result
        } catch {
            Write-Warning "$OperationName failed on attempt $attempt`: $($_.Exception.Message)"
            if ($attempt -lt $MaxAttempts) {
                Write-Host "⏳ Waiting $DelaySeconds seconds before retry..." -ForegroundColor Yellow
                Start-Sleep -Seconds $DelaySeconds
            } else {
                Write-Host "❌ $OperationName failed after $MaxAttempts attempts" -ForegroundColor Red
                throw
            }
        }
    }
}

# Enhanced domain controller collection
function Get-EnhancedDomainControllerInfo {
    param(
        [string]$DomainFQDN,
        [string]$DomainId
    )
    
    try {
        Write-Host "🖥️ Collecting domain controller information for $DomainFQDN..." -ForegroundColor Cyan
        
        $domainControllers = Invoke-WithRetry -OperationName "Domain Controller Collection" -ScriptBlock {
            Get-ADDomainController -Filter * -Server $DomainFQDN | ForEach-Object {
                @{
                    Name = $_.Name
                    HostName = $_.HostName
                    Site = $_.Site
                    OperatingSystem = $_.OperatingSystem
                    OperatingSystemVersion = $_.OperatingSystemVersion
                    IPv4Address = $_.IPv4Address
                    IPv6Address = $_.IPv6Address
                    IsGlobalCatalog = $_.IsGlobalCatalog
                    IsReadOnly = $_.IsReadOnly
                    Enabled = $_.Enabled
                    Forest = $_.Forest
                    Domain = $DomainId
                    FQDN = $DomainFQDN
                    Roles = $_.OperationMasterRoles -join ", "
                    LastLogonDate = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                    CreatedDate = if ($_.Created) { $_.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                }
            }
        }
        
        Write-Host "✅ Collected $($domainControllers.Count) domain controllers" -ForegroundColor Green
        return $domainControllers
        
    } catch {
        Write-Host "❌ Failed to collect domain controller info for $DomainFQDN`: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Enhanced user collection with detailed properties
function Get-EnhancedUserInfo {
    param(
        [string]$DomainFQDN,
        [string]$DomainId,
        [int]$MaxUsers = 2000
    )
    
    try {
        Write-Host "👥 Collecting user information for $DomainFQDN (max: $MaxUsers)..." -ForegroundColor Cyan
        
        $users = Invoke-WithRetry -OperationName "User Collection" -ScriptBlock {
            Get-ADUser -Filter * -Server $DomainFQDN -Properties DisplayName, Department, Title, Office, Manager, EmailAddress, LastLogonDate, PasswordLastSet, Enabled, PasswordNeverExpires, LockedOut, AccountExpirationDate, Created, Modified -ResultSetSize $MaxUsers | ForEach-Object {
                @{
                    SamAccountName = $_.SamAccountName
                    UserPrincipalName = $_.UserPrincipalName
                    DisplayName = $_.DisplayName
                    GivenName = $_.GivenName
                    Surname = $_.Surname
                    EmailAddress = $_.EmailAddress
                    Department = $_.Department
                    Title = $_.Title
                    Office = $_.Office
                    Manager = if ($_.Manager) { try { (Get-ADUser $_.Manager -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName } catch { "" } } else { "" }
                    Enabled = $_.Enabled
                    LockedOut = $_.LockedOut
                    LastLogonDate = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                    PasswordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                    PasswordNeverExpires = $_.PasswordNeverExpires
                    AccountExpirationDate = if ($_.AccountExpirationDate) { $_.AccountExpirationDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                    Created = if ($_.Created) { $_.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                    Modified = if ($_.Modified) { $_.Modified.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                    Domain = $DomainId
                    FQDN = $DomainFQDN
                }
            }
        }
        
        Write-Host "✅ Collected $($users.Count) users" -ForegroundColor Green
        return $users
        
    } catch {
        Write-Host "❌ Failed to collect user info for $DomainFQDN`: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Enhanced computer collection
function Get-EnhancedComputerInfo {
    param(
        [string]$DomainFQDN,
        [string]$DomainId,
        [int]$MaxComputers = 2000
    )
    
    try {
        Write-Host "💻 Collecting computer information for $DomainFQDN (max: $MaxComputers)..." -ForegroundColor Cyan
        
        $computers = Invoke-WithRetry -OperationName "Computer Collection" -ScriptBlock {
            Get-ADComputer -Filter * -Server $DomainFQDN -Properties OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack, LastLogonDate, Enabled, IPv4Address, Description, Location, ManagedBy, Created, Modified -ResultSetSize $MaxComputers | ForEach-Object {
                @{
                    Name = $_.Name
                    DNSHostName = $_.DNSHostName
                    OperatingSystem = $_.OperatingSystem
                    OperatingSystemVersion = $_.OperatingSystemVersion
                    OperatingSystemServicePack = $_.OperatingSystemServicePack
                    Enabled = $_.Enabled
                    LastLogonDate = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                    IPv4Address = $_.IPv4Address
                    Description = $_.Description
                    Location = $_.Location
                    ManagedBy = if ($_.ManagedBy) { try { (Get-ADUser $_.ManagedBy -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName } catch { "" } } else { "" }
                    Created = if ($_.Created) { $_.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                    Modified = if ($_.Modified) { $_.Modified.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                    Domain = $DomainId
                    FQDN = $DomainFQDN
                }
            }
        }
        
        Write-Host "✅ Collected $($computers.Count) computers" -ForegroundColor Green
        return $computers
        
    } catch {
        Write-Host "❌ Failed to collect computer info for $DomainFQDN`: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Enhanced group collection
function Get-EnhancedGroupInfo {
    param(
        [string]$DomainFQDN,
        [string]$DomainId,
        [int]$MaxGroups = 1000
    )
    
    try {
        Write-Host "🛡️ Collecting group information for $DomainFQDN (max: $MaxGroups)..." -ForegroundColor Cyan
        
        $groups = Invoke-WithRetry -OperationName "Group Collection" -ScriptBlock {
            Get-ADGroup -Filter * -Server $DomainFQDN -Properties Description, GroupCategory, GroupScope, MemberOf, ManagedBy, Created, Modified -ResultSetSize $MaxGroups | ForEach-Object {
                $memberCount = 0
                try {
                    $memberCount = (Get-ADGroupMember -Identity $_.DistinguishedName -Server $DomainFQDN -ErrorAction SilentlyContinue | Measure-Object).Count
                } catch {
                    # Ignore errors for member count - some groups may not be accessible
                }
                
                @{
                    Name = $_.Name
                    SamAccountName = $_.SamAccountName
                    Description = $_.Description
                    GroupCategory = $_.GroupCategory
                    GroupScope = $_.GroupScope
                    MemberCount = $memberCount
                    ManagedBy = if ($_.ManagedBy) { try { (Get-ADUser $_.ManagedBy -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName } catch { "" } } else { "" }
                    Created = if ($_.Created) { $_.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                    Modified = if ($_.Modified) { $_.Modified.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                    Domain = $DomainId
                    FQDN = $DomainFQDN
                }
            }
        }
        
        Write-Host "✅ Collected $($groups.Count) groups" -ForegroundColor Green
        return $groups
        
    } catch {
        Write-Host "❌ Failed to collect group info for $DomainFQDN`: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Main domain data collection function
function Collect-EnhancedDomainData {
    param(
        [object]$DomainConfig,
        [object]$CollectionSettings
    )
    
    $domainStartTime = Get-Date
    Write-Host "`n🏢 Starting enhanced data collection for domain: $($DomainConfig.name)" -ForegroundColor Yellow
    Write-Host "📍 FQDN: $($DomainConfig.fqdn)" -ForegroundColor Gray
    Write-Host "🎯 Priority: $($DomainConfig.priority)" -ForegroundColor Gray
    
    # Initialize domain data structure
    $domainData = @{
        info = @{
            id = $DomainConfig.id
            name = $DomainConfig.name
            fqdn = $DomainConfig.fqdn
            description = $DomainConfig.description
            color = $DomainConfig.color
            priority = $DomainConfig.priority
            location = $DomainConfig.location
            contact = $DomainConfig.contact
        }
        connectivity = @{}
        summary = @{}
        users = @()
        computers = @()
        groups = @()
        domainControllers = @()
        status = "In Progress"
        lastCollection = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        collectionTime = $null
        errors = @()
    }
    
    try {
        # Test connectivity first
        Write-Host "🔍 Testing domain connectivity..." -ForegroundColor Cyan
        $connectivityTest = Test-DomainConnectivity -DomainConfig $DomainConfig -TimeoutSeconds $CollectionSettings.timeout
        $domainData.connectivity = $connectivityTest
        
        if (-not $connectivityTest.overallStatus) {
            $domainData.status = "Failed - Connectivity"
            $domainData.errors = $connectivityTest.errors
            $domainData.collectionTime = (Get-Date) - $domainStartTime
            return $domainData
        }
        
        # Collect domain controllers
        if ($CollectionSettings.collectDomainControllers) {
            Write-Host "🖥️ Collecting domain controllers..." -ForegroundColor Cyan
            $domainData.domainControllers = Get-EnhancedDomainControllerInfo -DomainFQDN $DomainConfig.fqdn -DomainId $DomainConfig.id
        }
        
        # Collect users
        if ($CollectionSettings.collectUsers) {
            Write-Host "👥 Collecting users..." -ForegroundColor Cyan
            $domainData.users = Get-EnhancedUserInfo -DomainFQDN $DomainConfig.fqdn -DomainId $DomainConfig.id -MaxUsers $CollectionSettings.maxUsers
        }
        
        # Collect computers
        if ($CollectionSettings.collectComputers) {
            Write-Host "💻 Collecting computers..." -ForegroundColor Cyan
            $domainData.computers = Get-EnhancedComputerInfo -DomainFQDN $DomainConfig.fqdn -DomainId $DomainConfig.id -MaxComputers $CollectionSettings.maxComputers
        }
        
        # Collect groups
        if ($CollectionSettings.collectGroups) {
            Write-Host "🛡️ Collecting groups..." -ForegroundColor Cyan
            $domainData.groups = Get-EnhancedGroupInfo -DomainFQDN $DomainConfig.fqdn -DomainId $DomainConfig.id -MaxGroups $CollectionSettings.maxGroups
        }
        
        # Calculate enhanced summary statistics
        $activeUsers = ($domainData.users | Where-Object { $_.Enabled -eq $true }).Count
        $disabledUsers = ($domainData.users | Where-Object { $_.Enabled -eq $false }).Count
        $lockedUsers = ($domainData.users | Where-Object { $_.LockedOut -eq $true }).Count
        $activeComputers = ($domainData.computers | Where-Object { $_.Enabled -eq $true }).Count
        $securityGroups = ($domainData.groups | Where-Object { $_.GroupCategory -eq "Security" }).Count
        $distributionGroups = ($domainData.groups | Where-Object { $_.GroupCategory -eq "Distribution" }).Count
        
        $domainData.summary = @{
            totalUsers = $domainData.users.Count
            activeUsers = $activeUsers
            disabledUsers = $disabledUsers
            lockedUsers = $lockedUsers
            totalComputers = $domainData.computers.Count
            activeComputers = $activeComputers
            inactiveComputers = $domainData.computers.Count - $activeComputers
            totalGroups = $domainData.groups.Count
            securityGroups = $securityGroups
            distributionGroups = $distributionGroups
            domainControllers = $domainData.domainControllers.Count
            globalCatalogs = ($domainData.domainControllers | Where-Object { $_.IsGlobalCatalog -eq $true }).Count
            readOnlyDCs = ($domainData.domainControllers | Where-Object { $_.IsReadOnly -eq $true }).Count
        }
        
        $domainData.status = "Completed"
        $domainData.collectionTime = (Get-Date) - $domainStartTime
        
        Write-Host "✅ Enhanced domain collection completed for $($DomainConfig.name)" -ForegroundColor Green
        Write-Host "📊 Summary: $($domainData.summary.totalUsers) users, $($domainData.summary.totalComputers) computers, $($domainData.summary.totalGroups) groups, $($domainData.summary.domainControllers) DCs" -ForegroundColor Gray
        Write-Host "⏱️ Collection time: $([math]::Round($domainData.collectionTime.TotalMinutes, 2)) minutes" -ForegroundColor Gray
        
        return $domainData
        
    } catch {
        Write-Host "❌ Error during enhanced domain collection for $($DomainConfig.name)`: $($_.Exception.Message)" -ForegroundColor Red
        $domainData.status = "Failed - Collection Error"
        $domainData.errors += $_.Exception.Message
        $domainData.collectionTime = (Get-Date) - $domainStartTime
        return $domainData
    }
}

# Initialize script
Import-RequiredModules

if (-not (Initialize-OutputDirectory -Path $OutputPath)) {
    Write-Host "❌ Failed to initialize output directory. Exiting." -ForegroundColor Red
    exit 1
}

# Load or create configuration
if (-not (Test-Path $ConfigFile)) {
    Write-Host "📝 Configuration file not found. Creating enhanced default configuration..." -ForegroundColor Yellow
    
    # Create enhanced default configuration for 6 domains
    $defaultConfig = @{
        metadata = @{
            version = "3.1"
            created = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            description = "Enhanced Multi-Domain Active Directory Configuration"
        }
        domains = @(
            @{
                id = "corp-hq"
                name = "Corporate Headquarters"
                fqdn = "corp.company.com"
                description = "Main corporate domain with executive and administrative users"
                color = "#3498db"
                priority = 1
                enabled = $true
                location = "New York, NY"
                contact = "IT-Admin@corp.company.com"
                credentials = @{
                    useCurrentUser = $true
                    username = ""
                    domain = ""
                }
            },
            @{
                id = "sales-region"
                name = "Sales Regional Office"
                fqdn = "sales.company.com"
                description = "Sales team domain with CRM and sales applications"
                color = "#9b59b6"
                priority = 2
                enabled = $true
                location = "Chicago, IL"
                contact = "Sales-IT@sales.company.com"
                credentials = @{
                    useCurrentUser = $true
                    username = ""
                    domain = ""
                }
            },
            @{
                id = "dev-environment"
                name = "Development Environment"
                fqdn = "dev.company.com"
                description = "Development and testing domain for software teams"
                color = "#e67e22"
                priority = 3
                enabled = $true
                location = "Austin, TX"
                contact = "DevOps@dev.company.com"
                credentials = @{
                    useCurrentUser = $true
                    username = ""
                    domain = ""
                }
            },
            @{
                id = "manufacturing"
                name = "Manufacturing Division"
                fqdn = "mfg.company.com"
                description = "Manufacturing and production domain with industrial systems"
                color = "#1abc9c"
                priority = 4
                enabled = $true
                location = "Detroit, MI"
                contact = "MFG-IT@mfg.company.com"
                credentials = @{
                    useCurrentUser = $true
                    username = ""
                    domain = ""
                }
            },
            @{
                id = "finance-dept"
                name = "Finance Department"
                fqdn = "finance.company.com"
                description = "Finance and accounting domain with sensitive financial data"
                color = "#e74c3c"
                priority = 5
                enabled = $true
                location = "Boston, MA"
                contact = "Finance-IT@finance.company.com"
                credentials = @{
                    useCurrentUser = $true
                    username = ""
                    domain = ""
                }
            },
            @{
                id = "research-lab"
                name = "Research Laboratory"
                fqdn = "research.company.com"
                description = "Research and development domain with scientific applications"
                color = "#f1c40f"
                priority = 6
                enabled = $true
                location = "San Francisco, CA"
                contact = "Research-IT@research.company.com"
                credentials = @{
                    useCurrentUser = $true
                    username = ""
                    domain = ""
                }
            }
        )
        collection = @{
            timeout = 300
            retryAttempts = 3
            parallelCollection = $false
            collectUsers = $true
            collectComputers = $true
            collectGroups = $true
            collectDomainControllers = $true
            maxUsers = 2000
            maxComputers = 2000
            maxGroups = 1000
            includeDisabledObjects = $true
            collectDetailedProperties = $true
        }
        output = @{
            generateIndividualFiles = $true
            generateConsolidatedFile = $true
            includeTimestamps = $true
            compressOutput = $false
            logLevel = "Verbose"
            retainLogDays = 30
        }
        dashboard = @{
            title = "Multi-Domain Active Directory Dashboard"
            refreshInterval = 30
            defaultView = "overview"
            enableRealTimeUpdates = $true
            maxDisplayItems = 1000
        }
    }
    
    $defaultConfig | ConvertTo-Json -Depth 10 | Set-Content $ConfigFile -Encoding UTF8
    Write-Host "✅ Enhanced default configuration created: $ConfigFile" -ForegroundColor Green
    Write-Host "⚠️ Please edit the configuration file to match your environment" -ForegroundColor Yellow
    Write-Host "💡 Update domain FQDNs, credentials, and collection settings as needed" -ForegroundColor Cyan
    return
}

# Load configuration
try {
    $config = Get-Content $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Host "✅ Enhanced configuration loaded from: $ConfigFile" -ForegroundColor Green
    Write-Host "📋 Configuration version: $($config.metadata.version)" -ForegroundColor Gray
} catch {
    Write-Host "❌ Failed to load configuration file: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Handle test connectivity mode
if ($TestConnectivity) {
    Write-Host "`n🔍 Testing connectivity to all enabled domains..." -ForegroundColor Cyan
    $enabledDomains = $config.domains | Where-Object { $_.enabled -eq $true }
    
    foreach ($domain in $enabledDomains) {
        $testResult = Test-DomainConnectivity -DomainConfig $domain -TimeoutSeconds $config.collection.timeout
        Write-Host ""
    }
    
    Write-Host "`n✅ Connectivity testing completed" -ForegroundColor Green
    return
}

# Determine domains to process
$domainsToProcess = @()

if ($SpecificDomain) {
    $domain = $config.domains | Where-Object { $_.id -eq $SpecificDomain }
    if ($domain) {
        $domainsToProcess = @($domain)
        Write-Host "🎯 Processing specific domain: $($domain.name)" -ForegroundColor Cyan
    } else {
        Write-Host "❌ Domain '$SpecificDomain' not found in configuration" -ForegroundColor Red
        Write-Host "Available domains:" -ForegroundColor Yellow
        $config.domains | ForEach-Object { Write-Host "   • $($_.id) - $($_.name)" -ForegroundColor Gray }
        exit 1
    }
} elseif ($CollectAll) {
    $domainsToProcess = $config.domains | Where-Object { $_.enabled -eq $true } | Sort-Object priority
    Write-Host "📋 Processing $($domainsToProcess.Count) enabled domains:" -ForegroundColor Cyan
    $domainsToProcess | ForEach-Object { Write-Host "   • $($_.name) ($($_.fqdn)) - Priority $($_.priority)" -ForegroundColor Gray }
} else {
    Write-Host "ℹ️ No collection mode specified. Available options:" -ForegroundColor Yellow
    Write-Host "   • Use -CollectAll to collect data from all enabled domains" -ForegroundColor Gray
    Write-Host "   • Use -SpecificDomain <domain-id> to collect from a specific domain" -ForegroundColor Gray
    Write-Host "   • Use -TestConnectivity to test domain connectivity" -ForegroundColor Gray
    return
}

# Start enhanced collection process
$collectionStartTime = Get-Date
$allDomainData = @{}
$successfulCollections = 0
$failedCollections = 0
$collectionErrors = @()

Write-Host "`n" + "=" * 80 -ForegroundColor DarkGray
Write-Host "🚀 Starting Enhanced Multi-Domain Data Collection" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor DarkGray

foreach ($domain in $domainsToProcess) {
    try {
        $domainResult = Collect-EnhancedDomainData -DomainConfig $domain -CollectionSettings $config.collection
        $allDomainData[$domain.id] = $domainResult
        
        if ($domainResult.status -eq "Completed") {
            $successfulCollections++
            
            # Save individual domain file
            if ($config.output.generateIndividualFiles) {
                $domainFile = Join-Path $OutputPath "individual\$($domain.id)-data.json"
                $domainResult | ConvertTo-Json -Depth 10 | Set-Content $domainFile -Encoding UTF8
                Write-Host "💾 Saved domain data: $domainFile" -ForegroundColor Green
            }
        } else {
            $failedCollections++
            $collectionErrors += @{
                domain = $domain.name
                domainId = $domain.id
                status = $domainResult.status
                errors = $domainResult.errors
            }
        }
        
    } catch {
        $failedCollections++
        $error = @{
            domain = $domain.name
            domainId = $domain.id
            status = "Exception"
            errors = @($_.Exception.Message)
        }
        $collectionErrors += $error
        Write-Host "❌ Failed to collect data for domain $($domain.name)`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Generate enhanced consolidated data
if ($GenerateConsolidated -and $allDomainData.Count -gt 0) {
    Write-Host "`n🔄 Generating enhanced consolidated data..." -ForegroundColor Cyan
    
    # Calculate comprehensive aggregated summary
    $aggregatedSummary = @{
        totalUsers = 0
        activeUsers = 0
        disabledUsers = 0
        lockedUsers = 0
        totalComputers = 0
        activeComputers = 0
        inactiveComputers = 0
        totalGroups = 0
        securityGroups = 0
        distributionGroups = 0
        domainControllers = 0
        globalCatalogs = 0
        readOnlyDCs = 0
    }
    
    # Aggregate data from all successful collections
    foreach ($domainData in $allDomainData.Values) {
        if ($domainData.status -eq "Completed" -and $domainData.summary) {
            $summary = $domainData.summary
            $aggregatedSummary.totalUsers += $summary.totalUsers
            $aggregatedSummary.activeUsers += $summary.activeUsers
            $aggregatedSummary.disabledUsers += $summary.disabledUsers
            $aggregatedSummary.lockedUsers += $summary.lockedUsers
            $aggregatedSummary.totalComputers += $summary.totalComputers
            $aggregatedSummary.activeComputers += $summary.activeComputers
            $aggregatedSummary.inactiveComputers += $summary.inactiveComputers
            $aggregatedSummary.totalGroups += $summary.totalGroups
            $aggregatedSummary.securityGroups += $summary.securityGroups
            $aggregatedSummary.distributionGroups += $summary.distributionGroups
            $aggregatedSummary.domainControllers += $summary.domainControllers
            $aggregatedSummary.globalCatalogs += $summary.globalCatalogs
            $aggregatedSummary.readOnlyDCs += $summary.readOnlyDCs
        }
    }
    
    # Create comprehensive consolidated data structure
    $consolidatedData = @{
        metadata = @{
            version = $ScriptVersion
            generatedOn = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            generatedBy = $env:USERNAME
            computerName = $env:COMPUTERNAME
            totalDomains = $domainsToProcess.Count
            successfulCollections = $successfulCollections
            failedCollections = $failedCollections
            collectionDuration = [math]::Round(((Get-Date) - $collectionStartTime).TotalMinutes, 2)
            configurationFile = $ConfigFile
            outputPath = $OutputPath
        }
        aggregatedSummary = $aggregatedSummary
        domainData = $allDomainData
        collectionErrors = $collectionErrors
        configuration = @{
            domains = $config.domains
            collection = $config.collection
            dashboard = $config.dashboard
        }
    }
    
    # Save consolidated data
    $consolidatedFile = Join-Path $OutputPath "consolidated\consolidated-data.json"
    $consolidatedData | ConvertTo-Json -Depth 15 | Set-Content $consolidatedFile -Encoding UTF8
    Write-Host "💾 Saved consolidated data: $consolidatedFile" -ForegroundColor Green
    
    # Save collection metadata separately for quick access
    $metadataFile = Join-Path $OutputPath "consolidated\collection-metadata.json"
    $consolidatedData.metadata | ConvertTo-Json -Depth 5 | Set-Content $metadataFile -Encoding UTF8
    Write-Host "💾 Saved collection metadata: $metadataFile" -ForegroundColor Green
}

# Generate collection summary report
$collectionEndTime = Get-Date
$totalDuration = $collectionEndTime - $collectionStartTime

Write-Host "`n" + "=" * 80 -ForegroundColor DarkGray
Write-Host "📊 Enhanced Multi-Domain Collection Summary" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor DarkGray
Write-Host "⏱️ Total Duration: $([math]::Round($totalDuration.TotalMinutes, 2)) minutes" -ForegroundColor Yellow
Write-Host "📋 Total Domains: $($domainsToProcess.Count)" -ForegroundColor Cyan
Write-Host "✅ Successful Collections: $successfulCollections" -ForegroundColor Green
Write-Host "❌ Failed Collections: $failedCollections" -ForegroundColor Red

if ($successfulCollections -gt 0) {
    Write-Host "`n📈 Aggregated Statistics:" -ForegroundColor Cyan
    Write-Host "   👥 Total Users: $($aggregatedSummary.totalUsers)" -ForegroundColor Gray
    Write-Host "   💻 Total Computers: $($aggregatedSummary.totalComputers)" -ForegroundColor Gray
    Write-Host "   🛡️ Total Groups: $($aggregatedSummary.totalGroups)" -ForegroundColor Gray
    Write-Host "   🖥️ Domain Controllers: $($aggregatedSummary.domainControllers)" -ForegroundColor Gray
}

if ($collectionErrors.Count -gt 0) {
    Write-Host "`n❌ Collection Errors:" -ForegroundColor Red
    foreach ($error in $collectionErrors) {
        Write-Host "   • $($error.domain) ($($error.domainId)): $($error.status)" -ForegroundColor Red
        if ($error.errors) {
            $error.errors | ForEach-Object { Write-Host "     - $_" -ForegroundColor DarkRed }
        }
    }
}

Write-Host "`n✅ Enhanced Multi-Domain Active Directory Data Collection Completed!" -ForegroundColor Green
Write-Host "📁 Output files saved to: $OutputPath" -ForegroundColor Cyan
Write-Host "🌐 Ready for dashboard integration!" -ForegroundColor Magenta

# Save execution log
$logFile = Join-Path $OutputPath "logs\collection-log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$logContent = @"
Enhanced Multi-Domain AD Data Collection Log
============================================
Script Version: $ScriptVersion
Start Time: $($ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))
End Time: $($collectionEndTime.ToString('yyyy-MM-dd HH:mm:ss'))
Duration: $([math]::Round($totalDuration.TotalMinutes, 2)) minutes
Configuration File: $ConfigFile
Output Path: $OutputPath

Summary:
- Total Domains: $($domainsToProcess.Count)
- Successful Collections: $successfulCollections
- Failed Collections: $failedCollections

Aggregated Statistics:
- Total Users: $($aggregatedSummary.totalUsers)
- Active Users: $($aggregatedSummary.activeUsers)
- Total Computers: $($aggregatedSummary.totalComputers)
- Active Computers: $($aggregatedSummary.activeComputers)
- Total Groups: $($aggregatedSummary.totalGroups)
- Security Groups: $($aggregatedSummary.securityGroups)
- Domain Controllers: $($aggregatedSummary.domainControllers)

Collection completed successfully.
"@

$logContent | Set-Content $logFile -Encoding UTF8
Write-Host "📝 Execution log saved: $logFile" -ForegroundColor Gray

