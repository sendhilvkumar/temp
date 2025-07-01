# Enhanced Multi-Domain Active Directory Data Collection Script v3.2
# UNLIMITED SCANNING VERSION - Complete Object Enumeration
# Removes all artificial limits for true AD object counts

param(
    [string]$ConfigFile = "domain-config.json",
    [string]$OutputPath = "data",
    [string]$SpecificDomain = "",
    [switch]$UnlimitedScan = $true,
    [switch]$FastScan = $false,
    [int]$BatchSize = 1000,
    [switch]$Verbose = $false
)

# Set error handling
$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"

# Enhanced logging function
function Write-EnhancedLog {
    param(
        [string]$Message,
        [string]$Level = "Info",
        [string]$Color = "White"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Write-Host $logMessage -ForegroundColor $Color
    
    # Also log to file if verbose
    if ($Verbose) {
        $logFile = Join-Path $OutputPath "logs\collection-$(Get-Date -Format 'yyyyMMdd').log"
        $logMessage | Add-Content $logFile -Encoding UTF8
    }
}

Write-EnhancedLog "🚀 Enhanced Multi-Domain Active Directory Data Collection Script v3.2" "Info" "Cyan"
Write-EnhancedLog "📊 UNLIMITED SCANNING VERSION - Complete Object Enumeration" "Info" "Yellow"
Write-EnhancedLog "🔄 Scanning Mode: $(if ($UnlimitedScan) { 'UNLIMITED (Complete)' } else { 'LIMITED (Fast)' })" "Info" "Green"

# Import required modules with enhanced error handling
function Import-RequiredModules {
    $requiredModules = @("ActiveDirectory")
    $importErrors = @()
    
    Write-EnhancedLog "📦 Importing required modules..." "Info" "Cyan"
    
    foreach ($module in $requiredModules) {
        try {
            Import-Module $module -Force -ErrorAction Stop
            Write-EnhancedLog "✅ Module imported successfully: $module" "Success" "Green"
        } catch {
            $importErrors += "Failed to import $module`: $($_.Exception.Message)"
            Write-EnhancedLog "❌ Failed to import module: $module" "Error" "Red"
        }
    }
    
    if ($importErrors.Count -gt 0) {
        Write-EnhancedLog "❌ Critical Error: Required modules could not be imported" "Error" "Red"
        Write-EnhancedLog "💡 Please install RSAT tools or run on a domain controller" "Warning" "Yellow"
        $importErrors | ForEach-Object { Write-EnhancedLog "   • $_" "Error" "Red" }
        exit 1
    }
}

# Enhanced directory creation with error handling
function Initialize-OutputDirectory {
    param([string]$Path)
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            Write-EnhancedLog "📁 Created output directory: $Path" "Success" "Green"
        } else {
            Write-EnhancedLog "📁 Using existing output directory: $Path" "Info" "Gray"
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
        Write-EnhancedLog "❌ Failed to create output directory: $($_.Exception.Message)" "Error" "Red"
        return $false
    }
}

# Enhanced retry mechanism with exponential backoff
function Invoke-WithRetry {
    param(
        [string]$OperationName,
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [int]$BaseDelaySeconds = 5
    )
    
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            Write-EnhancedLog "🔄 $OperationName (attempt $attempt/$MaxRetries)" "Info" "Cyan"
            $result = & $ScriptBlock
            Write-EnhancedLog "✅ $OperationName completed successfully" "Success" "Green"
            return $result
        } catch {
            $delaySeconds = $BaseDelaySeconds * [Math]::Pow(2, $attempt - 1)
            Write-EnhancedLog "❌ $OperationName failed on attempt $attempt`: $($_.Exception.Message)" "Warning" "Yellow"
            
            if ($attempt -lt $MaxRetries) {
                Write-EnhancedLog "⏳ Waiting $delaySeconds seconds before retry..." "Info" "Yellow"
                Start-Sleep -Seconds $delaySeconds
            } else {
                Write-EnhancedLog "❌ $OperationName failed after $MaxRetries attempts" "Error" "Red"
                throw $_
            }
        }
    }
}

# UNLIMITED USER COLLECTION - No artificial limits
function Get-UnlimitedUserInfo {
    param(
        [string]$DomainFQDN,
        [string]$DomainId,
        [bool]$UnlimitedScan = $true,
        [int]$BatchSize = 1000
    )
    
    try {
        if ($UnlimitedScan) {
            Write-EnhancedLog "👥 Collecting ALL users from $DomainFQDN (UNLIMITED SCAN)..." "Info" "Cyan"
            Write-EnhancedLog "⚠️  This may take several minutes for large domains..." "Warning" "Yellow"
        } else {
            Write-EnhancedLog "👥 Collecting users from $DomainFQDN (LIMITED SCAN - first 2000)..." "Info" "Cyan"
        }
        
        $users = Invoke-WithRetry -OperationName "User Collection" -ScriptBlock {
            $allUsers = @()
            $userCount = 0
            
            if ($UnlimitedScan) {
                # UNLIMITED SCAN - Get ALL users with paging
                Write-EnhancedLog "🔄 Starting unlimited user enumeration..." "Info" "Cyan"
                
                $userQuery = Get-ADUser -Filter * -Server $DomainFQDN -Properties DisplayName, Department, Title, Office, Manager, EmailAddress, LastLogonDate, PasswordLastSet, Enabled, PasswordNeverExpires, LockedOut, AccountExpirationDate, Created, Modified -ResultPageSize $BatchSize
                
                foreach ($user in $userQuery) {
                    $userCount++
                    if ($userCount % $BatchSize -eq 0) {
                        Write-EnhancedLog "📊 Processed $userCount users..." "Info" "Gray"
                    }
                    
                    $allUsers += @{
                        SamAccountName = $user.SamAccountName
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        GivenName = $user.GivenName
                        Surname = $user.Surname
                        EmailAddress = $user.EmailAddress
                        Department = $user.Department
                        Title = $user.Title
                        Office = $user.Office
                        Manager = if ($user.Manager) { try { (Get-ADUser $user.Manager -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName } catch { "" } } else { "" }
                        Enabled = $user.Enabled
                        LockedOut = $user.LockedOut
                        LastLogonDate = if ($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                        PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                        PasswordNeverExpires = $user.PasswordNeverExpires
                        AccountExpirationDate = if ($user.AccountExpirationDate) { $user.AccountExpirationDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                        Created = if ($user.Created) { $user.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Modified = if ($user.Modified) { $user.Modified.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Domain = $DomainId
                        FQDN = $DomainFQDN
                    }
                }
            } else {
                # LIMITED SCAN - First 2000 users only
                $userQuery = Get-ADUser -Filter * -Server $DomainFQDN -Properties DisplayName, Department, Title, Office, Manager, EmailAddress, LastLogonDate, PasswordLastSet, Enabled, PasswordNeverExpires, LockedOut, AccountExpirationDate, Created, Modified -ResultSetSize 2000
                
                foreach ($user in $userQuery) {
                    $allUsers += @{
                        SamAccountName = $user.SamAccountName
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        GivenName = $user.GivenName
                        Surname = $user.Surname
                        EmailAddress = $user.EmailAddress
                        Department = $user.Department
                        Title = $user.Title
                        Office = $user.Office
                        Manager = if ($user.Manager) { try { (Get-ADUser $user.Manager -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName } catch { "" } } else { "" }
                        Enabled = $user.Enabled
                        LockedOut = $user.LockedOut
                        LastLogonDate = if ($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                        PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                        PasswordNeverExpires = $user.PasswordNeverExpires
                        AccountExpirationDate = if ($user.AccountExpirationDate) { $user.AccountExpirationDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                        Created = if ($user.Created) { $user.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Modified = if ($user.Modified) { $user.Modified.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Domain = $DomainId
                        FQDN = $DomainFQDN
                    }
                }
            }
            
            return $allUsers
        }
        
        Write-EnhancedLog "✅ Collected $($users.Count) users $(if ($UnlimitedScan) { '(COMPLETE SCAN)' } else { '(LIMITED SCAN)' })" "Success" "Green"
        return $users
        
    } catch {
        Write-EnhancedLog "❌ Failed to collect user info for $DomainFQDN`: $($_.Exception.Message)" "Error" "Red"
        return @()
    }
}

# UNLIMITED COMPUTER COLLECTION - No artificial limits
function Get-UnlimitedComputerInfo {
    param(
        [string]$DomainFQDN,
        [string]$DomainId,
        [bool]$UnlimitedScan = $true,
        [int]$BatchSize = 1000
    )
    
    try {
        if ($UnlimitedScan) {
            Write-EnhancedLog "💻 Collecting ALL computers from $DomainFQDN (UNLIMITED SCAN)..." "Info" "Cyan"
            Write-EnhancedLog "⚠️  This may take several minutes for large domains..." "Warning" "Yellow"
        } else {
            Write-EnhancedLog "💻 Collecting computers from $DomainFQDN (LIMITED SCAN - first 2000)..." "Info" "Cyan"
        }
        
        $computers = Invoke-WithRetry -OperationName "Computer Collection" -ScriptBlock {
            $allComputers = @()
            $computerCount = 0
            
            if ($UnlimitedScan) {
                # UNLIMITED SCAN - Get ALL computers with paging
                Write-EnhancedLog "🔄 Starting unlimited computer enumeration..." "Info" "Cyan"
                
                $computerQuery = Get-ADComputer -Filter * -Server $DomainFQDN -Properties OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack, LastLogonDate, Enabled, IPv4Address, Description, Location, ManagedBy, Created, Modified -ResultPageSize $BatchSize
                
                foreach ($computer in $computerQuery) {
                    $computerCount++
                    if ($computerCount % $BatchSize -eq 0) {
                        Write-EnhancedLog "📊 Processed $computerCount computers..." "Info" "Gray"
                    }
                    
                    $allComputers += @{
                        Name = $computer.Name
                        DNSHostName = $computer.DNSHostName
                        OperatingSystem = $computer.OperatingSystem
                        OperatingSystemVersion = $computer.OperatingSystemVersion
                        OperatingSystemServicePack = $computer.OperatingSystemServicePack
                        IPv4Address = $computer.IPv4Address
                        Description = $computer.Description
                        Location = $computer.Location
                        Enabled = $computer.Enabled
                        LastLogonDate = if ($computer.LastLogonDate) { $computer.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                        ManagedBy = if ($computer.ManagedBy) { try { (Get-ADUser $computer.ManagedBy -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName } catch { "" } } else { "" }
                        Created = if ($computer.Created) { $computer.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Modified = if ($computer.Modified) { $computer.Modified.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Domain = $DomainId
                        FQDN = $DomainFQDN
                    }
                }
            } else {
                # LIMITED SCAN - First 2000 computers only
                $computerQuery = Get-ADComputer -Filter * -Server $DomainFQDN -Properties OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack, LastLogonDate, Enabled, IPv4Address, Description, Location, ManagedBy, Created, Modified -ResultSetSize 2000
                
                foreach ($computer in $computerQuery) {
                    $allComputers += @{
                        Name = $computer.Name
                        DNSHostName = $computer.DNSHostName
                        OperatingSystem = $computer.OperatingSystem
                        OperatingSystemVersion = $computer.OperatingSystemVersion
                        OperatingSystemServicePack = $computer.OperatingSystemServicePack
                        IPv4Address = $computer.IPv4Address
                        Description = $computer.Description
                        Location = $computer.Location
                        Enabled = $computer.Enabled
                        LastLogonDate = if ($computer.LastLogonDate) { $computer.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                        ManagedBy = if ($computer.ManagedBy) { try { (Get-ADUser $computer.ManagedBy -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName } catch { "" } } else { "" }
                        Created = if ($computer.Created) { $computer.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Modified = if ($computer.Modified) { $computer.Modified.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Domain = $DomainId
                        FQDN = $DomainFQDN
                    }
                }
            }
            
            return $allComputers
        }
        
        Write-EnhancedLog "✅ Collected $($computers.Count) computers $(if ($UnlimitedScan) { '(COMPLETE SCAN)' } else { '(LIMITED SCAN)' })" "Success" "Green"
        return $computers
        
    } catch {
        Write-EnhancedLog "❌ Failed to collect computer info for $DomainFQDN`: $($_.Exception.Message)" "Error" "Red"
        return @()
    }
}

# UNLIMITED GROUP COLLECTION - No artificial limits
function Get-UnlimitedGroupInfo {
    param(
        [string]$DomainFQDN,
        [string]$DomainId,
        [bool]$UnlimitedScan = $true,
        [int]$BatchSize = 1000
    )
    
    try {
        if ($UnlimitedScan) {
            Write-EnhancedLog "🛡️ Collecting ALL groups from $DomainFQDN (UNLIMITED SCAN)..." "Info" "Cyan"
            Write-EnhancedLog "⚠️  This may take several minutes for large domains..." "Warning" "Yellow"
        } else {
            Write-EnhancedLog "🛡️ Collecting groups from $DomainFQDN (LIMITED SCAN - first 1000)..." "Info" "Cyan"
        }
        
        $groups = Invoke-WithRetry -OperationName "Group Collection" -ScriptBlock {
            $allGroups = @()
            $groupCount = 0
            
            if ($UnlimitedScan) {
                # UNLIMITED SCAN - Get ALL groups with paging
                Write-EnhancedLog "🔄 Starting unlimited group enumeration..." "Info" "Cyan"
                
                $groupQuery = Get-ADGroup -Filter * -Server $DomainFQDN -Properties Description, GroupCategory, GroupScope, MemberOf, ManagedBy, Created, Modified -ResultPageSize $BatchSize
                
                foreach ($group in $groupQuery) {
                    $groupCount++
                    if ($groupCount % $BatchSize -eq 0) {
                        Write-EnhancedLog "📊 Processed $groupCount groups..." "Info" "Gray"
                    }
                    
                    # Get member count (this can be slow for large groups)
                    $memberCount = 0
                    try {
                        $memberCount = (Get-ADGroupMember $group.SamAccountName -Server $DomainFQDN -ErrorAction SilentlyContinue | Measure-Object).Count
                    } catch {
                        $memberCount = 0
                    }
                    
                    $allGroups += @{
                        Name = $group.Name
                        SamAccountName = $group.SamAccountName
                        Description = $group.Description
                        GroupCategory = $group.GroupCategory
                        GroupScope = $group.GroupScope
                        MemberCount = $memberCount
                        ManagedBy = if ($group.ManagedBy) { try { (Get-ADUser $group.ManagedBy -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName } catch { "" } } else { "" }
                        Created = if ($group.Created) { $group.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Modified = if ($group.Modified) { $group.Modified.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Domain = $DomainId
                        FQDN = $DomainFQDN
                    }
                }
            } else {
                # LIMITED SCAN - First 1000 groups only
                $groupQuery = Get-ADGroup -Filter * -Server $DomainFQDN -Properties Description, GroupCategory, GroupScope, MemberOf, ManagedBy, Created, Modified -ResultSetSize 1000
                
                foreach ($group in $groupQuery) {
                    # Get member count (this can be slow for large groups)
                    $memberCount = 0
                    try {
                        $memberCount = (Get-ADGroupMember $group.SamAccountName -Server $DomainFQDN -ErrorAction SilentlyContinue | Measure-Object).Count
                    } catch {
                        $memberCount = 0
                    }
                    
                    $allGroups += @{
                        Name = $group.Name
                        SamAccountName = $group.SamAccountName
                        Description = $group.Description
                        GroupCategory = $group.GroupCategory
                        GroupScope = $group.GroupScope
                        MemberCount = $memberCount
                        ManagedBy = if ($group.ManagedBy) { try { (Get-ADUser $group.ManagedBy -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName } catch { "" } } else { "" }
                        Created = if ($group.Created) { $group.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Modified = if ($group.Modified) { $group.Modified.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        Domain = $DomainId
                        FQDN = $DomainFQDN
                    }
                }
            }
            
            return $allGroups
        }
        
        Write-EnhancedLog "✅ Collected $($groups.Count) groups $(if ($UnlimitedScan) { '(COMPLETE SCAN)' } else { '(LIMITED SCAN)' })" "Success" "Green"
        return $groups
        
    } catch {
        Write-EnhancedLog "❌ Failed to collect group info for $DomainFQDN`: $($_.Exception.Message)" "Error" "Red"
        return @()
    }
}

# Domain controller collection (unchanged - already unlimited)
function Get-EnhancedDomainControllerInfo {
    param(
        [string]$DomainFQDN,
        [string]$DomainId
    )
    
    try {
        Write-EnhancedLog "🖥️ Collecting domain controller information for $DomainFQDN..." "Info" "Cyan"
        
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
        
        Write-EnhancedLog "✅ Collected $($domainControllers.Count) domain controllers" "Success" "Green"
        return $domainControllers
        
    } catch {
        Write-EnhancedLog "❌ Failed to collect domain controller info for $DomainFQDN`: $($_.Exception.Message)" "Error" "Red"
        return @()
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
    }
    
    try {
        Write-EnhancedLog "🔍 Testing connectivity to domain: $($DomainConfig.name)" "Info" "Cyan"
        
        # Test DNS resolution
        try {
            $dnsResult = Resolve-DnsName $DomainConfig.fqdn -ErrorAction Stop
            $testResults.dnsResolution = $true
            Write-EnhancedLog "✅ DNS resolution successful" "Success" "Green"
        } catch {
            $testResults.errors += "DNS resolution failed: $($_.Exception.Message)"
            Write-EnhancedLog "❌ DNS resolution failed" "Error" "Red"
        }
        
        # Test AD connectivity
        try {
            $domain = Get-ADDomain -Server $DomainConfig.fqdn -ErrorAction Stop
            $testResults.adConnectivity = $true
            Write-EnhancedLog "✅ AD connectivity successful" "Success" "Green"
        } catch {
            $testResults.errors += "AD connectivity failed: $($_.Exception.Message)"
            Write-EnhancedLog "❌ AD connectivity failed" "Error" "Red"
        }
        
        # Test domain controller reachability
        try {
            $dcs = Get-ADDomainController -Filter * -Server $DomainConfig.fqdn -ErrorAction Stop
            $testResults.dcReachability = $true
            Write-EnhancedLog "✅ Domain controller reachability successful ($($dcs.Count) DCs found)" "Success" "Green"
        } catch {
            $testResults.errors += "DC reachability failed: $($_.Exception.Message)"
            Write-EnhancedLog "❌ Domain controller reachability failed" "Error" "Red"
        }
        
        $testResults.overallStatus = $testResults.dnsResolution -and $testResults.adConnectivity -and $testResults.dcReachability
        
        if ($testResults.overallStatus) {
            Write-EnhancedLog "✅ Overall connectivity test: PASSED" "Success" "Green"
        } else {
            Write-EnhancedLog "❌ Overall connectivity test: FAILED" "Error" "Red"
        }
        
        return $testResults
        
    } catch {
        $testResults.errors += "Connectivity test failed: $($_.Exception.Message)"
        Write-EnhancedLog "❌ Connectivity test failed: $($_.Exception.Message)" "Error" "Red"
        return $testResults
    }
}

# Main domain data collection function with unlimited scanning
function Collect-UnlimitedDomainData {
    param(
        [object]$DomainConfig,
        [bool]$UnlimitedScan = $true,
        [int]$BatchSize = 1000
    )
    
    $domainStartTime = Get-Date
    Write-EnhancedLog "`n🏢 Starting $(if ($UnlimitedScan) { 'UNLIMITED' } else { 'LIMITED' }) data collection for domain: $($DomainConfig.name)" "Info" "Yellow"
    Write-EnhancedLog "📍 FQDN: $($DomainConfig.fqdn)" "Info" "Gray"
    Write-EnhancedLog "🎯 Priority: $($DomainConfig.priority)" "Info" "Gray"
    
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
        collectionInfo = @{
            startTime = $domainStartTime.ToString("yyyy-MM-dd HH:mm:ss")
            scanType = if ($UnlimitedScan) { "UNLIMITED" } else { "LIMITED" }
            batchSize = $BatchSize
        }
        status = "InProgress"
        errors = @()
    }
    
    try {
        # Test connectivity first
        Write-EnhancedLog "🔍 Testing domain connectivity..." "Info" "Cyan"
        $domainData.connectivity = Test-DomainConnectivity -DomainConfig $DomainConfig
        
        if (-not $domainData.connectivity.overallStatus) {
            Write-EnhancedLog "❌ Domain connectivity failed. Skipping data collection." "Error" "Red"
            $domainData.status = "Failed"
            $domainData.errors += "Connectivity test failed"
            return $domainData
        }
        
        # Collect domain controllers
        Write-EnhancedLog "🖥️ Collecting domain controllers..." "Info" "Cyan"
        $domainData.domainControllers = Get-EnhancedDomainControllerInfo -DomainFQDN $DomainConfig.fqdn -DomainId $DomainConfig.id
        
        # Collect users with unlimited scanning
        Write-EnhancedLog "👥 Collecting users..." "Info" "Cyan"
        $domainData.users = Get-UnlimitedUserInfo -DomainFQDN $DomainConfig.fqdn -DomainId $DomainConfig.id -UnlimitedScan $UnlimitedScan -BatchSize $BatchSize
        
        # Collect computers with unlimited scanning
        Write-EnhancedLog "💻 Collecting computers..." "Info" "Cyan"
        $domainData.computers = Get-UnlimitedComputerInfo -DomainFQDN $DomainConfig.fqdn -DomainId $DomainConfig.id -UnlimitedScan $UnlimitedScan -BatchSize $BatchSize
        
        # Collect groups with unlimited scanning
        Write-EnhancedLog "🛡️ Collecting groups..." "Info" "Cyan"
        $domainData.groups = Get-UnlimitedGroupInfo -DomainFQDN $DomainConfig.fqdn -DomainId $DomainConfig.id -UnlimitedScan $UnlimitedScan -BatchSize $BatchSize
        
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
            totalGroups = $domainData.groups.Count
            securityGroups = $securityGroups
            distributionGroups = $distributionGroups
            domainControllers = $domainData.domainControllers.Count
            scanType = if ($UnlimitedScan) { "COMPLETE" } else { "LIMITED" }
        }
        
        $domainEndTime = Get-Date
        $domainData.collectionInfo.endTime = $domainEndTime.ToString("yyyy-MM-dd HH:mm:ss")
        $domainData.collectionInfo.durationMinutes = [math]::Round(($domainEndTime - $domainStartTime).TotalMinutes, 2)
        $domainData.status = "Completed"
        
        Write-EnhancedLog "✅ Domain collection completed successfully!" "Success" "Green"
        Write-EnhancedLog "📊 Summary: $($domainData.summary.totalUsers) users, $($domainData.summary.totalComputers) computers, $($domainData.summary.totalGroups) groups, $($domainData.summary.domainControllers) DCs" "Info" "Cyan"
        Write-EnhancedLog "⏱️  Duration: $($domainData.collectionInfo.durationMinutes) minutes" "Info" "Gray"
        
        return $domainData
        
    } catch {
        $domainData.status = "Failed"
        $domainData.errors += $_.Exception.Message
        Write-EnhancedLog "❌ Domain collection failed: $($_.Exception.Message)" "Error" "Red"
        return $domainData
    }
}

# Load configuration
try {
    if (-not (Test-Path $ConfigFile)) {
        Write-EnhancedLog "❌ Configuration file not found: $ConfigFile" "Error" "Red"
        exit 1
    }
    
    $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    Write-EnhancedLog "✅ Configuration loaded successfully" "Success" "Green"
} catch {
    Write-EnhancedLog "❌ Failed to load configuration: $($_.Exception.Message)" "Error" "Red"
    exit 1
}

# Initialize environment
Import-RequiredModules
if (-not (Initialize-OutputDirectory -Path $OutputPath)) {
    exit 1
}

# Determine domains to process
$domainsToProcess = @()
if ($SpecificDomain) {
    $domain = $config.domains.PSObject.Properties | Where-Object { $_.Name -eq $SpecificDomain -or $_.Value.name -eq $SpecificDomain } | Select-Object -First 1
    if ($domain) {
        $domainsToProcess += $domain.Value
        Write-EnhancedLog "🎯 Processing specific domain: $($domain.Value.name)" "Info" "Yellow"
    } else {
        Write-EnhancedLog "❌ Specified domain not found: $SpecificDomain" "Error" "Red"
        exit 1
    }
} else {
    $domainsToProcess = $config.domains.PSObject.Properties | Where-Object { $_.Value.enabled -eq $true } | ForEach-Object { $_.Value }
    Write-EnhancedLog "🌐 Processing all enabled domains: $($domainsToProcess.Count) domains" "Info" "Yellow"
}

# Main collection process
$scriptStartTime = Get-Date
$allDomainData = @{}
$successfulCollections = 0
$failedCollections = 0

Write-EnhancedLog "🚀 Starting Enhanced Multi-Domain Data Collection" "Info" "Cyan"
Write-EnhancedLog "📊 Scan Mode: $(if ($UnlimitedScan) { 'UNLIMITED (Complete enumeration)' } else { 'LIMITED (Fast scan)' })" "Info" "Yellow"
Write-EnhancedLog "=" * 80 "Info" "DarkGray"

foreach ($domain in $domainsToProcess) {
    try {
        $domainResult = Collect-UnlimitedDomainData -DomainConfig $domain -UnlimitedScan $UnlimitedScan -BatchSize $BatchSize
        $allDomainData[$domain.id] = $domainResult
        
        if ($domainResult.status -eq "Completed") {
            $successfulCollections++
            
            # Save individual domain file
            $domainFile = Join-Path $OutputPath "individual\$($domain.id)-data.json"
            $domainResult | ConvertTo-Json -Depth 10 | Set-Content $domainFile -Encoding UTF8
            Write-EnhancedLog "💾 Saved domain data: $domainFile" "Success" "Green"
        } else {
            $failedCollections++
            Write-EnhancedLog "❌ Domain collection failed: $($domain.name)" "Error" "Red"
        }
        
    } catch {
        $failedCollections++
        Write-EnhancedLog "❌ Critical error processing domain $($domain.name): $($_.Exception.Message)" "Error" "Red"
    }
}

# Generate consolidated data
$scriptEndTime = Get-Date
$totalDuration = [math]::Round(($scriptEndTime - $scriptStartTime).TotalMinutes, 2)

# Calculate aggregated summary
$aggregatedSummary = @{
    totalDomains = $domainsToProcess.Count
    successfulCollections = $successfulCollections
    failedCollections = $failedCollections
    totalUsers = ($allDomainData.Values | ForEach-Object { $_.summary.totalUsers } | Measure-Object -Sum).Sum
    activeUsers = ($allDomainData.Values | ForEach-Object { $_.summary.activeUsers } | Measure-Object -Sum).Sum
    disabledUsers = ($allDomainData.Values | ForEach-Object { $_.summary.disabledUsers } | Measure-Object -Sum).Sum
    lockedUsers = ($allDomainData.Values | ForEach-Object { $_.summary.lockedUsers } | Measure-Object -Sum).Sum
    totalComputers = ($allDomainData.Values | ForEach-Object { $_.summary.totalComputers } | Measure-Object -Sum).Sum
    activeComputers = ($allDomainData.Values | ForEach-Object { $_.summary.activeComputers } | Measure-Object -Sum).Sum
    totalGroups = ($allDomainData.Values | ForEach-Object { $_.summary.totalGroups } | Measure-Object -Sum).Sum
    securityGroups = ($allDomainData.Values | ForEach-Object { $_.summary.securityGroups } | Measure-Object -Sum).Sum
    distributionGroups = ($allDomainData.Values | ForEach-Object { $_.summary.distributionGroups } | Measure-Object -Sum).Sum
    domainControllers = ($allDomainData.Values | ForEach-Object { $_.summary.domainControllers } | Measure-Object -Sum).Sum
    scanType = if ($UnlimitedScan) { "COMPLETE" } else { "LIMITED" }
}

$consolidatedData = @{
    metadata = @{
        version = "3.2"
        generatedAt = $scriptEndTime.ToString("yyyy-MM-dd HH:mm:ss")
        generatedBy = $env:USERNAME
        computerName = $env:COMPUTERNAME
        totalDurationMinutes = $totalDuration
        scanType = if ($UnlimitedScan) { "UNLIMITED" } else { "LIMITED" }
        batchSize = $BatchSize
    }
    aggregatedSummary = $aggregatedSummary
    domains = $allDomainData
}

# Save consolidated data
$consolidatedFile = Join-Path $OutputPath "consolidated\consolidated-data.json"
$consolidatedData | ConvertTo-Json -Depth 15 | Set-Content $consolidatedFile -Encoding UTF8
Write-EnhancedLog "💾 Saved consolidated data: $consolidatedFile" "Success" "Green"

# Generate dashboard data file
$dashboardDataFile = Join-Path $OutputPath "enhanced-dashboard-data.js"
$jsContent = "// Enhanced Multi-Domain AD Dashboard Data v3.2`n"
$jsContent += "// Generated: $($scriptEndTime.ToString('yyyy-MM-dd HH:mm:ss'))`n"
$jsContent += "// Scan Type: $(if ($UnlimitedScan) { 'UNLIMITED (Complete)' } else { 'LIMITED (Fast)' })`n"
$jsContent += "`nwindow.embeddedConsolidatedData = "
$jsContent += ($consolidatedData | ConvertTo-Json -Depth 15 -Compress)
$jsContent += ";"

$jsContent | Set-Content $dashboardDataFile -Encoding UTF8
Write-EnhancedLog "💾 Saved dashboard data: $dashboardDataFile" "Success" "Green"

# Final summary
Write-EnhancedLog "`n" + "=" * 80 "Info" "DarkGray"
Write-EnhancedLog "🎉 Enhanced Multi-Domain Data Collection Complete!" "Success" "Green"
Write-EnhancedLog "📊 Scan Type: $(if ($UnlimitedScan) { 'UNLIMITED (Complete enumeration)' } else { 'LIMITED (Fast scan)' })" "Info" "Yellow"
Write-EnhancedLog "📈 Results Summary:" "Info" "Cyan"
Write-EnhancedLog "   • Total Domains: $($aggregatedSummary.totalDomains)" "Info" "White"
Write-EnhancedLog "   • Successful Collections: $($aggregatedSummary.successfulCollections)" "Success" "Green"
Write-EnhancedLog "   • Failed Collections: $($aggregatedSummary.failedCollections)" "$(if ($aggregatedSummary.failedCollections -gt 0) { 'Warning' } else { 'Info' })" "$(if ($aggregatedSummary.failedCollections -gt 0) { 'Yellow' } else { 'White' })"
Write-EnhancedLog "   • Total Users: $($aggregatedSummary.totalUsers.ToString('N0'))" "Info" "White"
Write-EnhancedLog "   • Total Computers: $($aggregatedSummary.totalComputers.ToString('N0'))" "Info" "White"
Write-EnhancedLog "   • Total Groups: $($aggregatedSummary.totalGroups.ToString('N0'))" "Info" "White"
Write-EnhancedLog "   • Domain Controllers: $($aggregatedSummary.domainControllers)" "Info" "White"
Write-EnhancedLog "⏱️  Total Duration: $totalDuration minutes" "Info" "Gray"
Write-EnhancedLog "💾 Output Location: $OutputPath" "Info" "Gray"

if ($UnlimitedScan) {
    Write-EnhancedLog "`n✅ UNLIMITED SCAN COMPLETE - These are the TRUE numbers from your AD domains!" "Success" "Green"
    Write-EnhancedLog "📊 All objects have been enumerated without artificial limits." "Info" "Cyan"
} else {
    Write-EnhancedLog "`n⚠️  LIMITED SCAN COMPLETE - Numbers may be truncated for large domains." "Warning" "Yellow"
    Write-EnhancedLog "💡 Use -UnlimitedScan for complete enumeration." "Info" "Cyan"
}

Write-EnhancedLog "🎯 Dashboard ready at: $((Join-Path $OutputPath '..\dashboard\index.html'))" "Info" "Cyan"
Write-EnhancedLog "=" * 80 "Info" "DarkGray"

