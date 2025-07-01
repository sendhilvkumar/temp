@echo off
setlocal EnableDelayedExpansion

title Multi-Domain Active Directory Dashboard - Enhanced Collection System (FIXED)

echo.
echo ========================================================================
echo   Enhanced Multi-Domain Active Directory Dashboard Collection System
echo   Version 3.1 - Enterprise Edition (Path Fixed)
echo ========================================================================
echo.

REM Get script directory and set up paths
set "SCRIPT_DIR=%~dp0"
set "DATA_DIR=%SCRIPT_DIR%data"
set "DASHBOARD_DIR=%SCRIPT_DIR%dashboard"
set "LOGS_DIR=%DATA_DIR%\logs"
set "CONFIG_FILE=%SCRIPT_DIR%domain-config.json"
set "PS_SCRIPT=%SCRIPT_DIR%Enhanced-Multi-Domain-AD-Collector.ps1"

REM Create directories if they don't exist
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%DASHBOARD_DIR%" mkdir "%DASHBOARD_DIR%"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"

echo 📁 Working Directory: %SCRIPT_DIR%
echo 📊 Data Directory: %DATA_DIR%
echo 🌐 Dashboard Directory: %DASHBOARD_DIR%
echo.

REM Check if PowerShell script exists
if not exist "%PS_SCRIPT%" (
    echo ❌ ERROR: PowerShell script not found at %PS_SCRIPT%
    echo Please ensure all files are properly extracted.
    echo.
    echo Expected file location: %PS_SCRIPT%
    echo Current directory contents:
    dir "%SCRIPT_DIR%*.ps1" /b 2>nul || echo No PowerShell files found
    echo.
    pause
    exit /b 1
)

REM Display main menu
:MAIN_MENU
cls
echo.
echo ========================================================================
echo   Enhanced Multi-Domain AD Dashboard - Main Menu
echo ========================================================================
echo.
echo 1. 🔧 Configure Domains (First Time Setup)
echo 2. 🔍 Test Domain Connectivity
echo 3. 📊 Collect Data from All Domains
echo 4. 🎯 Collect Data from Specific Domain
echo 5. 🌐 Open Dashboard
echo 6. 📁 View Data Files
echo 7. 📝 View Logs
echo 8. ❓ Help and Documentation
echo 9. 🚪 Exit
echo.
set /p choice="Please select an option (1-9): "

if "%choice%"=="1" goto CONFIGURE_DOMAINS
if "%choice%"=="2" goto TEST_CONNECTIVITY
if "%choice%"=="3" goto COLLECT_ALL
if "%choice%"=="4" goto COLLECT_SPECIFIC
if "%choice%"=="5" goto OPEN_DASHBOARD
if "%choice%"=="6" goto VIEW_DATA
if "%choice%"=="7" goto VIEW_LOGS
if "%choice%"=="8" goto SHOW_HELP
if "%choice%"=="9" goto EXIT
goto MAIN_MENU

:CONFIGURE_DOMAINS
cls
echo.
echo ========================================================================
echo   Domain Configuration Setup
echo ========================================================================
echo.

if exist "%CONFIG_FILE%" (
    echo ⚠️  Configuration file already exists.
    echo Current configuration:
    echo.
    powershell.exe -Command "& {try { $config = Get-Content '%CONFIG_FILE%' -Raw | ConvertFrom-Json; $config.domains | ForEach-Object { Write-Host '   •' $_.name '(' $_.fqdn ')' -ForegroundColor Cyan } } catch { Write-Host 'Error reading configuration file' -ForegroundColor Red }}"
    echo.
    set /p overwrite="Do you want to recreate the configuration? (y/N): "
    if /i not "%overwrite%"=="y" goto MAIN_MENU
)

echo 📝 Creating default domain configuration...
echo This will create a template with 6 sample domains that you can customize.
echo.

powershell.exe -ExecutionPolicy Bypass -Command "& '%PS_SCRIPT%' -ConfigFile '%CONFIG_FILE%' -OutputPath '%DATA_DIR%' -Verbose"

if exist "%CONFIG_FILE%" (
    echo.
    echo ✅ Configuration file created successfully!
    echo 📝 Opening configuration file for editing...
    echo.
    echo IMPORTANT: Please update the following in the configuration file:
    echo   • Domain FQDNs to match your actual domains
    echo   • Domain names and descriptions
    echo   • Contact information and locations
    echo   • Enable/disable domains as needed
    echo   • Adjust collection limits if necessary
    echo.
    pause
    
    notepad.exe "%CONFIG_FILE%"
    
    echo.
    echo Configuration file updated. Press any key to return to main menu...
    pause >nul
) else (
    echo ❌ Failed to create configuration file.
    echo Please check PowerShell execution policy and permissions.
    pause
)
goto MAIN_MENU

:TEST_CONNECTIVITY
cls
echo.
echo ========================================================================
echo   Domain Connectivity Testing
echo ========================================================================
echo.

if not exist "%CONFIG_FILE%" (
    echo ❌ Configuration file not found. Please configure domains first.
    pause
    goto MAIN_MENU
)

echo 🔍 Testing connectivity to all configured domains...
echo This may take a few minutes depending on network conditions.
echo.

powershell.exe -ExecutionPolicy Bypass -Command "& '%PS_SCRIPT%' -ConfigFile '%CONFIG_FILE%' -OutputPath '%DATA_DIR%' -TestConnectivity -Verbose"

echo.
echo Connectivity testing completed. Press any key to return to main menu...
pause >nul
goto MAIN_MENU

:COLLECT_ALL
cls
echo.
echo ========================================================================
echo   Collect Data from All Domains
echo ========================================================================
echo.

if not exist "%CONFIG_FILE%" (
    echo ❌ Configuration file not found. Please configure domains first.
    pause
    goto MAIN_MENU
)

echo 📊 Starting data collection from all enabled domains...
echo This process may take 10-30 minutes depending on domain sizes.
echo.
echo Progress will be displayed below:
echo.

powershell.exe -ExecutionPolicy Bypass -Command "& '%PS_SCRIPT%' -ConfigFile '%CONFIG_FILE%' -OutputPath '%DATA_DIR%' -CollectAll -GenerateConsolidated -Verbose"

if exist "%DATA_DIR%\consolidated\consolidated-data.json" (
    echo.
    echo ✅ Data collection completed successfully!
    echo 🔄 Updating dashboard with new data...
    
    REM Update dashboard with collected data
    if exist "%SCRIPT_DIR%Dashboard-Data-Embedder.ps1" (
        powershell.exe -ExecutionPolicy Bypass -Command "& '%SCRIPT_DIR%Dashboard-Data-Embedder.ps1' -DataPath '%DATA_DIR%' -DashboardPath '%DASHBOARD_DIR%'"
        echo ✅ Dashboard updated with latest data!
    ) else (
        echo ⚠️ Dashboard embedder script not found. Data collected but dashboard not updated.
    )
    
    echo.
    set /p open_dashboard="Would you like to open the dashboard now? (Y/n): "
    if /i not "%open_dashboard%"=="n" (
        start "" "%DASHBOARD_DIR%\index.html"
    )
) else (
    echo.
    echo ❌ Data collection failed or incomplete.
    echo Please check the output above for error details.
    echo.
    if exist "%DATA_DIR%\consolidated\collection-metadata.json" (
        echo Error summary:
        powershell.exe -Command "& {try { $metadata = Get-Content '%DATA_DIR%\consolidated\collection-metadata.json' -Raw | ConvertFrom-Json; Write-Host 'Successful:' $metadata.successfulCollections -ForegroundColor Green; Write-Host 'Failed:' $metadata.failedCollections -ForegroundColor Red } catch { Write-Host 'Could not read metadata' -ForegroundColor Yellow }}"
    )
)

echo.
echo Press any key to return to main menu...
pause >nul
goto MAIN_MENU

:COLLECT_SPECIFIC
cls
echo.
echo ========================================================================
echo   Collect Data from Specific Domain
echo ========================================================================
echo.

if not exist "%CONFIG_FILE%" (
    echo ❌ Configuration file not found. Please configure domains first.
    pause
    goto MAIN_MENU
)

echo Available domains:
powershell.exe -Command "& {try { $config = Get-Content '%CONFIG_FILE%' -Raw | ConvertFrom-Json; $i = 1; $config.domains | ForEach-Object { Write-Host '   ' $i'.' $_.id '-' $_.name '(' $_.fqdn ')' -ForegroundColor Cyan; $i++ } } catch { Write-Host 'Error reading configuration' -ForegroundColor Red }}"

echo.
set /p domain_id="Enter the domain ID to collect data from: "

if "%domain_id%"=="" (
    echo ❌ No domain ID specified.
    pause
    goto MAIN_MENU
)

echo.
echo 📊 Starting data collection for domain: %domain_id%
echo.

powershell.exe -ExecutionPolicy Bypass -Command "& '%PS_SCRIPT%' -ConfigFile '%CONFIG_FILE%' -OutputPath '%DATA_DIR%' -SpecificDomain '%domain_id%' -Verbose"

echo.
echo Data collection completed. Press any key to return to main menu...
pause >nul
goto MAIN_MENU

:OPEN_DASHBOARD
cls
echo.
echo ========================================================================
echo   Open Dashboard
echo ========================================================================
echo.

if not exist "%DASHBOARD_DIR%\index.html" (
    echo ❌ Dashboard not found. Please ensure the dashboard files are present.
    echo Expected location: %DASHBOARD_DIR%\index.html
    pause
    goto MAIN_MENU
)

if not exist "%DATA_DIR%\consolidated\consolidated-data.json" (
    echo ⚠️  No consolidated data found. The dashboard may not display current information.
    echo Would you like to collect data first?
    set /p collect_first="Collect data now? (Y/n): "
    if /i not "%collect_first%"=="n" goto COLLECT_ALL
)

echo 🌐 Opening Multi-Domain Active Directory Dashboard...
start "" "%DASHBOARD_DIR%\index.html"

echo.
echo Dashboard opened in your default web browser.
echo Press any key to return to main menu...
pause >nul
goto MAIN_MENU

:VIEW_DATA
cls
echo.
echo ========================================================================
echo   View Data Files
echo ========================================================================
echo.

if not exist "%DATA_DIR%" (
    echo ❌ Data directory not found.
    pause
    goto MAIN_MENU
)

echo 📁 Opening data directory: %DATA_DIR%
explorer.exe "%DATA_DIR%"

echo.
echo Data directory opened in Windows Explorer.
echo.
echo Available data files:
if exist "%DATA_DIR%\consolidated\consolidated-data.json" (
    echo   ✅ Consolidated data file
) else (
    echo   ❌ No consolidated data file found
)

if exist "%DATA_DIR%\individual\" (
    echo   📊 Individual domain data files:
    dir /b "%DATA_DIR%\individual\*.json" 2>nul | findstr /v "File Not Found" && echo      Found individual domain files || echo      No individual domain files found
)

echo.
echo Press any key to return to main menu...
pause >nul
goto MAIN_MENU

:VIEW_LOGS
cls
echo.
echo ========================================================================
echo   View Execution Logs
echo ========================================================================
echo.

if not exist "%LOGS_DIR%" (
    echo ❌ Logs directory not found.
    pause
    goto MAIN_MENU
)

echo 📝 Recent log files:
dir /b /o-d "%LOGS_DIR%\*.txt" 2>nul | findstr /v "File Not Found" && (
    echo.
    echo Select a log file to view:
    set /p log_choice="Enter the log filename (or press Enter to open logs folder): "
    if not "!log_choice!"=="" (
        if exist "%LOGS_DIR%\!log_choice!" (
            notepad.exe "%LOGS_DIR%\!log_choice!"
        ) else (
            echo ❌ Log file not found.
        )
    ) else (
        explorer.exe "%LOGS_DIR%"
    )
) || (
    echo No log files found.
    echo.
    echo 📁 Opening logs directory: %LOGS_DIR%
    explorer.exe "%LOGS_DIR%"
)

echo.
echo Press any key to return to main menu...
pause >nul
goto MAIN_MENU

:SHOW_HELP
cls
echo.
echo ========================================================================
echo   Help and Documentation
echo ========================================================================
echo.
echo 📖 Enhanced Multi-Domain AD Dashboard Help
echo.
echo OVERVIEW:
echo   This system collects Active Directory data from multiple domains and
echo   presents it in a comprehensive web-based dashboard.
echo.
echo SETUP PROCESS:
echo   1. Configure Domains - Set up your domain connections
echo   2. Test Connectivity - Verify domain access
echo   3. Collect Data - Gather AD information
echo   4. View Dashboard - Analyze the results
echo.
echo CONFIGURATION:
echo   • Edit domain-config.json to match your environment
echo   • Update FQDNs, credentials, and collection settings
echo   • Enable/disable domains as needed
echo   • Adjust collection limits for performance
echo.
echo DATA COLLECTION:
echo   • Supports up to 6 domains simultaneously
echo   • Collects users, computers, groups, and domain controllers
echo   • Includes detailed properties and statistics
echo   • Generates both individual and consolidated reports
echo.
echo DASHBOARD FEATURES:
echo   • Real-time data visualization
echo   • Multi-domain overview and detailed views
echo   • Responsive design for desktop and mobile
echo   • Export capabilities for reports
echo.
echo TROUBLESHOOTING:
echo   • Ensure RSAT tools are installed
echo   • Verify domain connectivity and credentials
echo   • Check PowerShell execution policy
echo   • Review log files for detailed error information
echo.
echo REQUIREMENTS:
echo   • Windows with PowerShell 5.0+
echo   • Active Directory PowerShell module (RSAT)
echo   • Domain user account with read permissions
echo   • Network connectivity to target domains
echo.
echo COMMON ISSUES:
echo   • PowerShell execution policy: Run as Administrator and execute:
echo     Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
echo   • Missing RSAT: Install from Windows Features or Microsoft Download Center
echo   • Path issues: Ensure all files are in the same directory
echo.
echo For additional support, check the documentation files or contact your
echo system administrator.
echo.
echo Press any key to return to main menu...
pause >nul
goto MAIN_MENU

:EXIT
cls
echo.
echo ========================================================================
echo   Thank you for using Enhanced Multi-Domain AD Dashboard!
echo ========================================================================
echo.
echo 🎯 Quick Tips:
echo   • Run data collection regularly to keep dashboard current
echo   • Monitor logs for any collection issues
echo   • Update domain configuration as your environment changes
echo   • Share the dashboard URL with stakeholders for reporting
echo.
echo 📧 For support or feedback, contact your IT administrator.
echo.
echo Goodbye!
timeout /t 3 /nobreak >nul
exit /b 0

REM Error handling
:ERROR
echo.
echo ❌ An error occurred during execution.
echo Please check the output above for details.
echo.
pause
goto MAIN_MENU

