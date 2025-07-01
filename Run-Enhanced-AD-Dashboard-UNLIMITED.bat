@echo off
setlocal EnableDelayedExpansion

REM Enhanced Multi-Domain Active Directory Dashboard Collection System
REM Version 3.2 - UNLIMITED SCANNING EDITION
REM Removes all artificial limits for true AD object counts

title Enhanced Multi-Domain AD Dashboard - UNLIMITED SCANNING v3.2

echo ========================================================================
echo   Enhanced Multi-Domain Active Directory Dashboard Collection System
echo   Version 3.2 - UNLIMITED SCANNING EDITION
echo   TRUE OBJECT COUNTS - NO ARTIFICIAL LIMITS
echo ========================================================================
echo.

REM Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo 📁 Working Directory: %SCRIPT_DIR%
echo 📊 Data Directory: %SCRIPT_DIR%data
echo 🌐 Dashboard Directory: %SCRIPT_DIR%dashboard
echo.

REM Set PowerShell script paths
set "PS_SCRIPT=%SCRIPT_DIR%Enhanced-Multi-Domain-AD-Collector.ps1"
set "PS_SCRIPT_UNLIMITED=%SCRIPT_DIR%Enhanced-Multi-Domain-AD-Collector-UNLIMITED.ps1"
set "EMBEDDER_SCRIPT=%SCRIPT_DIR%Dashboard-Data-Embedder.ps1"
set "CONFIG_FILE=%SCRIPT_DIR%domain-config.json"

REM Check if unlimited script exists, otherwise use regular script
if exist "%PS_SCRIPT_UNLIMITED%" (
    set "ACTIVE_SCRIPT=%PS_SCRIPT_UNLIMITED%"
    echo ✅ Using UNLIMITED scanning script
) else (
    set "ACTIVE_SCRIPT=%PS_SCRIPT%"
    echo ⚠️  Using regular script ^(limited scanning^)
)

echo.
echo ========================================================================
echo   SCANNING OPTIONS
echo ========================================================================
echo   1. UNLIMITED SCAN ^(Complete enumeration - TRUE numbers^)
echo      • Scans ALL users, computers, and groups
echo      • No artificial limits
echo      • May take longer for large domains
echo      • Provides accurate, complete counts
echo.
echo   2. FAST SCAN ^(Limited enumeration - Quick results^)
echo      • Scans first 2000 users, 2000 computers, 1000 groups
echo      • Faster execution
echo      • May not show complete numbers for large domains
echo.
echo ========================================================================

:MAIN_MENU
echo.
echo 🎯 MAIN MENU - Choose an option:
echo.
echo   1. Configure Domains
echo   2. Test Domain Connectivity  
echo   3. Collect Data from All Domains ^(UNLIMITED SCAN^)
echo   4. Collect Data from All Domains ^(FAST SCAN^)
echo   5. Collect Data from Specific Domain
echo   6. Update Dashboard with Latest Data
echo   7. Open Dashboard in Browser
echo   8. View Collection Logs
echo   9. Exit
echo.
set /p "choice=Enter your choice (1-9): "

if "%choice%"=="1" goto CONFIGURE_DOMAINS
if "%choice%"=="2" goto TEST_CONNECTIVITY
if "%choice%"=="3" goto COLLECT_ALL_UNLIMITED
if "%choice%"=="4" goto COLLECT_ALL_FAST
if "%choice%"=="5" goto COLLECT_SPECIFIC
if "%choice%"=="6" goto UPDATE_DASHBOARD
if "%choice%"=="7" goto OPEN_DASHBOARD
if "%choice%"=="8" goto VIEW_LOGS
if "%choice%"=="9" goto EXIT

echo ❌ Invalid choice. Please try again.
goto MAIN_MENU

:CONFIGURE_DOMAINS
echo.
echo 📝 Creating default domain configuration...
powershell.exe -ExecutionPolicy Bypass -Command "& '%ACTIVE_SCRIPT%' -ConfigFile '%CONFIG_FILE%' -OutputPath 'data' -Verbose"
echo.
pause
goto MAIN_MENU

:TEST_CONNECTIVITY
echo.
echo 🔍 Testing connectivity to all enabled domains...
powershell.exe -ExecutionPolicy Bypass -Command "& '%ACTIVE_SCRIPT%' -ConfigFile '%CONFIG_FILE%' -OutputPath 'data' -TestConnectivity -Verbose"
echo.
pause
goto MAIN_MENU

:COLLECT_ALL_UNLIMITED
echo.
echo ========================================================================
echo   UNLIMITED SCAN - COMPLETE ENUMERATION
echo ========================================================================
echo   ⚠️  WARNING: This will scan ALL objects in ALL domains
echo   📊 This provides TRUE, COMPLETE object counts
echo   ⏱️  This may take 10-30 minutes for large domains
echo   💾 Results will show accurate numbers without limits
echo.
set /p "confirm=Are you sure you want to proceed? (Y/N): "
if /i not "%confirm%"=="Y" goto MAIN_MENU

echo.
echo 🚀 Starting UNLIMITED data collection from all enabled domains...
echo 📊 This will provide TRUE object counts from your AD domains
powershell.exe -ExecutionPolicy Bypass -Command "& '%ACTIVE_SCRIPT%' -ConfigFile '%CONFIG_FILE%' -OutputPath 'data' -UnlimitedScan -Verbose"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Data collection completed successfully!
    echo 🔄 Updating dashboard with collected data...
    powershell.exe -ExecutionPolicy Bypass -Command "& '%EMBEDDER_SCRIPT%' -DataPath 'data' -DashboardPath 'dashboard' -Verbose"
    
    if !ERRORLEVEL! EQU 0 (
        echo ✅ Dashboard updated successfully!
        echo 🌐 Dashboard ready at: %SCRIPT_DIR%dashboard\index.html
    ) else (
        echo ❌ Dashboard update failed. Check the logs for details.
    )
) else (
    echo ❌ Data collection failed. Check the logs for details.
)
echo.
pause
goto MAIN_MENU

:COLLECT_ALL_FAST
echo.
echo ========================================================================
echo   FAST SCAN - LIMITED ENUMERATION
echo ========================================================================
echo   ⚡ This will scan with limits for faster results
echo   📊 Users: First 2000, Computers: First 2000, Groups: First 1000
echo   ⏱️  Faster execution (2-5 minutes typically)
echo   ⚠️  May not show complete numbers for large domains
echo.
set /p "confirm=Proceed with FAST scan? (Y/N): "
if /i not "%confirm%"=="Y" goto MAIN_MENU

echo.
echo 🚀 Starting FAST data collection from all enabled domains...
powershell.exe -ExecutionPolicy Bypass -Command "& '%ACTIVE_SCRIPT%' -ConfigFile '%CONFIG_FILE%' -OutputPath 'data' -FastScan -Verbose"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Data collection completed successfully!
    echo 🔄 Updating dashboard with collected data...
    powershell.exe -ExecutionPolicy Bypass -Command "& '%EMBEDDER_SCRIPT%' -DataPath 'data' -DashboardPath 'dashboard' -Verbose"
    
    if !ERRORLEVEL! EQU 0 (
        echo ✅ Dashboard updated successfully!
        echo 🌐 Dashboard ready at: %SCRIPT_DIR%dashboard\index.html
    ) else (
        echo ❌ Dashboard update failed. Check the logs for details.
    )
) else (
    echo ❌ Data collection failed. Check the logs for details.
)
echo.
pause
goto MAIN_MENU

:COLLECT_SPECIFIC
echo.
echo 🎯 Available domains for data collection:
echo.
echo   1. europa     ^(EUROPA^)
echo   2. fm         ^(FM^)  
echo   3. rbsgretail ^(RBSGRETAIL^)
echo   4. rbsgrp     ^(RBSGRP^)
echo   5. rbsres01   ^(RBSRES01^)
echo   6. dsdom02    ^(DSDOM02^)
echo.
set /p "domain_choice=Enter domain number (1-6) or domain ID: "

REM Map numbers to domain IDs
if "%domain_choice%"=="1" set "domain_id=europa"
if "%domain_choice%"=="2" set "domain_id=fm"
if "%domain_choice%"=="3" set "domain_id=rbsgretail"
if "%domain_choice%"=="4" set "domain_id=rbsgrp"
if "%domain_choice%"=="5" set "domain_id=rbsres01"
if "%domain_choice%"=="6" set "domain_id=dsdom02"

REM If not a number, use as domain ID directly
if not defined domain_id set "domain_id=%domain_choice%"

echo.
echo 📊 Choose scan type for domain: %domain_id%
echo   1. UNLIMITED SCAN ^(Complete enumeration^)
echo   2. FAST SCAN ^(Limited enumeration^)
echo.
set /p "scan_choice=Enter scan type (1-2): "

if "%scan_choice%"=="1" (
    echo 🚀 Starting UNLIMITED data collection for domain: %domain_id%
    powershell.exe -ExecutionPolicy Bypass -Command "& '%ACTIVE_SCRIPT%' -ConfigFile '%CONFIG_FILE%' -OutputPath 'data' -SpecificDomain '%domain_id%' -UnlimitedScan -Verbose"
) else (
    echo 🚀 Starting FAST data collection for domain: %domain_id%
    powershell.exe -ExecutionPolicy Bypass -Command "& '%ACTIVE_SCRIPT%' -ConfigFile '%CONFIG_FILE%' -OutputPath 'data' -SpecificDomain '%domain_id%' -FastScan -Verbose"
)

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Data collection completed successfully!
    echo 🔄 Updating dashboard with collected data...
    powershell.exe -ExecutionPolicy Bypass -Command "& '%EMBEDDER_SCRIPT%' -DataPath 'data' -DashboardPath 'dashboard' -Verbose"
    
    if !ERRORLEVEL! EQU 0 (
        echo ✅ Dashboard updated successfully!
        echo 🌐 Dashboard ready at: %SCRIPT_DIR%dashboard\index.html
    ) else (
        echo ❌ Dashboard update failed. Check the logs for details.
    )
) else (
    echo ❌ Data collection failed. Check the logs for details.
)
echo.
pause
goto MAIN_MENU

:UPDATE_DASHBOARD
echo.
echo 🔄 Updating dashboard with latest collected data...
powershell.exe -ExecutionPolicy Bypass -Command "& '%EMBEDDER_SCRIPT%' -DataPath 'data' -DashboardPath 'dashboard' -Verbose"

if %ERRORLEVEL% EQU 0 (
    echo ✅ Dashboard updated successfully!
    echo 🌐 Dashboard ready at: %SCRIPT_DIR%dashboard\index.html
) else (
    echo ❌ Dashboard update failed. Check the logs for details.
)
echo.
pause
goto MAIN_MENU

:OPEN_DASHBOARD
echo.
echo 🌐 Opening dashboard in default browser...
start "" "%SCRIPT_DIR%dashboard\index.html"
echo.
pause
goto MAIN_MENU

:VIEW_LOGS
echo.
echo 📋 Recent collection logs:
echo.
if exist "%SCRIPT_DIR%data\logs\" (
    dir "%SCRIPT_DIR%data\logs\*.log" /b /o-d 2>nul
    echo.
    echo 💡 Log files are located in: %SCRIPT_DIR%data\logs\
) else (
    echo ❌ No log directory found. Run a collection first.
)
echo.
pause
goto MAIN_MENU

:EXIT
echo.
echo 👋 Thank you for using Enhanced Multi-Domain AD Dashboard!
echo 📊 Remember: Use UNLIMITED SCAN for TRUE object counts
echo.
pause
exit /b 0

