@echo off
REM ==============================================================================
REM Schemathesis Pro - Universal API DAST Launcher (Windows)
REM ==============================================================================
setlocal EnableDelayedExpansion

cd /d "%~dp0"

set "PYTHON="

REM 1. Check active virtual environment
if defined VIRTUAL_ENV (
    if exist "%VIRTUAL_ENV%\Scripts\python.exe" (
        set "PYTHON=%VIRTUAL_ENV%\Scripts\python.exe"
    )
)

REM 2. Check local .venv
if not defined PYTHON (
    if exist ".venv\Scripts\python.exe" (
        set "PYTHON=%CD%\.venv\Scripts\python.exe"
    )
)

REM 3. Check Python 3.12 via py launcher
if not defined PYTHON (
    py -3.12 -c "import sys" >nul 2>&1
    if !errorlevel! equ 0 (
        for /f "delims=" %%i in ('py -3.12 -c "import sys; print(sys.executable)"') do (
            if not defined PYTHON set "PYTHON=%%i"
        )
    )
)

REM 4. Check python in PATH
if not defined PYTHON (
    where python >nul 2>&1
    if !errorlevel! equ 0 (
        for /f "delims=" %%i in ('where python') do (
            if not defined PYTHON set "PYTHON=%%i"
        )
    )
)

REM 5. Fallback to py launcher
if not defined PYTHON (
    where py >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON=py"
    )
)

if not defined PYTHON (
    echo [X] Error: Python 3 was not found in PATH, .venv, or py launcher.
    pause
    exit /b 1
)

REM ------------------------------------------------------------------------------
REM Argument Dispatcher (must jump to labels outside parentheses before shift)
REM ------------------------------------------------------------------------------
set "EXIT_CODE=0"
if /i "%~1"=="auto" goto :cmd_auto
if /i "%~1"=="profiles" goto :cmd_profiles
if /i "%~1"=="report" goto :cmd_report
if /i "%~1"=="dashboard" goto :cmd_dashboard
if /i "%~1"=="gate" goto :cmd_gate
if /i "%~1"=="scan" goto :cmd_scan
if not "%~1"=="" goto :cmd_forward
goto :menu

:cmd_auto
shift
if "%~1"=="" (
    echo [!] Please specify an OpenAPI schema, e.g.: fuzz.bat auto .\openapi.json --url http://127.0.0.1:8000
    exit /b 1
)
set "REST_ARGS="
:auto_loop
if "%~1"=="" goto :auto_run
set "REST_ARGS=%REST_ARGS% %1"
shift
goto :auto_loop
:auto_run
echo [*] Running Autonomous BOLA Workflow...
"%PYTHON%" -B run_all.py auto-workflow%REST_ARGS%
exit /b %errorlevel%

:cmd_profiles
echo [*] Running Saved Target Profiles...
"%PYTHON%" -B run_all.py profiles
exit /b %errorlevel%

:cmd_report
"%PYTHON%" -B -m cli --report
exit /b %errorlevel%

:cmd_dashboard
"%PYTHON%" -B -m cli --dashboard
exit /b %errorlevel%

:cmd_gate
shift
set "REST_ARGS="
:gate_loop
if "%~1"=="" goto :gate_run
set "REST_ARGS=%REST_ARGS% %1"
shift
goto :gate_loop
:gate_run
"%PYTHON%" -B run_all.py gate%REST_ARGS%
exit /b %errorlevel%

:cmd_scan
shift
if "%~1"=="" (
    echo [!] Please specify a target URL, e.g.: fuzz.bat scan http://localhost:8000
    exit /b 1
)
set "FIRST_ARG=%~1"
set "SCAN_PREFIX="
if "%FIRST_ARG:~0,2%"=="--" goto :scan_collect
set "SCAN_PREFIX= --url %1"
shift
:scan_collect
set "REST_ARGS="
:scan_loop
if "%~1"=="" goto :scan_run
set "REST_ARGS=%REST_ARGS% %1"
shift
goto :scan_loop
:scan_run
"%PYTHON%" -B run_all.py scan%SCAN_PREFIX%%REST_ARGS%
exit /b %errorlevel%

:cmd_forward
"%PYTHON%" -B run_all.py %*
exit /b %errorlevel%

REM ------------------------------------------------------------------------------
REM Interactive One-Click Menu (When launched with no arguments / double-clicked)
REM ------------------------------------------------------------------------------
:menu
cls
echo ==================================================================================
echo             SCHEMATHESIS PRO - AUTOMATED API DAST SCANNER
echo ==================================================================================
echo.
echo   [1] Quick Scan Custom API URL (Auto-Discovery)            [DEFAULT - Press Enter]
echo   [2] Auto-Synthesize BOLA Workflows (OpenAPI -^> Zero-YAML)
echo   [3] Run Saved Target Profiles
echo   [4] Open Interactive Terminal Dashboard (TUI)
echo   [5] Open Latest Interactive HTML Report in Browser
echo   [q] Exit
echo.
echo ==================================================================================
set "CHOICE=1"
set /p "CHOICE=Select an option [1]: "

if /i "%CHOICE%"=="q" exit /b 0

if "%CHOICE%"=="1" (
    echo.
    set /p "SCAN_URL=Enter API Target Base URL: "
    if not "!SCAN_URL!"=="" (
        "%PYTHON%" run_all.py scan --url !SCAN_URL!
        set "OPEN_REP=y"
        set /p "OPEN_REP=Open interactive HTML report in browser now? [Y/n]: "
        if /i "!OPEN_REP!"=="y" "%PYTHON%" -m cli --report
        if /i "!OPEN_REP!"=="" "%PYTHON%" -m cli --report
    )
    goto :end
)

if "%CHOICE%"=="2" (
    echo.
    set /p "SCHEMA_PATH=Enter OpenAPI Schema path: "
    set /p "BASE_URL=Enter Target Base URL (optional): "
    if not "!SCHEMA_PATH!"=="" (
        if not "!BASE_URL!"=="" (
            "%PYTHON%" run_all.py auto-workflow "!SCHEMA_PATH!" --url "!BASE_URL!"
        ) else (
            "%PYTHON%" run_all.py auto-workflow "!SCHEMA_PATH!"
        )
    )
    goto :end
)

if "%CHOICE%"=="3" (
    echo.
    echo [*] Running saved target profiles...
    "%PYTHON%" run_all.py profiles
    goto :end
)

if "%CHOICE%"=="4" (
    "%PYTHON%" -m cli
    goto :end
)

if "%CHOICE%"=="5" (
    "%PYTHON%" -m cli --report
    goto :end
)

echo [!] Invalid selection.
timeout /t 2 >nul
goto :menu

:end
echo.
echo Done.
pause
