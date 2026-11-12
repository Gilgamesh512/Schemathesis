@echo off
REM ==============================================================================
REM Schemathesis Pro - Universal API Security Scanner One-Click Launcher (Windows)
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
REM Argument Dispatcher
REM ------------------------------------------------------------------------------
if "%~1"=="auto" (
    echo [*] Running Autonomous BOLA Workflow...
    "%PYTHON%" run_all.py auto-workflow
    goto :end
)

if "%~1"=="all" (
    echo [*] Running Full Security Testing Pipeline...
    "%PYTHON%" run_all.py run
    goto :end
)

if "%~1"=="run" (
    echo [*] Running Full Security Testing Pipeline...
    "%PYTHON%" run_all.py run
    goto :end
)

if "%~1"=="report" (
    "%PYTHON%" -m cli --report
    goto :end
)

if "%~1"=="dashboard" (
    "%PYTHON%" -m cli --dashboard
    goto :end
)

if "%~1"=="scan" (
    if "%~2"=="" (
        echo [!] Please specify a target URL, e.g.: fuzz.bat scan http://localhost:8000
        pause
        exit /b 1
    )
    shift
    "%PYTHON%" run_all.py scan %*
    goto :end
)

if not "%~1"=="" (
    REM Forward arbitrary arguments directly to run_all.py
    "%PYTHON%" run_all.py %*
    goto :end
)

REM ------------------------------------------------------------------------------
REM Interactive One-Click Menu (When launched with no arguments / double-clicked)
REM ------------------------------------------------------------------------------
:menu
cls
echo ==================================================================================
echo             SCHEMATHESIS PRO - UNIVERSAL API SECURITY SCANNER
echo ==================================================================================
echo.
echo   [1] Auto-Run BOLA Workflows (Zero-YAML, Auto-Infer CRUD)  [DEFAULT - Press Enter]
echo   [2] Run Full Security Pipeline (Auto-auth + VAmPI + crAPI + DVGA)
echo   [3] Quick Scan Custom API URL (Auto-Discovery)
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
    echo [*] Launching Autonomous BOLA Workflow Engine...
    "%PYTHON%" run_all.py auto-workflow
    echo.
    set "OPEN_REP=y"
    set /p "OPEN_REP=Open interactive HTML report in browser now? [Y/n]: "
    if /i "!OPEN_REP!"=="y" "%PYTHON%" -m cli --report
    if /i "!OPEN_REP!"=="" "%PYTHON%" -m cli --report
    goto :end
)

if "%CHOICE%"=="2" (
    echo.
    echo [*] Running full multi-target pipeline...
    "%PYTHON%" run_all.py run
    goto :end
)

if "%CHOICE%"=="3" (
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
