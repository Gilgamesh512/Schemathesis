@echo off
REM ==============================================================================
REM API Security Fuzzing Framework - Windows Launcher
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

REM 3. Check Python 3.12 via py launcher (detect exact executable path)
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
    echo [X] Error: Python was not found in PATH, .venv, or py launcher.
    pause
    exit /b 1
)

REM Check if required dependencies are installed
"%PYTHON%" -c "import pydantic, schemathesis, httpx, yaml, requests" >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] Missing required dependencies in %PYTHON%.
    if exist "requirements.txt" (
        echo [*] Auto-installing dependencies from requirements.txt...
        "%PYTHON%" -m pip install -r requirements.txt
    ) else (
        echo [X] Please run: pip install -r requirements.txt
        pause
        exit /b 1
    )
)

"%PYTHON%" -m cli %*
