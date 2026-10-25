@echo off
REM ==============================================================================
REM API Security Fuzzing Framework - Windows Launcher
REM ==============================================================================
setlocal EnableDelayedExpansion

cd /d "%~dp0"

REM Find Python in active virtualenv, local .venv, or system PATH
if defined VIRTUAL_ENV if exist "%VIRTUAL_ENV%\Scripts\python.exe" (
    set "PYTHON=%VIRTUAL_ENV%\Scripts\python.exe"
) else if exist ".venv\Scripts\python.exe" (
    set "PYTHON=.venv\Scripts\python.exe"
) else (
    where python >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON=python"
    ) else (
        where py >nul 2>&1
        if !errorlevel! equ 0 (
            set "PYTHON=py"
        ) else (
            echo [X] Error: Python was not found in PATH or .venv.
            pause
            exit /b 1
        )
    )
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
