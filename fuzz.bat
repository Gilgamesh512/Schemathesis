@echo off
REM ==============================================================================
REM API Security Fuzzing Framework - Windows Launcher
REM ==============================================================================
setlocal EnableDelayedExpansion

cd /d "%~dp0"

REM Find Python in virtualenv or system
if exist ".venv\Scripts\python.exe" (
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

"%PYTHON%" -m cli %*
