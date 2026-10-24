@echo off
title Defensive Guide to SQL Injection and Database Security (Python)
echo ==================================================================
echo   DEFENSIVE GUIDE TO SQL INJECTION AND DATABASE SECURITY
echo   Python Edition - Value Added Course in Cybersecurity
echo ==================================================================
echo.

:: Check python in standard locations
set PYTHON_CMD=python
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
        set "PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    ) else (
        where py >nul 2>nul
        if %ERRORLEVEL% EQU 0 (
            set PYTHON_CMD=py
        ) else (
            echo [ERROR] Python was not found on your system.
            echo Please install Python 3.10+ from https://www.python.org/
            pause
            exit /b 1
        )
    )
)

echo [INFO] Using Python: %PYTHON_CMD%
echo [INFO] Checking required dependencies...
"%PYTHON_CMD%" -m pip install -r requirements.txt --quiet

echo [INFO] Launching Web Application...
echo.
"%PYTHON_CMD%" app.py

pause
