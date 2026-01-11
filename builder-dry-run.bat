@echo off
title Azure Server Builder - Dry Run Mode
color 0F

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo.
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

REM Check Python version (requires 3.8+)
python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python 3.8 or higher is required
    echo.
    python --version
    pause
    exit /b 1
)

REM Check if virtual environment exists, create if not
if not exist "%~dp0venv\Scripts\python.exe" (
    echo.
    echo Creating virtual environment...
    python -m venv "%~dp0venv"
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo Virtual environment created successfully!
    echo.
)

REM Activate virtual environment
call "%~dp0venv\Scripts\activate.bat"

REM Check if dependencies are installed in venv
python -c "import yaml, azure.identity" >nul 2>&1
if errorlevel 1 (
    echo.
    echo Installing dependencies into virtual environment...
    pip install -r "%~dp0requirements.txt"
    if errorlevel 1 (
        echo.
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
    echo.
    echo Dependencies installed successfully!
    echo.
)

REM Run the builder in dry-run mode (preview without deploying)
python "%~dp0azure-server-builder.py" --dry-run

REM Always pause to review results
pause
