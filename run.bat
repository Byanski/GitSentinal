@echo off
title GitSentinel - Secret & API Key Guard
echo ===================================================
echo             Starting GitSentinel...
echo ===================================================
echo Checking Python environment...

python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH.
    pause
    exit /b 1
)

echo Installing dependencies if needed...
python -m pip install -r requirements.txt --quiet

echo Starting GitSentinel server on http://localhost:8000 ...
start "" http://localhost:8000
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause
