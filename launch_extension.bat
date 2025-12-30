@echo off
echo ====================================
echo  Cipher Vault - Extension Launcher
echo ====================================
echo.
echo IMPORTANT: Extension is configured for PRODUCTION
echo Server: https://cipher-vault-1.onrender.com
echo.
echo This script is for LOCAL DEVELOPMENT only.
echo If you want to use the production server, just load the extension.
echo.
pause
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python and try again
    pause
    exit /b 1
)

echo [1/3] Checking dependencies...
pip show Flask >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

echo [2/3] Starting LOCAL Flask backend server...
echo Server will run on http://localhost:5000
echo.
echo NOTE: You need to change API_BASE_URL in popup.js to use local server!
echo.

start "Cipher Vault Backend" cmd /k "python app.py"

timeout /t 3 /nobreak >nul

echo [3/3] Local backend server started!
echo.
echo ====================================
echo  Setup Instructions:
echo ====================================
echo.
echo 1. Open Chrome/Edge/Brave browser
echo 2. Go to: chrome://extensions/ (or edge://extensions/)
echo 3. Enable "Developer mode" (toggle in top-right)
echo 4. Click "Load unpacked"
echo 5. Select folder: %CD%\extension
echo 6. Click the extension icon to login
echo.
echo Press any key to open browser extensions page...
pause >nul

REM Try to open browser extensions page
start chrome://extensions/ 2>nul
if errorlevel 1 start msedge://extensions/ 2>nul

echo.
echo ====================================
echo  Server is running in background
echo  Close the "Cipher Vault Backend" 
echo  window when you're done
echo ====================================
echo.
pause
