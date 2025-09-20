@echo off
echo 🛡️ Phishing Detection System - GUI Launcher
echo =============================================
echo.

REM Try different Python commands
python --version >nul 2>&1
if %errorlevel%==0 (
    echo Starting GUI with 'python'...
    python "start phishing detector.py"
    goto :end
)

python3 --version >nul 2>&1
if %errorlevel%==0 (
    echo Starting GUI with 'python3'...
    python3 "start phishing detector.py"
    goto :end
)

py --version >nul 2>&1
if %errorlevel%==0 (
    echo Starting GUI with 'py'...
    py "start phishing detector.py"
    goto :end
)

echo ❌ Python not found! Please install Python 3.7+ from python.org
echo.
echo Alternative: You can try running the command-line version:
echo python example_usage.py
echo.

:end
pause
