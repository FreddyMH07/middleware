@echo off
REM MDB Agent Pro v2.0 - Launch Script
REM Professional Database-to-API Bridge
REM Author: Freddy Mazmur - PT Sahabat Agro Group

title MDB Agent Pro v2.0
echo ====================================================
echo MDB Agent Pro v2.0 - Database to API Bridge
echo PT Sahabat Agro Group
echo Author: Freddy Mazmur
echo ====================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found in PATH
    echo Please install Python or add it to your system PATH
    pause
    exit /b 1
)

REM Check if main script exists
if not exist "mdb_agent_pro.py" (
    echo ERROR: mdb_agent_pro.py not found
    echo Please ensure you're running this from the correct directory
    pause
    exit /b 1
)

REM Install dependencies if needed
echo Checking dependencies...
pip install -r requirements.txt --quiet

echo.
echo Starting MDB Agent Pro...
echo.

REM Run the application
python mdb_agent_pro.py

if %errorlevel% neq 0 (
    echo.
    echo Application exited with error code %errorlevel%
    echo Check the logs for more information
)

echo.
echo Press any key to exit...
pause >nul
