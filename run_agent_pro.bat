@echo off
echo Starting MDB Agent Pro...
echo.

REM Check if virtual environment exists
if exist ".venv\Scripts\python.exe" (
    echo Using virtual environment...
    .venv\Scripts\python.exe mdb_agent_pro.py
) else (
    echo Virtual environment not found, using system Python...
    python mdb_agent_pro.py
)

if %ERRORLEVEL% neq 0 (
    echo.
    echo Error occurred while running MDB Agent Pro!
    echo Please check the error messages above.
    pause
)
