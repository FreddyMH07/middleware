@echo off
echo ========================================
echo    MDB Agent Pro v2.0 - Build EXE
echo ========================================
echo.

echo [INFO] Starting build process...
python build_exe.py

echo.
echo [INFO] Build process completed!
echo.

if exist "release\MDBAgentPro.exe" (
    echo [SUCCESS] Executable created successfully!
    echo Location: release\MDBAgentPro.exe
    echo.
    echo [INFO] You can now distribute the 'release' folder
    echo Just copy it to any Windows PC and double-click MDBAgentPro.exe
    echo.
    
    set /p choice="Open release folder? (y/n): "
    if /i "%choice%"=="y" (
        explorer release
    )
) else (
    echo [ERROR] Build failed! Check error messages above.
)

echo.
pause
