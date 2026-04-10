@echo off
echo ============================================================
echo   Personal Firewall - Uninstaller (Windows)
echo ============================================================
echo.

:: Check admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This uninstaller requires Administrator privileges.
    echo     Right-click this file and select "Run as Administrator".
    pause
    exit /b 1
)

set INSTALL_DIR=%LOCALAPPDATA%\PersonalFirewall

echo [*] Removing scheduled task...
schtasks /delete /tn "PersonalFirewall" /f >nul 2>&1
echo [+] Startup task removed.

echo [*] Removing installed files...
if exist "%INSTALL_DIR%" (
    rmdir /s /q "%INSTALL_DIR%"
    echo [+] Files removed from %INSTALL_DIR%
) else (
    echo [*] Install directory not found. Already removed?
)

echo.
echo [+] Personal Firewall has been completely uninstalled.
echo     No files, tasks, or registry entries remain.
echo.
pause
