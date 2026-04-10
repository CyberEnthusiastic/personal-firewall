@echo off
echo ============================================================
echo   Personal Firewall - Installer (Windows)
echo   Copyright (c) 2026 Mohith Vasamsetti
echo ============================================================
echo.

:: Check admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This installer requires Administrator privileges.
    echo     Right-click this file and select "Run as Administrator".
    pause
    exit /b 1
)

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not installed. Install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

echo [*] Installing Personal Firewall...
echo.

:: Set install directory
set INSTALL_DIR=%LOCALAPPDATA%\PersonalFirewall
echo [*] Install directory: %INSTALL_DIR%

:: Create install directory
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

:: Copy files
echo [*] Copying files...
xcopy /E /Y /Q "%~dp0*" "%INSTALL_DIR%\" >nul
echo [+] Files copied.

:: Create default rules
if not exist "%INSTALL_DIR%\rules" mkdir "%INSTALL_DIR%\rules"
echo [{"type":"block_port","id":"DEFAULT-BLOCK-PORTS","name":"Block known malware ports","severity":"HIGH","ports":[4444,5555,6666,31337,12345,54321]}] > "%INSTALL_DIR%\rules\default_blocks.json"
echo [+] Default rules created.

:: Create Windows scheduled task (runs at startup + every 5 min)
echo [*] Creating startup task...
schtasks /create /tn "PersonalFirewall" /tr "python \"%INSTALL_DIR%\firewall.py\" monitor --interval 10 --no-intel" /sc onstart /rl highest /f >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Startup task created. Firewall will start on boot.
) else (
    echo [!] Could not create startup task. You can start manually:
    echo     python "%INSTALL_DIR%\firewall.py" monitor
)

:: Create shortcut batch files
echo @echo off > "%INSTALL_DIR%\start_firewall.bat"
echo python "%INSTALL_DIR%\firewall.py" monitor >> "%INSTALL_DIR%\start_firewall.bat"

echo @echo off > "%INSTALL_DIR%\scan_now.bat"
echo python "%INSTALL_DIR%\firewall.py" scan >> "%INSTALL_DIR%\scan_now.bat"

echo @echo off > "%INSTALL_DIR%\update_intel.bat"
echo python "%INSTALL_DIR%\firewall.py" update >> "%INSTALL_DIR%\update_intel.bat"

:: Add to PATH (optional)
echo.
echo [+] Installation complete!
echo.
echo   Install location : %INSTALL_DIR%
echo   Start firewall   : %INSTALL_DIR%\start_firewall.bat
echo   Quick scan       : %INSTALL_DIR%\scan_now.bat
echo   Update intel     : %INSTALL_DIR%\update_intel.bat
echo   Uninstall        : %INSTALL_DIR%\uninstall.bat
echo.
echo   The firewall will start automatically on next boot.
echo   To start now, run: start_firewall.bat
echo.
pause
