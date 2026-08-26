@echo off
REM ============================================================
REM  BitLocker Manager - Unlock Helper installer (double-click)
REM  Runs install-helper.ps1 with the right execution policy so
REM  you don't have to touch PowerShell settings.
REM ============================================================
echo Installing the BitLocker Manager Unlock Helper...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-helper.ps1"
echo.
echo Done. If you saw a red FAILED message above, read it and try again
echo (some PCs need this run as Administrator).
echo.
pause
