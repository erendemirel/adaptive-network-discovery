@echo off
setlocal
REM Windows: PowerShell does not run .sh with bash. Use this file, Git Bash, or run_e2e.ps1
where bash >nul 2>&1
if %ERRORLEVEL% equ 0 (
  bash "%~dp0run_e2e.sh"
  exit /b %ERRORLEVEL%
)
echo ERROR: bash not found in PATH.
echo   Option A:  powershell -ExecutionPolicy Bypass -File "%~dp0run_e2e.ps1"
echo   Option B:  Install Git for Windows, then: bash "%~dp0run_e2e.sh"
exit /b 1
