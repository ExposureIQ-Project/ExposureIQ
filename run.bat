@echo off
setlocal
rem Run PowerShell with a process-only policy; do not change system settings.
rem install sets up dependencies; the official Nmap installer may show prompts.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
set "EXPOSUREIQ_EXIT_CODE=%ERRORLEVEL%"
rem Keep errors visible when double-clicked without arguments.
if "%~1"=="" if not "%EXPOSUREIQ_EXIT_CODE%"=="0" pause
exit /b %EXPOSUREIQ_EXIT_CODE%
