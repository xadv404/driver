@echo off
:: Lanceur administrateur pour test_hide.ps1
:: Usage : test_hide.bat C:\chemin\vers\SelfHideDriver.sys

if "%~1"=="" (
    echo Usage: %~nx0 ^<chemin_vers_SelfHideDriver.sys^>
    pause
    exit /b 1
)

:: Relance en admin si necessaire
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Relancement en administrateur...
    powershell -Command "Start-Process '%~f0' -ArgumentList '%~1' -Verb RunAs"
    exit /b
)

powershell -ExecutionPolicy Bypass -File "%~dp0test_hide.ps1" -DriverPath "%~1"
pause
