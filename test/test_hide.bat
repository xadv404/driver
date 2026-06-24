@echo off
:: Lanceur admin pour test_hide.ps1
:: Usage : test_hide.bat <chemin_driver.sys> [kdmapper]

if "%~1"=="" (
    echo Usage: %~nx0 ^<SelfHideDriver.sys^> [kdmapper]
    pause & exit /b 1
)

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Relancement en administrateur...
    if "%~2"=="kdmapper" (
        powershell -Command "Start-Process '%~f0' -ArgumentList '%~1','kdmapper' -Verb RunAs"
    ) else (
        powershell -Command "Start-Process '%~f0' -ArgumentList '%~1' -Verb RunAs"
    )
    exit /b
)

if "%~2"=="kdmapper" (
    powershell -ExecutionPolicy Bypass -File "%~dp0test_hide.ps1" -DriverPath "%~1" -KdmapperMode
) else (
    powershell -ExecutionPolicy Bypass -File "%~dp0test_hide.ps1" -DriverPath "%~1"
)
pause
