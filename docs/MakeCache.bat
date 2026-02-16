@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "OUTPUT=offlinexmb.cache"
set "ROOT=%~dp0"

REM Remove trailing backslash from ROOT
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

REM === Build clean timestamp (no spaces) ===
for /f "tokens=1-4 delims=/ " %%a in ("%DATE%") do (
    set "D=%%a-%%b-%%c"
)

for /f "tokens=1-4 delims=:., " %%a in ("%TIME%") do (
    set "T=%%a-%%b-%%c"
)

REM === Write manifest header ===
> "%OUTPUT%" echo CACHE MANIFEST
>> "%OUTPUT%" echo # Saaqi HOST 5.05 Created on !D!-!T!
>> "%OUTPUT%" echo.
>> "%OUTPUT%" echo CACHE:

REM === Enumerate files ===
for /R "%ROOT%" %%F in (*) do (
    set "FILE=%%F"

    REM Make path relative
    set "REL=!FILE:%ROOT%\=!"

    REM Normalize slashes
    set "REL=!REL:\=/!"

    REM Skip empty lines
    if not "!REL!"=="" (

        REM Exclusions
        echo !REL! | findstr /I "\.bat \.exe \.mp4 \.cache \.txt \.md \.sh \.gitignore \.vscode \.git LICENSE ESP-VERSION media" >nul
        if errorlevel 1 (
            if /I not "!REL!"=="%OUTPUT%" (
                >> "%OUTPUT%" echo !REL!
            )
        )
    )
)

REM === Network section ===
>> "%OUTPUT%" echo.
>> "%OUTPUT%" echo NETWORK:
>> "%OUTPUT%" echo *

echo.
echo %OUTPUT% created successfully.
timeout 2 > nul
