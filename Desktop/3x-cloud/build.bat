@echo off
echo 3X Scanner Builder
echo ===================

if "%~1"=="" (
    echo Usage: build.bat ^<target_id^> [output_name] [webhook_url]
    echo Example: build.bat suspect_123 my_scanner https://discord.com/api/webhooks/...
    exit /b 1
)

set TARGET_ID=%~1
set OUTPUT_NAME=%~2
if "%~2"=="" set OUTPUT_NAME=3x_scanner
set WEBHOOK_URL=%~3

python builder\build.py "%TARGET_ID%" -o "%OUTPUT_NAME%" %~3

pause
