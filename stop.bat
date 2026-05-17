@echo off
rem stop.bat — Stop the PromptGuard service (Windows)

echo Stopping PromptGuard service...

rem Find process using port 7474 and kill it
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :7474') do (
    echo Killing process %%a on port 7474...
    taskkill /F /PID %%a >nul 2>&1
)

rem Also kill any leftover PromptGuard processes
taskkill /F /IM python.exe >nul 2>&1 & taskkill /F /IM python3.exe >nul 2>&1

echo PromptGuard service stopped.
echo To restart: promptguard serve