@echo off
rem uninstall.bat — Remove PromptGuard completely (Windows)

echo Uninstalling PromptGuard...
echo.

rem Stop the service
echo Stopping PromptGuard service...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :7474') do (
    taskkill /F /PID %%a >nul 2>&1
)

rem Remove CLI wrapper
echo Removing CLI wrapper...
del /q "%USERPROFILE%\.local\bin\dmcslab-code" >nul 2>&1
del /q "%USERPROFILE%\bin\dmcslab-code" >nul 2>&1

rem Uninstall Python package
echo Uninstalling Python package...
pip uninstall promptguard -y >nul 2>&1

rem Ask about data directory
set DATA_DIR=%USERPROFILE%\.promptguard
if exist "%DATA_DIR%" (
    echo.
    echo PromptGuard data directory: %DATA_DIR%
    set /p CONFIRM=Delete all data ^(config, audit logs, session keys^)? [y/N]:
    if /i "%CONFIRM%"=="y" (
        rmdir /s /q "%DATA_DIR%"
        echo Data directory removed.
    ) else (
        echo Data directory preserved.
    )
)

echo.
echo Uninstall complete.
echo If you used the VS Code extension, manually disable it in VS Code.