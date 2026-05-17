@echo off
rem upgrade.bat — Pull latest PromptGuard and restart (Windows)

echo Upgrading PromptGuard...
echo.

rem Check for existing config
if exist "%USERPROFILE%\.promptguard\config.yaml" (
    echo [OK] Existing config found at ^ ~/.promptguard/config.yaml ^
    echo      Your configuration will be preserved.
) else if exist ".promptguard.yaml" (
    echo [OK] Workspace config found at .promptguard.yaml
) else (
    echo [WARN] No config file found. Copy .promptguard.yaml from the repo after upgrade.
)

echo.
echo Reinstalling...
pip install -e . --quiet

echo.
echo Upgrade complete.
echo.
echo Data preservation:
echo   %%USERPROFILE%%\^/.promptguard/config.yaml  — preserved
echo   %%USERPROFILE%%\^/.promptguard/audit.db     — preserved
echo   %%USERPROFILE%%\^/.promptguard/audit.jsonl  — preserved
echo   Session keys in memory                   — cleared (restart required)
echo.
echo To restart: promptguard serve