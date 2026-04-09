@echo off
setlocal

cd /d %~dp0
set LOGS_DIR=logs
if not exist %LOGS_DIR% mkdir %LOGS_DIR%

REM Générer un timestamp fiable (ex: 20260409_114623)
for /f %%i in ('powershell -Command "Get-Date -Format 'yyyyMMdd_HHmmss'"') do set TIMESTAMP=%%i

echo %date% %time% : Début du pipeline >> %LOGS_DIR%\pipeline.log

poetry run python src\data\fetch_real_cloudtrail.py --output data\raw\latest_events.csv --max-events 1000
if errorlevel 1 (
    echo %date% %time% : ERREUR récupération logs >> %LOGS_DIR%\pipeline.log
    exit /b 1
)

poetry run python src\predict\predict_on_real.py --input data\raw\latest_events.csv --output reports\alertes_%TIMESTAMP%.csv
if errorlevel 1 (
    echo %date% %time% : ERREUR prédiction >> %LOGS_DIR%\pipeline.log
    exit /b 1
)

echo %date% %time% : Pipeline terminé >> %LOGS_DIR%\pipeline.log