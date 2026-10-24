@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    set "PYTHON_CMD=%CD%\.venv\Scripts\python.exe"
) else (
    where py >nul 2>nul
    if not errorlevel 1 (
        py -m venv .venv
    ) else (
        python -m venv .venv
    )
    if errorlevel 1 goto setup_error
    set "PYTHON_CMD=%CD%\.venv\Scripts\python.exe"
)

echo Installing or checking LogAnomaly requirements in its private environment...
"%PYTHON_CMD%" -m pip install --upgrade pip
if errorlevel 1 goto setup_error
"%PYTHON_CMD%" -m pip install -r requirements.txt
if errorlevel 1 goto setup_error

echo.
echo Starting LogAnomaly. Keep this window open while using the app.
"%PYTHON_CMD%" -m streamlit run app.py
pause
exit /b 0

:setup_error
echo.
echo Setup failed. Check Python and internet access, then try again.
pause
exit /b 1
