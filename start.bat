@echo off
rem GrizzDog-AI launcher for Windows: updates to the newest release, then starts.
rem Options: --docker  --kiosk  --no-update  --channel release|main|off  --check
rem Uses the project's virtual environment automatically if one exists (python -m venv .venv).
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto usevenv
where python >nul 2>nul
if %errorlevel%==0 goto bootstrap_python
where py >nul 2>nul
if %errorlevel%==0 goto bootstrap_py
echo Python 3 was not found. Install it from https://www.python.org/downloads/
exit /b 1
:bootstrap_python
echo [bootstrap] Creating virtual environment (.venv)...
python -m venv .venv
if exist ".venv\Scripts\pip.exe" (
    echo [bootstrap] Installing dependencies from requirements.txt...
    ".venv\Scripts\pip.exe" install -r requirements.txt --quiet
    goto usevenv
)
goto usepython
:bootstrap_py
echo [bootstrap] Creating virtual environment (.venv)...
py -3 -m venv .venv
if exist ".venv\Scripts\pip.exe" (
    echo [bootstrap] Installing dependencies from requirements.txt...
    ".venv\Scripts\pip.exe" install -r requirements.txt --quiet
    goto usevenv
)
goto usepy
:usevenv
".venv\Scripts\python.exe" start.py %*
exit /b %errorlevel%
:usepython
python start.py %*
exit /b %errorlevel%
:usepy
py -3 start.py %*
exit /b %errorlevel%
