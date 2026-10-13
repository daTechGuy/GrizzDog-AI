@echo off
rem GrizzDog-AI launcher for Windows: updates to the newest release, then starts.
rem Options: --docker  --kiosk  --no-update  --channel release|main|off  --check
rem Uses the project's virtual environment automatically if one exists (python -m venv .venv).
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto usevenv
where python >nul 2>nul
if %errorlevel%==0 goto usepython
where py >nul 2>nul
if %errorlevel%==0 goto usepy
echo Python 3 was not found. Install it from https://www.python.org/downloads/
exit /b 1
:usevenv
".venv\Scripts\python.exe" start.py %*
exit /b %errorlevel%
:usepython
python start.py %*
exit /b %errorlevel%
:usepy
py -3 start.py %*
exit /b %errorlevel%
