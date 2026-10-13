@echo off
rem GrizzDog-AI launcher for Windows: updates to the newest release, then starts.
rem Options: --docker  --kiosk  --no-update  --channel release|main|off  --check
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel%==0 goto usepython
where py >nul 2>nul
if %errorlevel%==0 goto usepy
echo Python 3 was not found. Install it from https://www.python.org/downloads/
exit /b 1
:usepython
python start.py %*
exit /b %errorlevel%
:usepy
py -3 start.py %*
exit /b %errorlevel%
