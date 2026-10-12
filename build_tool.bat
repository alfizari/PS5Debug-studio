@echo off
REM ==========================================================================
REM  Builds the main tool (gui.py) into  dist\PS5 Debug Toolkit.exe
REM  (one file, no console window).  The Cheat Player has its own
REM  cheat_player\build_player.bat - this script does not touch it.
REM
REM  Run it from anywhere: double-click it in Explorer.
REM  Optional:  build_tool.bat folder   -> builds a folder (faster start-up)
REM                                         dist\PS5 Debug Toolkit\PS5 Debug Toolkit.exe
REM
REM  The exe keeps its settings.json, cheats\ (default project), tables\,
REM  scripts\ and pointerscans\ next to itself.  On the first build your
REM  current ones are copied there; later builds never overwrite them.
REM
REM  Private: the ShnExt decryptor (cheat_player\shnext_decryptor.py) is NOT
REM  included in this exe.
REM ==========================================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "NAME=PS5 Debug Toolkit"
set "MODE=--onefile"
set "OUT=dist\%NAME%.exe"
set "DATA=dist"
if /I "%~1"=="folder" (
  set "MODE=--onedir"
  set "OUT=dist\%NAME%\%NAME%.exe"
  set "DATA=dist\%NAME%"
)

REM ---- Python --------------------------------------------------------------
where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found on PATH. Install Python 3.10+ from python.org
  echo and tick "Add python.exe to PATH".
  goto fail
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
  echo Python 3.10 or newer is needed.
  goto fail
)
python -c "import tkinter" 2>nul
if errorlevel 1 (
  echo This Python has no tkinter. Reinstall Python with "tcl/tk and IDLE" ticked.
  goto fail
)

REM ---- packages (quick when they are already installed) ---------------------
echo Checking packages...
python -m pip install --disable-pip-version-check -q --upgrade pyinstaller capstone keystone-engine numpy
if errorlevel 1 (
  echo pip could not install the packages - check your internet connection.
  goto fail
)

REM ---- every module of the tool (also the ones loaded only when a window opens)
set "HIDDEN="
for %%F in (*.py) do (
  if /I not "%%~nF"=="gui" set "HIDDEN=!HIDDEN! --hidden-import %%~nF"
)

REM ---- close a running copy, or the exe cannot be replaced -----------------
tasklist /FI "IMAGENAME eq %NAME%.exe" 2>nul | find /I "%NAME%.exe" >nul
if not errorlevel 1 (
  echo "%NAME%.exe" is running - close it, then press a key.
  pause >nul
)

if not exist "assets\icon.ico" (
  echo assets\icon.ico is missing - copy the assets folder from the repo.
  goto fail
)
echo Building %OUT% ...
python -m PyInstaller --noconfirm --clean %MODE% --windowed --name "%NAME%" ^
  --icon "assets\icon.ico" --add-data "assets;assets" ^
  --paths . ^
  !HIDDEN! ^
  --collect-all capstone --collect-all keystone ^
  --hidden-import numpy ^
  --exclude-module shnext_decryptor --exclude-module shnext_bridge --exclude-module player ^
  --exclude-module unicorn --exclude-module matplotlib --exclude-module pandas ^
  --exclude-module scipy --exclude-module PyQt5 --exclude-module PySide6 --exclude-module IPython ^
  gui.py
if errorlevel 1 goto fail
if not exist "%OUT%" goto fail

REM ---- first build: bring your data along (never overwrites) ----------------
for %%D in (cheats tables scripts pointerscans) do (
  if exist "%%D\" if not exist "%DATA%\%%D\" (
    echo Copying %%D\ next to the exe
    xcopy /E /I /Q /Y "%%D" "%DATA%\%%D" >nul
  )
)
if exist "settings.json" if not exist "%DATA%\settings.json" copy /Y "settings.json" "%DATA%\settings.json" >nul

echo.
echo Done:  %OUT%
echo Your settings and cheats for the exe are in  %DATA%\
goto end

:fail
echo.
echo BUILD FAILED - see the messages above.

:end
echo.
pause
endlocal
