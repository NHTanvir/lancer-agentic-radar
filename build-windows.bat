@echo off
setlocal enabledelayedexpansion
REM ============================================================
REM  build-windows.bat -- packaged Windows release build
REM  Output: dist\lancer-agentic-radar-windows-x86_64\
REM ============================================================

set "PKG=lancer-agentic-radar"
set "DIST=dist\%PKG%-windows-x86_64"

echo === Building %PKG% (release) for Windows x86_64 ===
cargo build --release
if errorlevel 1 exit /b 1

echo === Packaging ===
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"
mkdir "%DIST%\bin"

copy /Y "target\release\%PKG%.exe" "%DIST%\bin\" >nul
copy /Y "target\release\%PKG%-cli.exe" "%DIST%\bin\" >nul 2>nul
copy /Y "LICENSE" "%DIST%\" >nul 2>nul
copy /Y "README.md" "%DIST%\" >nul 2>nul

echo === Done. Binaries in %DIST%\bin ===
dir "%DIST%\bin"
exit /b 0
