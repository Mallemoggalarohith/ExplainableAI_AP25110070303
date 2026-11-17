@echo off
REM Compile the project (needs JDK 17+). Run from the Implementation folder:  scripts\build.bat
cd /d "%~dp0\.."
if not exist out mkdir out
dir /s /b src\*.java > sources.txt
javac -d out @sources.txt
del sources.txt
echo Build finished (see errors above if any).
