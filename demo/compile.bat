@echo off
setlocal enabledelayedexpansion

set OUTPUT_DIR=bin

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

for %%f in (*.cpp) do (
    set "FILENAME=%%~nf"
    echo Compiling %%f...
    cl /EHsc "%%f" /Fe:"%OUTPUT_DIR%\!FILENAME!.exe"
)

echo Compilation complete. Executables are in %OUTPUT_DIR%.
endlocal
