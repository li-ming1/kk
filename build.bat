@echo off
rem Build kk.exe with MSVC. Locates the Visual Studio dev environment, then
rem compiles the single translation unit into a static-CRT self-contained exe.
setlocal
set "VSD=D:\Program Files\Common7\Tools\vsdevcmd.bat"
if not exist "%VSD%" set "VSD=%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\Tools\vsdevcmd.bat"
if not exist "%VSD%" (
    echo build.bat: vsdevcmd.bat not found; edit VSD in this script.
    exit /b 1
)
call "%VSD%" -arch=x64 -no_logo
if errorlevel 1 exit /b 1
cl /nologo /std:c11 /W4 /O2 /GL /MT /Zi /utf-8 kk.c ^
    /link /LTCG /OUT:kk.exe winhttp.lib user32.lib
