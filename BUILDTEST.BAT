@echo off
rem
rem BUILDTEST.BAT - Build ssetest.exe (user-mode console acceptance test)
rem with the MSVC 4.2 toolchain, then restamp its PE version fields to NT 3.51.
rem
rem This is a Win32 console app, NOT a driver: it links the static single-
rem threaded CRT (LIBC.LIB, the MSVC 4.2 default) so there is no runtime DLL
rem dependency to trip over on 3.51, and uses only base Win32 APIs present in
rem NT 3.51.
rem

set ROOT=%~dp0..
set MSVC=%ROOT%\MSVC420

set PATH=%MSVC%\bin;%PATH%
set INCLUDE=%MSVC%\include
set LIB=%MSVC%\lib

echo === Compiling and linking ===
cl /nologo /W3 /Ox /DWIN32=0x0351 ssetest.c /link /subsystem:console /out:ssetest.exe
if errorlevel 1 goto fail

echo === Stamping NT 3.51 version fields ===
rem MSVC 4.2's linker stamps the subsystem version to 4.00; rewrite the OS,
rem image and subsystem version fields to 3.51 so the 3.51 image loader is
rem happy. (An EXE's checksum is not enforced by the loader, but stamp351
rem fixes it anyway.)
python "%~dp0scripts\stamp351.py" ssetest.exe 3 51
if errorlevel 1 goto fail

echo.
echo Built ssetest.exe
goto :eof

:fail
echo.
echo BUILD FAILED
exit /b 1
