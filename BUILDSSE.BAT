@echo off
rem
rem BUILD.BAT - Build nt351sse.sys with the NT 4.0 DDK + MSVC 4.2 toolchain,
rem then restamp the PE version fields for Windows NT 3.51.
rem
rem Edit the three paths below if your layout differs. This script assumes the
rem layout of the folder these files were delivered in:
rem
rem   <root>\MSVC420                       - Visual C++ 4.2
rem   <root>\WinNT4ddk.English\DDK         - Windows NT 4.0 DDK
rem   <root>\winnt351_ntoskrnl\ntoskrnl.exe - reference NT 3.51 kernel
rem   <root>\nt351test                     - this folder
rem

set ROOT=%~dp0..
set MSVC=%ROOT%\MSVC420
set DDK=%ROOT%\WinNT4ddk.English\DDK
set NT351=%ROOT%\winnt351_ntoskrnl\ntoskrnl.exe
set LIB351=%ROOT%\winnt351_ntoskrnl

set PATH=%MSVC%\bin;%PATH%

rem The NT 4 DDK headers first, then the VC 4.2 headers. _X86_ must be defined
rem the way the DDK expects it or ntddk.h takes the wrong branch.
set INCLUDE=%DDK%\INC;%MSVC%\include
set LIB=%DDK%\LIB\I386\FREE;%MSVC%\lib
set C_DEFINES=/D_X86_=1 /Di386=1 /DNDEBUG=1 /DWIN32=100 /D_NTDRIVER_

echo === Compiling ===
cl /nologo /c /W3 /Gz /Zp8 /Ox /Gs /Gy %C_DEFINES% nt351sse.c
if errorlevel 1 goto fail

echo === Linking ===
rem -subsystem:native means "no subsystem" so the loader does not apply the
rem GUI/console version rules. -driver marks a kernel-mode image. 4.00 is a
rem placeholder that stamp351.py rewrites to 3.51 immediately below.
rem
rem -nodefaultlib is required, not optional: the DDK's own makefile uses it
rem (MAKEFILE.DEF:1305). Without it the linker tries to pull in LIBC.LIB,
rem which a kernel driver must not link against.
link -nologo -machine:i386 -driver -nodefaultlib -subsystem:native,4.00 ^
     -entry:DriverEntry -align:0x20 -base:0x10000 ^
     -out:nt351sse.sys ^
     nt351sse.obj ^
     %DDK%\LIB\I386\FREE\ntoskrnl.lib ^
     %DDK%\LIB\I386\FREE\hal.lib
if errorlevel 1 goto fail

echo === Stamping NT 3.51 version fields ===
python "%~dp0scripts\stamp351.py" nt351sse.sys 3 51
if errorlevel 1 goto fail

echo === Verifying imports against the NT 3.51 kernel ===
if exist "%NT351%" (
    python "%~dp0scripts\checkimports.py" nt351sse.sys "%NT351%"
    if errorlevel 1 echo WARNING: some imports are not present in this kernel.
) else (
    echo NOTE: %NT351% not found, skipping the import check.
)

echo.
echo Built nt351sse.sys
goto :eof

:fail
echo.
echo BUILD FAILED
exit /b 1
