@echo off
set PATH=%PATH%;..\__scripts
set OUTPUTFILE=BIN\SOYO_025L.bin
mkdir BIN >nul
call build_asm.bat baserom.bin baserom.inc patch.asm %OUTPUTFILE%
python ..\__scripts\patch.py -i %OUTPUTFILE% -award450 -o %OUTPUTFILE%
