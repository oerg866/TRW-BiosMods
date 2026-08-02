::@echo off
:: This is expected to be run from one of the board subdirectories
:: Arg 1 input binary file (unedited.tmp)
:: Arg 2 include file to generate from arg 1 (unedited.inc)
:: Arg 3 assembly file (patch.asm)
:: Arg 4 final binary (original.tmp)
set INBIN=%1
set ININC=%2
set INASM=%3
set OUTBIN=%4
set OUTLST=%OUTBIN:~0,-4%.LST
set OUTMAP=%OUTBIN:~0,-4%.MAP
set OUTOBJ=%INASM:~0,-4%.OBJ

echo %INBIN%
echo %ININC%
echo %INASM%
echo %OUTBIN%
echo %OUTMAP%
echo %OUTOBJ%

python ..\__scripts\bin2inc.py %INBIN% %ININC%
ml /Fm%OUTMAP% /Fl%OUTLST% /c /Zm %INASM% 
echo %OUTLST%
link %OUTOBJ%,tmp.bin;

if not exist tmp.bin (
    echo ERROR
    pause
    exit /b -1
)

python ..\__scripts\patch.py -removeheader -i tmp.bin -o %OUTBIN%
del tmp.bin

exit /b
