@echo off
set PATH=%PATH%;..\__scripts
mkdir BIN >nul
python ..\__scripts\bin2inc.py unedited.tmp unedited.inc
ml /c /Zm patch.asm /FmPATCH.MAP
link patch.obj,tmp.bin;

if exist tmp.bin (
    python ..\__scripts\patch.py -removeheader -i tmp.bin -o original.tmp
    python ..\__scripts\patch.py -bios_build . bin\SOYO_4SAW.BIN
rem     del tmp.bin
)
