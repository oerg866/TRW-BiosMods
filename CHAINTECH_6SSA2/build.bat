@echo off
set PATH=%PATH%;..\__scripts
mkdir BIN >nul
python ..\__scripts\bin2inc.py unedited.tmp unedited.inc
ml /c /Zm patch.asm /FmPATCH.MAP
link patch.obj,tmp.bin;

if exist tmp.bin (
    python ..\__scripts\patch.py -removeheader -i tmp.bin -o 6ssa2419.BIN
    python ..\__scripts\patch.py -bios_build . bin\CHAINTECH_6SSA2.BIN
    del tmp.bin
)
