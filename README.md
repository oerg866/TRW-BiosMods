# TRW-BiosMods

This repository is for BIOS modifications of vintage motherboards provided unter the *TheRetroWeb* label.

Currently, the following motherboards have custom BIOSES:

* ABIT PW4 (N/A yet, need to clean up the patches)
* SOYO 4SAW

## Script files

Helper files and script files are in the `__scripts` directory.

### award45x.idc

This IDC file can be loaded in the **Interactive Disassembler (IDA)** using the `Execute Script` command. It provides structures and enums helpful in BIOS disassembly.

### award45x_ida.py

This is an IDAPython script file with several functions that help disassemble structures and strings in AWARD 4.5x BIOSes in IDA.

Since this is highly experimental, there is no documentation. But if you make it far enough to execute scripts inside a disassembly, you can probably figure out how to make it work :-)

### award45x_funcs.py

Recognizes common functions and structures, marks them in IDA and generates an include file named `CMN_FUNC.INC`

## BIOS Mod Documentation

The documentation of AWARD BIOS structures is being written as development progresses and can be found here:

https://hackmd.io/@theretroweb/BkY-LNNeR
