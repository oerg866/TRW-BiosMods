# TRW-BiosMods

This repository is for BIOS modifications of vintage motherboards provided unter the *TheRetroWeb* label.

Currently, the following motherboards have custom BIOSES:


* 486 Class
    * ABIT PW4 (N/A yet, need to clean up the patches)
    * [SOYO 4SAW](./SOYO_4SAW)
    * [SOYO 4SA2/4SA5](./SOYO_4SA2)
    * [SOYO SY-025L](./SOYO_025L)
* Slot 1
    * [Chaintech CT-6SSA2](./CHAINTECH_6SSA2)

## Script files

Helper files and script files are in the `__scripts` directory.

### award45x.idc

This IDC file can be loaded in the **Interactive Disassembler (IDA)** using the `Execute Script` command. It provides structures and enums helpful in BIOS disassembly.

### award45x_ida.py

This is an IDAPython script file with several functions that help disassemble structures and strings in AWARD 4.5x BIOSes in IDA.

Since this is highly experimental, there is no documentation. But if you make it far enough to execute scripts inside a disassembly, you can probably figure out how to make it work :-)

### award45x_funcs.py

Recognizes common functions and structures, marks them in IDA and generates an include file named `CMN_FUNC.INC`

## (semi) automated Patching scripts

These include files can be included and will automatically add or patch functionality in the BIOS.

### `nofadeout.inc`

Include this file to disable the EPA logo fadeout, speeding up the POST.

### `nohdtable.inc`

Removes the preset HDD parameter table and modifies the BIOS menu items automatically to relfect this change. It will then only be able to do None, Auto (if the BIOS supports it) and User entry.

This generates a code cave of ~500 bytes.

Update the `CODECAVE_HDDParams` variable after placing code here.

### `hddfix.inc`

Fixes HDD size calculation bugs, if a supported buggy BIOS function is detected.

### `mouse.inc`

Adds PS/2 mouse support to a BIOS that doesn't have it.

This uses lots of space in `CODECAVE_HDDParams` and `CODECAVE_ROMCopyrightß` and updates these variables accordingly.

### `5x86.inc`

Highly work-in-progress method(s) of patching 5x86 support into BIOSes.

Define `CPU_5X86_FIX_OERG866` before including.

You must alsoo define `CPU_5X86_STRING_TABLE_INDEX` which is an index in the CPU String list that points to an "unknown" string which will then be overridden with the 5x86 string.

## BIOS Mod Documentation

The documentation of AWARD BIOS structures is being written as development progresses and can be found here:

### [AWARD BIOS v4.5x Hacking Notes](wiki/AWARD-4.5x-hacking-notes)