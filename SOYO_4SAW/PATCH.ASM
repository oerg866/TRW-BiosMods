
INCLUDE ..\__scripts\macros.inc

.386p
.model small

    include unedited.inc

SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'
    ASSUME CS:G_15
    

    org 0DE00h  ; Seems to be free
NewChipsetRegisters:
    AwardChipsetRegisters <2, 40h, 28h, 7Fh, 0>
    AwardChipsetRegisters <2, 41h, 28h, 9Fh, 1>
    AwardChipsetRegisters <2, 43h, 28h, 0Eh, 4>
    AwardChipsetRegisters <2, 45h, 28h, 0Dh, 0Bh>
    AwardChipsetRegisters <2, 55h, 28h, 0FFh, 0>
    AwardChipsetRegisters <2, 0D3h, 28h, 0FFh, 0>
    AwardChipsetRegisters <2, 56h, 28h, 0F7h, 1>
    AwardChipsetRegisters <2, 5Bh, 28h, 0FFh, 1>
    AwardChipsetRegisters <2, 5Ch, 28h, 0FFh, 64h>
    AwardChipsetRegisters <2, 5Dh, 28h, 0FFh, 0>
    AwardChipsetRegisters <2, 0D0h, 28h, 0FFh, 70h>
    AwardChipsetRegisters <2, 0C0h, 28h, 0FFh, 0>
    AwardChipsetRegisters <2, 0C1h, 28h, 0FFh, 0>
    AwardChipsetRegisters <2, 0C2h, 28h, 0FFh, 0>
    AwardChipsetRegisters <2, 0C3h, 28h, 0FFh, 0>
    AwardChipsetRegisters <2, 0C6h, 28h, 0Fh, 2>
    AwardChipsetRegisters <2, 75h, 0, 0D8h, 10h>
    ; These are PM entries (i think) from theSOYO board
    AwardChipsetRegisters <3, 0F1h, 10h, 0FFh, 0FFh>
    AwardChipsetRegisters <3, 0F2h, 10h, 48FFh, 0>
    AwardChipsetRegisters <3, 0F3h, 10h, 48FFh, 800h>
    AwardChipsetRegisters <3, 0F4h, 10h, 48FFh, 800h>
NewChipsetRegisters_End:

; Fix address in code

    org 00794h
;    mov     bx, offset Rom_Table
    mov     bx, offset NewChipsetRegisters
ProcessConfigRegsLoop:                  ; CODE XREF: BIOS_F:07B9↓j
;    cmp     bx, offset EndRom_Table ; "16MHZ, 2b"
    cmp     bx, offset NewChipsetRegisters_End

; Fix address in setup structure
    org 0F85Fh
    dw offset NewChipsetRegisters
    dw offset NewChipsetRegisters_End

    end