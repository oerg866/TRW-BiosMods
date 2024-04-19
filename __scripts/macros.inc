; BIOS Hacking helper macros

FAR_JMP     MACRO SEGMENT, OFFSET
            DB 0EAh
            dw OFFSET
            dw SEGMENT
            ENDM

FAR_CALL    MACRO SEGMENT, OFFSET
            DB 090h, 09Ah
            DW OFFSET
            DW SEGMENT
            ENDM

POSTCODE MACRO CODE
            push ax
            mov al, CODE
            out 80h, al
            pop ax
            ENDM

AwardChipsetRegisters struc ; (sizeof=0x7, mappedto_1)
ItemType            db ?
Index               db ?
PCIDeviceFuncDev    db ?
RegMask             dw ?
Value               dw ?
AwardChipsetRegisters ends

MenuItem            struc ; (sizeof=0x19, mappedto_17)
ItemStatus          dw ?
ItemName            dw ?                    ; offset
ChipsetReg          dw ?
ChipsetRegMask      dw ?
CMOSLoc             db ?
CMOSMask            dw ?
FirstItemString     dw ?                    ; offset
MinVal              dw ?
MaxVal              dw ?
ItemX               db ?
ItemY               db ?
PowerOnDefault      dw ?
SetupDefault        dw ?
HelpString          dw ?                    ; offset
MenuItem            ends

MenuHeader      struc ; (sizeof=0x6, mappedto_11)                                                                                                     ; XREF: BIOS_F:PageOffset/r
                                                                                                                                                      ; BIOS_F:112F/r ...
PageStart       dw ?                                                                                                                                  ; offset (000F0000)
PageEnd         dw ?                                                                                                                                  ; offset (000F0000)
StartupString   dw ?                                                                                                                                  ; offset (000F0000)
MenuHeader      ends

LBL MACRO NAME, OFF
    ORG OFF
NAME:
    ENDM

SEGLBL MACRO NAME, SEG_LBL, CS_LBL, OFF
SEG_LBL SEGMENT USE16 PARA PUBLIC 'CODE'
    ASSUME CS:CS_LBL
    ORG offset OFF
NAME:
SEG_LBL ENDS
    ENDM

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; AWARD BIOS String stuff
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

V_DONE          EQU 0
V_DONE1         EQU 1
V_BORDER        EQU 2
V_CLEAR         EQU 3
V_STRSHOW       EQU 4
V_POS           EQU 5
V_HILITE        EQU 6
V_REVERSE       EQU 7
V_NORMAL        EQU 8
V_BLINK         EQU 9
V_WARN          EQU 0Ah
V_NEWLINE       EQU 0Bh
V_ADDX          EQU 0Ch
V_SUBX          EQU 0Dh
V_ADDY          EQU 0Eh
V_SUBY          EQU 0Fh
V_CALLROUTINE   EQU 10h

BP_TextAttr     EQU 080h

S_StrShow       struc ; (sizeof=0x5, mappedto_4)                                ; XREF: BIOS_F:62D9/r
                                                                                ; BIOS_F:62E5/r ...
field_0         db V_STRSHOW
x               db ?
y               db ?
string          dw ?                                                            ; offset
S_StrShow       ends

S_CallRoutine   struc
field_0         db V_CALLROUTINE        ; enum stringcodes
routine         dw ?                    ; offset (000F0000)
S_CallRoutine   ends

S_SetPos        struc
field_0         db V_POS
x               db ?
y               db ?
S_SetPos        ends