; BIOS Hacking helper macros

FAR_JMP     MACRO SEGMENT, OFFSET
            DB 0EAh
            dw OFFSET
            dw SEGMENT
            ENDM

FAR_CALL    MACRO SEGMENT, OFFSET
            DB 09Ah
            DW OFFSET
            DW SEGMENT
            ENDM

POSTCODE MACRO CODE
            push ax
            mov al, CODE
            out 80h, al
            pop ax
            ENDM

MESSAGE MACRO MODULE, TEXT
    ECHO ----------------------------------------
    ECHO [ MODULE ] TEXT
    ECHO ----------------------------------------
    ENDM

PATCH_CODE_START MACRO
    SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'
    ENDM

PATCH_CODE_END MACRO
    SEG_15 ENDS
    ENDM

STRINGIFY MACRO arg
    LOCAL foo
    foo CATSTR <'>,arg,<'>
    EXITM foo
ENDM

IODELAY macro
    jmp short $+2
    jmp short $+2
    endm

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
; AWARD BIOS Menu stuff
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
ITEM_Disabled EQU 1000b

UNHIDE_OPTION MACRO where
    PATCH_CODE_START

    ORG offset where
    dw &where&_FLAGS AND (NOT ITEM_Disabled)

    PATCH_CODE_END
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

CPU_Support_Entry_486 struc
CMOS_PROC_ID_3D db ?
CMOS_DATA_3F    db ?
ResetID_FROM    dw ?
ResetID_TO      dw ?
CPU_Support_Entry_486 ends


; A conditional NEAR JUMP, 386+

_JNZ    macro WHERE
    db 0fh, 085h
    dw (offset WHERE)-$-2
    endm

_JZ    macro WHERE
    db 0fh, 084h
    dw (offset WHERE)-$-2
    endm

_JA     macro WHERE
    db 0fh, 087h
    dw (offset WHERE)-$-2
    endm


; Misc Constants
KBC_DataPort            EQU 60h ; Keyboard controller data port
Bios_RAM_Segment        EQU 40h ; BIOS internal RAM segment

RAM_ExtData_Segment_ID  EQU 0Eh ; 40:0E Offset in BIOS RAM that contains the extended data segment identifier
RAM_Bios_Hardware       EQU 10h ; 40:10 Installed hardware


; Common Code Caves
CODECAVE_ROMCopyright0 = 0
CODECAVE_ROMCopyright1 = 0E000h

; Always use 286 except for special instructions
.286
.MODEL SMALL
