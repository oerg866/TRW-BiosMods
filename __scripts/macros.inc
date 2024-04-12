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

LBL MACRO NAME, OFF
    ORG OFF
NAME:
            ENDM