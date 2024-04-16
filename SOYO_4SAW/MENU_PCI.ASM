; ----------------------------------------------------------
; Mods for PCI CONFIGURATION menu

SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'
    ASSUME CS:G_15

    LBL BlankString, 03B00h


    ORG 060CCh
MenuItems_PCIConfigSetup:
    MenuItem <0, offset aPnpBiosAutoCon,    0FFFFh, 00010000b, 50h, 00010000b, offset aDisabled_2,  0,  1,  2,  4, 000h, 000h, offset BlankString> ; "PnP BIOS Auto-Config: " ; "Disabled"
    MenuItem <0, offset aSlot1UsingInt,     0FFFFh, 11100000b, 50h, 11100000b, offset aAuto_1,      0,  4,  2,  6, 000h, 000h, offset BlankString> ; "Slot 1 Using INT#   : " ; "AUTO"
    MenuItem <0, offset aSlot2,             0FFFFh, 00000111b, 50h, 00000111b, offset aAuto_1,      0,  4,  2,  7, 000h, 000h, offset BlankString> ; "Slot 2" ; "AUTO"
    MenuItem <0, offset aSlot3,             0FFFFh, 11100000b, 51h, 11100000b, offset aAuto_1,      0,  4,  2,  8, 000h, 000h, offset BlankString> ; "Slot 3" ; "AUTO"
    MenuItem <0, offset aSlot4,             0FFFFh, 00000111b, 51h, 00000111b, offset aAuto_1,      0,  4,  2,  9, 000h, 000h, offset BlankString> ; "Slot 4" ; "AUTO"
    MenuItem <0, offset a1stAvailableIr,    0FFFFh, 11110000b, 52h, 11110000b, offset aNa_0,        0, 0Fh, 2, 11, 090h, 090h, offset BlankString> ; "1st Available IRQ   : " ; "NA"
    MenuItem <0, offset a2nd,               0FFFFh, 00001111b, 52h, 00001111b, offset aNa_0,        0, 0Fh, 2, 12, 00Ah, 00Ah, offset BlankString> ; "2nd" ; "NA"
    MenuItem <0, offset a3rd,               0FFFFh, 11110000b, 53h, 11110000b, offset aNa_0,        0, 0Fh, 2, 13, 0B0h, 0B0h, offset BlankString> ; "3rd" ; "NA"
    MenuItem <0, offset a4th,               0FFFFh, 00001111b, 53h, 00001111b, offset aNa_0,        0, 0Fh, 2, 14, 00Ch, 00Ch, offset BlankString> ; "4th" ; "NA"

    MenuItem <0, offset aPciIrqActivedB,    0FFFFh, 00000001b, 54h, 00000001b, offset aEdge,    	0,  1,  2, 15, 000h, 000h, offset BlankString> ; "PCI IRQ Actived By  : " ; "Edge "
    MenuItem <0, offset aPciIdeIrqMapTo,    0FFFFh, 00001110b, 54h, 00001110b, offset aPciAuto,     0,  5,  2, 16, 000h, 000h, offset BlankString> ; "PCI IDE IRQ Map To  : " ; "PCI-AUTO "
    MenuItem <0, offset aPrimaryIdeInt,     0FFFFh, 00110000b, 54h, 00110000b, offset aA,           0,  3,  2, 17, 000h, 000h, offset BlankString> ; " Primary   IDE INT# : " ; "A"
    MenuItem <0, offset aSecondaryIdeIn,    0FFFFh, 11000000b, 54h, 11000000b, offset aA,           0,  3,  2, 18, 040h, 040h, offset BlankString> ; " Secondary IDE INT# : " ; "A"
    MenuItem <2, offset aMasterArbitrat,     2856h, 11000000b, 55h, 11000000b, offset aWeak,        0,  3,  2, 19, 000h, 000h, offset aAvailableOptio> ; "Master Arbitration Protocol : " ; "Weak  " ; "Available Options:\v"
    MenuItem <2, offset aCpuPciMemPostW,     2856h, 00100000b, 55h, 00000010b, offset aDisable_7,   0,  1,  2, 20, 000h, 000h, offset aAvailableOptio> ; "CPU->PCI Mem Post Write Buf : " ; "Disable" ; "Available Options:\v"
    MenuItem <2, offset aCpuPciMemoryBu,     2856h, 00010000b, 55h, 00000100b, offset aDisable_7,   0,  1,  2, 21, 000h, 000h, offset aAvailableOptio> ; "CPU->PCI Memory Burst Write : " ; "Disable" ; "Available Options:\v"
    MenuItem <2, offset aPciMasterBurst,     2857h, 10000000b, 55h, 00000001b, offset aDisable_7,   0,  1,  2, 22, 000h, 000h, offset aAvailableOptio> ; "PCI Master Burst Read/Write : " ; "Disable" ; "Available Options:\v"

    MenuItem <2, offset newDrvCAS,           2857h, 01000000b, 55h, 00100000b, offset newDrvopts,   0,  1, 42,  4, 000h, 000h, offset aAvailableOptio> 
    MenuItem <2, offset newDrvMA,            2857h, 00100000b, 55h, 00010000b, offset newDrvopts,   0,  1, 42,  5, 000h, 000h, offset aAvailableOptio> 
    MenuItem <2, offset newDrvMWE,           2857h, 00010000b, 55h, 00001000b, offset newDrvopts,   0,  1, 42,  6, 000h, 000h, offset aAvailableOptio> 
    MenuItem <2, offset newDrvSA,            28D4h, 00000100b, 56h, 10000000b, offset newDrvopts,   0,  1, 42,  7, 000h, 000h, offset aAvailableOptio> 
    MenuItem <2, offset newDrvIORW,          28D4h, 00000010b, 56h, 01000000b, offset newDrvopts,   0,  1, 42,  8, 000h, 000h, offset aAvailableOptio> 
    
    MenuItem <2, offset newPCIShadowAcc,     2845h, 00001000b, 56h, 00100000b, offset aDisable_7,   0,  1, 42, 10, 000h, 000h, offset aAvailableOptio> 

MenuItems_PCIConfigSetup_End:

    ORG ChipsetFeaturesStrings_End

newDrvCAS       db 'CAS Drive Strength          : ',0
newDrvMA        db 'MA  Drive Strength          : ',0
newDrvMWE       db 'MWE Drive Strength          : ',0
newDrvSA        db 'SA/SBHE Drive Strength      : ',0
newDrvIORW      db 'IOR/IOW Drive Strength      : ',0
newDrvopts      db '12 mA',0
                db '24 mA',0
newPCIShadowAcc db 'PCI/ISA Master Shad.RAM Acc.: ',0

aPnpBiosAutoCon db 'PnP BIOS Auto-Config: ',0                                   ; DATA XREF: BIOS_F:60CC↑o
aNa_0           db 'NA',0                                                       ; DATA XREF: BIOS_F:60CC↑o
                db '  ', V_DONE1
                db '  ', V_DONE1
a3_0            db '3 ',0
a4_0            db '4 ',0
a5              db '5 ',0
                db '  ', V_DONE1
a7              db '7 ',0
                db '  ', V_DONE1
a9              db '9 ',0
a10_0           db '10',0
a11             db '11',0
a12_0           db '12',0
                db '  ', V_DONE1
a14             db '14',0
a15_0           db '15',0
aSlot1UsingInt  db 'Slot 1 Using INT#   : ',0                                   ; DATA XREF: BIOS_F:60CC↑o
                                                                                ; BIOS_F:62D9↓o ...
aSlot2          db 'Slot 2'                                                     ; DATA XREF: BIOS_F:60CC↑o
                S_StrShow <V_STRSHOW, 0FFh, 0FFh, offset aSlot1UsingInt+6>      ; " Using INT#   : "
                db    0
aSlot3          db 'Slot 3'                                                     ; DATA XREF: BIOS_F:60CC↑o
                S_StrShow <V_STRSHOW, 0FFh, 0FFh, offset aSlot1UsingInt+6>      ; " Using INT#   : "
                db    0
aSlot4          db 'Slot 4'                                                     ; DATA XREF: BIOS_F:60CC↑o
                S_StrShow <V_STRSHOW, 0FFh, 0FFh, offset aSlot1UsingInt+6>      ; " Using INT#   : "
                db    0
aAuto_1         db 'AUTO',0                                                     ; DATA XREF: BIOS_F:60CC↑o
aA_0            db 'A   ',0
aB              db 'B   ',0
aC              db 'C   ',0
aD              db 'D   ',0
a1stAvailableIr db '1st Available IRQ   : ',0                                   ; DATA XREF: BIOS_F:60CC↑o
                                                                                ; BIOS_F:632A↓o ...
a2nd            db '2nd'                                                        ; DATA XREF: BIOS_F:60CC↑o
                S_StrShow <V_STRSHOW, 0FFh, 0FFh, offset a1stAvailableIr+3>     ; " Available IRQ   : "
                db    0
a3rd            db '3rd'                                                        ; DATA XREF: BIOS_F:60CC↑o
                S_StrShow <V_STRSHOW, 0FFh, 0FFh, offset a1stAvailableIr+3>     ; " Available IRQ   : "
                db    0
a4th            db '4th'                                                        ; DATA XREF: BIOS_F:60CC↑o
                S_StrShow <V_STRSHOW, 0FFh, 0FFh, offset a1stAvailableIr+3>     ; " Available IRQ   : "
                db    0
aPciIrqActivedB db 'PCI IRQ Actived By  : ',0                                   ; DATA XREF: BIOS_F:60CC↑o
aEdge           db 'Edge ',0                                                    ; DATA XREF: BIOS_F:60CC↑o
aLevel          db 'Level',0
aPciIdeIrqMapTo db 'PCI IDE IRQ Map To  : ',0                                   ; DATA XREF: BIOS_F:60CC↑o
aPciAuto        db 'PCI-AUTO ',0                                                ; DATA XREF: BIOS_F:60CC↑o
aIsa            db 'ISA      ',0
aPciSlot1       db 'PCI-SLOT1',0
aPciSlot2       db 'PCI-SLOT2',0
aPciSlot3       db 'PCI-SLOT3',0
aPciSlot4       db 'PCI-SLOT4',0
aPrimaryIdeInt  db ' Primary   IDE INT# : ',0                                   ; DATA XREF: BIOS_F:60CC↑o
aSecondaryIdeIn db ' Secondary IDE INT# : ',0                                   ; DATA XREF: BIOS_F:60CC↑o
aA              db 'A',0                                                        ; DATA XREF: BIOS_F:60CC↑o
aB_0            db 'B',0
aC_0            db 'C',0
aD_0            db 'D',0
aMasterArbitrat db 'PCI Arbitration Scheme : ',0                           ; DATA XREF: BIOS_F:60CC↑o
aWeak           db 'Weakest  ',0                                                  ; DATA XREF: BIOS_F:60CC↑o
                db 'Weak     ',0
                db 'Stronger ',0
                db 'Strongest',0
aCpuPciMemPostW db 'CPU->PCI Mem Post Write Buf : ',0                           ; DATA XREF: BIOS_F:60CC↑o
aCpuPciMemoryBu db 'CPU->PCI Memory Burst Write : ',0                           ; DATA XREF: BIOS_F:60CC↑o
aDisable_7      db 'Disable',0                                                  ; DATA XREF: BIOS_F:60CC↑o
aEnable_1       db 'Enable ',0
aPciMasterBurst db 'PCI Master Burst Read/Write : ',0                           ; DATA XREF: BIOS_F:60CC↑o


SEG_15 ENDS