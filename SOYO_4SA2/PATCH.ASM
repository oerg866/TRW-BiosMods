
INCLUDE ..\__scripts\macros.inc

.386p
.model small

    include unedited.inc

    INCLUDE CMN_FUNC.INC


; TRW Logo modification

TRW_HACK_ADDR_E_SEG EQU 0BF20h ; E Segment injection address
TRW_HACK_ADDR_F_SEG EQU 07FC0h ; F Segment injection address

    INCLUDE ..\__scripts\trw.inc

SEG_14 SEGMENT USE16 PARA PUBLIC 'CODE'
    ASSUME CS:G_14

;------------------------------------------------------
; Fix garbling of characters before "space" in the system font so we can show TRW monitor dot
    org 02BBFh
    ; int 10h <-- remove this instruction
    nop
    nop

SEG_14 ENDS

SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'
    ASSUME CS:G_15


;-----------------------------------------------------
; Modify version string
    org Str_BiosInfo
    db 'Soyo 4SA2 Mod Bios v0.92 by E. Voirin (oerg866)',0

;-----------------------------------------------------
; Modify POST string
    org 0EC71h
    db '05/10/24-SiS-496-497-TRW-2A4IBS2hC-00'

; Modify setup menu string
    org Str_SetupMenuCopyright
;   db 'AWARD SOFTWARE, INC.', 0
    db 'www.theretroweb.com ', 0

;------------------------------------------------------
;
; Setup Menu override 
    org 02A47h
; Main Menu
    MenuHeader <0304h, 0449h, 0140h>
; Standard CMOS Setup
    MenuHeader <5833h, 5D15h, 5758h>
; BIOS Features Setup
    MenuHeader <0BE4h, 0E0Ah, 0BC8h>
; ChipsetFeaturesSetup
    MenuHeader <offset MenuItems_ChipsetFeaturesSetup, offset MenuItems_ChipsetFeaturesSetup_End, 1124h> ; "Auto Configuration      : "
; PowerManagementSetup
    MenuHeader <1EA2h, 21A9h, 1E50h> ; "Power Management   : "
; PCI Config Setup
    MenuHeader <offset MenuItems_PCIConfigSetup, offset MenuItems_PCIConfigSetup_End, 261Ah>
; PNP Config Setup (N/A)
    MenuHeader <2A44h, 2A44h, 2A24h>

;------------------------------------------------------
;
; Fix boot with VLB cards

    org Sys_ChipsetInitTable+1Ch

;   Set pin mux config:
;   1X1 = MA11 PREQ3# PGNT3#
;   0 = Pin 207: LBD#, PIN 204: LRDY# 
    AwardChipsetRegisters <2, 57h, 28h, 7Fh, 0F7h>

SEG_15 ENDS

    include MENU_CFG.ASM
    include MENU_PCI.ASM


    END