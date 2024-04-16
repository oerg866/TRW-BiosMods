
INCLUDE ..\__scripts\macros.inc

.386p
.model small

    include unedited.inc

SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'
    ASSUME CS:G_15

;-----------------------------------------------------
; Modify version string
    org 0E0C1h
    db 'theretroweb.com - Soyo 4SAW Mod Bios v0.96 - by oerg866',0

;-----------------------------------------------------
; Modify POST string
    org 0EC71h
    db '04/16/24-SiS-496-497-TRW-2A4IBS29C-00'

; Modify setup menu string
    org 02AE4h
;   db 'AWARD SOFTWARE, INC.', 0
    db 'www.theretroweb.com ', 0

;------------------------------------------------------
;
; Setup Menu override 
    org 01129h
; Main Menu
    MenuHeader <2B48h, 2CA6h, 2984h>
; Standard CMOS Setup
    MenuHeader <361Eh, 3B00h, 3514h>
; BIOS Features Setup
    MenuHeader <45CAh, 4809h, 45AEh>
; ChipsetFeaturesSetup
    MenuHeader <offset MenuItems_ChipsetFeaturesSetup, offset MenuItems_ChipsetFeaturesSetup_End, 4B3Ah>
; PowerManagementSetup
    MenuHeader <5934h, 5C3Bh, 58E2h>
; PCI Config Setup
    MenuHeader <offset MenuItems_PCIConfigSetup, offset MenuItems_PCIConfigSetup_End, 60ACh>
; PNP Config Setup (N/A)
    MenuHeader <64d6h, 64d6h, 64b6h>

SEG_15 ENDS

    include MENU_CFG.ASM
    include MENU_PCI.ASM

    END