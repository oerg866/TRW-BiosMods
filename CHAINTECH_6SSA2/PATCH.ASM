
INCLUDE ..\__scripts\macros.inc

.386p
.model small

    include unedited.inc

    INCLUDE CMN_FUNC.INC


; TRW Logo modification

TRW_HACK_ADDR_E_SEG EQU 0FF20h ; E Segment injection address
TRW_HACK_ADDR_F_SEG EQU 0E7E0h ; F Segment injection addreyss

    INCLUDE ..\__scripts\trw.inc

SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'
    ASSUME CS:G_15

;-----------------------------------------------------
; Modify version string
    org Str_BiosInfo
    db 'CT-6SSA2 Mod Bios v0.10 by E. Voirin (oerg866)',0

;-----------------------------------------------------
; Modify POST string
    org Str_BiosString
    db '08/30/2025-SiS-5600-8661-2A6ILC39C-TR'

; Modify setup menu string
    org Str_SetupMenuCopyright
    db 'www.theretroweb.com ', 0

SEG_15 ENDS

    END