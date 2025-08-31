
INCLUDE ..\__scripts\macros.inc

.386p
.model small

    include unedited.inc

    INCLUDE CMN_FUNC.INC


; TRW Logo modification

TRW_HACK_ADDR_E_SEG EQU 0FF20h ; E Segment injection address
TRW_HACK_ADDR_F_SEG EQU 0E7E0h ; F Segment injection addreyss

    INCLUDE ..\__scripts\trw.inc

SEG_14 SEGMENT USE16 PARA PUBLIC 'CODE'
    ASSUME CS:G_14

;------------------------------------------------------
; Make memory test EXTREMELY fast like it is in later AWARD BIOSes
; Backports Quick POST Memory Test from late Award 4.51 versions

SEGLBL MemTestStart_CONT,  SEG_14, G_14, 0245Ah    ; Original MemTestStart Code continuation
SEGLBL MemTestStart_PATCH, SEG_14, G_14, 0FFB0h    ; Our patched start of MemTestStart
SEGLBL MemTestEnd,      SEG_14, G_14, 024B1h    ; End of memtest code

; Original jump to MemtestStart, overwrite to our patch location
    org 2450h
    jnb MemTestStart_PATCH

; Patched start of P49_1 
    org MemTestStart_PATCH
    or al, al ; Quick POST?
    jz MemTestStart_CONT

; Quick Mem Test backport from later AWARD BIOSes
    mov dx, [bp+152h]
QuickMemTestLoop:
    call DisplayMemMsg
    jc MemTestEnd ; Test finished? If yes, get out
    add dx, 4 ; Next segment
    cmp dx, [bp+154h] ; RAM Done?
    jc short QuickMemTestLoop ; If not, loop
    jmp MemTestEnd ; Exit 

SEG_14 ENDS

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