
INCLUDE ..\__scripts\macros.inc

.586p
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

SEGLBL MemTestStart_CONT,   SEG_14, G_14, 0245Ah    ; Original MemTestStart Code continuation
SEGLBL MemTestStart_PATCH,  SEG_14, G_14, 0FFB0h    ; Our patched start of MemTestStart
SEGLBL MemTestEnd,          SEG_14, G_14, 024B1h    ; End of memtest code

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

;------------------------------------------------------
; Re-Implement CPU string getting to work with more CPU types

CPU_UNKN EQU 08f17h

    org GetCPUString
    jmp GetCPUString_P

    org 0fa00h
GetCPUString_P    proc near               ; CODE XREF: PrintPOSTStrings+46↑p
    mov si, CPU_UNKN

    ; Get CPUID String
    mov eax, 0
    cpuid
    cmp ebx, 'uneG'
    je GetCPUString_Intel   
    cmp ebx, 'iryC'
    je GetCPUString_Cyrix
    cmp ebx, ' AIV'
    je GetCPUString_Cyrix
    cmp ebx, 'tneC'
    je GetCPUString_Cyrix
    retn

GetCPUString_Intel:
    call    CPUID1
    push ax
    and ax, 0f00h   ; Family needs to be 6
    cmp ax, 0600h
    pop ax
    je _isValidIntel
    mov si, CPU_UNKN
    retn
    
_isValidIntel:
    ; Preset table
    mov si, CPUStringTable_Pentium
    and ax, 01ff0h  ; Filter stepping out


    cmp ax, 1630h   ; Pentium II Overdrive
    jne _noP2OD
    mov si, CPU_OD_1
    retn

_noP2OD:
    and ax, 00ff0h  ; Filter stepping out

    ; Check for Celeron (CuMine/Tualatin)
    cmp ax, 0680h
    jl _noCeleron

    ; Brand ID for Celeron = 01
    pushad
    mov eax, 1
    cpuid
    cmp bl, 01h
    popad
    jne _noCeleron

    mov si, CPUStringTable_Celeron
_noCeleron:

    ; Check for Celeron Covington
    ;pushad
    ;mov ecx, 11Eh ; Read L2 Control Register 3
    ;rdmsr
    ;test eax, 00800000h ; Covington disables this bit
    ;popad
    ;jz _noCovington

    pushad
    mov eax, 2  ; Cache info in EAX
    cpuid
    rol eax, 8
    cmp al, 40h
    popad

    jne _noCovington
    mov si, CPUStringTable_Celeron
_noCovington:

    ; Check for Celeron Mendocino
    cmp ax, 0660h
    jne _noMendocino
    mov si, CPUStringTable_Celeron
_noMendocino:

DisplayStringFromModelOffset:
    ; Get Model = index into the table
    shr ax, 4-1
    and ax, 01Eh
    add si, ax

    ; Get the string from the table
    push ds
    push cs
    pop ds
    mov si, [si]
    pop ds 
    retn

GetCPUString_Cyrix:
    call    CPUID1

    ; Ezra and Samuel 2 share the same model (7)..
    push ax
    and ax, 0ff0h
    cmp ax, 0670h
    pop ax
    jne _noEzra ; Not model 7

    ; It is model 7, check stepping
    cmp ax, 0678h
    jl _noEzra
    mov si, CPU_C3_4
    retn

_noEzra:
    mov si, CPUStringTable_Cyrix
    jmp DisplayStringFromModelOffset

; Klamath       633 631
; Deschutes     650 651 652 653
; Covington     650 651
; Mendocino     660 665
; Katmai        672 673
; CuMine        681 683 686 68a
; tualatin      6b1 6b4
CPUStringTable_Pentium:
    dw CPU_UNKN ; 0
    dw CPU_PP_1 ; 1
    dw CPU_UNKN ; 2
    dw CPU_P2_1 ; 3
    dw CPU_UNKN ; 4
    dw CPU_P2_2 ; 5
    dw CPU_UNKN ; 6
    dw CPU_P3_1 ; 7
    dw CPU_P3_2 ; 8
    dw CPU_UNKN ; 9
    dw CPU_UNKN ; A
    dw CPU_P3_3 ; B
    dw CPU_UNKN ; C
    dw CPU_UNKN ; D
    dw CPU_UNKN ; E
    dw CPU_UNKN ; F

; Covington     650 651
; Mendocino     660 665
; Katmai        672 673
; CuMine        681 683 686 68a
; tualatin      6b1 6b4
CPUStringTable_Celeron:
    dw CPU_UNKN ; 0
    dw CPU_UNKN ; 1
    dw CPU_UNKN ; 2
    dw CPU_UNKN ; 3
    dw CPU_UNKN ; 4
    dw CPU_CL_1 ; 5
    dw CPU_CL_2 ; 6
    dw CPU_UNKN ; 7
    dw CPU_CL_3 ; 8
    dw CPU_UNKN ; 9
    dw CPU_UNKN ; A
    dw CPU_CL_4 ; B
    dw CPU_UNKN ; C
    dw CPU_UNKN ; D
    dw CPU_UNKN ; E
    dw CPU_UNKN ; F

    
; Joshua        650
; Samuel        662 663
; Samuel 2      670 671 672 673
; Ezra          678 67A
; Ezra-T        68A
; Nehemiah(+)   69A
CPUStringTable_Cyrix:
    dw CPU_UNKN ; 0
    dw CPU_UNKN ; 1
    dw CPU_UNKN ; 2
    dw CPU_UNKN ; 3
    dw CPU_UNKN ; 4
    dw CPU_C3_1 ; 5
    dw CPU_C3_2 ; 6
    dw CPU_C3_3 ; 7
    dw CPU_C3_5 ; 8
    dw CPU_C3_6 ; 9
    dw CPU_UNKN ; A
    dw CPU_UNKN ; B
    dw CPU_UNKN ; C
    dw CPU_UNKN ; D
    dw CPU_UNKN ; E
    dw CPU_UNKN ; F

CPU_PP_1: db "Pentium ", V_HILITE, "PRO", V_NORMAL, 0
CPU_OD_1: db "Pentium ][ ", V_HILITE, "Overdrive", V_NORMAL, 0

CPU_P2_1: db "Pentium ][ ", V_HILITE, "Klamath", V_NORMAL, 0
CPU_P2_2: db "Pentium ][ ", V_HILITE, "Deschutes", V_NORMAL, 0

CPU_CL_1: db "Celeron ", V_HILITE, "Covington", V_NORMAL, 0
CPU_CL_2: db "Celeron ", V_HILITE, "Mendocino", V_NORMAL, 0
CPU_CL_3: db "Celeron ", V_HILITE, "Coppermine", V_NORMAL, 0
CPU_CL_4: db "Celeron ", V_HILITE, "Tualatin", V_NORMAL, 0

CPU_P3_1: db "Pentium !!! ", V_HILITE, "Katmai", V_NORMAL, 0
CPU_P3_2: db "Pentium !!! ", V_HILITE, "CuMine", V_NORMAL, 0
CPU_P3_3: db "Pentium !!! ", V_HILITE, "Tualatin", V_NORMAL, 0

CPU_C3_1: db "Cyrix III ", V_HILITE, "Joshua", V_NORMAL, 0
CPU_C3_2: db "Cyrix III ", V_HILITE, "Samuel", V_NORMAL, 0
CPU_C3_3: db "VIA C3 ", V_HILITE, "Samuel 2", V_NORMAL, 0
CPU_C3_4: db "VIA C3 ", V_HILITE, "Ezra", V_NORMAL, 0
CPU_C3_5: db "VIA C3 ", V_HILITE, "Ezra-T", V_NORMAL, 0
CPU_C3_6: db "VIA C3 ", V_HILITE, "Nehemiah(+)", V_NORMAL, 0

GetCPUString_P    endp

; Disable CPU name suffix printing (don't need ODP since we have it in the string)

    ORG FixupCPUNameSuffixes
    retn

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