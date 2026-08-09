; Some code to make it easier to add 5x86 support to AWARD 4.5x BIOSes.
; CPU_5X86_FIX_OERG866 must be defined,
; CPU_5X86_STRING_TABLE_INDEX must be defined

IFDEF CPU_5X86_FIX_OERG866
SEGLBL orig_NotX4, SEG_15, G_15, (CalculateBusSpeed+06h)
SEGLBL orig_DoCalc, SEG_15, G_15, (CalculateBusSpeed+18h)

    PATCH_CODE_START

    ORG offset CalculateBusSpeed
    FAR_JMP G_15, CalculateBusSpeed_o866

    ORG offset CODECAVE_ROMCopyright0
CalculateBusSpeed_o866:
    xor bh, bh
    mov ax, bx

    ; Is this quadruple clock?
    test byte ptr [bp+3Fh], 20h
    out 80h, al
    jz short NotX4
    mov     bl, 4
    FAR_JMP G_15, orig_DoCalc
NotX4:
    FAR_JMP G_15, orig_NotX4


CODECAVE_ROMCopyright0 = $

    PATCH_CODE_END


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; In case of a 94/95 BIOS, we can override the CPU detection ID
; including the string table value.
; Do note that you MOST LIKELY have to do manual patching
; to apply this ID somewhere, if your BIOS
; doesn't have a known entry to wedge support into
IFDEF CPU_5X86_STRING_TABLE_INDEX
    PATCH_CODE_START

    ORG (offset CPUNameTable)+(CPU_5X86_STRING_TABLE_INDEX * 2)
    dw CPUSTR_5x86

    ORG offset CODECAVE_ROMCopyright1
CPUSTR_5x86:    db 'Am5x86',0
CODECAVE_ROMCopyright1 = $

    PATCH_CODE_END
ENDIF 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; In case an incomplete extended AMD CPU check exists, update it

IFDEF FinalizeCPUSetup_IncompleteAMDCheck

    PATCH_CODE_START

    ORG offset CODECAVE_ROMCopyright1
AMDCheck5x86:
    ; Previous condition holds true, so in case we land here from there
    ; skip our ammended checks
    jz short AMDCheck5x86_Exit

    cmp ax, 04E0h                       ; 4E0 = 5x86 Write Through
    jnz short AMDCheck5x86_Not5x86_WT
    mov dh, 030h                        ; 4x multi, Green CPU
    jmp short AMDCheck5x86_SetID 

AMDCheck5x86_Not5x86_WT:
    cmp ax, 04F0h                       ; 4F0 = 5x86 Write Back
    jnz short AMDCheck5x86_Exit
    mov dh, 038h                        ; 4x multi, Green CPU, Write Back

AMDCheck5x86_SetID:
    mov dl, ((CPU_5X86_STRING_TABLE_INDEX * 2) OR 081h)

AMDCheck5x86_Exit:
    call CMOS_ApplyCPUFeatureBits
    retn

    CODECAVE_ROMCopyright1 = $

    ORG (offset FinalizeCPUSetup_IncompleteAMDCheck)+8
    ; instead of CMOS_ApplyCPUFeatureBits
    call AMDCheck5x86

    PATCH_CODE_END

ENDIF

ENDIF