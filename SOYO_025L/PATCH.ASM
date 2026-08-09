    INCLUDE ..\__scripts\macros.inc
    include baserom.inc
    INCLUDE CMN_FUNC.INC

    ; Code Caves:

    ; ----------- Common code caves
    ; 0000-00B1 - 178 Bytes - ROM Copyright start string
    ; E000-E04F - 80 Bytes - Unused copyright string
    ; E110-E14B - 60 Bytes - IBM Disclaimer
    ; ----------- BIOS Specific
    ; E29C-E2C2 - 39 bytes - Uninitialized
    ; EAE1-EAFF - 15 bytes - Uninitialized
    ; EC29-EC58 - 48 bytes - Uninitialized
    ; ECAF-ECCF - 33 bytes - Uninitialized
    ; F068-F0A3 - 60 bytes - Uninitialized
    ; F509-F54F - 71 bytes - Uninitialized
    ; Total: 660 bytes SAFE code caves
    ; Verdict: TIGHT

    ; Restore hidden options
    UNHIDE_OPTION Menuitem_HIDDEN_MaDriveCapacity
    UNHIDE_OPTION Menuitem_HIDDEN_DramWriteBurst
    UNHIDE_OPTION Menuitem_HIDDEN_SlowRefresh
    UNHIDE_OPTION Menuitem_HIDDEN_HiddenRefresh
    UNHIDE_OPTION Menuitem_HIDDEN_InternalCacheWbWt
    UNHIDE_OPTION Menuitem_HIDDEN_FastResetEmulation
    UNHIDE_OPTION Menuitem_HIDDEN_FastResetLatency
    UNHIDE_OPTION Menuitem_HIDDEN_LatchLocalBus
    UNHIDE_OPTION Menuitem_HIDDEN_LocalBusReady
    UNHIDE_OPTION Menuitem_HIDDEN_MemoryHoleSize
    UNHIDE_OPTION Menuitem_HIDDEN_DmaClock
    UNHIDE_OPTION Menuitem_HIDDEN_MemoryRelocation

    ; Remove HD presets to create space for PS/2 code
    include ..\__scripts\nohdtable.inc

    ; Add PS2 Mouse Support
    include ..\__scripts\mouse.inc

    ; Skip EPA logo fadeout animation
    include ..\__scripts\nofadeout.inc

    ; Fix HDD size/display limit
    include ..\__scripts\hddfix.inc

    ; Add 5x86 mouse support
    CPU_5X86_FIX_OERG866 = 1
    CPU_5X86_STRING_TABLE_INDEX = 6
    include ..\__scripts\5x86.inc

    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ; BIOS INFO / Copyright string
    PATCH_CODE_START

    ORG offset Str_BiosInfo
    S_CallRoutine <, offset SetCyan>
    db 'Soyo SY-025L Mod Bios (C) 2026 E. Voirin (oerg866)'
    db V_NEWLINE
    db 'V0.6 (', STRINGIFY(@Date), ')'
    db V_NORMAL
    db 0
    
SetCyan:
    mov byte ptr [bp+BP_TextAttr], 00Bh
    retn

    PATCH_CODE_END

    END
    