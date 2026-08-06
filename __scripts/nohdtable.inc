; Include this file to remove the HDD preset parameter table suport.
; The BIOS' menu itself will be modified accordingly.
; Results in a free ~500 byte code cave.
; (C) 2026 Eric Voirin

SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'
; We put the strings for the menu override here
    ORG offset HDD_PresetTable


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Strings for 4.5x and 6.xx respectively
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

IF BIOS_VERSION LT 5000h
STR_None EQU 'None'
STR_Auto EQU 'Auto'
STR_User EQU 'User'
ELSE
STR_None EQU 'None  '
STR_Auto EQU 'Auto  '
STR_User EQU 'Manual'
ENDIF

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Preset entry count, seems like Auto is its own preset??
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

IFDEF BIOS_SupportsAutoDetect
PRESET_COUNT EQU 46
ELSE
PRESET_COUNT EQU 47
ENDIF

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; New item entries for HDD param table for each drive
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

HDDC_Items  db STR_None, 0
            db PRESET_COUNT dup (1)

IFDEF BIOS_SupportsAutoDetect
            db STR_Auto, 0
ENDIF
            db 1
            db STR_User, 0

HDDD_Items  db STR_None, 0
            db PRESET_COUNT dup (1)
IFDEF BIOS_SupportsAutoDetect
            db STR_Auto 0
ENDIF
            db STR_User, 0
            db 1

IFDEF BIOS_SupportsDualChannel

HDDE_Items  db STR_None, 0
            db PRESET_COUNT dup (1)
IFDEF BIOS_SupportsAutoDetect
            db STR_Auto 0
ENDIF
            db 1
            db 1
            db 1
            db STR_User, 0

HDDF_Items  db STR_None, 0
            db PRESET_COUNT dup (1)
IFDEF BIOS_SupportsAutoDetect
            db STR_Auto 0
ENDIF
            db 1
            db 1
            db STR_User, 0

ENDIF ; BIOS_SupportsDualChannel

; The free Code Cave:tm: starts here
CODECAVE_HDDParams LABEL BYTE

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Menu item overrides
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
HDD_MenuItem_Override MACRO where, newItems
    ORG (where)
    dw 0000000000000b                       ; Remove key-in and number showing support
    ORG (where) + 11
    dw offset newItems    ; Point string item selection to the table we made
    ENDM

    HDD_MenuItem_Override Menuitem_HDD_C, HDDC_Items
    HDD_MenuItem_Override Menuitem_HDD_D, HDDD_Items

IFDEF BIOS_SupportsDualChannel
    HDD_MenuItem_Override Menuitem_HDD_E, HDDE_Items
    HDD_MenuItem_Override Menuitem_HDD_F, HDDF_Items
ENDIF
SEG_15 ENDS
