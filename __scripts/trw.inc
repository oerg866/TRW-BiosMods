
; .ERRNDEF TRW_HACK_ADDR "Must define TRW_HACK_ADDR to add TRW logo hack."
IF BIOS_VERSION EQ 04510h


PRINTCS     MACRO STRING
            mov si, offset STRING
            call Display_String_FAR_CS_SaveDX
            ENDM


SEG_14 SEGMENT USE16 PARA PUBLIC 'CODE'
    ASSUME CS:G_14

    ORG TRW_HACK_ADDR_E_SEG

TRWBorder:
    S_SetPos <,0,1>
    db V_NORMAL, ' ', V_REVERSE, '          ', V_NEWLINE

; ROW 1
    db V_NORMAL, ' ', V_REVERSE, ' '
    S_CallRoutine <,offset  SetGreen>
    db ' The    '
    S_CallRoutine <, offset SetGray>
    db V_REVERSE, ' ', V_NEWLINE
; ROW 2
    db V_NORMAL, ' ', V_REVERSE, ' '
    S_CallRoutine <, offset SetGreen>
    db ' Retro  '
    S_CallRoutine <, offset SetGray>
    db V_REVERSE, ' ', V_NEWLINE
; ROW 3
    db V_NORMAL, ' ', V_REVERSE, ' '
    S_CallRoutine <, offset SetGreen>
    db ' Web', V_BLINK, '_', V_NORMAL, '   '
    S_CallRoutine <, offset SetGray>
    db V_REVERSE, ' ', V_NEWLINE
    db V_NORMAL, ' ', V_REVERSE, '       '
    S_CallRoutine <, offset PrintMonitorDot>
    db '  ', V_NORMAL, V_NEWLINE
    db 0

TRWUrl:
    S_SetPos <, 12, 5>
    S_CallRoutine <, SetGreen>
    db 'http://theretroweb.com'
    S_CallRoutine <, SetGray>
    db V_NEWLINE, V_NEWLINE, 0


SetCursorAndPrint:
    call SetCursorPosition_FAR
    call Display_String_FAR_SaveDX
    ret

; Put AwardMan (Yes it's a ribbon, I know. F*** Off :D) in the right spot
    ORG offset DrawAwardRibbon+10
    mov dx, 0010Dh  ; Y = 01 | X = 0D
    ORG offset DrawAwardRibbon+26
    mov dx, 0020Ch  ; Y = 02 | X = 0C

    ORG PrintPOSTStrings

    PRINTCS TRWBorder
    mov dx, 00110h
    mov si, offset Str_AwardBiosVersion
    call SetCursorAndPrint
    mov dx, 00210h
    mov si, Str_Copyright
    call SetCursorAndPrint
    mov dx, 0040Ch
    mov si, Str_BiosInfo
    call SetCursorAndPrint
    PRINTCS TRWURL
    jmp short PrintPOSTStrings + 02Bh



SEG_14 ENDS



SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'

    org TRW_HACK_ADDR_F_SEG

SetGreen:
    mov byte ptr [bp+BP_TextAttr], 00Ah ; Green foreground Color
    retn
    
SetGray:
    mov byte ptr [bp+BP_TextAttr], 007h ; Green foreground Color
    retn

PrintMonitorDot:
    mov     al, 07h ; this weirdo [o] character
    call    Write_Character
    ret


SEG_15 ENDS

endif