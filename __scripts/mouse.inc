; Mouse Handler Implementation
; To add mouse support to old BIOSes
; Original code by AWARD software
; Modifications by oerg866

Mouse_FarCallOffset     EQU 22h
Mouse_FarCallSegment    EQU 24h
Mouse_CountIndex        EQU 26h
Mouse_PacketSizeFlags   EQU 27h     ; Packet Size and Flags
Mouse_DriverFarCallFlag EQU 080h    ; ^ Bit 7 set = Device Driver Far Call routine is set
Mouse_AuxData           EQU 28h     ; 28 - 2F Mouse Aux Data Buffer

; KBC Aux/Mouse Return Codes
KBC_Aux_Code_SelfTestOK EQU 0AAh
KBC_Aux_Code_Resend     EQU 0FEh
KBC_Aux_Code_Ack        EQU 0FAh
KBC_Aux_Code_Error      EQU 0FCh

; KBC Aux/Mouse Command Codes
Cmd_ResetScaling        EQU 0E6h
Cmd_SetScaling          EQU 0E7h
Cmd_SetResolution       EQU 0E8h
Cmd_StatusRequest       EQU 0E9h
Cmd_SetStreamMode       EQU 0EAh
Cmd_ReadData            EQU 0EBh
Cmd_ResetWrapMode       EQU 0ECh
Cmd_SetWrapMode         EQU 0EEh
Cmd_SetRemoteMode       EQU 0F0h
Cmd_ReadDeviceType      EQU 0F2h
Cmd_SetSamplingRate     EQU 0F3h
Cmd_EnableData          EQU 0F4h
Cmd_DisableData         EQU 0F5h
Cmd_SetDefault          EQU 0F6h
Cmd_Resend              EQU 0FEh
Cmd_Reset               EQU 0FFh

KBC_WriteCMD            EQU 60h

Int15h_AH_Success               EQU 00h
Int15h_AH_InvalidFunction       EQU 01h
Int15h_AH_InvalidInput          EQU 02h
Int15h_AH_InterfaceError        EQU 03h
Int15h_AH_Resend                EQU 04h
Int15h_AH_NoFarCallInstalled    EQU 05h

; Int15h Function C2 Stack Frame (INPUT)
Int15h_C2_BP_SubFunction    EQU byte ptr [bp+10h] ; al
Int15h_C2_BP_Command        EQU byte ptr [bp+0fh] ; bh
Int15h_C2_BP_Segment        EQU word ptr [bp+02h] ; es
Int15h_C2_BP_Offset         EQU word ptr [bp+0eh] ; bx
; Int15h Function C2 Stack Frame (OUTPUT)
Int15h_C2_BP_Flags          EQU word ptr [bp+16h]
Int15h_C2_BP_Error          EQU byte ptr [bp+11h] ; ah
Int15h_C2_BP_bh             EQU byte ptr [bp+0fh] ; bh
Int15h_C2_BP_bl             EQU byte ptr [bp+0eh] ; bl
Int15h_C2_BP_cl             EQU byte ptr [bp+0ch] ; cl
Int15h_C2_BP_dl             EQU byte ptr [bp+0ah] ; dl


SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'

    org 0

IRQ12_New:
;;    push ax
;;    push bx
;;    push cx
;;    push si
;;    push di
;;    push bp
    pusha
    push ds
    push es
    cld
    in al, KBC_DataPort
    sti

    mov bx, Bios_RAM_Segment
    mov ds, bx

    mov bx, ds:RAM_ExtData_Segment_ID
    mov ds, bx
    assume ds:nothing   ; <-- why?
    mov bl, ds:Mouse_CountIndex
    and byte ptr ds:Mouse_CountIndex, 0f8h  ; Clear count index
    xor bh, bh
    and bl, 7

    ; Set mouse data
    mov ds:Mouse_AuxData[bx], al
    ; Get packet size
    mov bh, ds:Mouse_PacketSizeFlags
    and bh, 7
    ; If complete packet was received, do a far call
    inc bl
    cmp bl, bh
    ja IRQ12_DoFarCall
    ; If not, set new Count Index
    or ds:Mouse_CountIndex, bl
    ; Check data packet
    call Mouse_CheckDataPacket
    ; End the interrupt
    jmp short IRQ12_Exit

    ; Do far call for mouse driver
IRQ12_DoFarCall:
    ; If a mouse driver routine isn't installed, get out
    test byte ptr ds:Mouse_PacketSizeFlags, Mouse_DriverFarCallFlag
    jz short IRQ12_Exit

    ; Put packet size into bx
    xchg bl, bh
    xor bh, bh
    ; Prepare loop
    mov cx, bx
    inc cx
    ; Get Translation Table Address for our packet size
    mov si, bx
    shl si, 1
    lea bx, PacketSizeTable
    mov bx, word ptr cs:[bx+si]

    ; Set and clear stack
    xor ax, ax
    push ax
    push ax
    push ax
    push ax
    mov bp, sp
    mov si, Mouse_AuxData

IRQ12_SetStackLoop:
    ; Get stack relative position
    mov al, cs:[bx]
    mov di, ax
    ; Get mouse data and store it in stack
    lodsb
    mov [bp+di], al
    inc bx
    loop IRQ12_SetStackLoop
    ; Call driver service
    call dword ptr ds:Mouse_FarCallOffset
    add sp, 8

IRQ12_Exit:
    ; End of interrupt
    cli
    mov al, 20h
    out 0a0h, al
    out 0e1h, ax
    out 020h, al
    pop es
    pop ds
;;    pop bp
;;    pop di
;;    pop si
;;    pop cx
;;    pop bx
;;    pop ax
    popa
    iret

Mouse_CheckDataPacket:
    ; Loop count
    mov cx, 5*33
Mouse_CheckDataPacket_Loop:
    in al, 64h
    IODELAY
    sti
    ; TODO - Check what status code is being checked here
    ; Is KBC ready?
    and al, 21h
    cmp al, 21h ; '!'
    jz short Mouse_CheckDataPacket_End
    push cx
    push bx
    mov cx, 1
    xor bx, bx
    call Wait_Refresh
    pop bx
    pop cx
    loop Mouse_CheckDataPacket_Loop

    and byte ptr ds:Mouse_CountIndex, 0f8h
;;    mov ax, ds
;;    mov es, ax
    push ds
    pop es
    assume es:nothing
    cld

; Clear aux data buffer
;;    lea di, ds:Mouse_AuxData
    mov di, offset Mouse_AuxData
    xor ax, ax
    stosw
    stosw
    stosw
    stosw
Mouse_CheckDataPacket_End:
    retn
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15 Handler Code

Int15h_MouseFunction:
; [o866] I think this may be an archaic leftover and we can just assume this
; so get rid of it
IF 0
    ; this checks for "wait for external event supported"
    ; is this really necessary? could save some bytes
    test cs:Sys_BiosConfigTable+5, 4
    jnz short Int15h_MouseFunction_Process
    jmp Int15h_ContinueProcessing
ENDIF

; ---------------------------------------------------------------------------
Int15h_MouseFunction_Process:
    ; Check if mouse present
    push es
    push Bios_RAM_Segment
    pop es
    assume es:nothing
    test byte ptr es:RAM_Bios_Hardware, 4
    pop es
    assume es:nothing
    ; Mouse present, continue
    jnz short Int15h_MousePresent
    ; Mouse not present, go back to int15 main path
    jmp Int15h_ContinueProcessing

Int15h_MousePresent:

; [o866] size opt
;    cmp ah, 0C1h
;    jz Int15h_C1_Handler
;    jmp Int15h_C2_Handler
    cmp ah, 0C2h
    jz short Int15h_C2_Handler
    ; fallthrough

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h Function C1 Handler - Get Extended Data Segment
Int15h_C1_Handler:
; [o866] size opt
;    push ax
;    mov ax, 40h
;    mov es, ax
;    assume es:nothing
;    mov ax, es:RAM_ExtData_Segment_ID
;    mov es, ax
;    assume es:nothing
;    pop ax
;    iret
    push Bios_RAM_Segment
    pop es
    push [word ptr es:RAM_ExtData_Segment_ID]
    pop es
    iret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h Function C2 Handler - Pointing Device Interface
Int15h_C2_Handler:
    ; is function valid?
    test al, 0F8h
    jz short Int15h_C2_FunctionIsValid
    ; Function is invalid, exit
    mov ah, Int15h_AH_InvalidFunction
    stc
    retf 2

Int15h_C2_FunctionIsValid:
    ; Function is valid, continue processing
    ; Build a stack frame
    push ax   ; [bp+10]
    push bx   ; [bp+0e]
    push cx   ; [bp+0c]
    push dx   ; [bp+0a]
    push si   ; [bp+08]
    push di   ; [bp+06]
    push ds   ; [bp+04]
    push es   ; [bp+02]
    push bp   ; [bp+00]
    mov bp, sp

    ; [o866] size opt
    ; Disable Aux output buffer full (AOBF) interrupt
    call DisableAOBFIrq
    push Bios_RAM_Segment
    pop ds
    push [word ptr ds:RAM_ExtData_Segment_ID]
    pop ds
;;    ; Set ES to BIOS RAM segment (0040)
;;    mov ax, Bios_RAM_Segment
;;    mov es, ax
;;    ; Set DS to XBDA Segment (get from 40:0E)
;;    mov ax, es:RAM_ExtData_Segment_ID
;;    mov ds, ax

;; [o866] size opt
    ; Check mouse flag again (we already did this, WTF Award)
;;    test byte ptr es:RAM_Bios_Hardware, 4
;;    jz Int15h_C2_InterfaceError
    ; get entry in subfunction address table and jump to it
    xor ah, ah
    mov al, Int15h_C2_BP_SubFunction
    shl ax, 1
    mov si, offset Int15h_C2_SubFunctionTable
    add si, ax
    jmp word ptr cs:[si]

; Error handling
Int15h_C2_Success:
;;    mov Int15h_C2_BP_Error, Int15h_AH_Success
;;    mov al, Int15h_AH_Success ; actually ...
    xor al, al
    and Int15h_C2_BP_Flags, 0fffeh 
    jmp short Int15h_C2_Exit
Int15h_C2_InvalidFunctionError:
;;    mov Int15h_C2_BP_Error, Int15h_AH_InvalidFunction
    mov al, Int15h_AH_InvalidFunction
    jmp short Int15h_C2_ErrorExit
Int15h_C2_InvalidInputError:
;;    mov Int15h_C2_BP_Error, Int15h_AH_InvalidInput
    mov al, Int15h_AH_InvalidInput
    jmp short Int15h_C2_ErrorExit
Int15h_C2_InterfaceError:
;;    mov Int15h_C2_BP_Error, Int15h_AH_InterfaceError
    mov al, Int15h_AH_InterfaceError
    jmp short Int15h_C2_ErrorExit
Int15h_C2_NoFarCallInstalledError:
;;    mov Int15h_C2_BP_Error, Int15h_AH_NoFarCallInstalled
    mov al, Int15h_AH_NoFarCallInstalled
Int15h_C2_ErrorExit:
    ; Set carry flag in stack frame
    or Int15h_C2_BP_Flags, 01h
Int15h_C2_Exit:
    ;; [o866] size opt, we expect error code in al here
    mov Int15h_C2_BP_Error, al
    ; Re-Enable AOBF IRQ
    call EnableAOBFIrq
    ; Restore stack & exit
    pop bp
    pop es
    pop ds
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    iret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 0: Enable/Disable mouse
; bh: 0 = disable, 1 = enable
; cf: 0 = no error, 1 = error
Int15h_C2_EnableDisableMouse:
;;    mov al, Int15h_C2_BP_Command
    ;; bh is untouched at this point, I think
    mov al, bh
    test al, 0FEh
    jnz short Int15h_C2_InvalidFunctionError
    test byte ptr ds:Mouse_PacketSizeFlags, Mouse_DriverFarCallFlag
    jz short Int15h_C2_NoFarCallInstalledError
    xor al, 1
    add al, 0F4h
;;    call Out_8042_Aux
;;    jnz short Int15h_C2_InterfaceError
    ;; [o866] we can assume that if this call returns, it was successful.
    call Out_8042_Aux_NoReturnOnError

;; HACKY - Wait Ack and exit jump point
Int15h_C2_WaitAckAndExit:
    call Int15h_C2_WaitAck
    jmp short Int15h_C2_Exit

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 1: Reset Pointing Device
; cf: 0 = no error, 1 = error
Int15h_C2_ResetMouse:
    ; clear mouse packet buffer before sending
    and byte ptr ds:Mouse_PacketSizeFlags,0f8h

;; [o866] notes
;; So they use CL for the loop counter...
;; Going as far as push/popping cx when calling Out_8042_Aux
;; but they are NOT using the loop instruction? then what's the point on insisting on cl
;; two options:
;; 1. make counter bl (out_8042_aux saves BX) and remove push/pop, saves 2 bytes
;; 2. replace dec cl jz short with loop short, saves 2 bytes but ch needs to be cleared...
;; so probably option 1 is better...

;;    mov cl, 10   ; number of retry
    mov bl, 10
Int15h_C2_ResetMouse_TryLoop:
;;    push cx
    mov al, Cmd_Reset  ; reset mouse command
    call Out_8042_Aux
;;    pop cx
    ; Sending command failed - I/F error
    jnz short Int15h_C2_InterfaceError

    ; Wait for Ack
    call Int15h_C2_WaitAck
    ; Ack received? Get out
    jz short Int15h_C2_ResetMouse_GetID

    ; If not, loop
;;    dec cl
    dec bl
    jnz short Int15h_C2_ResetMouse_TryLoop

    ; !!!!!!!!!!!!!!!!!!!!!!!!
    ; Timeout occurred
    ; Set flags and exit
;;    or Int15h_C2_BP_Flags, 0    ;; waitack already affects the flags... is this really necessary? 
    jmp short Int15h_C2_Exit

Int15h_C2_ResetMouse_GetID:
    ; Read Aux Buffer Data First byte
;;    call ReadAuxData
;;    ; Read failed? Get out
;;    jz short Int15h_C2_InterfaceError
;;    ; Read OK
;;    mov Int15h_C2_BP_bl, al
;;
;;    ; Do this once more for 2nd byte
;;    call ReadAuxData
;;    jz short Int15h_C2_InterfaceError
;;    mov Int15h_C2_BP_bh, al

;; [o866] we can assume that if this call returns, it was successful.
    call ReadAuxData_NoReturnOnError
    mov Int15h_C2_BP_bl, al
    call ReadAuxData_NoReturnOnError
    mov Int15h_C2_BP_bh, al
    jmp Int15h_C2_Success

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 2: Set Sampling Rate
; bh on stack frame = sample rate table index
; cf: 0 = no error, 1 = error
Int15h_C2_SetSamplingRate:
    ; Check if input is valid
    ;; bh is untouched at this point, I think
;;    cmp Int15h_C2_BP_Command, 06
    cmp bh, 6
    ja short Int15h_C2_InvalidInputError
    ; Input is valid, send command
    mov al, Cmd_SetSamplingRate
;;    call Out_8042_Aux
;;    ; Sending failed, get out
;;    jnz short Int15h_C2_InterfaceError
    ;; [o866] we can assume that if this call returns, it was successful.
    call Out_8042_Aux_NoReturnOnError

    ; Wait for response
    call Int15h_C2_WaitAck
    ; Response error? get out
    jnz short Int15h_C2_Exit
    ; Get report rate based on index value
    ;; lea si, cs:Int15h_C2_SampleRateTable
    mov si, offset Int15h_C2_SampleRateTable
;;    xor ah, ah
;;    mov al, Int15h_C2_BP_Command
;;  I think bh is still untouched at this moment

    ;; Sorry.... too hacky :)
    .386
    movzx ax, bh
    .286

    add si, ax
    lods byte ptr cs:[si]

;;    ; Send the new rate to the mouse
;;    call Out_8042_Aux
;;    ; Sending OK? Continue
;;    jz short Int15h_C2_SetSamplingRate_SendOK
;;    ; Sending failed, get out
;;    jmp Int15h_C2_InterfaceError
    ;; [o866] we can assume that if this call returns, it was successful.
    call Out_8042_Aux_NoReturnOnError
Int15h_C2_SetSamplingRate_SendOK:
;;    ; wait for the response and set result flags accordingly
;;    call Int15h_C2_WaitAck
;;    ; WaitAck sets the appropriate error fields, so no need to handle them here
;;    jmp Int15h_C2_Exit
    jmp Int15h_C2_WaitAckAndExit


; Sample Rate Table (Reports per second)
Int15h_C2_SampleRateTable:
    db 0ah  ; 00 = 10  reports/second
    db 14h  ; 01 = 20  reports/second
    db 28h  ; 02 = 40  reports/second
    db 3ch  ; 03 = 60  reports/second
    db 50h  ; 04 = 80  reports/second
    db 64h  ; 05 = 100 reports/second
    db 0c8h ; 06 = 200 reports/second

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 3: Set Resolution
; bh on stack frame = Resolution value
; cf: 0 = no error, 1 = error
Int15h_C2_SetResolution:
;;    cmp Int15h_C2_BP_Command, 3
    cmp bh, 3
;;    jbe short Int15h_C2_SetResolution_ValidInput
;;    jmp Int15h_C2_InvalidInputError  ; invalid input
    ja Int15h_C2_InvalidInputError
Int15h_C2_SetResolution_ValidInput:
    ; Send Command
    mov al, Cmd_SetResolution
;;    call Out_8042_Aux
;;    ; Send ok? Continue
;;    jz short Int15h_C2_SetResolution_CmdSendOK
;;    ; Send failed, get out
;;    jmp Int15h_C2_InterfaceError
    ;; [o866] we can assume that if this call returns, it was successful.
    call Out_8042_Aux_NoReturnOnError
Int15h_C2_SetResolution_CmdSendOK:
    ; Wait for CMD's Ack
    call Int15h_C2_WaitAck
    jnz Int15h_C2_Exit
;;    ; OK? Continue
;;    jz short Int15h_C2_SetResolution_CmdAckOK
;;    ; Ack failed, get out
;;    jmp Int15h_C2_Exit
Int15h_C2_SetResolution_CmdAckOK:
    ; Send actual parameter
;;    mov al, Int15h_C2_BP_Command
;;  I think bh is still untouched at this moment
    mov al, bh

;;    call Out_8042_Aux
;;    ; OK? Continue
;;    jz short Int15h_C2_SetResolution_ParamSendOK
;;    ; Param send error
;;    jmp Int15h_C2_InterfaceError
    ;; [o866] we can assume that if this call returns, it was successful.
    call Out_8042_Aux_NoReturnOnError
Int15h_C2_SetResolution_ParamSendOK:
 ;;   ; wait for the response and set result flags accordingly
 ;;   call Int15h_C2_WaitAck
 ;;   ; WaitAck sets the appropriate error fields, so no need to handle them here
 ;;   jmp Int15h_C2_Exit
    jmp Int15h_C2_WaitAckAndExit

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 4: Read Aux Device Type
; cf: 0 = no error, 1 = error
Int15h_C2_ReadDeviceType:
    mov al, Cmd_ReadDeviceType
;;    call Out_8042_Aux
;;    ; Send ok, continue
;;    jz short Int15h_C2_ReadDeviceType_SendOK
;;    ; Send failed, get out
;;    jmp Int15h_C2_InterfaceError
    ;; [o866] we can assume that if this call returns, it was successful.
    call Out_8042_Aux_NoReturnOnError
Int15h_C2_ReadDeviceType_SendOK:
    ; Wait for Ack
    call Int15h_C2_WaitAck
    ; Ack OK? Continue
    jz short Int15h_C2_ReadDeviceType_AckOK
    ; No Ack - Exit
    jmp Int15h_C2_Exit
Int15h_C2_ReadDeviceType_AckOK:
;;    call ReadAuxData
;;    jz short Int15h_C2_ReadDeviceType_ReadFailed
    call ReadAuxData_NoReturnOnError
    ; Read OK, set result & get out
    mov Int15h_C2_BP_bh, al
    jmp Int15h_C2_Success
;;Int15h_C2_ReadDeviceType_ReadFailed:
;;    ; Read failed = I/F error
;;    jmp Int15h_C2_InterfaceError

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 5: Mouse Initialization
; bh on stack frame = packet size (1-8 bytes)
; cf: 0 = no error, 1 = error
Int15h_C2_MouseInit:
    ; Check supplied packet size
;;    or Int15h_C2_BP_Command, 0
;;    jz short Int15h_C2_MouseInit_InvalidInput
;;    cmp Int15h_C2_BP_Command, 8
;;    ; size <= 8? -> valid
;;    jbe short Int15h_C2_MouseInit_Valid
;;    ; Invalid: fallthrough
;;Int15h_C2_MouseInit_InvalidInput:
;;    ; Invalid input -> error
;;    jmp Int15h_C2_InvalidInputError
    dec bh  ;; so a zero which is invalid would become 0FFh, thus the unsigned comparison catches all
    cmp bh, 7
    ja Int15h_C2_InvalidInputError

Int15h_C2_MouseInit_Valid:
    ; Zero old packet size and set to new value
    and byte ptr ds:Mouse_PacketSizeFlags, 0f8h
;;    mov al, Int15h_C2_BP_Command
;;    dec al
;;    or byte ptr ds:Mouse_PacketSizeFlags, al
    ;; bh has our corrected value already
    or byte ptr ds:Mouse_PacketSizeFlags, bh

    ; Try reset command 3 times
    mov bh, 3
Int15h_C2_MouseInit_TryLoop:
    ; Send command
    mov al, Cmd_Reset 
    call Out_8042_Aux
;;    ; Send OK? Exit loop
;;    jz short Int15h_C2_MouseInit_SendOK
;;    ; Send failed -> Error
;;    jmp short Int15h_C2_MouseInit_Error
    jnz short Int15h_C2_MouseInit_Error

Int15h_C2_MouseInit_SendOK:
    ; Wait for ack, set status
    call Int15h_C2_WaitAck
    ; Send failed? -> Get out
    jnz short Int15h_C2_MouseInit_Error
    ; Try to read first byte from aux device
    call ReadAuxData
    ; Read failed? -> Get out
    jz short Int15h_C2_MouseInit_Error
    ; Try to read second byte from aux device
    call ReadAuxData
    ; Read OK? -> Finished
;;    jnz short Int15h_C2_MouseInit_Success
    jnz Int15h_C2_Success
    ; Fallthrough on error
Int15h_C2_MouseInit_Error:
    ; On error -> loop & retry
    dec bh
    jnz short Int15h_C2_MouseInit_TryLoop
    ; Failed after 3 loops -> Error
    jmp Int15h_C2_InterfaceError

;;Int15h_C2_MouseInit_Success:
;;    ; Everything OK!
;;    jmp Int15h_C2_Success

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 6: Extended Commands
; bl on stack frame = Extended Command
;   -> 0 = return status, 1 = set scale to 1:1, 2 = set scale to 2:1
; cf: 0 = no error, 1 = error
Int15h_C2_ExtendedCommand:
;;    mov al, Int15h_C2_BP_Command
;;    or al,al
    or bh, bh
    jz short Int15h_C2_ExtendedCommand_GetStatus
;;    dec al
    dec bh
    jz short Int15h_C2_ExtendedCommand_Scale11
;;    dec al
    dec bh
    jz short Int15h_C2_ExtendedCommand_Scale21
    jmp Int15h_C2_InvalidFunctionError  ; invalid subfunction

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 6, 0: Get status
; The format of this is complex and I have no clue about it
; but the result is put in BL, CL and DL on the stack frame
Int15h_C2_ExtendedCommand_GetStatus:
    ; Send status request command to aux device
    mov al, Cmd_StatusRequest
;;    call Out_8042_Aux
;;    ; sent ok? continue
;;    jz short Int15h_C2_ExtendedCommand_GetStatus_SendOK
;;    ; sending failed, get out
;;    jmp Int15h_C2_InterfaceError
    ;; [o866] we can assume that if this call returns, it was successful.
    call Out_8042_Aux_NoReturnOnError
Int15h_C2_ExtendedCommand_GetStatus_SendOK:
    call Int15h_C2_WaitAck  ; wait response and set status
;;    jz short Int15h_C2_ExtendedCommand_GetStatus_AckOK
;;    jmp Int15h_C2_Exit
    jnz Int15h_C2_Exit
Int15h_C2_ExtendedCommand_GetStatus_AckOK:
    ; Read byte 1, get out on error
;;     call ReadAuxData 
;;    jz short Int15h_C2_ExtendedCommand_GetStatus_Error
;;    mov Int15h_C2_BP_bl, al
;;    ; Read byte 2, get out on error
;;    call ReadAuxData
;;    jz short Int15h_C2_ExtendedCommand_GetStatus_Error
;;    mov Int15h_C2_BP_cl, al
;;    ; Read byte 3, get out on error
;;    call ReadAuxData
;;    jz short Int15h_C2_ExtendedCommand_GetStatus_Error
;;    mov Int15h_C2_BP_dl, al

    ;; [o866] we can assume that if this call returns, it was successful.
    call ReadAuxData_NoReturnOnError
    mov Int15h_C2_BP_bl, al
    call ReadAuxData_NoReturnOnError
    mov Int15h_C2_BP_cl, al
    call ReadAuxData_NoReturnOnError
    mov Int15h_C2_BP_dl, al
    ; All read ok, get out
    jmp Int15h_C2_Success

;; [o866] size opt
;;Int15h_C2_ExtendedCommand_GetStatus_Error:
;;    jmp Int15h_C2_InterfaceError

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 6, 1: Set scaling to 1:1
Int15h_C2_ExtendedCommand_Scale11:
    ; Send reset scaling command
    mov al, Cmd_ResetScaling
    ; To save space, use command 2's rest of the code path
    jmp short Int15h_C2_ExtendedCommand_Scale21_Execute

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 6, 1: Set scaling to 2:1
Int15h_C2_ExtendedCommand_Scale21:
    ; Send set scaling command
    mov al, Cmd_SetScaling
Int15h_C2_ExtendedCommand_Scale21_Execute:
;;    call Out_8042_Aux
;;    ; Sent ok? continue
;;    jz short Int15h_C2_ExtendedCommand_Scale21_SendOK
;;    ; Sending failed, get out
;;    jmp Int15h_C2_InterfaceError
    ;; [o866] we can assume that if this call returns, it was successful.
    call Out_8042_Aux_NoReturnOnError
Int15h_C2_ExtendedCommand_Scale21_SendOK:
;;    ; Wait for ack
;;    call Int15h_C2_WaitAck
;;    ; Exit C2 with WaitAck's result
;;    jmp Int15h_C2_Exit
    jmp Int15h_C2_WaitAckAndExit

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 7: Set Device Driver Far Call address
; ES:BX on stack frame = Driver's far call address
Int15h_C2_SetDriverFarCall:
;;    mov ax, Int15h_C2_BP_Segment
;;    mov word ptr ds:Mouse_FarCallSegment, ax
;;    mov ax, Int15h_C2_BP_Offset
;;    mov word ptr ds:Mouse_FarCallOffset, ax
;;    or byte ptr ds:Mouse_PacketSizeFlags, Mouse_DriverFarCallFlag
    mov si, offset Mouse_FarCallOffset
    mov ds:[si], bx
    mov ds:[si+2], es
    or byte ptr ds:[si+5], Mouse_DriverFarCallFlag

    ; This routine can't fail but it really ought to on NULL or something...
    jmp Int15h_C2_Success

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 Sub function table, 16 bytes
Int15h_C2_SubFunctionTable:
    dw offset Int15h_C2_EnableDisableMouse
    dw offset Int15h_C2_ResetMouse
    dw offset Int15h_C2_SetSamplingRate
    dw offset Int15h_C2_SetResolution
    dw offset Int15h_C2_ReadDeviceType
    dw offset Int15h_C2_MouseInit
    dw offset Int15h_C2_ExtendedCommand
    dw offset Int15h_C2_SetDriverFarCall

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Disable AOBF IRQ In KBC
; cf: 0 = No error, 1 = KBC error 
DisableAOBFIrq:
;;    mov cl, KBC_WriteCMD
    mov al, 65h
DisableAOBFIrq_Execute:
    mov cl, KBC_WriteCMD
    call SendCommandToKBC
;;    jnz short DisableAOBFIrq_Error
;;    clc
;;    jmp short DisableAOBFIrq_Exit
;;DisableAOBFIrq_Error:
;;    stc
;;DisableAOBFIrq_Exit:
;;    retn
    clc
    jz DisableAOBFIrq_SkipSuccess
    stc
DisableAOBFIrq_SkipSuccess:
    retn

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Enable AOBF IRQ In KBC
; cf: 0 = No error, 1 = KBC error 
EnableAOBFIrq:
    mov al, 47h
;;    mov cl, KBC_WriteCMD
;;    call SendCommandToKBC
;;    jnz short EnableAOBFIrq_Error
;;    clc
;;    jmp short EnableAOBFIrq_Exit
;;EnableAOBFIrq_Error:
;;    stc
;;EnableAOBFIrq_Exit:
;;    retn
    ;; [o866] size opt :)
    jmp short DisableAOBFIrq_Execute

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Wait for AUX Command Response
; cf: 0 = No error, 1 = error
; Error codes as usual
;; [o866] size opt
;; On errror, the error code is loaded into al for further processing by the C2 exit handler
Int15h_C2_WaitAck:
    push cx
    xor cx, cx
Int15h_C2_WaitAck_Loop:
    ; Wait for aux output buffer not to be full
    push cx
    call Out_8042_Aux_Full
    pop cx
    ; If buffer not full, we can continue
    jnz short Int15h_C2_WaitAck_GetAck
    ; Else keep looping
    loop short Int15h_C2_WaitAck_Loop
    ; !!!!!!!!!!!
    ; Timeout error - use generic error code path for this
    jmp short Int15h_C2_WaitAck_GenericError

Int15h_C2_WaitAck_GetAck:
    ; Check Ack Code
    in al, KBC_DataPort
    cmp al, KBC_Aux_Code_Ack
    je short Int15h_C2_WaitAck_Success
    ; Check Resend Code
    cmp al, KBC_Aux_Code_Resend
    jne short Int15h_C2_WaitAck_GenericError
    ; Resend code was returned
;;    mov Int15h_C2_BP_Error, Int15h_AH_Resend
    mov al, Int15h_AH_Resend
    jmp short Int15h_C2_WaitAck_Error

Int15h_C2_WaitAck_GenericError:
;;    mov Int15h_C2_BP_Error, Int15h_AH_InterfaceError
    mov al, Int15h_AH_InterfaceError
    ; fallthrough
Int15h_C2_WaitAck_Error:
    ; Error happened, clear packet size in 27h byte
    and byte ptr ds:Mouse_PacketSizeFlags, 0f0h
    ; Set carry flag
    or Int15h_C2_BP_Flags, 1
    jmp short Int15h_C2_WaitAck_Exit

Int15h_C2_WaitAck_Success:
    ; Clear error code & Carry flag on stack frame
;;    mov Int15h_C2_BP_Error, 00
    mov al, 0
    and Int15h_C2_BP_Flags, 0fffeh

;; [o866] thoughts
;; this isn't really necessary, as we never take a decision based on *success*
;; all Waitack = success conditions result in us taking the success code path which sets all this garbage for us
;; CORRECTION: No actually at one point we call waitack and jump to regular exit, not succes... Bleh. 

Int15h_C2_WaitAck_Exit:
    pop cx
    ; Set ZF according to result
;;    or Int15h_C2_BP_Error, 0
    or al, 0
    ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Read data from the mouse when the aux output buffer is full
; zf: 0 = data in AL, 1 = error or no data
ReadAuxData:
    push cx
    xor cx, cx
ReadAuxData_Loop:
    push cx
    call Out_8042_Aux_Full
    pop cx
    ; Is AOB full? If yes, read the byte, else keep looping
    jnz short ReadAuxData_ReadData
    loop short ReadAuxData_Loop
    ; Timeout
    jmp short ReadAuxData_Exit
ReadAuxData_ReadData:
    in al, KBC_DataPort
ReadAuxData_Exit:
    pop cx
ReadAuxData_ReturnInstruction:
    ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; SIZE OPTIMIZATION!!!!
; This one does NOT return on error, instead it pops the return address and moves DIRECTLY
; to the C2 interface error!!
ReadAuxData_NoReturnOnError:
    call ReadAuxData
    ; Read OK, return like normal
ReadAuxData_ErrorCheck:
    jnz short ReadAuxData_ReturnInstruction
;;    add sp, 2
    inc sp
    inc sp
    jmp Int15h_C2_InterfaceError

; This one does NOT return on error, instead it pops the return address and moves DIRECTLY
; to the C2 interface error!!
Out_8042_Aux_NoReturnOnError:
    call Out_8042_Aux
    jmp short ReadAuxData_ErrorCheck


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Bend Int15 handler to call our MouseFunction...function for C1/C2
    org offset Int15_CheckMouse
    cmp ah, 0C1h
    jnz NoC1
    jmp Int15h_MouseFunction
NoC1:
    cmp ah, 0C2h
    jnz NoC2
    jmp Int15h_MouseFunction
NoC2:
Int15h_ContinueProcessing:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Packet size translation table
;;size1:  db 6                ; 1
;;size2:  db 6,7              ; 2
;;size3:  db 6,4,2            ; 3
;;size4:  db 6,7,4,2          ; 4
;;size5:  db 6,4,2,5,3        ; 5
;;size6:  db 6,7,4,2,5,3      ; 6
;;size7:  db 6,4,2,0,5,3,1    ; 7
;;size8:  db 6,7,4,2,0,5,3,1  ; 8

;; Some of these can be expressed as pars of others

size1:
size2:
size4:
size6:  db 6,7,4,2,5,3      ; 6
size3:
size7:  db 6,4,2,0,5,3,1    ; 7
size8:  db 6,7,4,2,0,5,3,1  ; 8
size5:  db 6,4,2,5,3        ; 5

PacketSizeTable:
		dw	offset size1
		dw	offset size2
		dw	offset size3
		dw	offset size4
		dw	offset size5
		dw	offset size6
		dw	offset size7
		dw	offset size8

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Set new IRQ12 Address
    org offset SetupMouse_SetIRQ12Handler
    mov ax, cs
    mov word ptr ds:1d0h, offset IRQ12_New
    mov ds:1d2h, ax

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Enable mouse support in the BIOS features byte
    org Sys_BiosSupportedFeatures
    db ((CONST_BiosSupportedFeatures) OR 080h)


SEG_15 ENDS
