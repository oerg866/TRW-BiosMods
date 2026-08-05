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
    lea bx, cs:PacketSizeTable
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
    push ds
    pop es
    assume es:nothing
    cld

; Clear aux data buffer
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
;;; [o866] I think this may be an archaic leftover and we can just assume this
;;; so get rid of it
;;    ; this checks for "wait for external event supported" - whatever that is
;;    test cs:Sys_BiosConfigTable+5, 4
;;    jnz short Int15h_MouseFunction_Process
;;    jmp Int15h_ContinueProcessing

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

    cmp ah, 0C2h
    jz short Int15h_C2_Handler
    ; fallthrough

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h Function C1 Handler - Get Extended Data Segment
; Outputs XBDA segment in ES and leaves the interrupt outright
Int15h_C1_Handler:
    push Bios_RAM_Segment
    pop es
    push [word ptr es:RAM_ExtData_Segment_ID]
    pop es
    iret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h Function C2 Handler - Pointing Device Interface
Int15h_C2_Handler:
;;    ; is function valid?
;;    test al, 0F8h
;;    jz short Int15h_C2_FunctionIsValid
;;    ; Function is invalid, exit
;;    mov ah, Int15h_AH_InvalidFunction
;;    stc
;;    retf 2
;;
;; Int15h_C2_FunctionIsValid:
;;    ; Function is valid, continue processing

;;  ^ this is moved further down so we can use our usual error code path to save some bytes

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
;;    push ax
    ;; we dont need DX, so we can use it to store AL which gets clobbered in disableirq
    mov dl, al
    call DisableAOBFIrq
;;    pop ax

;; [o866] insert validity check here.. less performant but WAY smaller
    test dl, 0f8h
    jnz short Int15h_C2_InvalidFunctionError

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
;;    xor ah, ah
;;;;    mov al, Int15h_C2_BP_SubFunction
;;;;  ^ al is still valid at this point
;;    shl ax, 1
    mov si, offset Int15h_C2_SubFunctionTable
;;    add si, ax
    xor dh, dh
    shl dx, 1
    add si, dx
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
    ;; [o866] size opt, we expect error code in al here and Int15h_C2_BP_Flags already set
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
;; DISREGARD THIS -> bh: 0 = disable, 1 = enable
; bh nonzero = enable, 0 = disable
; This is a deviation from original AWD bios but much smaller
; cf: 0 = no error, 1 = error
Int15h_C2_EnableDisableMouse:
    test byte ptr ds:Mouse_PacketSizeFlags, Mouse_DriverFarCallFlag
    jz short Int15h_C2_NoFarCallInstalledError
    ;; AL F4h / BH 1 = enable
    mov al, Cmd_EnableData
    or bh, bh
    ;; BH 1 = enable --> skip setting AL to disable command
    jz short Int15h_C2_EnableDisableMouse_NotDisable
    inc al ; al is now "disable mouse" command
    ; fallthrough

Int15h_C2_EnableDisableMouse_NotDisable:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Code path  jump point for sending a byte out and waiting for ack
;; and then taking C2 exit path
Int15h_C2_SendByteWaitAckAndExit:
    call Out_8042_Aux_And_WaitAck_NoReturnOnError
    jmp short Int15h_C2_Exit

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 1: Reset Pointing Device
; cf: 0 = no error, 1 = error
Int15h_C2_ResetMouse:
    ; clear mouse packet buffer before sending
    xor bh, bh ; Reset mouse command resets packet size in OG funcition
    mov dl, 1

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Code path jump point for RESETTING THE MOUSE and SETTING THE PACKET SIZE
; bh = Packet size
; DX = 1 - store returned ID in stack frame's BX
;      0 - don't store result in stack frame's BX
Int15h_C2_ResetMouse_Execute:
    ; Set packet size to given value
    mov si, Mouse_PacketSizeFlags
    and byte ptr ds:[si], 0f8h
    or byte ptr ds:[si], bh

    ; Number of (re)tries
    mov bl, 10
Int15h_C2_ResetMouse_TryLoop:
    ; Send "reset" command to the mouse
    mov al, Cmd_Reset
    call Out_8042_Aux

    ; Sending command failed - I/F error
    jnz short Int15h_C2_InterfaceError

    ; Wait for Ack
    call Int15h_C2_WaitAck
    ; Ack received? Success, leave the try-loop
    jz short Int15h_C2_ResetMouse_GetID

    ; If not, loop
    dec bl
    jnz short Int15h_C2_ResetMouse_TryLoop

    ; !!!!!!!!!!!!!!!!!!!!!!!!
    ; Timeout occurred
    ; This can only come from WaitAck so the error code and flags are in place
    ; and we move to C2 exit code path
    jmp short Int15h_C2_Exit

    ; At this point we got an acknowledgement to our command
Int15h_C2_ResetMouse_GetID:
    call ReadAuxData_NoReturnOnError
    mov bl, al  ; Store data into BX for later

;; Hacky jump point because this call + storage + success jump is duplicated below 
Int15_C2_ResetMouse_ReadLastByteAndJumpOnSuccess:
    call ReadAuxData_NoReturnOnError
    mov bh, al ; Store data into BX for later

;; We can move BL and BH on the stack frame on demand
;; DX = 0 means DONT do that
    or dx, dx
    jz short SkipWritingResultIntoBH
    mov Int15h_C2_BP_Offset, bx
SkipWritingResultIntoBH:
    jmp Int15h_C2_Success

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 2: Set Sampling Rate
; bh on stack frame = sample rate table index
; cf: 0 = no error, 1 = error
Int15h_C2_SetSamplingRate:
    ; Check if input is valid

    cmp bh, 6
    _JA Int15h_C2_InvalidInputError

    ; Send "Set report rate" command and wait for ack
    mov al, Cmd_SetSamplingRate
    call Out_8042_Aux_And_WaitAck_NoReturnOnError

    ; Read report rate from table based on index
    mov bl, bh
    xor bh, bh
    mov al, byte ptr cs:[bx+Int15h_C2_SampleRateTable]

    ; Send report rate to the mouse
    jmp short Int15h_C2_SendByteWaitAckAndExit

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 3: Set Resolution
; bh on stack frame = Resolution value (0-3)
; cf: 0 = no error, 1 = error
Int15h_C2_SetResolution:
    ; Check parameter for validity
    cmp bh, 3
    _JA Int15h_C2_InvalidInputError

    ; Send "set resolution" command to the mouse and wait for ack
    mov al, Cmd_SetResolution
    call Out_8042_Aux_And_WaitAck_NoReturnOnError

    ; Ack ok, send the resolution value
    mov al, bh
    jmp short Int15h_C2_SendByteWaitAckAndExit


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 4: Read Aux Device Type
; cf: 0 = no error, 1 = error
Int15h_C2_ReadDeviceType:
    ; Send "read type" command to the mouse and wait for ack
    mov al, Cmd_ReadDeviceType
    call Out_8042_Aux_And_WaitAck_NoReturnOnError

    ; Ack ok, read the response
    mov dl, 1 ;; Force writing result into BH
    jmp short Int15_C2_ResetMouse_ReadLastByteAndJumpOnSuccess

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 5: Mouse Initialization
; bh on stack frame = packet size (1-8 bytes)
; cf: 0 = no error, 1 = error
Int15h_C2_MouseInit:
    ; Check supplied packet size
    dec bh  ;; so a zero which is invalid would become 0FFh, thus the unsigned comparison catches all
    cmp bh, 7
    _JA Int15h_C2_InvalidInputError

    xor dx, dx ;; DX = 0 -> Do not write the result
    ; The rest of the code path is so similar to ResetMouse
    ; that I just decided to use it outright.
    ; Close enough (tm)
    jmp Int15h_C2_ResetMouse_Execute

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 6: Extended Commands
; bl on stack frame = Extended Command
;   -> 0 = return status, 1 = set scale to 1:1, 2 = set scale to 2:1
; cf: 0 = no error, 1 = error
Int15h_C2_ExtendedCommand:
    or bh, bh
    jz short Int15h_C2_ExtendedCommand_GetStatus

    dec bh

    ; If it is 0 now: Int15h C2 SubFunction 6, 1: Set scaling to 1:1
    mov al, Cmd_ResetScaling
    jz short Int15h_C2_ExtendedCommand_Scale21_Execute


    ; If it is 0 now: Int15h C2 SubFunction 6, 2: Set scaling to 2:1
    inc ax ; AL is now Cmd_SetScaling
    dec bh

    ; Also not it? Then we leave
    _JNZ Int15h_C2_InvalidFunctionError

; Execution code path for C2/6 scaling commands 0/1
Int15h_C2_ExtendedCommand_Scale21_Execute:
    jmp Int15h_C2_SendByteWaitAckAndExit

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 6, 0: Get status
; The format of this is complex and I have no clue about it
; but the result is put in BL, CL and DL on the stack frame
Int15h_C2_ExtendedCommand_GetStatus:
    ; Send status request command to aux device
    mov al, Cmd_StatusRequest
    call Out_8042_Aux_And_WaitAck_NoReturnOnError

    ; We can now theoretically read the status bytes from the mouse
;;    call ReadAuxData_NoReturnOnError
;;    mov Int15h_C2_BP_bl, al
;;    call ReadAuxData_NoReturnOnError
;;    mov Int15h_C2_BP_cl, al
;;    call ReadAuxData_NoReturnOnError
;;    mov Int15h_C2_BP_dl, al

    ;; [o866] shit man, this is 13 bytes but kind of disgusting
    mov si, 04h
fdsfsd:
    call ReadAuxData_NoReturnOnError
    mov byte ptr [bp + si + 0ah], al    ;; This stupid contraption writes to bp+0eh (bl), bp+0ch (cl), bp+0ah (dl)
    dec si
    dec si
    jnz short fdsfsd

    ; All read ok, get out
    jmp Int15h_C2_Success

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Int15h C2 SubFunction 7: Set Device Driver Far Call address
; ES:BX on stack frame = Driver's far call address
Int15h_C2_SetDriverFarCall:
    ; Technically ES and BX on stack frame are supposed to be used
    ; But these two registers have NOT been touched yet, so we can
    ; use them outright
    mov si, offset Mouse_FarCallOffset
    mov ds:[si], bx
    mov ds:[si+2], es
    or byte ptr ds:[si+5], Mouse_DriverFarCallFlag
    ; This routine can't fail but it really ought to on NULL.
    ; Whatever, it's worked for hundereds of years...
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

;; [o866] thoughts
;; We could save 8 bytes here by only storing the 8 bit offset to the
;; very first function but the problem is that scattered code caves
;; may require us to store different functions in different locations
;; in the ROM, so it is not practical

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Sample Rate Conversion Table (reports per second)
Int15h_C2_SampleRateTable:
    db 0ah  ; 00 = 10  reports/second
    db 14h  ; 01 = 20  reports/second
    db 28h  ; 02 = 40  reports/second
    db 3ch  ; 03 = 60  reports/second
    db 50h  ; 04 = 80  reports/second
    db 64h  ; 05 = 100 reports/second
    db 0c8h ; 06 = 200 reports/second

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Disable AOBF IRQ In KBC
; cf: 0 = No error, 1 = KBC error 
DisableAOBFIrq:
;;    mov cl, KBC_WriteCMD
    mov al, 65h
DisableAOBFIrq_Execute:
    mov cl, KBC_WriteCMD
    call SendCommandToKBC
    clc
    jz short DisableAOBFIrq_SkipSuccess
    stc
DisableAOBFIrq_SkipSuccess:
    retn

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Enable AOBF IRQ In KBC
; cf: 0 = No error, 1 = KBC error 
EnableAOBFIrq:
    mov al, 47h
    ;; Enable = Disable with a different command value
    jmp short DisableAOBFIrq_Execute

Int15_C2_TryAuxFull:
;; using dx here saves 1 byte
    push cx
    xor cx, cx
Int15_C2_TryAuxFull_Loop:
    push cx
    call Out_8042_Aux_Full
    pop cx
    loopz short Int15_C2_TryAuxFull_Loop
    pop cx
    retn

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Wait for AUX Command Response
; cf: 0 = No error, 1 = error
; Returns Error code for C2 Exit in al
Int15h_C2_WaitAck:
    ; Try and wait for AUX buffer to be full
    call Int15_C2_TryAuxFull
    jz short Int15h_C2_WaitAck_GenericError
    ; Check Ack Code
    in al, KBC_DataPort
    cmp al, KBC_Aux_Code_Ack
    je short Int15h_C2_WaitAck_Success
    ; Check Resend Code
    cmp al, KBC_Aux_Code_Resend
    jne short Int15h_C2_WaitAck_GenericError
    ; Resend code was returned
    mov al, Int15h_AH_Resend
    jmp short Int15h_C2_WaitAck_Error

;; Flags Interface Error in AL
Int15h_C2_WaitAck_GenericError:
    mov al, Int15h_AH_InterfaceError
    ; fallthrough
Int15h_C2_WaitAck_Error:
    ; Error happened, clear packet size in 27h byte
    and byte ptr ds:Mouse_PacketSizeFlags, 0f0h
    ; Set carry flag (cf 1 = error)
    or Int15h_C2_BP_Flags, 1
    jmp short Int15h_C2_WaitAck_Exit

Int15h_C2_WaitAck_Success:
    ; Clear error code & Carry flag on stack frame
    mov al, 0
    and Int15h_C2_BP_Flags, 0fffeh

Int15h_C2_WaitAck_Exit:
    ; Set ZF according to result
    or al, 0
    ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Read data from the mouse when the aux output buffer is full
; zf: 0 = data in AL, 1 = error or no data
ReadAuxData:
    ; Try and wait for AUX buffer to be full
    call Int15_C2_TryAuxFull
    ; Read the data - if there is none, the result can be discarded by the caller
    in al, KBC_DataPort
    ; Doesn't affect flags, so the zero flag will contain result of AUX buffer wait
ReadAuxData_ReturnInstruction:
    ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; SIZE OPTIMIZATION!!!!
; ReadAuxData but it DOES NOT return on error, instead it pops the return address and moves DIRECTLY
; to the C2 interface error!!
ReadAuxData_NoReturnOnError:
    ; Read the data. Return as normal in case of success...
    call ReadAuxData
    ; ... using another function's return instruction :D
    jnz short ReadAuxData_ReturnInstruction
ReadAuxData_Error:
    ; Discard return address into an unused register
    pop si
    jmp Int15h_C2_InterfaceError

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; SIZE OPTIMIZATION!!!!
; This calls two functions:
; 1.    Out_8042_Aux - but does NOT return on error, instead it pops the return address and moves DIRECTLY to the C2 interface error!!
;       This function sends a byte to the mouse.
; 2.    Int15h_C2_WaitAck - but does NOT return on error, instead it pops the return address and moves DIRECTLY to the C2 EXIT!!
;       EXIT because WaitAck already fills out all the result stuff on the stack frame
;       This function sends a byte to the mouse.
;       
Out_8042_Aux_And_WaitAck_NoReturnOnError:
    call Out_8042_Aux
    jnz short ReadAuxData_Error
    ; Fall through

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; SIZE OPTIMIZATION!!!!
;  Int15h_C2_WaitAck but does NOT return on error, instead it pops the return address and moves DIRECTLY to the C2 EXIT!!
;  EXIT because WaitAck already fills out all the result stuff on the stack frame
Int15h_C2_WaitAck_NoReturnOnError:
    call Int15h_C2_WaitAck
    jz short ReadAuxData_ReturnInstruction
    pop si ; register can be trashed, save 1 byte :))
    jmp Int15h_C2_Exit


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
;; Some of these can be expressed as pars of others
;; size1:   db 6                ; 1
;; size2:   db 6,7              ; 2
;; size3:   db 6,4,2            ; 3
;; size4:   db 6,7,4,2          ; 4
size5:      db 6,4,2,5,3        ; 5
size6:      db 6,7,4,2,5,3      ; 6
size7:      db 6,4,2,0,5,3,1    ; 7
size8:      db 6,7,4,2,0,5,3,1  ; 8

PacketSizeTable:
		dw	offset size5    ;; size1
		dw	offset size6    ;; size2
		dw	offset size5    ;; size3
		dw	offset size6    ;; size4
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
