; AWARD 4.5x HDD bug fix code
; Include this file, if a supported BUGGY function is known then it will apply the fix

IFDEF CalculateHDDSize_BUGGY1

; Jan Steunebrink HDD calculation fix
SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'
    ORG offset CalculateHDDSize_BUGGY1
    push cx
    mov al, [bp+96h]
    xor ch, ch
    mov cl, [bp+9bh]
    shl cl, 2
    mul cl
    mov cx, [bp+94h]
    mul cx
    mov cx, 2000h
    div cx
    mov [bp+9ch], ax
    pop cx
SEG_15 ENDS

ENDIF
