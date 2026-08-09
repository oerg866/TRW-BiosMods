import re
import ida_bytes
import ida_name
import ida_ua
import ida_funcs
import idaapi
import ida_lines
import importlib

import award45x_ida

#
# Find common functions
#

CONST_BYTE = 0
CONST_WORD = 1
CONST_DWORD = 2
CONST_OFFSET_IS_VALUE=3
CONST_OFFSET_IS_STRUCT=4
CONST_OFFSET_IS_VALUE_RELATIVE_TO_FUNC=5

REF_RELATIVE = 0
REF_ABSOLUTE = 1

def getConstantFromData(data, offset, type):
    if type == CONST_BYTE:
        return data[offset]
    if type == CONST_WORD:
        return (data[offset] << 0) | (data[offset+1] << 8)
    if type == CONST_DWORD:
        return (data[offset] << 0) | (data[offset+1] << 8) | (data[offset+2] << 16) | (data[offset+3] << 24)
    raise Exception("Invalid type")

# structure is as such:

# (
#    < function name>
#    [
#       some pattern bytes
#       e.g. 0x00, 0x04, None, 0x85
#       None = any byte value can apply here
#    ],
#    THIS PART IS OPTIONAL:
#    [
#       List of exported constants
#       ( <constant name>, <offset in found pattern>, data type(CONST_BYTE, CONST_WORD, CONST_DWORD))
#    ]
# )

COMMON_FUNCTION_LIST = [
    (
        'Display_String',
        [
            0x06, 0x57, 0x53,                   # push es, push di, push bx
            0xAC,                               # lodsb
            0x3C, 0x00                          # cmp al, 0
        ],
        []
    ),
    (
        'Display_CS_String',
        [
            0x1E, 0x0E, 0x1F,                   # push ds, push cs, pop ds
            0xE8, None, None,                   # call * (Display_String)
            0x1F, 0xC3                          # pop ds, retn
        ],
        []
    ),
    (
        'DispStr_RestoreTextAttr',
        [
            0x50, 0x53,                         # push ax,  push bx
            0x8B, 0x9E, None, 0x01,             # mov     bx, [bp+1**h] <- this is 12Bh in 4.50, 14Bh in 4.51
            0x2E, 0x8A, 0x07,                   # mov     al, cs:[bx]
            0x88, 0x86, 0x80, 0x00              # mov     [bp+TEXT_ATTR], al
        ],
        [
            ( 'BP_CurrentColorStyle', 4, CONST_WORD )
        ]
    ),
    (   # 4.50 Variant
        'Write_Character',
        [
            0x50, 0x53, 0x51, 0x52, 0x50,       # push ax, push bx, push cx, push dx, push ax
            0x8A, 0x96, 0x81, 0x00,             # mov     dl, [bp+TEXT_X]
            0x8A, 0xB6, 0x82, 0x00,             # mov     dh, [bp+TEXT_Y]
        ],
        []
    ),
    (   # 4.51 Variant
        'Write_Character',
        [
            0x50, 0x53, 0x51, 0x52, 0x9C, 0x50, # push ax, push bx, push cx, push dx, pushf, push ax
            0x8A, 0x96, 0x81, 0x00,             # mov     dl, [bp+TEXT_X]
            0x8A, 0xB6, 0x82, 0x00,             # mov     dh, [bp+TEXT_Y]
        ],
        []
    ),
    (
        'DispStr_LF',
        [
            0x50, 
            0x8A, 0x86, 0x82, 0x00,
            0x3A, 0x86, None, 0x01,
        ],
        [
            ('BP_ClipBottomY', 7, CONST_WORD)
        ]
    ),
    (
        'DispStr_CR',
        [
            0x50, 
            0x8A, 0x86, None, 0x01,
            0x88, 0x86, 0x81, 0x00,
        ],
        []
    ),
    (
        'DispStr_CRLF',
        [
            0xE8, 0x04, 0x00,
            0xE8, 0x16, 0x00,
            0xC3
        ],
        []
    ),
    (
        'SetCursorPosition',
        [
            0x89, 0x96, 0x81, 0x00,             # mov [bp+TEXT_X], dx
            0x83, 0xBE, None, 0x01              # cmp word ptr [bp+1**h], 0
        ],
        []
    ),
    (
        'DrawAwardRibbon',
        [
            0x8A, 0x9E, 0x80, 0x00,             # mov bl, [bp+TEXT_ATTR]
            0x53,                               # push bx 
            0xC6, 0x86, 0x80, 0x00, 0x09,       # mov byte ptr [bp+TEXT_ATTR], 9
            0xBA, None, None,                   # mov dx, * (cursor position)
            0xE8, None, None                    # call * (SetCursorPosition)
        ],
        []
    ),
    (
        'DispStr_CRLF_FAR',
        [
            0x68, 0x00, 0xe0,   # push 0e000h (segment index)
            0x68, None, None,   # push locret (near, in E segment)
            0x68, None, None,   # push locret (far, in F segment)
            0x68, (REF_ABSOLUTE, 'DispStr_CRLF'), # push address - honestly the most ingenious hack of all time
            0xEA, None, None, 0x00, 0xF0  # jmp far locret (near, but in F segment)
        ],
        []
    ),
    (
        'SetCursorPosition_FAR',
        [
            0x68, 0x00, 0xe0,   # push 0e000h (segment index)
            0x68, None, None,   # push locret (near, in E segment)
            0x68, None, None,   # push locret (far, in F segment)
            0x68, (REF_ABSOLUTE, 'SetCursorPosition'), # push address
            0xEA, None, None, 0x00, 0xF0  # jmp far locret (near, but in F segment)
        ],
        []
    ),
    (
        'Write_Character_FAR',
        [
            0x68, 0x00, 0xe0,   # push 0e000h (segment index)
            0x68, None, None,   # push locret (near, in E segment)
            0x68, None, None,   # push locret (far, in F segment)
            0x68, (REF_ABSOLUTE, 'Write_Character'), # push address
            0xEA, None, None, 0x00, 0xF0  # jmp far locret (near, but in F segment)
        ],
        []
    ),
    (
        'Display_String_FAR',
        [
            0x68, 0x00, 0xe0,   # push 0e000h (segment index)
            0x68, None, None,   # push locret (near, in E segment)
            0x68, None, None,   # push locret (far, in F segment)
            0x68, (REF_ABSOLUTE, 'Display_String'), # push address 
            0xEA, None, None, 0x00, 0xF0  # jmp far locret (near, but in F segment)
        ],
        []
    ),
    (
        'Display_String_FAR_SaveDX',
        [
            0x52,                                           # push dx
            0xE8, (REF_RELATIVE, 'Display_String_FAR'),     # call Display_String_FAR
            0x5A,                                           # pop dx
            0xC3,                                           # retn
        ],
        []
    ),
    (   # Variant 1
        'Display_String_FAR_CS',
        [
            0x1E, 0x0E, 0x1F,   # push ds, push cs, pop ds
            0x68, 0x00, 0xe0,   # push 0e000h (segment index)
            0x68, None, None,   # push locret (near, in E segment)
            0x68, None, None,   # push locret (far, in F segment)
            0x68, (REF_ABSOLUTE, 'Display_String'), # push address 
            0xEA, None, None, 0x00, 0xF0,  # jmp far locret (near, but in F segment)
            0x1F, 0xC3          # pop ds, retn
        ],
        []
    ),
    (   # Variant 2, calls the FAR routine instead of doing a manual far call
        'Display_String_FAR_CS',
        [
            0x1E, 0x0E, 0x1F,   # push ds, push cs, pop ds
            0xE8, (REF_RELATIVE, 'Display_String_FAR'),     # call Display_String_FAR
            0x1F, 0xC3          # pop ds, retn
        ],
        []
    ),
    (
        'Display_String_FAR_CS_SaveDX',
        [
            0x52,                                           # push dx
            0xE8, (REF_RELATIVE, 'Display_String_FAR_CS'),  # call Display_String_FAR_CS
            0x5A,                                           # pop dx
            0xC3,                                           # retn
        ],
        []
    ),
    (
        'Display_String_FAR_SaveCursor',
        [
            0xFF, 0xB6, 0x81, 0x00,                                 # push word ptr [bp+81h]
            0xE8, (REF_RELATIVE, 'Display_String_FAR_CS_SaveDX'),  # call  Display_String_FAR_CS_SaveDX
            0x8F, 0x86, 0x81, 0x00,                                 # pop word ptr [bp+81h]
            0x60,                                                   # pusha
        ],
        []
    ),
    (
        'CheckIfWarmReboot',
        [
            0x1E, 0x50,                             # push ds, push ax
            0xB8, 0x00, 0x00,                       # mov ax, 0
            0x8E, 0xD8,                             # mov ds, ax
            0x81, 0x3E, 0x72, 0x04, 0x34, 0x12,     # cmp word ptr ds:472h, 1234h
        ],
        []
    ),
    (    # Variant 1
        'PrintPOSTStrings',
        [
            0x52,                   # push dx
            0xE8, (REF_RELATIVE, 'SetCursorPosition_FAR'),  # call SetCursorPosition_FAR
            0xBE, None, None,   # mov si, offset biosString
            0xE8, (REF_RELATIVE, 'Display_String_FAR_SaveDX'),
            0xBE, None, None,   # mov si, offset anEnergyStarAlly
            0xE8, (REF_RELATIVE, 'Display_String_FAR_CS_SaveDX'),
            0x5A, # pop dx
            0xFE, 0xC6, # inc dh
            0xE8, (REF_RELATIVE, 'SetCursorPosition_FAR'),
            0xBE, None, None,   # mov si, offset Copyright
            0xE8, (REF_RELATIVE, 'Display_String_FAR_SaveDX'),
            0xE8, (REF_RELATIVE, 'DispStr_CRLF_FAR'),
            0xE8, (REF_RELATIVE, 'DispStr_CRLF_FAR'),
            0xBE, None, None,   # mov si, offset biosrevinfo
            0xE8, (REF_RELATIVE, 'Display_String_FAR_SaveDX'),
            0xE8, (REF_RELATIVE, 'DispStr_CRLF_FAR'),
            0xE8, (REF_RELATIVE, 'CheckIfWarmReboot'),
            0x74, 0x18  # jz somwehere down the line
            # I think that's probably enough to say for sure that this is 100% identical
        ],
        [        ]
    ),
    (    # Variant 2
        'PrintPOSTStrings',
        [
            0x52,                   # push dx
            0xE8, (REF_RELATIVE, 'SetCursorPosition_FAR'),  # call SetCursorPosition_FAR
            0xBE, None, None,   # mov si, offset biosString
            0xE8, (REF_RELATIVE, 'Display_String_FAR_SaveDX'),
            0xBE, None, None,   # mov si, offset anEnergyStarAlly
            0xE8, (REF_RELATIVE, 'Display_String_FAR_CS_SaveDX'),
            0x5A, # pop dx
            0xFE, 0xC6, # inc dh
            0xE8, (REF_RELATIVE, 'SetCursorPosition_FAR'),
            0xBE, None, None,   # mov si, offset Copyright
            0xE8, (REF_RELATIVE, 'Display_String_FAR_SaveDX'),
            0xE8, (REF_RELATIVE, 'DispStr_CRLF_FAR'),
            0xE8, (REF_RELATIVE, 'DispStr_CRLF_FAR'),
            0xBE, None, None,   # mov si, offset biosrevinfo
            0xE8, (REF_RELATIVE, 'Display_String_FAR_SaveDX'),
            0xE8, (REF_RELATIVE, 'DispStr_CRLF_FAR'),
            0x06,               # push es
            0xB8, 0x00, 0x40    # mov ax, 4000h
        ],
        []
    ),
    (
        'PrintPOSTStrings_Full',
        [
            0xe8, None, None,                           # call    nullsub_7
            0xe8, None, None,                           # call    sub_F2791
            0xb8, 0x00, 0xf0,                           # mov     ax, 0F000h
            0x8e, 0xd8,                                 # mov     ds, ax
            0xe8, None, None,                           # call    sub_F0EE4
            0xba, None, None,                           # mov     dx, 1800h
            0xe8, (REF_RELATIVE, 'SetCursorPosition'),  # call    SetCursorPosition
            0xbe, None, None,                           # mov     si, 0EC71h
            0xe8, (REF_RELATIVE, 'Display_CS_String'),  # call    Display_CS_String
            0xba, 0x00, 0x01,                           # mov     dx, 100h
            0xf6, 0x86, 0x9e, 0x00, 0x01,               # test    byte ptr [bp+9Eh], 1
        ],
        [
            ( 'Str_BiosString', 0x15, CONST_WORD ),
        ]
    ),
    (
        'EarlyChipsetInit',
        [
            0x8C, 0xC8,                             # mov ax, cs
            0x8E, 0xD8,                             # mov ds, ax
            0xBB, None, None,                       # mov bx, offset <chipset table>
            0x81, 0xFB, None, None,                 # cmp bx, offset <chipset table end>
            0x74, 0x1E,                             # jz short <somewhere>
            0x8B, 0x4F, 0x01,                       # mov cx, [bx+1]
        ],
        [
            ( 'Sys_ChipsetInitTable',        5, CONST_WORD ),
            ( 'Sys_ChipsetInitTable_end',    9, CONST_WORD ),
        ]
    ),
    (
        'OutPort16',
        [
            0xEE, 0xFE, 0xC2, 0x86, 0xE0,           # out dx, al | inc dl | xchg ah, al
            0xEE, 0xFE, 0xCA, 0x86, 0xE0            # out dx, al | dec dl | xchg ah, al
        ],
        []
    ),
    (
        'CheckCTRLAltDel',
        [
            0x80, 0x7E, 0xFF, 0x53,                 # cmp     byte ptr [bp-1], 53h
            0x75, None,                             # jnz short xxx
            0xF6, 0x06, None, 0x00, 0x08,           # test byte ptr ds:xx, 8
            0x74, None,                             # jz short xxx
            0xf6, 0x06, None, 0x00, 0x04,           # test byte ptr ds:xx, 4
            0x74, None,                             # jz short xxx
            0xC7, 0x06, None, None, 0x34, 0x12      # mov wrd ptr ds:xxxx, 1234h
        ],
        [
        ]
    ),
    (
        'Reboot',
        [
            0xB8, 0x40, 0x00,                       # mov ax, 40h
            0x8E, 0xD8,                             # mov dx, ax
            0x32, 0xE4,                             # xor ah, ah
            0xa0, None, None,                       # mov al, ds:49h
            0xcd, 0x10
        ],
        [
        ]
    ),
    (
        'Start_1',
        [
            0x8E, 0xEA,                             # mov gs, dx
            0xFA, 0xFC,                             # cli | cld
            0xE4, 0x64,                             # in al, 64h
            0xA8, 0x04,                             # test al, 4
        ],
        [
        ]
    ),
    (
        'ISR_IRQ12_PS2Mouse',
        [
            0x50, 0x53, 0x51, 0x56, 0x57, 0x55,     # push ax, bx, cx, si, di, bp,
            0x1e, 0x06,  0xfc,                      # push ds, push es, cld
            0xe4, 0x60,                             # in al, 60h
        ],
        [
        ]
    ),
    (
        'Wait_Refresh',
        [
            0x2e, 0xf6, 0x06, 0xe2, 0xff, 0xc0, # test cs:ffe2h, 0c0h
            0x74, 0x05,                         # jz ....
            0x79, 0x03,                         # jns ....
            0xeb, 0x1d,                         # jmp short ...
        ],
        []
    ),
    (
        'Mouse_CheckDataPacket',
        [
            0xb9, 0xa5, 0x00,       # mov cx, 0a5h
            0xe4, 0x64,             # in al, 64h
            0xeb, 0x00, 0xeb, 0x00, # IODELAY
            0xfb,                   # sti
            0x24, 0x21,             # and al, 21h
            0x3c, 0x21,             # cmp al, 21h
            0x74, 0x22,             # jz short locret
        ],
        []
    ),
    (
        'APM_Service',
        [
            # push.... a lot of shit
            0xfa, 0x55, 0x1e, 0x06, 0x56, 0x57, 0x52, 0x51, 0x53, 0x66, 0x50,
            0x8b, 0xec,             # mov bp, sp
            0x83, 0x66, 0x18, 0xfe, # and word ptr [bp+18h], 0fffeh
        ],
        []
    ),
    (
        'APM_Service',
        [
            # push a lot of shit
            0x9c, 0xfa, 0x56, 0x1e, 0x50,
            0xe8, None, None,   # Call ...
            0x8e, 0xd8,         # mov ds, ax
        ],
        []
    ),
    (
        'Int15h_Handler',
        [
            # Same as below but starts witha n STI instruction
            0xfb,                                   # sti
            0x80, 0xfc, 0x53,                       # cmp ah, 53h
            0x75, 0x03,                             # jnz short ...
            0xe9, (REF_RELATIVE, 'APM_Service'),    # jmp apm_service
        ],
        []
    ),
    (
        'Int15h_Handler',
        [
            0x80, 0xFC, 0x53,                       # cmp ah, 53h
            0x75, 0x03,                             # jnz short ...
            0xe9, (REF_RELATIVE, 'APM_Service'),    # jmp apm_service
        ],
        []
    ),
    (
        'Int15_CheckMouse',
        [
            0x80, 0xfc, 0xc1,       # cmp ah, 0c1h
            0x0f, 0x85, 0x03, 0x00, # jnz ...
            # This snippet exists in BIOSes that have
            # No mouse support, it points to a dummy handler in this case.
            # Since we can't uniquely identify nullsubs,
            # we have to do a wildcard here.
            0xe9, None, None,       # jmp Int15_MouseFunction
            0x80, 0xfc, 0xc2,       # cmp ah, 0c2h
            0x0f, 0x85, 0x03, 0x00, # jnz ...
            0xe9, None, None,       # jmp Int15_MouseFunction
        ],
        []
    ),
    (
        'Int15h_MouseFunction',
        [
            0x2e, 0xf6, 0x06, 0xfa, 0xe6, 0x04, # test cs:[E6FA], 4
            0x75, 0x03,                         # jnz short ...
            0xe9, None, None,                   # jmp <skipmouse>
            0x06,                               # push es
        ],
        []
    ),
    (
        'MouseInstall',
        [
            0xb8, 0x00, 0xf0,                   # mov ax, 0f000h
            0x8e, 0xd8,                         # mov ds, ax
            0xf6, 0x06, 0xec, 0xff, 0x80,       # test byte ptr [ffec], 80h
            0x75, 0x03,                         # jnz short InstallYes
            0xe9, None, None,                   # jmp locret
            0xb8, 0x00, 0x00,                   # mov ax, 0
        ],
        []
    ),
    (
        'CheckNewHelpFormat',
        [
            0x60,                                   # pusha
            0x1e,                                   # push ds
            0xbe, None, None,                       # mov si, offset <table>
            0xb9, None, None,                       # mov cx, <table len>
            0x01, 0xce                              # add si, cx
        ],
        []
    ),
    (
        'EnableInternalCache',
        [
            0x66, 0x60,                             # pushad
            0xbb, None, None,                        # mov bx, <offset>
            0x89, 0xe5,                             # mov bp, sp
    #        0x0f, 0x01, 0xe0,                       # smsw ax
    #        0x83, 0xe0, 0x01,                       # and ax, 1
    #        0xb4, 0x01                              # mov ah, 1
        ],
        []
    ),
    (
        'EnableDisableCache_Intel',
        [
            0x8a, 0xe0,                         # mov ah, al
            0x0a, 0xe4,                         # or ah, ah
            0x75, None,                         # jnz short EnableCache
            0x0f, 0x20, 0xc0,                   # mov eax, cr0
            0x66, 0x0d, 0x00, 0x00, 0x00, 0x60, # or eax, 60000000h
            0x0f, 0x22, 0xc0,                   # mov cr0, eax
            0x0f, 0x09,                         # wbinvd
            0xeb, None,                         #
            0x0f, 0x20, 0xc0,                   # mov eax, cr0
            0x66, 0x25, 0xff, 0xff, 0xff, 0x9f, # and eax, 9fffffffh
            0x0f, 0x22, 0xc0,                   # mov cr0, eax
            0x0f, 0x09,                         # wbinvd
            0xc3                                # retn
        ],
        []
    ),
    (
        'EnableProtMode',
        [
            0x66, 0x60,         # pushad
            0xe8, None, None,   # call e000_a20_on
            0x72, None,         # jc short epm_9
            0x0e, 0x1f,         # push cs, pop ds
        ],
        []
    ),
    (
        'SpuriousInterrupt',
        [
            0x66, 0x50,         # push eax
            0x52,               # push dx
            0xb0, 0xb0,         # mov al, 0b0h
            0xe6, 0x80,         # out 80h, al
            0x0f, 0x20, 0xc0,   # mov eax, cr0
        ],
        []
    ),
    (
        'ExitProtModeAfterMemtest',
        [
            0x66, 0x50,     # push eax
            0x66, 0x56,     # push esi
            0x8c, 0xd8,     # mov ax, ds
            0x8e, 0xc0,     # mov es, ax
            0x8e, 0xe8,     # mov gs, ax
            0x8e, 0xe0,     # mov fs, ax
            0xfa,           # cli
        ],
        []
    ),
    (
        'QuickMemTest',
        [
            0x68, None, None,               # push return segment
            0x68, None, None,               # push return addr
            0x68, None, None,               # push <???>
            0x68, None, None,               # push <???>
            0xEA, None, None, 0x00, 0xF0,   # jmp far locret (near, but in F segment)
            0xfa,                           # cli
            0xb8, None, None,               # mov ax, g_Segment
            0x8e, 0xd8,                     # mov ds, ax
            0x8b, 0x86, None, None,         # mov ax, word ptr <mem>[bp]
        ],
        []
    ),
    (
        'GetDisplaySwitch',
        [
            0xFA,               # cli
            0x33, 0xc9,         # xor cx, cx
            0xbb, 0x0f, 0xff,   # mov bx, 0ff0fh
        ],
        []
    ),
    (
        'DetectMemSize',
        [
            0x68, 0x00, 0xe0,                           # push return segment
            0x68, None, None,                           # push return addr
            0x68, None, None,                           # push <???>
            0x68, None, None,                           # push <???>
            0xEA, None, None, 0x00, 0xF0,               # jmp far locret (near, but in F segment)
            0xb8, 0x00, 0xf0,                           # mov ax, 0f000h
            0x8e, 0xd8,                                 # mov ds, ax
            0x8d, 0x36, 0xed, 0xff,                     # lea si, SystemByte ; (0xfffed)
            0xe8, (REF_RELATIVE, 'GetDisplaySwitch'),   # call GetSwitch
            0xe8, None, None,                           # call SpecialKbcInit
            0xfa,                                       # cli
            0xb8, 0x00, 0x00,                           # mov ax, RamSegment (0x0000)
            0x8e, 0xd8,                                 # mov ds, ax
            0xa3, 0x13, 0x04,                           # mov ds:413h, ax
        ],
        []
    ),
    (
        'DisplayMemMsg',
        [
            0xe8, (REF_RELATIVE, 'ExitProtModeAfterMemtest'),   # call ExitProtModeAfterMemtest
            0xfb,                                               # sti
            0x66, 0x50,                                         # push eax
            0x66, 0x33, 0xc0,                                   # xor eax, eax
            0x8b, 0xc2,                                         # mov ax, dx
            0x40,                                               # inc ax
        ],
        []
    ),
    (   # Earlier P2 BIOSes
        'CPUID1',
        [
            0x66, 0x53, # push ebx
            0x66, 0xb8, 0x01, 0x00, 0x00, 0x00, #mov eax, 1
            0x0f, 0xa2, # cpuid
            0x66, 0x5b, # pop ebx
            0xc3, # retn
        ],
        [
        ]
    ),
    (   # 486 variant, 2A4UKS21 courtesy of Jan Steunebrink
        'GetCPUString',
        [
            0x8A, 0x46, 0x3D,                   # mov al, [bp+PROC_ID]
            0x24, 0x7F,                         # and aL, 7Fh
            0x3C, 0x3F,                         # cmp al, 3Fh
            0x90, 0x90,                         # nop nop :3
            0xBE, None, None,                   # mov si, offset CPUSTR_Unknown
            0x77, None,                         # ja short *
            0xD0, 0xE0,                         # shl al, 1
            0x0F, 0xB6, 0xF0,                   # movzx si, al
            0x2E, 0x8B, 0xB4, None, None,       # mov si, word ptr cs:[si+CPUNameTable]
        ],
        [
            ( 'CPUSTR_Unknown', 10, CONST_WORD ),
            ( 'CPUNameTable', 22, CONST_WORD ),
        ]
    ),
    (   # 486 variant, via SOYO 025L
        'GetCPUString',
        [
            0x8A, 0x46, 0x3D,                   # mov al, [bp+PROC_ID]
            0x24, 0x7E,                         # and al, 7Eh
            0x90, 0x90,                         # nop nop :3
            0x3C, 0x4C,                         # cmp al, 4Ch
            0x90, 0x90,                         # nop nop :3
            0xBE, None, None,                   # mov si, offset CPUSTR_Unknown
            0x77, None,                         # ja short *
            0x0F, 0xB6, 0xF0,                   # movzx si, al
            0x2E, 0x8B, 0xB4, None, None,       # mov si, word ptr cs:[si+CPUNameTable]
        ],
        [
            ( 'CPUSTR_Unknown', 12, CONST_WORD ),
            ( 'CPUNameTable', 22, CONST_WORD ),
        ]
    ),
    (   # Earlier P2 BIOSes
        'GetCPUString',
        [
            0x8a, 0x46, 0x3D,               # mov al, [bp+3dh]
            0x24, 0x7e,                     # and al, 7eh
            0x3c, 0x58,                     # cmp al, 58h
            0xbe, None, None,               # mov si, offset CPUSTR_Unknown
            0x77, 0x08,                     # ja short OlderThanPentium
            0x0f, 0xb6, 0xf0,               # movzx si, al
            0x2e, 0x8b, 0xb4, None, None,   # mov si, cs:CPUNameTable[si]
        ],
        [
            ( 'CPUSTR_Unknown', 8, CONST_WORD ),
            ( 'CPUNameTable', 0x12, CONST_WORD ),
        ]
    ),
    (   # 486 variant
        'CalculateBusSpeed',
        [
            0x32, 0xff,             # xor bh, bh
            0x8b, 0xc3,             # mov ax, bx
            0xb3, 0x01,             # mov bl, 1
            0xf6, 0x46, 0x3f, 0x80, # test byte ptr [bp+3Fh], 80h
            0x74, 0x04,             # jz short ...
            0xb3, 0x03,             # mov bl, 3
            0xeb, 0x08,             # jmp short ...
            0xf6, 0x46, 0x3f, 0x40, # test byte ptr [bp+3Fh], 40h
            0x74, 0x02,             # jz short ...
            0xb3, 0x02,             # mov bl, 2
            0xf6, 0xf3,             # div bl
        ],
        [
            ( 'CPUClockTable', 0x21, CONST_WORD ),
        ]
    ),
    (
        'RoundOffClock',
        [
            0x83, 0xee, 0x03, # sub     si, 3
            0x83, 0xc6, 0x03, # add     si, 3
            0x2e, 0x8b, 0x1c, # mov     bx, cs:[si]
            0x3a, 0xc7,       # cmp     al, bh
            0x73, 0x02,       # jnb     short locret_F2131
            0xe2, 0xf4,       # loop    loc_F2125
        ],
        []
    ),
    (   # 486
        'InitCpuTypeFromTable',
        [
            0xBE, None, None,       # mov si, offset CPUSupportTable
            0x2E, 0x8B, 0x04,       # mov ax, cs:[si]
            0x2E, 0x3B, 0x54, 0x02, # cmp dx, cs:[si+2]
            0x72, 0x06,             # jb short ...
            0x2E, 0x3B, 0x54, 0x04, # cmp dx, cs:[si+4]
            0x76, 0x05,             # jbe short ...
        ],
        [
            ( 'CPUSupportTable', 0x2, CONST_WORD ),
        ]
    ),
    (   # Earlier P2 BIOSes
        'FixupCPUNameSuffixes',
        [
            0xe8, (REF_RELATIVE, 'CPUID1'), # call CPUID1
            0x24, 0xF0,                     # and al, 0f0h
            0x3c, 0x70,                     # cmp al, 70h
            0x72, 0x05,                     # jb short <whatever>
            0xb0, 0x49,                     # mov al, 49h ; 'I' <-- this is how they add I to II to make III for P3s LMFAO.
        ],
        []
    ),
    (   # 486, For CPUID-less CPUs
        'FinaliseCPUSetup_OpcodeErrorHandler',
        [
            0x55,                   # push    bp
            0x8b, 0xec,             # mov     bp, sp
            0x83, 0x46, 0x02, 0x02, # add     word ptr [bp+2], 2
            0x5d,                   # pop     bp
            0xcf,                   # iret
        ],
        []
    ),
    (   # variant 1
        'ReadCMOSByte',
        [
            0x87, 0xdb,                     # xchg bx, bx
            0xe6, 0x70,                     # out 70h, al
            0xe3, 0x00, 0xe3, 0x00,         # iodelay
            0x87, 0xdb,                     # xchg bx, bx
            0xe4, 0x71,                     # in al, 71h
            0xe3, 0x00, 0xe3, 0x00,         # iodelay
            0xc3                            # retn
        ],
        []
    ),
    (   # variant 2, now with extra nops(tm)
        'ReadCMOSByte',
        [
            0x87, 0xdb,                     # xchg bx, bx
            0x90,                           # nop
            0xe6, 0x70,                     # out 70h, al
            0xe3, 0x00, 0xe3, 0x00,         # iodelay
            0x87, 0xdb,                     # xchg bx, bx
            0xe4, 0x71,                     # in al, 71h
            0xe3, 0x00, 0xe3, 0x00,         # iodelay
            0xc3                            # retn
        ],
        []
    ),
    (
        'WriteCMOSByte',
        [
            0x90,                           # nop
            0xe6, 0x70,                     # out 70h, al
            0xe3, 0x00,                     # jcxz short $+2
            0xe3, 0x00,                     # jcxz short $+2
            0x86, 0xc4,                     # xchg al, ah
            0xe6, 0x71,                     # out 71h, al
            0xe3, 0x00,                     # jcxz short $+2
            0xe3, 0x00,                     # jcxz short $+2
            0xc3                            # retn
        ],
        []
    ),
    (
        'CMOS_ClearSMIBit',
        [
            0xb4, 0xbf,                             # mov     ah, 0BFh
            0x8a, 0xc4,                             # mov     al, ah
            0xe8, (REF_RELATIVE, 'ReadCMOSByte'),   # call    ReadCMOSByte
            0x24, 0xef,                             # and     al, 0EFh
            0x86, 0xe0,                             # xchg    ah, al
            0xe8, (REF_RELATIVE, 'WriteCMOSByte'),  # call    WriteCMOSByte
            0xc3,                                   # retn
        ],
        []
    ),
    (
        'CMOS_IsSMIBitSet',
        [
            0x50,                                   # push    ax
            0xb0, 0xbf,                             # mov     al, 0BFh
            0xe8, (REF_RELATIVE, 'ReadCMOSByte'),   # call    ReadCMOSByte
            0xa8, 0x10,                             # test    al, 10h
            0x58,                                   # pop     ax
            0xc3,                                   # retn
        ],
        []
    ),
    (
        'CMOS_ApplyCPUFeatureBits',
        [
            0xb0, 0xbd,                             # mov     al, 0BDh
            0x8a, 0xe2,                             # mov     ah, dl
            0xe8, (REF_RELATIVE, 'WriteCMOSByte'),  # call    WriteCMOSByte
            0xb4, 0xbf,                             # mov     ah, 0BFh
            0x8a, 0xc4,                             # mov     al, ah
            0xe8, (REF_RELATIVE, 'ReadCMOSByte'),   # call    ReadCMOSByte
            0x24, 0x07,                             # and     al, 7
            0x0A, 0xC6,                             # or      al, dh
        ],
        []
    ),
    (
        # This is a part of the FinalizeCPUFunction's AMD section
        # in BIOSes without 5x86 support, so it ends on 486.
        'FinalizeCPUSetup_IncompleteAMDCheck',
        [
            0x3d, 0x80, 0x04,                                   # cmp     ax, 480h
            0x74, 0x03,                                         # jz      short loc_F83AD
            0xba, None, 0x98,                                   # mov     dx, 98XXh ; <-- ID
            0xe8, (REF_RELATIVE, 'CMOS_ApplyCPUFeatureBits'),   # call    CMOS_ApplyCPUFeatureBits
        ],
        []
    ),
    (
        'Out_8042',
        [
            0x8a, 0xe0,
            0xe8, None, None,
            0x0f, 0x85, 0x07, 0x00,
            0x8a, 0xc4,
            0xe6, 0x64,
            0xe8, None, None,
            0xc3,
        ],
        []
    ),
    (
        'Out_8042_Full',
        [
            0xb4, 0x0c,
            0x33, 0xc9,
            0xe4, 0x64,
            0xe7, 0xe1,
            0xa8, 0x01,
        ],
        []
    ),
    (
        'SendCommandToKBC',
        [
            0x53,                               # push bx
            0xb4, 0x20,                         # mov ah, 20h
            0x51,                               # push cx
            0x50,                               # push ax
            0xfa,                               # cli
            0x58,                               # pop ax
            0x59,                               # pop cx
            0x51,                               # push cx
            0x50,                               # push ax
            0x8a, 0xc1,                         # mov al, cl
            0xe8, (REF_RELATIVE, 'Out_8042')    # call Out_8042
        ],
        []
    ),
    (
        'Out_8042_Aux',
        [
            0xb1, 0xd4,                                 # mov cl, 0D4h
            0xe8, (REF_RELATIVE, 'SendCommandToKBC'),   # call SedCommandToKBC
            0xc3                                        # retn
        ],
        []
    ),
    (
        'Out_8042_Aux_Full',
        [
            0xe8, (REF_RELATIVE, 'Out_8042_Full'),  # call Out_8042_Full
            0x74, 0x02,                             # jz short locret
            0xa8, 0x20,                             # test al, 20h
            0xc3                                    # retn
        ],
        []
    ),
    (
        'DisableAOBFIrq',
        [
            0xb1, 0x60,                                 # mov cl, 60h
            0xb0, 0x65,                                 # mov al, 65h
            0xe8, (REF_RELATIVE, 'SendCommandToKBC')    # call SendCommandToKBC
        ],
        []
    ),
    (
        'EnableAOBFIrq',
        [
            0xb1, 0x60,                                 # mov cl, 60h
            0xb0, 0x47,                                 # mov al, 47h
            0xe8, (REF_RELATIVE, 'SendCommandToKBC')    # call SendCommandToKBC
        ],
        []
    ),
    (
        'SetupMouse',
        [
            0xb8, 0x00, 0x00,                       # mov ax, 0
            0x8e, 0xd8,                             # mov ds, ax
            0x80, 0x26, 0x10, 0x04, 0xfb,           # and ds:410h, 0fbh
            0xfa,                                   # cli
            0xb0, 0x20,                             # mov al, 20h
            0xe8, (REF_RELATIVE, 'Out_8042'),       # call...
            0xe8, (REF_RELATIVE, 'Out_8042_Full'),  # call...
        ],
        []
    ),
    (
        'SetupMouse_SetIRQ12Handler',
        [
            0x8c, 0xc8,                             # mov ax, cs
            0xc7, 0x06, 0xd0, 0x01, None, None,     # mov ds:1d0h, <handler>
            0xa3, 0xd2, 0x01,                       # mov ds:1d2h, ax
        ],
        [        
            ( 'IRQ12Handler', 0x6, CONST_WORD ),
        ]
    ),
    (   # Dummy to find the offset of the HDD preset table
        None,                                       # No name
        [
            0xfe, 0xc8,                             # dec al
            0x32, 0xe4,                             # xor ah, ah
            0xc1, 0xe0, 0x04,                       # shl ax, 4
            0x8d, 0x36, None, None,                 # lea si, ds:<hdd param table>
            0x03, 0xf0,                             # add si, ax
        ],
        [
            ( 'HDD_PresetTable', 9, CONST_WORD ),
        ]
    ),
    (
        'CalculateHDDSize_BUGGY1', 
        [
            0x51,                   # push cx
            0x8b, 0x86, 0x94, 0x00, # mov ax, [bp+94h]
            0x32, 0xed,             # xor ch, ch
            0x8a, 0x8e, 0x96, 0x00, # mov cl, [bp+96h]
            0xf7, 0xe1,             # mul cx
            0x8a, 0x8e, 0x9b, 0x00, # mov cl, [bp+9bh]
            0xc1, 0xe1, 0x03,       # shl cx, 3
            0xf7, 0xe1,             # mul cx,
            0xb9, 0x09, 0x3d,       # mov cx, 3d09h
        ],
        []
    ),
    (
        'SetPaletteEntry',
        [
            0x50,               # push    ax
            0x53,               # push    bx
            0xb8, 0x07, 0x10,   # mov     ax, 1007h
            0xcd, 0x10,         # int     10h
            0x8a, 0xdf,         # mov     bl, bh
            0x32, 0xff,         # xor     bh, bh
            0xb8, 0x10, 0x10,   # mov     ax, 1010h
            0xcd, 0x10,         # int     10h
            0x5b,               # pop     bx
            0x58,               # pop     ax
            0xc3,               # retn
        ],
        []
    ),
    (
        'ClearEPAArea',
        [
            0xb4, 0x02,       # mov     ah, 2
            0x32, 0xff,       # xor     bh, bh
            0x50,             # push    ax
            0xcd, 0x10,       # int     10h
            0x58,             # pop     ax
            0xb4, 0x09,       # mov     ah, 9
            0xb9, 0x01, 0x00, # mov     cx, 1
            0xb3, 0x0e,       # mov     bl, 0Eh
        ],
        []
    ),
    (
        'ClearEPAAreaAndFadeOut',
        [
            0x50,                   # push    ax
            0x53,                   # push    bx
            0x51,                   # push    cx
            0x52,                   # push    dx
            0x8c, 0xdb,             # mov     bx, ds
            0x66, 0xc1, 0xe3, 0x10, # shl     ebx, 10h
            0xb8, 0x00, 0x00,       # mov     ax, 0
            0x8e, 0xd8,             # mov     ds, ax
        ],
        []
    ),
    (
        'PerformSingleFadeStep',
        [
            0x84, 0xc2,       # test    al, dl
            0x74, 0x46,       # jz      short locret_F0CB2
            0xb3, 0x0e,       # mov     bl, 0Eh
            0x90,             # nop
            0x90,             # nop
            0x80, 0xfa, 0x01, # cmp     dl, 1
            0x74, 0x04,       # jz      short loc_F0C79
            0xb3, 0x0a,       # mov     bl, 0Ah
        ],
        []
    ),
    (
        'EPAFadeOutLoop',
        [
            0x52,                                           # push    dx
            0xb2, 0x01,                                     # mov     dl, 1
            0xe8, (REF_RELATIVE, 'PerformSingleFadeStep'),  # call    PerformSingleFadeStep
            0xb2, 0x10,                                     # mov     dl, 10h
            0xe8, (REF_RELATIVE, 'PerformSingleFadeStep'),  # call    PerformSingleFadeStep
            0x5a,                                           # pop     dx
            0xfe, 0xca,                                     # dec     dl
            0x74, 0x04,                                     # jz      short loc_F0C15
        ],
        []
    )
]

STRUCT_ColorStyle_Default = (
    'ColorStyle_Default',
    [
        0x07, 0x0F, 0x70, 0x07,
        0x70, 0x78, 0x07, 0x70
    ],
    []
)

STRUCT_ColorStyle_ContainsGreen = (
    'ColorStyle_ContainsGreen',
    [
        0x0A, 0x0B, 0x3E, 0x0E,
        0x07, 0x0F, 0x70, 0x07,
    ],
    []
)

STRUCT_BIOS_Version_String1 = (
    'Str_AwardBiosVersion',
    b'Award Modular BIOS v4.50',
    [
        ( 'BIOS_VERSION', 0x4500, CONST_OFFSET_IS_VALUE ),
        ( 'Str_BiosInfo', 0xE0C1, CONST_OFFSET_IS_STRUCT ),
    ]
)

STRUCT_BIOS_Version_String2 = (
    'Str_AwardBiosVersion',
    b'Award Modular BIOS v4.51',
    [
        ( 'BIOS_VERSION', 0x4510, CONST_OFFSET_IS_VALUE ),
        ( 'Str_BiosInfo', 0xE0C1, CONST_OFFSET_IS_STRUCT ),
        ( 'Str_BiosString', 0xEC71, CONST_OFFSET_IS_STRUCT )
    ]
)

STRUCT_EnergystarAlly_String= (
    'Str_AnEnergyStarAlly',
    b', An Energy Star Ally',
    []
)

STRUCT_Copyright_String = (
    'Str_Copyright',
    b'Copyright (C) 1984',
    []
)

STRUCT_SetupMenuCopyright_String = (
    'Str_SetupMenuCopyright',
    b'AWARD SOFTWARE, INC.',
    []
)

DATA_PTR = 0
DATA_WORD_AT_ADDR = 1
DATA_BYTE = 2

DATA_GenericStructures = (
    #  Label                        Seg  Offset  Type (pointer or dereferenced)
    ( 'Sys_ChipsetInitTablePtr',    0xF, 0xF85F, DATA_PTR ),
    ( 'Sys_ChipsetInitTableendPtr', 0xF, 0xF861, DATA_PTR ),
    ( 'Sys_BiosConfigTable',        0xF, 0xE6F5, DATA_PTR ),
    ( 'Sys_BiosSupportedFeatures',  0xF, 0xFFEC, DATA_PTR ),
    ( 'CONST_BiosSupportedFeatures',  0xF, 0xFFEC, DATA_BYTE ),
#    ( 'Sys_ChipsetInitTable',       0xF, 0xF85F, DATA_WORD_AT_ADDR ),
#    ( 'Sys_ChipsetInitTable_End',   0xF, 0xF861, DATA_WORD_AT_ADDR ),
)

COMMON_STRUCT_LIST = [
    STRUCT_ColorStyle_Default,
    STRUCT_ColorStyle_ContainsGreen,
    STRUCT_BIOS_Version_String1,
    STRUCT_BIOS_Version_String2,
    STRUCT_EnergystarAlly_String,
    STRUCT_Copyright_String,
    STRUCT_SetupMenuCopyright_String
]


COMMON_LABEL_LIST = [

]

def getSegment(dataLen, offset):
    return 15 - ((dataLen - offset) >> 16)

def getBytesFromWord(word):
    word &= 0xFFFF
    return word & 0xff, word >> 8

def findSinglePattern(data, name, pattern, knownPatterns=None):
    regex = bytearray()

    referencesToCheck = []

    curPos = 0

    for i in pattern:
#        print(type(i))
        if i is None:
            regex.append(ord('.'))
            curPos += 1

        elif type(i) is tuple and knownPatterns is not None:
            # tuple means reference to a previously known pattern, which requires a lot more work later on :\

            referenceType, referenceLabel = i

            # if the requested reference is known, add it, else we need to get out

            found = False

            for knownName, ea in knownPatterns:
                if knownName == referenceLabel:
                    #                           offset, type of reference, label of reference, absolute offset of the reference
                    referencesToCheck.append( (curPos, referenceType, referenceLabel, ea) )
                    found = True

            # We don't know this function, so we can't process this one!

            if not found:
                print(f'Error: Function {referenceLabel} requested by pattern {name} is not known yet! Skipping pattern scan')
                return None

            # Add placeholders for now

            regex.append(ord('.'))
            regex.append(ord('.'))
            
            curPos += 2

#            for name, ea in knownPatterns:
#                if name == i:
#                    offset = ea & 0xFFFF
#                    lo = offset & 0xff
#                    hi = offset >> 8
#                    print(f'Using offset address of known pattern {name}, offset {hex(offset)}')
#                    regex += f'\\x{lo:02x}'.encode()
#                    regex += f'\\x{hi:02x}'.encode()
#                    print(f'{regex}')

        else:
            regex += f'\\x{i:02x}'.encode()
            curPos += 1
    
#    print(f'Pattern {pattern} -> {regex}')

    if len(referencesToCheck) > 0:
        print(f'Scanning Referencing previously known functions/structs: {referencesToCheck}')

        allMatches = re.finditer(bytes(regex), data)

        # Go through all matches and find one that matches perfectly

        for match in allMatches:
            matchOffset = match.start()
            #print(matchOffset)

            allFound = True

            # Check that all references match
            for referenceOffsetInPattern, referenceType, referenceLabel, referenceAbsolute in referencesToCheck:
                if referenceType == REF_ABSOLUTE:
                    matchWordAtReferenceOffset = getConstantFromData(data, matchOffset + referenceOffsetInPattern, CONST_WORD)
                    allFound = allFound and (matchWordAtReferenceOffset == (referenceAbsolute & 0xFFFF))
                elif referenceType == REF_RELATIVE:
                    # For calls things get a bit more... interesting.
                    matchWordAtReferenceOffset = getConstantFromData(data, matchOffset + referenceOffsetInPattern, CONST_WORD)
                    relativeTo = matchOffset + referenceOffsetInPattern + 2

                    relativeOffset = (referenceAbsolute - relativeTo) & 0xFFFF

                    # print(f'matchoffset {hex(matchOffset)} offsetinpattern {hex(referenceOffsetInPattern)} abs {hex(referenceAbsolute)} rel {hex(relativeOffset)} inMatch {hex(matchWordAtReferenceOffset)}')

                    allFound = allFound and (matchWordAtReferenceOffset == relativeOffset)

            if allFound:
                # print(f'...Success at {hex(matchOffset)}')
                return matchOffset
   
        ret = None
    else:
        # There is just one regex to check
        ret = re.search(bytes(regex), data)
    

    if ret is None:
        return None
        
    return ret.start()

def findPatterns(data, patternlist):
    foundItems = []
    foundConsts = []
    for name, pattern, constants in patternlist:
        #print(f'{name} {pattern}')
        ea = findSinglePattern(data, name, pattern, foundItems)

        if ea is not None:
            known = False

            # If this is not a dummy
            if name:
                # Check if we already know a matched pattern with this name
                # This is not a big deal, but we need to prevent it from being added
                # to the list in order to avoid IDA errors later
                for knownItem in foundItems:
                    if knownItem[0] == name:
                        print(f'WARNING: Duplicate pattern; "{name}" is already known!')
                        known = True

                if known: continue

                foundItems.append((name, ea))

            matchSegment = getSegment(len(data), ea)
            matchSegmentAbsolute = matchSegment << 16

            # Find all the constant exports associated with this pattern:
            if constants is not None:
                for constName, constOffset, constType in constants:
                    if constType == CONST_OFFSET_IS_STRUCT:
                        constOffset |= matchSegmentAbsolute
                        foundItems.append((constName, constOffset))
                    elif constType == CONST_OFFSET_IS_VALUE:
                        foundConsts.append((constName, constOffset))
                    else:
                        foundConsts.append((constName, getConstantFromData(data, ea + constOffset, constType)))

    return foundItems, foundConsts

def getAbsoluteAddress(length, segment, offset):
    actualSegment = (length >> 16) - (15 - segment)
    return (actualSegment << 16) | offset

def readGenericData(data, datalist):
    foundItems = []
    
    for dataName, dataSegment, dataOffset, dataType in datalist:
        if dataType == DATA_PTR:
            val = dataOffset
        elif dataType == DATA_WORD_AT_ADDR:
            absolute = getAbsoluteAddress(len(data), dataSegment, dataOffset)
            val = getConstantFromData(data, absolute, CONST_WORD)
        elif dataType == DATA_BYTE:
            absolute = getAbsoluteAddress(len(data), dataSegment, dataOffset)
            val = getConstantFromData(data, absolute, CONST_BYTE)
        else:
            raise Exception('Invalid data type')

        print(f'readGenericData({dataName}, {dataSegment}, {hex(dataOffset)}, {dataType}) -> {hex(val)}')

        foundItems.append((dataName, dataSegment, val))

    return foundItems

def writeConstantsToIncludeFile(outfile, constantList):
    # Write out constants
    for constName, constValue in constantList:
        outfile.write(f'{constName.ljust(40)} EQU 0{constValue:x}h\n')

def writeMatchedLabelsToIncludeFile(dataLen, outfile, matchList):
    for matchName, matchLoc in matchList:
        # Write this out into the include file
        funcNameComma = matchName + ', '
        segment = getSegment(dataLen, matchLoc)
#        outfile.write(f' LBL {funcNameComma.ljust(40)} 0{(matchLoc & 0xffff):x}h ; Segment {segment}\n')
        outfile.write(f' SEGLBL {funcNameComma.ljust(40)} SEG_{segment}, G_{segment}, 0{(matchLoc & 0xffff):x}h ; Segment {segment}\n')

def writeGenericDataToIncludeFile(outfile, dataList):
    for name, segment, offset in dataList:
        outfile.write(f'{name.ljust(40)} EQU 0{offset:x}h\n')
#        outfile.write(f' SEGLBL {nameComma.ljust(40)} SEG_{segment}, G_{segment}, 0{(matchLoc & 0xffff):x}h ; Segment {segment}\n')


def writeSingleEquate(outfile, name, value):
    outfile.write(f'{name.ljust(40)} EQU 0{value:x}h\n')

def writeSingleSegLbl(outfile, name, segment, offset):
    outfile.write(f' SEGLBL {name.ljust(40) + ', '} SEG_{segment}, G_{segment}, 0{offset:x}h ; Segment {segment}\n')

def makeAsmLabel(prefix, name):
    # Split on anything that's not A-Z, a-z or 0-9
    words = re.findall(r"[A-Za-z0-9]+", name)

    # Convert to PascalCase
    label = "".join(word.capitalize() for word in words)

    if not label: label = "Unnamed"

    return prefix + '_' + label


def sanitizeAwardString(input):
    ret = ''
    for i in range(0, len(input)):
        c = ord(input[i])
        if   c <= 0x01: break
        elif c == 0x02: i += 5
        elif c == 0x03: i += 4
        elif c == 0x04: i += 4
        elif c == 0x05: i += 2
        elif c >= 0x06 and c <= 0x0b: continue
        elif c >= 0x0c and c <= 0x0f: i += 1
        elif c == 0x10: i += 2
        elif input[i] == ':': continue
        elif c >= 0x20: ret += chr(c)
#        elif input[i] >= '0' and input[i] <= '9': ret += chr(c)
#        elif input[i] >= 'A' and input[i] <= 'Z': ret += chr(c)
#        elif input[i] >= 'a' and input[i] <= 'z': ret += chr(c)
        else: continue

    return ret.strip()


def writeMenuDataToIncludeFile (outfile, menus: list[award45x_ida.MenuInfo]):
    writeSingleSegLbl(outfile, 'BIOS_SysBiosMenuTablePtr', 15, 0xf85d)
    writeSingleSegLbl(outfile, 'BIOS_SysBiosMenuTable', 15, menus[0].sysBiosEntry_ptr & 0xffff)
    writeSingleEquate(outfile, 'BIOS_SysBiosMenuEntries', len(menus))


    for i in range(1, len(menus)):
        currentMenu = menus[i]

        if currentMenu.title.strip() == '': continue
        exportLabel = makeAsmLabel('Menu', currentMenu.title)
        writeSingleSegLbl(outfile, exportLabel, 15, currentMenu.sysBiosEntry_ptr & 0xffff)

    # Write our data for menu items to the include file
    for menu in menus:
        for item in menu.items:
            a = sanitizeAwardString(item.name)
            o = item.ea & 0xffff

            # Special case for HDD Preset disable mod: C/D/E/F config option
            if      a.startswith("Drive C") or a.startswith("Primary Master"):
                writeSingleSegLbl(outfile, "Menuitem_HDD_C", 15, o)
            elif    a.startswith("Drive D") or a.startswith("Primary Slave"):
                writeSingleSegLbl(outfile, "Menuitem_HDD_D", 15, o)
            elif    a.startswith("Secondary Master"):
                writeSingleEquate(outfile, "BIOS_SupportsDualChannel", 1)
                writeSingleSegLbl(outfile, "Menuitem_HDD_E", 15, o)
            elif    a.startswith("Secondary Slave"):
                writeSingleSegLbl(outfile, "Menuitem_HDD_F", 15, o)

            # Export symbols for all HIDDEN options
            if item.flags & 0b1000:
                print(f'Hidden menu item @ {item.ea:02X}: {menu.title} / {a}')
                outfile.write(f'; HIDDEN Menu item {menu.title} / {a}\n')
                exportLabel = makeAsmLabel("Menuitem_HIDDEN", a)
                writeSingleEquate(outfile, f'{exportLabel}_FLAGS', item.flags)
                writeSingleSegLbl(outfile, exportLabel, 15, o)

def findFuncs_IDA():

    data = bytearray(ida_bytes.get_bytes(0, 0xFFFFF))

    foundFuncs, foundFuncConsts = findPatterns(data, COMMON_FUNCTION_LIST)
    foundStructs, foundStructConsts = findPatterns(data, COMMON_STRUCT_LIST)
    
    foundData = readGenericData(data, DATA_GenericStructures)

    foundMenus = award45x_ida.parseMenuFromScratch()

    # print(foundFuncs)
    # print(foundFuncConsts)
    # print(foundStructs)
    # print(foundStructConsts)

    with open('CMN_FUNC.INC', 'w') as asmInclude:

        asmInclude.write('; AUTO-GENERATED\n')

        asmInclude.write('\n\n; GENERIC DATA STRUCTURES AND LABELS \n\n')

        writeGenericDataToIncludeFile(asmInclude, foundData)

        asmInclude.write('\n\n; COMMON BIOS CONSTANTS \n\n')

        writeConstantsToIncludeFile(asmInclude,  foundFuncConsts)
        writeConstantsToIncludeFile(asmInclude,  foundStructConsts)
        
        asmInclude.write('\n\n; COMMON BIOS FUNCTIONS \n\n')

        writeMatchedLabelsToIncludeFile(len(data), asmInclude, foundFuncs)
        
        asmInclude.write(f'\n\n; COMMON BIOS STRUCTURES \n\n')

        writeMatchedLabelsToIncludeFile(len(data), asmInclude, foundStructs)

        asmInclude.write(f'\n\n; MENU DATA \n\n')

        writeMenuDataToIncludeFile (asmInclude,  foundMenus)


        for funcName, funcLoc in foundFuncs:

            # If in IDA this is not already a function, make it one

            flags = ida_bytes.get_flags(funcLoc)

            if not ida_bytes.is_code(flags):

                ida_bytes.del_items(
                    funcLoc,
                    ida_bytes.DELIT_SIMPLE,
                    1
                )
                success = ida_ua.create_insn(funcLoc) and ida_funcs.add_func(funcLoc)
            
                if not success:
                    raise Exception(f"Couldn't make function {funcName} at {hex(funcLoc)} in IDA")
            
            # Set the label for this location in the disassembly to the function name

            success = ida_name.set_name(funcLoc, funcName)
            if not success:
                raise Exception(f"Couldn't rename function {funcName} in IDA")


# freaking python

importlib.reload(award45x_ida)
findFuncs_IDA()
