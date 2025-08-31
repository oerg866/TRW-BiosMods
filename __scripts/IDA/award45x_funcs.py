import re
import ida_bytes
import ida_name
import ida_ua
import ida_funcs

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

# Name = (
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

FUNCTION_Display_String = (
    'Display_String',
    [
        0x06, 0x57, 0x53,                   # push es, push di, push bx
        0xAC,                               # lodsb
        0x3C, 0x00                          # cmp al, 0
    ],
    []
)

FUNCTION_Display_CS_String = (
    'Display_CS_String',
    [
        0x1E, 0x0E, 0x1F,                   # push ds, push cs, pop ds
        0xE8, None, None,                   # call * (Display_String)
        0x1F, 0xC3                          # pop ds, retn
    ],
    []
)

FUNCTION_DispStr_RestoreTextAttr = (
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
)

FUNCTION_Write_Character1 = (               # 4.50
    'Write_Character',
    [
        0x50, 0x53, 0x51, 0x52, 0x50,       # push ax, push bx, push cx, push dx, push ax
        0x8A, 0x96, 0x81, 0x00,             # mov     dl, [bp+TEXT_X]
        0x8A, 0xB6, 0x82, 0x00,             # mov     dh, [bp+TEXT_Y]
    ],
    []
)

FUNCTION_Write_Character2 = (   # 4.51 
    'Write_Character',
    [
        0x50, 0x53, 0x51, 0x52, 0x9C, 0x50, # push ax, push bx, push cx, push dx, pushf, push ax
        0x8A, 0x96, 0x81, 0x00,             # mov     dl, [bp+TEXT_X]
        0x8A, 0xB6, 0x82, 0x00,             # mov     dh, [bp+TEXT_Y]
    ],
    []
)

FUNCTION_DispStr_LF = (
    'DispStr_LF',
    [
        0x50, 
        0x8A, 0x86, 0x82, 0x00,
        0x3A, 0x86, None, 0x01,
    ],
    [
        ('BP_ClipBottomY', 7, CONST_WORD)
    ]
)

FUNCTION_DispStr_CR = (
    'DispStr_CR',
    [
        0x50, 
        0x8A, 0x86, None, 0x01,
        0x88, 0x86, 0x81, 0x00,
    ],
    []
)

FUNCTION_DispStr_CRLF = (
    'DispStr_CRLF',
    [
        0xE8, 0x04, 0x00,
        0xE8, 0x16, 0x00,
        0xC3
    ],
    []
)

FUNCTION_SetCursorPosition = (
    'SetCursorPosition',
    [
        0x89, 0x96, 0x81, 0x00,             # mov [bp+TEXT_X], dx
        0x83, 0xBE, None, 0x01              # cmp word ptr [bp+1**h], 0
    ],
    []
)

FUNCTION_DrawAwardRibbon = (
    'DrawAwardRibbon',
    [
        0x8A, 0x9E, 0x80, 0x00,             # mov bl, [bp+TEXT_ATTR]
        0x53,                               # push bx 
        0xC6, 0x86, 0x80, 0x00, 0x09,       # mov byte ptr [bp+TEXT_ATTR], 9
        0xBA, None, None,                   # mov dx, * (cursor position)
        0xE8, None, None                    # call * (SetCursorPosition)
    ],
    []
)


###############################################
# FAR functions called from E segment
# WATCH OUT - this is hacky as f-

FUNCTION_DispStr_CRLF_FAR = (
    'DispStr_CRLF_FAR',
    [
        0x68, 0x00, 0xe0,   # push 0e000h (segment index)
        0x68, None, None,   # push locret (near, in E segment)
        0x68, None, None,   # push locret (far, in F segment)
        0x68, (REF_ABSOLUTE, 'DispStr_CRLF'), # push address - honestly the most ingenious hack of all time
        0xEA, None, None, 0x00, 0xF0  # jmp far locret (near, but in F segment)
    ],
    []
)

FUNCTION_SetCursorPosition_FAR = (
    'SetCursorPosition_FAR',
    [
        0x68, 0x00, 0xe0,   # push 0e000h (segment index)
        0x68, None, None,   # push locret (near, in E segment)
        0x68, None, None,   # push locret (far, in F segment)
        0x68, (REF_ABSOLUTE, 'SetCursorPosition'), # push address
        0xEA, None, None, 0x00, 0xF0  # jmp far locret (near, but in F segment)
    ],
    []
)

FUNCTION_Write_Character_FAR = (
    'Write_Character_FAR',
    [
        0x68, 0x00, 0xe0,   # push 0e000h (segment index)
        0x68, None, None,   # push locret (near, in E segment)
        0x68, None, None,   # push locret (far, in F segment)
        0x68, (REF_ABSOLUTE, 'Write_Character'), # push address
        0xEA, None, None, 0x00, 0xF0  # jmp far locret (near, but in F segment)
    ],
    []
)

FUNCTION_Display_String_FAR = (
    'Display_String_FAR',
    [
        0x68, 0x00, 0xe0,   # push 0e000h (segment index)
        0x68, None, None,   # push locret (near, in E segment)
        0x68, None, None,   # push locret (far, in F segment)
        0x68, (REF_ABSOLUTE, 'Display_String'), # push address 
        0xEA, None, None, 0x00, 0xF0  # jmp far locret (near, but in F segment)
    ],
    []
)

FUNCTION_Display_String_FAR_SaveDX = (
    'Display_String_FAR_SaveDX',
    [
        0x52,                                           # push dx
        0xE8, (REF_RELATIVE, 'Display_String_FAR'),     # call Display_String_FAR
        0x5A,                                           # pop dx
        0xC3,                                           # retn
    ],
    []
)

FUNCTION_Display_String_FAR_CS_v1 = (   # Variant 1
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
)

FUNCTION_Display_String_FAR_CS_v2 = (   # Variant 2, calls the FAR routine instead of doing a manual far call
    'Display_String_FAR_CS',
    [
        0x1E, 0x0E, 0x1F,   # push ds, push cs, pop ds
        0xE8, (REF_RELATIVE, 'Display_String_FAR'),     # call Display_String_FAR
        0x1F, 0xC3          # pop ds, retn
    ],
    []
)

FUNCTION_Display_String_FAR_CS_SaveDX = (
    'Display_String_FAR_CS_SaveDX',
    [
        0x52,                                           # push dx
        0xE8, (REF_RELATIVE, 'Display_String_FAR_CS'),  # call Display_String_FAR_CS
        0x5A,                                           # pop dx
        0xC3,                                           # retn
    ],
    []
)

FUNCTION_Display_String_FAR_SaveCursor = (
    'Display_String_FAR_SaveCursor',
    [
        0xFF, 0xB6, 0x81, 0x00,                                 # push word ptr [bp+81h]
        0xE8, (REF_RELATIVE, 'Display_String_FAR_CS_SaveDX'),  # call  Display_String_FAR_CS_SaveDX
        0x8F, 0x86, 0x81, 0x00,                                 # pop word ptr [bp+81h]
        0x60,                                                   # pusha
    ],
    []
)

FUNCTION_CheckIfWarmReboot = (
    'CheckIfWarmReboot',
    [
        0x1E, 0x50,                             # push ds, push ax
        0xB8, 0x00, 0x00,                       # mov ax, 0
        0x8E, 0xD8,                             # mov ds, ax
        0x81, 0x3E, 0x72, 0x04, 0x34, 0x12,     # cmp word ptr ds:472h, 1234h
    ],
    []
)

FUNCTION_PrintPOSTStrings_451_v1 = (    # Variant 1
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
    [
    ]
)

FUNCTION_PrintPOSTStrings_451_v2 = (    # Variant 2
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
    [
    ]
)


FUNCTION_EarlyChipsetInit = (
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
)


FUNCTION_OutPort16 = (
    'OutPort16',
    [
        0xEE, 0xFE, 0xC2, 0x86, 0xE0,           # out dx, al | inc dl | xchg ah, al
        0xEE, 0xFE, 0xCA, 0x86, 0xE0            # out dx, al | dec dl | xchg ah, al
    ],
    [
    ]
)

FUNCTION_CheckCTRLAltDel = (
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
)

FUNCTION_Reboot = (
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
)

FUNCTION_Start_1 = (
    'Start_1',
    [
        0x8E, 0xEA,                             # mov gs, dx
        0xFA, 0xFC,                             # cli | cld
        0xE4, 0x64,                             # in al, 64h
        0xA8, 0x04,                             # test al, 4
    ],
    [
    ]
)

FUNCTION_ISR_IRQ12_PS2Mouse = (
    'ISR_IRQ12_PS2Mouse',
    [
        0x50, 0x53, 0x51, 0x56, 0x57, 0x55,     # push ax, bx, cx, si, di, bp,
        0x1e, 0x06,  0xfc,                      # push ds, push es, cld
        0xe4, 0x60,                             # in al, 60h
    ],
    [
    ]
)

FUNCTION_EnableDisableCacheIntel = (
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
)

FUNCTION_EnableProtMode = (
    'EnableProtMode',
    [
        0x66, 0x60,         # pushad
        0xe8, None, None,   # call e000_a20_on
        0x72, None,         # jc short epm_9
        0x0e, 0x1f,         # push cs, pop ds
    ],
    []
)

FUNCTION_SpuriousInterrupt = (
    'SpuriousInterrupt',
    [
        0x66, 0x50,         # push eax
        0x52,               # push dx
        0xb0, 0xb0,         # mov al, 0b0h
        0xe6, 0x80,         # out 80h, al
        0x0f, 0x20, 0xc0,   # mov eax, cr0
    ],
    []
)

FUNCTION_ExitProtModeAfterMemtest = (
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
)

FUNCTION_GetDisplaySwitch = (
    'GetDisplaySwitch',
    [
        0xFA,               # cli
        0x33, 0xc9,         # xor cx, cx
        0xbb, 0x0f, 0xff,   # mov bx, 0ff0fh
    ],
    []
)

FUNCTION_DetectMemSize = (
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
)
FUNCTION_DisplayMemMsg = (
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
)

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

DATA_GenericStructures = (
    #  Label                        Seg  Offset  Type (pointer or dereferenced)
    ( 'Sys_ChipsetInitTablePtr',    0xF, 0xF85F, DATA_PTR ),
    ( 'Sys_ChipsetInitTableendPtr', 0xF, 0xF861, DATA_PTR ),
#    ( 'Sys_ChipsetInitTable',       0xF, 0xF85F, DATA_WORD_AT_ADDR ),
#    ( 'Sys_ChipsetInitTable_End',   0xF, 0xF861, DATA_WORD_AT_ADDR ),
)

COMMON_FUNCTION_LIST = [
    FUNCTION_Display_String,
    FUNCTION_DispStr_RestoreTextAttr,
    FUNCTION_Write_Character1,
    FUNCTION_Write_Character2,
    FUNCTION_DispStr_LF,
    FUNCTION_DispStr_CR,
    FUNCTION_DispStr_CRLF,
    FUNCTION_SetCursorPosition,
    FUNCTION_DrawAwardRibbon,
    FUNCTION_DispStr_CRLF_FAR,
    FUNCTION_SetCursorPosition_FAR,
    FUNCTION_Write_Character_FAR,
    FUNCTION_Display_String_FAR,
    FUNCTION_Display_String_FAR_SaveDX,
    FUNCTION_Display_String_FAR_CS_v1,
    FUNCTION_Display_String_FAR_CS_v2,
    FUNCTION_Display_String_FAR_CS_SaveDX,
    FUNCTION_Display_String_FAR_SaveCursor,
    FUNCTION_CheckIfWarmReboot,
    FUNCTION_PrintPOSTStrings_451_v1,
    FUNCTION_PrintPOSTStrings_451_v2,
    FUNCTION_EarlyChipsetInit,
    FUNCTION_OutPort16,
    FUNCTION_CheckCTRLAltDel,
    FUNCTION_Reboot,
    FUNCTION_Start_1,
    FUNCTION_ISR_IRQ12_PS2Mouse,
    FUNCTION_EnableDisableCacheIntel,
    FUNCTION_EnableProtMode,
    FUNCTION_SpuriousInterrupt,
    FUNCTION_ExitProtModeAfterMemtest,
    FUNCTION_GetDisplaySwitch,
    FUNCTION_DetectMemSize,
    FUNCTION_DisplayMemMsg
]

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

def findSinglePattern(data, pattern, knownPatterns=None):
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

            for name, ea in knownPatterns:
                if name == referenceLabel:
                    #                           offset, type of reference, label of reference, absolute offset of the reference
                    referencesToCheck.append( (curPos, referenceType, referenceLabel, ea) )
                    found = True

            # We don't know this function, so we can't process this one!

            if not found:
                print(f'Error: Function {referenceLabel} requested by pattern is not known yet! Skipping pattern scan')
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

                    print(f'matchoffset {hex(matchOffset)} offsetinpattern {hex(referenceOffsetInPattern)} abs {hex(referenceAbsolute)} rel {hex(relativeOffset)} inMatch {hex(matchWordAtReferenceOffset)}')

                    allFound = allFound and (matchWordAtReferenceOffset == relativeOffset)
                    print(allFound)

            if allFound:
                print(f'...Success at {hex(matchOffset)}')
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
        ea = findSinglePattern(data, pattern, foundItems)

        if ea is not None:
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
    actualSegment = (length >> 16) - (16 - segment)
    return (actualSegment << 16) | offset

def readGenericData(data, datalist):
    foundItems = []
    
    for dataName, dataSegment, dataOffset, dataType in datalist:
        if dataType == DATA_PTR:
            val = dataOffset
        elif dataType == DATA_WORD_AT_ADDR:
            absolute = getAbsoluteAddress(len(data), dataSegment, dataOffset)
            val = getConstantFromData(data, absolute, CONST_WORD)
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

def findFuncs_IDA():

    data = bytearray(ida_bytes.get_bytes(0, 0xFFFFF))

    foundFuncs, foundFuncConsts = findPatterns(data, COMMON_FUNCTION_LIST)
    foundStructs, foundStructConsts = findPatterns(data, COMMON_STRUCT_LIST)
    
    foundData = readGenericData(data, DATA_GenericStructures)

    print(foundFuncs)
    print(foundFuncConsts)
    print(foundStructs)
    print(foundStructConsts)

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

        for funcName, funcLoc in foundFuncs:

            # If in IDA this is not already a function, make it one

            flags = ida_bytes.get_flags(funcLoc)

            if not ida_bytes.is_code(flags):

                ida_bytes.del_items(funcLoc)
                success = ida_ua.create_insn(funcLoc) and ida_funcs.add_func(funcLoc)
            
                if not success:
                    raise Exception(f"Couldn't make function {funcName} at {hex(funcLoc)} in IDA")
            
            # Set the label for this location in the disassembly to the function name

            success = ida_name.set_name(funcLoc, funcName)
            if not success:
                raise Exception(f"Couldn't rename function {funcName} in IDA")


findFuncs_IDA()