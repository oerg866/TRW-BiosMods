; AUTO-GENERATED


; GENERIC DATA STRUCTURES AND LABELS 

Sys_ChipsetInitTablePtr                  EQU 0f85fh
Sys_ChipsetInitTableendPtr               EQU 0f861h


; COMMON BIOS CONSTANTS 

BP_CurrentColorStyle                     EQU 014bh
BP_ClipBottomY                           EQU 01c5h
Sys_ChipsetInitTable                     EQU 0114ch
Sys_ChipsetInitTable_end                 EQU 011d8h
BIOS_VERSION                             EQU 04510h


; COMMON BIOS FUNCTIONS 

 SEGLBL Display_String,                          SEG_15, G_15, 0377ch ; Segment 15
 SEGLBL DispStr_RestoreTextAttr,                 SEG_15, G_15, 0395eh ; Segment 15
 SEGLBL Write_Character,                         SEG_15, G_15, 039bbh ; Segment 15
 SEGLBL DispStr_LF,                              SEG_15, G_15, 0418bh ; Segment 15
 SEGLBL DispStr_CR,                              SEG_15, G_15, 041a0h ; Segment 15
 SEGLBL DispStr_CRLF,                            SEG_15, G_15, 04184h ; Segment 15
 SEGLBL SetCursorPosition,                       SEG_15, G_15, 040cch ; Segment 15
 SEGLBL DrawAwardRibbon,                         SEG_14, G_14, 02c24h ; Segment 14
 SEGLBL DispStr_CRLF_FAR,                        SEG_14, G_14, 088f8h ; Segment 14
 SEGLBL SetCursorPosition_FAR,                   SEG_14, G_14, 088e6h ; Segment 14
 SEGLBL Write_Character_FAR,                     SEG_14, G_14, 088b0h ; Segment 14
 SEGLBL Display_String_FAR,                      SEG_14, G_14, 08940h ; Segment 14
 SEGLBL Display_String_FAR_SaveDX,               SEG_14, G_14, 089cah ; Segment 14
 SEGLBL Display_String_FAR_CS,                   SEG_14, G_14, 089ach ; Segment 14
 SEGLBL Display_String_FAR_CS_SaveDX,            SEG_14, G_14, 089c4h ; Segment 14
 SEGLBL Display_String_FAR_SaveCursor,           SEG_14, G_14, 02cbbh ; Segment 14
 SEGLBL CheckIfWarmReboot,                       SEG_14, G_14, 02130h ; Segment 14
 SEGLBL PrintPOSTStrings,                        SEG_14, G_14, 02a3ch ; Segment 14
 SEGLBL EarlyChipsetInit,                        SEG_15, G_15, 05380h ; Segment 15
 SEGLBL OutPort16,                               SEG_14, G_14, 02c74h ; Segment 14


; COMMON BIOS STRUCTURES 

 SEGLBL ColorStyle_Default,                      SEG_15, G_15, 02a9dh ; Segment 15
 SEGLBL ColorStyle_ContainsGreen,                SEG_15, G_15, 02ad9h ; Segment 15
 SEGLBL Str_AwardBiosVersion,                    SEG_15, G_15, 0e061h ; Segment 15
 SEGLBL Str_BiosInfo,                            SEG_15, G_15, 0e0c1h ; Segment 15
 SEGLBL Str_AnEnergyStarAlly,                    SEG_14, G_14, 0429ah ; Segment 14
 SEGLBL Str_Copyright,                           SEG_15, G_15, 0e091h ; Segment 15
 SEGLBL Str_SetupMenuCopyright,                  SEG_15, G_15, 02a0h ; Segment 15
