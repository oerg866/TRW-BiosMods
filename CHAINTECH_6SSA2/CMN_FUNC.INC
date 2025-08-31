; AUTO-GENERATED


; GENERIC DATA STRUCTURES AND LABELS 

Sys_ChipsetInitTablePtr                  EQU 0f85fh
Sys_ChipsetInitTableendPtr               EQU 0f861h


; COMMON BIOS CONSTANTS 

BP_CurrentColorStyle                     EQU 014bh
BP_ClipBottomY                           EQU 01c5h
BIOS_VERSION                             EQU 04510h


; COMMON BIOS FUNCTIONS 

 SEGLBL Display_String,                          SEG_15, G_15, 042c8h ; Segment 15
 SEGLBL DispStr_RestoreTextAttr,                 SEG_15, G_15, 044b3h ; Segment 15
 SEGLBL Write_Character,                         SEG_15, G_15, 04510h ; Segment 15
 SEGLBL DispStr_LF,                              SEG_15, G_15, 04cbbh ; Segment 15
 SEGLBL DispStr_CR,                              SEG_15, G_15, 04cd0h ; Segment 15
 SEGLBL DispStr_CRLF,                            SEG_15, G_15, 04cb4h ; Segment 15
 SEGLBL SetCursorPosition,                       SEG_15, G_15, 04bfch ; Segment 15
 SEGLBL DrawAwardRibbon,                         SEG_14, G_14, 01d86h ; Segment 14
 SEGLBL DispStr_CRLF_FAR,                        SEG_14, G_14, 08b34h ; Segment 14
 SEGLBL SetCursorPosition_FAR,                   SEG_14, G_14, 08b22h ; Segment 14
 SEGLBL Write_Character_FAR,                     SEG_14, G_14, 08aech ; Segment 14
 SEGLBL Display_String_FAR,                      SEG_14, G_14, 08b7ch ; Segment 14
 SEGLBL Display_String_FAR_SaveDX,               SEG_14, G_14, 08c06h ; Segment 14
 SEGLBL Display_String_FAR_CS,                   SEG_14, G_14, 08be8h ; Segment 14
 SEGLBL Display_String_FAR_CS_SaveDX,            SEG_14, G_14, 08c00h ; Segment 14
 SEGLBL Display_String_FAR_SaveCursor,           SEG_14, G_14, 01e1bh ; Segment 14
 SEGLBL CheckIfWarmReboot,                       SEG_14, G_14, 012a0h ; Segment 14
 SEGLBL PrintPOSTStrings,                        SEG_14, G_14, 01b98h ; Segment 14
 SEGLBL OutPort16,                               SEG_14, G_14, 01dd4h ; Segment 14
 SEGLBL CheckCTRLAltDel,                         SEG_15, G_15, 0aa75h ; Segment 15
 SEGLBL Start_1,                                 SEG_15, G_15, 0f470h ; Segment 15
 SEGLBL ISR_IRQ12_PS2Mouse,                      SEG_15, G_15, 0eeb0h ; Segment 15
 SEGLBL EnableDisableCache_Intel,                SEG_15, G_15, 0e4a0h ; Segment 15
 SEGLBL EnableProtMode,                          SEG_14, G_14, 01e68h ; Segment 14
 SEGLBL SpuriousInterrupt,                       SEG_14, G_14, 01ed8h ; Segment 14
 SEGLBL ExitProtModeAfterMemtest,                SEG_14, G_14, 01ef0h ; Segment 14
 SEGLBL GetDisplaySwitch,                        SEG_14, G_14, 01ac0h ; Segment 14
 SEGLBL MemTest,                                 SEG_14, G_14, 02090h ; Segment 14
 SEGLBL DispMemMsg,                              SEG_14, G_14, 024d4h ; Segment 14


; COMMON BIOS STRUCTURES 

 SEGLBL ColorStyle_Default,                      SEG_15, G_15, 035b5h ; Segment 15
 SEGLBL ColorStyle_ContainsGreen,                SEG_15, G_15, 035f1h ; Segment 15
 SEGLBL Str_AwardBiosVersion,                    SEG_15, G_15, 0e061h ; Segment 15
 SEGLBL Str_BiosInfo,                            SEG_15, G_15, 0e0c1h ; Segment 15
 SEGLBL Str_BiosString,                          SEG_15, G_15, 0ec71h ; Segment 15
 SEGLBL Str_AnEnergyStarAlly,                    SEG_14, G_14, 0397dh ; Segment 14
 SEGLBL Str_Copyright,                           SEG_15, G_15, 0e091h ; Segment 15
 SEGLBL Str_SetupMenuCopyright,                  SEG_15, G_15, 02b8h ; Segment 15
