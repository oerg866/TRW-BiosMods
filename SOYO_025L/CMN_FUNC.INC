; AUTO-GENERATED


; GENERIC DATA STRUCTURES AND LABELS 

Sys_ChipsetInitTablePtr                  EQU 0f85fh
Sys_ChipsetInitTableendPtr               EQU 0f861h
Sys_BiosConfigTable                      EQU 0e6f5h
Sys_BiosSupportedFeatures                EQU 0ffech
CONST_BiosSupportedFeatures              EQU 01h


; COMMON BIOS CONSTANTS 

BP_CurrentColorStyle                     EQU 012bh
BP_ClipBottomY                           EQU 01a5h
Str_BiosString                           EQU 0ec71h
CPUSTR_Unknown                           EQU 08248h
CPUNameTable                             EQU 081d2h
CPUClockTable                            EQU 02132h
CPUSupportTable                          EQU 02e7fh
IRQ12Handler                             EQU 0d8d0h
HDD_PresetTable                          EQU 0e401h
BIOS_VERSION                             EQU 04500h


; COMMON BIOS FUNCTIONS 

 SEGLBL Display_String,                          SEG_15, G_15, 03696h ; Segment 15
 SEGLBL Display_CS_String,                       SEG_15, G_15, 010e1h ; Segment 15
 SEGLBL DispStr_RestoreTextAttr,                 SEG_15, G_15, 0386bh ; Segment 15
 SEGLBL Write_Character,                         SEG_15, G_15, 038c3h ; Segment 15
 SEGLBL DispStr_LF,                              SEG_15, G_15, 027d7h ; Segment 15
 SEGLBL DispStr_CR,                              SEG_15, G_15, 027ech ; Segment 15
 SEGLBL DispStr_CRLF,                            SEG_15, G_15, 027d0h ; Segment 15
 SEGLBL SetCursorPosition,                       SEG_15, G_15, 02718h ; Segment 15
 SEGLBL DrawAwardRibbon,                         SEG_15, G_15, 0105bh ; Segment 15
 SEGLBL CheckIfWarmReboot,                       SEG_15, G_15, 02167h ; Segment 15
 SEGLBL PrintPOSTStrings_Full,                   SEG_15, G_15, 0e2eh ; Segment 15
 SEGLBL OutPort16,                               SEG_15, G_15, 0109eh ; Segment 15
 SEGLBL CheckCTRLAltDel,                         SEG_15, G_15, 0c770h ; Segment 15
 SEGLBL Reboot,                                  SEG_15, G_15, 0e3d4h ; Segment 15
 SEGLBL Wait_Refresh,                            SEG_15, G_15, 0edcch ; Segment 15
 SEGLBL APM_Service,                             SEG_15, G_15, 0898dh ; Segment 15
 SEGLBL Int15h_Handler,                          SEG_15, G_15, 0d920h ; Segment 15
 SEGLBL Int15_CheckMouse,                        SEG_15, G_15, 0d931h ; Segment 15
 SEGLBL EnableProtMode,                          SEG_15, G_15, 01134h ; Segment 15
 SEGLBL ExitProtModeAfterMemtest,                SEG_15, G_15, 011bch ; Segment 15
 SEGLBL GetDisplaySwitch,                        SEG_15, G_15, 0d92h ; Segment 15
 SEGLBL DisplayMemMsg,                           SEG_15, G_15, 01720h ; Segment 15
 SEGLBL GetCPUString,                            SEG_15, G_15, 081ach ; Segment 15
 SEGLBL CalculateBusSpeed,                       SEG_15, G_15, 020f4h ; Segment 15
 SEGLBL RoundOffClock,                           SEG_15, G_15, 02122h ; Segment 15
 SEGLBL InitCpuTypeFromTable,                    SEG_15, G_15, 07f7bh ; Segment 15
 SEGLBL FinaliseCPUSetup_OpcodeErrorHandler,     SEG_15, G_15, 08426h ; Segment 15
 SEGLBL ReadCMOSByte,                            SEG_15, G_15, 0e98ah ; Segment 15
 SEGLBL WriteCMOSByte,                           SEG_15, G_15, 0e99bh ; Segment 15
 SEGLBL CMOS_ClearSMIBit,                        SEG_15, G_15, 0844ch ; Segment 15
 SEGLBL CMOS_IsSMIBitSet,                        SEG_15, G_15, 0845bh ; Segment 15
 SEGLBL CMOS_ApplyCPUFeatureBits,                SEG_15, G_15, 08465h ; Segment 15
 SEGLBL FinalizeCPUSetup_IncompleteAMDCheck,     SEG_15, G_15, 083a5h ; Segment 15
 SEGLBL Out_8042,                                SEG_15, G_15, 0ca3ch ; Segment 15
 SEGLBL Out_8042_Full,                           SEG_15, G_15, 0ca50h ; Segment 15
 SEGLBL SendCommandToKBC,                        SEG_15, G_15, 0d8dah ; Segment 15
 SEGLBL Out_8042_Aux,                            SEG_15, G_15, 0d8d4h ; Segment 15
 SEGLBL Out_8042_Aux_Full,                       SEG_15, G_15, 0d914h ; Segment 15
 SEGLBL SetupMouse,                              SEG_15, G_15, 084fch ; Segment 15
 SEGLBL SetupMouse_SetIRQ12Handler,              SEG_15, G_15, 08543h ; Segment 15
 SEGLBL CalculateHDDSize_BUGGY1,                 SEG_15, G_15, 056b6h ; Segment 15
 SEGLBL SetPaletteEntry,                         SEG_15, G_15, 0ba2h ; Segment 15
 SEGLBL ClearEPAArea,                            SEG_15, G_15, 0cb3h ; Segment 15
 SEGLBL ClearEPAAreaAndFadeOut,                  SEG_15, G_15, 0bbch ; Segment 15
 SEGLBL PerformSingleFadeStep,                   SEG_15, G_15, 0c68h ; Segment 15
 SEGLBL EPAFadeOutLoop,                          SEG_15, G_15, 0c01h ; Segment 15


; COMMON BIOS STRUCTURES 

 SEGLBL ColorStyle_Default,                      SEG_15, G_15, 0284bh ; Segment 15
 SEGLBL ColorStyle_ContainsGreen,                SEG_15, G_15, 02887h ; Segment 15
 SEGLBL Str_AwardBiosVersion,                    SEG_15, G_15, 0e061h ; Segment 15
 SEGLBL Str_BiosInfo,                            SEG_15, G_15, 0e0c1h ; Segment 15
 SEGLBL Str_AnEnergyStarAlly,                    SEG_15, G_15, 0dc3h ; Segment 15
 SEGLBL Str_Copyright,                           SEG_15, G_15, 0e091h ; Segment 15
 SEGLBL Str_SetupMenuCopyright,                  SEG_15, G_15, 03fadh ; Segment 15


; MENU DATA 

 SEGLBL BIOS_SysBiosMenuTablePtr                ,  SEG_15, G_15, 0f85dh ; Segment 15
 SEGLBL BIOS_SysBiosMenuTable                   ,  SEG_15, G_15, 02801h ; Segment 15
BIOS_SysBiosMenuEntries                  EQU 06h
 SEGLBL Menu_StandardCmosSetup                  ,  SEG_15, G_15, 02807h ; Segment 15
 SEGLBL Menu_BiosFeaturesSetup                  ,  SEG_15, G_15, 0280dh ; Segment 15
 SEGLBL Menu_ChipsetFeaturesSetup               ,  SEG_15, G_15, 02813h ; Segment 15
 SEGLBL Menu_PowerManagementSetup               ,  SEG_15, G_15, 02819h ; Segment 15
 SEGLBL Menu_PciConfigurationSetup              ,  SEG_15, G_15, 0281fh ; Segment 15
; HIDDEN Menu item  / 
Menuitem_HIDDEN_Unnamed_FLAGS            EQU 08h
 SEGLBL Menuitem_HIDDEN_Unnamed                 ,  SEG_15, G_15, 04026h ; Segment 15
; HIDDEN Menu item STANDARD CMOS SETUP / Daylight Saving
Menuitem_HIDDEN_DaylightSaving_FLAGS     EQU 08h
 SEGLBL Menuitem_HIDDEN_DaylightSaving          ,  SEG_15, G_15, 04a37h ; Segment 15
 SEGLBL Menuitem_HDD_C                          ,  SEG_15, G_15, 04ab4h ; Segment 15
 SEGLBL Menuitem_HDD_D                          ,  SEG_15, G_15, 04b7ch ; Segment 15
BIOS_SupportsDualChannel                 EQU 01h
 SEGLBL Menuitem_HDD_E                          ,  SEG_15, G_15, 04c44h ; Segment 15
 SEGLBL Menuitem_HDD_F                          ,  SEG_15, G_15, 04d0ch ; Segment 15
; HIDDEN Menu item BIOS FEATURES SETUP / Virus Warning
Menuitem_HIDDEN_VirusWarning_FLAGS       EQU 08h
 SEGLBL Menuitem_HIDDEN_VirusWarning            ,  SEG_15, G_15, 058d6h ; Segment 15
; HIDDEN Menu item BIOS FEATURES SETUP / Boot Up Floppy Seek
Menuitem_HIDDEN_BootUpFloppySeek_FLAGS   EQU 08h
 SEGLBL Menuitem_HIDDEN_BootUpFloppySeek        ,  SEG_15, G_15, 0596ch ; Segment 15
; HIDDEN Menu item BIOS FEATURES SETUP / Boot Up System Speed
Menuitem_HIDDEN_BootUpSystemSpeed_FLAGS  EQU 08h
 SEGLBL Menuitem_HIDDEN_BootUpSystemSpeed       ,  SEG_15, G_15, 0599eh ; Segment 15
; HIDDEN Menu item BIOS FEATURES SETUP / System BIOS Shadow
Menuitem_HIDDEN_SystemBiosShadow_FLAGS   EQU 08h
 SEGLBL Menuitem_HIDDEN_SystemBiosShadow        ,  SEG_15, G_15, 05a66h ; Segment 15
; HIDDEN Menu item BIOS FEATURES SETUP / E0000-E7FFF Shadow
Menuitem_HIDDEN_E0000E7fffShadow_FLAGS   EQU 08h
 SEGLBL Menuitem_HIDDEN_E0000E7fffShadow        ,  SEG_15, G_15, 05ae3h ; Segment 15
; HIDDEN Menu item BIOS FEATURES SETUP / E8000-EFFFF Shadow
Menuitem_HIDDEN_E8000EffffShadow_FLAGS   EQU 08h
 SEGLBL Menuitem_HIDDEN_E8000EffffShadow        ,  SEG_15, G_15, 05afch ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / MA Drive Capacity
Menuitem_HIDDEN_MaDriveCapacity_FLAGS    EQU 08h
 SEGLBL Menuitem_HIDDEN_MaDriveCapacity         ,  SEG_15, G_15, 06236h ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / DRAM Write Burst
Menuitem_HIDDEN_DramWriteBurst_FLAGS     EQU 08h
 SEGLBL Menuitem_HIDDEN_DramWriteBurst          ,  SEG_15, G_15, 0629ah ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / Slow Refresh
Menuitem_HIDDEN_SlowRefresh_FLAGS        EQU 08h
 SEGLBL Menuitem_HIDDEN_SlowRefresh             ,  SEG_15, G_15, 062b3h ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / Hidden Refresh
Menuitem_HIDDEN_HiddenRefresh_FLAGS      EQU 08h
 SEGLBL Menuitem_HIDDEN_HiddenRefresh           ,  SEG_15, G_15, 062cch ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / Internal Cache WB/WT
Menuitem_HIDDEN_InternalCacheWbWt_FLAGS  EQU 08h
 SEGLBL Menuitem_HIDDEN_InternalCacheWbWt       ,  SEG_15, G_15, 062e5h ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / Fast Reset Emulation
Menuitem_HIDDEN_FastResetEmulation_FLAGS EQU 08h
 SEGLBL Menuitem_HIDDEN_FastResetEmulation      ,  SEG_15, G_15, 0637bh ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / Fast Reset Latency
Menuitem_HIDDEN_FastResetLatency_FLAGS   EQU 08h
 SEGLBL Menuitem_HIDDEN_FastResetLatency        ,  SEG_15, G_15, 06394h ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / Latch Local Bus
Menuitem_HIDDEN_LatchLocalBus_FLAGS      EQU 04008h
 SEGLBL Menuitem_HIDDEN_LatchLocalBus           ,  SEG_15, G_15, 063adh ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / Local Bus Ready
Menuitem_HIDDEN_LocalBusReady_FLAGS      EQU 08h
 SEGLBL Menuitem_HIDDEN_LocalBusReady           ,  SEG_15, G_15, 063c6h ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / Memory Hole Size
Menuitem_HIDDEN_MemoryHoleSize_FLAGS     EQU 08h
 SEGLBL Menuitem_HIDDEN_MemoryHoleSize          ,  SEG_15, G_15, 063dfh ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / DMA Clock
Menuitem_HIDDEN_DmaClock_FLAGS           EQU 08h
 SEGLBL Menuitem_HIDDEN_DmaClock                ,  SEG_15, G_15, 063f8h ; Segment 15
; HIDDEN Menu item CHIPSET FEATURES SETUP / Memory Relocation
Menuitem_HIDDEN_MemoryRelocation_FLAGS   EQU 08h
 SEGLBL Menuitem_HIDDEN_MemoryRelocation        ,  SEG_15, G_15, 06411h ; Segment 15
; HIDDEN Menu item POWER MANAGEMENT SETUP / PM Mode
Menuitem_HIDDEN_PmMode_FLAGS             EQU 028h
 SEGLBL Menuitem_HIDDEN_PmMode                  ,  SEG_15, G_15, 0683bh ; Segment 15
; HIDDEN Menu item POWER MANAGEMENT SETUP / Break Switch
Menuitem_HIDDEN_BreakSwitch_FLAGS        EQU 028h
 SEGLBL Menuitem_HIDDEN_BreakSwitch             ,  SEG_15, G_15, 06854h ; Segment 15
; HIDDEN Menu item POWER MANAGEMENT SETUP / Auto Doze
Menuitem_HIDDEN_AutoDoze_FLAGS           EQU 04028h
 SEGLBL Menuitem_HIDDEN_AutoDoze                ,  SEG_15, G_15, 06903h ; Segment 15
; HIDDEN Menu item POWER MANAGEMENT SETUP / Auto Standby
Menuitem_HIDDEN_AutoStandby_FLAGS        EQU 04028h
 SEGLBL Menuitem_HIDDEN_AutoStandby             ,  SEG_15, G_15, 06935h ; Segment 15
