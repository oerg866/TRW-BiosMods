; ----------------------------------------------------------
; Mods for CHIPSET FEATURES SETUP menu

SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'
    ASSUME CS:G_15

    LBL aAvailableOptio, 3DD1h
    LBL aDisabled_2, 3D5Dh
    LBL aEnabled_0, 3D54h


    ORG 14DBh

MenuItems_ChipsetFeaturesSetup:

    MenuItem <0,        offset aAutoConfigurat,     0FFFFh, 00000001b, 41h, 00000001b, offset aDisable_0,       0, 1,  2, 6,  0, 1,   offset aAvailableOptio>    ; "Auto Configuration      : "  ; "Disable" ; "Available Options:\v"
    MenuItem <4002h,    offset aIsaBusClock,        70h,    11000000b, 41h, 00000110b, offset a7159mhz,         0, 2,  2, 7,  0, 0,   offset aAvailableOptio> ; "ISA Bus Clock           : " ; "7.159MHz" ; "Available Options:\v"
    MenuItem <4002h,    offset aLbdSamplePoint,     2858h,  00000001b, 41h, 00001000b, offset aEndOfT3,         0, 1,  2, 8,  0, 0,   offset aAvailableOptio> ; "LBD# Sample Point       : " ; "End of T3" ; "Available Options:\v"
;   MenuItem <0,        offset aAutoConfigurat,     0FFFFh, 00000001b, 41h, 00000001b, offset aDisable_0,       0, 1,  2, 4,  0, 1,   offset aAvailableOptio>    ; "Auto Configuration      : "  ; "Disable" ; "Available Options:\v"
;   MenuItem <4002h,    offset aIsaBusClock,        70h,    11000000b, 41h, 00000110b, offset a7159mhz,         0, 2,  2, 6,  0, 0,   offset aAvailableOptio> ; "ISA Bus Clock           : " ; "7.159MHz" ; "Available Options:\v"
;   MenuItem <4002h,    offset aLbdSamplePoint,     2858h,  00000001b, 41h, 00001000b, offset aEndOfT3,         0, 1,  2, 7,  0, 0,   offset aAvailableOptio> ; "LBD# Sample Point       : " ; "End of T3" ; "Available Options:\v"
    MenuItem <4002h,    offset aCacheWriteCycl,     2843h,  00001000b, 41h, 00010000b, offset a3Cclk_0,         0, 1,  2, 19, 0, 10h, offset aAvailableOptio> ; "Cache Write Cycle       : " ; "3 CCLK" ; "Available Options:\v"

    MenuItem <4002h,    offset aCacheBurstRead,     2843h,  00000110b, 41h, 01100000b, offset newCBurstOpt,     0, 3,  2, 20, 4, 4,   offset aAvailableOptio> ; "Cache Burst Read Cycle  : " ; "1 CCLK" ; "Available Options:\v"
    ; Delete 2nd option to keep table order somewhat intact
    MenuItem <000Ah,    0,     0FFFFh, 0,      0, 0,   0,    0, 0, 0, 0, 0, 0, 0>
    
;   MenuItem <4002h,    offset aCacheBurstRead,     2843h,  00000100b, 41h, 00100000b, offset a1Cclk_2,         0, 1,  2, 20, 4, 0,   offset aAvailableOptio> ; "Cache Burst Read Cycle  : " ; "1 CCLK" ; "Available Options:\v"
;   MenuItem <4002h,    offset aL2CacheDramCyc,     2843h,  00000010b, 41h, 01000000b, offset a3Cclk_1,         0, 1,  2, 21, 0, 40h, offset aAvailableOptio> ; "L2 Cache/DRAM Cycle WS  : " ; "3 CCLK" ; "Available Options:\v"

    MenuItem <4002h,    offset aDramRasToCasDe,     2841h,  00001000b, 41h, 10000000b, offset a3Cclk,           0, 1,  2, 15, 0, 0,   offset aAvailableOptio> ; "DRAM RAS to CAS Delay   : " ; "3 CCLK" ; "Available Options:\v"
;   MenuItem <400Ah,    offset aDramRasToCasDe,     2841h,  00001000b, 41h, 10000000b, offset a3Cclk,           0, 1,  2, 13, 0, 0,   offset aAvailableOptio> ; "DRAM RAS to CAS Delay   : " ; "3 CCLK" ; "Available Options:\v"
    MenuItem <4002h,    offset aDramWriteCycle,     2841h,  00000100b, 42h, 00000001b, offset a1Ws,             0, 1,  2, 12, 0, 0,   offset aAvailableOptio> ; "DRAM Write Cycle        : " ; "1 WS" ; "Available Options:\v"
    MenuItem <4002h,    offset aDramWriteCasPu,     2841h,  00000010b, 42h, 00000010b, offset a2Cclk_0,         0, 1,  2, 13, 0, 0,   offset aAvailableOptio> ; "DRAM Write CAS Pulse    : " ; "2 CCLK" ; "Available Options:\v"
    MenuItem <4002h,    offset aDramCasPrechar,     2841h,  00000001b, 42h, 00000100b, offset a2Cclk_1,         0, 1,  2, 16, 0, 0,   offset aAvailableOptio> ; "DRAM CAS Precharge Time : " ; "2 CCLK" ; "Available Options:\v"
;   MenuItem <400Ah,    offset aDramCasPrechar,     2841h,  00000001b, 42h, 00000100b, offset a2Cclk_1,         0, 1,  2, 16, 0, 0,   offset aAvailableOptio> ; "DRAM CAS Precharge Time : " ; "2 CCLK" ; "Available Options:\v"
    MenuItem <4002h,    offset aDramRasToMaDel,     2843h,  00010000b, 42h, 00001000b, offset a2Cclk_2,         0, 1,  2, 9,  0, 0,   offset aAvailableOptio> ; "DRAM RAS to MA Delay    : " ; "2 CCLK" ; "Available Options:\v"
;   MenuItem <400Ah,    offset aDramRasToMaDel,     2843h,  00010000b, 42h, 00001000b, offset a2Cclk_2,         0, 1,  2, 17, 0, 0,   offset aAvailableOptio> ; "DRAM RAS to MA Delay    : " ; "2 CCLK" ; "Available Options:\v"
    MenuItem <4002h,    offset aDramSpeed,          2840h,  00000011b, 42h, 00110000b, offset aSlowest,         0, 3,  2, 11, 0, 20h, offset aAvailableOptio> ; "DRAM Speed              : " ; "Slowest" ; "Available Options:\v"
    MenuItem <02h,      offset aDramSlowRefres,     2841h,  00010000b, 42h, 01000000b, offset aDisable_0,       0, 1,  2, 10, 0, 0,  offset aAvailableOptio> ; "DRAM Slow Refresh       : " ; "Disable" ; "Available Options:\v"
;   MenuItem <0Ah,      offset aDramSlowRefres,     2841h,  00010000b, 42h, 01000000b, offset aDisable_0,       0, 1,  2, 19, 0, 0,   offset aAvailableOptio> ; "DRAM Slow Refresh       : " ; "Disable" ; "Available Options:\v"
    MenuItem <2,        offset aCpuInternalCac_0,   0FFFFh, 00000001b, 42h, 10000000b, offset aWriteThru,       0, 1,  2, 14, 0, 0,   offset aAvailableOptio>  ; "CPU Internal Cache      : " ; "Write Thru" ; "Available Options:\v"
    MenuItem <2,        offset aCpuBurstWrite,      0FFFFh, 01000000b, 43h, 00000001b, offset aDisable_0,       0, 1,  2, 17, 0, 0,   offset aAvailableOptio> ; "CPU Burst Write         : " ; "Disable" ; "Available Options:\v"
    MenuItem <2,        offset aL2CachePolicy,      0FFFFh, 00000001b, 43h, 00000010b, offset aWriteThru_0,     0, 1,  2, 18, 0, 2,   offset aAvailableOptio> ; "L2 Cache Policy         : " ; "Write Thru" ; "Available Options:\v"
    MenuItem <2002h,    offset aL2CacheTagBits,     2842h,  00000100b, 43h, 00000100b, offset a8Bits,           0, 1,  2, 21, 4, 4,   offset aAvailableOptio> ; "L2 Cache Tag Bits       : " ; "8 bits" ; "Available Options:\v"
;   MenuItem <2002h,    offset aL2CacheTagBits,     2842h,  00000100b, 43h, 00000100b, offset a8Bits,           0, 1,  2, 23, 4, 4,   offset aAvailableOptio> ; "L2 Cache Tag Bits       : " ; "8 bits" ; "Available Options:\v"
    MenuItem <200Ah,    offset aOnboard496aIde,     0FFFFh, 00000011b, 43h, 00011000b, offset aDisable_1,       0, 3, 42, 4,  3, 18h, offset aAvailableOptio> ; "Onboard 496A IDE Port   : " ; "Disable" ; "Available Options:\v"
    MenuItem <0Ah,      offset aOnboardVesaIde,     0FFFFh, 00000111b, 43h, 11100000b, offset aSlowest_0,       0, 7, 42, 5,  0, 40h, offset aAvailableOptio> ; "Onboard VESA IDE-1 WS   : " ; "Slowest" ; "Available Options:\v"
    MenuItem <0Ah,      offset aOnboardVesaIde_0,   0FFFFh, 01110000b, 44h, 00000111b, offset aSlowest_0,       0, 7, 42, 6,  0, 2,   offset aAvailableOptio> ; "Onboard VESA IDE-2 WS   : " ; "Slowest" ; "Available Options:\v"
    MenuItem <2,        offset aOnboard496bIde,     0FFFFh, 00000011b, 46h, 11000000b, offset aBoth,            0, 3, 42, 4,  3, 0,   offset aAvailableOptio> ; "Onboard 496B IDE Port   : " ; "Both     " ; "Available Options:\v"
    MenuItem <0,        offset aIde0MasterMode,     0FFFFh, 00000111b, 44h, 01110000b, offset aAuto,            0, 5, 42, 5,  0, 0,   offset aAvailableOptio> ; "IDE 0 Master Mode       : " ; "Auto" ; "Available Options:\v"
    MenuItem <0,        offset aIde0SlaveMode,      0FFFFh, 01110000b, 45h, 00000111b, offset aAuto,            0, 5, 42, 6,  0, 0,   offset aAvailableOptio> ; "IDE 0 Slave  Mode       : " ; "Auto" ; "Available Options:\v"
    MenuItem <0,        offset aIde1MasterMode,     0FFFFh, 00000111b, 45h, 00111000b, offset aAuto,            0, 5, 42, 7,  0, 0,   offset aAvailableOptio> ; "IDE 1 Master Mode       : " ; "Auto" ; "Available Options:\v"
    MenuItem <0,        offset aIde1SlaveMode,      0FFFFh, 01110000b, 46h, 00000111b, offset aAuto,            0, 5, 42, 8,  0, 0,   offset aAvailableOptio> ; "IDE 1 Slave  Mode       : " ; "Auto" ; "Available Options:\v"
    MenuItem <2002h,    offset aIdePrefetchRea,     0FFFFh, 01100000b, 46h, 00011000b, offset aDisable_2,       0, 3, 2, 22,  0, 0,   offset aAvailableOptio> ; "IDE Prefetch Read Buffer: " ; "Disable" ; "Available Options:\v"
;   MenuItem <200Ah,    offset aIdePrefetchRea,     0FFFFh, 01100000b, 46h, 00011000b, offset aDisable_2,       0, 3, 42, 9,  0, 0,   offset aAvailableOptio> ; "IDE Prefetch Read Buffer: " ; "Disable" ; "Available Options:\v"
    MenuItem <8,        offset aProgrammingIOC,     0FFFFh, 00000001b, 58h, 00000001b, offset aDisabled,        0, 1, 42, 9, 1, 1,    offset aAvailableOptio> ; "Programming I/O Chip    : " ; "Disabled" ; "Available Options:\v"
    MenuItem <0,        offset aOnboardFdcCont,     0FFFFh, 00000100b, 58h, 00000010b, offset aEnable_0,        0, 1, 42, 10, 0, 0,   offset aAvailableOptio> ; "Onboard FDC Control     : " ; "Enable " ; "Available Options:\v"
    MenuItem <0,        offset aOnboardSerialP,     0FFFFh, 00000111b, 58h, 00011100b, offset aCom13f8h,        0, 4, 42, 11, 0, 0,   offset aAvailableOptio> ; "Onboard Serial Port 1   : " ; "COM1/3F8H" ; "Available Options:\v"
    MenuItem <0,        offset aOnboardSerialP_0,   0FFFFh, 00111000b, 58h, 11100000b, offset aCom13f8h_0,      0, 4, 42, 12, 8, 20h, offset aAvailableOptio> ; "Onboard Serial Port 2   : " ; "COM1/3F8H" ; "Available Options:\v"
    MenuItem <0,        offset aOnboardParalle,     0FFFFh, 00111000b, 59h, 00000111b, offset a378hIrq7,        0, 4, 42, 13, 0, 0,   offset aAvailableOptio> ; "Onboard Parallel Port   : " ; "378H/IRQ7" ; "Available Options:\v"
    MenuItem <0,        offset aOnboardPrinter,     0FFFFh, 00000011b, 59h, 00011000b, offset aCompatible,      0, 3, 42, 14, 0, 0,   offset aAvailableOptio> ; "Onboard Printer Mode    : " ; "Compatible" ; "Available Options:\v"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; NEW ITEMS

; NEW option for IDE controller address setup time
    MenuItem <0,    offset newIdeCtrlAccessTime,     2859h, 00011100b, 44h, 11100000b, offset newIdeCtrlOpts,   0, 7, 2, 23, 0Ch, 0Ch, offset aAvailableOptio> 
; New option for 16bit I/O cycle recovery
    MenuItem <2,    offset newIO16recovery,          0071h, 11000000b, 47h, 11000000b, offset newIO16opts,      0, 3, 2,  4,  0, 0, offset aAvailableOptio>
; New option for 8bit I/O cycle recovery
    MenuItem <2,    offset newIO8recovery,           0071h, 01110000b, 47h, 01110000b, offset newIO8opts,       0, 3, 2,  5,  0, 0, offset aAvailableOptio>
; New option for 16bit I/O Wait State
    MenuItem <2,    offset newMemIO16ws,             0071h, 00000100b, 47h, 00000100b, offset newMemIO16opts,   0, 1, 42, 15, 0, 0, offset aAvailableOptio>
; New option for 8bit I/O Wait State
    MenuItem <2,    offset newMemIO8ws,              0071h, 00000010b, 47h, 00000010b, offset newMemIO8opts,    0, 1, 42, 16, 0, 0, offset aAvailableOptio>

MenuItems_ChipsetFeaturesSetup_End:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Relocate the strings so we can add new options.
    ORG 7000h
newIdeCtrlAccessTime:
    db 'IDE Address Setup Time  : ',0
newIdeCtrlOpts:
    db '8 CCLK',0
    db '1 CCLK',0
    db '2 CCLK',0
    db '3 CCLK',0
    db '4 CCLK',0
    db '5 CCLK',0
    db '6 CCLK',0
    db '7 CCLK',0
newIO16recovery:
    db '16Bit IO Cycle Recovery : ',0
newIO8recovery:
    db ' 8Bit IO Cycle Recovery : ',0
newMemIO16ws:
    db '16Bit Mem IO WaitStates : ',0
newMemIO8ws:
    db ' 8Bit Mem IO WaitStates : ',0
newIO8opts:
    db '8 BCLK',0
newIO16opts:
    db '5 BCLK',0
    db '4 BCLK',0
    db '3 BCLK',0
    db '2 BCLK',0 ; 8-bit doesnt have this
newMemIO16opts:
    db '2 WS',0
    db '1 WS',0
newMemIO8opts:
    db '5 WS',0
    db '4 WS',0
newCBurstOpt:
    db '3-1-1-1',0
    db '2-1-1-1',0
    db '3-2-2-2',0
    db '2-2-2-2',0
newCBurstOptEnd:
aAutoConfigurat db 'Auto Configuration      : ',0
aBoth           db 'Both     ',0
aPrimary        db 'Primary  ',0
aSecondary      db 'Secondary',0
aDisable        db 'Disable  ',0
aDisable_0      db 'Disable',0
aEnable         db 'Enable ',0
aIsaBusClock    db 'ISA Bus Clock           : ',0
a7159mhz        db '7.159MHz',0
a14Pclk         db '1/4 PCLK',0
a13Pclk         db '1/3 PCLK',0
aCpuBurstWrite  db 'CPU Burst Write         : ',0
aCpuInternalCac_0 db 'CPU Internal Cache      : ',0
aWriteThru      db 'Write Thru',0
aWriteBack      db 'Write Back',0
aDramSpeed      db 'DRAM Speed              : ',0
aSlowest        db 'Slowest',0
aSlower         db 'Slower ',0
aFaster         db 'Faster ',0
aFastest        db 'Fastest',0
aDramSlowRefres db 'DRAM Slow Refresh       : ',0
aDramRasToCasDe db 'DRAM RAS to CAS Delay   : ',0
a3Cclk          db '3 CCLK',0
a2Cclk          db '2 CCLK',0
aDramWriteCycle db 'DRAM Write Cycle        : ',0
a1Ws            db '1 WS',0
a0Ws            db '0 WS',0
aDramWriteCasPu db 'DRAM Write CAS Pulse    : ',0
a2Cclk_0        db '2 CCLK',0
a1Cclk          db '1 CCLK',0
aDramCasPrechar db 'DRAM CAS Precharge Time : ',0
a2Cclk_1        db '2 CCLK',0
a1Cclk_0        db '1 CCLK',0
aDramRasToMaDel db 'DRAM RAS to MA Delay    : ',0
a2Cclk_2        db '2 CCLK',0
a1Cclk_1        db '1 CCLK',0
aCacheWriteCycl db 'Cache Write Cycle       : ',0
a3Cclk_0        db '3 CCLK',0
a2Cclk_3        db '2 CCLK',0
aCacheBurstRead db 'Cache Burst Read Cycle  : ',0
a1Cclk_2        db '1 CCLK',0
a2Cclk_4        db '2 CCLK',0
aL2CachePolicy  db 'L2 Cache Policy         : ',0
aWriteThru_0    db 'Write Thru',0
aWriteBack_0    db 'Write Back',0
aL2CacheTagBits db 'L2 Cache Tag Bits       : ',0
a8Bits          db '8 bits',0
a7Bits          db '7 bits',0
aOnboard496aIde db 'Onboard 496A IDE Port   : ',0
aDisable_1      db 'Disable',0
aPrimary_0      db 'Primary',0
                db '???????',1
aBoth_1         db 'Both   ',0
aOnboardVesaIde db 'Onboard VESA IDE-1 WS   : ',0
aOnboardVesaIde_0 db 'Onboard VESA IDE-2 WS   : ',0
aSlowest_0      db 'Slowest',0
                db '???????',1
aSlower_0       db 'Slower ',0
                db '???????',1
aFaster_0       db 'Faster ',0
                db '???????',1
aFastest_0      db 'Fastest',0
                db '???????',1
aOnboard496bIde db 'Onboard 496B IDE Port   : ',0
aIde0MasterMode db 'IDE 0 Master Mode       : ',0
aIde0SlaveMode  db 'IDE 0 Slave  Mode       : ',0
aIde1MasterMode db 'IDE 1 Master Mode       : ',0
aIde1SlaveMode  db 'IDE 1 Slave  Mode       : ',0
aAuto           db 'Auto',0
a0              db '0   ',0
a1              db '1   ',0
a2              db '2   ',0
a3              db '3   ',0
a4              db '4   ',0
aIdePrefetchRea db 'IDE Prefetch Read Buffer: ',0
aDisable_2      db 'Disable',0
                db '???????',1
aBoth_0         db 'Both   ',0
aPrimary_1      db 'Primary',0
aL2CacheDramCyc db 'L2 Cache/DRAM Cycle WS  : ',0
a3Cclk_1        db '3 CCLK',0
a2Cclk_5        db '2 CCLK',0
aLbdSamplePoint db 'LBD# Sample Point       : ',0
aEndOfT3        db 'End of T3',0
aEndOfT2        db 'End of T2',0
aProgrammingIOC db 'Programming I/O Chip    : ',0
aDisabled       db 'Disabled',0
aEnabled        db 'Enabled ',0
aOnboardFdcCont db 'Onboard FDC Control     : ',0
aOnboardSerialP db 'Onboard Serial Port 1   : ',0
aOnboardSerialP_0 db 'Onboard Serial Port 2   : ',0
aOnboardParalle db 'Onboard Parallel Port   : ',0
aOnboardPrinter db 'Onboard Printer Mode    : ',0
aEnable_0       db 'Enable ',0
aDisable_3      db 'Disable',0
aCom13f8h       db 'COM1/3F8H',0
aCom22f8h       db 'COM2/2F8H',0
aCom33e8h       db 'COM3/3E8h',0
aCom42e8h       db 'COM4/2E8h',0
aDisable_4      db 'Disable  ',0
aCom13f8h_0     db 'COM1/3F8H',0
aCom22f8h_0     db 'COM2/2F8H',0
aCom33e8h_0     db 'COM3/3E8h',0
aCom42e8h_0     db 'COM4/2E8h',0
aDisable_5      db 'Disable  ',0
a378hIrq7       db '378H/IRQ7',0
a378hIrq5       db '378H/IRQ5',0
a3bchIrq7       db '3BCH/IRQ7',0
a278hIrq5       db '278H/IRQ5',0
aDisable_6      db 'Disable  ',0
aCompatible     db 'Compatible',0
aExtended       db 'Extended  ',0
aEppMode        db 'EPP Mode  ',0
aEcpMode        db 'ECP Mode  ',0

ChipsetFeaturesStrings_End:

SEG_15 ENDS