; ----------------------------------------------------------
; Mods for CHIPSET FEATURES SETUP menu

SEG_15 SEGMENT USE16 PARA PUBLIC 'CODE'
    ASSUME CS:G_15

    LBL aAvailableOptio, 3DD1h
    LBL aDisabled_2, 3D5Dh
    LBL aEnabled_0, 3D54h


    ORG 4EF1h

MenuItems_ChipsetFeaturesSetup:
    MenuItem <0,        offset aAutoConfigurat,     0FFFFh, 1,      41h, 1,     offset aDisable_0,  0, 1, 2, 6, 0, 1, offset aAvailableOptio> ; "Auto Configuration      : " ; "Disable"
    MenuItem <4002h,    offset aIsaBusClock,        70h,    0C0h,   41h, 6,     offset a7159mhz,    0, 2, 2, 7, 0, 0, offset aAvailableOptio> ; "ISA Bus Clock           : " ; "7.159MHz"
    MenuItem <4002h,    offset aLbdSamplePoint,     2858h,  1,      41h, 8,     offset aEndOfT3,    0, 1, 2, 8, 0, 0, offset aAvailableOptio> ; "LBD# Sample Point       : " ; "End of T3"
    MenuItem <4002h,    offset aCacheWriteCycl,     2843h,  8,      41h, 10h,   offset a3Cclk_0,    0, 1, 2, 13h, 0, 10h, offset aAvailableOptio> ; "Cache Write Cycle       : "; "3 CCLK"

    ; NEW single option to replace dual separate option, similar to ASUS BIOS
    MenuItem <4002h,    offset aCacheBurstRead,     2843h,  6,      41h, 60h,   offset newCBurstOpt,0, 3, 2, 14h, 4, 4, offset aAvailableOptio> ; "Cache Burst Read Cycle  : " ; "3-1-1-1"

    ; Delete 2nd option to keep table order somewhat intact
    MenuItem <000Ah,    0,     0FFFFh, 0,      0, 0,   0,    0, 0, 0, 0, 0, 0, 0>
    
;   MenuItem <4002h,    offset aCacheBurstRead,     2843h,  4,      41h, 20h,   offset a1Cclk_2,    0, 1, 2, 14h, 4, 0, offset aAvailableOptio> ; "Cache Burst Read Cycle  : "; "1 CCLK"
;   MenuItem <4002h,    offset aL2CacheDramCyc,     2843h,  2,      41h, 40h,   offset a3Cclk_1,    0, 1, 2, 15h, 0, 40h, offset aAvailableOptio> ; "L2 Cache/DRAM Cycle WS  : "; "3 CCLK"

    ; Unhide RAS to CAS delay option
    MenuItem <4002h,    offset aDramRasToCasDe,     2841h,  8,      41h, 80h,   offset a3Cclk,      0, 1, 2, 0Fh, 0, 0, offset aAvailableOptio> ; "DRAM RAS to CAS Delay   : "; "3 CCLK"
;   MenuItem <400Ah,    offset aDramRasToCasDe,     2841h,  8,      41h, 80h,   offset a3Cclk,      0, 1, 2, 0Dh, 0, 0, offset aAvailableOptio> ; "DRAM RAS to CAS Delay   : "; "3 CCLK"

    MenuItem <4002h,    offset aDramWriteCycle,     2841h,  4,      42h, 1,     offset a1Ws,        0, 1, 2, 0Ch, 0, 0, offset aAvailableOptio> ; "DRAM Write Cycle        : "; "1 WS"
    MenuItem <4002h,    offset aDramWriteCasPu,     2841h,  2,      42h, 2,     offset a2Cclk_0,    0, 1, 2, 0Dh, 0, 0, offset aAvailableOptio> ; "DRAM Write CAS Pulse    : "; "2 CCLK"

    ; Unhide CAS Precharge Time
    MenuItem <4002h,    offset aDramCasPrechar,     2841h,  1,      42h, 4,     offset a2Cclk_1,    0, 1, 2, 10h, 0, 0, offset aAvailableOptio> ; "DRAM CAS Precharge Time : "; "2 CCLK"
;   MenuItem <400Ah,    offset aDramCasPrechar,     2841h,  1,      42h, 4,     offset a2Cclk_1,    0, 1, 2, 10h, 0, 0, offset aAvailableOptio> ; "DRAM CAS Precharge Time : "; "2 CCLK"

    ; Unhide RAS to MA delay
    MenuItem <4002h,    offset aDramRasToMaDel,     2843h,  10h,    42h, 8,     offset a2Cclk_2,    0, 1, 2, 9,   0, 0, offset aAvailableOptio> ; "DRAM RAS to MA Delay    : "; "2 CCLK"
;   MenuItem <400Ah,    offset aDramRasToMaDel,     2843h,  10h,    42h, 8,     offset a2Cclk_2,    0, 1, 2, 11h, 0, 0, offset aAvailableOptio> ; "DRAM RAS to MA Delay    : "; "2 CCLK"

    MenuItem <4002h,    offset aDramSpeed,          2840h,  3,      42h, 30h,   offset aSlowest,    0, 3, 2, 0Bh, 2, 20h, offset aAvailableOptio> ; "DRAM Speed              : "; "Slowest"

    ; Unhide Slow Refresh
    MenuItem <2,        offset aDramSlowRefres,     2841h,  10h,    42h, 40h,   offset aDisable_0,  0, 1, 2, 0Ah, 0, 0, offset aAvailableOptio> ; "DRAM Slow Refresh       : "; "Disable"
;   MenuItem <0Ah,      offset aDramSlowRefres,     2841h,  10h,    42h, 40h,   offset aDisable_0,  0, 1, 2, 13h, 0, 0, offset aAvailableOptio> ; "DRAM Slow Refresh       : "; "Disable"

    MenuItem <2,        offset aCpuInternalCac_0,   0FFFFh, 1,      42h, 80h,   offset aWriteThru,  0, 1, 2, 0Eh, 0, 0, offset aAvailableOptio> ; "CPU Internal Cache      : "; "Write Thru"
    MenuItem <2,        offset aCpuBurstWrite,      0FFFFh, 40h,    43h, 1,     offset aDisable_0,  0, 1, 2, 11h, 0, 0, offset aAvailableOptio> ; "CPU Burst Write         : "; "Disable"
    MenuItem <2,        offset aL2CachePolicy,      0FFFFh, 1,      43h, 2,     offset aWriteThru_0,0, 1, 2, 12h, 1, 2, offset aAvailableOptio> ; "L2 Cache Policy         : "; "Write Thru"

    MenuItem <200Ah,    offset aL2CacheTagBits,     2842h,  4,      43h, 4,     offset a8Bits,      0, 1, 2, 15h, 4, 4, offset aAvailableOptio> ; "L2 Cache Tag Bits       : "; "8 bits"
;   MenuItem <200Ah,    offset aL2CacheTagBits,     2842h,  4,      43h, 4,     offset a8Bits,      0, 1, 2, 17h, 4, 4, offset aAvailableOptio> ; "L2 Cache Tag Bits       : "; "8 bits"

    MenuItem <200Ah,    offset aOnboard496aIde,     0FFFFh, 3,      43h, 18h,   offset aDisable_1,  0, 3, 2Ah, 4, 3, 18h, offset aAvailableOptio> ; "Onboard 496A IDE Port   : "; "Disable"
    MenuItem <0Ah,      offset aOnboardVesaIde,     0FFFFh, 7,      43h, 0E0h,  offset aSlowest_0,  0, 7, 2Ah, 5, 0, 40h, offset aAvailableOptio> ; "Onboard VESA IDE-1 WS   : "; "Slowest"
    MenuItem <0Ah,      offset aOnboardVesaIde_0,   0FFFFh, 70h,    44h, 7,     offset aSlowest_0,  0, 7, 2Ah, 6, 0, 2, offset aAvailableOptio> ; "Onboard VESA IDE-2 WS   : "; "Slowest"

    MenuItem <2,        offset aOnboard496bIde,     0FFFFh, 3,      46h, 0C0h,  offset aBoth,       0, 3, 2, 16h, 0, 0, offset aAvailableOptio> ; "Onboard 496B IDE Port   : "; "Both     "
    MenuItem <0,        offset aIde0MasterMode,     0FFFFh, 7,      44h, 70h,   offset aAuto_0,     0, 5, 2Ah, 4, 0, 0, offset aAvailableOptio> ; "IDE 0 Master Mode       : "; "Auto"
    MenuItem <0,        offset aIde0SlaveMode,      0FFFFh, 70h,    45h, 7,     offset aAuto_0,     0, 5, 2Ah, 5, 0, 0, offset aAvailableOptio> ; "IDE 0 Slave  Mode       : "; "Auto"
    MenuItem <0,        offset aIde1MasterMode,     0FFFFh, 7,      45h, 38h,   offset aAuto_0,     0, 5, 2Ah, 6, 0, 0, offset aAvailableOptio> ; "IDE 1 Master Mode       : "; "Auto"
    MenuItem <0,        offset aIde1SlaveMode,      0FFFFh, 70h,    46h, 7,     offset aAuto_0,     0, 5, 2Ah, 7, 0, 0, offset aAvailableOptio> ; "IDE 1 Slave  Mode       : "; "Auto"

    ; Unhide IDE Prefetch Read Buffer
    MenuItem <2002h,    offset aIdePrefetchRea,     0FFFFh, 60h,    46h, 18h,   offset aDisable_2,  0, 3, 2, 17h, 0, 0, offset aAvailableOptio> ; "IDE Prefetch Read Buffer: "; "Disable"
;   MenuItem <200Ah,    offset aIdePrefetchRea,     0FFFFh, 60h,    46h, 18h,   offset aDisable_2,  0, 3, 2Ah, 9, 0, 0, offset aAvailableOptio> ; "IDE Prefetch Read Buffer: "; "Disable"

    ; TODO: Figure out what the hell this is
    MenuItem <0Bh,      offset aProgrammingIOC,     0FFFFh, 1,      58h, 1,     offset aDisabled_2, 0, 1, 2Ah, 9, 1, 1, offset aAvailableOptio> ; "Programming I/O Chip    : "; "Disabled"

    MenuItem <3,        offset aOnboardFddCont,     0FFFFh, 20h,    58h, 8,     offset aEnabled_0,  0, 1, 2Ah, 0Ah, 0, 0, offset aAvailableOptio> ; "Onboard FDD Controller  : "; "Enabled "
    MenuItem <3,        offset aOnboardSerialP,     0FFFFh, 38h,    58h, 70h,   offset aCom42e8,    0, 4, 2Ah, 0Bh, 10h, 20h, offset aAvailableOptio> ; "Onboard Serial Port 1   : "; "COM4/2E8"
    MenuItem <3,        offset aOnboardSerialP_0,   0FFFFh, 0Eh,    5Ah, 700h,  offset aCom33e8_0,  0, 4, 2Ah, 0Ch, 4, 200h, offset aAvailableOptio> ; "Onboard Serial Port 2   : "; "COM3/3E8"
    MenuItem <3,        offset aOnboardParalle,     0FFFFh, 3,      58h, 300h,  offset a3bch,       0, 3, 2Ah, 0Dh, 2, 200h, offset aIfYouChoose3bc> ; "Onboard Parallel Port   : "; "3BCH    "
    MenuItem <3,        offset aOnboardParalle_0,   0FFFFh, 0Ch,    58h, 0C00h, offset aNormal_1,   0, 3, 2Ah, 0Eh, 8, 800h, offset aAvailableOptio> ; "Onboard Parallel Mode   : "; "Normal "
 
    ; These two options were hidden to make room for the other new options
    MenuItem <0Fh,      offset aSerialPort1Mid,     0FFFFh, 10h,    58h, 2000h, offset aDisabled_2, 0, 1, 2Ah, 10h, 0, 0, offset aAvailableOptio> ; "Serial Port 1 MIDI      : "; "Disabled"
    MenuItem <0Fh,      offset aSerialPort2Mid,     0FFFFh, 20h,    58h, 4000h, offset aDisabled_2, 0, 1, 2Ah, 11h, 0, 0, offset aAvailableOptio> ; "Serial Port 2 MIDI      : "; "Disabled"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;; NEW ITEMS

; NEW option for IDE controller address setup time
    MenuItem <0,    offset newIdeCtrlAccessTime,     2859h,  1Ch,   44h, 0e0h,  offset newIdeCtrlOpts,0, 7, 2Ah, 8, 0Ch, 0Ch, offset aAvailableOptio> 
; New option for 16bit I/O cycle recovery
    MenuItem <2,    offset newIO16recovery,          0071h, 0c0h,   47h, 0c0h,  offset newIO16opts, 0, 3, 2, 4, 0, 0, offset aAvailableOptio>
; New option for 8bit I/O cycle recovery
    MenuItem <2,    offset newIO8recovery,           0071h, 030h,   47h, 030h,  offset newIO8opts,  0, 3, 2, 5, 0, 0, offset aAvailableOptio>
; New option for 16bit I/O Wait State
    MenuItem <2,    offset newMemIO16ws,             0071h,  04h,   47h, 04h,   offset newMemIO16opts, 0, 1, 2Ah, 0Fh, 0, 0, offset aAvailableOptio>
; New option for 8bit I/O Wait State
    MenuItem <2,    offset newMemIO8ws,              0071h,  02h,   47h, 02h,   offset newMemIO8opts,  0, 1, 2Ah, 10h, 0, 0, offset aAvailableOptio>

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

aAutoConfigurat db 'Auto Configuration      : ',0                               ; DATA XREF: BIOS_F:4EF1↑o
aBoth           db 'Both     ',0                                                ; DATA XREF: BIOS_F:50E5↑o
aPrimary        db 'Primary  ',0
aSecondary      db 'Secondary',0
aDisable        db 'Disable  ',0
aDisable_0      db 'Disable',0                                                  ; DATA XREF: BIOS_F:4EF1↑o
aEnable         db 'Enable ',0
aIsaBusClock    db 'ISA Bus Clock           : ',0                               ; DATA XREF: BIOS_F:4F0A↑o
a7159mhz        db '7.159MHz',0                                                 ; DATA XREF: BIOS_F:4F0A↑o
a14Pclk         db '1/4 PCLK',0
a13Pclk         db '1/3 PCLK',0
aCpuBurstWrite  db 'CPU Burst Write         : ',0                               ; DATA XREF: BIOS_F:504F↑o
aCpuInternalCac_0 db 'CPU Internal Cache      : ',0                             ; DATA XREF: BIOS_F:5036↑o
aWriteThru      db 'Write Thru',0                                               ; DATA XREF: BIOS_F:5036↑o
aWriteBack      db 'Write Back',0
aDramSpeed      db 'DRAM Speed              : ',0                               ; DATA XREF: BIOS_F:5004↑o
aSlowest        db 'Slowest',0                                                  ; DATA XREF: BIOS_F:5004↑o
aSlower         db 'Slower ',0
aFaster         db 'Faster ',0
aFastest        db 'Fastest',0                                                  ; CODE XREF: BIOS_F:F8E5↓j
aDramSlowRefres db 'DRAM Slow Refresh       : ',0                               ; DATA XREF: BIOS_F:501D↑o
aDramRasToCasDe db 'DRAM RAS to CAS Delay   : ',0                               ; DATA XREF: BIOS_F:4F87↑o
a3Cclk          db '3 CCLK',0                                                   ; DATA XREF: BIOS_F:4F87↑o
a2Cclk          db '2 CCLK',0
aDramWriteCycle db 'DRAM Write Cycle        : ',0                               ; DATA XREF: BIOS_F:4FA0↑o
a1Ws            db '1 WS',0                                                     ; DATA XREF: BIOS_F:4FA0↑o
a0Ws            db '0 WS',0
aDramWriteCasPu db 'DRAM Write CAS Pulse    : ',0                               ; DATA XREF: BIOS_F:4FB9↑o
a2Cclk_0        db '2 CCLK',0                                                   ; DATA XREF: BIOS_F:4FB9↑o
a1Cclk          db '1 CCLK',0
aDramCasPrechar db 'DRAM CAS Precharge Time : ',0                               ; DATA XREF: BIOS_F:4FD2↑o
a2Cclk_1        db '2 CCLK',0                                                   ; DATA XREF: BIOS_F:4FD2↑o
a1Cclk_0        db '1 CCLK',0
aDramRasToMaDel db 'DRAM RAS to MA Delay    : ',0                               ; DATA XREF: BIOS_F:4FEB↑o
a2Cclk_2        db '2 CCLK',0                                                   ; DATA XREF: BIOS_F:4FEB↑o
a1Cclk_1        db '1 CCLK',0
aCacheWriteCycl db 'Cache Write Cycle       : ',0                               ; DATA XREF: BIOS_F:4F3C↑o
a3Cclk_0        db '3 CCLK',0                                                   ; DATA XREF: BIOS_F:4F3C↑o
a2Cclk_3        db '2 CCLK',0
aCacheBurstRead db 'Cache Burst Read Cycle  : ',0                               ; DATA XREF: BIOS_F:4F55↑o
a1Cclk_2        db '1 CCLK',0                                                   ; DATA XREF: BIOS_F:4F55↑o
a2Cclk_4        db '2 CCLK',0
aL2CachePolicy  db 'L2 Cache Policy         : ',0                               ; DATA XREF: BIOS_F:5068↑o
aWriteThru_0    db 'Write Thru',0                                               ; DATA XREF: BIOS_F:5068↑o
aWriteBack_0    db 'Write Back',0
aL2CacheTagBits db 'L2 Cache Tag Bits       : ',0                               ; DATA XREF: BIOS_F:5081↑o
a8Bits          db '8 bits',0                                                   ; DATA XREF: BIOS_F:5081↑o
a7Bits          db '7 bits',0
aOnboard496aIde db 'Onboard 496A IDE Port   : ',0                               ; DATA XREF: BIOS_F:509A↑o
aDisable_1      db 'Disable',0                                                  ; DATA XREF: BIOS_F:509A↑o
aPrimary_0      db 'Primary',0
                db '???????',1
aBoth_0         db 'Both   ',0
aOnboardVesaIde db 'Onboard VESA IDE-1 WS   : ',0                               ; DATA XREF: BIOS_F:50B3↑o
aOnboardVesaIde_0 db 'Onboard VESA IDE-2 WS   : ',0                             ; DATA XREF: BIOS_F:50CC↑o
aSlowest_0      db 'Slowest',0                                                  ; DATA XREF: BIOS_F:50B3↑o
                db '???????',1
aSlower_0       db 'Slower ',0
                db '???????',1
aFaster_0       db 'Faster ',0
                db '???????',1
aFastest_0      db 'Fastest',0
                db '???????',1
aOnboard496bIde db 'Onboard 496B IDE Port   : ',0                               ; DATA XREF: BIOS_F:50E5↑o
aIde0MasterMode db 'IDE 0 Master Mode       : ',0                               ; DATA XREF: BIOS_F:50FE↑o
aIde0SlaveMode  db 'IDE 0 Slave  Mode       : ',0                               ; DATA XREF: BIOS_F:5117↑o
aIde1MasterMode db 'IDE 1 Master Mode       : ',0                               ; DATA XREF: BIOS_F:5130↑o
aIde1SlaveMode  db 'IDE 1 Slave  Mode       : ',0                               ; DATA XREF: BIOS_F:5149↑o
aAuto_0         db 'Auto',0                                                     ; DATA XREF: BIOS_F:50FE↑o
a0              db '0   ',0
a1              db '1   ',0
a2              db '2   ',0
a3              db '3   ',0
a4              db '4   ',0
aIdePrefetchRea db 'IDE Prefetch Read Buffer: ',0                               ; DATA XREF: BIOS_F:5162↑o
aDisable_2      db 'Disable',0                                                  ; DATA XREF: BIOS_F:5162↑o
                db '???????',1
aBoth_1         db 'Both   ',0
aPrimary_1      db 'Primary',0
aL2CacheDramCyc db 'L2 Cache/DRAM Cycle WS  : ',0                               ; DATA XREF: BIOS_F:4F6E↑o
a3Cclk_1        db '3 CCLK',0                                                   ; DATA XREF: BIOS_F:4F6E↑o
a2Cclk_5        db '2 CCLK',0
aLbdSamplePoint db 'VLB LBD# Sample Point   : ',0                               ; DATA XREF: BIOS_F:4F23↑o
aEndOfT3        db 'End of T3',0                                                ; DATA XREF: BIOS_F:4F23↑o
aEndOfT2        db 'End of T2',0
aIfYouChoose3bc db 'If you choose 3BC port,',0Bh,'it CAN NOT use EPP func.',0Bh,'( EPP and ECP+EPP )',0Bh
                                                                                ; DATA XREF: BIOS_F:51DF↑o
                db 'Otherwise is OK',0
aProgrammingIOC db 'Programming I/O Chip    : ',0                               ; DATA XREF: BIOS_F:517B↑o
aOnboardFddCont db 'Onboard FDD Controller  : ',0                               ; DATA XREF: BIOS_F:5194↑o
aOnboardParalle db 'Onboard Parallel Port   : ',0                               ; DATA XREF: BIOS_F:51DF↑o
a3bch           db '3BCH    ',0                                                 ; DATA XREF: BIOS_F:51DF↑o
a278h           db '278H    ',0
a378h           db '378H    ',0
aDisabled       db 'Disabled',0
aOnboardSerialP db 'Onboard Serial Port 1   : ',0                               ; DATA XREF: BIOS_F:51AD↑o
aCom42e8        db 'COM4/2E8',0                                                 ; DATA XREF: BIOS_F:51AD↑o
aCom33e8        db 'COM3/3E8',0
aCom13f8        db 'COM1/3F8',0
aDisabled_0     db 'Disabled',0
aCom22f8        db 'COM2/2F8',0
aOnboardSerialP_0 db 'Onboard Serial Port 2   : ',0                             ; DATA XREF: BIOS_F:51C6↑o
aCom33e8_0      db 'COM3/3E8',0                                                 ; DATA XREF: BIOS_F:51C6↑o
aCom42e8_0      db 'COM4/2E8',0
aCom22f8_0      db 'COM2/2F8',0
aDisabled_1     db 'Disabled',0
aCom13f8_0      db 'COM1/3F8',0
aOnboardParalle_0 db 'Onboard Parallel Mode   : ',0                             ; DATA XREF: BIOS_F:51F8↑o
aNormal_1       db 'Normal ',0                                                  ; DATA XREF: BIOS_F:51F8↑o
aEppSpp         db 'EPP/SPP',0
aEcp            db 'ECP    ',0
aEcpEpp         db 'ECP/EPP',0
aSerialPort1Mid db 'Serial Port 1 MIDI      : ',0                               ; DATA XREF: BIOS_F:5211↑o
aSerialPort2Mid db 'Serial Port 2 MIDI      : ',0                               ; DATA XREF: BIOS_F:522A↑o

ChipsetFeaturesStrings_End:

SEG_15 ENDS