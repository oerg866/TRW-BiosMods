SOYO - 4SAW

https://theretroweb.com/motherboards/s/soyo-sy-4saw

BIOS mod by Eric Voirin

-<V0.98>--------------------------------------------
* Add TRW logo mod :-)

-<V0.96>--------------------------------------------
* Remove buggy chipset init table again
  - Fixes IDE not working when PCI devices are plugged
* Fix flipped bit in PCI IRQ CMOS bitmask
  - Fixes broken PCI IRQ assignments

-<V0.94>--------------------------------------------

* CHIPSET FEATURES SETUP
  - Add 16 / 8 bit IO Cycle Recovery settings
  - Add IDE Address setup time settings
  - Add 16 / 8 bit Memory IO WaitState settings

* PCI CONFIGURATION SETUP
  - Add CAS/MA/MWE/SA/SBHE/IOR/IOW Drive Strength settings
  - Add PCI/ISA Master Shadow RAM Access setting
  - Add missing options to PCI Arbitration Scheme setting

-<V0.9>--------------------------------------------
* Restore hidden chipset configuration options
* Change version strings

-<V0.1>--------------------------------------------

* Change chipset register table
  Based on ASUS PVI-486SP3 registers

Based on WA53.