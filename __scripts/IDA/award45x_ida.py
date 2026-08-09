# IDAPython Helper for AWARD 4.5x BIOS disassembling
# For IDA >= 7.x and Python 3.1x

from idaapi import *
from idc import *
from dataclasses import dataclass, field

@dataclass
class MenuItemInfo:
    ea: int
    flags: int
    name_ptr: int
    name: str
    first_option_ptr: int
    help_ptr: int
    cmosLoc: int
    cmosMask: int

@dataclass
class MenuInfo:
    sysBiosEntry_ptr: int
    start_ptr: int
    end_ptr: int
    startup_string: int
    title: str = ""
    items: list[MenuItemInfo] = field(default_factory=list)

@dataclass
class MenuSystem:
    menus: list[MenuInfo] = field(default_factory=list)
    cmosMap: dict = field(default_factory=dict)

CtrlCharStructNames = {
    0 : 'S_TextCtrl',
    1 : 'S_TextCtrl',
    2 : 'S_Border',
    3 : 'S_ClearRect',
    4 : 'S_StrShow',
    5 : 'S_SetPos',
    6 : 'S_TextCtrl',
    7 : 'S_TextCtrl',
    8 : 'S_TextCtrl',
    9 : 'S_TextCtrl',
    10 : 'S_TextCtrl',
    11 : 'S_TextCtrl',
    12 : 'S_CursorChange',
    13 : 'S_CursorChange',
    14 : 'S_CursorChange',
    15 : 'S_CursorChange',
    16 : 'S_CallRoutine',
    19 : 'S_SubX',
}

def setCurrentPosStruct(ctrlChar, ea=here()):
    structName = CtrlCharStructNames[ctrlChar]
    ok = createStructForce(ea, -1, structName)
    return ok

def nextItem():
    jumpto(get_item_end(here()))

def getNextItemAddr(ea=here()):
    return get_item_end(ea)

def processStringShowCode(ea=here()):
    #print(f'processStringShowCode {hex(ea)}')
    #return parseAwardString(ea + 3)

    offset = get_wide_word(ea + 3)
    #print(f'new offset {offset}')
    parseAwardString(absoluteOffset(offset))

def interpretWordAsCodeOffsetAndMakeCode(ea):
    offset = get_wide_word(ea)
    create_insn(absoluteOffset(offset))

def cleanupAscii(ea):
    while (True):
        curbyte = get_wide_byte(ea)
        
        if (curbyte <= 16):
            break

        ida_bytes.del_items(ea)        
        ea += 1 

def parseAwardString(ea):
    if (ea & 0xffff) == 0 or (ea & 0xffff) == 0xffff:
        return True
    
    #print(f'parseAwardString {hex(ea)}')

    while (True):
        curbyte = get_wide_byte(ea)
        #print (hex(curbyte))

        if (curbyte == 0):
            # do nothing
            #print('V_DONE')
            break
        elif (curbyte == 1):
            # do nothing
            #print('V_DONE1')
            break
        elif (curbyte >= 18) :
            # CP437 text
            cleanupAscii(ea)

            if create_strlit(ea, BADADDR) == True:
                #print('true')
                ea = getNextItemAddr(ea) - 1
                peek = get_wide_byte(ea)
                if (peek == 0) or (peek == 1):
                    break
            
            ea += 1
        else:
            #Control code

            if (curbyte == 4):
                processStringShowCode(ea)
            
            if (curbyte == 16):
                interpretWordAsCodeOffsetAndMakeCode(ea + 1)


            if (setCurrentPosStruct(curbyte, ea) == False):
                print ('Parsing AWD String failed.')
                return False
                break
            
            # Advance cursor
            ea = getNextItemAddr(ea)
    
    return ea

def parseAwardMenuCallbacks(ea):

    #print(f'parseAwardMenuCallbacks = {hex(ea)}')
    if (createWordForce(ea) == False):
        print('Cant create word :(')

    count = get_wide_word(ea)

    ea = getNextItemAddr(ea)

    #print(f'Menu callback count: {count}')
    for i in range(0, count):
        if createStructForce(ea, -1, 'MenuItemCallback') == False:
            #print('Error')
            return False
        
        interpretWordAsCodeOffsetAndMakeCode(ea + 2)

        ea = getNextItemAddr(ea)

def getWord(ea=here()):
    word = get_wide_word(here())
    return word

# OLD IDA 8.x CODE
# def createStructForce(ea, size, strname):
#     strid = ida_struct.get_struc_id(strname)
# 
#     if size == -1:
#         size = ida_struct.get_struc_size(strid)
# 
#     return ida_bytes.create_struct(ea, size, strid, True)
# 
# def createWordForce(ea):
#     return ida_bytes.create_word(ea, 2, True)
# 
# def sizeofStruct(strname):
#     strid = ida_struct.get_struc_id(strname)
#     return ida_struct.get_struc_size(strid)
#     

def getStructId(name):
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        raise RuntimeError(f"Structure '{name}' not found")

    return tif.get_tid()


def sizeofStruct(name):
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        raise RuntimeError(f"Structure '{name}' not found")

    return tif.get_size()


def createStructForce(ea, size, name):
    tid = getStructId(name)

    if size == -1:
        size = sizeofStruct(name)

    return ida_bytes.create_struct(ea, size, tid, True)

def createWordForce(ea):
    return ida_bytes.create_word(ea, 2, True)

def absoluteOffset(offset):
    return 0xF0000 + offset

def parseMenuItem(ea):
    # Create the struct
    if createStructForce(ea, -1, 'MenuItem') == False:
        raise Exception(f'Failed to parse menu item at {hex(ea)}')

    item = MenuItemInfo(
        ea                  = ea,
        flags               = get_wide_word(ea),
        name_ptr            = absoluteOffset(get_wide_word(ea + 2)),
        name                = readAwardString(absoluteOffset(get_wide_word(ea + 2))),
        first_option_ptr    = absoluteOffset(get_wide_word(ea + 11)),
        help_ptr            = absoluteOffset(get_wide_word(ea + 23)),
        cmosLoc             = get_byte(ea + 8),
        cmosMask            = get_wide_word(ea + 9),
    )

# This needs some more logic so it doesn't get stuck here...
#    min = get_wide_word(ea + 13)
#    max = get_wide_word(ea + 15)
#    optionCount = max - min + 1
#    
#    
#    optionOffset = firstOptionPtr
#
#    for i in range(0, optionCount):
#        optionOffset = parseAwardString(optionOffset)


    parseAwardString(item.name_ptr)
    parseAwardString(item.first_option_ptr)

    return item

def readAwardString(ea, stop_on_01=True):
    data = bytearray()

    while True:
        b = get_wide_byte(ea)

        if b == 0:                  break
        if stop_on_01 and b == 1:   break

        data.append(b)
        ea += 1

    return data.decode("cp437", errors="replace")

def parseMenuFromScratch() -> MenuSystem:
    print(f'Parsing menu...')
    
    print(f'here: {hex(here())}')
    offset = 0xf0000 + get_wide_word(0xff85d)

    topMenusItemTuples = []
    topMenusPtrTuples = []

    print(f'Menu offset: {hex(offset)}')

    topMenuCount = 0
    while (topMenuCount < 255):
        endMarker = get_wide_word(offset)
        #print (f'{hex(endMarker)}')

        if endMarker == 0xffff:
            createWordForce(offset)
            print('End of list')
            break

        # Push these params to top menu item tuple list
        #print(f'{hex(get_wide_word(offset + 0))}')
        #print(f'{hex(get_wide_word(offset + 2))}')
        #print(f'{hex(get_wide_word(offset + 4))}')
        #print(f'---------------------------')
        toAdd = [offset, get_wide_word(offset), get_wide_word(offset+2), get_wide_word(offset+4)]
        topMenusItemTuples.append(toAdd)

        # Create sysbios menu def

        createStructForce(offset, -1, 'SysbiosMenuDef')

        offset = get_item_end(offset)

        topMenuCount += 1

    print("Processing Items")

    menus = []
    names = []

    count = 0

    for entryPtr, startPtr, endPtr, startupStr in topMenusItemTuples:

        menu = MenuInfo(
            sysBiosEntry_ptr=entryPtr,
            start_ptr=absoluteOffset(startPtr),
            end_ptr=absoluteOffset(endPtr),
            startup_string=absoluteOffset(startupStr),
        )

        itemCount = int((endPtr - startPtr) / sizeofStruct('MenuItem'))

        #print(f'itemCount = {itemCount}')

        parseAwardString(menu.startup_string)

        itemOffset = menu.start_ptr

        for i in range(itemCount):
            menu.items.append(parseMenuItem(itemOffset))
            itemOffset = getNextItemAddr(itemOffset)

        # Item 0 is the top level menu and contains the names of the submenus
        if (count == 0):
            # The names for the next menus live in these items
            for item in menu.items:
                names.append(readAwardString(item.first_option_ptr))
        else:
            menu.title = names[count - 1]

        count += 1
        menus.append(menu)


    # Now parse all the Menu Callbacks
    offset += 2
    print(f'Top menu count: {topMenuCount}, MenuCBStructTable Offset {hex(offset)}')


    for i in range(0, topMenuCount):
        createStructForce(offset, -1, 'MenuPageEntry')

        cbList1Ptr = absoluteOffset(get_wide_word(offset))
        cbList2Ptr = absoluteOffset(get_wide_word(offset + 2))
        menuFuncsPtr = absoluteOffset(get_wide_word(offset + 4))

        parseAwardMenuCallbacks(cbList1Ptr)
        parseAwardMenuCallbacks(cbList2Ptr)


        createStructForce(menuFuncsPtr, -1, 'MenuPageFuncs')
        interpretWordAsCodeOffsetAndMakeCode(menuFuncsPtr + 0)
        interpretWordAsCodeOffsetAndMakeCode(menuFuncsPtr + 2)
        interpretWordAsCodeOffsetAndMakeCode(menuFuncsPtr + 4)
        interpretWordAsCodeOffsetAndMakeCode(menuFuncsPtr + 6)


        offset = getNextItemAddr(offset)

    print("CMOS List")

    cmosUsed = {}
    cmosTuplesToCheck = []

    for i in range(1, len(menus)):
        menu = menus[i]
        for item in menu.items:
            cmosTuplesToCheck.append( (item.cmosLoc, item.cmosMask & 0xFF) )

            if (item.cmosMask > 0xFF):
                cmosTuplesToCheck.append( (item.cmosLoc + 1, item.cmosMask >> 8) )

    for loc, mask in cmosTuplesToCheck:

        if loc > 0x7F:
            # This is a memory item, not a cmos storage item
            continue

        if loc in cmosUsed:
            previousMask = cmosUsed[loc]

            overlappingBits = previousMask & mask
            if overlappingBits:
                print(
                    f"WARNING: CMOS {loc:02X}: "
                    f"bits already used: {overlappingBits:02X}, "
                    f"new mask: {mask:02X}, "
                    f"previous mask: {previousMask:02X}"
                )

            cmosUsed[loc] |= mask
        else:
            cmosUsed[loc] = mask

    #######################################
    # Add some known locations 

    cmosUsed[0x00] = 0xFF # RTC seconds
    cmosUsed[0x01] = 0xFF # RTA seconds
    cmosUsed[0x02] = 0xFF # RTC minutes
    cmosUsed[0x03] = 0xFF # RTA minutes
    cmosUsed[0x04] = 0xFF # RTC hours
    cmosUsed[0x05] = 0xFF # RTA hours
    cmosUsed[0x06] = 0xFF # Day of week
    cmosUsed[0x07] = 0xFF # Day of month
    cmosUsed[0x08] = 0xFF # Month
    cmosUsed[0x09] = 0xFF # Year 
    cmosUsed[0x0D] = 0xFF # ?
    cmosUsed[0x0E] = 0xFF # Status (memory, keyboard, checksum, equipment)
    cmosUsed[0x0F] = 0xFF # ACPI shutdown
    cmosUsed[0x10] = 0xFF # Floppy type
    cmosUsed[0x11] = 0xFF # General BIOS settings (block mode, a20, numlock)
    cmosUsed[0x12] = 0xFF # C/D Drive present
    cmosUsed[0x13] = 0xFF # General BIOS Settings (floppy seek, typematic)
    cmosUsed[0x14] = 0xFF # installed equipment
    cmosUsed[0x15] = 0xFF # Base Memory 1
    cmosUsed[0x16] = 0xFF # Base Memory 2
    cmosUsed[0x17] = 0xFF # Extended memory 1
    cmosUsed[0x18] = 0xFF # Extended memory 2
    cmosUsed[0x19] = 0xFF # Drive C type
    cmosUsed[0x1A] = 0xFF # Drive D type
    cmosUsed[0x1C] = 0xFF # Password
    cmosUsed[0x2E] = 0xFF # Checksum 1
    cmosUsed[0x2F] = 0xFF # Checksum 2
    cmosUsed[0x30] = 0xFF # Extended memory 1 (not sure what the difference is)
    cmosUsed[0x31] = 0xFF # Extended memory 2 (not sure what the difference is)
    cmosUsed[0x32] = 0xFF # Century
    cmosUsed[0x33] = 0xFF # ?
    cmosUsed[0x37] = 0xFF # ?
    cmosUsed[0x38] = 0xFF # EMS Size
    cmosUsed[0x39] = 0xFF # EMS I/O Address
    cmosUsed[0x3A] = 0xFF # EMS Page offset
    cmosUsed[0x3B] = 0xFF # Cache control
    cmosUsed[0x3C] = 0xFF # General BIOS settings (DRAM > 64MB OS, no fdd for win95)
    cmosUsed[0x3D] = 0xFF # CPU type index
    cmosUsed[0x3E] = 0xFF # General BIOS settings (Halt on, swap floppy drive)
    cmosUsed[0x3F] = 0xFF # CPU feature flags

    # Drive 48 params
    for i in range (0x1E, 0x26): cmosUsed[i] = 0xFF
    # Drive 49 params
    for i in range (0x26, 0x2E): cmosUsed[i] = 0xFF
    # Drive 50 params
    for i in range (0x68, 0x6F): cmosUsed[i] = 0xFF
    # Drive 41 params
    for i in range (0x71, 0x79): cmosUsed[i] = 0xFF

    cmosUsed[0x67] = 0xFF # Drive E type
    cmosUsed[0x70] = 0xFF # Drive F type
    cmosUsed[0x79] = 0xFF # Drives C-F Access mode (Normal/LBA/Large)


    ######################################
    # Print CMOS bit mask

    for loc in range(0, 0x80):
        mask = 0

        if loc in cmosUsed: 
            mask = cmosUsed[loc] 

        usedStr = ''
        for i in range(0, 8):
            if mask & 1:    usedStr = 'X' + usedStr
            else:           usedStr = '.' + usedStr
            mask >>= 1

        print(f'{loc:02X}, {usedStr}')

    menuSystem = MenuSystem(menus, cmosUsed)
    return menuSystem

# menus = parseMenuFromScratch()
# 
# count = 0
# for menu in menus:
# 
#     count += 1
#     if count == 1: continue
# 
#     print (f'[ {menu.title} ]:')
# 
#     for item in menu.items:
#         print('               ', readAwardString(item.name_ptr))
# 