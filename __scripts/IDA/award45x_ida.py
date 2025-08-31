# IDAPython Helper for AWARD 4.5x BIOS disassembling
# For IDA >= 7.x and Python 3.1x

from idaapi import *
from idc import *

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
    print(f'processStringShowCode {hex(ea)}')
    #return parseAwardString(ea + 3)

    offset = get_wide_word(ea + 3)
    print(f'new offset {offset}')
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
    
    print(f'parseAwardString {hex(ea)}')

    while (True):
        curbyte = get_wide_byte(ea)
        print (hex(curbyte))

        if (curbyte == 0):
            # do nothing
            print('V_DONE')
            break
        elif (curbyte == 1):
            # do nothing
            print('V_DONE1')
            break
        elif (curbyte >= 18) :
            # CP437 text
            cleanupAscii(ea)

            if create_strlit(ea, BADADDR) == True:
                print('true')
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

def parseAwardMenuCallbacks(ea=here()):

    print(f'parseAwardMenuCallbacks = {hex(ea)}')
    if (createWordForce(ea) == False):
        print('Cant create word :(')

    count = get_wide_word(ea)

    ea = getNextItemAddr(ea)

    print(f'Menu callback count: {count}')
    for i in range(0, count):
        if createStructForce(ea, -1, 'MenuItemCallback') == False:
            print('Error')
            return False
        
        interpretWordAsCodeOffsetAndMakeCode(ea + 2)

        ea = getNextItemAddr(ea)

def getWord(ea=here()):
    word = get_wide_word(here())
    return word

def createStructForce(ea, size, strname):
    strid = ida_struct.get_struc_id(strname)

    if size == -1:
        size = ida_struct.get_struc_size(strid)

    return ida_bytes.create_struct(ea, size, strid, True)

def createWordForce(ea):
    return ida_bytes.create_word(ea, 2, True)

def sizeofStruct(strname):
    strid = ida_struct.get_struc_id(strname)
    return ida_struct.get_struc_size(strid)
    

def absoluteOffset(offset):
    return 0xF0000 + offset

def parseMenuItem(ea):
    # Create the struct
    if createStructForce(ea, -1, 'MenuItem') == False:
        raise Exception('Failed to parse menu item')
    
    itemNamePtr = absoluteOffset(get_wide_word(ea + 2))
    firstOptionPtr = absoluteOffset(get_wide_word(ea + 11))
    HelpStrPtr = absoluteOffset(get_wide_word(ea + 23))

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

    parseAwardString(itemNamePtr)
    parseAwardString(firstOptionPtr)


def parseMenuFromScratch():
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
        print(f'{hex(get_wide_word(offset + 0))}')
        print(f'{hex(get_wide_word(offset + 2))}')
        print(f'{hex(get_wide_word(offset + 4))}')
        print(f'---------------------------')
        topMenusItemTuples.append((get_wide_word(offset), get_wide_word(offset+2), get_wide_word(offset+4)))

        # Create sysbios menu def

        createStructForce(offset, -1, 'SysbiosMenuDef')

        offset = get_item_end(offset)

        topMenuCount += 1

    print("Processing Items")

    for startPtr, endPtr, startupStr in topMenusItemTuples:
        print(f'{hex(startPtr)} {hex(endPtr)} {hex(startupStr)}')
        itemCount = int((endPtr - startPtr) / sizeofStruct('MenuItem'))

        startPtr = absoluteOffset(startPtr)
        startupStr = absoluteOffset(startupStr)
        print(f'itemCount = {itemCount}')

        # Parse StartupString
        parseAwardString(startupStr)

        # Parse Menu Items
        itemOffset = startPtr
        for i in range(0, itemCount):
            parseMenuItem(itemOffset)
            itemOffset = getNextItemAddr(itemOffset)

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

    print("donezo schmonezo")
