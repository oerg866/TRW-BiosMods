#########################################
#
#   BIOS modding helper script
#   (C) 2024 Eric Voirin (oerg866)
#   www.theretroweb.com
#
#########################################

import argparse
import os
import sys
import lhafile
import struct

def linear_checksum_1(bios_data, offset, count):
    sum = 0
    
    for i in range(0, count):
        sum += (int(bios_data[offset + i]) & 0xff)

    sum = sum & 0xff

#    print(f'Linear checksum (normal), offset {hex(offset)}, size {hex(count)}: {hex(sum)}')
    
    return sum

def linear_checksum_2(bios_data, offset, count):
    sum = 0
    
    for i in range(0, count):
        sum += (int(bios_data[offset + i]) & 0xff)

    sum = (0x100 - sum) & 0xff

#    print(f'Linear checksum (0x100-n), offset {hex(offset)}, size {hex(count)}: {hex(sum)}')
    
    return sum

def checksum_award450(bios_data):
    size = len(bios_data)

    checksum_firstblock = linear_checksum_1(bios_data, 0, 0x100)

    if checksum_firstblock != 0:
        bios_data[0x00b2] = (bios_data[0x00b2] + 0x100 - checksum_firstblock) & 0xff

    linear_checksum_1(bios_data, 0, 0x100)
    
    bios_data[0xe07b] = linear_checksum_2(bios_data, 0xe061, 0x1a)
    bios_data[0xe10f] = linear_checksum_2(bios_data, 0xe0c1, 0x4e)
    bios_data[0xffee] = linear_checksum_2(bios_data, 0xe000, 0x1fee)
    checksums = bytes([bios_data[0xe07b], bios_data[0xe10f], bios_data[0xffee]])
    bios_data[0xffef] = linear_checksum_2(checksums, 0, 3)
    bios_data[0xffff] = linear_checksum_2(bios_data, 0, size - 1)
    
    return bios_data


def extract_lzh_from(destination_folder, buffer, offset):
    if os.path.isfile(destination_folder):
        raise Exception("Given destination folder is a file")

    if not os.path.isdir(destination_folder):
        os.makedirs(destination_folder)

    arc_data = buffer[offset:]

    # Check if we can actually have a file here
    if len(arc_data) < 22:
        return [0, "", 0, 0]

    # Check header data for plausibility
    comp_scheme = struct.unpack_from('3s', arc_data, 2)[0]
    if comp_scheme != bytearray("-lh",encoding="ascii"):
        print (comp_scheme)
        return [-1, "", 0, 0]

    if struct.unpack_from('B', arc_data, 20)[0] != 0x01:
        return [-2, "", 0, 0]

    header_length = struct.unpack_from('B', arc_data, 0)[0]
    compressed_length = struct.unpack_from('<I', arc_data, 7)[0]
    temporary_compressed_length = compressed_length + header_length
    filename_length = struct.unpack_from('B', arc_data, 21)[0]

    filetime = struct.unpack_from('<H', arc_data, 15)[0]
    filedate = struct.unpack_from('<H', arc_data, 17)[0]

    filename = struct.unpack_from(f'{filename_length}s', arc_data, 22)[0].decode()
    
    temporary_compressed_length = temporary_compressed_length + 2 # 2 for the "next header size" field

    if (temporary_compressed_length > len(arc_data)):
        return [-3, "", 0, 0]

#    print(f'{filename} {header_length} + {compressed_length} = {header_length + compressed_length}')
#    print(f'Searching for extended headers...')

    extHeader_start = header_length

    while True:
        extHeader_length = struct.unpack_from('<H', arc_data, extHeader_start)[0]
        extHeader_start = extHeader_start + extHeader_length
        temporary_compressed_length += extHeader_length
        if extHeader_length == 0:
            break
 #       print(f'Ext header length {extHeader_length} skipped...')

    temp_compressed_filename = f'{filename}.lzh'

    # Last byte needs to be 0x00

    if arc_data[temporary_compressed_length] != 0x00:
        raise Exception("Compressed data end stamp mismatch")
    
    temporary_compressed_length += 1

#    print(f'Total archive size: {temporary_compressed_length}')

    compressed_file_data = arc_data[:temporary_compressed_length]

    with open(temp_compressed_filename, 'wb') as temp_compressed_file:
        temp_compressed_file.write(compressed_file_data)
    
    output_filename = os.path.join(destination_folder, filename)

    with open(output_filename, 'wb') as outfile:
        with open(temp_compressed_filename, 'rb') as arc_fp:
            lzh_file = lhafile.Lhafile(arc_fp)
            outfile.write(lzh_file.read(filename))

    os.remove(temp_compressed_filename)

    print(f'File {filename} extraction complete!')

    return [temporary_compressed_length, filename, filetime, filedate]

def extract_lzh_all(destination_folder, buffer):
    current_arc_offset = 0
    files_extracted = 0

    all_files = []

    while True:
        last_arc_size, last_arc_filename, last_arc_offset, last_arc_segment = extract_lzh_from(destination_folder, buffer, current_arc_offset)

        if last_arc_size <= 0:
            print(f'extract_lzh_from returned with code {last_arc_size}')
            break
        
        print(f'Module name: {last_arc_filename}, Module Size: {last_arc_size}, LoadSegment: {hex(last_arc_segment)}, LoadOffset: {hex(last_arc_offset)}')

        files_extracted += 1
        # The first file is the system BIOS
        if files_extracted == 1:
#            print(f'SYSTEM BIOS name is {last_arc_filename}')
            current_arc_checksum = linear_checksum_1(buffer, current_arc_offset, last_arc_size)
            print(f'System BIOS Checksum: {hex(current_arc_checksum)} (calculated) | {hex(buffer[current_arc_offset + last_arc_size])} (in file)')
            current_arc_offset += 1 # +1 for checksum byte

        current_arc_offset += last_arc_size

        all_files.append(tuple([last_arc_filename, last_arc_offset, last_arc_segment]))

    print(f'Files extracted: {files_extracted}: {all_files}')

    # Find padding size

    padding_size = 0

    while (current_arc_offset < len(buffer)) and (buffer[current_arc_offset] == 0xff):
        padding_size += 1
        current_arc_offset += 1

    print(f'Padding size: {padding_size}, max. compressed modules total size = {current_arc_offset} ({hex(current_arc_offset)})')

    # Write files.dat to rebuild the ROM with
    with open(os.path.join(destination_folder, "files.dat"), "w") as listfile:
        # Write maximal compressed modules total size as first line (important!)
        listfile.write(f'{current_arc_offset}\n')
        for file, offset, segment in all_files:
            listfile.write(f'{file} {hex(offset)} {hex(segment)}\n')

    with open(os.path.join(destination_folder, "baserom.bin"), "wb") as baseromfile:
        baseromfile.write(buffer)

    return files_extracted

def compress_lzh(in_filename, out_filename):
    scriptpath = (os.path.dirname(os.path.realpath(__file__)))
    lha_exe = os.path.join(scriptpath, 'lha32.exe')

    # LHA adds pathnames for whatever reason so we need to go in that directory to make sure that's not the case...
    in_absolute = os.path.abspath(in_filename)
    in_relative = os.path.basename(in_absolute)
    in_path = os.path.dirname(in_absolute)
    out_absolute = os.path.abspath(out_filename)

    if os.path.exists(out_absolute):
        os.remove(out_absolute)

    olddir = os.path.abspath(os.curdir)
    lha_cmd = f'"{lha_exe}" a /h1 /s /c "{out_absolute}" "{in_relative}"'
    print(lha_cmd)
    os.chdir(in_path)
    ret = os.popen(lha_cmd).read()
    os.chdir(olddir)

    return ret

# Converts an LZH header to an AWARD compliant format:
# * Strips extended headers of a single LZH file. (If there are multiple, the other ones will be ignored.)
# * Adds module type/segment/offset info to the DATE/TIME fields
def lzh_convert_to_award_header(input_data:bytearray, offset, segment):
    current_offset = 0
    first_header_size = struct.unpack_from('B', input_data, 0)[0]
  
    # Header checksum before

#    print(f'PREV HEADER CHECKSUM: {hex(linear_checksum_1(input_data, 2, first_header_size))} (calculated) {hex(input_data[1])} (in header)')    

    output_data = input_data[current_offset:first_header_size]

    # Award hack to use date time for the offset and segment
    struct.pack_into('<HH', output_data, 15, offset, segment)

    output_data += bytearray([0x00, 0x00])    # Overwrite extended header length

    # ... and skip all the extended headers
    current_offset += first_header_size
    
    total_skip_length = 0

    while (current_offset + 2) < len(input_data):
        skip_length = struct.unpack_from('<H', input_data, current_offset)[0]
        current_offset += 2

        # If it was the last extended header, break
        if skip_length == 0:
            break

        if skip_length < 3:
            raise Exception("Broken LHA file has too short extended header...")

        # If not, skip its length and try again
        current_offset += (skip_length - 2) # -2 because the next length is part of it
        print(f'LZH: Stripped extended header of length {skip_length}')  

        total_skip_length += skip_length
        
    output_data += input_data[current_offset:]

    # Compressed size includes the size of all Extended headers for the file, we must correct for it
    compressed_length = struct.unpack_from('<H', output_data, 7)[0] - total_skip_length
    struct.pack_into('<H', output_data, 7, compressed_length)

    # Fix header checksum
    output_data[1] = linear_checksum_1(output_data, 2, first_header_size)

    return output_data

def rebuild_rom(source_folder, output_filename):
    with open(os.path.join(source_folder, 'files.dat'), 'r') as filelist:
        with open(os.path.join(source_folder, 'baserom.bin'), 'rb') as baserom:
            rom_data = bytearray(baserom.read())

        uncomp_start_offset = int(filelist.readline())

        print(f'{hex(uncomp_start_offset)}')

        # Remove everything before the important data starts
        rom_data[0:uncomp_start_offset] = [0xff] * uncomp_start_offset
        
        tmp_filename = 'tmp.lzh'
        file_count = 0
        current_module_offset = 0

        # Iterate through every module to compress

        for module_entry in filelist:

            module_filename, module_offset, module_segment = module_entry.rstrip().split(' ')

            # Fix F-Segment checksum if needed

            if file_count == 0:
                sysbios_filename = os.path.join(source_folder, module_filename)
                with open(sysbios_filename, 'rb') as tmp:
                    sysbios_data = bytearray(tmp.read())
                with open(sysbios_filename, 'wb') as tmp:
                    print(f'{sysbios_filename} {len(sysbios_data)}')
                    sum = linear_checksum_2(sysbios_data, len(sysbios_data) - 0x10000, 0xffff)
                    print(f'SYSBIOS F-Segment Checksum: {hex(sum)} (calculated) {hex(sysbios_data[len(sysbios_data)-1])} (in file)')
                    sysbios_data[len(sysbios_data)-1] = sum
                    tmp.write(sysbios_data)

            # Compress into temporary LZH file

            errcode = compress_lzh(os.path.join(source_folder, module_filename), tmp_filename)
            
            # Load resulting compressed file in a buffer and write it to the rom data
            with open(tmp_filename, 'rb') as lzh_file:
                compressed_data = bytearray(lzh_file.read())

            os.remove(tmp_filename)

            # Finnagle header to make it AWARD compliant
            compressed_data = lzh_convert_to_award_header(compressed_data, int(module_offset, base=0), int(module_segment, base=0))

            rom_data[current_module_offset:current_module_offset+len(compressed_data)] = compressed_data
            
            print(f'{file_count}: Compress {module_filename} -> {tmp_filename}, offset {hex(current_module_offset)}, size {len(compressed_data)}')

            current_module_offset += len(compressed_data)

            # For the system bios we need to add a checksum

            if file_count == 0:
                checksum = linear_checksum_1(compressed_data, 0, len(compressed_data))
                print(f'System BIOS checksum: {hex(checksum)}')
                rom_data[current_module_offset] = checksum
                current_module_offset += 1

            file_count += 1

            if current_module_offset > uncomp_start_offset:
                raise Exception("ERROR - compressed modules too big to fit inside free space in BIOS ROM!")

    with open(output_filename, 'wb') as outfile:
        outfile.write(rom_data)



# create an argument parser with options, parse and extract them
parser = argparse.ArgumentParser(description='BIOS patch stuffery by Oerg866 :3', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i', type=str, help='Filename of BIOS to patch.')
parser.add_argument('-removeheader', action='store_true', help='Remove MZ header from a binary file (e.g. if a multi-segment BIOS file was assembled using MASM+LINK)')
parser.add_argument('-blob', type=str, action='append', help='Apply a binary file to specified location.', nargs=2, metavar=('filename', 'offset'))
parser.add_argument('-blobpart', type=str, action='append', help='Apply a binary blob to specified location.', nargs=4, metavar=('filename', 'source_offset', 'target_offset', 'length'))
parser.add_argument('-b', type=str, action='append', help='Patch a byte in the file.', nargs=2, metavar=('offset', 'value'))
parser.add_argument('-s', type=str, action='append', help='Write a string to the given offset into the file.', nargs=2, metavar=('offset', 'string'))
parser.add_argument('-o', type=str, help='Output file name.')
parser.add_argument('-award450', action='store_true', help='Fixup AWARD 4.50 checksum (EXPERIMENTAL)')
#parser.add_argument('-get_sysbios', action='store_true', help='Extract system BIOS ("original.tmp") from file.')
parser.add_argument('-bios_extract', type=str, help="Extract all compressed BIOS modules to given directory (will be created if it doesn't exist)")
parser.add_argument('-bios_build', type=str, help="Build a BIOS ROM with compressed modules based off a directory created with -bios_extract", nargs=2, metavar=('srcdir', 'rom_filename'))

args = parser.parse_args()

# Extract command line arguments

if args.bios_build is not None:
    rebuild_rom(args.bios_build[0], args.bios_build[1])
    exit()

bios_filename = args.i
output_filename = args.o

# All other options require an -i parameter

if bios_filename is None:
    print("Output file name required.")
    exit()

with open(bios_filename, 'rb') as bios_file:
    bios_data = bytearray(bios_file.read())

if args.bios_extract is not None:
    extract_lzh_all(args.bios_extract, bios_data)
    exit()

if output_filename is None:
    print("Output file name required.")
    exit()


with open(output_filename, 'wb') as patched_file:

    if args.removeheader is not None:
        bios_data = bios_data[0x200:]

    if args.blob is not None:
        for blobpatch in args.blob:
            patch_filename = blobpatch[0]
            patch_offset = int(blobpatch[1], 0)
            print(f'{patch_filename}  {hex(patch_offset)}')

            # Open and read the patch file into a byte buffer
            with open(patch_filename, 'rb') as patch_file:
                patch_data = bytearray(patch_file.read())
            
            # Calculate the end offset where the patch data will be copied and check for oob
            end_offset = patch_offset + len(patch_data)

            if end_offset > len(bios_data):
                print('Error: Patch offset exceeds BIOS size')
                quit()
            
            # Copy patch data into the BIOS buffer
            for i in range(len(patch_data)):
                bios_data[patch_offset + i] = patch_data[i]
                
    if args.blobpart is not None:
        for blobpatch in args.blobpart:
            patch_filename = blobpatch[0]
            source_offset = int(blobpatch[1], 0)
            patch_offset = int(blobpatch[2], 0)
            patch_size = int(blobpatch[3], 0)
            print(f'{patch_filename} {hex(source_offset)} {hex(patch_offset)} {patch_size}')

            # Open and read the patch file into a byte buffer
            with open(patch_filename, 'rb') as patch_file:
                patch_data = bytearray(patch_file.read())
            
            # Calculate the end offset where the patch data will be copied and check for oob
            end_offset = patch_offset + patch_size

            if end_offset > len(bios_data):
                print('Error: Patch offset exceeds BIOS size')
                quit()
            
            # Copy patch data into the BIOS buffer
            for i in range(patch_size):
                bios_data[patch_offset + i] = patch_data[source_offset + i]

    if args.b is not None:
        for bytepatch in args.b:
            patch_offset = int(bytepatch[0], 0)
            patch_value = int(bytepatch[1], 0)

            print(f'{hex(patch_offset)} {hex(patch_value)}')

            if patch_offset > len(bios_data):
                print('Error: Patch offset exceeds BIOS size')
                quit()

            if patch_value > 0xFF or patch_value < 0:
                print('ERROR: Patch value out of range.')
                quit()
            
            bios_data[patch_offset] = patch_value

    if args.s is not None:
        for stringpatch in args.s:
            patch_offset = int(bytepatch[0], 0)
            patch_value = int(bytepatch[1], 0)

            print('NOT IMPLEMENTED')

    if args.award450:
        bios_data = checksum_award450(bios_data)

    patched_file.write(bios_data)


quit()