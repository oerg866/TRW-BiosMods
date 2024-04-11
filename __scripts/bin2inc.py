#########################################
#
#   BIOS modding helper script
#   (C) 2024 Eric Voirin (oerg866)
#   www.theretroweb.com
#
#########################################

import sys

def hex_no_0x(val, padding):
    retstr = f'{val:0{padding}x}'
    return retstr


print('bin2inc.py - Convert binary file to includable x86 assembly file for MASM')
print(f'{sys.argv[1]}')

with open(sys.argv[1], 'rb') as infile:
    binfile = infile.read()

if len(binfile) > (16 * 65536):
    raise Exception("File too big.")


with open(sys.argv[2], 'w') as outfile:
    BYTES_PER_LINE = 8
    bytecount = 0
    pagecount = int(len(binfile) / 65536)
    first_page = 16 - pagecount # first page segment = 0xF000
    cur_page = first_page

    outfile.write(f'')

    for i in range(0, len(binfile), BYTES_PER_LINE):

        # Write next segment if needed

        if (bytecount % 65536) == 0:
            if cur_page != first_page:
                outfile.write(f'SEG_{cur_page-1} ENDS\n')

            seg =  cur_page * 0x1000
            outfile.write(f'G_{cur_page} SEGMENT USE16 AT {hex_no_0x(seg, 5)}h\n')
            outfile.write(f'G_{cur_page} ENDS\n')
            outfile.write(f'SEG_{cur_page} SEGMENT USE16 PARA PUBLIC \'CODE\'\n')
            outfile.write(f' ASSUME CS:G_{cur_page}\n')
            outfile.write(f' ORG 0h\n')
#            outfile.write(f'SEG_{cur_page} SEGMENT USE16 AT {hex_no_0x(seg, 5)}h\n')


#ECODE		SEGMENT USE16 PARA PUBLIC 'ECODE'
#		ASSUME	CS:EGROUP,DS:G_RAM,ES:EGROUP

            cur_page += 1

        outfile.write(' DB ')


        for j in range(0, BYTES_PER_LINE):
            if (i+j) > len(binfile):
                break

            outfile.write(f'0{hex_no_0x(binfile[i + j], 2)}h')
            
            if j < (BYTES_PER_LINE-1):
                outfile.write(',')
                
        
        outfile.write('\n')

        bytecount += BYTES_PER_LINE
    
    outfile.write(f'SEG_{cur_page-1} ENDS\n')
#    outfile.write(' END\n')
