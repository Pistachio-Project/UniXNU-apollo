#!/usr/bin/env python3
"""Make the prelink's naming reference from a Kernel Debug Kit kernel and its dSYM.

    scripts/kdk-reference.py KERNEL KERNEL.dwarf OUTPUT

The KDK kernel is the code UniXNU's matcher compares the stripped iOS kernel with; its own symbol table holds only
the exported symbols. The dSYM's Mach-O holds every symbol (static functions too) at the same addresses. The output
is the kernel with the dSYM's symbol and string tables appended and LC_SYMTAB pointing at them; nothing else changes.
"""
import struct
import sys
from pathlib import Path

LC_SYMTAB, LC_SEGMENT_64, LC_UUID = 0x2, 0x19, 0x1B


def commands(data):
    offset = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, offset)
        yield command, offset
        offset += size


def find(data, wanted):
    return next(offset for command, offset in commands(data) if command == wanted)


def main():
    kernel_path, dwarf_path, output = map(Path, sys.argv[1:4])
    kernel, dwarf = bytearray(kernel_path.read_bytes()), dwarf_path.read_bytes()
    for name, image in (('kernel', kernel), ('dSYM', dwarf)):
        if struct.unpack_from('<I', image, 0)[0] != 0xFEEDFACF:
            sys.exit(f'{name}: not a 64-bit Mach-O')
    if kernel[find(kernel, LC_UUID) + 8:][:16] != dwarf[find(dwarf, LC_UUID) + 8:][:16]:
        sys.exit('the dSYM is not this kernel\'s (UUIDs differ)')
    symoff, nsyms, stroff, strsize = struct.unpack_from('<4I', dwarf, find(dwarf, LC_SYMTAB) + 8)
    symbols, strings = dwarf[symoff:symoff + 16 * nsyms], dwarf[stroff:stroff + strsize]
    while len(kernel) % 8:
        kernel.append(0)
    new_symoff = len(kernel)
    kernel += symbols
    new_stroff = len(kernel)
    kernel += strings
    struct.pack_into('<4I', kernel, find(kernel, LC_SYMTAB) + 8, new_symoff, nsyms, new_stroff, strsize)
    # __LINKEDIT, the last segment of the file, grows to hold the appended tables.
    for command, offset in commands(kernel):
        if command == LC_SEGMENT_64 and bytes(kernel[offset + 8:offset + 24]).rstrip(b'\0') == b'__LINKEDIT':
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<4Q', kernel, offset + 24)
            grown = len(kernel) - fileoff
            struct.pack_into('<Q', kernel, offset + 32, max(vmsize, (grown + 0x3fff) & ~0x3fff))
            struct.pack_into('<Q', kernel, offset + 48, grown)
    output.write_bytes(kernel)
    print(f'{output}: {nsyms} symbols')


if __name__ == '__main__':
    main()
