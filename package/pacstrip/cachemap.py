#!/usr/bin/env python3
"""The code of a dyld shared cache: which bytes of its executable mappings are instructions.

    cachemap.py scan DIRECTORY        count what a code-only rewrite changes, and what a whole-mapping one would damage

A cache is a main file and sub-cache files (dyld_shared_cache_arm64e, .01, .02, ...), each with a header and a
mapping table. The main header lists every image; an image's Mach-O header sits in some file's read-execute
mapping and names its sections by address. The instruction sections (__text, stubs, ...) of all images are the
code; everything else in an executable mapping (headers, constants, strings, unwind tables) is data that a rewrite
must leave alone: a data word can look exactly like a PAC instruction.
"""
import bisect
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from insn import KEEP, PATCH, TRAP, rewrite  # noqa: E402

MAGIC = b"dyld_v1  arm64e\0"
VM_PROT_EXECUTE = 4
LC_SEGMENT_64 = 0x19
CODE_SECTION = 0x80000000 | 0x00000400
ZERO_FILL = (0x1, 0xC, 0x12)


class CacheFile:
    def __init__(self, path):
        self.path = path
        self.data = memoryview(path.read_bytes())
        if bytes(self.data[:16]) != MAGIC:
            raise ValueError(f"{path}: not an arm64e dyld shared cache file")
        offset, count = struct.unpack_from("<II", self.data, 0x10)
        # (address, size, file offset, max protection, initial protection)
        self.mappings = [struct.unpack_from("<QQQII", self.data, offset + 32 * i) for i in range(count)]


class Cache:
    def __init__(self, directory):
        main = Path(directory) / "dyld_shared_cache_arm64e"
        self.files = [CacheFile(main)]
        for path in sorted(Path(directory).glob("dyld_shared_cache_arm64e.*")):
            if path.suffix in (".symbols", ".atlas", ".map") or path.name.endswith(".dylddata") and False:
                continue
            try:
                self.files.append(CacheFile(path))
            except ValueError:
                continue
        self.regions = sorted((address, size, offset, prot, index)
                              for index, file in enumerate(self.files)
                              for address, size, offset, _maxprot, prot in file.mappings)
        self.starts = [region[0] for region in self.regions]
        header = self.files[0].data
        images_offset, images_count = struct.unpack_from("<II", header, 0x1C0)
        if images_offset == 0:
            images_offset, images_count = struct.unpack_from("<II", header, 0x18)
        self.images = [struct.unpack_from("<Q", header, images_offset + 32 * i)[0] for i in range(images_count)]

    def locate(self, address):
        """(file index, file offset, bytes left in the mapping, protection) of a cache address."""
        i = bisect.bisect_right(self.starts, address) - 1
        if i < 0:
            return None
        start, size, offset, prot, index = self.regions[i]
        if address >= start + size:
            return None
        return index, offset + (address - start), start + size - address, prot

    def code_ranges(self):
        """{file index: sorted [(file offset, end)]} of the instruction sections of every image."""
        ranges = {}
        for image in self.images:
            where = self.locate(image)
            if where is None:
                raise ValueError(f"image header {image:#x} is in no mapping")
            index, offset, _left, _prot = where
            data = self.files[index].data
            magic, _cpu, _sub, _type, ncmds, _size = struct.unpack_from("<IiiIII", data, offset)
            if magic != 0xFEEDFACF:
                raise ValueError(f"image at {image:#x} has no Mach-O header")
            command = offset + 32
            for _ in range(ncmds):
                cmd, cmdsize = struct.unpack_from("<II", data, command)
                if cmd == LC_SEGMENT_64:
                    nsects, = struct.unpack_from("<I", data, command + 64)
                    for s in range(nsects):
                        section = command + 72 + 80 * s
                        address, size = struct.unpack_from("<QQ", data, section + 32)
                        flags, = struct.unpack_from("<I", data, section + 64)
                        if not flags & CODE_SECTION or flags & 0xFF in ZERO_FILL or size == 0:
                            continue
                        place = self.locate(address)
                        if place is None or place[2] < size or not place[3] & VM_PROT_EXECUTE:
                            raise ValueError(f"code section at {address:#x} of image {image:#x} is not in an executable mapping")
                        ranges.setdefault(place[0], []).append((place[1], place[1] + size))
                command += cmdsize
        return {index: merge(sorted(found)) for index, found in ranges.items()}


def merge(ranges):
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def count(data, start, end):
    patched = trapped = 0
    words = struct.unpack_from(f"<{(end - start) // 4}I", data, start)
    for word in words:
        # the families all have one of five top bytes; skip the rest quickly
        if word >> 24 in (0xD6, 0xD7, 0xDA, 0x9A, 0xF8, 0x1E):
            status, _ = rewrite(word)
            patched += status == PATCH
            trapped += status == TRAP
    return patched, trapped


def scan(directory):
    cache = Cache(directory)
    ranges = cache.code_ranges()
    total = {"code": 0, "patched": 0, "trapped": 0, "exec": 0, "data_hits": 0, "ranges": 0}
    for index, file in enumerate(cache.files):
        executable = [(offset, offset + size) for _address, size, offset, _maxprot, prot in file.mappings
                      if prot & VM_PROT_EXECUTE]
        code = ranges.get(index, [])
        for start, end in code:
            patched, trapped = count(file.data, start, end)
            total["code"] += end - start
            total["patched"] += patched
            total["trapped"] += trapped
        total["ranges"] += len(code)
        for start, end in executable:
            total["exec"] += end - start
            # what lies between the code ranges of this mapping is data
            at = start
            for code_start, code_end in [r for r in code if r[0] < end and r[1] > start] + [(end, end)]:
                if code_start > at:
                    patched, trapped = count(file.data, at & ~3, code_start & ~3)
                    total["data_hits"] += patched + trapped
                at = max(at, code_end)
    print(f"{len(cache.files)} cache files, {len(cache.images)} images, {total['ranges']} code ranges")
    print(f"executable mappings: {total['exec']} bytes, of which code: {total['code']} bytes")
    print(f"code: {total['patched']} instructions to rewrite, {total['trapped']} left to the emulator")
    print(f"data in executable mappings: {total['data_hits']} words that look like those instructions (left alone)")
    return total


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "scan":
        sys.exit(__doc__)
    scan(sys.argv[2])
