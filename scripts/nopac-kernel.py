#!/usr/bin/env python3
"""Rewrite the built kernel for apollo's CPUs, which have no pointer authentication.

    scripts/nopac-kernel.py [--unixnu DIR] [--kernel FILE] [--kernel-args "ARGS"]

Run it after "./unixnu build kernel" (or "./unixnu prelink") and before "./unixnu payload". It works on
out/apollo/<os>/apollo/kernel/kernel.macho of the UniXNU checkout:

  1. keeps the arm64e kernel as it was linked beside it (kernel.macho.arm64e);
  2. rewrites every code section of the kernel and of each prelinked kext with package/pacstrip (PAC*, AUT*, XPAC* to
     NOP, authenticated branches and loads to their plain forms, PACGA to a deterministic EOR);
  3. stores the integrity HMAC of Apple's corecrypto kext again and seals the source corecrypto again: the power-on
     self-test of each hashes its own code;
  4. records what it did in kernel.nopac.json.

A kernel that is already rewritten is left alone.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

DEVICE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEVICE / 'package/pacstrip'))
from macho import strip  # noqa: E402


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def executable_leftovers(data):
    """PAC instructions still present in any section of an executable segment, by "segment,section" (independent of
    the section attributes the rewrite itself goes by). Hint-space forms are not counted: they execute as NOP."""
    import struct
    from insn import KEEP, rewrite
    left = {}

    def image(header, base):
        offset = header + 32
        for _ in range(struct.unpack_from('<I', data, header + 16)[0]):
            command, size = struct.unpack_from('<II', data, offset)
            if command == 0x19:
                segment = bytes(data[offset + 8:offset + 24]).rstrip(b'\0').decode()
                maxprot, initprot, count = struct.unpack_from('<iiI', data, offset + 56)
                if (maxprot | initprot) & 4 and count == 0 and segment != '__TEXT':
                    # a kernel collection's own executable segment: no sections, all code
                    start, length = struct.unpack_from('<QQ', data, offset + 40)
                    found = sum(rewrite(word)[0] != KEEP for (word,) in
                                struct.iter_unpack('<I', bytes(data[base + start:base + start + (length & ~3)])))
                    if found:
                        left[segment] = left.get(segment, 0) + found
                for index in range(count if (maxprot | initprot) & 4 else 0):
                    section = offset + 72 + 80 * index
                    name = bytes(data[section:section + 16]).rstrip(b'\0').decode()
                    length, start = struct.unpack_from('<QI', data, section + 40)
                    kind = struct.unpack_from('<I', data, section + 64)[0] & 0xFF
                    if not start or kind in (0x1, 0xC, 0x12) or segment == '__TEXT':
                        continue
                    found = sum(rewrite(word)[0] != KEEP for (word,) in
                                struct.iter_unpack('<I', bytes(data[base + start:base + start + (length & ~3)])))
                    if found:
                        left[f'{segment},{name}'] = left.get(f'{segment},{name}', 0) + found
            elif command == 0x80000035:
                image(struct.unpack_from('<Q', data, offset + 16)[0], 0)
            offset += size

    image(0, 0)
    return left


def match_kernel_subtype(data):
    """Give com.apple.kernel the CPU subtype of the collection it sits in; returns (old, new) when it changed.

    Apple's linker marks an arm64e kernel 0xC0000002 (versioned pointer authentication ABI, kernel ABI bit); upstream
    clang and cctools-port's ld64 have no option for the kernel bit and write 0x80000002. DarwinBoot refuses a
    collection whose kernel member differs from the collection header ("Load error")."""
    import struct
    if struct.unpack_from('<I', data, 12)[0] != 12:
        return None
    offset = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, offset)
        if command == 0x80000035:
            name = offset + struct.unpack_from('<I', data, offset + 24)[0]
            if bytes(data[name:data.index(b'\0', name)]) == b'com.apple.kernel':
                header = struct.unpack_from('<Q', data, offset + 16)[0]
                old, new = struct.unpack_from('<I', data, header + 8)[0], struct.unpack_from('<I', data, 8)[0]
                if old != new and old & 0x00ffffff == new & 0x00ffffff:
                    struct.pack_into('<I', data, header + 8, new)
                    return old, new
        offset += size
    return None


def reseal_original_corecrypto(data):
    """Store the integrity HMAC of each prelinked kext that carries one (com.apple.kec.corecrypto) again.

    corecrypto's power-on self-test (fipspost_get_hmac) computes HMAC-SHA256 with a one-byte zero key over the first
    __text section of the kext's __TEXT/__TEXT_EXEC and compares it with the value in __TEXT,__fips_hmacs; the
    rewrite changed that section, and a mismatch panics ("FIPS Kernel POST Failed (-2074)"). The kernel's own value
    is UniXNU's seal-source-crypto-kernel.py's business. Returns the kexts whose value changed."""
    import hmac
    import struct
    if struct.unpack_from('<I', data, 12)[0] != 12:
        return []
    top, entries, offset = [], [], 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, offset)
        if command == 0x19:
            top.append(struct.unpack_from('<QQQ', data, offset + 24))
        elif command == 0x80000035:
            name = offset + struct.unpack_from('<I', data, offset + 24)[0]
            entries.append((bytes(data[name:data.index(b'\0', name)]).decode(),
                            struct.unpack_from('<Q', data, offset + 16)[0]))
        offset += size

    def file_offset(address):
        return next(start + address - base for base, length, start in top if base <= address < base + length)

    changed = []
    for name, header in entries:
        if name == 'com.apple.kernel':
            continue
        text = stored = None
        offset = header + 32
        for _ in range(struct.unpack_from('<I', data, header + 16)[0]):
            command, size = struct.unpack_from('<II', data, offset)
            if command == 0x19:
                segment = bytes(data[offset + 8:offset + 24]).rstrip(b'\0')
                for index in range(struct.unpack_from('<I', data, offset + 64)[0]):
                    section = offset + 72 + 80 * index
                    section_name = bytes(data[section:section + 16]).rstrip(b'\0')
                    address, length = struct.unpack_from('<QQ', data, section + 32)
                    if section_name == b'__text' and segment in (b'__TEXT', b'__TEXT_EXEC') and text is None:
                        text = (file_offset(address), length)
                    elif section_name == b'__fips_hmacs' and length == 32:
                        stored = file_offset(address)
            offset += size
        if text is None or stored is None:
            continue
        digest = hmac.new(b'\0', bytes(data[text[0]:text[0] + text[1]]), hashlib.sha256).digest()
        if bytes(data[stored:stored + 32]) != digest:
            data[stored:stored + 32] = digest
            changed.append(name)
    return changed


def main():
    board = tomllib.loads((DEVICE / 'board.toml').read_text())
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--unixnu', type=Path, default=DEVICE / board['package']['unixnu'])
    parser.add_argument('--kernel', type=Path)
    parser.add_argument('--kernel-args', default=' '.join(board['payload'].get('kernel_args', [])))
    args = parser.parse_args()
    unixnu = args.unixnu.resolve()
    name, profile = board['board']['name'], board['board']['os_profile']
    work = unixnu / 'out' / name / profile / name
    kernel = (args.kernel or work / 'kernel/kernel.macho').resolve()
    data = bytearray(kernel.read_bytes())
    original = hashlib.sha256(data).hexdigest()
    subtype = match_kernel_subtype(data)
    report = strip(data)
    if report.traps:
        # In the kernel these would trap at EL1 on every execution; the emulator handles them, but name them.
        print(f'nopac-kernel: {len(report.traps)} instructions are left to the kernel emulator', file=sys.stderr)
    record_path = kernel.with_name('kernel.nopac.json')
    if report.patched == 0 and subtype is None and not reseal_original_corecrypto(bytearray(data)):
        print(f'nopac-kernel: {kernel} has no pointer authentication instructions left')
        return
    resealed = reseal_original_corecrypto(data)
    left = executable_leftovers(data)
    if left:
        sys.exit(f'nopac-kernel: pointer authentication instructions left in executable segments: {left}')
    if report.patched:   # not when only a header field or an HMAC was brought up to date
        shutil.copyfile(kernel, kernel.with_name(kernel.name + '.arm64e'))
    kernel.write_bytes(data)
    sealed = False
    if b'_source_corecrypto14_bootstrap\0' in data:
        os_profile = tomllib.loads((unixnu / 'profiles/os' / profile / 'profile.toml').read_text())['os']
        env = dict(os.environ, UNIXNU_XNU_ARCH=os_profile.get('arch', 'arm64'), UNIXNU_IOS_VERSION=os_profile['ios_version'])
        subprocess.run([sys.executable, work / 'tree/scripts/seal-source-crypto-kernel.py', kernel,
                        '--kernel-args', args.kernel_args], cwd=work / 'tree', env=env, check=True)
        sealed = True
    record = {'kernel': str(kernel), 'arm64e_sha256': original, 'sha256': sha256(kernel), 'rewritten': report.patched,
              'emulated': [f'{offset:#x} {word:#010x}' for offset, word in report.traps], 'source_crypto_sealed': sealed,
              'kernel_subtype': [hex(value) for value in subtype] if subtype else None,
              'kext_integrity_hmac_stored_again': resealed}
    record_path.write_text(json.dumps(record, indent=2) + '\n')
    print(f'nopac-kernel: {report.patched} instructions rewritten, sealed again: {sealed}, sha256 {record["sha256"]}')


if __name__ == '__main__':
    main()
