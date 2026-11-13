#!/usr/bin/env python3
"""Decrypt an AEA disk image of an IPSW (OS, Cryptex1,SystemOS) on Linux.

    scripts/aea-decrypt.py IMAGE.dmg.aea [OUTPUT]      (default OUTPUT: IMAGE.dmg beside it)

UniXNU's own flow decrypts these with macOS /usr/bin/aea. Here package/aea/aea-decrypt.c does it with OpenSSL: this
script builds it once (cc, libcrypto, the lzfse library of the UniXNU Linux toolchain), reads the archive's
com.apple.wkms.fcs-response and fetches the private key Apple publishes at its com.apple.wkms.fcs-key-url, which
opens the archive key. Nothing but that one key URL is contacted, and nothing about this machine is sent.
"""
import base64
import json
import os
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

DEVICE = Path(__file__).resolve().parents[1]
SOURCE = DEVICE / 'package/aea'
TOOL = DEVICE / '.cache/toolchain/bin/aea-decrypt'
TOOLCHAIN = Path(os.environ.get('UNIXNU_TOOLCHAIN', '/opt/unixnu-linux'))


def build():
    sources = [SOURCE / 'aea-decrypt.c', SOURCE / 'libzbitmap.c']
    if TOOL.is_file() and all(TOOL.stat().st_mtime >= s.stat().st_mtime for s in sources):
        return
    TOOL.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['cc', '-std=gnu2x', '-O2', '-Wall', '-Wextra', f'-I{TOOLCHAIN / "include"}', '-o', str(TOOL),
                    *map(str, sources), str(TOOLCHAIN / 'lib/liblzfse.a'), '-lcrypto'], check=True)


def metadata(path):
    """The key/value auth data of the archive."""
    with open(path, 'rb') as stream:
        magic, profile, size = struct.unpack('<4sII', stream.read(12))
        if magic != b'AEA1' or profile & 0xffffff != 1 or size > 16 << 20:
            sys.exit(f'{path}: not an AEA archive of profile 1')
        data = stream.read(size)
    values, at = {}, 0
    while at < len(data):
        length, = struct.unpack_from('<I', data, at)
        key, _, value = data[at + 4:at + length].partition(b'\0')
        values[key.decode()] = value
        at += length
    return values


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    source = Path(sys.argv[1])
    output = Path(sys.argv[2]) if len(sys.argv) == 3 else source.with_suffix('')
    build()
    values = metadata(source)
    if 'encryption_key' in values:
        key_arguments = ['--key', values['encryption_key'].decode()]
        subprocess.run([str(TOOL), str(source), str(output) + '.partial', *key_arguments], check=True)
    else:
        try:
            response = json.loads(values['com.apple.wkms.fcs-response'])
            url = values['com.apple.wkms.fcs-key-url'].decode()
        except KeyError as missing:
            sys.exit(f'{source}: no {missing} in the archive')
        if not url.startswith('https://'):
            sys.exit(f'{source}: unexpected key URL {url}')
        with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'aea-decrypt'}), timeout=60) as reply:
            pem = reply.read()
        with tempfile.NamedTemporaryFile(suffix='.pem') as key_file:
            key_file.write(pem)
            key_file.flush()
            subprocess.run([str(TOOL), str(source), str(output) + '.partial', '--pem', key_file.name,
                            '--enc-request', base64.b64decode(response['enc-request']).hex(),
                            '--wrapped-key', base64.b64decode(response['wrapped-key']).hex()], check=True)
    os.replace(str(output) + '.partial', output)
    print(output)


if __name__ == '__main__':
    main()
