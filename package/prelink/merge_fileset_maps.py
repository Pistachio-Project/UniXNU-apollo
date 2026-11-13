#!/usr/bin/env python3
"""Pair the original kernel of a kernel collection with the native kernel through several naming references.

    merge_fileset_maps.py --kit DIR --kernelcache FILE --native FILE --reference FILE [--reference FILE ...] --output MAP

UniXNU's matcher (kits/XnuPrelink/fileset_match.py) takes one symbol-bearing reference kernel. Two are available here
and each names functions the other cannot:

  1. Apple's own kernel of the same XNU from the Kernel Debug Kit (scripts/fetch-kdk-kernel.sh): the same code as the
     stripped kernel in the collection, so what it names is named by identity. It is a macOS kernel, and the
     functions an iOS kernel has beyond it stay unnamed.
  2. UniXNU's RELEASE build of its own source (scripts/build-fileset-release-reference.py): it has those functions,
     but built on Linux with upstream clang its code is shaped differently from Apple's and matches less of it.

The matcher runs once per reference, unchanged. The first reference's pairing is kept whole; a later one adds the
original functions and data the earlier ones left unpaired, unless the native address it proposes is already taken.
The result has the format and signature of a single run and is passed to emit_prelink.py with --fileset-map.
"""
import argparse
import contextlib
import hashlib
import io
import json
import sys
from collections import Counter
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--kit', required=True, type=Path, help='kits/XnuPrelink of the UniXNU checkout or build tree')
    parser.add_argument('--kernelcache', required=True, type=Path)
    parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--reference', required=True, type=Path, action='append')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.kit.resolve()))
    from fileset_match import match_images

    raw, native = args.kernelcache.read_bytes(), args.native.read_bytes()
    merged, sources = None, []
    for reference in args.reference:
        data = reference.read_bytes()
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            pairing = match_images(raw, native, reference_data=data)
        named = pairing['stats']['kext_targets_named']
        added = Counter()
        if merged is None:
            merged = pairing
        else:
            for kind in ('functions', 'data'):
                taken = {value['native'] for value in merged[kind].values()}
                for original, value in pairing[kind].items():
                    if original not in merged[kind] and value['native'] not in taken:
                        merged[kind][original] = dict(value, how=value['how'] + '+')
                        taken.add(value['native'])
                        added[kind] += 1
        sources.append({'reference': str(reference), 'sha256': hashlib.sha256(data).hexdigest(),
                        'kext_targets_named_alone': named, 'added': dict(added)})
        print(f'{reference.name}: names {named} of {pairing["stats"]["kext_targets"]} kext-facing targets alone'
              + (f', adds {added["functions"]} functions and {added["data"]} data' if len(sources) > 1 else ''))
    merged.pop('reference_sha256', None)
    merged['merged_references'] = sources
    merged['functions'] = dict(sorted(merged['functions'].items(), key=lambda item: int(item[0], 16)))
    merged['data'] = dict(sorted(merged['data'].items(), key=lambda item: int(item[0], 16)))
    merged['stats']['functions_matched'] = len(merged['functions'])
    merged['stats']['data_matched'] = len(merged['data'])
    args.output.write_text(json.dumps(merged, indent=2) + '\n')
    print(f'{args.output}: {len(merged["functions"])} functions, {len(merged["data"])} data')


if __name__ == '__main__':
    main()
