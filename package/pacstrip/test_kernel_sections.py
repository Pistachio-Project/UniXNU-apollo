"""Which sections of a kernel image the rewrite treats as code (macho.code_sections)."""
import struct
import unittest

from macho import strip

RETAB, RET = 0xD65F0FFF, 0xD65F03C0
MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, LC_SEGMENT_64 = 0xFEEDFACF, 0x0100000C, 2, 0x19
PURE_INSTRUCTIONS, S_ZEROFILL = 0x80000000, 0x1


def image(*segments):
    """A Mach-O of single-section segments: (segname, sectname, initprot, section flags, words)."""
    commands_size = len(segments) * (72 + 80)
    offset = 32 + commands_size
    commands, body, offsets = b"", b"", []
    for segname, sectname, prot, flags, words in segments:
        data = struct.pack(f"<{len(words)}I", *words)
        commands += struct.pack("<II16sQQQQiiII", LC_SEGMENT_64, 72 + 80, segname, 0, len(data), offset, len(data),
                                prot, prot, 1, 0)
        commands += struct.pack("<16s16sQQIIIIIIII", sectname, segname, 0, len(data), offset, 2, 0, 0, flags, 0, 0, 0)
        offsets.append(offset)
        offset += len(data)
        body += data
    header = struct.pack("<IiiIIIII", MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, 2, len(segments),
                         commands_size, 0, 0)
    return bytearray(header + commands + body), offsets


def word(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


class KernelSections(unittest.TestCase):
    def test_unmarked_section_of_an_executable_segment_is_code(self):
        # xnu's __KLD,__text (arm_init's rebase and sign code) has no instruction attribute
        data, (kld,) = image((b"__KLD", b"__text", 5, 0, [RETAB]))
        self.assertEqual(strip(data).patched, 1)
        self.assertEqual(word(data, kld), RET)

    def test_text_segment_keeps_its_data_sections(self):
        # a user image keeps constants and strings in its executable __TEXT
        data, (const, text) = image((b"__TEXT", b"__const", 5, 0, [RETAB]),
                                    (b"__TEXT", b"__text", 5, PURE_INSTRUCTIONS, [RETAB]))
        self.assertEqual(strip(data).patched, 1)
        self.assertEqual((word(data, const), word(data, text)), (RETAB, RET))

    def test_data_segments_are_left_alone(self):
        data, (const,) = image((b"__DATA_CONST", b"__const", 3, 0, [RETAB]))
        self.assertEqual(strip(data).patched, 0)
        self.assertEqual(word(data, const), RETAB)

    def test_zero_fill_has_no_file_contents(self):
        data, (last,) = image((b"__LAST", b"__last", 5, S_ZEROFILL, [RETAB]))
        self.assertEqual(strip(data).patched, 0)
        self.assertEqual(word(data, last), RETAB)


if __name__ == "__main__":
    unittest.main()
