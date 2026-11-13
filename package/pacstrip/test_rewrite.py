"""The kernel's page rewriter (patches/xnu-12377/nopac-user-text.patch, osfmk/arm64/nopac_rewrite.c) against insn.py."""
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from insn import PATCH, rewrite
from test_emulate import new_file

HERE = Path(__file__).resolve().parent
PATCH_FILE = HERE.parents[1] / "patches/xnu-12377/nopac-user-text.patch"
MAIN = r"""
#include <stdio.h>
#include <arm64/nopac_rewrite.h>
int main(void) {
	uint32_t words[4096]; size_t count;
	while ((count = fread(words, 4, 4096, stdin)) > 0) {
		nopac_rewrite_words(words, count);
		fwrite(words, 4, count, stdout);
	}
	return 0;
}
"""


def words_to_test():
    """Random words, and for every rewritten family every value of its variable bits around random bases."""
    rng = random.Random(27)
    words = [rng.getrandbits(32) for _ in range(200000)]
    families = (0xD65F0BFF, 0xD69F0BFF, 0xD71F0800, 0xD61F081F, 0xD73F0800, 0xD63F081F, 0xDAC10000, 0x9AC03000,
                0xF8200400, 0x1E7E0000, 0xD503201F)
    for base in families:
        for _ in range(60000):
            words.append(base ^ rng.getrandbits(32) & rng.choice((0xFFFF, 0x1FFFFF, 0xFFFFFF, 0x3FF, 0xFFF)))
    return words


@unittest.skipUnless(shutil.which("cc"), "needs a host C compiler")
class Rewriter(unittest.TestCase):
    def test_same_as_python(self):
        patch = PATCH_FILE.read_text()
        words = words_to_test()
        with tempfile.TemporaryDirectory() as work:
            include = Path(work) / "arm64"
            include.mkdir()
            for name in ("nopac_rewrite.c", "nopac_rewrite.h"):
                (include / name).write_text(new_file(patch, f"osfmk/arm64/{name}"))
            (Path(work) / "main.c").write_text(MAIN)
            binary = Path(work) / "rewrite"
            subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-I", work, str(Path(work) / "main.c"),
                            str(include / "nopac_rewrite.c"), "-o", str(binary)], check=True)
            out = subprocess.run([str(binary)], input=struct.pack(f"<{len(words)}I", *words), capture_output=True,
                                 check=True).stdout
        got = struct.unpack(f"<{len(words)}I", out)
        changed = 0
        for word, result in zip(words, got):
            status, expected = rewrite(word)
            expected = expected if status == PATCH else word
            self.assertEqual(result, expected, f"{word:#010x}: C {result:#010x}, Python {expected:#010x}")
            changed += result != word
        self.assertGreater(changed, 100000)


if __name__ == "__main__":
    unittest.main()
