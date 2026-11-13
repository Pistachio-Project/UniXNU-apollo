"""Compile and run test_emulate.c against the emulator of patches/xnu-12377/nopac-emulate.patch."""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PATCH = HERE.parents[1] / "patches/xnu-12377/nopac-emulate.patch"


def new_file(patch, path):
    """The contents of a file the patch adds."""
    match = re.search(rf"^\+\+\+ b/{re.escape(path)}\n@@[^\n]*\n((?:\+[^\n]*\n)+)", patch, re.M)
    return "".join(line[1:] + "\n" for line in match.group(1).splitlines())


@unittest.skipUnless(shutil.which("cc"), "needs a host C compiler")
class Emulator(unittest.TestCase):
    def test_host(self):
        patch = PATCH.read_text()
        with tempfile.TemporaryDirectory() as work:
            include = Path(work) / "arm64"
            include.mkdir()
            for name in ("nopac_emulate.c", "nopac_emulate.h"):
                (include / name).write_text(new_file(patch, f"osfmk/arm64/{name}"))
            binary = Path(work) / "test"
            subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNOPAC_HOST_TEST", "-I", work,
                            str(HERE / "test_emulate.c"), str(include / "nopac_emulate.c"), "-lm", "-o", str(binary)],
                           check=True)
            self.assertEqual(subprocess.run([str(binary)], capture_output=True, text=True, check=True).stdout, "ok\n")


if __name__ == "__main__":
    unittest.main()
