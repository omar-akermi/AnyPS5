import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "configure_seed.py"
sys.path.insert(0, str(TOOL.parent))

import configure_seed

PROJECT = """cmake_minimum_required(VERSION 3.20)
project(mini C)
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckCSourceCompiles)
include(CheckTypeSize)
check_include_file(stdio.h MINI_HAVE_STDIO_H)
check_include_file(mini_missing_header.h MINI_HAVE_MISSING_H)
check_symbol_exists(printf stdio.h MINI_HAVE_PRINTF)
check_c_source_compiles("int main(void) { return 0; }" MINI_COMPILES)
check_c_source_compiles("int main(void) { return undefined_name; }" MINI_FAILS)
check_type_size(long MINI_LONG_BYTES)
check_type_size("struct mini_missing_type" MINI_MISSING_BYTES)
configure_file(sizes.h.in sizes.h @ONLY)
set(MINI_OPTION "value" CACHE STRING "An option, not a check result")
"""


@unittest.skipUnless(shutil.which("ninja") and (shutil.which("gcc") or shutil.which("cc")), "needs ninja and a C compiler")
class ConfigureSeedTests(unittest.TestCase):
    def test_check_names_with_spaces_round_trip_through_cmake(self):
        cache = self.root / "named-check.txt"
        cache.write_text('//Test HAVE FEATURE\nHAVE FEATURE:INTERNAL=1\n', encoding="utf-8")
        output = self.configure("named-check", "-C", str(self.seed(cache, "named-check.cmake")))
        self.assertNotRegex(output, r"CMake Error")
        seeded = self.root / "named-check" / "CMakeCache.txt"
        self.assertEqual(configure_seed.checks(seeded)["HAVE FEATURE"][0], "1")
        self.assertNotIn("HAVE:INTERNAL=", seeded.read_text(encoding="utf-8"))

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        (cls.root / "source").mkdir()
        (cls.root / "source" / "CMakeLists.txt").write_text(PROJECT, encoding="utf-8")
        (cls.root / "source" / "sizes.h.in").write_text("@MINI_LONG_BYTES_CODE@\n@MINI_MISSING_BYTES_CODE@\n", encoding="utf-8")
        cls.compiler = shutil.which("gcc") or shutil.which("cc")
        cls.fresh = cls.configure("fresh")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    @classmethod
    def configure(cls, name, *extra):
        return subprocess.run(["cmake", *extra, "-S", str(cls.root / "source"), "-B", str(cls.root / name), "-G", "Ninja",
                               f"-DCMAKE_C_COMPILER={cls.compiler}"], check=True, capture_output=True, text=True).stdout

    def seed(self, cache, name):
        seed = self.root / name
        subprocess.run([sys.executable, str(TOOL), str(cache), str(seed)], check=True, capture_output=True)
        return seed

    def test_seeded_configure_runs_no_check_and_gets_the_same_results(self):
        self.assertRegex(self.fresh, r"Looking for|Performing Test")
        output = self.configure("seeded", "-C", str(self.seed(self.root / "fresh" / "CMakeCache.txt", "seed.cmake")))
        self.assertNotRegex(output, r"Looking for|Performing Test|Check size of")
        fresh = configure_seed.checks(self.root / "fresh" / "CMakeCache.txt")
        self.assertEqual(configure_seed.checks(self.root / "seeded" / "CMakeCache.txt"), fresh)
        self.assertEqual(fresh["MINI_HAVE_STDIO_H"][0], "1")
        self.assertEqual(fresh["MINI_FAILS"][0], "")
        self.assertEqual((self.root / "seeded" / "sizes.h").read_text(), (self.root / "fresh" / "sizes.h").read_text())
        self.assertGreater(int(fresh["MINI_LONG_BYTES"][0]), 0)
        self.assertEqual(fresh["MINI_MISSING_BYTES"][0], "")

    def test_only_check_results_are_seeded(self):
        found = configure_seed.checks(self.root / "fresh" / "CMakeCache.txt")
        self.assertEqual({n for n in found if n.startswith("MINI_")},
                         {"MINI_HAVE_STDIO_H", "MINI_HAVE_MISSING_H", "MINI_HAVE_PRINTF", "MINI_COMPILES", "MINI_FAILS",
                          "MINI_LONG_BYTES", "MINI_MISSING_BYTES"})
        self.assertNotIn("CMAKE_C_COMPILER", found)

    def test_values_with_cmake_syntax_round_trip(self):
        cache = self.root / "odd" / "CMakeCache.txt"
        cache.parent.mkdir()
        value = r'a;b "c" \d ${e} $f'
        cache.write_text(f"//Test MINI_ODD\nMINI_ODD:INTERNAL={value}\n", encoding="utf-8")
        self.configure("odd-seeded", "-C", str(self.seed(cache, "odd.cmake")))
        seeded = (self.root / "odd-seeded" / "CMakeCache.txt").read_text(encoding="utf-8")
        self.assertIn(f"MINI_ODD:INTERNAL={value}\n", seeded)
        self.assertEqual(configure_seed.checks(self.root / "odd-seeded" / "CMakeCache.txt")["MINI_ODD"][0], value)

    def test_cache_without_checks_writes_an_empty_seed(self):
        cache = self.root / "empty" / "CMakeCache.txt"
        cache.parent.mkdir()
        cache.write_text("//Path to a program.\nCMAKE_AR:FILEPATH=/usr/bin/ar\n", encoding="utf-8")
        self.assertEqual(self.seed(cache, "empty.cmake").read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
