#!/usr/bin/env python3

import ast
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "app/src/main/assets/aicode/bin/aicode-blutter"
COMPLETED_MARKER = ".aicode-blutter-completed"
EXIT_MARKER = ".aicode-blutter-exitcode"


class BlutterCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="aicode-blutter-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.out = self.root / "out"
        self.out.mkdir()
        self.toolchain = self.root / "flutter-re"
        self.invocations = self.root / "invocations"
        self.source = CLI.read_text(encoding="utf-8")
        self.script = self.root / "aicode-blutter"
        self.script.write_text(
            self.source.replace(
                "RE=/root/flutter-re", "RE=" + shlex.quote(str(self.toolchain))
            ).replace("/root/out", str(self.out)),
            encoding="utf-8",
        )
        self.env = os.environ.copy()
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.env["PYTHONIOENCODING"] = "utf-8"
        self.env["TEST_INVOCATIONS"] = str(self.invocations)
        dependencies = self.root / "dependencies"
        dependencies.mkdir()
        (dependencies / "elftools.py").write_text("", encoding="utf-8")
        self.env["PYTHONPATH"] = str(dependencies)
        commands = self.root / "bin"
        commands.mkdir()
        for name in ("cmake", "ninja"):
            path = commands / name
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(0o700)
        self.env["PATH"] = str(commands) + os.pathsep + self.env.get("PATH", os.defpath)
        blutter = self.toolchain / "blutter"
        blutter.mkdir(parents=True)
        (blutter / "blutter.py").write_text(
            "import os, sys\n"
            "from pathlib import Path\n"
            "counter = Path(os.environ['TEST_INVOCATIONS'])\n"
            "with counter.open('a', encoding='utf-8') as stream:\n"
            "    stream.write('run\\n')\n"
            "out = Path(sys.argv[2])\n"
            "mode = os.environ.get('TEST_PRODUCTS', 'valid')\n"
            "if mode != 'empty':\n"
            "    (out / 'asm' / 'package').mkdir(parents=True, exist_ok=True)\n"
            "    (out / 'pp.txt').write_text('pool\\n', encoding='utf-8')\n"
            "    (out / 'objs.txt').write_text('objects\\n', encoding='utf-8')\n"
            "    if mode == 's':\n"
            "        (out / 'asm' / 'package' / 'code.S').write_text('ret\\n')\n"
            "    else:\n"
            "        (out / 'asm' / 'package' / 'code.dart').write_text(\n"
            "            '// ** addr: 0x10\\nret\\n', encoding='utf-8')\n"
            "sys.exit(int(os.environ.get('TEST_EXIT', '0')))\n",
            encoding="utf-8",
        )
        (self.toolchain / "setup.sh").write_text(
            "#!/bin/sh\nexit 91\n", encoding="utf-8"
        )
        self.apk = self.root / "demo.apk"
        self.libapp = b"\x7fELF mock libapp"
        self.libflutter = b"\x7fELF mock flutter"
        with zipfile.ZipFile(self.apk, "w") as archive:
            archive.writestr("lib/arm64-v8a/libapp.so", self.libapp)
            archive.writestr("lib/arm64-v8a/libflutter.so", self.libflutter)

    def cli(self, *args):
        return subprocess.run(
            ["sh", str(self.script)] + [str(arg) for arg in args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=self.env,
            timeout=30,
        )

    def assert_success(self, result):
        self.assertEqual(
            result.returncode, 0, (result.stdout + result.stderr)[:600]
        )

    def field(self, result, name):
        match = re.search(r"\b" + re.escape(name) + r"=([^\s]+)", result.stdout)
        self.assertIsNotNone(match, "缺少输出字段 " + name)
        return match.group(1)

    def rows(self, result):
        return [
            (match.group(1), int(match.group(2)), match.group(3))
            for line in result.stdout.splitlines()
            for match in [re.match(r"^(.+):(\d+): (.*)$", line)]
            if match
        ]

    def make_file(self, relative, text):
        path = self.out / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")
        return path

    def products(self, marker=None):
        self.make_file("pp.txt", "pool\n")
        self.make_file("objs.txt", "objects\n")
        self.make_file("asm/package/code.dart", "// ** addr: 0x10\nret\n")
        self.make_file("lib/arm64-v8a/libapp.so", self.libapp)
        self.make_file("lib/arm64-v8a/libflutter.so", self.libflutter)
        if marker:
            self.make_file(marker, "completed\n" if marker == COMPLETED_MARKER else "{}")

    def snapshot(self):
        return {
            str(path.relative_to(self.out)): path.read_bytes()
            for path in self.out.rglob("*")
            if path.is_file()
        }

    def assert_friendly_error(self, *args):
        result = self.cli(*args)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue("Traceback" not in result.stdout + result.stderr)
        self.assertTrue("参数错误" in result.stdout + result.stderr)

    def test_help_and_short_help_cover_all_modes(self):
        for flag in ("--help", "-h"):
            with self.subTest(flag=flag):
                result = self.cli(flag)
                self.assert_success(result)
                for term in (
                    "--help", "-h", "--scan", "--status", "--search", "--read",
                    "limit=30", "offset=0", "per_file=3", "limit=4000", "start_line=1",
                    "200", "16000",
                ):
                    self.assertTrue(term in result.stdout, "帮助缺少 " + term)
                self.assertFalse(self.invocations.exists())

    def test_status_recursively_counts_files_and_function_markers(self):
        self.products(COMPLETED_MARKER)
        for index in range(2704):
            self.make_file(
                "asm/pkg%d/file%d.dart" % (index % 150, index),
                "// ** addr: 0x%x\n" % index,
            )
        self.make_file("asm/deep/one.S", "// ** addr: 0xa\nret\n")
        self.make_file("asm/deep/two.S", "// ** addr: 0xb\nret\n")
        result = self.cli("--status", self.out)
        self.assert_success(result)
        self.assertEqual(self.field(result, "dart_files"), "2705")
        self.assertEqual(self.field(result, "s_files"), "2")
        self.assertEqual(self.field(result, "function_markers"), "2707")
        self.assertEqual(self.field(result, "function_files"), "2707")
        self.assertEqual(self.field(result, "state"), "completed")
        self.assertFalse(self.invocations.exists())

    def test_status_lists_actual_frida_outputs(self):
        self.products()
        self.make_file("blutter_frida.js", "script\n")
        self.make_file("frida.log", "log\n")
        result = self.cli("--status", self.out)
        self.assert_success(result)
        self.assertTrue("blutter_frida.js" in result.stdout)
        self.assertTrue("frida.log" in result.stdout)
        self.assertFalse(re.search(r"^\s*frida\.js\s", result.stdout, re.M))
        self.assertEqual(self.field(result, "state"), "partial")

    def test_status_distinguishes_completed_partial_and_unknown(self):
        result = self.cli("--status", self.out)
        self.assertEqual(self.field(result, "state"), "unknown")
        self.make_file(COMPLETED_MARKER, "completed\n")
        result = self.cli("--status", self.out)
        self.assertEqual(self.field(result, "state"), "partial")
        self.products()
        result = self.cli("--status", self.out)
        self.assertEqual(self.field(result, "state"), "completed")
        self.make_file("pp.txt", "")
        result = self.cli("--status", self.out)
        self.assertEqual(self.field(result, "state"), "partial")
        self.assertEqual(self.field(result, "products_valid"), "false")

    def test_status_rejects_empty_objects_and_dart_without_functions(self):
        self.products(COMPLETED_MARKER)
        self.make_file("objs.txt", "")
        result = self.cli("--status", self.out)
        self.assertEqual(self.field(result, "products_valid"), "false")
        self.make_file("objs.txt", "objects\n")
        self.make_file("asm/package/code.dart", "class Placeholder {}\n")
        result = self.cli("--status", self.out)
        self.assertEqual(self.field(result, "products_valid"), "false")
        self.assertEqual(self.field(result, "function_markers"), "0")

    def test_status_recognizes_legacy_marker(self):
        self.products(".analyzed_meta")
        result = self.cli("--status", self.out)
        self.assert_success(result)
        self.assertEqual(self.field(result, "state"), "completed")
        self.assertTrue(".analyzed_meta" in result.stdout)

    def test_status_invalid_completed_content_is_not_complete(self):
        self.products()
        self.make_file(COMPLETED_MARKER, "running\n")
        result = self.cli("--status", self.out)
        self.assertEqual(self.field(result, "state"), "partial")

    def test_status_accepts_output_name_or_apk_basename(self):
        directory = self.out / "demo"
        directory.mkdir()
        for value in ("demo", "demo.apk", directory):
            with self.subTest(value=value):
                result = self.cli("--status", value)
                self.assert_success(result)
                self.assertEqual(self.field(result, "state"), "unknown")

    def test_status_without_arguments_only_lists_results(self):
        (self.out / "demo").mkdir()
        result = self.cli("--status")
        self.assert_success(result)
        self.assertTrue("demo" in result.stdout)
        self.assertFalse(self.invocations.exists())

    def test_search_counts_all_matches_after_page_cap(self):
        for name in ("pp.txt", "objs.txt", "asm/a.dart", "asm/b.dart"):
            self.make_file(name, "needle\n" * 10)
        result = self.cli("--search", self.out, "needle", 2)
        self.assert_success(result)
        self.assertEqual(self.field(result, "total_hits"), "40")
        self.assertEqual(self.field(result, "scanned_files"), "4")
        self.assertEqual(self.field(result, "emitted"), "2")
        self.assertEqual(self.field(result, "truncated"), "true")
        self.assertEqual(self.field(result, "next_offset"), "2")

    def test_search_round_robin_spreads_hits_across_files(self):
        self.make_file("pp.txt", "needle\n" * 20)
        self.make_file("objs.txt", "needle\n" * 20)
        self.make_file("asm/code.dart", "needle\n" * 20)
        result = self.cli("--search", self.out, "needle", 9)
        self.assert_success(result)
        names = [Path(row[0]).name for row in self.rows(result)]
        self.assertEqual(names, ["pp.txt"] * 3 + ["objs.txt"] * 3 + ["code.dart"] * 3)

    def test_search_pagination_reaches_other_hits_in_same_file(self):
        self.make_file("asm/one.dart", "needle\n" * 17)
        seen = []
        offset = 0
        while True:
            result = self.cli("--search", self.out, "needle", 4, offset, 3)
            self.assert_success(result)
            seen.extend(row[1] for row in self.rows(result))
            next_offset = self.field(result, "next_offset")
            if next_offset == "none":
                self.assertEqual(self.field(result, "truncated"), "false")
                break
            self.assertGreater(int(next_offset), offset)
            offset = int(next_offset)
        self.assertEqual(seen, list(range(1, 18)))

    def test_search_pages_preserve_round_robin_and_result_priority(self):
        for name, count in (("pp.txt", 6), ("objs.txt", 2), ("asm/code.dart", 4), ("0.json", 3)):
            self.make_file(name, "needle\n" * count)
        expected = [
            ("pp.txt", 1), ("pp.txt", 2), ("objs.txt", 1), ("objs.txt", 2),
            ("code.dart", 1), ("code.dart", 2), ("pp.txt", 3), ("pp.txt", 4),
            ("code.dart", 3), ("code.dart", 4), ("pp.txt", 5), ("pp.txt", 6),
            ("0.json", 1), ("0.json", 2), ("0.json", 3),
        ]
        seen = []
        offset = 0
        while True:
            result = self.cli("--search", self.out, "needle", 5, offset, 2)
            self.assert_success(result)
            self.assertEqual(self.field(result, "total_hits"), "15")
            seen.extend((Path(row[0]).name, row[1]) for row in self.rows(result))
            next_offset = self.field(result, "next_offset")
            if next_offset == "none":
                break
            self.assertGreater(int(next_offset), offset)
            offset = int(next_offset)
        self.assertEqual(seen, expected)

    def test_search_prioritizes_real_outputs_over_javascript_and_json(self):
        self.make_file("0_telemetry.json", "needle\n" * 600)
        self.make_file("0_script.js", "needle\n" * 600)
        self.make_file("pp.txt", "needle\n" * 3)
        self.make_file("objs.txt", "needle\n")
        self.make_file("asm/framework/code.dart", "needle\n" * 4)
        result = self.cli("--search", self.out, "needle", 8)
        self.assert_success(result)
        self.assertEqual(self.field(result, "total_hits"), "1208")
        self.assertFalse(any(row[0].endswith((".js", ".json")) for row in self.rows(result)))
        self.assertEqual(len(self.rows(result)), 8)

    def test_search_includes_ad_helper_framework_and_precise_subdirectory(self):
        self.make_file("asm/ad_helper/code.dart", "Needle\n")
        self.make_file("asm/flutter/framework.dart", "needle\n")
        result = self.cli("--search", self.out, "needle")
        self.assert_success(result)
        self.assertEqual(self.field(result, "total_hits"), "2")
        self.assertEqual(len(self.rows(result)), 2)
        result = self.cli("--search", self.out / "asm/ad_helper", "needle")
        self.assert_success(result)
        self.assertEqual(self.field(result, "total_hits"), "1")
        self.assertEqual(self.field(result, "scanned_files"), "1")

    def test_search_hard_caps_requested_match_count(self):
        self.make_file("asm/code.dart", "needle\n" * 500)
        result = self.cli("--search", self.out, "needle", 999999)
        self.assert_success(result)
        self.assertEqual(len(self.rows(result)), 200)
        self.assertEqual(self.field(result, "limit"), "200")
        self.assertEqual(self.field(result, "next_offset"), "200")
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 16000)

    def test_search_caps_utf8_output_and_pages_without_skipping(self):
        directory = "/".join(["路径" * 30] * 8)
        self.make_file("asm/" + directory + "/code.dart", ("needle " + "中文" * 1000 + "\n") * 400)
        result = self.cli("--search", self.out, "needle", 200)
        self.assert_success(result)
        rows = self.rows(result)
        self.assertGreater(len(rows), 0)
        self.assertLess(len(rows), 200)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 16000)
        self.assertTrue(all(len((row[0] + row[2]).encode("utf-8")) <= 600 for row in rows))
        self.assertEqual(int(self.field(result, "next_offset")), len(rows))
        self.assertEqual(self.field(result, "total_hits"), "400")
        next_result = self.cli("--search", self.out, "needle", 200, len(rows))
        self.assert_success(next_result)
        self.assertEqual(self.rows(next_result)[0][1], len(rows) + 1)
        self.assertTrue("�" not in result.stdout + next_result.stdout)

    def test_search_offset_beyond_total_is_empty_not_false_zero(self):
        self.make_file("pp.txt", "needle\n" * 7)
        result = self.cli("--search", self.out, "needle", 30, 1000000000)
        self.assert_success(result)
        self.assertEqual(self.field(result, "total_hits"), "7")
        self.assertEqual(self.field(result, "emitted"), "0")
        self.assertEqual(self.field(result, "next_offset"), "none")
        self.assertEqual(self.field(result, "truncated"), "false")

    def test_search_bad_regex_and_integers_are_friendly(self):
        self.make_file("pp.txt", "needle\n")
        for args in (("[",), ("needle", "bad"), ("needle", "0"), ("needle", "3", "-1"), ("needle", "3", "0", "0")):
            with self.subTest(args=args):
                self.assert_friendly_error("--search", self.out, *args)

    def test_read_supports_start_line_and_reports_characters_and_lines(self):
        path = self.make_file("pp.txt", "一\n二\n三\n四\n五\n六\n")
        result = self.cli("--read", path, 4, 4)
        self.assert_success(result)
        self.assertTrue("四\n五\n" in result.stdout)
        self.assertTrue("一\n" not in result.stdout)
        self.assertEqual(self.field(result, "start_line"), "4")
        self.assertEqual(self.field(result, "end_line"), "5")
        self.assertEqual(self.field(result, "chars"), "4")
        self.assertEqual(self.field(result, "next_line"), "6")
        self.assertEqual(self.field(result, "next_char"), "0")

    def test_read_default_character_limit(self):
        path = self.make_file("pp.txt", "x" * 8000)
        result = self.cli("--read", path)
        self.assert_success(result)
        self.assertEqual(self.field(result, "chars"), "4000")
        self.assertEqual(self.field(result, "truncated"), "true")
        self.assertEqual(self.field(result, "next_line"), "1")
        self.assertEqual(self.field(result, "next_char"), "4000")
        self.assertTrue("x" * 4001 not in result.stdout)

    def test_read_caps_utf8_and_reports_partial_line(self):
        path = self.make_file("pp.txt", "中文" * 20000 + "\nTAIL\n")
        result = self.cli("--read", path, 999999, 1)
        self.assert_success(result)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 16000)
        self.assertLessEqual(int(self.field(result, "chars")), 16000)
        self.assertEqual(self.field(result, "truncated"), "true")
        self.assertEqual(self.field(result, "next_line"), "1")
        self.assertGreater(int(self.field(result, "next_char")), 0)
        self.assertTrue("TAIL" not in result.stdout)
        self.assertTrue("�" not in result.stdout)

    def test_read_character_cursor_advancesThroughLongLine(self):
        path = self.make_file("pp.txt", "abcdefghijklmnop\nNEXT\n")
        first = self.cli("--read", path, 5, 1, 0)
        self.assert_success(first)
        self.assertTrue("abcde" in first.stdout)
        self.assertEqual(self.field(first, "next_line"), "1")
        self.assertEqual(self.field(first, "next_char"), "5")
        second = self.cli("--read", path, 5, 1, 5)
        self.assert_success(second)
        self.assertTrue("fghij" in second.stdout)
        self.assertEqual(self.field(second, "next_char"), "10")
        third = self.cli("--read", path, 7, 1, 10)
        self.assert_success(third)
        self.assertTrue("klmnop\n" in third.stdout)
        self.assertEqual(self.field(third, "next_line"), "2")
        self.assertEqual(self.field(third, "next_char"), "0")
        fourth = self.cli("--read", path, 5, 2, 0)
        self.assert_success(fourth)
        self.assertTrue("NEXT\n" in fourth.stdout)
        self.assertEqual(self.field(fourth, "truncated"), "false")

    def test_read_start_after_eof(self):
        path = self.make_file("pp.txt", "one\ntwo\n")
        result = self.cli("--read", path, 4000, 20)
        self.assert_success(result)
        self.assertEqual(self.field(result, "chars"), "0")
        self.assertEqual(self.field(result, "truncated"), "false")

    def test_read_bad_integers_are_friendly(self):
        path = self.make_file("pp.txt", "text\n")
        for args in (("bad",), ("0",), ("3", "0"), ("3", "wrong"),
                     ("3", "1", "-1"), ("3", "1", "wrong"), ("3", "1", "0", "extra")):
            with self.subTest(args=args):
                self.assert_friendly_error("--read", path, *args)

    def test_diagnostic_modes_do_not_write_or_start_analysis(self):
        self.products(COMPLETED_MARKER)
        before = self.snapshot()
        for args in (("--help",), ("--status", self.out), ("--search", self.out, "pool"), ("--read", self.out / "pp.txt")):
            self.assert_success(self.cli(*args))
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.invocations.exists())

    def test_python_readers_do_not_load_whole_files(self):
        blocks = re.findall(r"<<'PYEOF'\n(.*?)\nPYEOF", self.source, re.S)
        self.assertGreater(len(blocks), 0)
        for block in blocks:
            tree = ast.parse(block)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    self.assertFalse(node.func.attr in ("readlines", "splitlines"))
                    if node.func.attr == "read":
                        self.assertGreater(len(node.args), 0, "禁止无界 read()")

    def test_scan_still_accepts_an_explicit_apk(self):
        with zipfile.ZipFile(self.apk, "w") as archive:
            archive.writestr("assets/flutter_assets/test", "asset")
            archive.writestr("lib/arm64-v8a/libapp.so", b"\x7fELF")
            archive.writestr("lib/arm64-v8a/libflutter.so", b"\x7fELF")
        result = self.cli("--scan", self.apk)
        self.assert_success(result)
        self.assertTrue("Flutter 应用" in result.stdout)
        self.assertFalse(self.invocations.exists())

    def test_run_mock_writes_completed_and_exit_markers_after_valid_products(self):
        result = self.cli(self.apk, self.out)
        self.assert_success(result)
        self.assertEqual((self.out / COMPLETED_MARKER).read_text(), "completed\n")
        self.assertEqual((self.out / EXIT_MARKER).read_text(), "0\n")
        self.assertEqual(self.invocations.read_text(), "run\n")

    def test_run_zero_exit_cannot_claim_stale_products_as_new_results(self):
        self.products()
        self.make_file("pp.txt", "previous pool\n")
        self.env["TEST_PRODUCTS"] = "empty"
        result = self.cli(self.apk, self.out)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.out / COMPLETED_MARKER).exists())
        self.assertEqual((self.out / "pp.txt").read_text(), "previous pool\n")

    def test_run_persists_library_identity_for_following_cache_reuse(self):
        self.assert_success(self.cli(self.apk, self.out))
        result = self.cli(self.apk, self.out)
        self.assert_success(result)
        self.assertTrue("现有输出" in result.stdout)
        self.assertEqual(self.invocations.read_text(), "run\n")
        self.assertEqual((self.out / "lib/arm64-v8a/libapp.so").read_bytes(), self.libapp)
        self.assertEqual((self.out / "lib/arm64-v8a/libflutter.so").read_bytes(), self.libflutter)

    def test_failed_run_preserves_previous_products(self):
        self.products()
        self.make_file("pp.txt", "previous pool\n")
        self.env["TEST_EXIT"] = "7"
        result = self.cli(self.apk, self.out)
        self.assertEqual(result.returncode, 7)
        self.assertEqual((self.out / "pp.txt").read_text(), "previous pool\n")
        self.assertFalse((self.out / COMPLETED_MARKER).exists())

    def test_run_mock_zero_exit_without_products_is_not_complete(self):
        self.env["TEST_PRODUCTS"] = "empty"
        result = self.cli(self.apk, self.out)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.out / COMPLETED_MARKER).exists())
        self.assertEqual((self.out / EXIT_MARKER).read_text(), "0\n")

    def test_run_mock_nonzero_exit_never_marks_complete(self):
        self.env["TEST_EXIT"] = "7"
        result = self.cli(self.apk, self.out)
        self.assertEqual(result.returncode, 7)
        self.assertFalse((self.out / COMPLETED_MARKER).exists())
        self.assertEqual((self.out / EXIT_MARKER).read_text(), "7\n")

    def test_run_reuses_completed_or_legacy_results_without_mutation(self):
        for marker in (COMPLETED_MARKER, ".analyzed_meta"):
            with self.subTest(marker=marker):
                self.products(marker)
                before = self.snapshot()
                result = self.cli(self.apk, self.out)
                self.assert_success(result)
                self.assertTrue("现有输出" in result.stdout)
                self.assertFalse(self.invocations.exists())
                self.assertEqual(self.snapshot(), before)

    def test_run_reuse_checks_both_so_sizes_and_checksums(self):
        self.products(COMPLETED_MARKER)
        with zipfile.ZipFile(self.apk, "w") as archive:
            archive.writestr("lib/arm64-v8a/libapp.so", self.libapp)
            archive.writestr("lib/arm64-v8a/libflutter.so", b"X" * len(self.libflutter))
        result = self.cli(self.apk, self.out)
        self.assert_success(result)
        self.assertEqual(self.invocations.read_text(), "run\n")
        self.assertTrue("现有输出" not in result.stdout)

    def test_run_reuse_rejects_missing_or_wrong_size_so(self):
        self.products(COMPLETED_MARKER)
        self.make_file("lib/arm64-v8a/libapp.so", b"short")
        result = self.cli(self.apk, self.out)
        self.assert_success(result)
        self.assertEqual(self.invocations.read_text(), "run\n")

    def test_run_failure_invalidates_stale_completion_markers(self):
        self.products(COMPLETED_MARKER)
        self.make_file(".analyzed_meta", "{}")
        self.make_file("lib/arm64-v8a/libapp.so", b"changed")
        self.env["TEST_EXIT"] = "7"
        result = self.cli(self.apk, self.out)
        self.assertEqual(result.returncode, 7)
        self.assertFalse((self.out / COMPLETED_MARKER).exists())
        self.assertFalse((self.out / ".analyzed_meta").exists())
        self.assertEqual((self.out / EXIT_MARKER).read_text(), "7\n")

    def test_run_can_reuse_without_toolchain(self):
        self.products(COMPLETED_MARKER)
        blutter = self.toolchain / "blutter/blutter.py"
        blutter.rename(blutter.with_suffix(".unavailable"))
        result = self.cli(self.apk, self.out)
        self.assert_success(result)
        self.assertFalse(self.invocations.exists())

    def test_run_keeps_default_apk_output_name(self):
        result = self.cli(self.apk)
        self.assert_success(result)
        self.assertEqual((self.out / "demo" / COMPLETED_MARKER).read_text(), "completed\n")

    def test_run_mock_accepts_nonempty_s_without_dart_markers(self):
        self.env["TEST_PRODUCTS"] = "s"
        result = self.cli(self.apk, self.out)
        self.assert_success(result)
        self.assertEqual((self.out / COMPLETED_MARKER).read_text(), "completed\n")
        status = self.cli("--status", self.out)
        self.assertEqual(self.field(status, "state"), "completed")
        self.assertEqual(self.field(status, "function_markers"), "0")
        self.assertEqual(self.field(status, "nonempty_s_files"), "1")

    def test_read_skips_a_very_long_line_without_losing_line_numbers(self):
        path = self.make_file("pp.txt", "长" * 100000 + "\nTARGET\nEND\n")
        result = self.cli("--read", path, 7, 2)
        self.assert_success(result)
        self.assertTrue("TARGET\n" in result.stdout)
        self.assertTrue("长" not in result.stdout)
        self.assertEqual(self.field(result, "next_line"), "3")

    def test_bad_argument_counts_and_oversized_offsets_are_friendly(self):
        path = self.make_file("pp.txt", "text\n")
        for args in (
            ("--read",), ("--read", path, 1, 1, "extra"),
            ("--read", path, 1, "9" * 100),
            ("--search", self.out), ("--search", self.out, "text", 1, 0, 3, "extra"),
            ("--search", self.out, "text", 1, "9" * 100),
            ("--status", self.out, "extra"), ("--scan", self.apk, "extra"),
        ):
            with self.subTest(args=args):
                self.assert_friendly_error(*args)

    def test_unknown_mode_is_a_friendly_error_not_an_apk(self):
        self.assert_friendly_error("--unknown")
        self.assertFalse(self.invocations.exists())

    def test_shell_syntax(self):
        result = subprocess.run(["sh", "-n", str(CLI)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
