import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = ROOT / "app/src/main/assets/reverse/apk_tool"
TOOL = TOOL_DIR / "apk_tool.py"
sys.path.insert(0, str(TOOL_DIR))
from reapk import Arsc, Apk, DexFile, Manifest, disassemble, parse_axml, read_zip_entries
from reapk.dex._leb import _uleb128, enc_mutf8
from reapk.dex.file import build_return_insns
from reapk.errors import DexError, ZipError

spec = importlib.util.spec_from_file_location("source_apk_tool", TOOL)
apk_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apk_tool)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from reverse_fixtures import make_apk, make_arsc, make_dex, make_manifest, make_xref_dex


def capture(function, args):
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        function(args)
    return output.getvalue()


def entry_data_offset(data, info):
    nlen, elen = struct.unpack_from("<HH", data, info.header_offset + 26)
    return info.header_offset + 30 + nlen + elen


def assert_dex_integrity(case, data):
    case.assertEqual(len(data), struct.unpack_from("<I", data, 0x20)[0])
    case.assertEqual(data[12:32], hashlib.sha1(data[32:]).digest())
    case.assertEqual(struct.unpack_from("<I", data, 8)[0], zlib.adler32(data[12:]) & 0xFFFFFFFF)
    dex = DexFile(data)
    strings = list(dex.all_strings())
    case.assertEqual(strings, sorted(set(strings), key=lambda s: s.encode("utf-16-be", "surrogatepass")))
    data_size, data_offset = struct.unpack_from("<II", data, 0x68)
    case.assertEqual(data_size + data_offset, len(data))
    map_off = struct.unpack_from("<I", data, 0x34)[0]
    count = struct.unpack_from("<I", data, map_off)[0]
    case.assertLessEqual(map_off + 4 + count * 12, len(data))


class TemporaryApkTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="apk-tool-tests-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def put(self, name, data):
        path = self.directory / name
        path.write_bytes(data)
        return str(path)


class ManifestTests(unittest.TestCase):
    def test_false_overwrites_existing_true_and_roundtrips(self):
        manifest = Manifest(make_manifest(True, True))
        manifest.set_debuggable(False).set_cleartext(False)
        app = parse_axml(manifest.to_bytes())["children"][0]
        self.assertEqual(app["attrs"]["debuggable"], "false")
        self.assertEqual(app["attrs"]["usesCleartextTraffic"], "false")
        self.assertFalse(manifest.debuggable)

    def test_false_adds_explicit_boolean_attributes(self):
        manifest = Manifest(make_manifest())
        manifest.set_debuggable(False).set_cleartext(False)
        app = parse_axml(manifest.to_bytes())["children"][0]
        self.assertEqual(app["attrs"], {"debuggable": "false", "usesCleartextTraffic": "false"})

    def test_default_true_stays_supported(self):
        manifest = Manifest(make_manifest(False, False))
        manifest.set_debuggable().set_cleartext()
        self.assertTrue(manifest.debuggable)
        self.assertEqual(parse_axml(manifest.to_bytes())["children"][0]["attrs"]["usesCleartextTraffic"], "true")


class ResourceTests(unittest.TestCase):
    def test_entry_key_is_independent_of_dense_sparse_or_offset16_resource_index(self):
        for mode in ("dense", "sparse", "offset16"):
            with self.subTest(mode=mode):
                arsc = Arsc(make_arsc(mode))
                self.assertEqual(arsc.names[0x7F010000], "string/second")
                self.assertEqual(arsc.names[0x7F010003], "string/first")
                self.assertEqual(arsc.resolve(0x7F010000), "one")
                self.assertEqual(arsc.resolve(0x7F010003), "two")


class RebuildTests(TemporaryApkTest):
    def signed_input(self):
        return make_apk(extra_entries=[
            ("lib/arm64-v8a/libapp.so", b"native library", zipfile.ZIP_STORED),
            ("lib/x86_64/libother.so", b"compressed library", zipfile.ZIP_DEFLATED),
            ("assets/packed.bin", b"compress me" * 100, zipfile.ZIP_DEFLATED),
            ("resources.arsc", make_arsc(), zipfile.ZIP_STORED),
            ("assets/empty", b"", zipfile.ZIP_STORED),
            ("META-INF/LICENSE.txt", b"license", zipfile.ZIP_DEFLATED),
            ("META-INF/services/CERT.RSA", b"service", zipfile.ZIP_DEFLATED),
        ], signatures=True)

    def assert_unsigned_aligned(self, data):
        self.assertNotIn(b"APK Sig Block 42", data)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            self.assertIsNone(zf.testzip())
            for name in ("META-INF/MANIFEST.MF", "META-INF/CERT.SF", "META-INF/CERT.RSA",
                         "meta-inf/old.dsa", "META-INF/CERT.EC", "META-INF/SIG-CUSTOM"):
                self.assertNotIn(name, zf.namelist())
            for info in zf.infolist():
                if info.compress_type == zipfile.ZIP_STORED:
                    alignment = 16384 if info.filename.endswith(".so") else 4
                    self.assertEqual(entry_data_offset(data, info) % alignment, 0, info.filename)

    def test_rebuild_without_manifest_edits_is_unsigned_aligned_and_preserves_raw_entries(self):
        original = self.signed_input()
        result = Apk.from_bytes(original).to_bytes()
        self.assert_unsigned_aligned(result)
        before = {e["name"]: e for e in read_zip_entries(original)}
        after = {e["name"]: e for e in read_zip_entries(result)}
        with zipfile.ZipFile(io.BytesIO(original)) as zin, zipfile.ZipFile(io.BytesIO(result)) as zout:
            self.assertEqual(zin.comment, zout.comment)
            for info in zout.infolist():
                old = zin.getinfo(info.filename)
                self.assertEqual(zin.read(old), zout.read(info))
                self.assertEqual(before[info.filename.encode()]["raw"], after[info.filename.encode()]["raw"])
                self.assertEqual(info.compress_type, old.compress_type)
                self.assertEqual(info.date_time, old.date_time)
                self.assertEqual(info.comment, old.comment)
                self.assertEqual(info.extra, old.extra)
                self.assertEqual(info.external_attr, old.external_attr)

    def test_dirty_manifest_uses_the_same_unsigned_alignment_path(self):
        apk = Apk.from_bytes(self.signed_input())
        apk.manifest.set_debuggable(False)
        self.assert_unsigned_aligned(apk.to_bytes())

    def test_repeated_replace_cli_keeps_compression_and_unmodified_payloads(self):
        original = self.signed_input()
        src = self.put("in.apk", original)
        out = str(self.directory / "out.apk")
        native = self.put("new.so", b"replacement native code")
        packed = self.put("packed.bin", b"replacement packed content" * 20)
        capture(apk_tool.cmd_rebuild, [src, out, "--replace", "lib/arm64-v8a/libapp.so=" + native,
                                       "--replace", "assets/packed.bin=" + packed])
        result = Path(out).read_bytes()
        self.assert_unsigned_aligned(result)
        before = {e["name"]: e for e in read_zip_entries(original)}
        after = {e["name"]: e for e in read_zip_entries(result)}
        with zipfile.ZipFile(io.BytesIO(result)) as zf:
            self.assertEqual(zf.read("lib/arm64-v8a/libapp.so"), Path(native).read_bytes())
            self.assertEqual(zf.read("assets/packed.bin"), Path(packed).read_bytes())
            self.assertEqual(zf.getinfo("assets/packed.bin").compress_type, zipfile.ZIP_DEFLATED)
            self.assertEqual(zf.getinfo("lib/arm64-v8a/libapp.so").compress_type, zipfile.ZIP_STORED)
            for name in (b"resources.arsc", b"META-INF/LICENSE.txt", b"lib/x86_64/libother.so"):
                self.assertEqual(before[name]["raw"], after[name]["raw"])

    def test_replace_validation_does_not_write_output(self):
        src = self.put("in.apk", self.signed_input())
        out = self.put("out.apk", b"existing output")
        replacement = self.put("new.so", b"new")
        bad_options = [
            ["--replace", "missing.so=" + replacement],
            ["--replace", "lib/arm64-v8a/libapp.so=" + str(self.directory / "missing")],
            ["--replace", "lib/arm64-v8a/libapp.so=" + str(self.directory)],
            ["--replace", "lib/arm64-v8a/libapp.so"],
            ["--replace"],
            ["--unknown", "lib/arm64-v8a/libapp.so=" + replacement],
            ["--replace", "lib/arm64-v8a/libapp.so=" + replacement,
             "--replace", "lib/arm64-v8a/libapp.so=" + replacement],
        ]
        for options in bad_options:
            with self.subTest(options=options):
                with self.assertRaises((SystemExit, ValueError, ZipError)):
                    capture(apk_tool.cmd_rebuild, [src, out] + options)
                self.assertEqual(Path(out).read_bytes(), b"existing output")

    def test_streaming_zip_descriptors_are_removed_without_recompressing_payloads(self):
        original = make_apk(extra_entries=[
            ("lib/arm64-v8a/libapp.so", b"native code", zipfile.ZIP_STORED),
            ("assets/compressed", b"streaming payload" * 40, zipfile.ZIP_DEFLATED),
        ], streaming=True, signatures=True, comment=b"streaming zip comment")
        with zipfile.ZipFile(io.BytesIO(original)) as zf:
            self.assertTrue(all(i.flag_bits & 8 for i in zf.infolist()))
        result = Apk.from_bytes(original).to_bytes()
        self.assert_unsigned_aligned(result)
        with zipfile.ZipFile(io.BytesIO(result)) as zf:
            self.assertTrue(all(not i.flag_bits & 8 for i in zf.infolist()))
            self.assertEqual(zf.comment, b"streaming zip comment")
        self.assertEqual(result, Apk.from_bytes(result).to_bytes())

    def test_reader_ignores_an_eocd_marker_inside_the_zip_comment(self):
        entries = read_zip_entries(make_apk(comment=b"inside PK\x05\x06 zip comment"))
        self.assertEqual([e["name"] for e in entries], [b"AndroidManifest.xml"])

    def test_unicode_member_and_container_path_with_equals_are_replaced(self):
        src = self.put("in.apk", make_apk(extra_entries=[("assets/会员.txt", b"old", zipfile.ZIP_DEFLATED)]))
        replacement = self.put("content=new.bin", "新内容".encode("utf-8"))
        out = str(self.directory / "out.apk")
        capture(apk_tool.cmd_rebuild, [src, out, "--replace=assets/会员.txt=" + replacement])
        with zipfile.ZipFile(out) as zf:
            self.assertEqual(zf.read("assets/会员.txt"), "新内容".encode("utf-8"))

    def test_replacing_a_signature_entry_is_rejected_instead_of_silently_discarded(self):
        with self.assertRaises((ValueError, ZipError)):
            Apk.from_bytes(self.signed_input()).to_bytes(replacements={"META-INF/CERT.RSA": b"new"})

    def test_api_rejects_a_replacement_for_a_missing_entry(self):
        with self.assertRaises((ValueError, ZipError)):
            Apk.from_bytes(self.signed_input()).to_bytes(replacements={"missing.so": b"new"})

    def test_reader_rejects_truncated_central_directory_instead_of_dropping_entries(self):
        data = bytearray(make_apk())
        eocd = data.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", data, eocd + 8, 2, 2)
        with self.assertRaises(ZipError):
            read_zip_entries(bytes(data))


class XrefTests(TemporaryApkTest):
    def setUp(self):
        super().setUp()
        self.dex = DexFile(make_xref_dex())
        self.apk = self.put("xref.apk", make_apk(dex=self.dex.d))

    def test_method_and_field_indexes_include_the_owner(self):
        method_indexes = apk_tool._xref_method_index(self.dex, "Lfixture/A;", "foo")
        self.assertEqual({self.dex.method_ref(i) for i in method_indexes}, {
            ("Lfixture/A;", "foo", "()V"), ("Lfixture/A;", "foo", "(I)V"),
        })
        field_indexes = apk_tool._xref_field_index(self.dex, "Lfixture/A;", "value")
        self.assertEqual({self.dex.field_ref(i) for i in field_indexes}, {
            ("Lfixture/A;", "value", "I"), ("Lfixture/A;", "value", "J"),
        })

    def test_method_signature_and_field_type_filter_cli_hits(self):
        text = capture(apk_tool.cmd_dex_xref, [self.apk, "method", "Lfixture/A;->foo()V"])
        self.assertIn("命中 1 处", text)
        self.assertNotIn("→ Lfixture/B;", text)
        self.assertNotIn("→ Lfixture/A;->foo(I)V", text)
        text = capture(apk_tool.cmd_dex_xref, [self.apk, "field", "Lfixture/A;->value:J"])
        self.assertIn("命中 1 处", text)
        self.assertNotIn("→ Lfixture/B;", text)
        self.assertNotIn("→ Lfixture/A;->value:I", text)

    def test_missing_signature_has_no_hits(self):
        with self.assertRaises(SystemExit):
            capture(apk_tool.cmd_dex_xref, [self.apk, "method", "Lfixture/A;->foo(J)V"])

    def test_owner_normalization_and_type_xrefs_remain_supported(self):
        text = capture(apk_tool.cmd_dex_xref, [self.apk, "method", "fixture.A->foo"])
        self.assertIn("命中 2 处", text)
        text = capture(apk_tool.cmd_dex_xref, [self.apk, "type", "fixture.A"])
        self.assertIn("命中 1 处", text)


class ReturnTests(TemporaryApkTest):
    def test_return_kinds_and_wide_values_have_correct_opcodes(self):
        cases = [
            ("V", "void", 0, [0x000E]),
            ("I", "true", 1, [0x1012, 0x000F]),
            ("Z", "false", 1, [0x0012, 0x000F]),
            ("Ljava/lang/Object;", "null", 1, [0x0012, 0x0011]),
            ("[I", "null", 1, [0x0012, 0x0011]),
            ("J", "true", 2, [0x0016, 1, 0x0010]),
            ("J", "false", 2, [0x0016, 0, 0x0010]),
            ("D", "true", 2, [0x0019, 0x3FF0, 0x0010]),
            ("D", "false", 2, [0x0016, 0, 0x0010]),
            ("F", "true", 1, [0x0015, 0x3F80, 0x000F]),
        ]
        for ret, value, regs, words in cases:
            with self.subTest(ret=ret, value=value, regs=regs):
                self.assertEqual(build_return_insns(ret, value, regs), words)

    def test_invalid_type_value_pairs_and_register_counts_are_rejected(self):
        cases = [("I", "void", 1), ("I", "null", 1), ("V", "true", 0),
                 ("V", "null", 0), ("[I", "true", 1), ("Ljava/lang/Object;", "false", 1),
                 ("I", "true", 0), ("J", "false", 1), ("D", "true", 1),
                 ("I", "maybe", 1), ("Q", "false", 1), ("[V", "null", 1),
                 ("V", "void", -1), ("I", "true", 65536)]
        for ret, value, regs in cases:
            with self.subTest(ret=ret, value=value, regs=regs):
                with self.assertRaises(DexError):
                    build_return_insns(ret, value, regs)

    def test_wide_patch_roundtrips_through_the_existing_disassembler(self):
        dex = DexFile(make_dex(methods=[{"owner": "Lfixture/A;", "name": "wide", "ret": "J"}]))
        method = dex.find_method("Lfixture/A;", "wide")
        dex.patch_return(method["code_off"], "J", "true")
        result = dex.finalize()
        _, lines = disassemble(DexFile(result), method["code_off"])
        self.assertTrue(any("const-wide/16" in line for line in lines))
        self.assertTrue(any("return-wide v0" in line for line in lines))
        assert_dex_integrity(self, result)

    def test_invalid_cli_return_keeps_the_original_apk(self):
        data = make_apk(dex=make_dex(methods=[{"owner": "Lfixture/A;", "name": "number", "ret": "I"}]))
        path = self.put("return.apk", data)
        with self.assertRaises(DexError):
            capture(apk_tool.cmd_dex_return, [path, "Lfixture/A;", "number", "null"])
        self.assertEqual(Path(path).read_bytes(), data)

    def test_too_small_method_and_ins_larger_than_registers_are_rejected(self):
        dex = DexFile(make_dex(methods=[{"owner": "Lfixture/A;", "name": "number", "ret": "I"}]))
        method = dex.find_method("Lfixture/A;", "number")
        co = method["code_off"]
        before = dex.d
        with self.assertRaises(DexError):
            dex.patch_return(co, "D", "true")
        self.assertEqual(dex.d, before)
        bad = bytearray(before)
        struct.pack_into("<HH", bad, co, 1, 2)
        dex = DexFile(bytes(bad))
        with self.assertRaises(DexError):
            dex.patch_return(co, "I", "true")
        self.assertEqual(dex.d, bytes(bad))

    def test_constructor_patch_is_a_structural_test_only(self):
        dex = DexFile(make_dex(methods=[{"owner": "Lfixture/A;", "name": "<init>",
                                        "access": 0x10001, "regs": 1}]))
        method = dex.find_method("Lfixture/A;", "<init>")
        dex.patch_return(method["code_off"], "V", "void")
        info = dex.code_insns(method["code_off"])
        self.assertEqual(struct.unpack_from("<H", dex.d, info["insns_off"])[0], 0x000E)
        assert_dex_integrity(self, dex.finalize())


class StringEditTests(TemporaryApkTest):
    def fixture(self):
        return make_apk(dex=make_dex(strings=["premium", "paid", "peach", "会员", "\0x", "😀"], methods=[
            {"owner": "Lfixture/A;", "name": "run", "body": [
                'const-string v0, "premium"', 'const-string v1, "paid"', "return-void",
            ]},
            {"owner": "Lfixture/A;", "name": "premium", "ret": "I"},
        ], fields=[("Lfixture/A;", "premium", "I")], metadata_string="premium"), extra_entries=[
            ("lib/arm64-v8a/libapp.so", b"keep native", zipfile.ZIP_STORED),
            ("assets/raw.bin", b"keep compression" * 50, zipfile.ZIP_DEFLATED),
        ], signatures=True)

    def test_shortening_pads_once_then_rebuilds_a_sorted_unique_pool_and_remaps_references(self):
        original = self.fixture()
        src = self.put("in.apk", original)
        out = str(self.directory / "edited.apk")
        rebuild_inputs = []
        rebuild = apk_tool.build_dex

        def inspect_rebuild(dex, *args, **kwargs):
            rebuild_inputs.append((len(dex.d), struct.unpack_from("<I", dex.d, 0x20)[0]))
            return rebuild(dex, *args, **kwargs)

        with mock.patch.object(apk_tool, "build_dex", side_effect=inspect_rebuild):
            count = apk_tool._patch_string_in_dexes(src, "premium", "paid", out)
        self.assertEqual(count, 1)
        self.assertTrue(rebuild_inputs)
        self.assertTrue(all(actual == header for actual, header in rebuild_inputs))
        result = Path(out).read_bytes()
        with zipfile.ZipFile(io.BytesIO(result)) as zf:
            data = zf.read("classes.dex")
            self.assertEqual(zf.read("lib/arm64-v8a/libapp.so"), b"keep native")
            self.assertEqual(entry_data_offset(result, zf.getinfo("lib/arm64-v8a/libapp.so")) % 16384, 0)
        assert_dex_integrity(self, data)
        dex = DexFile(data)
        self.assertNotIn("premium", list(dex.all_strings()))
        self.assertEqual(list(dex.all_strings()).count("paid"), 1)
        self.assertIsNotNone(dex.find_method("Lfixture/A;", "paid"))
        self.assertIn(("Lfixture/A;", "paid", "I"), {dex.field_ref(i) for i in range(dex.n_field)})
        method = dex.find_method("Lfixture/A;", "run")
        _, lines = disassemble(dex, method["code_off"])
        self.assertEqual(sum('"paid"' in line for line in lines), 2)
        source_idx = struct.unpack_from("<I", data, dex.off_class + 16)[0]
        self.assertEqual(dex.string(source_idx), "paid")
        sv = struct.unpack_from("<I", data, dex.off_class + 28)[0]
        size, p = _uleb128(data, sv)
        self.assertEqual(size, 1)
        width = (data[p] >> 5) + 1
        self.assertEqual(dex.string(int.from_bytes(data[p + 1:p + 1 + width], "little")), "paid")
        before = {e["name"]: e for e in read_zip_entries(original)}
        after = {e["name"]: e for e in read_zip_entries(result)}
        self.assertEqual(before[b"assets/raw.bin"]["raw"], after[b"assets/raw.bin"]["raw"])
        self.assertNotIn(b"APK Sig Block 42", result)

    def test_debug_and_annotation_string_references_follow_the_sorted_pool(self):
        src = self.put("in.apk", self.fixture())
        out = str(self.directory / "out.apk")
        self.assertEqual(apk_tool._patch_string_in_dexes(src, "premium", "alpha", out), 1)
        with zipfile.ZipFile(out) as zf:
            data = zf.read("classes.dex")
        assert_dex_integrity(self, data)
        dex = DexFile(data)
        co = dex.find_method("Lfixture/A;", "run")["code_off"]
        debug = struct.unpack_from("<I", data, co + 8)[0]
        _, p = _uleb128(data, debug)
        _, p = _uleb128(data, p)
        self.assertEqual(data[p], 3)
        _, p = _uleb128(data, p + 1)
        name, p = _uleb128(data, p)
        typ, p = _uleb128(data, p)
        self.assertEqual(dex.string(name - 1), "alpha")
        self.assertEqual(dex.type(typ - 1), "Ljava/lang/String;")
        self.assertEqual(data[p], 9)
        source, p = _uleb128(data, p + 1)
        self.assertEqual(dex.string(source - 1), "alpha")
        directory = struct.unpack_from("<I", data, dex.off_class + 20)[0]
        annotations = struct.unpack_from("<I", data, directory)[0]
        annotation = struct.unpack_from("<I", data, annotations + 4)[0]
        tidx, p = _uleb128(data, annotation + 1)
        self.assertEqual(dex.type(tidx), "Lfixture/Annotation;")
        count, p = _uleb128(data, p)
        self.assertEqual(count, 1)
        name, p = _uleb128(data, p)
        self.assertEqual(dex.string(name), "value")
        width = (data[p] >> 5) + 1
        self.assertEqual(dex.string(int.from_bytes(data[p + 1:p + 1 + width], "little")), "alpha")

    def test_multiple_dex_replacements_leave_the_untouched_dex_compressed_bytes_intact(self):
        src_bytes = make_apk(dex=make_dex(strings=["premium", "paid"]), extra_entries=[
            ("classes2.dex", make_dex(strings=["premium"]), zipfile.ZIP_STORED),
            ("classes3.dex", make_dex(strings=["untouched"]), zipfile.ZIP_DEFLATED),
        ])
        src = self.put("in.apk", src_bytes)
        out = str(self.directory / "out.apk")
        self.assertEqual(apk_tool._patch_string_in_dexes(src, "premium", "paid", out), 2)
        with zipfile.ZipFile(out) as zf:
            for name in ("classes.dex", "classes2.dex"):
                data = zf.read(name)
                assert_dex_integrity(self, data)
                self.assertEqual(list(DexFile(data).all_strings()), ["paid"])
        before = {e["name"]: e for e in read_zip_entries(src_bytes)}
        after = {e["name"]: e for e in read_zip_entries(Path(out).read_bytes())}
        self.assertEqual(before[b"classes3.dex"]["raw"], after[b"classes3.dex"]["raw"])

    def test_no_hits_neither_creates_output_nor_overwrites_existing_output(self):
        src = self.put("in.apk", self.fixture())
        out = str(self.directory / "new.apk")
        self.assertEqual(apk_tool._patch_string_in_dexes(src, "absent", "a", out), 0)
        self.assertFalse(Path(out).exists())
        self.put("new.apk", b"existing output")
        self.assertEqual(apk_tool._patch_string_in_dexes(src, "absent", "a", out), 0)
        self.assertEqual(Path(out).read_bytes(), b"existing output")
        self.assertFalse(Path(out + ".tmp").exists())

    def test_cli_no_hits_does_not_create_an_output_directory(self):
        src = self.put("in.apk", self.fixture())
        out = self.directory / "not-created" / "out.apk"
        with self.assertRaises(SystemExit):
            capture(apk_tool.cmd_dex_string_edit, [src, "absent", "a", str(out)])
        self.assertFalse(out.parent.exists())

    def test_longer_mutf8_is_rejected_without_output(self):
        src = self.put("in.apk", self.fixture())
        out = str(self.directory / "new.apk")
        with self.assertRaises(SystemExit):
            capture(apk_tool.cmd_dex_string_edit, [src, "paid", "longer string", out])
        self.assertFalse(Path(out).exists())

    def test_mutf8_nul_and_surrogate_pairs_can_be_shortened(self):
        for old, new in (("会员", "会"), ("\0x", "\0"), ("😀", "a")):
            with self.subTest(old=old):
                src = self.put("in.apk", make_apk(dex=make_dex(strings=[old, new])))
                out = str(self.directory / "new.apk")
                self.assertLessEqual(len(enc_mutf8(new)), len(enc_mutf8(old)))
                self.assertEqual(apk_tool._patch_string_in_dexes(src, old, new, out), 1)
                with zipfile.ZipFile(out) as zf:
                    data = zf.read("classes.dex")
                assert_dex_integrity(self, data)
                self.assertEqual(list(DexFile(data).all_strings()), [new])


class SourceAndFastScanTests(TemporaryApkTest):
    def test_script_uses_its_own_reapk_without_a_live_tool_installation(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        env.pop("PYTHONPATH", None)
        probe = "import runpy; runpy.run_path(%r); import reapk; print(reapk.__file__)" % str(TOOL)
        completed = subprocess.run([sys.executable, "-c", probe], cwd=self.directory, env=env,
                                   capture_output=True, text=True, check=True)
        self.assertEqual(Path(completed.stdout.strip()).resolve(), (TOOL_DIR / "reapk/__init__.py").resolve())

    def test_fast_scan_reports_utf8_utf16_chinese_and_dex_hits_as_file_offsets(self):
        utf8 = "会员VIP".encode("utf-8")
        utf16 = "会员Vip".encode("utf-16-le")
        path = self.put("scan.apk", make_apk(dex=make_dex(strings=["会员优惠"]), extra_entries=[
            ("lib/arm64-v8a/libapp.so", b"\0" * 11 + utf8 + b"\0" * 7 + utf16, zipfile.ZIP_STORED),
        ]))
        self.assertIn("fast-scan", apk_tool.COMMANDS)
        text = capture(apk_tool.COMMANDS["fast-scan"][0], [path, "会员,vip"])
        self.assertIn("UTF-8", text)
        self.assertIn("UTF-16LE", text)
        self.assertIn("文件偏移", text)
        self.assertIn("非函数", text)
        self.assertIn("classes.dex", text)
        self.assertRegex(text, r"@0x0*[Bb]\b")
        self.assertRegex(text, r"@0x0*%X\b" % (11 + len(utf8) + 7))

    def test_utf16_chinese_is_not_corrupted_by_ascii_lowercasing_of_encoded_bytes(self):
        path = self.put("scan.apk", make_apk(extra_entries=[
            ("lib/arm64-v8a/libapp.so", "会员vip".encode("utf-16-le"), zipfile.ZIP_STORED),
        ]))
        text = capture(apk_tool.COMMANDS["fast-scan"][0], [path, "会员,vip"])
        self.assertIn("[会员] 1 处", text)
        self.assertIn("[vip] 1 处", text)
        self.assertNotIn("UTF-8 @", text)

    def test_fast_scan_keeps_native_hits_when_another_dex_is_malformed(self):
        path = self.put("scan.apk", make_apk(dex=make_dex(strings=["会员"]), extra_entries=[
            ("classes2.dex", b"not a dex", zipfile.ZIP_STORED),
        ]))
        text = capture(apk_tool.COMMANDS["fast-scan"][0], [path, "会员"])
        self.assertIn("classes2.dex", text)
        self.assertIn("跳过", text)
        self.assertIn("classes.dex 字符串", text)

    def test_fast_scan_reports_output_truncation_and_does_not_infer_server_logic(self):
        path = self.put("scan.apk", make_apk(extra_entries=[
            ("lib/x86_64/libapp.so", b"vip\0" * 25, zipfile.ZIP_STORED),
        ]))
        self.assertIn("fast-scan", apk_tool.COMMANDS)
        text = capture(apk_tool.COMMANDS["fast-scan"][0], [path, "vip"])
        self.assertIn("25", text)
        self.assertIn("仅显示前", text)
        self.assertLessEqual(text.count("@0x"), apk_tool.MAX_KW_HITS)
        text = capture(apk_tool.COMMANDS["fast-scan"][0], [path, "nothing"])
        self.assertIn("未命中", text)
        self.assertNotIn("服务端", text)


if __name__ == "__main__":
    unittest.main()
