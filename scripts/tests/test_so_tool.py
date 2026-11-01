import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "app/src/main/assets/reverse/so_tool/so_tool.py"
spec = importlib.util.spec_from_file_location("so_tool", SOURCE)
so = importlib.util.module_from_spec(spec)
sys.modules["so_tool"] = so
spec.loader.exec_module(so)
patch = types.ModuleType("patch_so_test")
override = os.environ.get("SO_PATCH_SOURCE")
patch_path = Path(override) if override else None
if patch_path is not None and patch_path.is_file():
    patch_source = patch_path.read_text()
    patch_label = str(patch_path)
else:
    archive_path = ROOT / "app/src/main/assets/reverse/flutter-re.tar"
    with tarfile.open(archive_path) as archive:
        member = next(m for m in archive.getmembers() if m.name.endswith("/patch_so.py") or m.name == "patch_so.py")
        patch_source = archive.extractfile(member).read().decode()
    patch_label = str(archive_path) + "!" + member.name
exec(compile(patch_source, patch_label, "exec"), patch.__dict__)


def make_elf(path, machine=183, bits=64, endian="<", etype=3, payload=None,
             nobits=False, segments_only=False):
    payload = payload or bytes.fromhex("1f2003d5c0035fd6") * 8
    base, fileoff, namesoff, shoff = 0x1000, 0x200, 0x400, 0x500
    names = b"\0.text\0.bss\0.shstrtab\0"
    data = bytearray(0x700)
    ident = b"\x7fELF" + bytes((2 if bits == 64 else 1, 1 if endian == "<" else 2, 1, 0)) + bytes(8)
    count = 0 if segments_only else 4
    if bits == 64:
        struct.pack_into(endian + "16sHHIQQQIHHHHHH", data, 0, ident, etype, machine, 1,
                         base, 64, shoff if count else 0, 0, 64, 56, 1, 64, count, 3 if count else 0)
        struct.pack_into(endian + "IIQQQQQQ", data, 64, 1, 5, fileoff, base, base,
                         len(payload), len(payload) + 16, 0x100)
        sfmt = endian + "IIQQQQIIQQ"
    else:
        struct.pack_into(endian + "16sHHIIIIIHHHHHH", data, 0, ident, etype, machine, 1,
                         base, 52, shoff if count else 0, 0, 52, 32, 1, 40, count, 3 if count else 0)
        struct.pack_into(endian + "IIIIIIII", data, 52, 1, fileoff, base, base,
                         len(payload), len(payload) + 16, 5, 0x100)
        sfmt = endian + "IIIIIIIIII"
    data[fileoff:fileoff + len(payload)] = payload
    if count:
        data[namesoff:namesoff + len(names)] = names
        stride = struct.calcsize(sfmt)
        struct.pack_into(sfmt, data, shoff + stride, 1, 1, 6, base, fileoff, len(payload), 0, 0, 4, 0)
        struct.pack_into(sfmt, data, shoff + stride * 2, 7, 8 if nobits else 1, 3,
                         base + len(payload), fileoff + len(payload), 16, 0, 0, 4, 0)
        struct.pack_into(sfmt, data, shoff + stride * 3, 12, 3, 0, 0, namesoff, len(names), 0, 0, 1, 0)
    Path(path).write_bytes(data)
    return base, len(payload), bytes(data)


class FakeCtx:
    def __init__(self, code, machine="EM_AARCH64", base=0x1000, symbols=(), bits=64, little=True):
        self.code, self.machine, self.base, self.bits = code, machine, base, bits
        self.path = "fake.so"
        self.sym_by_addr = sorted(symbols)
        self.sym_by_name = {n: (a, s) for a, s, n in symbols}
        self.elf = types.SimpleNamespace(little_endian=little)

    def read(self, addr, size):
        off = addr - self.base
        return self.code[off:off + size] if 0 <= off < len(self.code) else b""

    def find(self, addr):
        if self.base <= addr < self.base + len(self.code):
            return self.base, len(self.code), 0, ".text", 6

    def is_exec(self, addr):
        return self.find(addr) is not None

    def symbolize(self, addr):
        for start, size, name in self.sym_by_addr:
            if start <= addr < start + max(size, 1):
                return name, addr - start
        return None, 0


class IsolatedTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cabinet = self.root / "patches"
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(so, "PATCH_CABINET_DIR", str(self.cabinet)).start()
        mock.patch.object(so, "KB_DIR", str(self.root / "knowledge")).start()
        mock.patch.object(so, "_finish", side_effect=SystemExit).start()
        ctx_class = so.SoCtx

        def tracked_ctx(*args, **kwargs):
            ctx = ctx_class(*args, **kwargs)
            self.addCleanup(ctx.f.close)
            return ctx

        mock.patch.object(so, "SoCtx", side_effect=tracked_ctx).start()

    def command(self, fn, args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            fn(args)
        self.assertIn(cm.exception.code, (None, 0), out.getvalue())
        return out.getvalue()

    def records(self):
        return [(p, json.loads(p.read_text())) for p in self.cabinet.glob("*/*.json")]

    def elf(self, name="libtest.so", **kwargs):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        make_elf(path, **kwargs)
        return path

    def ctx(self, path):
        ctx = so.SoCtx(str(path))
        self.addCleanup(ctx.f.close)
        return ctx


class JniTests(IsolatedTest):
    def jni_entry(self, sig, fn=0x1000, machine="EM_AARCH64", name="nativeCall"):
        ctx = FakeCtx(bytes(64), machine=machine)
        ctx.read_cstr = lambda addr, maxlen=256: {0x2000: name, 0x2100: sig}.get(addr)
        hits = []
        accepted = so._try_jni_entry(ctx, 0x2000, 0x2100, fn, hits)
        return accepted, hits

    def test_object_and_array_descriptors(self):
        for sig in ("(Ljava/lang/String;)Z", "([I[[Ljava/lang/String;)Ljava/lang/Object;",
                    "()V", "(ZBCSIJFD)[[B", "([Ljava/lang/Object;)[Ljava/lang/String;"):
            with self.subTest(sig=sig):
                self.assertTrue(self.jni_entry(sig)[0])

    def test_java_dollar_identifier(self):
        self.assertTrue(self.jni_entry("()V", name="native$Call")[0])

    def test_invalid_descriptors(self):
        for sig in ("(V)I", "([V)I", "(L)V", "([)Z", "()L", "()Ljava/lang/String",
                    "(L;)V", "(Ljava//lang/String;)V", "(Ljava.lang.String;)V",
                    "(Ljava/lang/String;;)Z", "()VV", "(I)Vjunk", "I)V", "()[V"):
            with self.subTest(sig=sig):
                self.assertFalse(self.jni_entry(sig)[0])

    def test_thumb_function_pointer(self):
        ctx = FakeCtx(bytes(4), machine="EM_ARM", bits=32)
        ctx.read_cstr = lambda addr, maxlen=256: {0x2000: "nativeCall", 0x2100: "()V"}.get(addr)
        ctx.is_exec = lambda addr: addr == 0x1000
        hits = []
        self.assertTrue(so._try_jni_entry(ctx, 0x2000, 0x2100, 0x1001, hits))
        self.assertEqual(hits[0][2], 0x1000)
        self.assertTrue(hits[0][3])

    def test_relative_rela_and_rel_use_slot_and_endianness(self):
        class Relocations:
            def __init__(self, rela, records):
                self.rela, self.records = rela, records

            def is_RELA(self):
                return self.rela

            def iter_relocations(self):
                return iter(self.records)

        for bits, little, machine in ((64, True, "EM_AARCH64"), (32, False, "EM_ARM"), (32, True, "EM_386")):
            with self.subTest(bits=bits, little=little, machine=machine):
                slot = bits // 8
                ctx = FakeCtx((0x1234).to_bytes(slot, "little" if little else "big"), machine, bits=bits, little=little)
                reltype = so.RELATIVE_TYPE[machine]
                sections = [Relocations(True, [{"r_info_type": reltype, "r_offset": 0x2000, "r_addend": 0x2345}]),
                            Relocations(False, [{"r_info_type": reltype, "r_offset": 0x1000}])]
                ctx.elf.iter_sections = lambda: iter(sections)
                with mock.patch.object(so, "RelocationSection", Relocations):
                    self.assertEqual(so._collect_relative(ctx), {0x2000: 0x2345, 0x1000: 0x1234})

    def test_direct_jni_big_endian(self):
        for bits, machine in ((32, "EM_ARM"), (64, "EM_AARCH64")):
            with self.subTest(bits=bits):
                fmt = ">III" if bits == 32 else ">QQQ"
                data = struct.pack(fmt, 0x2000, 0x2100, 0x1000)
                ctx = FakeCtx(bytes(32), machine, bits=bits, little=False)
                ctx.f = io.BytesIO(data)
                ctx.path = "fake.so"
                ctx.maps = [(0x3000, len(data), 0, ".data", 3)]
                ctx.elf.header = {"e_type": "ET_EXEC"}
                ctx.read_cstr = lambda addr, maxlen=256: {0x2000: "nativeCall", 0x2100: "(Ljava/lang/String;)Z"}.get(addr)
                with mock.patch.object(so, "SoCtx", return_value=ctx), mock.patch.object(so, "so_path", return_value="fake.so"), mock.patch.object(so, "_collect_relative", return_value={}):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        so.cmd_jni(["fake.so"])
                    self.assertIn("nativeCall", output.getvalue())


class CfgTests(IsolatedTest):
    def cfg(self, code, machine="EM_AARCH64", size=None, symbols=(), addr=0x1000):
        ctx = FakeCtx(bytes.fromhex(code), machine, symbols=symbols, bits=32 if machine in ("EM_ARM", "EM_386") else 64)
        return so._build_cfg(ctx, addr, len(ctx.code) if size is None else size)

    def starts(self, blocks):
        return {b[1] for b in blocks}

    def targets(self, blocks, edges):
        starts = {b[0]: b[1] for b in blocks}
        return {(starts[a], starts[b], k) for a, b, k in edges}

    def test_cbz_target_after_register(self):
        blocks, edges = self.cfg("600000b4c0035fd61f2003d5c0035fd6")
        self.assertEqual(self.starts(blocks), {0x1000, 0x1004, 0x100c})
        self.assertIn((0x1000, 0x100c, "cond"), self.targets(blocks, edges))

    def test_tbz_target_after_bit_operand(self):
        blocks, edges = self.cfg("40001836c0035fd6c0035fd6")
        self.assertIn((0x1000, 0x1008, "cond"), self.targets(blocks, edges))

    def test_x86_absolute_target(self):
        blocks, edges = self.cfg("7404c3909090c3", "EM_X86_64")
        self.assertEqual(self.starts(blocks), {0x1000, 0x1002, 0x1006})
        self.assertIn((0x1000, 0x1006, "cond"), self.targets(blocks, edges))

    def test_x86_32_absolute_target(self):
        blocks, edges = self.cfg("eb029090c3", "EM_386")
        self.assertEqual(self.starts(blocks), {0x1000, 0x1004})
        self.assertEqual(self.targets(blocks, edges), {(0x1000, 0x1004, "branch")})

    def test_unconditional_branch_continues_at_target(self):
        blocks, edges = self.cfg("02000014ffffffffc0035fd6")
        self.assertEqual(self.starts(blocks), {0x1000, 0x1008})
        self.assertEqual(self.targets(blocks, edges), {(0x1000, 0x1008, "branch")})

    def test_mov_immediate_does_not_create_leader_or_edge(self):
        blocks, edges = self.cfg("48b80b1000000000000090c3", "EM_X86_64")
        self.assertEqual(len(blocks), 1)
        self.assertEqual(edges, [])

    def test_loop_and_interior_target_split(self):
        blocks, edges = self.cfg("1f2003d51f2003d5e0ffffb4c0035fd6")
        self.assertEqual(self.starts(blocks), {0x1000, 0x1004, 0x100c})
        self.assertIn((0x1004, 0x1004, "cond"), self.targets(blocks, edges))

    def test_call_is_not_an_intraprocedural_branch(self):
        blocks, edges = self.cfg("02000094c0035fd6c0035fd6")
        self.assertNotIn(0x1008, self.starts(blocks))
        self.assertFalse(any(k == "branch" for _, _, k in edges))

    def test_user_length_caps_symbol_size(self):
        blocks, edges = self.cfg("02000014ffffffffc0035fd6", size=8, symbols=((0x1000, 12, "entry"),))
        self.assertEqual(self.starts(blocks), {0x1000})
        self.assertEqual(edges, [])

    def test_unknown_size_follows_target_beyond_64_bytes(self):
        code = "20000014" + "ffffffff" * 31 + "c0035fd6"
        blocks, edges = self.cfg(code, size=0)
        self.assertEqual(self.starts(blocks), {0x1000, 0x1080})

    def test_symbol_boundary_blocks_cross_function_branch(self):
        blocks, edges = self.cfg("02000014ffffffffc0035fd6", size=0,
                                 symbols=((0x1000, 0, "entry"), (0x1008, 4, "next")))
        self.assertEqual(self.starts(blocks), {0x1000})
        self.assertEqual(edges, [])

    def test_unknown_size_caps_at_4096(self):
        code = "1f2003d5" * 1100
        blocks, edges = self.cfg(code, size=0)
        self.assertLessEqual(max(b[2] for b in blocks), 0x2000)

    def test_invalid_cfg_length(self):
        for size in (-1, 4097):
            with self.subTest(size=size), self.assertRaises(SystemExit):
                self.cfg("c0035fd6", size=size)
        ctx = FakeCtx(bytes.fromhex("c0035fd6"))
        with mock.patch.object(so, "SoCtx", return_value=ctx), mock.patch.object(so, "so_path", return_value="fake.so"):
            with self.assertRaises(SystemExit):
                so.cmd_cfg(["fake.so", "1000", "0"])

    def test_thumb_address_bit_selects_mode(self):
        blocks, edges = self.cfg("00bffde700bf7047", "EM_ARM", addr=0x1001)
        self.assertEqual(self.starts(blocks), {0x1000})
        self.assertEqual(blocks[0][3][0][1], "nop")
        self.assertIn((0x1000, 0x1000, "branch"), self.targets(blocks, edges))

    def test_thumb_pop_pc_stops_before_following_function(self):
        blocks, edges = self.cfg("00bd00bf7047", "EM_ARM", addr=0x1001, size=0)
        self.assertEqual(blocks[0][2], 0x1002)
        self.assertEqual(edges, [])

    def test_arm_mode_return(self):
        blocks, edges = self.cfg("1eff2fe10000a0e1", "EM_ARM", size=0)
        self.assertEqual(blocks[0][2], 0x1004)
        self.assertEqual(edges, [])

    def test_thumb_disasm_uses_even_memory_address(self):
        path = self.elf(machine=40, bits=32, payload=bytes.fromhex("00bf7047"))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            so.cmd_disasm([str(path), "1001", "4"])
        self.assertIn("nop", out.getvalue())
        self.assertIn("0x00001000", out.getvalue())


class MappingTests(IsolatedTest):
    def test_nobits_is_not_file_backed(self):
        ctx = self.ctx(self.elf(nobits=True))
        self.assertIsNone(ctx.find(0x1040))
        self.assertEqual(ctx.read(0x1040, 4), b"")

    def test_read_stops_at_mapping_end(self):
        ctx = self.ctx(self.elf(nobits=True))
        self.assertEqual(ctx.read(0x103c, 16), bytes.fromhex("c0035fd6"))
        self.assertEqual(ctx.read(0x1000, -1), b"")

    def test_segment_fallback_excludes_memsz_tail(self):
        ctx = self.ctx(self.elf(segments_only=True))
        self.assertEqual(ctx.find(0x1000)[3], "LOAD")
        self.assertIsNone(ctx.find(0x1040))
        self.assertEqual(len(ctx.read(0x103c, 16)), 4)

    def test_virtual_address_differs_from_file_offset(self):
        ctx = self.ctx(self.elf())
        self.assertEqual(ctx.vaddr_to_off(0x1004)[0], 0x204)

    def test_strings_preserves_minlen_and_regex(self):
        path = self.elf(payload=b"abcd\0target-string\0othertext\0" + bytes(32))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            so.cmd_strings([str(path), "4", "target"])
        self.assertIn("target-string", output.getvalue())
        self.assertNotIn("othertext", output.getvalue())


class PatchTests(IsolatedTest):
    def test_repeated_patch_arguments(self):
        path = self.elf()
        self.command(so.cmd_patch, [str(path), "1000:20008052", "1004:c0035fd6"])
        self.assertEqual(path.read_bytes()[0x200:0x208], bytes.fromhex("20008052c0035fd6"))
        self.assertEqual(len(self.records()[0][1]["patches"]), 2)

    def test_colon_chain_and_repeated_arguments(self):
        path = self.elf()
        self.command(so.cmd_patch, [str(path), "1000:20008052:1004:c0035fd6", "1008:00008052"])
        self.assertEqual(len(self.records()[0][1]["patches"]), 3)

    def test_all_invalid_items_leave_no_side_effects(self):
        cases = ("1000:20008052:1004", "1000:20008052:1004:gg", "1000:", "1000:123",
                 "--unknown", "-4:20008052", "1040:20008052", "1001:20008052",
                 "1000:20", "103c:20008052c0035fd6")
        for item in cases:
            with self.subTest(item=item):
                path = self.elf(nobits=True)
                before = path.read_bytes()
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as cm:
                    so.cmd_patch([str(path), "1008:20008052", item])
                self.assertNotIn(cm.exception.code, (None, 0))
                self.assertEqual(path.read_bytes(), before)
                self.assertFalse(Path(str(path) + ".orig").exists())
                self.assertFalse(Path(str(path) + ".bak").exists())
                self.assertFalse(self.cabinet.exists())

    def test_overlapping_patches_rejected_before_backup(self):
        path = self.elf()
        before = path.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            so.cmd_patch([str(path), "1000:20008052c0035fd6", "1004:00008052"])
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse(Path(str(path) + ".orig").exists())
        self.assertFalse(self.cabinet.exists())

    def test_dry_run_creates_nothing(self):
        path = self.elf()
        before = path.read_bytes()
        self.command(so.cmd_patch, [str(path), "1000:20008052:1004:c0035fd6", "--dry"])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [path.name])

    def test_arm64_length_and_alignment_rejected(self):
        for item in ("1001:20008052", "1000:2000"):
            with self.subTest(item=item):
                path = self.elf()
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as cm:
                    so.cmd_patch([str(path), item])
                self.assertNotIn(cm.exception.code, (None, 0))
                self.assertFalse(Path(str(path) + ".orig").exists())

    def test_x86_byte_patch_is_allowed(self):
        path = self.elf(machine=62)
        self.command(so.cmd_patch, [str(path), "1001:90"])
        self.assertEqual(path.read_bytes()[0x201], 0x90)

    def test_first_orig_and_previous_bak(self):
        path = self.elf()
        original = path.read_bytes()
        self.command(so.cmd_patch, [str(path), "1000:20008052"])
        first = path.read_bytes()
        self.command(so.cmd_patch, [str(path), "1000:00008052"])
        self.assertEqual(Path(str(path) + ".orig").read_bytes(), original)
        self.assertEqual(Path(str(path) + ".bak").read_bytes(), first)
        self.assertEqual(len(self.records()), 2)

    def test_atomic_publish_failure_preserves_target_and_marks_record_failed(self):
        path = self.elf()
        before = path.read_bytes()
        real_replace = so.os.replace

        def intercepted(source, target):
            if os.fspath(target) == str(path) and os.fspath(source).endswith(".patch"):
                raise OSError("injected publish failure")
            return real_replace(source, target)

        with mock.patch.object(so.os, "replace", side_effect=intercepted), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(OSError):
            so.cmd_patch([str(path), "1000:20008052"])
        self.assertEqual(path.read_bytes(), before)
        records = self.records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0][1]["status"], "failed")
        self.assertTrue(Path(str(path) + ".orig").is_file())
        self.assertTrue(Path(str(path) + ".bak").is_file())
        self.assertFalse(any(item.name.endswith(".patch") for item in self.root.iterdir()))


class CabinetTests(IsolatedTest):
    def record(self, path, rid=None):
        plan = [(0x1000, 0x200, b"old!", b"new!", ".text")]
        if rid is None:
            return so._record_patch(str(path), plan)
        target = self.cabinet / path.stem / (rid + ".json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"id": rid, "so": str(path), "orig": str(path) + ".orig",
                                      "time": "2020-01-01 00:00:00", "status": "active", "note": "", "patches": []}))
        return rid

    def backup(self, path):
        original = path.read_bytes()
        Path(str(path) + ".orig").write_bytes(original)
        path.write_bytes(b"patched")
        return original

    def test_same_second_and_address_ids_do_not_overwrite(self):
        path = self.elf()
        with mock.patch("time.strftime", return_value="20260101_000000"):
            ids = [self.record(path) for _ in range(4)]
        self.assertEqual(len(set(ids)), 4)
        self.assertEqual(len(self.records()), 4)

    def test_ambiguous_old_record_id_is_rejected(self):
        self.record(self.elf("a.so"), "legacy")
        self.record(self.elf("b.so"), "legacy")
        with self.assertRaises(SystemExit):
            so._load_record("legacy")
        rec, _ = so._load_record(str(self.cabinet / "a/legacy.json"))
        self.assertEqual(rec["id"], "legacy")

    def test_old_record_remains_readable(self):
        path = self.elf()
        self.record(path, "20200101_000000_1000")
        rec, _ = so._load_record("20200101_000000_1000")
        self.assertEqual(rec["so"], str(path))

    def test_same_basename_rollback_only_cleans_matching_path(self):
        a, b = self.elf("app-a/libshared.so"), self.elf("app-b/libshared.so")
        original = self.backup(a)
        self.backup(b)
        rid = self.record(a)
        self.record(a)
        self.record(b)
        self.command(so.cmd_patch_rollback, [rid])
        self.assertEqual(a.read_bytes(), original)
        self.assertEqual(b.read_bytes(), b"patched")
        self.assertTrue(Path(str(a) + ".orig").is_file())
        self.assertEqual([r["so"] for _, r in self.records()], [str(b)])

    def test_rollback_all_collects_before_cleanup(self):
        a, b = self.elf("app-a/libshared.so"), self.elf("app-b/libshared.so")
        originals = {a: self.backup(a), b: self.backup(b)}
        self.record(a)
        self.record(b)
        self.command(so.cmd_patch_rollback, ["all"])
        for path, original in originals.items():
            self.assertEqual(path.read_bytes(), original)
            self.assertTrue(Path(str(path) + ".orig").is_file())
        self.assertEqual(self.records(), [])

    def test_rollback_all_prevalidates_every_backup(self):
        a, b = self.elf("app-a/libshared.so"), self.elf("app-b/libshared.so")
        self.backup(a)
        self.backup(b)
        self.record(a)
        self.record(b)
        Path(str(b) + ".orig").unlink()
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            so.cmd_patch_rollback(["all"])
        self.assertEqual(a.read_bytes(), b"patched")
        self.assertEqual(b.read_bytes(), b"patched")
        self.assertEqual(len(self.records()), 2)

    def test_restore_preserves_orig_and_cleans_target_records(self):
        path = self.elf()
        original = self.backup(path)
        self.record(path)
        self.command(so.cmd_patch_restore, [str(path)])
        self.assertEqual(path.read_bytes(), original)
        self.assertTrue(Path(str(path) + ".orig").is_file())
        self.assertEqual(self.records(), [])


class FullPatchTests(IsolatedTest):
    def invoke(self, path, addr, text, *options):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["patch_so.py", str(path), addr, text, *options]), contextlib.redirect_stdout(out):
            patch.main()
        return out.getvalue()

    def test_hex_patch_records_source(self):
        path = self.elf()
        self.invoke(path, "0x1000", "20 00 80 52", "--bytes")
        self.assertEqual(path.read_bytes()[0x200:0x204], bytes.fromhex("20008052"))
        self.assertEqual(self.records()[0][1]["so"], str(path))
        self.assertTrue(Path(str(path) + ".orig").is_file())
        self.assertTrue(Path(str(path) + ".bak").is_file())

    def test_out_records_destination_and_preserves_source(self):
        path = self.elf()
        original = path.read_bytes()
        dest = self.root / "libresult.so"
        self.invoke(path, "0x1000", "20 00 80 52", "--bytes", "--out", str(dest))
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self.records()[0][1]["so"], str(dest))
        self.assertEqual(Path(str(dest) + ".orig").read_bytes(), original)
        self.assertEqual(Path(str(dest) + ".bak").read_bytes(), original)
        self.assertFalse(Path(str(path) + ".orig").exists())

    def test_existing_out_uses_its_own_baseline(self):
        path, dest = self.elf(), self.elf("result.so")
        previous = bytearray(dest.read_bytes())
        previous[0x210:0x214] = b"keep"
        dest.write_bytes(previous)
        self.invoke(path, "0x1000", "20 00 80 52", "--bytes", "--out", str(dest))
        self.assertEqual(Path(str(dest) + ".orig").read_bytes(), bytes(previous))
        self.assertEqual(Path(str(dest) + ".bak").read_bytes(), bytes(previous))
        rec = self.records()[0][1]
        self.assertEqual(rec["so"], str(dest))
        self.command(so.cmd_patch_rollback, [rec["id"]])
        self.assertEqual(dest.read_bytes(), bytes(previous))

    def test_common_orig_and_bak_across_tools(self):
        path = self.elf()
        original = path.read_bytes()
        self.command(so.cmd_patch, [str(path), "1000:20008052"])
        prior = path.read_bytes()
        self.invoke(path, "0x1004", "00 00 80 52", "--bytes")
        self.assertEqual(Path(str(path) + ".orig").read_bytes(), original)
        self.assertEqual(Path(str(path) + ".bak").read_bytes(), prior)
        self.assertEqual(len(self.records()), 2)

    def test_invalid_patch_does_not_create_output(self):
        path = self.elf(nobits=True)
        original = path.read_bytes()
        for addr, text in (("0x1001", "20 00 80 52"), ("0x103c", "20 00 80 52 c0 03 5f d6"), ("0x1000", "20 00")):
            with self.subTest(addr=addr, text=text), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                self.invoke(path, addr, text, "--bytes", "--out", str(self.root / "result.so"))
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse((self.root / "result.so").exists())
        self.assertFalse(self.cabinet.exists())

    def test_non_arm64_is_rejected(self):
        path = self.elf(machine=62)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            self.invoke(path, "0x1000", "20 00 80 52", "--bytes")
        self.assertFalse(self.cabinet.exists())

    def test_gnu_assembly_and_branch_relocation(self):
        if shutil.which("aarch64-linux-gnu-as") is None and os.uname().machine not in ("aarch64", "arm64"):
            self.skipTest("GNU AArch64 assembler unavailable")
        path = self.elf()
        self.invoke(path, "0x1000", "b.eq 0x1008; cbz x0, 0x100c; mov w0, #1; ret")
        ctx = self.ctx(path)
        md = so._make_disassembler(ctx)
        md.detail = True
        insns = list(md.disasm(ctx.read(0x1000, 16), 0x1000))
        self.assertEqual([i.mnemonic for i in insns], ["b.eq", "cbz", "mov", "ret"])
        self.assertEqual(so._branch_target(insns[0], ctx.machine), 0x1008)
        self.assertEqual(so._branch_target(insns[1], ctx.machine), 0x100c)
        self.assertEqual(len(self.records()), 1)


class CliTests(IsolatedTest):
    def cli(self, *args):
        script = self.root / "so_tool.py"
        source = SOURCE.read_text().replace('PATCH_CABINET_DIR = "/root/patches"',
                                           "PATCH_CABINET_DIR = " + repr(str(self.cabinet)))
        source = source.replace('KB_DIR = "/root/knowledge"',
                                "KB_DIR = " + repr(str(self.root / "knowledge")))
        script.write_text(source)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([sys.executable, str(script), *map(str, args)],
                              capture_output=True, text=True, env=env, timeout=30)

    def test_patch_chain_cli(self):
        path = self.elf()
        result = self.cli("patch", path, "1000:20008052:1004:c0035fd6")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.records()[0][1]["patches"]), 2)

    def test_dry_cli_has_no_cabinet_or_backups(self):
        path = self.elf()
        original = path.read_bytes()
        result = self.cli("patch", path, "1000:20008052", "--dry")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(self.cabinet.exists())
        self.assertFalse(Path(str(path) + ".orig").exists())
        self.assertFalse(Path(str(path) + ".bak").exists())

    def test_cfg_invalid_len_cli(self):
        path = self.elf()
        for length in ("0", "-1", "4097", "oops"):
            with self.subTest(length=length):
                result = self.cli("cfg", path, "1000", length)
                self.assertEqual(result.returncode, 1, result.stdout)
        self.assertFalse(self.cabinet.exists())

    def test_full_patch_cli_loads_source_module(self):
        path = self.elf()
        self.cli("--help")
        script = self.root / "patch_so.py"
        script.write_text(patch_source.replace('sys.path.insert(0, "/root/so-tool")',
                                              "sys.path.insert(0, " + repr(str(self.root)) + ")"))
        result = subprocess.run([sys.executable, str(script), str(path), "0x1000",
                                 "20 00 80 52", "--bytes"], capture_output=True, text=True,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"), timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.records()[0][1]["so"], str(path))


if __name__ == "__main__":
    unittest.main()
