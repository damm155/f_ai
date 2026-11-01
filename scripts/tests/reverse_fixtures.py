import io
import struct
import zipfile

from reapk import (
    Assembler, DexFile, Interner, assemble, build_code_item, build_dex,
    compute_outs, encode_axml,
)
from reapk.axml import (
    ANDROID_NS, RID_CLEARTEXT, RID_DEBUGGABLE, T_INT_BOOL, T_STRING,
    _enc_string_pool,
)
from reapk.dex._leb import enc_mutf8, enc_uleb
from reapk.dex.writer import emit_class_data


def make_manifest(debuggable=None, cleartext=None):
    attrs, resids = [], []
    for name, rid, value in (
        ("debuggable", RID_DEBUGGABLE, debuggable),
        ("usesCleartextTraffic", RID_CLEARTEXT, cleartext),
    ):
        if value is not None:
            resids.append((name, rid))
            attrs.append({"ns": ANDROID_NS, "name": name, "resid": rid,
                          "vtype": T_INT_BOOL, "vstr": None,
                          "vdata": 0xFFFFFFFF if value else 0})
    package = {"ns": None, "name": "package", "resid": None,
               "vtype": T_STRING, "vstr": "test.fixture", "vdata": 0}
    return encode_axml({"resid": resids, "events": [
        ("ns_start", 1, "android", ANDROID_NS),
        ("start", 1, None, "manifest", [package], 0, 0, 0),
        ("start", 2, None, "application", attrs, 0, 0, 0),
        ("end", 2, None, "application"),
        ("end", 3, None, "manifest"),
        ("ns_end", 3, "android", ANDROID_NS),
    ]})


def _empty_dex():
    data = bytearray(0x70)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<III", data, 0x20, len(data), 0x70, 0x12345678)
    return DexFile(bytes(data))


def _index_value(kind, index):
    width = max(1, (index.bit_length() + 7) // 8)
    return bytes([kind | ((width - 1) << 5)]) + index.to_bytes(width, "little")


def make_dex(strings=(), methods=(), fields=(), metadata_string=None):
    seed = _empty_dex()
    interner = Interner(seed)
    owners = sorted({m["owner"] for m in methods} | {f[0] for f in fields})
    fields = list(fields)
    for value in strings:
        interner.add_string(value)
    if metadata_string is not None:
        interner.add_string(metadata_string).add_string("value")
        interner.add_type("Lfixture/Annotation;")
        if owners:
            fields.append((owners[0], "a_text", "Ljava/lang/String;"))
    if owners:
        interner.add_type("Ljava/lang/Object;")
        interner.add_string("Fixture.java")
    for owner, name, typ in fields:
        interner.add_field(owner, name, typ)
    bodies = []
    for method in methods:
        ret, params = method.get("ret", "V"), tuple(method.get("params", ()))
        interner.add_method(method["owner"], method["name"], ret, params)
        if "body" in method:
            body = method["body"]
        elif ret == "V":
            body = ["return-void"]
        elif ret in ("J", "D"):
            body = ["const-wide/16 v0, #0", "return-wide v0"]
        else:
            body = ["const/4 v0, #0", "return-object v0" if ret[0] in "L[" else "return v0"]
        assemble(Assembler(seed, interner=interner, collecting=True), body)
        bodies.append(body)
    interner.finalize()
    if not owners:
        return build_dex(seed, interner=interner)

    r = interner
    off_str = 0x70
    off_type = off_str + 4 * len(r.S)
    off_proto = off_type + 4 * len(r.T)
    off_field = off_proto + 12 * len(r.P)
    off_method = off_field + 8 * len(r.F)
    off_class = off_method + 8 * len(r.M)
    data_start = off_class + 32 * len(owners)
    data = bytearray()

    def place(blob, alignment=1):
        data.extend(b"\0" * (-(data_start + len(data)) % alignment))
        offset = data_start + len(data)
        data.extend(blob)
        return offset

    string_offsets = [place(enc_mutf8(s)) for s in r.S]
    type_lists = {}
    for _, params in r.P:
        if params and params not in type_lists:
            type_lists[params] = place(struct.pack("<I", len(params)) + b"".join(
                struct.pack("<H", r.tpos[p]) for p in params), 4)
    debug_off = annotation_dir = static_values = 0
    if metadata_string is not None:
        si = r.spos[metadata_string]
        debug_off = place(enc_uleb(1) + enc_uleb(0) + b"\x03" + enc_uleb(0)
                          + enc_uleb(si + 1) + enc_uleb(r.tpos["Ljava/lang/String;"] + 1)
                          + b"\x09" + enc_uleb(si + 1) + b"\0")
        annotation = place(b"\x01" + enc_uleb(r.tpos["Lfixture/Annotation;"])
                           + enc_uleb(1) + enc_uleb(r.spos["value"])
                           + _index_value(0x17, si))
        annotation_set = place(struct.pack("<II", 1, annotation), 4)
        annotation_dir = place(struct.pack("<IIII", annotation_set, 0, 0, 0), 4)
        static_values = place(enc_uleb(1) + _index_value(0x17, si))
    codes, declared = {}, {owner: [] for owner in owners}
    for method, body in zip(methods, bodies):
        ret, params = method.get("ret", "V"), tuple(method.get("params", ()))
        access = method.get("access", 0x9)
        ins = sum(2 if p in ("J", "D") else 1 for p in params) + (0 if access & 8 else 1)
        words = assemble(Assembler(seed, interner=r), body)
        code = bytearray(build_code_item(method.get("regs", max(2, ins)), ins,
                                         compute_outs(words), words))
        if debug_off:
            struct.pack_into("<I", code, 8, debug_off)
        code_off = place(code, 4)
        codes[code_off] = code_off
        midx = r.mpos[(method["owner"], method["name"], ret, params)]
        declared[method["owner"]].append([midx, access, code_off])
    class_data = {}
    for owner in owners:
        sfields = sorted([r.fpos[f], 0x9] for f in fields if f[0] == owner)
        direct, virtual = [], []
        for m in sorted(declared[owner]):
            name = r.M[m[0]][1]
            (direct if m[1] & 0xA or name == "<init>" else virtual).append(m)
        class_data[owner] = place(emit_class_data((sfields, [], direct, virtual), codes))

    data_out = bytearray(0x70)
    data_out += b"".join(struct.pack("<I", o) for o in string_offsets)
    data_out += b"".join(struct.pack("<I", r.spos[t]) for t in r.T)
    data_out += b"".join(struct.pack("<III", r.spos[r._shorty(ret, params)],
                                   r.tpos[ret], type_lists.get(params, 0)) for ret, params in r.P)
    data_out += b"".join(struct.pack("<HHI", r.tpos[c], r.tpos[t], r.spos[n]) for c, n, t in r.F)
    data_out += b"".join(struct.pack("<HHI", r.tpos[c], r.ppos[(ret, params)], r.spos[n])
                         for c, n, ret, params in r.M)
    for owner in owners:
        primary = owner == owners[0]
        source = metadata_string if primary and metadata_string is not None else "Fixture.java"
        data_out += struct.pack("<8I", r.tpos[owner], 1, r.tpos["Ljava/lang/Object;"], 0,
                                r.spos[source], annotation_dir if primary else 0,
                                class_data[owner], static_values if primary else 0)
    data_out += data
    data_out[:8] = b"dex\n035\0"
    struct.pack_into("<III", data_out, 0x20, len(data_out), 0x70, 0x12345678)
    struct.pack_into("<14I", data_out, 0x38, len(r.S), off_str, len(r.T), off_type,
                     len(r.P), off_proto, len(r.F), off_field, len(r.M), off_method,
                     len(owners), off_class, len(data), data_start)
    dex = DexFile(bytes(data_out))
    return build_dex(dex, interner=Interner(dex).finalize())


def make_xref_dex():
    a, b, caller = "Lfixture/A;", "Lfixture/B;", "Lfixture/Caller;"
    return make_dex(methods=[
        {"owner": a, "name": "foo"},
        {"owner": a, "name": "foo", "params": ("I",)},
        {"owner": b, "name": "foo"},
        {"owner": caller, "name": "run", "body": [
            "const/4 v0, #0", "invoke-static {}, Lfixture/A;->foo()V",
            "invoke-static {v0}, Lfixture/A;->foo(I)V", "invoke-static {}, Lfixture/B;->foo()V",
            "sget v0, Lfixture/A;->value:I", "sget-wide v0, Lfixture/A;->value:J",
            "sget v0, Lfixture/B;->value:I", "const-class v0, Lfixture/A;", "return-void",
        ]},
    ], fields=[(a, "value", "I"), (a, "value", "J"), (b, "value", "I")])


def make_arsc(mode="dense"):
    global_pool = _enc_string_pool(["one", "two"])
    type_pool = _enc_string_pool(["string"])
    key_pool = _enc_string_pool(["first", "second"])
    entries = b"".join(struct.pack("<HHIHBBI", 8, 0, key, 8, 0, T_STRING, value)
                       for key, value in ((1, 0), (0, 1)))
    if mode == "sparse":
        flags, count, offsets = 1, 2, struct.pack("<4H", 0, 0, 3, 4)
    elif mode == "offset16":
        flags, count, offsets = 2, 4, struct.pack("<4H", 0, 0xFFFF, 0xFFFF, 4)
    else:
        flags, count, offsets = 0, 4, struct.pack("<4I", 0, 0xFFFFFFFF, 0xFFFFFFFF, 16)
    type_header = bytearray(84)
    struct.pack_into("<HHIBBHII", type_header, 0, 0x0201, 84,
                     84 + len(offsets) + len(entries), 1, flags, 0, count, 84 + len(offsets))
    struct.pack_into("<I", type_header, 20, 64)
    package_body = type_pool + key_pool + type_header + offsets + entries
    package_header = bytearray(288)
    struct.pack_into("<HHII", package_header, 0, 0x0200, 288, 288 + len(package_body), 0x7F)
    package_header[12:12 + 24] = "test.fixture".encode("utf-16-le")
    struct.pack_into("<5I", package_header, 268, 288, 1, 288 + len(type_pool), 2, 0)
    body = global_pool + package_header + package_body
    return struct.pack("<HHII", 0x0002, 12, 12 + len(body), 1) + body


class _StreamingBuffer(io.BytesIO):
    def seek(self, *args):
        raise io.UnsupportedOperation("seek")


def make_apk(manifest=None, dex=None, extra_entries=(), signatures=False,
             comment=b"fixture zip comment", streaming=False):
    buffer = _StreamingBuffer() if streaming else io.BytesIO()
    entries = [("AndroidManifest.xml", manifest or make_manifest(), zipfile.ZIP_DEFLATED)]
    if dex is not None:
        entries.append(("classes.dex", dex, zipfile.ZIP_DEFLATED))
    entries.extend(extra_entries)
    if signatures:
        entries.extend((n, b"old signature", zipfile.ZIP_DEFLATED) for n in (
            "META-INF/MANIFEST.MF", "META-INF/CERT.SF", "META-INF/CERT.RSA",
            "meta-inf/old.dsa", "META-INF/CERT.EC", "META-INF/SIG-CUSTOM",
        ))
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.comment = comment
        for name, data, compression in entries:
            info = zipfile.ZipInfo(name, (2020, 1, 2, 3, 4, 6))
            info.compress_type = compression
            info.comment = b"entry comment"
            info.extra = struct.pack("<HH", 0xCAFE, 2) + b"xy"
            info.external_attr = 0o100644 << 16
            zf.writestr(info, data)
    data = buffer.getvalue()
    if not signatures:
        return data
    eocd = len(data) - 22 - len(comment)
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    value = b"fixture v2 signature"
    pair = struct.pack("<QI", 4 + len(value), 0x7109871A) + value
    size = len(pair) + 24
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + b"APK Sig Block 42"
    result = bytearray(data[:cd_offset] + block + data[cd_offset:])
    struct.pack_into("<I", result, eocd + len(block) + 16, cd_offset + len(block))
    return bytes(result)
