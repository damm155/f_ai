import struct
from ..errors import DexError
import zlib

from ._leb import _mutf8, _uleb128, enc_mutf8


ACC = [(0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"),
       (0x10, "final"), (0x100, "native"), (0x200, "interface"),
       (0x400, "abstract"), (0x1000, "synthetic")]


def _find_class_def(data, base, size, class_desc):
    """Return the absolute class_def offset in a DEX byte range, or ``None``."""
    if size < 0x70 or base + size > len(data) or data[base:base + 4] != b"dex\n":
        raise ValueError("not a DEX file")
    n_str, off_str, n_type, off_type = struct.unpack_from("<4I", data, base + 0x38)
    n_class, off_class = struct.unpack_from("<2I", data, base + 0x60)
    if (off_str + n_str * 4 > size or off_type + n_type * 4 > size or
            off_class + n_class * 32 > size):
        raise ValueError("invalid DEX ID table bounds")
    encoded = enc_mutf8(class_desc)
    _, start = _uleb128(encoded, 0)
    wanted = encoded[start:-1]
    left, right = 0, n_class
    while left < right:
        mid = (left + right) // 2
        class_def = base + off_class + 32 * mid
        type_idx = struct.unpack_from("<I", data, class_def)[0]
        if type_idx >= n_type:
            raise ValueError("invalid DEX class type index")
        string_idx = struct.unpack_from("<I", data, base + off_type + 4 * type_idx)[0]
        if string_idx >= n_str:
            raise ValueError("invalid DEX type string index")
        string_off = struct.unpack_from("<I", data, base + off_str + 4 * string_idx)[0]
        if string_off >= size:
            raise ValueError("invalid DEX string offset")
        _, text_off = _uleb128(data, base + string_off)
        if text_off >= base + size:
            raise ValueError("invalid DEX string data")
        end = data.find(b"\0", text_off, base + size)
        if end < 0:
            raise ValueError("unterminated DEX string")
        current = data[text_off:end]
        if current < wanted:
            left = mid + 1
        elif current > wanted:
            right = mid
        else:
            return class_def
    # 二分未命中时的线性兜底：部分加固/重打包 APK 的 class_def 表不再严格按
    # type_idx 排序（或存在重复/乱序项），会让二分漏掉真实存在的类（短混淆名尤甚，
    # 如 La4/b;）。此处按字节序线性扫描全部 class_def 精确比对，命中即返回。
    for i in range(n_class):
        class_def = base + off_class + 32 * i
        type_idx = struct.unpack_from("<I", data, class_def)[0]
        if type_idx >= n_type:
            continue
        string_idx = struct.unpack_from("<I", data, base + off_type + 4 * type_idx)[0]
        if string_idx >= n_str:
            continue
        string_off = struct.unpack_from("<I", data, base + off_str + 4 * string_idx)[0]
        if string_off >= size:
            continue
        _, text_off = _uleb128(data, base + string_off)
        if text_off >= base + size:
            continue
        end = data.find(b"\0", text_off, base + size)
        if end < 0:
            continue
        if data[text_off:end] == wanted:
            return class_def
    return None

def _acc_str(flags):
    return " ".join(n for bit, n in ACC if flags & bit)

# 字段访问标志（含字段特有 flag：volatile/transient/enum，方法表 ACC 不含这些）
FIELD_ACC = [(0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"),
             (0x10, "final"), (0x40, "volatile"), (0x80, "transient"),
             (0x1000, "synthetic"), (0x4000, "enum")]


def field_acc_str(flags):
    return " ".join(n for bit, n in FIELD_ACC if flags & bit)

def _desc_to_java(d):
    """Lst;-style descriptor -> dotted Java name."""
    arr = ""
    while d.startswith("["):
        arr += "[]"
        d = d[1:]
    prim = {"V": "void", "Z": "boolean", "B": "byte", "S": "short", "C": "char",
            "I": "int", "J": "long", "F": "float", "D": "double"}
    if d in prim:
        return prim[d] + arr
    if d.startswith("L") and d.endswith(";"):
        return d[1:-1].replace("/", ".") + arr
    return d + arr

class DexFile:
    def __init__(self, data):
        if data[:4] != b"dex\n":
            raise ValueError("not a DEX file")
        self.d = data
        h = struct.unpack_from("<14I", data, 0x38)
        (self.n_str, self.off_str, self.n_type, self.off_type,
         self.n_proto, self.off_proto, self.n_field, self.off_field,
         self.n_method, self.off_method, self.n_class, self.off_class,
         _ds, _do) = h
        self._scache = {}

    def string(self, i):
        if i in self._scache:
            return self._scache[i]
        off = struct.unpack_from("<I", self.d, self.off_str + 4 * i)[0]
        _, off = _uleb128(self.d, off)           # utf16 length (unused)
        end = self.d.index(0, off)
        s = _mutf8(self.d[off:end])
        self._scache[i] = s
        return s

    def type(self, i):
        return self.string(struct.unpack_from("<I", self.d, self.off_type + 4 * i)[0])

    def proto_desc(self, i):
        base = self.off_proto + 12 * i
        ret_idx, params_off = struct.unpack_from("<II", self.d, base + 4)
        params = ""
        if params_off:
            n = struct.unpack_from("<I", self.d, params_off)[0]
            for k in range(n):
                t = struct.unpack_from("<H", self.d, params_off + 4 + 2 * k)[0]
                params += self.type(t)
        return "(%s)%s" % (params, self.type(ret_idx))

    def method_ref(self, i):
        base = self.off_method + 8 * i
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.d, base)
        return self.type(class_idx), self.string(name_idx), self.proto_desc(proto_idx)

    def field_ref(self, i):
        base = self.off_field + 8 * i
        class_idx, type_idx, name_idx = struct.unpack_from("<HHI", self.d, base)
        return self.type(class_idx), self.string(name_idx), self.type(type_idx)

    def proto_parts(self, i):
        base = self.off_proto + 12 * i
        ret_idx, params_off = struct.unpack_from("<II", self.d, base + 4)
        params = []
        if params_off:
            n = struct.unpack_from("<I", self.d, params_off)[0]
            for k in range(n):
                t = struct.unpack_from("<H", self.d, params_off + 4 + 2 * k)[0]
                params.append(self.type(t))
        return self.type(ret_idx), tuple(params)

    def method_full(self, i):
        base = self.off_method + 8 * i
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.d, base)
        ret, params = self.proto_parts(proto_idx)
        return self.type(class_idx), self.string(name_idx), ret, params

    def classes(self):
        for i in range(self.n_class):
            base = self.off_class + 32 * i
            class_idx, access, _super, _ifc, _src, _anno, cdata_off, _sv = \
                struct.unpack_from("<8I", self.d, base)
            yield {"name": self.type(class_idx), "access": access, "cdata": cdata_off}

    def find_class(self, class_desc):
        """Find an exact class descriptor without walking every class definition.

        DEX class definitions are sorted by type index, and type descriptors are
        sorted in UTF-16 code-unit order. Use that ordering for a binary search.
        """
        offset = _find_class_def(self.d, 0, len(self.d), class_desc)
        if offset is None:
            return None
        access = struct.unpack_from("<I", self.d, offset + 4)[0]
        cdata_off = struct.unpack_from("<I", self.d, offset + 24)[0]
        return {"name": class_desc, "access": access, "cdata": cdata_off}

    def class_methods(self, cdata_off):
        if not cdata_off:
            return []
        off = cdata_off
        sf, off = _uleb128(self.d, off)
        inf, off = _uleb128(self.d, off)
        dm, off = _uleb128(self.d, off)
        vm, off = _uleb128(self.d, off)
        # skip encoded_fields (static + instance)
        for _ in range(sf + inf):
            _, off = _uleb128(self.d, off)       # field_idx_diff
            _, off = _uleb128(self.d, off)       # access_flags
        methods = []
        for count in (dm, vm):
            midx = 0
            for _ in range(count):
                diff, off = _uleb128(self.d, off)
                acc, off = _uleb128(self.d, off)
                code_off, off = _uleb128(self.d, off)
                midx += diff
                _, name, proto = self.method_ref(midx)
                methods.append({"name": name, "proto": proto,
                                "access": acc, "code_off": code_off})
        return methods

    def class_fields(self, cdata_off):
        """Decode encoded_fields (static + instance) of a class_data_item.

        差分索引累加到 field_ids，再经 field_ref 取字段名/类型/所属类；
        header 直读路线（n_field/off_field），不依赖 map list（部分 APK 的
        map_off 指向文件末尾且 map list 被截断，按 map 解析会 struct.error）。
        """
        if not cdata_off:
            return []
        off = cdata_off
        sf, off = _uleb128(self.d, off)
        inf, off = _uleb128(self.d, off)
        _, off = _uleb128(self.d, off)           # direct_methods count (skip)
        _, off = _uleb128(self.d, off)           # virtual_methods count (skip)
        fields = []
        for kind, count in (("static", sf), ("instance", inf)):
            fidx = 0
            for _ in range(count):
                diff, off = _uleb128(self.d, off)
                acc, off = _uleb128(self.d, off)
                fidx += diff
                _, name, ftype = self.field_ref(fidx)
                fields.append({"name": name, "type": ftype,
                               "access": acc, "static": kind == "static"})
        return fields

    def all_strings(self):
        return (self.string(i) for i in range(self.n_str))

    def find_method(self, class_desc, mname):
        c = self.find_class(class_desc)
        if c is not None:
            for m in self.class_methods(c["cdata"]):
                if m["name"] == mname and m["code_off"]:
                    return m
        return None

    def code_insns(self, code_off):
        regs, ins, outs, tries, _dbg, insz = struct.unpack_from("<HHHHII", self.d, code_off)
        return {"regs": regs, "ins": ins, "outs": outs, "insns_size": insz, "insns_off": code_off + 16}

    def patch_return(self, code_off, ret_desc, value):
        """Overwrite a method body with a forced return (in place, nop-padded)."""
        ci = self.code_insns(code_off)
        words = build_return_insns(ret_desc, value, ci["regs"])
        if len(words) > ci["insns_size"]:
            raise DexError("method body too small to patch (%d > %d words)"
                             % (len(words), ci["insns_size"]))
        b = bytearray(self.d)
        for i in range(ci["insns_size"]):
            w = words[i] if i < len(words) else 0x0000  # pad with nop
            struct.pack_into("<H", b, ci["insns_off"] + 2 * i, w)
        self.d = bytes(b)

    def finalize(self):
        """Recompute DEX signature (SHA-1) + checksum (Adler-32) after edits."""
        import hashlib
        b = bytearray(self.d)
        b[12:32] = hashlib.sha1(bytes(b[32:])).digest()
        struct.pack_into("<I", b, 8, zlib.adler32(bytes(b[12:])) & 0xFFFFFFFF)
        self.d = bytes(b)
        return self.d

def build_return_insns(ret_desc, value, regs):
    """Dalvik bytecode for a forced return. value in {true,false,null,void}."""
    if ret_desc == "V" or value == "void":
        return [0x000E]                                   # return-void
    is_obj = ret_desc.startswith("L") or ret_desc.startswith("[")
    if regs < 1:
        raise DexError("method has no registers; cannot synthesize a value return")
    if is_obj or value == "null":
        return [0x0012, 0x0011]                           # const/4 v0,#0 ; return-object v0
    lit = 1 if value == "true" else 0
    return [(lit << 12) | 0x12, 0x000F]
