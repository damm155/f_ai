#!/usr/bin/env python3
"""FBox APK 原生工具链驱动（基于 vendored reapk，纯 Python 标准库，无 Java）。

容器内统一入口，由 Android 侧 LinuxViewModel 经 shell 调用：
    python3 /root/apk-tool/apk_tool.py <子命令> <参数...>

子命令一览（输出统一为 UTF-8 文本，✓/✗ 标记成败，供 AI 直接阅读）：
  info <apk>                          manifest 分析：包名/版本/权限/导出组件/标志
  manifest-edit <apk> <ops> <out>     编辑 manifest（ops 见下），产出未签名 APK
  dex-strings <apk> <regex>           搜全部 dex 字符串（正则，限 200 条）
  dex-refs <apk> <regex>              搜 const-string 代码引用：谁在哪个方法加载了它
  dex-class <apk> <class>             列类的方法清单（class=Lcom/a/B; 格式）
  dex-fields <apk> <class>            列类的字段清单（static/instance、Java 类型、访问标志）
  dex-method <apk> <class> <name>     反汇编方法体为 smali（带 %04x: 地址前缀）
                                    可选分页：<apk> <class> <name> [offset] [limit]
                                    offset 起始行(0起)、limit 单页行数(默认400，最大2000)
  dex-return <apk> <class> <name> <v> 原地补丁：强制方法返回 true/false/null/void
  dex-smali <apk> <class> <name> <f>  smali 文本重写方法体（整 DEX 重写，支持扩容）
  dex-string-edit <apk> <old> <new> <out>  原地改字符串内容（等长或尾部截断补零）
  resource-read <apk> <locator>...    按资源 locator 批量读 resources.arsc 值
  dex-xref <apk> <method|field|type> <目标>  dex 方法/字段/类引用查询（谁引用了目标）
  rebuild <apk> <out>                 仅重打包（manifest 修改后落盘 zipaligned 未签名 APK）

ops 语法（逗号分隔多个）：debuggable=1,cleartext=1,perm=android.permission.XXX

安全说明：所有编辑只落盘到容器 /root/apk/ 下，签名由 Android 侧 apksig 完成。
"""
import json
import os
import re
import struct
import sys
import zipfile

sys.path.insert(0, "/root/apk-tool")
from reapk import (  # noqa: E402
    Apk, Arsc, DexFile, Interner, find_string_code_refs,
    assemble_interned, build_code_item, build_dex, compute_outs,
    disassemble, encode_insn, insn_length,
)
from reapk.dex import field_acc_str, _desc_to_java  # noqa: E402

APK_DIR = "/root/apk"
MAX_HITS = 200          # 字符串/引用搜索上限，防大 dex 刷屏
MAX_SMALI_LINES = 400   # 反汇编单页输出上限（可用 offset/limit 分页）
MAX_CLASS_METHODS = 300 # 类方法清单上限（防混淆大类全量刷屏）


def apk_path(name: str) -> str:
    p = name if name.startswith("/") else os.path.join(APK_DIR, name)
    if not os.path.isfile(p):
        sys.exit("✗ APK 不存在: %s" % p)
    return p


def out_path(path: str) -> str:
    p = path if path.startswith("/") else os.path.join(APK_DIR, path)
    os.makedirs(os.path.dirname(p) or APK_DIR, exist_ok=True)
    return p


def load_dexes(p: str):
    """按需解压全部 classesN.dex（DexFile 解析 header + 惰性字符串表）。"""
    out = []
    with zipfile.ZipFile(p) as zf:
        for n in sorted(x for x in zf.namelist()
                        if re.fullmatch(r"classes\d*\.dex", x)):
            out.append((n, DexFile(zf.read(n))))
    return out


def resolve_method(dexes, cls, mname):
    """在多个 dex 里定位方法，返回 (dex 名, dex, method dict)。"""
    for name, dex in dexes:
        c = dex.find_class(cls)
        if c is None or not c["cdata"]:
            continue
        for m in dex.class_methods(c["cdata"]):
            if m["name"] == mname and m["code_off"]:
                return name, dex, m
    return None, None, None


# ---------------------------------------------------------------- 子命令实现

def cmd_info(args):
    apk = Apk.open(apk_path(args[0]))
    info = apk.analyze()
    print("✓ Manifest 分析（%s）" % os.path.basename(args[0]))
    print(json.dumps(info, ensure_ascii=False, indent=1))


def cmd_manifest_edit(args):
    # 输入同样走 apk_path 规范化：AI 传相对文件名时补 /root/apk 前缀（与 info 一致）
    apk_path_in, ops, out = apk_path(args[0]), args[1], out_path(args[2])
    apk = Apk.open(apk_path_in)
    m = apk.manifest
    did = []
    for op in ops.split(","):
        op = op.strip()
        if not op:
            continue
        if op in ("debuggable=1", "debuggable"):
            m.set_debuggable(True); did.append("debuggable=true")
        elif op == "debuggable=0":
            m.set_debuggable(False); did.append("debuggable=false")
        elif op in ("cleartext=1", "cleartext"):
            m.set_cleartext(True); did.append("usesCleartextTraffic=true")
        elif op == "cleartext=0":
            m.set_cleartext(False); did.append("usesCleartextTraffic=false")
        elif op.startswith("perm="):
            m.add_permission(op[5:]); did.append("+uses-permission %s" % op[5:])
        else:
            sys.exit("✗ 未知 manifest 操作: %s（可用: debuggable=1|0, cleartext=1|0, perm=<name>）" % op)
    if not did:
        sys.exit("✗ ops 为空，未做任何修改")
    apk.save(out)   # zipaligned 未签名；签名走 Android 侧 apksig
    size = os.path.getsize(out)
    print("✓ Manifest 已修改并重打包（未签名）")
    print("• 修改项: %s" % "; ".join(did))
    print("• 输出: %s（%.2f MB）" % (out, size / 1048576))
    print("• 下一步: 调用 apk_sign 工具（参数 apk 传该输出文件名）完成签名与导出")


def cmd_dex_strings(args):
    p, pat = apk_path(args[0]), args[1]
    try:
        rx = re.compile(pat)
    except re.error as e:
        sys.exit("✗ 无效正则: %s" % e)
    hits, total = [], 0
    for name, dex in load_dexes(p):
        for s in dex.all_strings():
            if rx.search(s):
                total += 1
                if len(hits) < MAX_HITS:
                    hits.append("[%s] %s" % (name, s))
    if not total:
        sys.exit("✗ 无命中（正则: %s）" % pat)
    print("✓ 字符串搜索命中 %d 条%s（正则: %s）"
          % (total, "，仅显示前 %d" % MAX_HITS if total > MAX_HITS else "", pat))
    print("\n".join(hits))
    print("提示: 命中后用 dex-refs 确认代码引用位置，再 dex-method 反汇编上下文。")


def cmd_dex_refs(args):
    p, pat = apk_path(args[0]), args[1]
    try:
        rx = re.compile(pat)
    except re.error as e:
        sys.exit("✗ 无效正则: %s" % e)
    hits = list(find_string_code_refs(p, rx))
    if not hits:
        sys.exit("✗ 无 const-string 代码引用（正则: %s）" % pat)
    shown = hits[:MAX_HITS]
    print("✓ 代码引用 %d 处%s（正则: %s）"
          % (len(hits), "，仅显示前 %d" % MAX_HITS if len(hits) > MAX_HITS else "", pat))
    for dex_name, cls, meth, strings in shown:
        print("[%s] %s->%s" % (dex_name, cls, meth))
        for s in sorted(strings):
            print("    %r" % s)


def cmd_dex_class(args):
    p, cls = apk_path(args[0]), args[1]
    if not (cls.startswith("L") and cls.endswith(";")):
        sys.exit("✗ 类名格式应为 Lcom/a/B;，当前: %s" % cls)
    for name, dex in load_dexes(p):
        c = dex.find_class(cls)
        if c is None:
            continue
        print("✓ 类 %s（%s）" % (cls, name))
        methods = dex.class_methods(c["cdata"])
        total = len(methods)
        for i, m in enumerate(methods):
            if i >= MAX_CLASS_METHODS:
                print("…（共 %d 个方法，仅显示前 %d；用 dex-method 按方法名反汇编目标）" % (total, MAX_CLASS_METHODS))
                break
            tag = ("native" if m["access"] & 0x100
                   else ("无code" if not m["code_off"] else "code@0x%x" % m["code_off"]))
            print("  %s%s  [%s]" % (m["name"], m["proto"], tag))
        return
    sys.exit("✗ 类未找到: %s（注意混淆后类名，可先用 dex-strings 搜特征字符串定位）" % cls)


def cmd_dex_fields(args):
    p, cls = apk_path(args[0]), args[1]
    if not (cls.startswith("L") and cls.endswith(";")):
        sys.exit("✗ 类名格式应为 Lcom/a/B;，当前: %s" % cls)
    for name, dex in load_dexes(p):
        c = dex.find_class(cls)
        if c is None:
            continue
        fields = dex.class_fields(c["cdata"])
        print("✓ 类 %s 的字段（%s，共 %d 个）" % (cls, name, len(fields)))
        if not fields:
            print("  （无字段：空类或无 class_data）")
        for section, is_static in (("static 静态字段", True), ("instance 实例字段", False)):
            group = [f for f in fields if f["static"] == is_static]
            if not group:
                continue
            print("── %s（%d）" % (section, len(group)))
            for f in group:
                acc = field_acc_str(f["access"]) or "default"
                print("  %-28s %s  [%s]" % (f["name"], _desc_to_java(f["type"]), acc))
        print("提示: 字段语义不明（加密混淆）时，配合 dex-class 看方法、dex-refs 搜 UI 文案锚点定位写入处。")
        return
    sys.exit("✗ 类未找到: %s（注意混淆后类名，可先用 dex-strings 搜特征字符串定位）" % cls)


def cmd_dex_method(args):
    p, cls, mname = apk_path(args[0]), args[1], args[2]
    # 可选分页：dex-method <apk> <class> <method> [offset] [limit]
    offset = int(args[3]) if len(args) > 3 and args[3].lstrip("-").isdigit() else 0
    limit = int(args[4]) if len(args) > 4 and args[4].lstrip("-").isdigit() else MAX_SMALI_LINES
    if offset < 0:
        offset = 0
    if limit <= 0 or limit > 2000:
        limit = 2000
    dexes = load_dexes(p)
    dname, dex, m = resolve_method(dexes, cls, mname)
    if m is None:
        sys.exit("✗ 方法未找到: %s->%s（先用 dex-class 核对方法名）" % (cls, mname))
    ci, lines = disassemble(dex, m["code_off"])
    print("✓ %s->%s%s（%s, code_off=0x%x）"
          % (cls, mname, m["proto"], dname, m["code_off"]))
    print("  registers=%d ins=%d outs=%d insns_size=%d  共 %d 行 smali" % (ci["regs"], ci["ins"], ci["outs"], ci["insns_size"], len(lines)))
    total = len(lines)
    page = lines[offset:offset + limit]
    if offset:
        print("── 第 %d-%d 行（共 %d 行）" % (offset + 1, min(offset + limit, total), total))
    print("\n".join(page))
    if offset + limit < total:
        print("…（未完，下一页: 追加参数 offset=%d limit=%d）" % (offset + limit, limit))
    print("提示: 补丁可直接改某行 smali 后整段交给 dex-smali 重写；或 dex-return 一键强制返回值。")


def cmd_dex_return(args):
    p, cls, mname, val = apk_path(args[0]), args[1], args[2], args[3]
    if val not in ("true", "false", "null", "void"):
        sys.exit("✗ value 只能是 true/false/null/void")
    dexes = load_dexes(p)
    dname, dex, m = resolve_method(dexes, cls, mname)
    if m is None:
        sys.exit("✗ 方法未找到: %s->%s" % (cls, mname))
    ret_desc = m["proto"].split(")")[-1]
    dex.patch_return(m["code_off"], ret_desc, val)
    new_dex = dex.finalize()
    _write_dex_back(p, dname, new_dex)
    print("✓ 已补丁 %s->%s%s 强制返回 %s（%s，原地 nop 填充，SHA-1/Adler32 已重算）"
          % (cls, mname, m["proto"], val, dname))


def cmd_dex_smali(args):
    p, cls, mname, smali_file = apk_path(args[0]), args[1], args[2], args[3]
    sf = smali_file if smali_file.startswith("/") else os.path.join(APK_DIR, smali_file)
    if not os.path.isfile(sf):
        sys.exit("✗ smali 文件不存在: %s（先用 run_terminal_command 写入新方法体）" % sf)
    with open(sf, "r", encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f if ln.strip()]
    dexes = load_dexes(p)
    dname, dex, m = resolve_method(dexes, cls, mname)
    if m is None:
        sys.exit("✗ 方法未找到: %s->%s" % (cls, mname))
    # 汇编（未知引用自动 intern 进池，索引全量重映射）
    interner, words = assemble_interned(dex, lines)
    ci = dex.code_insns(m["code_off"])
    outs = compute_outs(words)
    code_item = build_code_item(ci["regs"], ci["ins"], outs, words)
    new_dex = build_dex(dex, replacements={m["code_off"]: code_item}, interner=interner)
    new_dex = DexFile(new_dex).finalize()
    _write_dex_back(p, dname, new_dex)
    print("✓ 已重写 %s->%s%s（%d 指令字，outs=%d，整 DEX 重写 + 池扩容，%s）"
          % (cls, mname, m["proto"], len(words), outs, dname))


def cmd_dex_string_edit(args):
    p, old, new, out = apk_path(args[0]), args[1], args[2], out_path(args[3])
    from reapk.dex._leb import enc_mutf8
    if len(enc_mutf8(new)) > len(enc_mutf8(old)):
        sys.exit("✗ 新字符串不能比旧字符串长（原地修改限制）：新 %d > 旧 %d 字节（MUTF-8 编码后长度）"
                 % (len(enc_mutf8(new)), len(enc_mutf8(old))))
    replaced = _patch_string_in_dexes(p, old, new, save_to=out)
    if replaced == 0:
        sys.exit("✗ 未在 dex 字符串池中找到: %r" % old)
    print("✓ 已替换 %d 处字符串 %r -> %r（原地 MUTF-8 写回，校验和已重算）" % (replaced, old, new))
    print("• 输出: %s（未签名）" % out)
    print("• 下一步: 调用 apk_sign 工具（参数 apk 传该输出文件名）完成签名与导出")


def cmd_rebuild(args):
    p, out = apk_path(args[0]), out_path(args[1])
    apk = Apk.open(p)
    apk.save(out)
    print("✓ 已重打包（zipaligned，未签名）: %s（%.2f MB）"
          % (out, os.path.getsize(out) / 1048576))


def _load_arsc(p: str):
    """读取 resources.arsc -> Arsc，缺失时报错退出。"""
    with zipfile.ZipFile(p) as zf:
        if "resources.arsc" not in zf.namelist():
            sys.exit("✗ 该 APK 无 resources.arsc（可能资源已被抽取/加固）")
        return Arsc(zf.read("resources.arsc"))


def _lookup_rid(arsc, loc):
    """把资源 locator 解析为 rid 列表。

    支持：
      string/app_name           type/entry 精确
      @string/app_name          @ 前缀
      0x7f010000                十六进制 rid（大小写/0x 前缀均可）
      app_name                   entry 名模糊（唯一命中时）
      com.pkg:string/app_name   带包名（忽略包名，取最后一段 type/entry）
    """
    s = loc.strip()
    if s.startswith("@"):
        s = s[1:]
    if "/" in s and not s.startswith("0x"):
        # 带包名形式 com.pkg:type/entry -> 取冒号后
        if ":" in s:
            s = s.split(":", 1)[1]
        type_part, entry_part = s.split("/", 1)
        want = "%s/%s" % (type_part, entry_part)
        hits = [rid for rid, nm in arsc.names.items() if nm == want]
        if hits:
            return hits
        # 兜底：type 精确 + entry 模糊
        entry_lower = entry_part.lower()
        return [rid for rid, nm in arsc.names.items()
                if nm.lower() == "%s/%s" % (type_part.lower(), entry_lower)]
    if s.lower().startswith("0x"):
        try:
            rid = int(s, 16)
        except ValueError:
            sys.exit("✗ 无效 rid: %s" % loc)
        return [rid] if rid in arsc.values else []
    # 纯 entry 名模糊：先精确匹配 entry，再子串模糊
    exact = [rid for rid, nm in arsc.names.items()
             if nm.rsplit("/", 1)[-1] == s]
    if exact:
        return exact
    lower = s.lower()
    return [rid for rid, nm in arsc.names.items()
            if lower in nm.rsplit("/", 1)[-1].lower()]


def cmd_resource_read(args):
    p = apk_path(args[0])
    arsc = _load_arsc(p)
    locs = args[1:]
    if not locs:
        sys.exit("✗ 需至少一个资源 locator（如 string/app_name 或 0x7f010000）")
    print("✓ 资源读取（%s，共 %d 个资源条目，%d 个含名称）"
          % (os.path.basename(p), len(arsc.values), len(arsc.names)))
    for loc in locs:
        rids = _lookup_rid(arsc, loc)
        if not rids:
            print("✗ %-28s 未找到" % loc)
            continue
        for rid in rids:
            name = arsc.names.get(rid, arsc.type_names.get(rid, ""))
            val = arsc.format(rid)
            if val is None:
                vtype, vdata = arsc.values[rid]
                val = _fmt_raw(vtype, vdata, arsc)
            label = ("%s" % name) if name else "@0x%08x" % rid
            print("  %-28s 0x%08x  %s" % (label, rid, val))
    print("提示: locator 支持 type/entry（string/app_name）、@前缀、0x 十六进制 rid、entry 名模糊。")


def _fmt_raw(vtype, vdata, arsc):
    """绕过 format 的类型兜底（含 string/ref 之外的类型）。"""
    from reapk.axml import T_STRING, T_REFERENCE, T_INT_BOOL, T_INT_HEX, T_INT_DEC, T_FLOAT
    gs = arsc.global_strings
    if vtype == T_STRING:
        return gs[vdata] if vdata < len(gs) else ""
    if vtype == T_REFERENCE:
        r = arsc.resolve(vdata)
        return "@%s" % (r if r else "0x%08x" % vdata)
    if vtype == T_INT_BOOL:
        return "true" if vdata != 0 else "false"
    if vtype == T_INT_HEX:
        return "0x%x" % vdata
    if vtype == T_INT_DEC:
        return str(vdata if vdata < 0x80000000 else vdata - 0x100000000)
    if vtype == T_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", vdata))[0])
    return str(vdata)


# ---------------------------------------------------------------- dex-xref

# 指令引用类型：opcode -> (kind, 格式)。kind: method/field/type
# 21c = 2 个 code unit，idx 在 w1；31c 在 w1|w2<<16；35c/3rc 的 idx 在 w1；22c 在 w1
_XREF_OPS = {
    # type 引用（const-class/check-cast/instance-of/new-instance/new-array/filled-new-array）
    0x1C: "type", 0x1F: "type", 0x20: "type", 0x22: "type", 0x23: "type",
    0x24: "type", 0x25: "type",
    # field 引用（iget*/iput*/sget*/sput*）
    0x52: "field", 0x53: "field", 0x54: "field", 0x55: "field", 0x56: "field",
    0x57: "field", 0x58: "field", 0x59: "field", 0x5A: "field", 0x5B: "field",
    0x5C: "field", 0x5D: "field", 0x5E: "field", 0x5F: "field", 0x60: "field",
    0x61: "field", 0x62: "field", 0x63: "field", 0x64: "field", 0x65: "field",
    0x66: "field", 0x67: "field", 0x68: "field", 0x69: "field", 0x6A: "field",
    0x6B: "field", 0x6C: "field", 0x6D: "field",
    # method 引用（invoke-*）
    0x6E: "method", 0x6F: "method", 0x70: "method", 0x71: "method", 0x72: "method",
    0x74: "method", 0x75: "method", 0x76: "method", 0x77: "method", 0x78: "method",
    0xFA: "method", 0xFB: "method",
}


def _xref_method_index(dex, cls, mname):
    """在 dex 里找方法名匹配的 method_idx 集合（跨所有引用处用 idx 匹配）。"""
    return {i for i in range(dex.n_method) if dex.method_ref(i)[1] == mname}


def _xref_field_index(dex, cls, fname):
    return {i for i in range(dex.n_field) if dex.field_ref(i)[1] == fname}


def _xref_type_index(dex, cls):
    return {i for i in range(dex.n_type) if dex.type(i) == cls}


def cmd_dex_xref(args):
    """dex 方法/字段/类引用查询：谁引用了目标 method/field/type。

    用法: dex-xref <apk> <kind> <目标>
      kind: method | field | type
      目标（method）: Lcom/a/B;->foo(Ljava/lang/String;)V  或 Lcom/a/B;->foo
      目标（field） : Lcom/a/B;->fieldName:I                  或 Lcom/a/B;->fieldName
      目标（type）  : Lcom/a/B;                               或 com.a.B
    """
    p, kind, target = apk_path(args[0]), args[1], args[2]
    if kind not in ("method", "field", "type"):
        sys.exit("✗ kind 只能是 method/field/type，当前: %s" % kind)

    # 解析目标为 (owner, name)
    owner, name = None, None
    if "->" in target:
        owner, rest = target.split("->", 1)
        name = rest.split("(", 1)[0].split(":", 1)[0]
    else:
        # type 直接给类描述符
        if kind == "type":
            owner = target
        else:
            sys.exit("✗ method/field 目标需含 ->，如 Lcom/a/B;->foo")

    # 归一化 owner 为 DEX 描述符 Lcom/a/B;
    if owner and not owner.startswith("L"):
        owner = "L" + owner.replace(".", "/") + ";"
    if kind == "type" and not owner.endswith(";"):
        owner = owner + ";"

    hits = []
    for dex_name, dex in load_dexes(p):
        # 计算目标 idx 集合
        if kind == "method":
            wanted = _xref_method_index(dex, owner, name)
            get_ref = lambda i: dex.method_ref(i)
        elif kind == "field":
            wanted = _xref_field_index(dex, owner, name)
            get_ref = lambda i: dex.field_ref(i)
        else:
            wanted = _xref_type_index(dex, owner)
            get_ref = lambda i: (dex.type(i), "", "")
        if not wanted:
            continue
        # 遍历所有类所有方法，找引用 wanted 的指令
        for ci in dex.classes():
            cdata = ci["cdata"]
            if not cdata:
                continue
            for m in dex.class_methods(cdata):
                if not m["code_off"]:
                    continue
                for off, idx in _scan_method_xrefs(dex, m["code_off"], kind, wanted):
                    hits.append((dex_name, ci["name"], m["name"] + m["proto"], off, idx, get_ref(idx)))

    if not hits:
        sys.exit("✗ 无引用（kind=%s target=%s）" % (kind, target))
    shown = hits[:MAX_HITS]
    print("✓ dex-xref 命中 %d 处%s（kind=%s target=%s）"
          % (len(hits), "，仅显示前 %d" % MAX_HITS if len(hits) > MAX_HITS else "", kind, target))
    for dex_name, cls, meth, off, idx, ref in shown:
        extra = ""
        if kind == "method":
            extra = "%s->%s%s" % ref
        elif kind == "field":
            extra = "%s->%s:%s" % ref
        else:
            extra = ref[0]
        print("[%s] %s->%s  (+0x%04x)  → %s" % (dex_name, cls, meth, off, extra))
    print("提示: 用 dex-method <apk> <class> <method> 反汇编引用处上下文。")


def _scan_method_xrefs(dex, code_off, kind, wanted):
    """扫描单个方法体，yield (code_unit_offset, idx) 命中的引用。

    所有 method/field/type 引用指令（const-class 21c、check-cast 21c、
    instance-of/new-instance 21c、new-array 22c、filled-new-array 35c/3rc、
    iget/iput/sget/sput 21c/22c、invoke-* 35c/3rc）的引用索引统一位于
    words[pos+1]（第 2 个 code unit 起），与具体格式无关，故无需区分。
    """
    from reapk.dex.disasm import insn_length
    data = dex.d
    info = dex.code_insns(code_off)
    start = info["insns_off"]
    n = info["insns_size"]
    words = struct.unpack_from("<%dH" % n, data, start)
    pos = 0
    while pos < n:
        op = words[pos] & 0xFF
        if _XREF_OPS.get(op) == kind and pos + 1 < n:
            idx = words[pos + 1]
            if idx in wanted:
                yield pos, idx
        length = insn_length(words, pos)
        if length < 1:
            break
        pos += length


# ---------------------------------------------------------------- 内部工具

def _write_dex_back(p: str, dex_name: str, new_dex: bytes):
    """把改后的 classesN.dex 写回 APK（其余条目原样复制，对齐不破坏）。"""
    tmp = p + ".tmp"
    with zipfile.ZipFile(p) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = new_dex if item.filename == dex_name else zin.read(item.filename)
            zout.writestr(item, data)
    os.replace(tmp, p)


def _patch_string_in_dexes(p: str, old: str, new: str, save_to: str) -> int:
    """在所有 dex 字符串池中原地替换 old -> new（只允许等长或变短）。

    变短时以 NUL 填充剩余空间并更新 MUTF-8 长度头，保持后续条目偏移不变。
    """
    from reapk.dex._leb import enc_mutf8, _uleb128

    old_bytes = enc_mutf8(old)   # uleb(utf16长度) + mutf8 字节 + NUL
    total = 0
    with zipfile.ZipFile(p) as zf:
        items = {n: zf.read(n) for n in zf.namelist()}
    for name in [n for n in items if re.fullmatch(r"classes\d*\.dex", n)]:
        data = items[name]
        dex = DexFile(data)
        hit = False
        for i in range(dex.n_str):
            off = struct.unpack_from("<I", data, dex.off_str + 4 * i)[0]
            _, text_off = _uleb128(data, off)
            end = data.index(0, text_off)
            if data[off:end + 1] != old_bytes:
                continue
            new_bytes = enc_mutf8(new)
            if len(new_bytes) > len(old_bytes):
                continue  # 不可能（已在外层校验），防御
            buf = bytearray(data)
            buf[off:off + len(old_bytes)] = new_bytes
            # 变短时尾部补 NUL，保证 string_data_item 总长不变、后续偏移不动
            pad = len(old_bytes) - len(new_bytes)
            if pad:
                buf[off + len(new_bytes):off + len(new_bytes) + pad] = b"\x00" * pad
            data = bytes(buf)
            hit = True
            total += 1
        if hit:
            items[name] = DexFile(data).finalize()
    # 写出新 APK
    tmp = save_to + ".tmp"
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in items.items():
            zout.writestr(name, data)
    os.replace(tmp, save_to)
    return total


COMMANDS = {
    "info": (cmd_info, 1, "<apk>"),
    "manifest-edit": (cmd_manifest_edit, 3, "<apk> <ops> <out.apk>"),
    "dex-strings": (cmd_dex_strings, 2, "<apk> <regex>"),
    "dex-refs": (cmd_dex_refs, 2, "<apk> <regex>"),
    "dex-class": (cmd_dex_class, 2, "<apk> <class>"),
    "dex-fields": (cmd_dex_fields, 2, "<apk> <class>"),
    "dex-method": (cmd_dex_method, 3, "<apk> <class> <method>"),
    "dex-return": (cmd_dex_return, 4, "<apk> <class> <method> <value>"),
    "dex-smali": (cmd_dex_smali, 4, "<apk> <class> <method> <smali_file>"),
    "dex-string-edit": (cmd_dex_string_edit, 4, "<apk> <old> <new> <out.apk>"),
    "resource-read": (cmd_resource_read, 2, "<apk> <locator>..."),
    "dex-xref": (cmd_dex_xref, 3, "<apk> <method|field|type> <目标>"),
    "rebuild": (cmd_rebuild, 2, "<apk> <out.apk>"),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        print("用法: apk_tool.py <子命令> <参数>")
        for k, (_, _, usage) in sorted(COMMANDS.items()):
            print("  %-18s %s" % (k, usage))
        return
    cmd = sys.argv[1]
    entry = COMMANDS.get(cmd)
    if entry is None:
        sys.exit("✗ 未知子命令: %s（--help 查看全部）" % cmd)
    fn, argc, usage = entry
    if len(sys.argv) - 2 < argc:
        sys.exit("✗ 参数不足: %s %s" % (cmd, usage))
    try:
        fn(sys.argv[2:])
    except SystemExit:
        raise
    except Exception as e:
        sys.exit("✗ %s: %s" % (type(e).__name__, e))


if __name__ == "__main__":
    main()
