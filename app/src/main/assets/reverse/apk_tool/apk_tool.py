#!/usr/bin/env python3
"""FBox APK 原生工具链驱动（基于 vendored reapk，纯 Python 标准库，无 Java）。

容器内统一入口，由 Android 侧 LinuxViewModel 经 shell 调用：
    python3 /root/apk-tool/apk_tool.py <子命令> <参数...>

子命令一览（输出统一为 UTF-8 文本，✓/✗ 标记成败，供 AI 直接阅读）：
  info <apk>                          manifest 分析：包名/版本/权限/导出组件/标志
  manifest-edit <apk> <ops> <out>     编辑 manifest（ops 见下），产出未签名 APK
  dex-strings <apk> <regex>           搜全部 dex 字符串（正则，限 200 条）
  fast-scan <apk> [keywords]          扫 libapp.so（UTF-8/UTF-16LE）和全部 DEX 字符串池
  dex-refs <apk> <regex>              搜 const-string 代码引用：谁在哪个方法加载了它
  dex-class <apk> <class>             列类的方法清单（class=Lcom/a/B; 格式）
  dex-fields <apk> <class>            列类的字段清单（static/instance、Java 类型、访问标志）
  dex-method <apk> <class> <name>     反汇编方法体为 smali（带 %04x: 地址前缀）
                                    可选分页：<apk> <class> <name> [offset] [limit]
                                    offset 起始行(0起)、limit 单页行数(默认400，最大2000)
  dex-return <apk> <class> <name> <v> 原地补丁：强制方法返回 true/false/null/void
  dex-smali <apk> <class> <name> <f>  smali 文本重写方法体（整 DEX 重写，支持扩容）
  dex-string-edit <apk> <old> <new> <out>  改字符串后重排/去重池并重映射引用（新串不可更长）
  resource-read <apk> <locator>...    按资源 locator 批量读 resources.arsc 值
  dex-xref <apk> <method|field|type> <目标>  dex 方法/字段/类引用查询（谁引用了目标）
  rebuild <apk> <out> [--replace ZIP_ENTRY=FILE]...  重打包为 aligned unsigned APK
                                    替换只接受已有条目；非压缩 SO 16 KiB，其余 stored 4 字节

ops 语法（逗号分隔多个）：debuggable=1,cleartext=1,perm=android.permission.XXX

路径说明：APK 相对路径按 /root/apk/ 解析，替换文件按容器当前目录解析；可传绝对路径。
签名由 Android 侧 apksig 单独完成。
"""
import argparse
import json
import os
import re
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from reapk import (  # noqa: E402
    Apk, Arsc, DexFile, Interner, find_string_code_refs,
    assemble_interned, build_code_item, build_dex, compute_outs,
    disassemble, encode_insn, insn_length,
)
from reapk.dex import field_acc_str, _desc_to_java  # noqa: E402

APK_DIR = "/root/apk"
MAX_HITS = 200          # 字符串/引用搜索上限，防大 dex 刷屏
MAX_KW_HITS = 8
CONTEXT_BEFORE = 14
CONTEXT_AFTER = 26
DEFAULT_FAST_SCAN_KEYWORDS = (
    "vip,member,premium,subscription,entitlement,unlock,paid,advert,admob,"
    "showad,show_ad,loadad,load_ad,banner,interstitial,reward,pangle,穿山甲,优量汇"
)
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


def _fast_scan_pattern(keyword, encoding):
    parts = []
    for char in keyword:
        variants = {char.encode(encoding), char.lower().encode(encoding), char.upper().encode(encoding)}
        parts.append(b"(?:" + b"|".join(re.escape(v) for v in sorted(variants)) + b")")
    return re.compile(b"".join(parts))


def cmd_fast_scan(args):
    p = apk_path(args[0])
    keywords_text = args[1] if len(args) > 1 and args[1].strip() else DEFAULT_FAST_SCAN_KEYWORDS
    keywords = list(dict.fromkeys(k.strip() for k in keywords_text.split(",") if k.strip()))
    if not keywords:
        sys.exit("✗ 关键词为空")
    patterns = {kw: [(encoding, label, _fast_scan_pattern(kw, encoding)) for encoding, label in
                     (("utf-8", "UTF-8"), ("utf-16-le", "UTF-16LE"))] for kw in keywords}
    hits, totals, sources = {kw: [] for kw in keywords}, {kw: 0 for kw in keywords}, []
    with zipfile.ZipFile(p) as zf:
        for name in sorted(n for n in zf.namelist() if re.fullmatch(r"lib/[^/]+/libapp\.so", n)):
            blob = zf.read(name)
            sources.append(name)
            for kw in keywords:
                for encoding, label, pattern in patterns[kw]:
                    for match in pattern.finditer(blob):
                        totals[kw] += 1
                        if len(hits[kw]) < MAX_KW_HITS:
                            if encoding == "utf-16-le":
                                # 二进制快照周围的随机字节常能解成貌似合法的 CJK 字符，
                                # UTF-16 命中只显示匹配词，避免把噪声伪装成上下文。
                                context = blob[match.start():match.end()].decode(encoding, "strict")
                            else:
                                lo = max(0, match.start() - CONTEXT_BEFORE)
                                hi = min(len(blob), match.end() + CONTEXT_AFTER)
                                context = blob[lo:hi].decode(encoding, "replace")
                            hits[kw].append("%s %s @0x%X  %r" % (name, label, match.start(), context))
        for name in sorted(n for n in zf.namelist() if re.fullmatch(r"classes\d*\.dex", n)):
            try:
                dex = DexFile(zf.read(name))
                strings = list(dex.all_strings())
            except Exception as e:
                sys.stderr.write("DEX 字符串扫描跳过 %s: %s\n" % (name, e))
                continue
            sources.append(name)
            for value in strings:
                lowered = value.casefold()
                for kw in keywords:
                    if kw.casefold() in lowered:
                        totals[kw] += 1
                        if len(hits[kw]) < MAX_KW_HITS:
                            hits[kw].append("%s 字符串: %r" % (name, value))
    if not sources:
        sys.exit("✗ 未找到可扫描的 libapp.so 或 DEX 字符串池")
    print("✓ 快速扫描完成：%s，关键词 %d 个，命中 %d 处" % (", ".join(sources), len(keywords), sum(totals.values())))
    print("SO 偏移为 ZIP 条目解压后的文件偏移，非函数 VA，也不是 APK 内 ZIP 偏移。")
    if not any(totals.values()):
        print("未命中任何关键词；扫描仅覆盖可见字符串，不能据此判断业务逻辑位置。")
        return
    for kw in keywords:
        if totals[kw]:
            print("  [%s] %d 处%s" % (kw, totals[kw],
                  "，仅显示前 %d（输出截断）" % MAX_KW_HITS if totals[kw] > MAX_KW_HITS else ""))
            for hit in hits[kw]:
                print("    " + hit)
    print("提示: DEX 命中用 dex-refs 查代码引用；SO 文件偏移仅用于字符串定位。")


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
    p, old, new = apk_path(args[0]), args[1], args[2]
    out = args[3] if args[3].startswith("/") else os.path.join(APK_DIR, args[3])
    from reapk.dex._leb import enc_mutf8
    if len(enc_mutf8(new)) > len(enc_mutf8(old)):
        sys.exit("✗ 新字符串不能比旧字符串长（原地修改限制）：新 %d > 旧 %d 字节（MUTF-8 编码后长度）"
                 % (len(enc_mutf8(new)), len(enc_mutf8(old))))
    replaced = _patch_string_in_dexes(p, old, new, save_to=out)
    if replaced == 0:
        sys.exit("✗ 未在 dex 字符串池中找到: %r" % old)
    print("✓ 已替换 %d 处字符串 %r -> %r（字符串池已重排/去重，引用与校验和已重算）" % (replaced, old, new))
    print("• 输出: %s（未签名）" % out)
    print("• 下一步: 调用 apk_sign 工具（参数 apk 传该输出文件名）完成签名与导出")


def cmd_rebuild(args):
    parser = argparse.ArgumentParser(prog="apk_tool.py rebuild")
    parser.add_argument("apk")
    parser.add_argument("out")
    parser.add_argument("--replace", action="append", default=[], metavar="ZIP_ENTRY=FILE")
    options = parser.parse_args(args)
    p = apk_path(options.apk)
    replacements = {}
    with zipfile.ZipFile(p) as zf:
        names = zf.namelist()
    for replacement in options.replace:
        name, separator, filename = replacement.partition("=")
        if not separator or not name or not filename:
            parser.error("--replace 需使用 ZIP条目=容器文件 格式")
        if names.count(name) != 1:
            parser.error("--replace 仅支持唯一存在的 ZIP 条目: %s" % name)
        if name in replacements:
            parser.error("--replace 重复指定 ZIP 条目: %s" % name)
        if not os.path.isfile(filename):
            parser.error("--replace 文件不存在或不是普通文件: %s" % filename)
        try:
            with open(filename, "rb") as f:
                replacements[name] = f.read()
        except OSError as e:
            parser.error("--replace 文件无法读取: %s" % e)
    out = out_path(options.out)
    Apk.open(p).save(out, replacements=replacements)
    print("✓ 已重打包（zipaligned，SO 16 KiB，其余 stored 4 字节；未签名）: %s（%.2f MB）"
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


def _xref_method_index(dex, cls, mname, signature=None):
    return {i for i in range(dex.n_method)
            if dex.method_ref(i)[:2] == (cls, mname)
            and (signature is None or dex.method_ref(i)[2] == signature)}


def _xref_field_index(dex, cls, fname, field_type=None):
    return {i for i in range(dex.n_field)
            if dex.field_ref(i)[:2] == (cls, fname)
            and (field_type is None or dex.field_ref(i)[2] == field_type)}


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

    owner, name, signature, field_type = None, None, None, None
    if kind == "type":
        owner = target
    elif "->" in target:
        owner, rest = target.split("->", 1)
        if kind == "method":
            name, separator, tail = rest.partition("(")
            if separator:
                signature = separator + tail
                if not re.fullmatch(r"\([^)]*\).+", signature):
                    sys.exit("✗ 无效 method signature: %s" % signature)
        else:
            name, separator, tail = rest.partition(":")
            if separator:
                field_type = tail
                if not field_type:
                    sys.exit("✗ field type 不能为空")
        if not owner or not name:
            sys.exit("✗ method/field 目标需包含 owner 和 name")
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
            wanted = _xref_method_index(dex, owner, name, signature)
            get_ref = lambda i: dex.method_ref(i)
        elif kind == "field":
            wanted = _xref_field_index(dex, owner, name, field_type)
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
    """把改后的 classesN.dex 写回 aligned unsigned APK，其余压缩数据保持不变。"""
    tmp = p + ".tmp"
    Apk.open(p).save(tmp, replacements={dex_name: new_dex})
    os.replace(tmp, p)


def _patch_string_in_dexes(p: str, old: str, new: str, save_to: str) -> int:
    """替换字符串后用现有 Interner 和 DEX writer 重排池与全部引用。"""
    from reapk.dex._leb import enc_mutf8, _uleb128

    old_bytes, new_bytes = enc_mutf8(old), enc_mutf8(new)
    if len(new_bytes) > len(old_bytes):
        raise ValueError("new MUTF-8 string must not be longer than the old string")
    padded = new_bytes + b"\0" * (len(old_bytes) - len(new_bytes))
    total, replacements = 0, {}
    for name, dex in load_dexes(p):
        data = dex.d
        buf = bytearray(data)
        hits = 0
        for i in range(dex.n_str):
            off = struct.unpack_from("<I", data, dex.off_str + 4 * i)[0]
            _, text_off = _uleb128(data, off)
            end = data.index(0, text_off)
            if data[off:end + 1] == old_bytes:
                # Equal-size assignment keeps every old offset valid until the writer remaps it.
                buf[off:off + len(old_bytes)] = padded
                hits += 1
        if hits:
            patched = DexFile(bytes(buf))
            interner = Interner(patched).finalize()
            replacements[name] = build_dex(patched, interner=interner)
            total += hits
    if not total:
        return 0
    save_to = out_path(save_to)
    tmp = save_to + ".tmp"
    Apk.open(p).save(tmp, replacements=replacements)
    os.replace(tmp, save_to)
    return total


COMMANDS = {
    "info": (cmd_info, 1, "<apk>"),
    "manifest-edit": (cmd_manifest_edit, 3, "<apk> <ops> <out.apk>"),
    "dex-strings": (cmd_dex_strings, 2, "<apk> <regex>"),
    "fast-scan": (cmd_fast_scan, 1, "<apk> [关键词,逗号分隔]"),
    "dex-refs": (cmd_dex_refs, 2, "<apk> <regex>"),
    "dex-class": (cmd_dex_class, 2, "<apk> <class>"),
    "dex-fields": (cmd_dex_fields, 2, "<apk> <class>"),
    "dex-method": (cmd_dex_method, 3, "<apk> <class> <method>"),
    "dex-return": (cmd_dex_return, 4, "<apk> <class> <method> <value>"),
    "dex-smali": (cmd_dex_smali, 4, "<apk> <class> <method> <smali_file>"),
    "dex-string-edit": (cmd_dex_string_edit, 4, "<apk> <old> <new> <out.apk>"),
    "resource-read": (cmd_resource_read, 2, "<apk> <locator>..."),
    "dex-xref": (cmd_dex_xref, 3, "<apk> <method|field|type> <目标>"),
    "rebuild": (cmd_rebuild, 2, "<apk> <out.apk> [--replace ZIP_ENTRY=FILE]..."),
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
    except BrokenPipeError:
        os._exit(0)
    except SystemExit:
        raise
    except Exception as e:
        sys.exit("✗ %s: %s" % (type(e).__name__, e))


if __name__ == "__main__":
    main()
