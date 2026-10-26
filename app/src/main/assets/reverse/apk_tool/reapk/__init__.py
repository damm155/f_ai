"""reapk -- a native, zero-Java APK toolkit (FBox vendored subset).

Parses and rewrites Android's binary formats directly: AndroidManifest (AXML),
resources.arsc, the DEX bytecode (disassemble / assemble / whole-DEX rewrite).
No apktool, no apksigner, no Java.

FBox 裁剪版：去掉了 sign.py（cryptography 依赖，签名走 Android 侧 apksig）、
secrets.py、commands.py、cli.py、engines.py、playground.py，只保留容器 AI
工具链需要的纯标准库核心模块。上游 MIT License 见同目录 LICENSE。
"""
from .errors import (
    REapkError, AssembleError, AxmlError, BundleError, DexError, EngineError,
    SignError, ZipError,
)
from .api import Apk, Manifest
from .lookup import find_class_dex
from .xrefs import find_string_code_refs
from .axml import Arsc, encode_axml, parse_axml, parse_axml_ir
from .manifest import analyze_manifest
from .bundle import detect_framework, load_base_apk, read_manifest_bytes
from .zipalign import read_zip_entries, stored_entry, write_aligned_zip
from .dex import (
    Assembler, DexFile, Interner, PoolModel, OPCODES, assemble,
    assemble_interned, build_code_item, build_dex, compute_outs, decode_insn,
    disassemble, encode_insn, insn_length,
)

__version__ = "0.1.1-fbox"

__all__ = [
    "Apk", "Manifest", "find_class_dex", "find_string_code_refs",
    "REapkError", "AxmlError", "BundleError", "ZipError", "DexError",
    "AssembleError", "SignError", "EngineError",
    "Arsc", "encode_axml", "parse_axml", "parse_axml_ir",
    "analyze_manifest",
    "detect_framework", "load_base_apk", "read_manifest_bytes",
    "read_zip_entries", "stored_entry", "write_aligned_zip",
    "DexFile", "disassemble", "decode_insn", "insn_length", "OPCODES",
    "Assembler", "assemble", "assemble_interned", "encode_insn",
    "build_code_item", "compute_outs", "PoolModel", "Interner", "build_dex",
]
