"""Find DEX instructions that load strings matching a regular expression."""

import re
import struct
import sys
import zipfile

from .dex._leb import _uleb128
from .dex.disasm import insn_length
from .dex.file import DexFile


_DEX_NAME = re.compile(r"classes\d*\.dex")


def _code_methods(dex):
    """Yield (class type index, method index, code offset) without decoding names."""
    data = dex.d
    for index in range(dex.n_class):
        class_def = dex.off_class + 32 * index
        class_idx, cdata_off = struct.unpack_from("<I20xI", data, class_def)
        if not cdata_off:
            continue
        offset = cdata_off
        static_fields, offset = _uleb128(data, offset)
        instance_fields, offset = _uleb128(data, offset)
        direct_methods, offset = _uleb128(data, offset)
        virtual_methods, offset = _uleb128(data, offset)
        for _ in range(static_fields + instance_fields):
            _, offset = _uleb128(data, offset)
            _, offset = _uleb128(data, offset)
        for count in (direct_methods, virtual_methods):
            method_idx = 0
            for _ in range(count):
                delta, offset = _uleb128(data, offset)
                _, offset = _uleb128(data, offset)
                code_off, offset = _uleb128(data, offset)
                method_idx += delta
                if code_off:
                    yield class_idx, method_idx, code_off


def _string_indices(dex, pattern):
    return {index for index in range(dex.n_str)
            if pattern.search(dex.string(index))}


def _method_string_refs(dex, code_off, wanted):
    data = dex.d
    info = dex.code_insns(code_off)
    start = info["insns_off"]
    end = start + info["insns_size"] * 2
    if end > len(data):
        raise ValueError("DEX code_item extends past end of file")
    words = (memoryview(data)[start:end].cast("H") if sys.byteorder == "little"
             else struct.unpack_from(f"<{info['insns_size']}H", data, start))
    found = set()
    pos = 0
    while pos < len(words):
        opcode = words[pos] & 0xFF
        if opcode == 0x1A and pos + 1 < len(words):
            string_idx = words[pos + 1]
            if string_idx in wanted:
                found.add(string_idx)
        elif opcode == 0x1B and pos + 2 < len(words):
            string_idx = words[pos + 1] | (words[pos + 2] << 16)
            if string_idx in wanted:
                found.add(string_idx)
        length = insn_length(words, pos)
        if length < 1 or pos + length > len(words):
            raise ValueError("invalid DEX instruction length")
        pos += length
    return found


def find_string_code_refs(apk_path, query):
    """Yield (DEX, class descriptor, method name, matched strings) for code refs.

    ``query`` is a case-sensitive regular expression, matching ASC's string
    search syntax. Only const-string and const-string/jumbo instructions count;
    a string-pool entry without a code reference is not a hit.
    """
    pattern = re.compile(query)
    with zipfile.ZipFile(apk_path) as archive:
        for entry in archive.infolist():
            if not _DEX_NAME.fullmatch(entry.filename):
                continue
            dex = DexFile(archive.read(entry))
            wanted = _string_indices(dex, pattern)
            if not wanted:
                continue
            for class_idx, method_idx, code_off in _code_methods(dex):
                matched = _method_string_refs(dex, code_off, wanted)
                if matched:
                    _, method, _ = dex.method_ref(method_idx)
                    yield (entry.filename, dex.type(class_idx), method,
                           tuple(sorted(dex.string(idx) for idx in matched)))
