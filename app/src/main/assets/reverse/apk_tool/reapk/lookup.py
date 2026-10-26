"""Targeted, read-only lookups that avoid loading an entire APK into memory."""

import mmap
import re
import struct
import zipfile
import zlib

from .dex.file import _find_class_def


_DEX_NAME = re.compile(r"classes\d*\.dex")
_CD_HEADER = struct.Struct("<4s6H3I5H2I")


def _dex_entries(mm):
    """Read standard ZIP central-directory DEX entries; return None for ZIP64."""
    end = len(mm)
    eocd = mm.rfind(b"PK\x05\x06", max(0, end - 65557))
    if eocd < 0 or eocd + 22 > end:
        return None
    count, cd_size, cd_off = struct.unpack_from("<HII", mm, eocd + 10)
    if count == 0xFFFF or cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF:
        return None
    comment_len = struct.unpack_from("<H", mm, eocd + 20)[0]
    if eocd + 22 + comment_len != end or cd_off + cd_size != eocd:
        return None
    entries = []
    seen = set()
    ptr = cd_off
    cd_end = cd_off + cd_size
    while True:
        name_start = mm.find(b"classes", ptr, cd_end)
        if name_start < 0:
            break
        ptr = name_start + 7
        header_off = name_start - _CD_HEADER.size
        if header_off < cd_off or mm[header_off:header_off + 4] != b"PK\x01\x02":
            continue
        fields = _CD_HEADER.unpack_from(mm, header_off)
        flags, method = fields[3], fields[4]
        compressed_size, uncompressed_size = fields[8], fields[9]
        name_len = fields[10]
        local_off = fields[16]
        if name_start + name_len > cd_end:
            continue
        name_bytes = mm[name_start:name_start + name_len]
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError:
            name = ""
        if _DEX_NAME.fullmatch(name) and name not in seen:
            if (flags & 1 or method not in (0, 8) or compressed_size == 0xFFFFFFFF
                    or uncompressed_size == 0xFFFFFFFF or local_off == 0xFFFFFFFF):
                return None
            seen.add(name)
            entries.append((name, compressed_size, uncompressed_size, local_off, method))
    return sorted(entries, key=lambda entry: entry[1])


def _read_dex_entry(mm, entry, class_desc):
    name, compressed_size, uncompressed_size, local_off, method = entry
    if local_off + 30 > len(mm) or mm[local_off:local_off + 4] != b"PK\x03\x04":
        raise zipfile.BadZipFile("invalid DEX local header")
    name_len, extra_len = struct.unpack_from("<HH", mm, local_off + 26)
    data_off = local_off + 30 + name_len + extra_len
    if mm[local_off + 30:local_off + 30 + name_len] != name.encode("ascii"):
        raise zipfile.BadZipFile("DEX local and central names differ")
    if data_off + compressed_size > len(mm):
        raise zipfile.BadZipFile("DEX data extends past APK")
    if method == 0:
        if compressed_size != uncompressed_size:
            raise zipfile.BadZipFile("stored DEX size mismatch")
        if _find_class_def(mm, data_off, uncompressed_size, class_desc) is not None:
            return name, mm[data_off:data_off + uncompressed_size]
    else:
        data = zlib.decompress(mm[data_off:data_off + compressed_size], -15)
        if len(data) != uncompressed_size:
            raise zipfile.BadZipFile("inflated DEX size mismatch")
        if _find_class_def(data, 0, len(data), class_desc) is not None:
            return name, data
    return None


def _zipfile_fallback(apk_path, class_desc):
    from .dex import DexFile

    with zipfile.ZipFile(apk_path) as archive:
        entries = sorted((entry for entry in archive.infolist()
                          if _DEX_NAME.fullmatch(entry.filename)),
                         key=lambda entry: entry.compress_size)
        for entry in entries:
            data = archive.read(entry)
            if DexFile(data).find_class(class_desc) is not None:
                return entry.filename, data
    return None


def find_class_dex(apk_path, class_desc):
    """Return ``(DEX entry name, DEX bytes)`` defining an exact class, or ``None``.

    Search smaller DEX entries first so late, compact splits do not require
    parsing every earlier DEX. Only the current candidate is decompressed.
    This path accepts an APK file; bundles can be opened through :class:`Apk`.
    """
    if not isinstance(class_desc, str) or not re.fullmatch(r"L[^;]+;", class_desc):
        raise ValueError("class_desc must be a DEX descriptor such as Lpkg/Class;")
    if "\0" in class_desc:
        raise ValueError("class_desc cannot contain NUL")
    with open(apk_path, "rb") as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            entries = _dex_entries(mm)
            if entries is not None:
                for entry in entries:
                    hit = _read_dex_entry(mm, entry, class_desc)
                    if hit is not None:
                        return hit
                return None
    return _zipfile_fallback(apk_path, class_desc)
