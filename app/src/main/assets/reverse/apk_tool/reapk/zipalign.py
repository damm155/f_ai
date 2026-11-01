import struct
from .errors import ZipError
import zlib


def read_zip_entries(data):
    """Parse a ZIP's central directory, retaining compressed payloads and metadata."""
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    while eocd >= 0:
        if eocd + 22 <= len(data):
            comment_size = struct.unpack_from("<H", data, eocd + 20)[0]
            if eocd + 22 + comment_size == len(data):
                break
        eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557), eocd)
    if eocd < 0:
        raise ZipError("missing ZIP end of central directory")
    disk, cd_disk, disk_count, total, cd_size, off = struct.unpack_from("<4H2I", data, eocd + 4)
    if disk or cd_disk or disk_count != total:
        raise ZipError("multi-disk ZIP is not supported")
    if total == 0xFFFF or cd_size == 0xFFFFFFFF or off == 0xFFFFFFFF:
        raise ZipError("ZIP64 is not supported")
    cd_start, cd_end = off, off + cd_size
    if cd_end > eocd:
        raise ZipError("central directory outside ZIP bounds")
    entries = []
    for _ in range(total):
        if off + 46 > cd_end or data[off:off + 4] != b"PK\x01\x02":
            raise ZipError("truncated or invalid central directory")
        made_by, version, flags, method, mtime, mdate = struct.unpack_from("<6H", data, off + 4)
        crc, csize, usize = struct.unpack_from("<III", data, off + 16)
        nlen, elen, clen, disk_start, internal_attr, external_attr, lho = struct.unpack_from(
            "<5H2I", data, off + 28)
        end = off + 46 + nlen + elen + clen
        if end > cd_end:
            raise ZipError("truncated central-directory entry")
        if disk_start or csize == 0xFFFFFFFF or usize == 0xFFFFFFFF or lho == 0xFFFFFFFF:
            raise ZipError("ZIP64 or multi-disk entry is not supported")
        if flags & 0x41:
            raise ZipError("encrypted ZIP entries are not supported")
        name = data[off + 46:off + 46 + nlen]
        if lho + 30 > cd_start or data[lho:lho + 4] != b"PK\x03\x04":
            raise ZipError("invalid local ZIP header")
        local_version, local_flags, local_method = struct.unpack_from("<3H", data, lho + 4)
        lnlen, lelen = struct.unpack_from("<HH", data, lho + 26)
        dstart = lho + 30 + lnlen + lelen
        if dstart + csize > cd_start or data[lho + 30:lho + 30 + lnlen] != name:
            raise ZipError("local entry outside ZIP bounds or name mismatch")
        if local_method != method or local_flags != flags:
            raise ZipError("local and central ZIP entry disagree")
        entries.append({"name": name, "method": method, "flags": flags,
                        "mtime": mtime, "mdate": mdate, "crc": crc,
                        "csize": csize, "usize": usize, "version": version,
                        "local_version": local_version, "made_by": made_by,
                        "extra": data[off + 46 + nlen:off + 46 + nlen + elen],
                        "comment": data[off + 46 + nlen + elen:end],
                        "local_extra": data[lho + 30 + lnlen:dstart],
                        "internal_attr": internal_attr, "external_attr": external_attr,
                        "raw": data[dstart:dstart + csize]})
        off = end
    if off != cd_end:
        raise ZipError("central-directory size does not match its entries")
    return entries


def _without_alignment_extra(extra):
    out, pos = bytearray(), 0
    while pos + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, pos)
        end = pos + 4 + size
        if end > len(extra):
            break
        if tag != 0xD935:
            out += extra[pos:end]
        pos = end
    return bytes(out) + extra[pos:]


def write_aligned_zip(entries, comment=b""):
    """Write unsigned ZIP32, aligning stored SOs to 16 KiB and other stored data to 4."""
    out = bytearray()
    records = []
    if len(entries) >= 0xFFFF or len(comment) > 0xFFFF:
        raise ZipError("ZIP32 entry count or comment length exceeded")
    for e in entries:
        name = e["name"]
        if e["method"] == 0:
            align = 16384 if name.endswith(b".so") else 4
        else:
            align = 1
        lho = len(out)
        extra = _without_alignment_extra(e.get("local_extra", b""))
        data_off = lho + 30 + len(name) + len(extra)
        pad = (-data_off) % align
        if pad:
            while pad < 6:
                pad += align
            extra += struct.pack("<HHH", 0xD935, pad - 4, align) + b"\0" * (pad - 6)
        if len(name) > 0xFFFF or len(extra) > 0xFFFF or lho > 0xFFFFFFFF:
            raise ZipError("ZIP32 local-header limit exceeded")
        flags = e["flags"] & ~0x08  # Payloads exclude descriptors; sizes are in the header.
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, e.get("local_version", 20),
                           flags, e["method"], e["mtime"], e["mdate"], e["crc"],
                           e["csize"], e["usize"], len(name), len(extra))
        out += name + extra + e["raw"]
        records.append((e, lho))
    cd_off = len(out)
    for e, lho in records:
        name, extra, entry_comment = e["name"], e.get("extra", b""), e.get("comment", b"")
        if len(extra) > 0xFFFF or len(entry_comment) > 0xFFFF:
            raise ZipError("ZIP32 central-header limit exceeded")
        out += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, e.get("made_by", 20),
                           e.get("version", 20), e["flags"] & ~0x08, e["method"],
                           e["mtime"], e["mdate"], e["crc"], e["csize"], e["usize"],
                           len(name), len(extra), len(entry_comment), 0,
                           e.get("internal_attr", 0), e.get("external_attr", 0), lho)
        out += name + extra + entry_comment
    cd_size = len(out) - cd_off
    if cd_size > 0xFFFFFFFF or cd_off > 0xFFFFFFFF:
        raise ZipError("ZIP32 central-directory limit exceeded")
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(records), len(records),
                       cd_size, cd_off, len(comment)) + comment
    return bytes(out)

def stored_entry(name, data):
    return {"name": name if isinstance(name, bytes) else name.encode(), "method": 0,
            "flags": 0, "mtime": 0, "mdate": 0x21, "crc": zlib.crc32(data) & 0xFFFFFFFF,
            "csize": len(data), "usize": len(data), "raw": data}