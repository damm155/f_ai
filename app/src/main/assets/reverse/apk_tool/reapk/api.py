"""High-level, object-oriented API.

This is the ergonomic entry point most callers want::

    from reapk import Apk

    apk = Apk.open("app.apk")
    print(apk.manifest.package, len(apk.manifest.exported_components))

    apk.manifest.set_debuggable().set_cleartext()
    apk.manifest.add_permission("android.permission.INTERNET")
    apk.save("patched.apk")              # repackage (zipalign), unsigned

The classes here are thin, well-typed facades over the package's verified
procedural core (``axml``, ``dex``, ``zipalign``, ``sign`` ...).
"""
from __future__ import annotations

import io
import re
import zipfile
import zlib
from typing import List, Optional

from .axml import (
    Arsc, encode_axml, parse_axml, parse_axml_ir, patch_add_permission,
    patch_cleartext, patch_debuggable,
)
from .bundle import load_base_apk
from .dex import DexFile, disassemble
from .errors import BundleError, ZipError
from .manifest import analyze_manifest
from .zipalign import read_zip_entries, write_aligned_zip

_MANIFEST = "AndroidManifest.xml"
_V1_SIGNATURE = re.compile(rb"META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC)|SIG-[^/]+)", re.IGNORECASE)


class Manifest:
    """The ``AndroidManifest.xml`` of an APK: read its attack surface, or edit it.

    Reads are lazy and cached. Edits build a binary-XML IR and mark the manifest
    dirty; :meth:`to_bytes` re-encodes it with the native AXML writer.
    """

    def __init__(self, raw: bytes, arsc: Optional[Arsc] = None) -> None:
        self._raw = raw
        self._arsc = arsc
        self._info: Optional[dict] = None
        self._ir: Optional[dict] = None
        self._dirty = False

    # -- analysis ---------------------------------------------------------
    @property
    def info(self) -> dict:
        """Parsed manifest facts (package, components, flags, permissions)."""
        if self._info is None:
            self._info = analyze_manifest(parse_axml(self.to_bytes(), self._arsc))
        return self._info

    @property
    def package(self) -> str:
        return self.info["package"]

    @property
    def permissions(self) -> List[str]:
        return self.info["permissions"]

    @property
    def exported_components(self) -> List[dict]:
        return self.info["exported"]

    @property
    def debuggable(self) -> bool:
        return self.info["debuggable"] == "true"

    # -- editing ----------------------------------------------------------
    @property
    def dirty(self) -> bool:
        return self._dirty

    def _edit(self):
        if self._ir is None:
            self._ir = parse_axml_ir(self._raw)
        self._dirty = True
        self._info = None
        return self._ir

    def set_debuggable(self, value: bool = True) -> "Manifest":
        """Set the boolean ``android:debuggable`` on ``<application>``."""
        patch_debuggable(self._edit(), value)
        return self

    def set_cleartext(self, value: bool = True) -> "Manifest":
        """Set the boolean ``android:usesCleartextTraffic`` on ``<application>``."""
        patch_cleartext(self._edit(), value)
        return self

    def add_permission(self, name: str) -> "Manifest":
        """Add a ``<uses-permission>`` for ``name``."""
        patch_add_permission(self._edit(), name)
        return self

    def to_bytes(self) -> bytes:
        """Re-encode the (possibly edited) manifest to binary XML."""
        return encode_axml(self._ir) if self._ir is not None else self._raw


class Apk:
    """An Android package -- the high-level facade tying everything together."""

    def __init__(self, data: bytes, label: str = "<bytes>") -> None:
        self._data = data
        self.label = label
        self._zf = zipfile.ZipFile(io.BytesIO(data))
        self._manifest: Optional[Manifest] = None
        self._dex: Optional[List[DexFile]] = None

    # -- construction -----------------------------------------------------
    @classmethod
    def open(cls, path: str) -> "Apk":
        """Open an ``.apk`` or the base split of an ``.xapk`` / ``.apks`` bundle."""
        if path.lower().endswith(".apk"):
            with open(path, "rb") as f:
                return cls(f.read(), path)
        _zf, label = load_base_apk(path)        # picks + validates the base split
        if "!" not in label:
            with open(path, "rb") as f:
                return cls(f.read(), label)
        outer, member = label.split("!", 1)
        return cls(zipfile.ZipFile(outer).read(member), label)

    @classmethod
    def from_bytes(cls, data: bytes, label: str = "<bytes>") -> "Apk":
        return cls(data, label)

    # -- views ------------------------------------------------------------
    @property
    def manifest(self) -> Manifest:
        if self._manifest is None:
            try:
                arsc = Arsc(self._zf.read("resources.arsc"))
            except Exception:
                arsc = None
            self._manifest = Manifest(self._zf.read(_MANIFEST), arsc)
        return self._manifest

    @property
    def dex(self) -> List[DexFile]:
        """Every ``classesN.dex`` parsed into a :class:`DexFile`."""
        if self._dex is None:
            import re
            names = sorted(n for n in self._zf.namelist()
                           if re.fullmatch(r"classes\d*\.dex", n))
            self._dex = [DexFile(self._zf.read(n)) for n in names]
        return self._dex

    def analyze(self, secrets: bool = False) -> dict:
        """Attack-surface report: manifest facts (FBox 裁剪版无 secrets 扫描)."""
        return dict(self.manifest.info)

    def disassemble(self, method_sig: str) -> List[str]:
        """Disassemble ``Lpkg/Cls;->name()Ret`` to smali across all dex files."""
        import re
        m = re.match(r"(L[^;]+;)->([^(]+)\(", method_sig)
        if not m:
            raise ValueError("bad method signature: %s" % method_sig)
        for dex in self.dex:
            meth = dex.find_method(m.group(1), m.group(2))
            if meth:
                return disassemble(dex, meth["code_off"])[1]
        raise BundleError("method not found: %s" % method_sig)

    # -- output -----------------------------------------------------------
    def to_bytes(self, sign: bool = False, replacements: Optional[dict] = None) -> bytes:
        """Repackage as aligned unsigned APK, replacing only existing ZIP members.

        Unchanged entries retain their compressed payloads. APK signing blocks
        are outside ZIP members and are not emitted; v1 signing files are stripped.
        Signing is performed separately by Android-side apksig.
        """
        replacements = dict(replacements or {})
        if self._manifest is not None and self._manifest.dirty:
            if _MANIFEST in replacements:
                raise ValueError("manifest was edited and also supplied as a replacement")
            replacements[_MANIFEST] = self._manifest.to_bytes()
        entries = read_zip_entries(self._data)
        by_name = {}
        for entry in entries:
            name = entry["name"].decode("utf-8" if entry["flags"] & 0x800 else "cp437")
            by_name.setdefault(name, []).append(entry)
        for name, payload in replacements.items():
            matches = by_name.get(name, [])
            if len(matches) != 1:
                raise ValueError("replacement requires exactly one existing ZIP entry: %s" % name)
            entry = matches[0]
            if _V1_SIGNATURE.fullmatch(entry["name"]):
                raise ValueError("signature files cannot be replaced in an unsigned APK: %s" % name)
            if entry["method"] == zipfile.ZIP_STORED:
                raw = payload
            elif entry["method"] == zipfile.ZIP_DEFLATED:
                compressor = zlib.compressobj(wbits=-15)
                raw = compressor.compress(payload) + compressor.flush()
            else:
                raise ZipError("unsupported replacement compression method: %d" % entry["method"])
            entry.update(raw=raw, crc=zlib.crc32(payload) & 0xFFFFFFFF,
                         csize=len(raw), usize=len(payload))
        entries = [e for e in entries if not _V1_SIGNATURE.fullmatch(e["name"])]
        return write_aligned_zip(entries, comment=self._zf.comment)

    def save(self, path: str, sign: bool = False, replacements: Optional[dict] = None) -> None:
        """Write an aligned unsigned APK; signing is performed separately."""
        data = self.to_bytes(sign=sign, replacements=replacements)
        with open(path, "wb") as f:
            f.write(data)


__all__ = ["Apk", "Manifest"]
