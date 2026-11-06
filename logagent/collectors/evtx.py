"""Read Windows .evtx files without Windows (no wevtutil) and without third-party packages.

An .evtx file is a 4 KB file header followed by 64 KB chunks. Each chunk holds event records whose body is
"binary XML" (BinXML): a token stream where element/attribute names live once in the chunk's string table and the
event's shape is a template filled with substitution values. This turns every record back into the same
<Event xmlns=...> XML that wevtutil prints, so the normal Windows parser handles the rest.

Reference: the libevtx format documentation (Joachim Metz) and Microsoft's MS-EVEN6 BinXml grammar.
"""
from __future__ import annotations

import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterator

CHUNK = 0x10000
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class EvtxError(ValueError):
    pass


def _esc(s: str, attr: bool = False) -> str:
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = "".join(c if c in "\t\n\r" or ord(c) >= 0x20 else " " for c in s)  # XML 1.0 forbids most control chars
    return s.replace("'", "&apos;").replace('"', "&quot;") if attr else s


def _filetime(v: int) -> str:
    if not v:
        return ""
    t = _EPOCH + timedelta(microseconds=v // 10)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{v % 10_000_000:07d}Z"


def _systime(b: bytes) -> str:
    y, mo, _dow, d, h, mi, s, ms = struct.unpack_from("<8H", b)
    return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{ms:03d}0000Z"


def _sid(b: bytes) -> str:
    if len(b) < 8:
        return b.hex()
    rev, n = b[0], b[1]
    auth = int.from_bytes(b[2:8], "big")
    subs = struct.unpack_from(f"<{n}I", b, 8) if len(b) >= 8 + 4 * n else ()
    return f"S-{rev}-{auth}" + "".join(f"-{x}" for x in subs)


class _Chunk:
    def __init__(self, data: bytes):
        self.d = data
        self.templates: dict[int, tuple[int, int]] = {}  # offset -> (body start, body end)

    # ------------------------------------------------------------ helpers
    def name(self, off: int) -> str:
        n = struct.unpack_from("<H", self.d, off + 6)[0]
        return self.d[off + 8: off + 8 + 2 * n].decode("utf-16-le", "replace")

    def _skip_inline_name(self, name_off: int, pos: int) -> int:
        if name_off == pos:  # the name is stored right here, the first time it is used in the chunk
            n = struct.unpack_from("<H", self.d, pos + 6)[0]
            pos += 8 + 2 * n + 2
        return pos

    # ------------------------------------------------------------ values
    def value(self, vtype: int, b: bytes) -> str:
        if vtype & 0x80:  # array
            base = vtype & 0x7F
            if base == 0x01:
                return ", ".join(x for x in b.decode("utf-16-le", "replace").split("\x00") if x)
            size = {0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8, 0x0A: 8, 0x0F: 16, 0x11: 8, 0x14: 4, 0x15: 8}.get(base)
            if not size:
                return b.hex()
            return ", ".join(self.value(base, b[i:i + size]) for i in range(0, len(b) - size + 1, size))
        if vtype == 0x00:
            return ""
        if vtype == 0x01:
            return b.decode("utf-16-le", "replace").rstrip("\x00")
        if vtype == 0x02:
            return b.decode("latin-1").rstrip("\x00")
        fmt = {0x03: "<b", 0x04: "<B", 0x05: "<h", 0x06: "<H", 0x07: "<i", 0x08: "<I", 0x09: "<q", 0x0A: "<Q",
               0x0B: "<f", 0x0C: "<d"}.get(vtype)
        if fmt:
            return str(struct.unpack_from(fmt, b)[0]) if len(b) >= struct.calcsize(fmt) else ""
        if vtype == 0x0D:
            return "true" if b and int.from_bytes(b[:4], "little") else "false"
        if vtype == 0x0E:
            return b.hex().upper()
        if vtype == 0x0F:
            return "{" + str(uuid.UUID(bytes_le=b[:16])).upper() + "}" if len(b) >= 16 else ""
        if vtype == 0x10:
            return f"0x{int.from_bytes(b, 'little'):x}"
        if vtype == 0x11:
            return _filetime(int.from_bytes(b[:8], "little"))
        if vtype == 0x12:
            return _systime(b) if len(b) >= 16 else ""
        if vtype == 0x13:
            return _sid(b)
        if vtype == 0x14:
            return f"0x{int.from_bytes(b[:4], 'little'):x}"
        if vtype == 0x15:
            return f"0x{int.from_bytes(b[:8], 'little'):016x}"
        return b.hex()

    # ------------------------------------------------------------ BinXML
    def fragment(self, pos: int, end: int, subs: list | None, out: list) -> int:
        while pos < end:
            tok = self.d[pos]
            if tok == 0x00:  # end of stream
                return pos + 1
            if tok == 0x0F:  # fragment header
                pos += 4
            elif tok in (0x01, 0x41):
                pos = self.element(pos, subs, out)
            elif tok == 0x0C:
                pos = self.template(pos, out)
            else:
                pos = self.content(pos, subs, out)
        return pos

    def content(self, pos: int, subs, out: list) -> int:
        tok = self.d[pos]
        base = tok & 0x0F if tok not in (0x41, 0x45, 0x46) else tok & 0x0F
        if base == 0x05:  # value text
            vtype = self.d[pos + 1]
            n = struct.unpack_from("<H", self.d, pos + 2)[0]
            raw = self.d[pos + 4: pos + 4 + 2 * n]
            out.append(_esc(raw.decode("utf-16-le", "replace")) if vtype == 0x01 else _esc(raw.hex()))
            return pos + 4 + 2 * n
        if base in (0x0D, 0x0E):  # normal / optional substitution
            idx = struct.unpack_from("<H", self.d, pos + 1)[0]
            if subs is not None and idx < len(subs):
                vtype, b, nested = subs[idx]
                if vtype == 0x21 and b:
                    out.append(nested(b))
                else:
                    out.append(_esc(self.value(vtype, b)))
            return pos + 4
        if base == 0x07:  # CDATA
            n = struct.unpack_from("<H", self.d, pos + 1)[0]
            out.append(_esc(self.d[pos + 3: pos + 3 + 2 * n].decode("utf-16-le", "replace")))
            return pos + 3 + 2 * n
        if base == 0x08:  # character reference
            out.append(f"&#{struct.unpack_from('<H', self.d, pos + 1)[0]};")
            return pos + 3
        if base == 0x09:  # entity reference
            off = struct.unpack_from("<I", self.d, pos + 1)[0]
            out.append(f"&{self.name(off)};")
            return self._skip_inline_name(off, pos + 5)
        if base == 0x0C:
            return self.template(pos, out)
        if base in (0x0A, 0x0B):  # processing instruction target / data
            raise EvtxError("processing instructions are not supported")
        raise EvtxError(f"unexpected BinXML token 0x{tok:02x} at {pos}")

    def element(self, pos: int, subs, out: list) -> int:
        tok = self.d[pos]
        # token, dependency id (2), data size (4), name offset (4)
        name_off = struct.unpack_from("<I", self.d, pos + 7)[0]
        name = self.name(name_off)
        pos = self._skip_inline_name(name_off, pos + 11)
        out.append("<" + name)
        if tok & 0x40:
            pos += 4  # attribute list size
            while self.d[pos] in (0x06, 0x46):
                a_off = struct.unpack_from("<I", self.d, pos + 1)[0]
                pos = self._skip_inline_name(a_off, pos + 5)
                val: list = []
                while self.d[pos] not in (0x06, 0x46, 0x02, 0x03):  # an attribute value can be several value nodes
                    pos = self.content(pos, subs, val)
                out.append(f' {self.name(a_off)}="{"".join(val).replace(chr(34), "&quot;")}"')
        tok = self.d[pos]
        if tok == 0x03:  # empty element
            out.append("/>")
            return pos + 1
        if tok != 0x02:
            raise EvtxError(f"bad element close token 0x{tok:02x}")
        out.append(">")
        pos += 1
        while self.d[pos] != 0x04:
            t = self.d[pos]
            if t in (0x01, 0x41):
                pos = self.element(pos, subs, out)
            elif t == 0x00:
                raise EvtxError("stream ended inside an element")
            else:
                pos = self.content(pos, subs, out)
        out.append(f"</{name}>")
        return pos + 1

    def template(self, pos: int, out: list) -> int:
        # token, unknown (1), template id (4), template definition offset (4)
        def_off = struct.unpack_from("<I", self.d, pos + 6)[0]
        pos += 10
        if def_off not in self.templates:
            size = struct.unpack_from("<I", self.d, def_off + 20)[0]
            self.templates[def_off] = (def_off + 24, def_off + 24 + size)
        body = self.templates[def_off]
        if def_off == pos:  # definition stored inline, right here
            pos = body[1]
        count = struct.unpack_from("<I", self.d, pos)[0]
        pos += 4
        descr = [struct.unpack_from("<HBx", self.d, pos + 4 * i) for i in range(count)]
        pos += 4 * count
        subs = []
        for size, vtype in descr:
            subs.append((vtype, self.d[pos: pos + size], self._nested))
            pos += size
        self.fragment(body[0], body[1], subs, out)
        return pos

    def _nested(self, b: bytes) -> str:
        # embedded BinXML (vtype 0x21): its offsets are relative to the chunk, so find it inside the chunk
        start = self.d.find(b)
        if start < 0:
            return ""
        sub: list = []
        self.fragment(start, start + len(b), None, sub)
        return "".join(sub)

    def records(self) -> Iterator[tuple[int, str]]:
        free = struct.unpack_from("<I", self.d, 0x30)[0]
        pos = 0x200
        while pos + 24 <= min(free, len(self.d)):
            if self.d[pos:pos + 4] != b"\x2a\x2a\x00\x00":
                break
            size = struct.unpack_from("<I", self.d, pos + 4)[0]
            rid = struct.unpack_from("<Q", self.d, pos + 8)[0]
            if size < 28 or pos + size > len(self.d):
                break
            out: list = []
            try:
                self.fragment(pos + 24, pos + size - 4, None, out)
                yield rid, "".join(out)
            except (EvtxError, struct.error, IndexError) as exc:
                yield rid, f"!{exc}"
            pos += size


def read_records(path: str, warn=print, max_records: int | None = None) -> Iterator[tuple[int, str]]:
    """(record id, event XML) for every record in an .evtx file."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
        if head[:8] != b"ElfFile\x00":
            raise EvtxError(f"{path} is not an .evtx file")
        n, bad = 0, 0
        while True:
            data = fh.read(CHUNK)
            if len(data) < CHUNK:
                break
            if data[:8] != b"ElfChnk\x00":
                continue
            for rid, xml in _Chunk(data).records():
                if xml.startswith("!"):
                    bad += 1
                    continue
                yield rid, xml
                n += 1
                if max_records and n >= max_records:
                    return
        if bad:
            warn(f"{path}: {bad} record(s) could not be decoded and were skipped")
