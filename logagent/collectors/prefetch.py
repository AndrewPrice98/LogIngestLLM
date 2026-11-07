"""Windows Prefetch (.pf) files: which programs ran, when, how often, and what they loaded.

Windows writes C:\\Windows\\Prefetch\\<EXE>-<HASH>.pf the first time a program runs and updates it on later runs.
Each file records the executable name, a run count, the last run time (up to eight on Windows 8 and later), the
volumes and files the program touched in its first seconds. Formats: 17 (XP/2003), 23 (Vista/7), 26 (8.1), 30/31
(10/11). Windows 10 and later compress the file (a "MAM" header + LZXPRESS Huffman, [MS-XCA] 2.2); that is decoded
here in pure Python, or by Windows itself (ntdll) when running on Windows.

One Event per recorded run time, so a folder of prefetch files becomes a timeline of program execution.
"""
from __future__ import annotations

import os
import struct
from datetime import datetime, timedelta, timezone
from typing import Iterator

from ..model import Event, INFO

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
MAX_PF_BYTES = 16 * 2**20      # real prefetch files are well under 1 MB
# Folders that normal programs don't run from; a run from here is worth a look.
USER_WRITABLE = ("\\USERS\\PUBLIC\\", "\\APPDATA\\LOCAL\\TEMP\\", "\\WINDOWS\\TEMP\\", "\\DOWNLOADS\\",
                 "\\APPDATA\\ROAMING\\", "\\$RECYCLE.BIN\\", "\\PERFLOGS\\")


class PrefetchError(ValueError):
    pass


# ---------------------------------------------------------------- LZXPRESS Huffman ([MS-XCA] 2.2.4)
def _decoding_table(lengths: list[int]) -> list[int]:
    """Canonical Huffman: codes go to symbols by (length, symbol); a 15-bit lookup maps the next bits to a symbol."""
    table = [-1] * 32768
    pos = 0
    for bits in range(1, 16):
        for sym in range(512):
            if lengths[sym] == bits:
                span = 1 << (15 - bits)
                if pos + span > 32768:
                    raise PrefetchError("bad Huffman table")
                table[pos:pos + span] = [sym] * span
                pos += span
    if pos == 0:
        raise PrefetchError("empty Huffman table")
    return table


def xpress_huffman_decompress(data: bytes, out_size: int) -> bytes:
    out = bytearray()
    n = len(data)
    i = 0

    def u16(at: int) -> int:
        return data[at] | (data[at + 1] << 8) if at + 1 < n else (data[at] if at < n else 0)

    while len(out) < out_size:
        if i + 256 > n:
            raise PrefetchError("compressed data ends early")
        lengths = [0] * 512
        for k in range(256):
            b = data[i + k]
            lengths[2 * k], lengths[2 * k + 1] = b & 15, b >> 4
        table = _decoding_table(lengths)
        i += 256
        bits = (u16(i) << 16) | u16(i + 2)
        i += 4
        extra = 16
        block_end = min(len(out) + 65536, out_size)
        while len(out) < block_end:
            sym = table[bits >> 17]
            if sym < 0:
                raise PrefetchError("bad Huffman code")
            ln = lengths[sym]
            bits = (bits << ln) & 0xFFFFFFFF
            extra -= ln
            if extra < 0:
                bits |= u16(i) << -extra
                extra += 16
                i += 2
            if sym < 256:
                out.append(sym)
                continue
            sym -= 256
            length, off_bits = sym & 15, sym >> 4
            if length == 15:
                if i >= n:
                    raise PrefetchError("compressed data ends early")
                length = data[i]
                i += 1
                if length == 255:
                    length = u16(i)
                    i += 2
                    if length == 0:
                        length = struct.unpack_from("<I", data, i)[0]
                        i += 4
                    if length < 15:
                        raise PrefetchError("bad match length")
                    length -= 15
                length += 15
            length += 3
            offset = ((bits >> (32 - off_bits)) if off_bits else 0) + (1 << off_bits)
            bits = (bits << off_bits) & 0xFFFFFFFF
            extra -= off_bits
            if extra < 0:
                bits |= u16(i) << -extra
                extra += 16
                i += 2
            start = len(out) - offset
            if start < 0:
                raise PrefetchError("match points before the start of the data")
            if offset >= length:
                out += out[start:start + length]
            else:  # overlapping copy repeats the last `offset` bytes
                for k in range(length):
                    out.append(out[start + k])
    return bytes(out[:out_size])


def _ntdll_decompress(data: bytes, out_size: int) -> bytes | None:
    """Windows' own decoder (RtlDecompressBufferEx, COMPRESSION_FORMAT_XPRESS_HUFF). None when not on Windows."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        ntdll = ctypes.WinDLL("ntdll")
        ws, fws = ctypes.c_ulong(), ctypes.c_ulong()
        if ntdll.RtlGetCompressionWorkSpaceSize(4, ctypes.byref(ws), ctypes.byref(fws)):
            return None
        work = ctypes.create_string_buffer(ws.value)
        out = ctypes.create_string_buffer(out_size)
        src = ctypes.create_string_buffer(data, len(data))
        final = ctypes.c_ulong()
        if ntdll.RtlDecompressBufferEx(4, out, out_size, src, len(data), ctypes.byref(final), work):
            return None
        return out.raw[:final.value]
    except (OSError, AttributeError):
        return None


def decompress(raw: bytes) -> bytes:
    """Uncompressed SCCA bytes from a .pf file (Windows 10+ files start with MAM, older ones with the version)."""
    if raw[:3] != b"MAM":
        return raw
    if len(raw) < 8 or raw[3] & 0x0F != 4:
        raise PrefetchError("unsupported prefetch compression")
    size = struct.unpack_from("<I", raw, 4)[0]
    body = raw[12:] if raw[3] & 0x80 else raw[8:]  # 0x80: a CRC32 follows the size
    if not 0 < size <= MAX_PF_BYTES:
        raise PrefetchError("bad uncompressed size")
    return _ntdll_decompress(body, size) or xpress_huffman_decompress(body, size)


# ---------------------------------------------------------------- SCCA
def _ft(v: int) -> datetime | None:
    if not v or v >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return _EPOCH + timedelta(microseconds=v // 10)
    except OverflowError:
        return None


def _utf16(b: bytes) -> str:
    s = b.decode("utf-16-le", errors="replace")
    return s.split("\x00", 1)[0]


def parse(raw: bytes) -> dict:
    """Parse one prefetch file (compressed or not) into a dict."""
    d = decompress(raw)
    if len(d) < 0x54 or d[4:8] != b"SCCA":
        raise PrefetchError("not a prefetch file (no SCCA signature)")
    version = struct.unpack_from("<I", d, 0)[0]
    if version not in (17, 23, 26, 30, 31):
        raise PrefetchError(f"unknown prefetch version {version}")
    exe = _utf16(d[0x10:0x4C])
    pf_hash = struct.unpack_from("<I", d, 0x4C)[0]
    metrics_off, = struct.unpack_from("<I", d, 0x54)
    names_off, names_size, vol_off, vol_count, vol_size = struct.unpack_from("<IIIII", d, 0x64)
    if version == 17:
        times_at, n_times, count_at = 0x78, 1, 0x90
    elif version == 23:
        times_at, n_times, count_at = 0x80, 1, 0x98
    else:  # 26 and 30/31; the newest Windows 11 layout is 8 bytes shorter (file metrics start at 0x128)
        times_at, n_times, count_at = 0x80, 8, (0xC8 if version >= 30 and metrics_off == 0x128 else 0xD0)
    runs = [t for t in (_ft(v) for v in struct.unpack_from(f"<{n_times}Q", d, times_at)) if t]
    run_count = struct.unpack_from("<I", d, count_at)[0]

    files = []
    if 0 < names_off < len(d) and names_size:
        files = [s for s in d[names_off:names_off + names_size].decode("utf-16-le", errors="replace").split("\x00") if s]
    volumes = []
    entry = {17: 40, 23: 104, 26: 104}.get(version, 96)
    for k in range(min(vol_count, 32)):
        at = vol_off + k * entry
        if at + 20 > len(d):
            break
        p_off, p_len, created, serial = struct.unpack_from("<IIQI", d, at)
        path = d[vol_off + p_off:vol_off + p_off + 2 * p_len].decode("utf-16-le", errors="replace") if p_len else ""
        volumes.append({"device": path, "serial": f"{serial:08X}", "created": _ft(created)})
    # the program's own path is the loaded file that ends in \EXE (the name is cut to 29 characters)
    up = exe.upper()
    path = next((f for f in files if f.upper().rsplit("\\", 1)[-1] == up), None) or \
        next((f for f in files if up and f.upper().rsplit("\\", 1)[-1].startswith(up)), "")
    return {"version": version, "exe": exe, "hash": f"{pf_hash:08X}", "run_count": run_count, "runs": sorted(runs),
            "path": path, "files": files, "volumes": volumes}


def _friendly(path: str) -> str:
    """\\VOLUME{01d8...}\\WINDOWS\\SYSTEM32\\X.EXE -> \\WINDOWS\\SYSTEM32\\X.EXE (the volume GUID only adds noise)."""
    if path.upper().startswith("\\VOLUME{") and "}" in path:
        return path[path.index("}") + 1:]
    parts = path.split("\\", 3)  # \DEVICE\HARDDISKVOLUME3\WINDOWS\X.EXE -> \WINDOWS\X.EXE
    return "\\" + parts[3] if path.upper().startswith("\\DEVICE\\") and len(parts) == 4 else path


def read_prefetch(path: str, host: str, warn=print) -> Iterator[Event]:
    size = os.path.getsize(path)
    if size > MAX_PF_BYTES:
        warn(f"skipped {path}: {size / 2**20:.0f} MB is too big for a prefetch file")
        return
    with open(path, "rb") as fh:
        pf = parse(fh.read())
    where = _friendly(pf["path"]) or pf["exe"]
    loaded = len(pf["files"])
    fields = {"ExecutableName": pf["exe"], "Path": where, "RunCount": pf["run_count"], "PrefetchHash": pf["hash"],
              "FilesLoaded": loaded}
    if pf["volumes"]:
        fields["VolumeSerial"] = pf["volumes"][0]["serial"]
    if any(p in where.upper() for p in USER_WRITABLE):
        fields["UserWritablePath"] = True
    total = len(pf["runs"])
    for n, ts in enumerate(pf["runs"], 1):
        msg = f"Program executed: {pf['exe']} ({where}); ran {pf['run_count']} times in total, {loaded} files loaded"
        yield Event(ts=ts, host=host, source="windows:Prefetch", severity=INFO, message=msg, program=pf["exe"],
                    event_id="", fields=dict(fields, RunTimeIndex=f"{n} of {total}"),
                    loc={"file": path, "prefetch": n})


def is_prefetch(path: str) -> bool:
    if not path.lower().endswith(".pf"):
        return False
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    return head[:3] == b"MAM" or head[4:8] == b"SCCA"


def describe(path: str, hit: int | None = None) -> list[dict]:
    """Readable lines for the log viewer: header, every run time, volumes, loaded files."""
    with open(path, "rb") as fh:
        pf = parse(fh.read())
    rows = [f"Prefetch version {pf['version']}: {pf['exe']}  hash {pf['hash']}  run count {pf['run_count']}",
            f"Path: {_friendly(pf['path']) or '(not in the loaded-file list)'}"]
    lines = [{"n": i + 1, "text": t} for i, t in enumerate(rows)]
    for k, ts in enumerate(pf["runs"], 1):
        lines.append({"n": len(lines) + 1, "text": f"Run {k}: {ts:%Y-%m-%d %H:%M:%SZ}", "run": k, "hit": k == hit})
    for v in pf["volumes"]:
        c = f", created {v['created']:%Y-%m-%d}" if v["created"] else ""
        lines.append({"n": len(lines) + 1, "text": f"Volume {v['device']} serial {v['serial']}{c}"})
    for f in pf["files"][:400]:
        lines.append({"n": len(lines) + 1, "text": f"Loaded: {_friendly(f)}"})
    if len(pf["files"]) > 400:
        lines.append({"n": len(lines) + 1, "text": f"... and {len(pf['files']) - 400} more loaded files"})
    return lines
