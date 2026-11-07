"""Prefetch (.pf): the LZXPRESS Huffman decoder, the SCCA parser, and a folder of .pf files becoming events."""
import os
import random
import struct
from datetime import datetime, timedelta, timezone

import pytest

from logagent.collectors import prefetch
from logagent.collectors.sources import collect, detect_format, parse_window
from logagent.signals import load_rules


# ---------------------------------------------------------------- a small spec-following encoder, for tests only
class _Enc:
    """[MS-XCA] LZ77+Huffman with every symbol 9 bits long (so a symbol's code is the symbol). One block (< 64 KB)."""

    def __init__(self):
        self.out = bytearray(b"\x99" * 256 + b"\0" * 4)
        self.slots = [256, 258]
        self.acc = self.n = self.total = 0

    def bits(self, v: int, k: int):
        for s in range(k - 1, -1, -1):
            if self.total and self.total % 16 == 0:  # the decoder reads the next word as soon as this one starts
                self.slots.append(len(self.out))
                self.out += b"\0\0"
            self.acc = (self.acc << 1) | ((v >> s) & 1)
            self.n += 1
            self.total += 1
            if self.n == 16:
                struct.pack_into("<H", self.out, self.slots.pop(0), self.acc)
                self.acc = self.n = 0

    def literal(self, b: int):
        self.bits(b, 9)

    def match(self, length: int, offset: int):
        ob = offset.bit_length() - 1
        self.bits(256 + (ob << 4) + min(length - 3, 15), 9)
        if length - 3 >= 15:
            rest = length - 3 - 15
            if rest < 255:
                self.out.append(rest)
            else:
                self.out.append(255)
                self.out += struct.pack("<H", length - 3)
        self.bits(offset - (1 << ob), ob)

    def done(self) -> bytes:
        if self.n:
            struct.pack_into("<H", self.out, self.slots.pop(0), self.acc << (16 - self.n))
        return bytes(self.out)


def _compress(data: bytes) -> bytes:
    """Greedy: reuse the last 4 KB when a 3+ byte match is there, else a literal."""
    e, i = _Enc(), 0
    while i < len(data):
        best = (0, 0)
        for off in range(1, min(i, 4096) + 1):
            k = 0
            while i + k < len(data) and k < 600 and data[i + k] == data[i - off + k]:
                k += 1
            if k > best[0]:
                best = (k, off)
            if k >= 600:
                break
        if best[0] >= 3:
            e.match(*best)
            i += best[0]
        else:
            e.literal(data[i])
            i += 1
    return e.done()


def test_decoder_round_trip():
    rnd = random.Random(3)
    data = (b"C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL\0" * 20 + bytes(rnd.randrange(256) for _ in range(300)) +
            b"A" * 700 + b"xyz" * 90)  # long matches (extra length bytes), overlapping runs, random literals
    assert prefetch.xpress_huffman_decompress(_compress(data), len(data)) == data


@pytest.mark.skipif(os.name != "nt", reason="uses Windows' own compressor")
def test_decoder_matches_windows():
    """Windows compresses (several 64 KB blocks), the pure-Python decoder must get the same bytes back."""
    import ctypes
    ntdll = ctypes.WinDLL("ntdll")
    rnd = random.Random(5)
    words = [b"WINDOWS", b"SYSTEM32", b"\\", b".DLL", b"PREFETCH", b"\0\0"]
    data = b"".join(rnd.choice(words) if rnd.random() < 0.8 else bytes([rnd.randrange(256)]) for _ in range(60000))
    ws, fws = ctypes.c_ulong(), ctypes.c_ulong()
    assert ntdll.RtlGetCompressionWorkSpaceSize(4 | 0x100, ctypes.byref(ws), ctypes.byref(fws)) == 0
    work, out, final = ctypes.create_string_buffer(ws.value), ctypes.create_string_buffer(len(data) * 2), ctypes.c_ulong()
    src = ctypes.create_string_buffer(data, len(data))
    assert ntdll.RtlCompressBuffer(4 | 0x100, src, len(data), out, len(out), 4096, ctypes.byref(final), work) == 0
    assert len(data) > 3 * 65536
    assert prefetch.xpress_huffman_decompress(out.raw[:final.value], len(data)) == data


# ---------------------------------------------------------------- SCCA version 30 (Windows 10/11)
def _ft(dt: datetime) -> int:
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10**7)


def _scca(exe: str, exe_path: str, runs: list[datetime], run_count: int) -> bytes:
    names = "\0".join(["\\VOLUME{01d8e2a1b3c4d5e6-1a2b3c4d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL", exe_path]).encode("utf-16-le") + b"\0\0"
    names_off = 0x130
    vol_off = names_off + len(names)
    dev = "\\VOLUME{01d8e2a1b3c4d5e6-1a2b3c4d}".encode("utf-16-le")
    vol = struct.pack("<IIQI", 96, len(dev) // 2, _ft(datetime(2024, 3, 1, tzinfo=timezone.utc)), 0x1A2B3C4D)
    vol = vol.ljust(96, b"\0") + dev
    d = bytearray(vol_off + len(vol))
    struct.pack_into("<I4sII", d, 0, 30, b"SCCA", 17, len(d))
    d[0x10:0x10 + 2 * len(exe)] = exe.encode("utf-16-le")
    struct.pack_into("<I", d, 0x4C, 0xDEADBEEF)
    struct.pack_into("<IIIIIIIIII", d, 0x54, 0x130, 0, 0, 0, names_off, len(names), vol_off, 1, len(vol), 0)
    struct.pack_into("<8Q", d, 0x80, *([_ft(t) for t in runs] + [0] * (8 - len(runs))))
    struct.pack_into("<I", d, 0xD0, run_count)
    d[names_off:vol_off] = names
    d[vol_off:] = vol
    return bytes(d)


def _mam(raw: bytes) -> bytes:
    return b"MAM\x04" + struct.pack("<I", len(raw)) + _compress(raw)


T0 = datetime(2025, 2, 14, 9, 30, tzinfo=timezone.utc)


def test_parse_compressed_v30():
    runs = [T0 + timedelta(hours=k) for k in (3, 0, 1)]
    pf = prefetch.parse(_mam(_scca("MIMIKATZ.EXE", "\\VOLUME{01d8e2a1b3c4d5e6-1a2b3c4d}\\USERS\\PUBLIC\\MIMIKATZ.EXE", runs, 5)))
    assert pf["version"] == 30 and pf["exe"] == "MIMIKATZ.EXE" and pf["hash"] == "DEADBEEF" and pf["run_count"] == 5
    assert pf["runs"] == sorted(runs) and pf["path"].endswith("\\USERS\\PUBLIC\\MIMIKATZ.EXE")
    assert pf["volumes"][0]["serial"] == "1A2B3C4D" and len(pf["files"]) == 2


def test_not_prefetch():
    with pytest.raises(prefetch.PrefetchError):
        prefetch.parse(b"\0" * 200)


def test_folder_of_prefetch_files(tmp_path):
    folder = tmp_path / "Prefetch"
    folder.mkdir()
    (folder / "MIMIKATZ.EXE-DEADBEEF.pf").write_bytes(_mam(_scca(
        "MIMIKATZ.EXE", "\\VOLUME{01d8e2a1b3c4d5e6-1a2b3c4d}\\USERS\\PUBLIC\\MIMIKATZ.EXE", [T0, T0 + timedelta(minutes=5)], 2)))
    (folder / "NOTEPAD.EXE-0A1B2C3D.pf").write_bytes(_scca(  # stored uncompressed, as older tools export them
        "NOTEPAD.EXE", "\\VOLUME{01d8e2a1b3c4d5e6-1a2b3c4d}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE", [T0], 40))
    (folder / "Layout.ini").write_text("ignored")
    assert detect_format(str(folder / "NOTEPAD.EXE-0A1B2C3D.pf")) == "prefetch"

    # files from a year ago still count: prefetch is a record, not a live log cut to the scan window
    evs = list(collect({"type": "files", "path": str(folder)}, parse_window("24h"), warn=print))
    assert len(evs) == 3 and {e.fields["ExecutableName"] for e in evs} == {"MIMIKATZ.EXE", "NOTEPAD.EXE"}
    mimi = [e for e in evs if e.fields["ExecutableName"] == "MIMIKATZ.EXE"]
    assert mimi[0].message.startswith("Program executed: MIMIKATZ.EXE (\\USERS\\PUBLIC\\MIMIKATZ.EXE)")
    assert mimi[0].loc == {"file": str(folder / "MIMIKATZ.EXE-DEADBEEF.pf"), "prefetch": 1}

    rule = next(r for r in load_rules(None) if r.id == "pf_user_writable_run")
    assert all(rule.matches(e) for e in mimi)
    assert not any(rule.matches(e) for e in evs if e not in mimi)

    lines = prefetch.describe(mimi[1].loc["file"], 2)
    assert [l["text"] for l in lines if l.get("hit")] == [f"Run 2: {T0 + timedelta(minutes=5):%Y-%m-%d %H:%M:%SZ}"]
