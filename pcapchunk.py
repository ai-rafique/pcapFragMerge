#!/usr/bin/env python3
"""
pcapchunk.py - split capture files into chunks, merge them back, verify, trim,
convert, combine and demux them.

Pure Python standard library. No third-party packages, no threads.

  split    capture.pcap [-s 50M | -n 8 | -p 100000 | --every 1h | --gap 5m]
  merge    capture_chunks/
  verify   capture_chunks/ [--deep]
  info     capture.pcap [--top 10]
  trim     capture.pcap -o trimmed.pcap --from 2026-01-01T00:00:00 --to ...
  convert  capture.pcapng -o capture.pcap --format pcap
  combine  a.pcap b.pcap -o merged.pcap [--sort] [--dedupe]
  demux    capture.pcap -o flows/ [--max-flows 500]

Every chunk is a valid, standalone capture (it carries the file header /
interface definitions it needs), so chunks open fine in Wireshark/tcpdump.
Merging strips those repeated headers again, so the merged file is
byte-for-byte identical to the original. The hash recorded at split time is
checked on merge and by `verify`.

Chunks are written into a staging folder and only promoted into place after
the whole split succeeded, so an interrupted or failed split never destroys a
previous chunk set. `--resume` continues an interrupted split.

For GUIs: every long operation is a *_steps() generator that yields
(bytes_done, bytes_total) and returns a summary dict. A GUI can advance it
from its event loop (no threads) and cancel with gen.close(), which removes
partial output.

See docs/API_V2.md for the full public API.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import gzip
import hashlib
import json
import logging
import os
import re
import shutil
import struct
import sys
import time
from collections import namedtuple
from typing import Any, Dict, Iterable, Iterator, List, NamedTuple, Optional, Tuple

try:  # Python 3.14+
    from compression import zstd as _zstd  # type: ignore
except Exception:  # pragma: no cover - optional
    _zstd = None

__version__ = "2.0.0"
APP_NAME = "PcapChunk"

BUF = 1 << 20  # 1 MiB I/O buffers
PROGRESS_EVERY = 1 << 20  # yield progress roughly every 1 MiB
MANIFEST = "manifest.json"
SUMS = "SHA256SUMS"
INCOMPLETE = ".pcapchunk-incomplete"
STAGING = ".pcapchunk-staging"
LOCKNAME = ".pcapchunk.lock"
SCHEMA = 2

# Safety caps: a corrupt length field must never turn a tiny file into a huge
# allocation. Real captures are far below these numbers.
MAX_PCAP_RECORD = 64 << 20
MAX_PCAPNG_BLOCK = 256 << 20

PRESETS = {
    "email": 20 << 20,
    "upload": 100 << 20,
    "telegram": 1900 << 20,
    "fat32": (4 << 30) - 1,
    "dvd": 4_700_000_000,
}

FILTER_KEYS = ("host", "src", "dst", "port", "sport", "dport", "proto")

log = logging.getLogger("pcapchunk")

# ---------------------------------------------------------------- formats --

# classic pcap: magic bytes as they appear on disk -> (endianness, record header len)
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 16),  # microsecond, little-endian
    b"\xa1\xb2\xc3\xd4": (">", 16),  # microsecond, big-endian
    b"\x4d\x3c\xb2\xa1": ("<", 16),  # nanosecond, little-endian
    b"\xa1\xb2\x3c\x4d": (">", 16),  # nanosecond, big-endian
    b"\x34\xcd\xb2\xa1": ("<", 24),  # Kuznetzov modified pcap, LE
    b"\xa1\xb2\xcd\x34": (">", 24),  # Kuznetzov modified pcap, BE
}
PCAP_NANO_MAGICS = {b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAP_GLOBAL_HDR = 24

# pcapng block types
SHB_BYTES = b"\x0a\x0d\x0d\x0a"  # Section Header Block (palindrome: same in LE/BE)
SHB = 0x0A0D0D0A
IDB = 0x00000001  # Interface Description Block
OPB = 0x00000002  # obsolete Packet Block
SPB = 0x00000003  # Simple Packet Block
NRB = 0x00000004
EPB = 0x00000006  # Enhanced Packet Block
PACKET_BLOCKS = {OPB, SPB, EPB}
BOM_LE = b"\x4d\x3c\x2b\x1a"
BOM_BE = b"\x1a\x2b\x3c\x4d"

GZIP_MAGIC = b"\x1f\x8b"

# chunk file names: <stem>_<id><ext> or <stem>_<start>-<end>_<id><ext>
_EXT_RE = r"(?P<ext>(?:\.[A-Za-z0-9]+)+)"
INDEX_RE = re.compile(r"^(?P<stem>.+)_(?P<id>\d{1,})" + _EXT_RE + r"$")
TIME_RE = re.compile(
    r"^(?P<stem>.+)_(?P<start>\d{8}T\d{6})-(?P<end>\d{8}T\d{6})_(?P<id>\d{1,})"
    + _EXT_RE + r"$"
)

HASH_NAMES = ("sha256", "blake2b")
COMPRESSIONS = (None, "gzip", "zstd")


class PcapError(Exception):
    """A user-facing error: bad input, incompatible chunks, unsafe operation."""


def warn(msg):
    log.warning(msg)


def new_hash(name="sha256"):
    if name == "sha256":
        return hashlib.sha256()
    if name == "blake2b":
        return hashlib.blake2b()
    raise PcapError(f"unsupported hash {name!r} (use sha256 or blake2b)")


def _fs(path):
    r"""Windows long-path helper (\\?\ prefix) for paths near the 260 char limit."""
    if os.name != "nt" or not isinstance(path, str) or not path:
        return path
    if path.startswith("\\\\?\\") or not os.path.isabs(path):
        return path
    if len(path) < 240:
        return path
    path = os.path.abspath(path)
    if ".." in path.split(os.sep):
        return path
    return "\\\\?\\" + path


def _tell(f):
    pos = getattr(f, "pos", None)
    if pos is not None:
        return pos
    try:
        return f.tell()
    except (OSError, AttributeError):
        return 0


class _GuardedStream:
    """Translates decompression/IO failures into PcapError."""

    def __init__(self, f, name, comp):
        self.f = f
        self.name = name
        self.comp = comp

    def read(self, n=-1):
        try:
            return self.f.read(n)
        except EOFError as e:
            raise PcapError(f"{self.name}: truncated {self.comp} stream ({e})")
        except OSError as e:
            raise PcapError(f"{self.name}: cannot read {self.comp} stream ({e})")

    def seek(self, offset, whence=0):
        return self.f.seek(offset, whence)

    def tell(self):
        return self.f.tell()

    def close(self):
        try:
            self.f.close()
        except OSError:
            pass


def _compression_of(path):
    """Return None, 'gzip' or 'zstd' by sniffing the file header."""
    try:
        with open(_fs(path), "rb") as f:
            magic = f.read(4)
    except OSError:
        return None
    if magic[:2] == GZIP_MAGIC:
        return "gzip"
    if magic == b"\x28\xb5\x2f\xfd":
        return "zstd"
    return None


def _is_gzip(path):
    return _compression_of(path) == "gzip"


def _open_compressed(path, mode="rb"):
    comp = _compression_of(path)
    if comp == "gzip":
        return gzip.open(_fs(path), mode)
    if comp == "zstd":
        if _zstd is None:
            raise PcapError(f"{os.path.basename(path)} is zstd-compressed but this "
                            "Python has no compression.zstd")
        return _zstd.open(_fs(path), mode)
    return open(_fs(path), mode)


class HashingReader:
    """File wrapper that hashes everything read through it and tracks position."""

    def __init__(self, f, hash_name="sha256"):
        self.f = f
        self.h = new_hash(hash_name)
        self.pos = 0

    def read(self, n=-1):
        data = self.f.read(n)
        self.h.update(data)
        self.pos += len(data)
        return data

    def seek(self, offset, whence=0):
        self.f.seek(offset, whence)
        self.pos = self.f.tell()
        return self.pos

    def tell(self):
        return self.pos


class HashingWriter:
    """File wrapper that hashes everything written through it."""

    def __init__(self, f, hash_name="sha256"):
        self.f = f
        self.h = new_hash(hash_name)
        self.bytes = 0

    def write(self, data):
        self.h.update(data)
        self.bytes += len(data)
        return self.f.write(data)

    def flush(self):
        try:
            self.f.flush()
        except (AttributeError, OSError):
            pass

    def hexdigest(self):
        return self.h.hexdigest()


def _fmt_from_magic(magic, name):
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == SHB_BYTES:
        return "pcapng"
    if magic[:2] == GZIP_MAGIC:
        raise PcapError(f"{name} is gzip-compressed; decompress it first")
    raise PcapError(f"{name} is not a pcap or pcapng file")


def detect_format(path):
    """Return 'pcap' or 'pcapng', looking through gzip/zstd transparently."""
    name = os.path.basename(path)
    comp = _compression_of(path)
    try:
        if comp:
            stream = _open_compressed(path, "rb")
            try:
                magic = stream.read(4)
            finally:
                stream.close()
        else:
            with open(_fs(path), "rb") as f:
                magic = f.read(4)
    except (OSError, EOFError) as e:
        raise PcapError(f"{name}: cannot read {comp} stream ({e})")
    return _fmt_from_magic(magic, name)


def open_capture(path):
    """Open a capture for reading.

    Returns (stream, format, compression, logical_size).  `compression` is
    None, 'gzip' or 'zstd'.  `logical_size` is the uncompressed capture size
    when it is known without a full scan.  Raises PcapError for a header that
    is too short to be a usable capture.
    """
    name = os.path.basename(path)
    comp = _compression_of(path)
    try:
        stream = _open_compressed(path, "rb")
    except PcapError:
        raise
    except (OSError, EOFError) as e:
        raise PcapError(f"{name}: cannot read {comp} stream ({e})")
    guarded = _GuardedStream(stream, name, comp) if comp else stream
    stream = guarded
    try:
        magic = stream.read(4)
        fmt = _fmt_from_magic(magic, name)
        if fmt == "pcap":
            rest = stream.read(PCAP_GLOBAL_HDR - 4)
            parse_pcap_header(magic + rest)
        else:
            # SHB layout: type (4), block total length (4), byte-order magic (4)
            rest = stream.read(8)
            if len(rest) < 8 or rest[4:8] not in (BOM_LE, BOM_BE):
                raise PcapError(f"{name}: pcapng section header has an invalid "
                                "byte-order magic")
        stream.seek(0)
    except PcapError:
        stream.close()
        raise
    except (OSError, EOFError) as e:
        stream.close()
        raise PcapError(f"{name}: cannot read capture header ({e})")
    logical = None if comp else os.path.getsize(_fs(path))
    return stream, fmt, comp, logical


# ------------------------------------------------------------------- pcap --


class PcapHeader(NamedTuple):
    raw: bytes
    endian: str
    rec_len: int
    nano: bool
    snaplen: int
    linktype: int

    @property
    def precision(self):
        return "nsec" if self.nano else "usec"


def parse_pcap_header(raw):
    if len(raw) < PCAP_GLOBAL_HDR:
        raise PcapError("bad or truncated pcap global header")
    magic = raw[:4]
    info = PCAP_MAGICS.get(magic)
    if info is None:
        raise PcapError("bad or truncated pcap global header")
    endian, rec_len = info
    snaplen, linktype = struct.unpack(endian + "II", raw[16:24])
    return PcapHeader(raw, endian, rec_len, magic in PCAP_NANO_MAGICS, snaplen, linktype)


def read_pcap_header(f):
    hdr = f.read(PCAP_GLOBAL_HDR)
    return parse_pcap_header(hdr)


class Record(NamedTuple):
    raw: bytes
    ts_ns: Optional[int]
    caplen: int
    origlen: int
    payload_off: int
    payload_len: int
    truncated: bool = False


def iter_pcap_records(f, hdr, salvage=False, max_record=None):
    """Yield Record objects. A truncated tail is yielded with truncated=True."""
    limit = max_record or MAX_PCAP_RECORD
    u32 = struct.Struct(hdr.endian + "I")
    while True:
        rec = f.read(hdr.rec_len)
        if not rec:
            return
        if len(rec) < hdr.rec_len:
            warn("file ends with a truncated record header; kept as-is")
            yield Record(rec, None, 0, 0, 0, 0, True)
            return
        incl = u32.unpack_from(rec, 8)[0]
        orig = u32.unpack_from(rec, 12)[0]
        if incl > limit:
            msg = (f"pcap record claims {incl:,} bytes (limit {limit:,}); "
                   "the file looks corrupt")
            if salvage:
                warn(msg + "; stopping here")
                yield Record(rec, None, 0, 0, 0, 0, True)
                return
            raise PcapError(msg + " (use --salvage to keep what was read)")
        data = f.read(incl)
        raw = rec + data
        ts = None
        try:
            sec, frac = struct.unpack_from(hdr.endian + "II", rec, 0)
            ts = sec * 1_000_000_000 + (frac if hdr.nano else frac * 1000)
        except struct.error:
            pass
        if len(data) < incl:
            warn("file ends with a truncated packet; kept as-is")
            yield Record(raw, ts, len(data), orig, hdr.rec_len, len(data), True)
            return
        yield Record(raw, ts, incl, orig, hdr.rec_len, incl, False)


# ----------------------------------------------------------------- pcapng --


class Interface:
    __slots__ = ("id", "linktype", "snaplen", "name", "tsresol", "tsoffset", "section")

    def __init__(self, id, linktype, snaplen, name=None, tsresol=6, tsoffset=0, section=0):
        self.id = id
        self.linktype = linktype
        self.snaplen = snaplen
        self.name = name
        self.tsresol = tsresol
        self.tsoffset = tsoffset
        self.section = section

    def as_dict(self):
        return {
            "id": self.id,
            "linktype": self.linktype,
            "snaplen": self.snaplen,
            "name": self.name,
            "tsresol": self.tsresol,
            "section": self.section,
        }


def _parse_idb_options(raw, endian, start=16):
    name = None
    tsresol = 6
    tsoffset = 0
    pos = start
    end = len(raw) - 4
    while pos + 4 <= end:
        code, length = struct.unpack_from(endian + "HH", raw, pos)
        pos += 4
        if code == 0:
            break
        if pos + length > end:
            warn("pcapng interface block has a malformed option; ignored")
            break
        value = raw[pos:pos + length]
        pos += (length + 3) & ~3
        if code == 2:
            name = value.decode("utf-8", "replace")
        elif code == 9 and length >= 1:
            tsresol = value[0]
        elif code == 14 and length == 8:
            tsoffset = struct.unpack(endian + "q", value)[0]
    return name, tsresol, tsoffset


def _iface_ts_ns(iface, value):
    res = iface.tsresol
    if res & 0x80:
        exp = res & 0x7F
        ns = (value * 1_000_000_000) >> exp
    else:
        exp = res
        if exp <= 9:
            ns = value * (10 ** (9 - exp))
        else:
            ns = value // (10 ** (exp - 9))
    if iface.tsoffset:
        ns += iface.tsoffset * 1_000_000_000
    return ns


def parse_pcapng_packet(btype, raw, endian, interfaces, salvage=False):
    """Return (payload_off, payload_len, caplen, origlen, ts_ns, ifid) or None."""
    n = len(raw)
    if btype == EPB:
        if n < 32:
            return None
        ifid, ts_hi, ts_lo, caplen, origlen = struct.unpack_from(endian + "IIIII", raw, 8)
        avail = n - 32
        if caplen > avail:
            msg = (f"pcapng packet claims {caplen:,} captured bytes but its block "
                   f"holds {avail:,}")
            if not salvage:
                raise PcapError(msg + " (use --salvage to keep what was read)")
            warn(msg + "; truncated")
        pay = min(caplen, avail)
        ts = None
        if ifid < len(interfaces):
            ts = _iface_ts_ns(interfaces[ifid], (ts_hi << 32) | ts_lo)
        return 28, pay, pay, origlen, ts, ifid
    if btype == OPB:
        if n < 32:
            return None
        ifid = struct.unpack_from(endian + "I", raw, 8)[0]
        ts_hi, ts_lo, caplen, origlen = struct.unpack_from(endian + "IIII", raw, 16)
        avail = n - 36
        if caplen > avail:
            msg = (f"pcapng packet claims {caplen:,} captured bytes but its block "
                   f"holds {avail:,}")
            if not salvage:
                raise PcapError(msg + " (use --salvage to keep what was read)")
            warn(msg + "; truncated")
        pay = min(caplen, avail)
        ts = None
        if ifid < len(interfaces):
            ts = _iface_ts_ns(interfaces[ifid], (ts_hi << 32) | ts_lo)
        return 32, pay, pay, origlen, ts, ifid
    if btype == SPB:
        if n < 16:
            return None
        origlen = struct.unpack_from(endian + "I", raw, 8)[0]
        avail = n - 16
        pay = min(origlen, avail)
        return 12, pay, pay, origlen, None, 0
    return None


class PcapngReader:
    """Streaming pcapng block reader with section and interface state."""

    def __init__(self, f, salvage=False, max_block=None):
        self.f = f
        self.salvage = salvage
        self.max_block = max_block or MAX_PCAPNG_BLOCK
        self.endian = None
        self.section = 0
        self.shb_raw = b""
        self.idb_raws = []
        self.interfaces = []
        self.truncated = False
        self._last_block = None
        self.last_start = 0

    def _corrupt(self, msg):
        if self.salvage:
            warn(msg + "; stopping here")
            self.truncated = True
            return False
        raise PcapError(msg + " (use --salvage to keep what was read)")
        return False

    def blocks(self):
        while True:
            self.last_start = _tell(self.f)
            head = self.f.read(8)
            if not head:
                return
            if len(head) < 8:
                warn("file ends with a truncated block; kept as-is")
                self.truncated = True
                yield None, head
                return
            if head[:4] == SHB_BYTES:
                bom = self.f.read(4)
                if len(bom) < 4:
                    warn("file ends with a truncated section header; kept as-is")
                    self.truncated = True
                    yield None, head + bom
                    return
                if bom == BOM_LE:
                    self.endian = "<"
                elif bom == BOM_BE:
                    self.endian = ">"
                else:
                    self._corrupt("pcapng section header has an invalid byte-order magic")
                    return
                blen = struct.unpack(self.endian + "I", head[4:8])[0]
                btype = SHB
                hdr = head + bom
            else:
                if self.endian is None:
                    self._corrupt("pcapng file does not start with a section header")
                    return
                btype, blen = struct.unpack(self.endian + "II", head)
                hdr = head
            if blen < 12 or blen % 4:
                if not self._corrupt(f"corrupt pcapng block length {blen:,} "
                                     f"(type 0x{btype:08x})"):
                    return
            if blen > self.max_block:
                if not self._corrupt(f"pcapng block claims {blen:,} bytes "
                                     f"(limit {self.max_block:,})"):
                    return
            rest = self.f.read(blen - len(hdr))
            raw = hdr + rest
            if len(raw) < blen:
                warn("file ends with a truncated block; kept as-is")
                self.truncated = True
                yield None, raw
                return
            try:
                trail = struct.unpack(self.endian + "I", raw[-4:])[0]
            except struct.error:
                trail = None
            if trail != blen:
                warn(f"pcapng block length mismatch ({trail} vs {blen}); kept as-is")
            if btype == SHB:
                self.section += 1
                self.shb_raw = raw
                self.idb_raws = []
                self.interfaces = []
            elif btype == IDB:
                pos = 8
                if len(raw) >= 20:
                    linktype, _reserved, snaplen = struct.unpack_from(
                        self.endian + "HHI", raw, pos)
                    name, tsresol, tsoffset = _parse_idb_options(raw, self.endian)
                    iface = Interface(len(self.interfaces), linktype, snaplen,
                                      name, tsresol, tsoffset, self.section)
                    self.interfaces.append(iface)
                self.idb_raws.append(raw)
            self._last_block = (btype, raw)
            yield btype, raw

    def prefix(self):
        """The valid standalone prefix for a chunk starting now."""
        if self.section == 0:
            return b""
        return self.shb_raw + b"".join(self.idb_raws)


# ---------------------------------------------------------------- writers --


def _pad4(data):
    return data + b"\x00" * (-len(data) % 4)


def _block_bytes(btype, body, endian="<"):
    body = _pad4(body)
    total = 12 + len(body)
    return struct.pack(endian + "II", btype, total) + body + struct.pack(endian + "I", total)


def _option(endian, code, value):
    return struct.pack(endian + "HH", code, len(value)) + _pad4(value)


class PcapWriter:
    """Writes a classic pcap file."""

    def __init__(self, f, linktype=1, snaplen=65535, endian="<", nano=False,
                 header_raw=None):
        self.f = f
        self.endian = endian
        self.nano = nano
        if header_raw is not None:
            hdr = parse_pcap_header(header_raw)
            self.endian, self.nano = hdr.endian, hdr.nano
            self.linktype, self.snaplen = hdr.linktype, hdr.snaplen
            f.write(header_raw)
        else:
            self.linktype, self.snaplen = linktype, snaplen
            magic = 0xA1B23C4D if nano else 0xA1B2C3D4
            f.write(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0,
                                snaplen, linktype))

    def write_packet(self, payload, ts_ns=None, origlen=None):
        payload = bytes(payload)
        if ts_ns is None:
            sec = frac = 0
        else:
            sec = (ts_ns // 1_000_000_000) & 0xFFFFFFFF
            rem = ts_ns % 1_000_000_000
            frac = rem if self.nano else rem // 1000
        orig = len(payload) if origlen is None else origlen
        self.f.write(struct.pack(self.endian + "IIII", sec, frac,
                                 len(payload), orig))
        self.f.write(payload)


class PcapngWriter:
    """Writes a pcapng file with a single little/big-endian section."""

    def __init__(self, f, endian="<", section_len=-1, tsresol=6):
        self.f = f
        self.endian = endian
        self.tsresol = tsresol
        self._next_id = 0
        self._iface_tsresol = []
        bom = BOM_LE if endian == "<" else BOM_BE
        body = bom + struct.pack(endian + "HHq", 1, 0, section_len)
        f.write(_block_bytes(SHB, body, endian))

    def add_interface(self, linktype=1, snaplen=65535, name=None, tsresol=None):
        if tsresol is None:
            tsresol = self.tsresol
        opts = b""
        if name:
            opts += _option(self.endian, 2, name.encode("utf-8", "replace"))
        opts += _option(self.endian, 9, bytes([tsresol & 0xFF]))
        opts += struct.pack(self.endian + "HH", 0, 0)
        body = struct.pack(self.endian + "HHI", linktype, 0, snaplen) + opts
        self.f.write(_block_bytes(IDB, body, self.endian))
        idx = self._next_id
        self._next_id += 1
        self._iface_tsresol.append(tsresol)
        return idx

    def write_packet(self, ifid, payload, ts_ns=None, origlen=None):
        payload = bytes(payload)
        if ts_ns is None:
            value = 0
        else:
            exp = (self._iface_tsresol[ifid]
                   if 0 <= ifid < len(self._iface_tsresol) else self.tsresol)
            if exp <= 9:
                value = ts_ns // (10 ** (9 - exp))
            else:
                value = ts_ns * (10 ** (exp - 9))
        hi = (value >> 32) & 0xFFFFFFFF
        lo = value & 0xFFFFFFFF
        orig = len(payload) if origlen is None else origlen
        body = struct.pack(self.endian + "IIIII", ifid, hi, lo,
                           len(payload), orig) + _pad4(payload)
        self.f.write(_block_bytes(EPB, body, self.endian))


# --------------------------------------------------------------- dissector --

_ETH_VLAN = (0x8100, 0x88A8, 0x9100)
_PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}


def _ipv4_str(b):
    return ".".join(str(x) for x in b)


def _ipv6_str(b):
    parts = [b[i:i + 2].hex() for i in range(0, 16, 2)]
    return ":".join(parts)


def decode_packet(data, linktype):
    """Decode enough of a packet for filtering/demuxing.

    Returns {"proto","num","src","dst","sport","dport"} or None.
    """
    if not data:
        return None
    off = 0
    ethertype = None
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        ethertype = struct.unpack_from(">H", data, 12)[0]
        off = 14
        while ethertype in _ETH_VLAN and len(data) >= off + 4:
            ethertype = struct.unpack_from(">H", data, off + 2)[0]
            off += 4
        version = 4 if ethertype == 0x0800 else 6 if ethertype == 0x86DD else None
    elif linktype in (101, 12):  # raw IP
        version = (data[0] >> 4) if data else None
        off = 0
    elif linktype == 228:  # LINKTYPE_IPV4
        version = 4
    elif linktype == 229:  # LINKTYPE_IPV6
        version = 6
    elif linktype == 0:  # BSD loopback: 4-byte family in host byte order
        if len(data) < 4:
            return None
        fam_le = struct.unpack_from("<I", data, 0)[0]
        fam_be = struct.unpack_from(">I", data, 0)[0]
        fam = fam_le if fam_le in (2, 24, 28, 30) else fam_be
        if fam == 2:
            version = 4
        elif fam in (24, 28, 30):
            version = 6
        else:
            return None
        off = 4
    elif linktype == 113:  # Linux cooked v1
        if len(data) < 16:
            return None
        ethertype = struct.unpack_from(">H", data, 14)[0]
        version = 4 if ethertype == 0x0800 else 6 if ethertype == 0x86DD else None
        off = 16
    else:
        return None

    if version == 4:
        if len(data) < off + 20:
            return None
        ihl = (data[off] & 0x0F) * 4
        if ihl < 20 or len(data) < off + ihl:
            return None
        num = data[off + 9]
        src = _ipv4_str(data[off + 12:off + 16])
        dst = _ipv4_str(data[off + 16:off + 20])
        frag = struct.unpack_from(">H", data, off + 6)[0] & 0x1FFF
        l4 = off + ihl
        if frag and num in (6, 17, 1, 58):
            return {"proto": _PROTO_NAMES.get(num, str(num)), "num": num,
                    "src": src, "dst": dst, "sport": None, "dport": None}
    elif version == 6:
        if len(data) < off + 40:
            return None
        num = data[off + 6]
        src = _ipv6_str(data[off + 8:off + 24])
        dst = _ipv6_str(data[off + 24:off + 40])
        l4 = off + 40
        hops = 0
        while num in (0, 43, 44, 60) and hops < 6:
            if len(data) < l4 + 2:
                return None
            nxt = data[l4]
            hlen = (data[l4 + 1] + 1) * 8
            if hlen <= 0 or len(data) < l4 + hlen:
                return None
            num = nxt
            l4 += hlen
            hops += 1
    else:
        return None

    sport = dport = None
    if num in (6, 17):
        if len(data) < l4 + 4:
            return None
        sport, dport = struct.unpack_from(">HH", data, l4)
    return {"proto": _PROTO_NAMES.get(num, str(num)), "num": num,
            "src": src, "dst": dst, "sport": sport, "dport": dport}


def flow_key(decoded):
    a = (decoded["src"], decoded.get("sport") or 0)
    b = (decoded["dst"], decoded.get("dport") or 0)
    if a > b:
        a, b = b, a
    return (decoded["proto"], a[0], a[1], b[0], b[1])


def flow_label(decoded):
    proto = decoded["proto"]
    a = decoded["src"]
    b = decoded["dst"]
    sp, dp = decoded.get("sport"), decoded.get("dport")
    if sp is not None and dp is not None:
        return f"{proto} {a}:{sp} <-> {b}:{dp}"
    return f"{proto} {a} <-> {b}"


def _norm_set(value, conv):
    if value is None:
        return None
    if isinstance(value, (list, tuple, set, frozenset)):
        items = value
    else:
        items = [value]
    try:
        return frozenset(conv(v) for v in items)
    except (TypeError, ValueError):
        raise PcapError(f"bad filter value {value!r}")


def compile_filter(spec):
    if not spec:
        return None
    out = {}
    for key in FILTER_KEYS:
        if key not in spec or spec[key] in (None, ""):
            continue
        if key in ("host", "src", "dst"):
            out[key] = _norm_set(spec[key], str)
        elif key in ("port", "sport", "dport"):
            out[key] = _norm_set(spec[key], int)
        elif key == "proto":
            out[key] = _norm_set(spec[key], lambda v: str(v).lower())
    return out or None


def filter_matches(compiled, decoded):
    if compiled is None:
        return True
    if decoded is None:
        return False
    if "host" in compiled and decoded["src"] not in compiled["host"] \
            and decoded["dst"] not in compiled["host"]:
        return False
    if "src" in compiled and decoded["src"] not in compiled["src"]:
        return False
    if "dst" in compiled and decoded["dst"] not in compiled["dst"]:
        return False
    if "port" in compiled:
        if decoded.get("sport") not in compiled["port"] \
                and decoded.get("dport") not in compiled["port"]:
            return False
    if "sport" in compiled and decoded.get("sport") not in compiled["sport"]:
        return False
    if "dport" in compiled and decoded.get("dport") not in compiled["dport"]:
        return False
    if "proto" in compiled:
        proto = decoded["proto"]
        num = str(decoded["num"])
        if proto not in compiled["proto"] and num not in compiled["proto"]:
            return False
    return True


# ------------------------------------------------------------------ time ---

_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def iso_ts(ns):
    if ns is None:
        return ""
    dt = _EPOCH + datetime.timedelta(microseconds=ns // 1000)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(value):
    """Parse epoch seconds (int/float/str) or ISO-8601 into epoch seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    iso = text.replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(iso)
    except ValueError:
        raise PcapError(f"cannot parse time {text!r} (use ISO-8601 or epoch seconds)")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp()


def parse_size(text):
    mt = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgKMG]?)[bB]?\s*", str(text))
    if not mt:
        raise argparse.ArgumentTypeError(
            f"bad size {text!r} (examples: 50M, 512K, 1G, 1048576)")
    mult = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}[mt.group(2).lower()]
    n = int(float(mt.group(1)) * mult)
    if n <= 0:
        raise argparse.ArgumentTypeError("size must be positive")
    return n


def parse_duration(text):
    mt = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?\s*", str(text))
    if not mt:
        raise argparse.ArgumentTypeError(
            f"bad duration {text!r} (examples: 30s, 10m, 2h, 1d)")
    mult = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, None: 1}[mt.group(2)]
    seconds = float(mt.group(1)) * mult
    if seconds <= 0:
        raise argparse.ArgumentTypeError("duration must be positive")
    return seconds


# --------------------------------------------------------- chunk sets ------

_CAPTURE_EXTS = {".pcap", ".pcapng", ".cap"}
_STAMP_FMT = "%Y%m%dT%H%M%S"


def _strip_compression_ext(name):
    low = name.lower()
    for suffix in (".gz", ".zst"):
        if low.endswith(suffix):
            return name[:-len(suffix)]
    return name


def _logical_ext(ext):
    return _strip_compression_ext(ext)


def _chunk_parse(name):
    m = TIME_RE.match(name)
    if m:
        return {"stem": m.group("stem"), "ext": m.group("ext"),
                "id": int(m.group("id")), "style": "time",
                "start": m.group("start"), "end": m.group("end")}
    m = INDEX_RE.match(name)
    if m:
        return {"stem": m.group("stem"), "ext": m.group("ext"),
                "id": int(m.group("id")), "style": "index",
                "start": None, "end": None}
    return None


def chunk_matches_name_style(name):
    """True when `name` looks like a chunk file produced by split."""
    return _chunk_parse(name) is not None


def _is_capture_chunk_name(name):
    info = _chunk_parse(name)
    if not info:
        return False
    return _logical_ext(info["ext"]).lower() in _CAPTURE_EXTS


def _stamp(ns):
    if ns is None:
        ns = 0
    dt = _EPOCH + datetime.timedelta(microseconds=ns // 1000)
    return dt.strftime(_STAMP_FMT)


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stem_ext(path, compressed):
    base = os.path.basename(path)
    if compressed:
        low = base.lower()
        for suffix in (".gz", ".zst"):
            if low.endswith(suffix):
                base = base[:-len(suffix)]
                break
    stem, ext = os.path.splitext(base)
    if not stem:
        stem = base or "capture"
    return stem, ext or ".pcap"


class ChunkSet(NamedTuple):
    folder: str
    manifest: Optional[dict]
    names: List[str]
    merged_name: str
    sha256: Optional[str]
    chunks: List[dict]
    schema: Optional[int]
    hash_name: str


def _read_manifest(folder):
    path = os.path.join(folder, MANIFEST)
    if not os.path.isfile(path):
        return None
    try:
        with open(_fs(path), "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError:
        raise
    except ValueError as e:
        raise PcapError(f"{path} is not valid JSON ({e})")
    if not isinstance(data, dict) or not isinstance(data.get("chunks"), list):
        raise PcapError(f"{path} is not a PcapChunk manifest")
    return data


def _manifest_stem(manifest):
    for c in manifest.get("chunks") or []:
        info = _chunk_parse(c.get("file", ""))
        if info:
            return info["stem"]
    source = manifest.get("source") or ""
    return os.path.splitext(source)[0] if source else None


def _manifest_hash(manifest):
    digest = manifest.get("digest") or manifest.get("sha256")
    return digest


def _chunk_record(raw, index):
    return {
        "file": raw["file"],
        "index": int(raw.get("index", index)),
        "bytes": raw.get("bytes"),
        "raw_bytes": raw.get("raw_bytes", raw.get("bytes")),
        "packets": raw.get("packets"),
        "sha256": raw.get("sha256"),
        "first_ts_ns": raw.get("first_ts_ns"),
        "last_ts_ns": raw.get("last_ts_ns"),
        "first_packet": raw.get("first_packet"),
        "last_packet": raw.get("last_packet"),
        "offset": raw.get("offset"),
        "compressed": raw.get("compressed"),
    }


def discover_chunks(folder, require_files=True):
    """Return a ChunkSet for a chunk folder, using manifest.json when present."""
    if not os.path.isdir(folder):
        raise PcapError(f"{folder} is not a folder")
    manifest = _read_manifest(folder)
    if manifest is not None:
        chunks = []
        for i, raw in enumerate(manifest["chunks"]):
            if not isinstance(raw, dict) or not raw.get("file"):
                raise PcapError(f"{MANIFEST} has an invalid chunk entry")
            chunks.append(_chunk_record(raw, i + 1))
        names = [c["file"] for c in chunks]
        if require_files:
            missing = [n for n in names
                       if not os.path.isfile(os.path.join(folder, n))]
            if missing:
                raise PcapError("missing chunk files: " + ", ".join(missing))
        merged = manifest.get("merged_name")
        if not merged:
            info = _chunk_parse(names[0])
            if info:
                merged = info["stem"] + _logical_ext(info["ext"])
            else:
                merged = os.path.basename(manifest.get("source") or "capture")
        return ChunkSet(folder, manifest, names, merged,
                        _manifest_hash(manifest), chunks,
                        int(manifest.get("schema", 1)),
                        manifest.get("hash", "sha256") or "sha256")

    groups = {}
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if not os.path.isfile(path) or not _is_capture_chunk_name(name):
            continue
        info = _chunk_parse(name)
        groups.setdefault((info["stem"], info["ext"].lower()), []).append(
            (info["id"], name))
    if not groups:
        raise PcapError(f"no <name>_<id>.<ext> chunk files found in {folder}")
    if len(groups) > 1:
        sets = ", ".join(stem + ext for stem, ext in groups)
        raise PcapError(f"folder holds chunks of several captures ({sets}); "
                        "keep one per folder or use a manifest")
    (stem, ext), items = next(iter(groups.items()))
    items.sort()
    ids = [i for i, _ in items]
    if ids[0] != 1:
        raise PcapError(f"chunk numbering starts at {ids[0]:04d}; "
                        f"missing {MANIFEST} and earlier chunks")
    expected_ids = list(range(1, len(ids) + 1))
    if ids != expected_ids:
        missing = sorted(set(expected_ids) - set(ids))
        raise PcapError("chunk ids are not contiguous; missing "
                        + ", ".join(f"{i:04d}" for i in missing))
    chunks = []
    for i, (cid, name) in enumerate(items, 1):
        size = os.path.getsize(os.path.join(folder, name))
        chunks.append({"file": name, "index": cid, "bytes": size,
                       "raw_bytes": size, "packets": None, "sha256": None,
                       "first_ts_ns": None, "last_ts_ns": None,
                       "first_packet": None, "last_packet": None,
                       "offset": None, "compressed": None})
    return ChunkSet(folder, None, [c["file"] for c in chunks],
                    stem + _logical_ext(ext), None, chunks, None, "sha256")


def default_outdir(path):
    base = _strip_compression_ext(os.path.basename(path))
    stem = os.path.splitext(base)[0] or base
    return os.path.join(os.path.dirname(os.path.abspath(path)), stem + "_chunks")


def default_merge_output(folder):
    return os.path.join(folder, discover_chunks(folder).merged_name)


def existing_chunk_files(folder, stem=None, ext=None):
    """Files a new split would replace in `folder` (never unrelated user files)."""
    if not os.path.isdir(folder):
        return []
    found = set()
    manifest = _read_manifest(folder)
    if manifest is not None:
        include_manifest = stem is None or _manifest_stem(manifest) == stem
        if include_manifest:
            for c in manifest["chunks"]:
                if isinstance(c, dict) and c.get("file"):
                    found.add(c["file"])
            found.add(MANIFEST)
            if os.path.isfile(os.path.join(folder, SUMS)):
                found.add(SUMS)
    for name in os.listdir(folder):
        if not os.path.isfile(os.path.join(folder, name)):
            continue
        info = _chunk_parse(name)
        if not info:
            continue
        if stem is not None and info["stem"] != stem:
            continue
        if ext is not None and info["ext"].lower() != ext.lower():
            continue
        found.add(name)
    return sorted(found)


# -------------------------------------------------------------- manifest ---


def _fsync_dir(path):
    if os.name == "nt":
        return
    try:
        fd = os.open(path or ".", os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write_json(path, data):
    tmp = path + ".tmp"
    with open(_fs(tmp), "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(_fs(tmp), _fs(path))
    _fsync_dir(os.path.dirname(path) or ".")


def _raw_digest(path, hash_name="sha256"):
    h = new_hash(hash_name)
    with open(_fs(path), "rb") as f:
        while True:
            data = f.read(BUF)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


def _write_sums(folder, chunks):
    """Write a sha256sum-compatible SHA256SUMS for the on-disk chunk files."""
    entries = []
    for c in chunks:
        path = os.path.join(folder, c["file"])
        if not os.path.isfile(path):
            continue
        digest = c.get("sha256") if not c.get("compressed") else _raw_digest(path)
        if digest:
            entries.append((c["file"], digest))
    manifest_path = os.path.join(folder, MANIFEST)
    if os.path.isfile(manifest_path):
        entries.append((MANIFEST, _raw_digest(manifest_path)))
    entries.sort()
    tmp = os.path.join(folder, SUMS + ".tmp")
    with open(_fs(tmp), "w", encoding="utf-8", newline="\n") as f:
        for name, digest in entries:
            f.write(f"{digest}  {name}\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(_fs(tmp), _fs(os.path.join(folder, SUMS)))


def _read_index_csv(path):
    """Not used by the engine; kept for future tooling."""
    with open(_fs(path), "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _write_index_csv(path, chunks):
    header = ["index", "file", "bytes", "raw_bytes", "packets", "first_ts",
              "last_ts", "first_packet", "last_packet", "sha256"]
    tmp = path + ".tmp"
    with open(_fs(tmp), "w", encoding="utf-8", newline="\n") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for c in chunks:
            writer.writerow([
                c.get("index"), c.get("file"), c.get("bytes"),
                c.get("raw_bytes"), c.get("packets"),
                iso_ts(c.get("first_ts_ns")), iso_ts(c.get("last_ts_ns")),
                c.get("first_packet"), c.get("last_packet"), c.get("sha256"),
            ])
    os.replace(_fs(tmp), _fs(path))


# ---------------------------------------------------------------- locking --


class _Lock:
    """Advisory per-folder lock so two jobs cannot split into one folder."""

    def __init__(self, folder):
        self.folder = folder
        self.path = os.path.join(folder, LOCKNAME)
        self.fd = None

    def _owner_alive(self):
        try:
            with open(_fs(self.path), "r", encoding="utf-8") as f:
                parts = f.read().split()
            pid = int(parts[0])
        except (OSError, ValueError, IndexError):
            return False
        if pid == os.getpid():
            return True
        if os.name == "nt":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                handle = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED
                if handle:
                    kernel32.CloseHandle(handle)
                    return True
                return False
            except Exception:
                return True
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def acquire(self):
        for attempt in range(2):
            try:
                fd = os.open(_fs(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except FileExistsError:
                if attempt == 0 and not self._owner_alive():
                    try:
                        os.remove(_fs(self.path))
                    except OSError:
                        pass
                    continue
                raise PcapError(
                    f"another PcapChunk job is already writing to "
                    f"{os.path.dirname(self.path)} (lock: {self.path})")
            self.fd = fd
            try:
                os.write(fd, f"{os.getpid()}\n{time.time():.0f}\n".encode())
            except OSError:
                pass
            return
            # unreachable
        raise PcapError(f"cannot lock {self.path}")

    def release(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
        try:
            os.remove(_fs(self.path))
        except OSError:
            pass


# --------------------------------------------------------------- staging ---


class _Staging:
    """Write chunks into .pcapchunk-staging, promote only when complete."""

    def __init__(self, outdir, resume=False, hash_name="sha256"):
        self.outdir = outdir
        self.path = os.path.join(outdir, STAGING)
        self.resume = resume
        self.hash_name = hash_name
        self.chunks = []
        self.consumed = 0
        self.journal = None

    def prepare(self, source, kind, mode_value):
        if os.path.isdir(self.path):
            if self.resume:
                if self._load(source, kind, mode_value):
                    self._clean_unlisted()
                    return True
                warn("staging data is unusable; starting a fresh split")
            shutil.rmtree(self.path, ignore_errors=True)
        os.makedirs(self.path, exist_ok=True)
        return False

    def _load(self, source, kind, mode_value):
        path = os.path.join(self.path, MANIFEST)
        if not os.path.isfile(path):
            return False
        try:
            with open(_fs(path), "r", encoding="utf-8") as f:
                journal = json.load(f)
        except (OSError, ValueError):
            return False
        if not isinstance(journal, dict) or journal.get("status") != "incomplete":
            return False
        if os.path.basename(journal.get("source") or "") != os.path.basename(source):
            return False
        mode = journal.get("mode") or {}
        if mode.get("kind") != kind:
            return False
        stored = mode.get("value", mode.get(kind))
        if isinstance(mode_value, list):
            try:
                if [float(x) for x in stored] != [float(x) for x in mode_value]:
                    return False
            except (TypeError, ValueError):
                return False
        elif stored != mode_value:
            return False
        chunks = journal.get("chunks") or []
        if not isinstance(chunks, list):
            return False
        for c in chunks:
            path = os.path.join(self.path, c.get("file", ""))
            if not os.path.isfile(path):
                return False
            expected_size = c.get("bytes")
            if expected_size is not None and os.path.getsize(path) != expected_size:
                return False
            expected_hash = c.get("sha256")
            if expected_hash:
                stream, _ = _open_chunk_stream(path)
                try:
                    if _stream_digest(stream, self.hash_name) != expected_hash:
                        return False
                finally:
                    stream.close()
        self.chunks = chunks
        self.consumed = int(journal.get("consumed") or 0)
        self.journal = journal
        return True

    def _clean_unlisted(self):
        keep = {c.get("file") for c in self.chunks} | {MANIFEST}
        for name in os.listdir(self.path):
            if name not in keep:
                try:
                    os.remove(os.path.join(self.path, name))
                except OSError:
                    pass

    def write_journal(self, data):
        _atomic_write_json(os.path.join(self.path, MANIFEST), data)

    def mark_incomplete(self):
        os.makedirs(self.outdir, exist_ok=True)
        marker = os.path.join(self.outdir, INCOMPLETE)
        with open(_fs(marker), "w", encoding="utf-8") as f:
            f.write(f"{APP_NAME} {__version__}: split in progress in {self.outdir}\n")
            f.flush()
            os.fsync(f.fileno())

    def clear_marker(self):
        try:
            os.remove(_fs(os.path.join(self.outdir, INCOMPLETE)))
        except OSError:
            pass

    def finish(self, manifest, chunks, old_files):
        self.write_journal(manifest)
        if (manifest.get("hash") or "sha256") == "sha256":
            _write_sums(self.path, chunks)
        self.promote(chunks, old_files)

    def promote(self, chunks, old_files):
        os.makedirs(self.outdir, exist_ok=True)
        self.mark_incomplete()
        for name in old_files:
            try:
                os.remove(_fs(os.path.join(self.outdir, name)))
            except OSError:
                pass
        for c in chunks:
            src = os.path.join(self.path, c["file"])
            dst = os.path.join(self.outdir, c["file"])
            os.replace(_fs(src), _fs(dst))
        for name in (MANIFEST, SUMS):
            src = os.path.join(self.path, name)
            if os.path.isfile(src):
                os.replace(_fs(src), _fs(os.path.join(self.outdir, name)))
        self.clear_marker()
        shutil.rmtree(self.path, ignore_errors=True)

    def abort(self, keep=False):
        if keep:
            return
        shutil.rmtree(self.path, ignore_errors=True)
        self.clear_marker()


# --------------------------------------------------------------- rotation --


class _Policy:
    def __init__(self, kind, value, total=0, local_time=False):
        self.kind = kind
        self.value = value
        self.total = total
        self.local_time = local_time
        self.first_ts = None
        self.prev_ts = None
        self.boundary = None
        self.period_ns = int(float(value) * 1e9) if kind == "every" else 0
        self.gap_ns = int(float(value) * 1e9) if kind == "gap" else 0

    def observe(self, ts):
        if ts is None:
            return
        if self.first_ts is None:
            self.first_ts = ts
            if self.kind == "every":
                self.boundary = (ts // self.period_ns + 1) * self.period_ns
            elif self.kind == "split_at":
                self.boundary = self._next_daily(ts)
        self.prev_ts = ts

    def due(self, writer, consumed, ts, next_len):
        if writer.chunk is None or writer.packets == 0:
            return False
        if self.kind == "size":
            return writer.raw_bytes + next_len > self.value
        if self.kind == "packets":
            return writer.packets >= self.value
        if self.kind == "chunks":
            if not self.total:
                return False
            return (writer.idx < self.value
                    and consumed >= writer.idx * self.total / self.value)
        if ts is None:
            return False
        if self.kind == "every":
            return ts >= self.boundary
        if self.kind == "gap":
            return self.prev_ts is not None and ts - self.prev_ts >= self.gap_ns
        if self.kind == "split_at":
            return ts >= self.boundary
        return False

    def after_rotate(self, ts):
        if ts is None:
            return
        if self.kind == "every":
            while ts >= self.boundary:
                self.boundary += self.period_ns
        elif self.kind == "split_at":
            self.boundary = self._next_daily(ts)

    def _next_daily(self, ts_ns):
        sec = ts_ns // 1_000_000_000
        if self.local_time:
            base = datetime.datetime.fromtimestamp(sec)
        else:
            base = _EPOCH + datetime.timedelta(seconds=sec)
        sod = base.hour * 3600 + base.minute * 60 + base.second
        for tod in self.value:
            if tod > sod:
                candidate = base.replace(hour=int(tod // 3600),
                                         minute=int((tod % 3600) // 60),
                                         second=int(tod % 60), microsecond=0)
                if self.local_time:
                    return int(candidate.timestamp() * 1_000_000_000)
                return int((candidate - _EPOCH).total_seconds() * 1_000_000_000)
        nxt = base.replace(hour=0, minute=0, second=0, microsecond=0) \
            + datetime.timedelta(days=1)
        tod = self.value[0]
        candidate = nxt.replace(hour=int(tod // 3600), minute=int((tod % 3600) // 60),
                                second=int(tod % 60))
        if self.local_time:
            return int(candidate.timestamp() * 1_000_000_000)
        return int((candidate - _EPOCH).total_seconds() * 1_000_000_000)


def _parse_split_at(values):
    if isinstance(values, str):
        values = [v.strip() for v in values.split(",") if v.strip()]
    out = []
    for value in values:
        if isinstance(value, (int, float)):
            out.append(float(value) % 86400)
            continue
        m = re.fullmatch(r"(\d{1,2}):(\d{2})(?::(\d{2}))?", str(value).strip())
        if not m:
            raise PcapError(f"bad split-at time {value!r} (use HH:MM or HH:MM:SS)")
        h, mi, se = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
        if h > 23 or mi > 59 or se > 59:
            raise PcapError(f"bad split-at time {value!r}")
        out.append(h * 3600 + mi * 60 + se)
    if not out:
        raise PcapError("split-at needs at least one time of day")
    return sorted(set(out))


# ------------------------------------------------------------ chunk write --


class _ChunkOut:
    """Writes chunk files (or just plans them) and reports metadata per chunk."""

    def __init__(self, directory, stem, ext, compression, name_style, hash_name,
                 plan=False, on_close=None):
        self.directory = directory
        self.stem = stem
        self.ext = ext
        self.compression = compression
        self.name_style = name_style
        self.hash_name = hash_name
        self.plan = plan
        self.on_close = on_close
        self.chunks = []
        self.idx = 0
        self.chunk = None
        self.f = None
        self.raw = None
        self.raw_bytes = 0
        self.packets = 0
        self.first_ts = None
        self.last_ts = None
        self.hasher = None
        self.current_path = None

    def _suffix(self):
        if self.compression == "gzip":
            return ".gz"
        if self.compression == "zstd":
            return ".zst"
        return ""

    def _chunk_name(self, idx, start=None, end=None):
        if self.name_style == "time" and start is not None:
            end = end if end is not None else start
            return (f"{self.stem}_{_stamp(start)}-{_stamp(end)}_{idx:04d}"
                    f"{self.ext}{self._suffix()}")
        return f"{self.stem}_{idx:04d}{self.ext}{self._suffix()}"

    def open(self, prefix, offset, first_packet):
        self.close(offset)
        self.idx += 1
        # `offset` is the cumulative size of the chunk files before this one,
        # i.e. where this chunk starts if the chunk files are concatenated.
        offset = sum(int(c.get("bytes") or 0) for c in self.chunks)
        name = self._chunk_name(self.idx)
        self.chunk = {
            "index": self.idx, "file": name, "bytes": 0, "raw_bytes": 0,
            "packets": 0, "sha256": None, "offset": offset,
            "first_packet": first_packet, "first_ts_ns": None,
            "last_ts_ns": None, "last_packet": None,
            "compressed": self.compression,
        }
        self.raw_bytes = 0
        self.packets = 0
        self.first_ts = None
        self.last_ts = None
        self.hasher = new_hash(self.hash_name)
        if not self.plan:
            self.current_path = os.path.join(self.directory, name)
            if self.compression == "gzip":
                self.raw = open(_fs(self.current_path), "wb")
                self.f = gzip.GzipFile(fileobj=self.raw, mode="wb", mtime=0)
            elif self.compression == "zstd":
                self.raw = None
                self.f = _zstd.open(_fs(self.current_path), "wb")
            else:
                self.raw = None
                self.f = open(_fs(self.current_path), "wb", buffering=BUF)
        self._write(prefix)

    def _write(self, data):
        if self.f is not None:
            self.f.write(data)
        self.hasher.update(data)
        self.raw_bytes += len(data)

    def write(self, raw, ts_ns=None, is_packet=True):
        self._write(raw)
        if is_packet:
            self.packets += 1
            if ts_ns is not None:
                if self.first_ts is None or ts_ns < self.first_ts:
                    self.first_ts = ts_ns
                if self.last_ts is None or ts_ns > self.last_ts:
                    self.last_ts = ts_ns

    def close(self, consumed=0):
        if self.chunk is None:
            return
        if self.f is not None:
            try:
                self.f.close()
            finally:
                if self.raw is not None and self.raw is not self.f:
                    try:
                        self.raw.close()
                    except OSError:
                        pass
            self.f = None
            self.raw = None
        chunk = self.chunk
        size = self.raw_bytes if self.plan else os.path.getsize(_fs(self.current_path))
        chunk.update({
            "bytes": size, "raw_bytes": self.raw_bytes, "packets": self.packets,
            "sha256": self.hasher.hexdigest(),
            "first_ts_ns": self.first_ts, "last_ts_ns": self.last_ts,
            "last_packet": (chunk["first_packet"] + self.packets - 1
                            if self.packets else None),
        })
        if self.name_style == "time" and self.packets:
            new_name = self._chunk_name(self.idx, self.first_ts, self.last_ts)
            if not self.plan and new_name != chunk["file"]:
                new_path = os.path.join(self.directory, new_name)
                try:
                    os.replace(_fs(self.current_path), _fs(new_path))
                except OSError as e:
                    raise PcapError(f"cannot rename chunk {chunk['file']}: {e}")
                self.current_path = new_path
            chunk["file"] = new_name
        self.chunks.append(chunk)
        self.chunk = None
        self.current_path = None
        if self.on_close is not None:
            self.on_close(chunk, consumed)

    def abort(self):
        if self.f is not None:
            try:
                self.f.close()
            except OSError:
                pass
        if self.raw is not None and self.raw is not self.f:
            try:
                self.raw.close()
            except OSError:
                pass
        self.f = None
        self.raw = None
        self.chunk = None


# ------------------------------------------------------------------ split --


def _split_mode(args, target):
    given = []
    for key in ("size", "packets", "chunks", "every", "gap", "split_at"):
        value = args.get(key)
        if value is not None:
            given.append((key, value))
    if target is not None:
        if target not in PRESETS:
            raise PcapError(f"unknown preset {target!r} (choose from "
                            + ", ".join(sorted(PRESETS)) + ")")
        if given:
            raise PcapError("--target cannot be combined with another split mode")
        given = [("size", PRESETS[target])]
    if not given:
        given = [("size", 50 << 20)]
    if len(given) > 1:
        raise PcapError("choose only one split mode (size, chunks, packets, "
                        "every, gap or split-at)")
    kind, value = given[0]
    if kind in ("size", "packets", "chunks"):
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise PcapError(f"{kind} must be a whole number")
        if value <= 0:
            raise PcapError(f"{kind} must be positive")
    elif kind in ("every", "gap"):
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise PcapError(f"{kind} must be a duration in seconds")
        if value <= 0:
            raise PcapError(f"{kind} must be positive")
    else:
        value = _parse_split_at(value)
    return kind, value


def _mode_manifest(kind, value):
    data = {"kind": kind}
    if kind == "split_at":
        data["value"] = [int(v) for v in value]
    else:
        data["value"] = value
    return data


def _split_summary(path, outdir, fmt, size, digest, writer, dry_run, index_csv=None,
                   plan=None):
    return {
        "input": path, "outdir": outdir, "format": fmt, "size": size,
        "sha256": digest, "chunks": len(writer.chunks),
        "packets": sum(int(c.get("packets") or 0) for c in writer.chunks),
        "bytes": sum(int(c.get("bytes") or 0) for c in writer.chunks),
        "dry_run": bool(dry_run),
        "plan": plan, "index_csv": index_csv,
    }


def split_steps(path, outdir=None, size=None, packets=None, chunks=None, *,
                every=None, gap=None, split_at=None, local_time=False,
                target=None, force=False, resume=False, compress=None,
                name_style="index", hash_name="sha256", index_csv=None,
                dry_run=False, salvage=False, space_check=True, max_record=None):
    """Generator: split `path`. Yields (bytes_done, bytes_total); returns a summary."""
    if not os.path.isfile(path):
        raise PcapError(f"{path} is not a file")
    args = {"size": size, "packets": packets, "chunks": chunks,
            "every": every, "gap": gap, "split_at": split_at}
    kind, value = _split_mode(args, target)
    if compress in ("none", ""):
        compress = None
    if compress not in COMPRESSIONS:
        raise PcapError(f"unsupported compression {compress!r} (gzip or zstd)")
    if compress == "zstd" and _zstd is None:
        raise PcapError("zstd output needs Python 3.14+ (compression.zstd)")
    if name_style not in ("index", "time"):
        raise PcapError("name_style must be 'index' or 'time'")
    new_hash(hash_name)

    stream, fmt, src_comp, logical = open_capture(path)
    f = HashingReader(stream, hash_name)
    stem, ext = _stem_ext(path, src_comp)
    outdir = outdir or default_outdir(path)
    total = logical if logical is not None else 0
    if kind == "chunks" and not total:
        f.f.close()
        raise PcapError("splitting by number of chunks needs an uncompressed source")

    writer = None
    staging = None
    lock = None
    promoted = False
    skip_until = 0
    total_packets = 0
    capture_first = None
    capture_last = None
    capture_interfaces = []
    capture_linktype = None
    capture_snaplen = None
    capture_precision = None

    try:
        if not dry_run:
            os.makedirs(outdir, exist_ok=True)
            lock = _Lock(outdir)
            lock.acquire()
            manifest = _read_manifest(outdir)
            if manifest is not None:
                other = _manifest_stem(manifest)
                if other and other != stem:
                    raise PcapError(
                        f"{outdir} already holds chunks of {other!r}; "
                        "use a different output folder")
            old = existing_chunk_files(outdir, stem)
            if old and not force and not resume:
                raise PcapError(f"{outdir} already contains chunk files for "
                                f"{stem!r} ({len(old)} file(s)); use --force to replace them")
            staging = _Staging(outdir, resume=resume, hash_name=hash_name)
            resumed = staging.prepare(path, kind, value)
            staging.mark_incomplete()
            if resumed:
                skip_until = staging.consumed
                total_packets = sum(int(c.get("packets") or 0) for c in staging.chunks)
                journal = staging.journal or {}
                cap = journal.get("capture") or {}
                capture_first = cap.get("first_ts_ns")
                capture_last = cap.get("last_ts_ns")
                capture_interfaces = list(cap.get("interfaces") or [])
                capture_linktype = cap.get("linktype")
                capture_snaplen = cap.get("snaplen")
                capture_precision = cap.get("precision")
            if space_check and total and not resumed:
                old_total = sum(os.path.getsize(os.path.join(outdir, n))
                                for n in old
                                if os.path.isfile(os.path.join(outdir, n)))
                need = total + old_total + (1 << 20)
                try:
                    free = shutil.disk_usage(outdir).free
                except OSError:
                    free = None
                if free is not None and free < need:
                    raise PcapError(
                        f"not enough free space in {outdir}: need about "
                        f"{need:,} bytes, {free:,} available "
                        "(use --no-space-check to try anyway)")

        plan = dry_run
        writer = _ChunkOut(staging.path if staging is not None else None,
                           stem, ext, compress, name_style, hash_name, plan=plan)
        if staging is not None and staging.chunks:
            writer.chunks = [dict(c) for c in staging.chunks]
            writer.idx = len(writer.chunks)

        policy = _Policy(kind, value, total=total, local_time=local_time)

        def capture_dict():
            return {
                "linktype": capture_linktype, "snaplen": capture_snaplen,
                "precision": capture_precision,
                "interfaces": list(capture_interfaces),
                "packets": total_packets,
                "first_ts_ns": capture_first, "last_ts_ns": capture_last,
            }

        if resume and staging is not None:
            journal = {
                "schema": SCHEMA, "tool": APP_NAME, "version": __version__,
                "created": _now_iso(), "status": "incomplete",
                "source": os.path.basename(path), "format": fmt,
                "compressed": src_comp, "size": skip_until,
                "hash": hash_name, "sha256": None, "digest": None,
                "mode": _mode_manifest(kind, value), "naming": name_style,
                "compression": compress, "capture": capture_dict(),
                "chunks": writer.chunks, "consumed": skip_until,
            }

            def on_close(chunk, consumed):
                journal["chunks"] = writer.chunks
                journal["consumed"] = consumed
                journal["size"] = consumed
                journal["capture"] = capture_dict()
                staging.write_journal(journal)

            writer.on_close = on_close

        yield skip_until, total

        last_report = _tell(f)

        def progress():
            nonlocal last_report
            if f.pos - last_report >= PROGRESS_EVERY:
                last_report = f.pos
                return f.pos, total
            return None

        if fmt == "pcap":
            hdr = read_pcap_header(f)
            capture_linktype = hdr.linktype
            capture_snaplen = hdr.snaplen
            capture_precision = hdr.precision
            if capture_interfaces == []:
                capture_interfaces = [{"id": 0, "linktype": hdr.linktype,
                                       "snaplen": hdr.snaplen, "name": None,
                                       "tsresol": 9 if hdr.nano else 6,
                                       "section": 1}]
            for rec in iter_pcap_records(f, hdr, salvage=salvage,
                                         max_record=max_record):
                start = f.pos - len(rec.raw)
                if start < skip_until:
                    policy.observe(rec.ts_ns)
                    continue
                if writer.chunk is None:
                    writer.open(hdr.raw, 0 if writer.idx == 0 else start,
                                total_packets)
                elif policy.due(writer, start, rec.ts_ns, len(rec.raw)):
                    writer.close(start)
                    writer.open(hdr.raw, 0 if writer.idx == 0 else start,
                                total_packets)
                    policy.after_rotate(rec.ts_ns)
                writer.write(rec.raw, rec.ts_ns)
                policy.observe(rec.ts_ns)
                total_packets += 1
                if rec.ts_ns is not None:
                    if capture_first is None or rec.ts_ns < capture_first:
                        capture_first = rec.ts_ns
                    if capture_last is None or rec.ts_ns > capture_last:
                        capture_last = rec.ts_ns
                step = progress()
                if step:
                    yield step
            if writer.chunk is None and writer.idx == 0:
                writer.open(hdr.raw, 0, 0)
            writer.close(f.pos)
        else:
            reader = PcapngReader(f, salvage=salvage,
                                  max_block=max_record or MAX_PCAPNG_BLOCK)

            def prefix():
                if writer.idx == 0:
                    return b""
                return reader.prefix()

            for btype, raw in reader.blocks():
                start = reader.last_start
                if btype is None:
                    if start < skip_until:
                        continue
                    if writer.chunk is None:
                        writer.open(prefix(), start, total_packets)
                    writer.write(raw, None, is_packet=False)
                    step = progress()
                    if step:
                        yield step
                    continue
                is_pkt = btype in PACKET_BLOCKS
                ts = None
                if is_pkt:
                    meta = parse_pcapng_packet(btype, raw, reader.endian,
                                               reader.interfaces, salvage=salvage)
                    if meta:
                        ts = meta[4]
                if start < skip_until:
                    policy.observe(ts)
                    continue
                if btype == IDB and reader.interfaces:
                    capture_interfaces.append(reader.interfaces[-1].as_dict())
                    capture_linktype = reader.interfaces[0].linktype
                    capture_snaplen = reader.interfaces[0].snaplen
                    capture_precision = ("nsec" if reader.interfaces[0].tsresol == 9
                                         else "usec")
                if is_pkt:
                    if writer.chunk is None:
                        writer.open(prefix(), 0 if writer.idx == 0 else start,
                                    total_packets)
                    elif policy.due(writer, start, ts, len(raw)):
                        writer.close(start)
                        writer.open(prefix(), 0 if writer.idx == 0 else start,
                                    total_packets)
                        policy.after_rotate(ts)
                    writer.write(raw, ts, is_packet=True)
                    policy.observe(ts)
                    total_packets += 1
                    if ts is not None:
                        if capture_first is None or ts < capture_first:
                            capture_first = ts
                        if capture_last is None or ts > capture_last:
                            capture_last = ts
                else:
                    if writer.chunk is None:
                        writer.open(prefix(), start, total_packets)
                    writer.write(raw, None, is_packet=False)
                step = progress()
                if step:
                    yield step
            if writer.chunk is None and writer.idx == 0:
                writer.open(b"", 0, 0)
            writer.close(f.pos)

        digest = f.h.hexdigest()
        size_logical = f.pos
        chunks_list = writer.chunks

        if dry_run:
            yield (total, total) if total else (size_logical, size_logical)
            return _split_summary(path, outdir, fmt, size_logical, None, writer,
                                  True, None, plan=chunks_list)

        if staging is not None:
            manifest = {
                "schema": SCHEMA, "tool": APP_NAME, "version": __version__,
                "created": _now_iso(), "status": "complete",
                "source": os.path.basename(path), "format": fmt,
                "compressed": src_comp, "size": size_logical,
                "hash": hash_name,
                "sha256": digest if hash_name == "sha256" else None,
                "digest": digest,
                "mode": _mode_manifest(kind, value), "naming": name_style,
                "compression": compress, "capture": capture_dict(),
                "chunks": chunks_list,
            }
            staging.finish(manifest, chunks_list, old)
            promoted = True
            if index_csv:
                _write_index_csv(index_csv, chunks_list)

        yield (total, total) if total else (size_logical, size_logical)
        return _split_summary(path, outdir, fmt, size_logical, digest, writer,
                              False, index_csv)
    finally:
        if writer is not None:
            writer.abort()
        if staging is not None and not promoted:
            staging.abort(keep=bool(resume))
        if lock is not None:
            lock.release()
        try:
            stream.close()
        except OSError:
            pass


def split(*args, **kwargs):
    return run(split_steps(*args, **kwargs))


# ------------------------------------------------------------------ merge --


def _open_chunk_stream(path):
    comp = _compression_of(path)
    if comp is None:
        return open(_fs(path), "rb"), None
    if comp == "zstd" and _zstd is None:
        raise PcapError(f"{os.path.basename(path)} is zstd-compressed but this "
                        "Python has no compression.zstd")
    stream = _open_compressed(path, "rb")
    return _GuardedStream(stream, os.path.basename(path), comp), comp


def _stream_digest(stream, hash_name):
    h = new_hash(hash_name)
    while True:
        data = stream.read(BUF)
        if not data:
            break
        h.update(data)
    return h.hexdigest()


def _check_chunk_digest(path, expected, actual, hash_name):
    if expected and expected != actual:
        raise PcapError(f"{os.path.basename(path)} is corrupt: {hash_name} is "
                        f"{actual}, expected {expected}")


def _merge_pcap(paths, out, checks, hash_name, salvage):
    first = None
    for i, path in enumerate(paths):
        stream, _ = _open_chunk_stream(path)
        reader = HashingReader(stream, hash_name)
        try:
            hdr = read_pcap_header(reader)
        except PcapError as e:
            stream.close()
            raise PcapError(f"{os.path.basename(path)}: {e}")
        if first is None:
            first = hdr
            out.write(hdr.raw)
        elif hdr.raw != first.raw:
            stream.close()
            raise PcapError(f"{os.path.basename(path)} has a different pcap header "
                            "(link type / snaplen / precision); cannot merge")
        yield len(hdr.raw)
        while True:
            data = reader.read(BUF)
            if not data:
                break
            out.write(data)
            yield len(data)
        stream.close()
        _check_chunk_digest(path, checks[i], reader.h.hexdigest(), hash_name)


def _merge_pcapng(paths, out, checks, hash_name, salvage):
    cur_shb = b""
    cur_idbs = []
    for i, path in enumerate(paths):
        stream, _ = _open_chunk_stream(path)
        reader = HashingReader(stream, hash_name)
        pcapng = PcapngReader(reader, salvage=salvage)
        blocks = pcapng.blocks()
        if i > 0:
            prefix = ([cur_shb] if cur_shb else []) + list(cur_idbs)
            for want in prefix:
                btype, raw = next(blocks, (None, b""))
                if raw != want:
                    stream.close()
                    raise PcapError(
                        f"{os.path.basename(path)} does not continue the previous "
                        "chunk (unexpected header blocks); was it reordered?")
                if btype == SHB:
                    cur_shb, cur_idbs = raw, []
                elif btype == IDB:
                    cur_idbs.append(raw)
                yield len(raw)
        for btype, raw in blocks:
            if btype == SHB:
                cur_shb, cur_idbs = raw, []
            elif btype == IDB:
                cur_idbs.append(raw)
            out.write(raw)
            yield len(raw)
        stream.close()
        _check_chunk_digest(path, checks[i], reader.h.hexdigest(), hash_name)


def merge_steps(folder, output=None, force=False, verify=True,
                allow_missing=False, salvage=False):
    """Generator: merge a chunk folder. Yields (bytes_done, bytes_total)."""
    chunkset = discover_chunks(folder, require_files=False)
    names = chunkset.names
    paths_all = [os.path.join(folder, n) for n in names]
    missing = [n for n, p in zip(names, paths_all) if not os.path.isfile(p)]
    if missing and not allow_missing:
        raise PcapError("missing chunk files: " + ", ".join(missing)
                        + " (use --allow-missing to merge what is there)")
    pairs = [(n, p) for n, p in zip(names, paths_all) if os.path.isfile(p)]
    if not pairs:
        raise PcapError(f"no chunk files left to merge in {folder}")
    names = [n for n, _ in pairs]
    paths = [p for _, p in pairs]
    output = output or os.path.join(folder, chunkset.merged_name)
    if os.path.exists(output) and not force:
        raise PcapError(f"{output} already exists; use --force to overwrite")
    parent = os.path.dirname(os.path.abspath(output))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    by_name = {c["file"]: c for c in chunkset.chunks}
    checks = []
    for name in names:
        c = by_name.get(name) or {}
        checks.append(c.get("sha256") if (verify and not salvage) else None)
    total = 0
    for name, path in zip(names, paths):
        c = by_name.get(name) or {}
        size = c.get("raw_bytes")
        if size is None or not isinstance(size, int):
            size = os.path.getsize(path)
        total += size
    fmt = detect_format(paths[0])
    expected = (chunkset.sha256
                if (verify and not missing and not salvage) else None)
    hash_name = chunkset.hash_name if chunkset.hash_name in HASH_NAMES else "sha256"

    tmp = output + ".part"
    done = 0
    last = 0
    yield 0, total
    try:
        with open(_fs(tmp), "wb", buffering=BUF) as raw_out:
            out = HashingWriter(raw_out, hash_name)
            steps = (_merge_pcap(paths, out, checks, hash_name, salvage)
                     if fmt == "pcap"
                     else _merge_pcapng(paths, out, checks, hash_name, salvage))
            for n in steps:
                done += n
                if done - last >= PROGRESS_EVERY:
                    last = done
                    yield done, total
        if expected:
            actual = out.hexdigest()
            if actual != expected:
                raise PcapError("SHA-256 mismatch: merged file differs from the "
                                "original (the chunk set is incomplete or corrupt)")
        os.replace(_fs(tmp), _fs(output))
    except BaseException:
        try:
            if os.path.exists(tmp):
                os.remove(_fs(tmp))
        except OSError:
            pass
        raise
    yield total, total
    return {
        "folder": folder, "output": output, "chunks": len(paths),
        "size": os.path.getsize(_fs(output)),
        "verified": True if expected else None,
        "complete": not missing, "missing": missing,
        "schema": chunkset.schema,
    }


def merge(*args, **kwargs):
    return run(merge_steps(*args, **kwargs))


# ----------------------------------------------------------------- verify --


def _stream_digest_and_scan(path, fmt, salvage=False, hash_name="sha256"):
    """One decompressing pass: digest plus framing summary."""
    stream, _ = _open_chunk_stream(path)
    reader = HashingReader(stream, hash_name)
    out = {"packets": 0, "first_ts_ns": None, "last_ts_ns": None,
           "truncated": False, "sha256": None}
    try:
        if fmt == "pcap":
            try:
                hdr = read_pcap_header(reader)
            except PcapError as e:
                raise PcapError(f"{os.path.basename(path)}: {e}")
            for rec in iter_pcap_records(reader, hdr, salvage=salvage):
                out["packets"] += 1
                if rec.truncated:
                    out["truncated"] = True
                ts = rec.ts_ns
                if ts is not None:
                    if out["first_ts_ns"] is None or ts < out["first_ts_ns"]:
                        out["first_ts_ns"] = ts
                    if out["last_ts_ns"] is None or ts > out["last_ts_ns"]:
                        out["last_ts_ns"] = ts
        else:
            pcapng = PcapngReader(reader, salvage=salvage)
            for btype, raw in pcapng.blocks():
                if btype is None:
                    out["truncated"] = True
                    continue
                if btype in PACKET_BLOCKS:
                    meta = parse_pcapng_packet(btype, raw, pcapng.endian,
                                               pcapng.interfaces, salvage=salvage)
                    if meta is None:
                        out["truncated"] = True
                        continue
                    out["packets"] += 1
                    ts = meta[4]
                    if ts is not None:
                        if out["first_ts_ns"] is None or ts < out["first_ts_ns"]:
                            out["first_ts_ns"] = ts
                        if out["last_ts_ns"] is None or ts > out["last_ts_ns"]:
                            out["last_ts_ns"] = ts
            if pcapng.truncated:
                out["truncated"] = True
        out["sha256"] = reader.h.hexdigest()
        return out
    finally:
        stream.close()


def verify_steps(folder, deep=False):
    """Generator: check a chunk folder. Yields (bytes_done, bytes_total)."""
    chunkset = discover_chunks(folder, require_files=False)
    manifest = chunkset.manifest
    problems = []
    warnings = []
    if manifest is None:
        problems.append("no manifest.json: chunk hashes cannot be verified")
    if os.path.isdir(os.path.join(folder, STAGING)):
        problems.append("an unfinished split is present (.pcapchunk-staging)")
    if os.path.isfile(os.path.join(folder, INCOMPLETE)):
        problems.append("incomplete marker present (.pcapchunk-incomplete)")
    by_name = {c["file"]: c for c in chunkset.chunks}
    existing = [n for n in chunkset.names
                if os.path.isfile(os.path.join(folder, n))]
    total = sum(os.path.getsize(os.path.join(folder, n)) for n in existing)
    hash_name = chunkset.hash_name if chunkset.hash_name in HASH_NAMES else "sha256"
    report = {"folder": folder, "ok": False, "schema": chunkset.schema,
              "manifest": manifest is not None, "problems": problems,
              "warnings": warnings, "chunks": [],
              "missing": [n for n in chunkset.names
                          if n not in existing],
              "incomplete": os.path.isfile(os.path.join(folder, INCOMPLETE))
              or os.path.isdir(os.path.join(folder, STAGING))}
    yield 0, total
    done = 0
    for name in chunkset.names:
        entry = by_name.get(name) or {}
        path = os.path.join(folder, name)
        item = {
            "file": name, "ok": False, "bytes": None,
            "expected_bytes": entry.get("bytes"), "packets": None,
            "expected_packets": entry.get("packets"), "sha256": None,
            "expected_sha256": entry.get("sha256"),
            "first_ts_ns": None, "last_ts_ns": None, "problems": [],
        }
        if not os.path.isfile(path):
            item["problems"].append("missing file")
            problems.append(f"{name}: missing")
            report["chunks"].append(item)
            continue
        size = os.path.getsize(path)
        item["bytes"] = size
        done += size
        expected_size = entry.get("bytes")
        if expected_size is not None and size != expected_size:
            msg = f"size is {size:,}, manifest says {expected_size:,}"
            item["problems"].append(msg)
            problems.append(f"{name}: {msg}")
        try:
            fmt = detect_format(path)
        except PcapError as e:
            item["problems"].append(str(e))
            problems.append(f"{name}: {e}")
            report["chunks"].append(item)
            yield done, total
            continue
        try:
            scan = _stream_digest_and_scan(path, fmt, salvage=False,
                                           hash_name=hash_name)
        except (PcapError, OSError) as e:
            item["problems"].append(str(e))
            problems.append(f"{name}: {e}")
            report["chunks"].append(item)
            yield done, total
            continue
        item["sha256"] = scan["sha256"]
        item["packets"] = scan["packets"] if deep else entry.get("packets")
        item["first_ts_ns"] = scan["first_ts_ns"]
        item["last_ts_ns"] = scan["last_ts_ns"]
        expected_hash = entry.get("sha256")
        if expected_hash:
            if scan["sha256"] != expected_hash:
                msg = f"hash is {scan['sha256'][:16]}…, manifest says " \
                      f"{expected_hash[:16]}…"
                item["problems"].append(msg)
                problems.append(f"{name}: {msg}")
        elif manifest is not None and chunkset.schema == 2:
            warnings.append(f"{name}: manifest has no per-chunk hash")
        if deep:
            expected_packets = entry.get("packets")
            if expected_packets is not None and scan["packets"] != expected_packets:
                msg = f"{scan['packets']} packets, manifest says {expected_packets}"
                item["problems"].append(msg)
                problems.append(f"{name}: {msg}")
            expected_first = entry.get("first_ts_ns")
            expected_last = entry.get("last_ts_ns")
            if expected_first is not None and scan["first_ts_ns"] != expected_first:
                item["problems"].append("first timestamp does not match")
                problems.append(f"{name}: first timestamp does not match")
            if expected_last is not None and scan["last_ts_ns"] != expected_last:
                item["problems"].append("last timestamp does not match")
                problems.append(f"{name}: last timestamp does not match")
            if scan["truncated"]:
                item["problems"].append("truncated or corrupt framing")
                problems.append(f"{name}: truncated or corrupt framing")
        item["ok"] = not item["problems"]
        report["chunks"].append(item)
        yield done, total
    report["ok"] = (manifest is not None and not problems
                    and not report["missing"] and not report["incomplete"])
    return report


def verify(folder, deep=False):
    return run(verify_steps(folder, deep=deep))


# ------------------------------------------------------------------ info ---


def _pcapng_header_scan(stream):
    """Read only SHB/IDB blocks (seeking past everything else)."""
    interfaces = []
    endian = None
    section = 0
    next_id = 0
    while True:
        head = stream.read(8)
        if not head:
            break
        if len(head) < 8:
            raise PcapError("pcapng file ends with a truncated block header")
        if head[:4] == SHB_BYTES:
            bom = stream.read(4)
            if len(bom) < 4:
                raise PcapError("pcapng file ends with a truncated section header")
            if bom == BOM_LE:
                endian = "<"
            elif bom == BOM_BE:
                endian = ">"
            else:
                raise PcapError("pcapng section header has an invalid byte-order magic")
            blen = struct.unpack(endian + "I", head[4:8])[0]
            btype = SHB
            section += 1
            next_id = 0
            skip = blen - 12
        else:
            if endian is None:
                raise PcapError("pcapng file does not start with a section header")
            btype, blen = struct.unpack(endian + "II", head)
            skip = blen - 8
        if blen < 12 or blen % 4:
            raise PcapError(f"corrupt pcapng block length {blen:,}")
        if blen > MAX_PCAPNG_BLOCK:
            raise PcapError(f"pcapng block claims {blen:,} bytes "
                            f"(limit {MAX_PCAPNG_BLOCK:,})")
        if btype == IDB:
            rest = stream.read(skip)
            if len(rest) < skip:
                raise PcapError("pcapng file ends with a truncated interface block")
            raw = head + rest
            linktype, _reserved, snaplen = struct.unpack_from(endian + "HHI", raw, 8)
            name, tsresol, tsoffset = _parse_idb_options(raw, endian)
            interfaces.append(Interface(next_id, linktype, snaplen, name,
                                        tsresol, tsoffset, section).as_dict())
            next_id += 1
        else:
            stream.seek(skip, 1)
    return interfaces


def describe(path):
    """Header-only summary of a capture."""
    stream, fmt, comp, logical = open_capture(path)
    out = {"path": path, "format": fmt, "compressed": comp,
           "size": os.path.getsize(_fs(path)), "logical_size": logical,
           "precision": None, "linktype": None, "snaplen": None,
           "interfaces": []}
    try:
        if fmt == "pcap":
            hdr = read_pcap_header(stream)
            out.update({"precision": hdr.precision, "linktype": hdr.linktype,
                        "snaplen": hdr.snaplen})
        else:
            interfaces = _pcapng_header_scan(stream)
            out["interfaces"] = interfaces
            if interfaces:
                out["linktype"] = interfaces[0]["linktype"]
                out["snaplen"] = interfaces[0]["snaplen"]
    finally:
        stream.close()
    return out


def info_steps(path, top=0):
    """Generator: full capture statistics. Yields (bytes_done, bytes_total)."""
    stream, fmt, comp, logical = open_capture(path)
    total = logical if logical is not None else 0
    if comp:
        total = 0
    out = {"path": path, "format": fmt, "compressed": comp,
           "size": os.path.getsize(_fs(path)), "logical_size": logical,
           "packets": 0, "bytes": 0, "first_ts_ns": None, "last_ts_ns": None,
           "duration_s": None, "interfaces": [], "top": []}
    iface_counts = {}
    iface_list = []
    flows = {}
    last_report = 0
    try:
        if fmt == "pcap":
            hdr = read_pcap_header(stream)
            iface = {"id": 0, "linktype": hdr.linktype, "snaplen": hdr.snaplen,
                     "name": None, "tsresol": 9 if hdr.nano else 6,
                     "section": 1, "packets": 0}
            iface_list.append(iface)
            iface_counts[(1, 0)] = iface
            for rec in iter_pcap_records(stream, hdr):
                ts = rec.ts_ns
                payload = rec.raw[rec.payload_off:rec.payload_off + rec.payload_len]
                _info_take(out, ts, rec.payload_len, iface, flows, top,
                           payload, hdr.linktype)
                pos = _tell(stream)
                if pos - last_report >= PROGRESS_EVERY:
                    last_report = pos
                    yield pos, total
        else:
            pcapng = PcapngReader(stream)
            for btype, raw in pcapng.blocks():
                if btype == IDB and pcapng.interfaces:
                    iface = pcapng.interfaces[-1].as_dict()
                    iface["packets"] = 0
                    iface_list.append(iface)
                    iface_counts[(pcapng.section, iface["id"])] = iface
                elif btype in PACKET_BLOCKS:
                    meta = parse_pcapng_packet(btype, raw, pcapng.endian,
                                               pcapng.interfaces)
                    if meta is None:
                        continue
                    payload_off, payload_len, caplen, origlen, ts, ifid = meta
                    payload = raw[payload_off:payload_off + payload_len]
                    iface = iface_counts.get((pcapng.section, ifid))
                    if iface is None:
                        iface = {"id": ifid, "linktype": None, "snaplen": None,
                                 "name": None, "tsresol": None, "section":
                                 pcapng.section, "packets": 0}
                        iface_list.append(iface)
                        iface_counts[(pcapng.section, ifid)] = iface
                    _info_take(out, ts, payload_len, iface, flows, top,
                               payload, iface.get("linktype"))
                pos = _tell(stream)
                if pos - last_report >= PROGRESS_EVERY:
                    last_report = pos
                    yield pos, total
    finally:
        stream.close()
    out["interfaces"] = iface_list
    if out["first_ts_ns"] is not None and out["last_ts_ns"] is not None:
        out["duration_s"] = max(0.0, (out["last_ts_ns"] - out["first_ts_ns"]) / 1e9)
    if top and flows:
        ranked = sorted(flows.values(), key=lambda f: (-f["packets"], -f["bytes"]))
        out["top"] = ranked[:int(top)]
    yield (total if total else out["bytes"]), (total if total else out["bytes"])
    return out


def _info_take(out, ts, caplen, iface, flows, top, payload, linktype):
    out["packets"] += 1
    out["bytes"] += caplen
    iface["packets"] += 1
    if ts is not None:
        if out["first_ts_ns"] is None or ts < out["first_ts_ns"]:
            out["first_ts_ns"] = ts
        if out["last_ts_ns"] is None or ts > out["last_ts_ns"]:
            out["last_ts_ns"] = ts
    if top:
        decoded = decode_packet(payload, linktype) if linktype is not None else None
        if decoded is None:
            return
        key = flow_key(decoded)
        entry = flows.get(key)
        if entry is None:
            entry = {"flow": flow_label(decoded), "packets": 0, "bytes": 0}
            flows[key] = entry
        entry["packets"] += 1
        entry["bytes"] += caplen


def info(path, top=0):
    return run(info_steps(path, top=top))


# ------------------------------------------------------------- transforms ---


class Packet(NamedTuple):
    data: bytes
    ts_ns: Optional[int]
    caplen: int
    origlen: int
    linktype: Optional[int]
    ifid: int
    section: int
    snaplen: Optional[int]
    name: Optional[str]
    tsresol: Optional[int]


def iter_packets(path, salvage=False):
    """Yield every packet in a capture with enough context to re-encode it."""
    stream, fmt, _comp, _logical = open_capture(path)
    try:
        if fmt == "pcap":
            hdr = read_pcap_header(stream)
            for rec in iter_pcap_records(stream, hdr, salvage=salvage):
                data = rec.raw[rec.payload_off:rec.payload_off + rec.payload_len]
                yield Packet(data, rec.ts_ns, len(data), rec.origlen,
                             hdr.linktype, 0, 1, hdr.snaplen, None,
                             9 if hdr.nano else 6)
        else:
            pcapng = PcapngReader(stream, salvage=salvage)
            for btype, raw in pcapng.blocks():
                if btype not in PACKET_BLOCKS:
                    continue
                meta = parse_pcapng_packet(btype, raw, pcapng.endian,
                                           pcapng.interfaces, salvage=salvage)
                if meta is None:
                    continue
                payload_off, payload_len, caplen, origlen, ts, ifid = meta
                data = raw[payload_off:payload_off + payload_len]
                iface = (pcapng.interfaces[ifid]
                         if ifid < len(pcapng.interfaces) else None)
                yield Packet(data, ts, len(data), origlen,
                             iface.linktype if iface else None, ifid,
                             pcapng.section,
                             iface.snaplen if iface else None,
                             iface.name if iface else None,
                             iface.tsresol if iface else None)
    finally:
        stream.close()


class _Matcher:
    def __init__(self, from_ns=None, to_ns=None, compiled=None):
        self.from_ns = from_ns
        self.to_ns = to_ns
        self.compiled = compiled

    def ok(self, ts_ns, data, linktype):
        if self.from_ns is not None:
            if ts_ns is None or ts_ns < self.from_ns:
                return False
        if self.to_ns is not None:
            if ts_ns is None or ts_ns >= self.to_ns:
                return False
        if self.compiled is not None:
            decoded = decode_packet(data, linktype) if linktype is not None else None
            if not filter_matches(self.compiled, decoded):
                return False
        return True


def _time_ns(value):
    if value is None:
        return None
    sec = parse_ts(value)
    return None if sec is None else int(sec * 1_000_000_000)


class _NormalizedSink:
    """Writes normalized packets as pcap or pcapng."""

    def __init__(self, stream, fmt, precision=None):
        self.stream = stream
        self.fmt = fmt
        self.precision = precision
        self.writer = None
        self.iface_ids = {}
        self.default_linktype = None
        self.default_snaplen = None
        if fmt == "pcapng":
            self.writer = PcapngWriter(stream)

    def set_defaults(self, linktype, snaplen):
        if self.default_linktype is None:
            self.default_linktype = linktype
        if self.default_snaplen is None:
            self.default_snaplen = snaplen

    def write(self, pkt):
        if self.fmt == "pcap":
            if self.writer is None:
                linktype = pkt.linktype if pkt.linktype is not None else self.default_linktype
                if linktype is None:
                    raise PcapError("cannot write pcap output without a link type")
                self.writer = PcapWriter(
                    self.stream, linktype=linktype,
                    snaplen=pkt.snaplen or self.default_snaplen or 65535,
                    nano=(self.precision == "nsec"))
            elif pkt.linktype is not None and pkt.linktype != self.writer.linktype:
                raise PcapError(
                    f"pcap output needs one link type, input mixes "
                    f"{self.writer.linktype} and {pkt.linktype}; use pcapng output")
            self.writer.write_packet(pkt.data, pkt.ts_ns, pkt.origlen)
            return
        key = (pkt.linktype, pkt.snaplen, pkt.name, pkt.tsresol)
        if key not in self.iface_ids:
            tsresol = pkt.tsresol if pkt.tsresol is not None else (
                9 if self.precision == "nsec" else 6)
            self.iface_ids[key] = self.writer.add_interface(
                pkt.linktype if pkt.linktype is not None else 1,
                pkt.snaplen or 65535, pkt.name, tsresol)
        self.writer.write_packet(self.iface_ids[key], pkt.data, pkt.ts_ns,
                                 pkt.origlen)

    def finish(self):
        if self.fmt == "pcap" and self.writer is None:
            self.writer = PcapWriter(
                self.stream, linktype=self.default_linktype or 1,
                snaplen=self.default_snaplen or 65535,
                nano=(self.precision == "nsec"))


def _replace_output(tmp, output, force=True):
    os.replace(_fs(tmp), _fs(output))


def _open_output(output):
    parent = os.path.dirname(os.path.abspath(output))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    return output + ".part"


def _transform_summary(inputs, output, fmt, packets, bytes_out, filtered):
    return {"input": inputs if isinstance(inputs, str) else None,
            "inputs": inputs if not isinstance(inputs, str) else None,
            "output": output, "format": fmt, "packets": packets,
            "bytes": bytes_out, "size": os.path.getsize(_fs(output)),
            "filtered": bool(filtered)}


def trim_steps(path, output, *, from_ts=None, to_ts=None, first=None, last=None,
               filter_spec=None, out_format=None, precision=None,
               salvage=False):
    """Generator: copy a time/packet/filter selection into a new capture."""
    if first is not None:
        first = int(first)
        if first <= 0:
            raise PcapError("first must be positive")
    if last is not None:
        last = int(last)
        if last <= 0:
            raise PcapError("last must be positive")
    if first is not None and last is not None:
        raise PcapError("choose either --first or --last, not both")
    from_ns = _time_ns(from_ts)
    to_ns = _time_ns(to_ts)
    if from_ns is not None and to_ns is not None and from_ns > to_ns:
        raise PcapError("--from is after --to")
    compiled = compile_filter(filter_spec)
    matcher = _Matcher(from_ns, to_ns, compiled)
    src_fmt = detect_format(path)
    dst_fmt = out_format or src_fmt
    if dst_fmt not in ("pcap", "pcapng"):
        raise PcapError("format must be pcap or pcapng")
    if precision not in (None, "usec", "nsec"):
        raise PcapError("precision must be usec or nsec")

    if dst_fmt == src_fmt and not (src_fmt == "pcap" and precision and
                                   precision != _pcap_precision(path)):
        result = yield from _trim_raw(path, output, src_fmt, matcher, first,
                                      last, salvage)
        return result

    result = yield from _trim_normalized(path, output, dst_fmt, precision,
                                         matcher, first, last, salvage)
    return result


def _pcap_precision(path):
    stream, fmt, _c, _l = open_capture(path)
    try:
        hdr = read_pcap_header(stream)
        return hdr.precision
    finally:
        stream.close()


def _trim_raw(path, output, fmt, matcher, first, last, salvage):
    total_matches = None
    stream, _fmt, _c, _l = open_capture(path)
    try:
        total_size = os.path.getsize(_fs(path))
        yield 0, total_size
        if fmt == "pcap":
            hdr = read_pcap_header(stream)
            last_report = _tell(stream)
            if last is not None:
                count = 0
                for rec in iter_pcap_records(stream, hdr, salvage=salvage):
                    data = rec.raw[rec.payload_off:rec.payload_off + rec.payload_len]
                    if matcher.ok(rec.ts_ns, data, hdr.linktype):
                        count += 1
                    pos = _tell(stream)
                    if pos - last_report >= PROGRESS_EVERY:
                        last_report = pos
                        yield pos, total_size
                total_matches = count
                stream.close()
                stream, _fmt, _c, _l = open_capture(path)
                hdr = read_pcap_header(stream)
            skip = max(0, (total_matches or 0) - last) if last is not None else 0
            tmp = _open_output(output)
            written = matches = bytes_out = 0
            try:
                with open(_fs(tmp), "wb", buffering=BUF) as out:
                    out.write(hdr.raw)
                    last_report = _tell(stream)
                    for rec in iter_pcap_records(stream, hdr, salvage=salvage):
                        data = rec.raw[rec.payload_off:rec.payload_off + rec.payload_len]
                        pos = _tell(stream)
                        if pos - last_report >= PROGRESS_EVERY:
                            last_report = pos
                            yield pos, total_size
                        if not matcher.ok(rec.ts_ns, data, hdr.linktype):
                            continue
                        matches += 1
                        if skip and matches <= skip:
                            continue
                        out.write(rec.raw)
                        written += 1
                        bytes_out += len(data)
                        if first is not None and written >= first:
                            break
                _replace_output(tmp, output)
            except BaseException:
                if os.path.exists(tmp):
                    os.remove(_fs(tmp))
                raise
            yield total_size, total_size
            return _transform_summary(path, output, fmt, written, bytes_out,
                                      matcher.compiled is not None
                                      or matcher.from_ns is not None
                                      or matcher.to_ns is not None)
        # pcapng raw copy
        pcapng = PcapngReader(stream, salvage=salvage)
        last_report = _tell(stream)
        if last is not None:
            count = 0
            for btype, raw in pcapng.blocks():
                pos = _tell(stream)
                if pos - last_report >= PROGRESS_EVERY:
                    last_report = pos
                    yield pos, total_size
                if btype in PACKET_BLOCKS:
                    meta = parse_pcapng_packet(btype, raw, pcapng.endian,
                                               pcapng.interfaces, salvage=salvage)
                    if meta is None:
                        continue
                    iface = (pcapng.interfaces[meta[5]]
                             if meta[5] < len(pcapng.interfaces) else None)
                    data = raw[meta[0]:meta[0] + meta[1]]
                    if matcher.ok(meta[4], data, iface.linktype if iface else None):
                        count += 1
        skip = max(0, (count if last is not None else 0) - last) if last is not None else 0
        stream.close()
        stream, _fmt, _c, _l = open_capture(path)
        pcapng = PcapngReader(stream, salvage=salvage)
        tmp = _open_output(output)
        written = matches = bytes_out = 0
        try:
            with open(_fs(tmp), "wb", buffering=BUF) as out:
                last_report = _tell(stream)
                for btype, raw in pcapng.blocks():
                    pos = _tell(stream)
                    if pos - last_report >= PROGRESS_EVERY:
                        last_report = pos
                        yield pos, total_size
                    if btype is None:
                        if not skip:
                            out.write(raw)
                        continue
                    if btype in PACKET_BLOCKS:
                        meta = parse_pcapng_packet(btype, raw, pcapng.endian,
                                                   pcapng.interfaces, salvage=salvage)
                        iface = None
                        if meta is not None and meta[5] < len(pcapng.interfaces):
                            iface = pcapng.interfaces[meta[5]]
                        data = raw[meta[0]:meta[0] + meta[1]] if meta else b""
                        if meta is None or not matcher.ok(
                                meta[4], data, iface.linktype if iface else None):
                            continue
                        matches += 1
                        if skip and matches <= skip:
                            continue
                        out.write(raw)
                        written += 1
                        bytes_out += len(data)
                        if first is not None and written >= first:
                            break
                    else:
                        out.write(raw)
            _replace_output(tmp, output)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(_fs(tmp))
            raise
        yield total_size, total_size
        return _transform_summary(path, output, fmt, written, bytes_out,
                                  matcher.compiled is not None
                                  or matcher.from_ns is not None
                                  or matcher.to_ns is not None)
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _trim_normalized(path, output, dst_fmt, precision, matcher, first, last,
                     salvage):
    total_matches = None
    total_size = os.path.getsize(_fs(path))
    yield 0, total_size
    if last is not None:
        total_matches = 0
        done = step = 0
        for pkt in iter_packets(path, salvage=salvage):
            if matcher.ok(pkt.ts_ns, pkt.data, pkt.linktype):
                total_matches += 1
            step += len(pkt.data) + 32
            if step >= PROGRESS_EVERY:
                done += step
                step = 0
                yield min(total_size, done), total_size
    skip = max(0, (total_matches or 0) - last) if last is not None else 0
    first_pkt = next(iter_packets(path, salvage=salvage), None)
    tmp = _open_output(output)
    written = matches = bytes_out = 0
    try:
        with open(_fs(tmp), "wb", buffering=BUF) as out:
            sink = _NormalizedSink(out, dst_fmt, precision)
            if first_pkt is not None:
                sink.set_defaults(first_pkt.linktype, first_pkt.snaplen)
            done = step = 0
            for pkt in iter_packets(path, salvage=salvage):
                step += len(pkt.data) + 32
                if step >= PROGRESS_EVERY:
                    done += step
                    step = 0
                    yield min(total_size, done), total_size
                if not matcher.ok(pkt.ts_ns, pkt.data, pkt.linktype):
                    continue
                matches += 1
                if skip and matches <= skip:
                    continue
                sink.write(pkt)
                written += 1
                bytes_out += len(pkt.data)
                if first is not None and written >= first:
                    break
            sink.finish()
        _replace_output(tmp, output)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(_fs(tmp))
        raise
    yield total_size, total_size
    return _transform_summary(path, output, dst_fmt, written, bytes_out,
                              matcher.compiled is not None
                              or matcher.from_ns is not None
                              or matcher.to_ns is not None)


def trim(*args, **kwargs):
    return run(trim_steps(*args, **kwargs))


def convert_steps(path, output, *, out_format="pcapng", precision=None,
                  filter_spec=None, salvage=False):
    """Generator: convert between pcap and pcapng (optionally filtering)."""
    if out_format not in ("pcap", "pcapng"):
        raise PcapError("out_format must be pcap or pcapng")
    if precision not in (None, "usec", "nsec"):
        raise PcapError("precision must be usec or nsec")
    compiled = compile_filter(filter_spec)
    matcher = _Matcher(None, None, compiled)
    total_size = os.path.getsize(_fs(path))
    yield 0, total_size
    first_pkt = next(iter_packets(path, salvage=salvage), None)
    tmp = _open_output(output)
    written = bytes_out = 0
    try:
        with open(_fs(tmp), "wb", buffering=BUF) as out:
            sink = _NormalizedSink(out, out_format, precision)
            if first_pkt is not None:
                sink.set_defaults(first_pkt.linktype, first_pkt.snaplen)
            else:
                desc = describe(path)
                sink.set_defaults(desc.get("linktype"), desc.get("snaplen"))
            done = step = 0
            for pkt in iter_packets(path, salvage=salvage):
                step += len(pkt.data) + 32
                if step >= PROGRESS_EVERY:
                    done += step
                    step = 0
                    yield min(total_size, done), total_size
                if not matcher.ok(pkt.ts_ns, pkt.data, pkt.linktype):
                    continue
                sink.write(pkt)
                written += 1
                bytes_out += len(pkt.data)
            sink.finish()
        _replace_output(tmp, output)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(_fs(tmp))
        raise
    yield total_size, total_size
    return _transform_summary(path, output, out_format, written, bytes_out,
                              compiled is not None)


def convert(*args, **kwargs):
    return run(convert_steps(*args, **kwargs))


def _pcap_headers_equal(paths):
    headers = []
    for path in paths:
        stream, fmt, _c, _l = open_capture(path)
        try:
            if fmt != "pcap":
                return False
            headers.append(read_pcap_header(stream).raw)
        finally:
            stream.close()
    return len(set(headers)) == 1


def _sorted_packets(paths, salvage):
    import heapq
    heap = []
    for i, path in enumerate(paths):
        it = iter(iter_packets(path, salvage=salvage))
        try:
            pkt = next(it)
        except StopIteration:
            continue
        key = (0, pkt.ts_ns) if pkt.ts_ns is not None else (1, 0)
        heapq.heappush(heap, (key, i, pkt, it))
    while heap:
        key, i, pkt, it = heapq.heappop(heap)
        yield pkt
        try:
            nxt = next(it)
        except StopIteration:
            continue
        if pkt.ts_ns is not None and nxt.ts_ns is not None and nxt.ts_ns < pkt.ts_ns:
            raise PcapError(f"{os.path.basename(paths[i])} is not in time order; "
                            "cannot sort")
        nkey = (0, nxt.ts_ns) if nxt.ts_ns is not None else (1, 0)
        heapq.heappush(heap, (nkey, i, nxt, it))


def combine_steps(paths, output, *, sort=False, dedupe=False, out_format=None,
                  salvage=False):
    """Generator: concatenate/sort/dedupe captures into one output file."""
    paths = list(paths)
    if not paths:
        raise PcapError("combine needs at least one input")
    for path in paths:
        if not os.path.isfile(path):
            raise PcapError(f"{path} is not a file")
    if out_format is None:
        out_format = "pcap" if _pcap_headers_equal(paths) else "pcapng"
    if out_format not in ("pcap", "pcapng"):
        raise PcapError("out_format must be pcap or pcapng")
    total_size = sum(os.path.getsize(_fs(p)) for p in paths)
    yield 0, total_size
    tmp = _open_output(output)
    written = bytes_out = 0
    last_key = None
    try:
        with open(_fs(tmp), "wb", buffering=BUF) as out:
            sink = _NormalizedSink(out, out_format)
            stream = _sorted_packets(paths, salvage) if sort else (
                pkt for path in paths for pkt in iter_packets(path, salvage=salvage))
            done = step = 0
            for pkt in stream:
                step += len(pkt.data) + 32
                if step >= PROGRESS_EVERY:
                    done += step
                    step = 0
                    yield min(total_size, done), total_size
                key = (pkt.ts_ns, pkt.data)
                if dedupe and key == last_key:
                    continue
                last_key = key
                sink.write(pkt)
                written += 1
                bytes_out += len(pkt.data)
            sink.finish()
        _replace_output(tmp, output)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(_fs(tmp))
        raise
    yield total_size, total_size
    return _transform_summary(paths, output, out_format, written, bytes_out, False)


def combine(*args, **kwargs):
    return run(combine_steps(*args, **kwargs))


def demux_steps(path, outdir, *, max_flows=500, filter_spec=None,
                salvage=False):
    """Generator: write one capture per bidirectional flow."""
    max_flows = int(max_flows)
    if max_flows <= 0:
        raise PcapError("max_flows must be positive")
    compiled = compile_filter(filter_spec)
    fmt = detect_format(path)
    total_size = os.path.getsize(_fs(path))
    yield 0, total_size
    flows = {}
    order = []
    interfaces = {}
    other = None
    done = step = 0
    for pkt in iter_packets(path, salvage=salvage):
        step += len(pkt.data) + 32
        if step >= PROGRESS_EVERY:
            done += step
            step = 0
            yield min(total_size, done), total_size
        ikey = (pkt.section, pkt.ifid)
        if ikey not in interfaces:
            interfaces[ikey] = {"linktype": pkt.linktype, "snaplen": pkt.snaplen,
                                "name": pkt.name, "tsresol": pkt.tsresol}
        decoded = decode_packet(pkt.data, pkt.linktype) if pkt.linktype is not None else None
        if compiled is not None and not filter_matches(compiled, decoded):
            continue
        key = flow_key(decoded) if decoded is not None else None
        if key is None:
            if other is None:
                other = {"flow": "unclassified", "packets": 0, "bytes": 0}
            other["packets"] += 1
            other["bytes"] += len(pkt.data)
            continue
        entry = flows.get(key)
        if entry is None:
            entry = {"flow": flow_label(decoded), "decoded": decoded,
                     "packets": 0, "bytes": 0}
            flows[key] = entry
            order.append(key)
            if len(flows) > max_flows:
                raise PcapError(f"more than {max_flows} flows; raise --max-flows "
                                "or filter the capture first")
        entry["packets"] += 1
        entry["bytes"] += len(pkt.data)
    os.makedirs(outdir, exist_ok=True)
    out_fmt = fmt
    ext = ".pcap" if out_fmt == "pcap" else ".pcapng"
    if out_fmt == "pcap":
        linktypes = {v["linktype"] for v in interfaces.values()
                     if v["linktype"] is not None}
        if len(linktypes) > 1:
            raise PcapError("demux needs a single link type for pcap output; "
                            "convert the capture to pcapng first")
    writer_fmt = out_fmt
    writers = {}
    rows = []
    src_desc = describe(path)
    pcap_nano = src_desc.get("precision") == "nsec"

    def open_writer(filename):
        stream = open(_fs(os.path.join(outdir, filename)), "wb", buffering=BUF)
        if writer_fmt == "pcap":
            iface = next((v for v in interfaces.values()
                          if v["linktype"] is not None), None)
            writer = PcapWriter(
                stream,
                linktype=(iface["linktype"] if iface else
                          src_desc.get("linktype") or 1),
                snaplen=(iface or {}).get("snaplen")
                or src_desc.get("snaplen") or 65535,
                nano=pcap_nano)
        else:
            writer = PcapngWriter(stream)
            writer._iface_ids = {}
            for ikey, info in interfaces.items():
                id_ = writer.add_interface(
                    info["linktype"] if info["linktype"] is not None else 1,
                    info["snaplen"] or 65535, info["name"],
                    info["tsresol"] if info["tsresol"] is not None else 6)
                writer._iface_ids[ikey] = id_
        return stream, writer

    if other is not None:
        fname = "flow_0000_other" + ext
        writers[None] = open_writer(fname)
        rows.append({"index": 0, "file": fname, "flow": other["flow"],
                     "packets": other["packets"], "bytes": other["bytes"]})
    for i, key in enumerate(order, 1):
        entry = flows[key]
        fname = f"flow_{i:04d}{ext}"
        writers[key] = open_writer(fname)
        rows.append({"index": i, "file": fname, "flow": entry["flow"],
                     "decoded": entry["decoded"],
                     "packets": entry["packets"], "bytes": entry["bytes"]})
    try:
        seen = seen_bytes = 0
        done = step = 0
        for pkt in iter_packets(path, salvage=salvage):
            step += len(pkt.data) + 32
            if step >= PROGRESS_EVERY:
                done += step
                step = 0
                yield min(total_size, done), total_size
            decoded = (decode_packet(pkt.data, pkt.linktype)
                       if pkt.linktype is not None else None)
            if compiled is not None and not filter_matches(compiled, decoded):
                continue
            key = flow_key(decoded) if decoded is not None else None
            target = writers.get(key)
            if target is None:
                continue
            stream, writer = target
            if writer_fmt == "pcap":
                writer.write_packet(pkt.data, pkt.ts_ns, pkt.origlen)
            else:
                ifid = writer._iface_ids.get((pkt.section, pkt.ifid), 0)
                writer.write_packet(ifid, pkt.data, pkt.ts_ns, pkt.origlen)
            seen += 1
            seen_bytes += len(pkt.data)
    finally:
        for stream, _w in writers.values():
            try:
                stream.close()
            except OSError:
                pass
    csv_path = os.path.join(outdir, "flows.csv")
    with open(_fs(csv_path), "w", encoding="utf-8", newline="\n") as f:
        w = csv.writer(f)
        w.writerow(["index", "file", "flow", "packets", "bytes"])
        for row in rows:
            w.writerow([row["index"], row["file"], row["flow"],
                        row["packets"], row["bytes"]])
    yield total_size, total_size
    return {"input": path, "outdir": outdir, "flows": len(order),
            "packets": seen, "bytes": seen_bytes, "csv": csv_path,
            "other": other is not None}


def demux(*args, **kwargs):
    return run(demux_steps(*args, **kwargs))


# -------------------------------------------------------------------- cli --


def run(steps):
    """Drive a *_steps generator to completion and return its summary."""
    while True:
        try:
            next(steps)
        except StopIteration as done:
            return done.value


def positive_int(text):
    try:
        n = int(text)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be a positive integer")
    if n <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return n


def _human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _drive(gen, label, quiet=False):
    last = 0.0
    try:
        while True:
            try:
                done, total = next(gen)
            except StopIteration as fin:
                if not quiet:
                    sys.stderr.write("\r" + " " * 78 + "\r")
                    sys.stderr.flush()
                return fin.value
            if quiet:
                continue
            now = time.time()
            if now - last < 0.2 and total and done < total:
                continue
            last = now
            if total:
                pct = 100.0 * done / total
                sys.stderr.write(f"\r{label}: {pct:5.1f}%  "
                                 f"{_human(done)} / {_human(total)}   ")
            else:
                sys.stderr.write(f"\r{label}: {_human(done)}   ")
            sys.stderr.flush()
    finally:
        gen.close()


def _emit(data, json_mode):
    if json_mode:
        data = dict(data)
        data["ok"] = True
        print(json.dumps(data, default=str))


def _filter_args(a):
    spec = {}
    for key in FILTER_KEYS:
        value = getattr(a, key, None)
        if not value:
            continue
        parts = [p.strip() for p in str(value).split(",") if p.strip()]
        if len(parts) > 1:
            spec[key] = parts
        elif parts:
            spec[key] = parts[0]
    return spec or None


def _add_filter_args(parser):
    parser.add_argument("--host", help="either side has this IP")
    parser.add_argument("--src", help="source IP (comma separated)")
    parser.add_argument("--dst", help="destination IP (comma separated)")
    parser.add_argument("--port", help="either side has this port")
    parser.add_argument("--sport", help="source port")
    parser.add_argument("--dport", help="destination port")
    parser.add_argument("--proto", help="tcp, udp, icmp, ip or a number")


def _mode_help():
    return ("one of: -s/--size, -n/--chunks, -p/--packets, --every, --gap, "
            "--split-at, --target")


def _cmd_split(a):
    plan = a.dry_run
    gen = split_steps(a.input, a.outdir, a.size, a.packets, a.chunks,
                      every=a.every, gap=a.gap, split_at=a.split_at,
                      local_time=a.local_time, target=a.target, force=a.force,
                      resume=a.resume,
                      compress=None if a.compress == "none" else a.compress,
                      name_style=a.name_style, index_csv=a.index_csv,
                      dry_run=plan, salvage=a.salvage,
                      space_check=not a.no_space_check)
    summary = _drive(gen, "split", quiet=a.json or not a.verbose)
    if a.json:
        _emit(summary, True)
        return 0
    if plan:
        print(f"dry run: {summary['chunks']} chunk(s) would be written to "
              f"{summary['outdir']} ({summary['packets']:,} packets, "
              f"{_human(summary['bytes'])})")
        for c in summary["plan"] or []:
            print(f"  {c['index']:>4}  {c['packets']:>10,} packets  "
                  f"{_human(c['bytes']):>10}  {iso_ts(c['first_ts_ns'])}  "
                  f"{c['file']}")
        return 0
    print(f"split {summary['input']} ({summary['format']}, "
          f"{summary['size']:,} bytes, {summary['packets']:,} packets) into "
          f"{summary['chunks']} chunks in {summary['outdir']}")
    return 0


def _cmd_merge(a):
    summary = _drive(merge_steps(a.folder, a.output, force=a.force,
                                 verify=not a.no_verify,
                                 allow_missing=a.allow_missing,
                                 salvage=a.salvage), "merge", quiet=a.json or not a.verbose)
    if a.json:
        _emit(summary, True)
        return 0
    print(f"merged {summary['chunks']} chunks into {summary['output']} "
          f"({summary['size']:,} bytes)")
    if summary["verified"]:
        print("verified: SHA-256 matches the original file")
    elif not summary["complete"]:
        print("warning: merged an incomplete chunk set; the result was not verified")
    return 0


def _cmd_verify(a):
    report = _drive(verify_steps(a.folder, deep=a.deep), "verify", quiet=a.json or not a.verbose)
    if a.json:
        print(json.dumps(dict(report, ok=report["ok"]), default=str))
        return 0 if report["ok"] else 2
    for item in report["chunks"]:
        status = "OK  " if item["ok"] else "FAIL"
        print(f"{status} {item['file']}  {_human(item['bytes'] or 0)}"
              + (f"  {item['packets']:,} packets" if item.get("packets") else ""))
        for problem in item["problems"]:
            print(f"       {problem}")
    for problem in report["problems"]:
        print(f"problem: {problem}")
    for warning in report.get("warnings") or []:
        print(f"warning: {warning}")
    print("verified OK" if report["ok"] else "verification FAILED")
    return 0 if report["ok"] else 2


def _cmd_info(a):
    result = _drive(info_steps(a.path, top=a.top), "info", quiet=a.json or not a.verbose)
    if a.json:
        _emit(result, True)
        return 0
    print(f"{result['path']}: {result['format']}"
          + (f" ({result['compressed']})" if result["compressed"] else ""))
    print(f"  packets: {result['packets']:,}   captured: {_human(result['bytes'])}"
          f"   file: {_human(result['size'])}")
    if result["first_ts_ns"] is not None:
        print(f"  first:  {iso_ts(result['first_ts_ns'])}")
        print(f"  last:   {iso_ts(result['last_ts_ns'])}")
        print(f"  span:   {result['duration_s']:.3f} s")
    for iface in result["interfaces"]:
        name = f" ({iface['name']})" if iface.get("name") else ""
        print(f"  interface {iface['id']}{name}: linktype {iface['linktype']}, "
              f"snaplen {iface['snaplen']}, {iface['packets']:,} packets")
    if result["top"]:
        print("  top conversations:")
        for row in result["top"]:
            print(f"    {row['packets']:>10,}  {_human(row['bytes']):>10}  {row['flow']}")
    return 0


def _cmd_trim(a):
    summary = _drive(trim_steps(a.input, a.output, from_ts=a.from_ts,
                                to_ts=a.to_ts, first=a.first, last=a.last,
                                filter_spec=_filter_args(a),
                                out_format=a.format, precision=a.precision,
                                salvage=a.salvage), "trim", quiet=a.json or not a.verbose)
    if a.json:
        _emit(summary, True)
        return 0
    print(f"wrote {summary['packets']:,} packets to {summary['output']} "
          f"({summary['size']:,} bytes, {summary['format']})")
    return 0


def _cmd_convert(a):
    summary = _drive(convert_steps(a.input, a.output, out_format=a.format,
                                   precision=a.precision,
                                   filter_spec=_filter_args(a),
                                   salvage=a.salvage), "convert", quiet=a.json or not a.verbose)
    if a.json:
        _emit(summary, True)
        return 0
    print(f"converted {a.input} -> {summary['output']} "
          f"({summary['format']}, {summary['packets']:,} packets, "
          f"{summary['size']:,} bytes)")
    return 0


def _cmd_combine(a):
    summary = _drive(combine_steps(a.inputs, a.output, sort=a.sort,
                                   dedupe=a.dedupe, out_format=a.format,
                                   salvage=a.salvage), "combine", quiet=a.json or not a.verbose)
    if a.json:
        _emit(summary, True)
        return 0
    print(f"combined {len(a.inputs)} files into {summary['output']} "
          f"({summary['format']}, {summary['packets']:,} packets, "
          f"{summary['size']:,} bytes)")
    return 0


def _cmd_demux(a):
    summary = _drive(demux_steps(a.input, a.outdir, max_flows=a.max_flows,
                                 filter_spec=_filter_args(a),
                                 salvage=a.salvage), "demux", quiet=a.json or not a.verbose)
    if a.json:
        _emit(summary, True)
        return 0
    print(f"wrote {summary['flows']} flows to {summary['outdir']} "
          f"({summary['packets']:,} packets); index: {summary['csv']}")
    return 0


def main(argv=None):
    logging.basicConfig(format="warning: %(message)s", level=logging.WARNING)
    ap = argparse.ArgumentParser(
        prog="pcapchunk",
        description="Split, merge, verify, inspect and reshape pcap/pcapng captures.")
    ap.add_argument("--version", action="version",
                    version=f"{APP_NAME} {__version__}")
    ap.add_argument("-v", "--verbose", action="store_true", help="show progress")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress warnings")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("split", help="split a capture into chunks")
    sp.add_argument("input", help="pcap or pcapng file (gzip allowed)")
    sp.add_argument("-o", "--outdir", help="output folder (default: <name>_chunks)")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("-s", "--size", type=parse_size, help="max chunk size, e.g. 50M")
    g.add_argument("-n", "--chunks", type=positive_int, help="number of chunks")
    g.add_argument("-p", "--packets", type=positive_int, help="packets per chunk")
    g.add_argument("--every", type=parse_duration, help="chunk per time period, e.g. 1h")
    g.add_argument("--gap", type=parse_duration, help="new chunk after an idle gap, e.g. 5m")
    g.add_argument("--split-at", dest="split_at", help="daily boundary times, e.g. 02:00,14:00")
    sp.add_argument("--target", choices=sorted(PRESETS),
                    help="size preset (" + ", ".join(sorted(PRESETS)) + ")")
    sp.add_argument("--compress", choices=["none", "gzip", "zstd"], default="none",
                    help="compress chunk files")
    sp.add_argument("--name-style", choices=["index", "time"], default="index",
                    help="chunk file naming")
    sp.add_argument("--resume", action="store_true",
                    help="continue an interrupted split")
    sp.add_argument("-f", "--force", action="store_true",
                    help="replace an existing chunk set")
    sp.add_argument("--dry-run", action="store_true", help="only show the plan")
    sp.add_argument("--index", dest="index_csv", help="write a CSV index of chunks")
    sp.add_argument("--salvage", action="store_true", help="keep what can be parsed")
    sp.add_argument("--no-space-check", action="store_true",
                    help="skip the free-space check")
    sp.add_argument("--local-time", action="store_true",
                    help="interpret --split-at in local time")
    sp.set_defaults(func=_cmd_split)

    mp = sub.add_parser("merge", help="merge a chunk folder back into one capture")
    mp.add_argument("folder")
    mp.add_argument("-o", "--output")
    mp.add_argument("-f", "--force", action="store_true", help="overwrite output")
    mp.add_argument("--no-verify", action="store_true", help="skip checksums")
    mp.add_argument("--allow-missing", action="store_true",
                    help="merge the chunks that exist")
    mp.add_argument("--salvage", action="store_true")
    mp.set_defaults(func=_cmd_merge)

    vp = sub.add_parser("verify", help="check a chunk folder against its manifest")
    vp.add_argument("folder")
    vp.add_argument("--deep", action="store_true", help="also parse every chunk")
    vp.set_defaults(func=_cmd_verify)

    ip = sub.add_parser("info", help="show capture statistics")
    ip.add_argument("path")
    ip.add_argument("--top", type=int, default=0,
                    help="show the N busiest conversations")
    ip.set_defaults(func=_cmd_info)

    tp = sub.add_parser("trim", help="extract a time/packet/filter selection")
    tp.add_argument("input")
    tp.add_argument("-o", "--output", required=True)
    tp.add_argument("--from", dest="from_ts", help="start time (ISO or epoch)")
    tp.add_argument("--to", dest="to_ts", help="end time (ISO or epoch)")
    tp.add_argument("--first", type=positive_int, help="first N matching packets")
    tp.add_argument("--last", type=positive_int, help="last N matching packets")
    tp.add_argument("--format", choices=["pcap", "pcapng"])
    tp.add_argument("--precision", choices=["usec", "nsec"])
    tp.add_argument("--salvage", action="store_true")
    _add_filter_args(tp)
    tp.set_defaults(func=_cmd_trim)

    cp = sub.add_parser("convert", help="convert between pcap and pcapng")
    cp.add_argument("input")
    cp.add_argument("-o", "--output", required=True)
    cp.add_argument("--format", choices=["pcap", "pcapng"], default="pcapng")
    cp.add_argument("--precision", choices=["usec", "nsec"])
    cp.add_argument("--salvage", action="store_true")
    _add_filter_args(cp)
    cp.set_defaults(func=_cmd_convert)

    bp = sub.add_parser("combine", help="merge several captures into one file")
    bp.add_argument("inputs", nargs="+")
    bp.add_argument("-o", "--output", required=True)
    bp.add_argument("--sort", action="store_true", help="merge by timestamp")
    bp.add_argument("--dedupe", action="store_true", help="drop duplicate packets")
    bp.add_argument("--format", choices=["pcap", "pcapng"])
    bp.add_argument("--salvage", action="store_true")
    bp.set_defaults(func=_cmd_combine)

    dp = sub.add_parser("demux", help="write one capture per conversation")
    dp.add_argument("input")
    dp.add_argument("-o", "--outdir", required=True)
    dp.add_argument("--max-flows", type=positive_int, default=500)
    dp.add_argument("--salvage", action="store_true")
    _add_filter_args(dp)
    dp.set_defaults(func=_cmd_demux)

    a = ap.parse_args(argv)
    if a.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif a.verbose:
        logging.getLogger().setLevel(logging.INFO)
    try:
        return a.func(a)
    except FileNotFoundError as e:
        message = f"file not found: {e.filename}"
        if a.json:
            print(json.dumps({"ok": False, "error": message}))
        else:
            print(f"error: {message}", file=sys.stderr)
        return 1
    except (PcapError, OSError) as e:
        if a.json:
            print(json.dumps({"ok": False, "error": str(e)}))
        else:
            print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

