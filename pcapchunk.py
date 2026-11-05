#!/usr/bin/env python3
"""
pcapchunk.py - split a capture file into smaller chunks, and merge them back.

Pure Python standard library. No third-party packages, no threads, no locks.
Supports classic libpcap (.pcap, usec/nsec, either byte order, Kuznetzov
variant) and pcapng (including multiple sections and interfaces defined
mid-file).

  Split:
    python pcapchunk.py split capture.pcap                  # 50 MB chunks -> ./capture_chunks/
    python pcapchunk.py split capture.pcap -o out/ -s 20M   # 20 MB chunks
    python pcapchunk.py split capture.pcap -n 8             # exactly 8 chunks (roughly equal)
    python pcapchunk.py split capture.pcap -p 100000        # 100k packets per chunk

    -> out/capture_0001.pcap, out/capture_0002.pcap, ... + out/manifest.json

  Merge (give it the folder):
    python pcapchunk.py merge out/                          # -> out/capture.pcap
    python pcapchunk.py merge out/ -o /tmp/restored.pcap

Every chunk is a valid, standalone capture (each carries the file header /
interface definitions it needs), so chunks open fine in Wireshark/tcpdump.
Merging strips those repeated headers again, so the merged file is
byte-for-byte identical to the original. The SHA-256 recorded at split time
is checked on merge.

For GUIs: split_steps() / merge_steps() are generators that do the work in
small pieces, yielding (bytes_done, bytes_total) as they go and returning a
summary dict. A GUI can advance them from its event loop (no threads), and
cancel with gen.close(), which removes partial output.
"""

import argparse
import hashlib
import json
import logging
import os
import re
import struct
import sys

BUF = 1 << 20  # 1 MiB I/O buffers
PROGRESS_EVERY = 1 << 20  # yield progress roughly every 1 MiB of input
MANIFEST = "manifest.json"
CHUNK_RE = re.compile(r"^(?P<base>.+)_(?P<id>\d+)(?P<ext>\.[A-Za-z0-9]+)$")

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
PCAP_GLOBAL_HDR = 24

# pcapng block types
SHB_BYTES = b"\x0a\x0d\x0d\x0a"  # Section Header Block (palindrome: same in LE/BE)
SHB = 0x0A0D0D0A
IDB = 0x00000001  # Interface Description Block
PACKET_BLOCKS = {0x00000002, 0x00000003, 0x00000006}  # old Packet, Simple, Enhanced
BOM_LE = b"\x4d\x3c\x2b\x1a"
BOM_BE = b"\x1a\x2b\x3c\x4d"


class PcapError(Exception):
    pass


def warn(msg):
    log.warning(msg)


def detect_format(path):
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == SHB_BYTES:
        return "pcapng"
    if magic[:2] == b"\x1f\x8b":
        raise PcapError(f"{os.path.basename(path)} is gzip-compressed; decompress it first")
    raise PcapError(f"{os.path.basename(path)} is not a pcap or pcapng file")


class HashingReader:
    """File wrapper that hashes everything read through it and tracks position."""

    def __init__(self, f):
        self.f = f
        self.h = hashlib.sha256()
        self.pos = 0

    def read(self, n):
        data = self.f.read(n)
        self.h.update(data)
        self.pos += len(data)
        return data


class HashingWriter:
    """File wrapper that hashes everything written through it."""

    def __init__(self, f):
        self.f = f
        self.h = hashlib.sha256()

    def write(self, data):
        self.h.update(data)
        return self.f.write(data)


def read_pcap_header(f):
    hdr = f.read(PCAP_GLOBAL_HDR)
    if len(hdr) < PCAP_GLOBAL_HDR or hdr[:4] not in PCAP_MAGICS:
        raise PcapError("bad or truncated pcap global header")
    endian, rec_len = PCAP_MAGICS[hdr[:4]]
    return hdr, endian, rec_len


def iter_pcap_records(f, endian, rec_len):
    """Yield raw record bytes (record header + packet data)."""
    incl_at = struct.Struct(endian + "I")
    while True:
        rec = f.read(rec_len)
        if not rec:
            return
        if len(rec) < rec_len:
            warn("file ends with a truncated record header; kept as-is")
            yield rec
            return
        incl = incl_at.unpack_from(rec, 8)[0]
        data = f.read(incl)
        if len(data) < incl:
            warn("file ends with a truncated packet; kept as-is")
            yield rec + data
            return
        yield rec + data


def iter_pcapng_blocks(f):
    """Yield (block_type, raw_block_bytes) for each pcapng block."""
    endian = None
    while True:
        head = f.read(8)
        if not head:
            return
        if len(head) < 8:
            warn("file ends with a truncated block; kept as-is")
            yield None, head
            return
        if head[:4] == SHB_BYTES:
            bom = f.read(4)
            if bom == BOM_LE:
                endian = "<"
            elif bom == BOM_BE:
                endian = ">"
            else:
                raise PcapError("pcapng section header has an invalid byte-order magic")
            btype = SHB
            blen = struct.unpack(endian + "I", head[4:])[0]
            head += bom
        else:
            if endian is None:
                raise PcapError("pcapng file does not start with a section header")
            btype, blen = struct.unpack(endian + "II", head)
        if blen < 12 or blen % 4:
            raise PcapError(f"corrupt pcapng block length {blen} (type 0x{btype:08x})")
        rest = f.read(blen - len(head))
        raw = head + rest
        if len(raw) < blen:
            warn("file ends with a truncated block; kept as-is")
            yield None, raw
            return
        yield btype, raw


def run(steps):
    """Drive a *_steps generator to completion and return its summary."""
    while True:
        try:
            next(steps)
        except StopIteration as done:
            return done.value


# ------------------------------------------------------------------ split --

def default_outdir(path):
    stem = os.path.splitext(os.path.basename(path))[0]
    return os.path.join(os.path.dirname(os.path.abspath(path)), f"{stem}_chunks")


def existing_chunk_files(folder):
    """Chunk files / manifest already in a folder (what split would replace)."""
    if not os.path.isdir(folder):
        return []
    return [n for n in os.listdir(folder) if CHUNK_RE.match(n) or n == MANIFEST]


class ChunkWriter:
    """Writes chunk files and decides when to start the next one."""

    def __init__(self, outdir, base, ext, max_bytes, max_packets, n_chunks, total_in):
        self.outdir, self.base, self.ext = outdir, base, ext
        self.max_bytes, self.max_packets = max_bytes, max_packets
        self.n_chunks, self.total_in = n_chunks, total_in
        self.f = None
        self.idx = 0
        self.bytes = 0
        self.packets = 0
        self.chunks = []

    def should_rotate(self, next_len, consumed_in):
        if self.f is None:
            return True
        if self.packets == 0:  # every chunk gets at least one packet
            return False
        if self.max_packets and self.packets >= self.max_packets:
            return True
        if self.max_bytes and self.bytes + next_len > self.max_bytes:
            return True
        if self.n_chunks and self.idx < self.n_chunks:
            return consumed_in >= self.idx * self.total_in / self.n_chunks
        return False

    def open(self, prefix):
        self.close()
        self.idx += 1
        name = f"{self.base}_{self.idx:04d}{self.ext}"
        self.chunks.append({"file": name})
        self.f = open(os.path.join(self.outdir, name), "wb", buffering=BUF)
        self.f.write(prefix)
        self.bytes = len(prefix)
        self.packets = 0

    def write(self, raw, is_packet):
        self.f.write(raw)
        self.bytes += len(raw)
        if is_packet:
            self.packets += 1

    def close(self):
        if self.f is not None:
            self.f.close()
            self.chunks[-1].update(bytes=self.bytes, packets=self.packets)
            self.f = None

    def remove_all(self):
        self.close()
        for c in self.chunks:
            try:
                os.remove(os.path.join(self.outdir, c["file"]))
            except OSError:
                pass


def split_steps(path, outdir=None, size=None, packets=None, chunks=None, force=False):
    """Generator: split `path`. Yields (bytes_done, bytes_total); returns a summary."""
    if not (size or packets or chunks):
        size = 50 << 20
    fmt = detect_format(path)
    total = os.path.getsize(path)
    stem, ext = os.path.splitext(os.path.basename(path))
    ext = ext or ".pcap"
    outdir = outdir or default_outdir(path)
    os.makedirs(outdir, exist_ok=True)

    existing = existing_chunk_files(outdir)
    if existing and not force:
        raise PcapError(f"{outdir} already contains chunk files; use --force to overwrite")
    for n in existing:
        os.remove(os.path.join(outdir, n))

    w = ChunkWriter(outdir, stem, ext, size, packets, chunks, total)
    yield 0, total
    try:
        with open(path, "rb", buffering=BUF) as raw_f:
            f = HashingReader(raw_f)
            last = 0
            if fmt == "pcap":
                hdr, endian, rec_len = read_pcap_header(f)
                w.open(hdr)
                for rec in iter_pcap_records(f, endian, rec_len):
                    if w.should_rotate(len(rec), f.pos - len(rec)):
                        w.open(hdr)
                    w.write(rec, True)
                    if f.pos - last >= PROGRESS_EVERY:
                        last = f.pos
                        yield last, total
            else:
                # Each new chunk is prefixed with the current section header and
                # every interface defined so far, so it is valid on its own.
                cur_shb, cur_idbs = b"", []
                w.open(b"")
                for btype, raw in iter_pcapng_blocks(f):
                    is_pkt = btype in PACKET_BLOCKS
                    if is_pkt and w.should_rotate(len(raw), f.pos - len(raw)):
                        w.open(cur_shb + b"".join(cur_idbs))
                    if btype == SHB:
                        cur_shb, cur_idbs = raw, []
                    elif btype == IDB:
                        cur_idbs.append(raw)
                    w.write(raw, is_pkt)
                    if f.pos - last >= PROGRESS_EVERY:
                        last = f.pos
                        yield last, total
            w.close()
    except BaseException:  # error or cancel (gen.close()): leave no partial chunks
        w.remove_all()
        raise

    with open(os.path.join(outdir, MANIFEST), "w") as mf:
        json.dump({
            "source": os.path.basename(path),
            "format": fmt,
            "size": total,
            "sha256": f.h.hexdigest(),
            "chunks": w.chunks,
        }, mf, indent=2)

    yield total, total
    return {
        "input": path,
        "outdir": outdir,
        "format": fmt,
        "size": total,
        "chunks": len(w.chunks),
        "packets": sum(c["packets"] for c in w.chunks),
    }


def split(*args, **kwargs):
    return run(split_steps(*args, **kwargs))


# ------------------------------------------------------------------ merge --

def discover_chunks(folder):
    """Return (ordered chunk filenames, merged filename, expected sha256 or None)."""
    if not os.path.isdir(folder):
        raise PcapError(f"{folder} is not a folder")
    mpath = os.path.join(folder, MANIFEST)
    if os.path.isfile(mpath):
        with open(mpath) as mf:
            m = json.load(mf)
        names = [c["file"] for c in m["chunks"]]
        missing = [n for n in names if not os.path.isfile(os.path.join(folder, n))]
        if missing:
            raise PcapError(f"missing chunk files: {', '.join(missing)}")
        return names, m["source"], m.get("sha256")

    groups = {}
    for name in os.listdir(folder):
        mt = CHUNK_RE.match(name)
        if mt and os.path.isfile(os.path.join(folder, name)):
            groups.setdefault((mt["base"], mt["ext"]), []).append((int(mt["id"]), name))
    if not groups:
        raise PcapError(f"no <name>_<id>.<ext> chunk files found in {folder}")
    if len(groups) > 1:
        sets = ", ".join(b + e for b, e in groups)
        raise PcapError(f"folder holds chunks of several captures ({sets}); keep one per folder")
    (base, ext), items = next(iter(groups.items()))
    items.sort()
    ids = [i for i, _ in items]
    if ids != list(range(ids[0], ids[0] + len(ids))):
        gaps = sorted(set(range(ids[0], ids[-1] + 1)) - set(ids))
        raise PcapError(f"chunk ids are not contiguous; missing {gaps}")
    return [n for _, n in items], base + ext, None


def default_merge_output(folder):
    _, merged_name, _ = discover_chunks(folder)
    return os.path.join(folder, merged_name)


def merge_steps(folder, output=None, force=False, verify=True):
    """Generator: merge a chunk folder. Yields (bytes_done, bytes_total); returns a summary."""
    names, merged_name, expected = discover_chunks(folder)
    output = output or os.path.join(folder, merged_name)
    if os.path.exists(output) and not force:
        raise PcapError(f"{output} already exists; use --force to overwrite")

    paths = [os.path.join(folder, n) for n in names]
    total = sum(os.path.getsize(p) for p in paths)
    fmt = detect_format(paths[0])
    tmp = output + ".part"
    done = last = 0
    yield 0, total
    try:
        with open(tmp, "wb", buffering=BUF) as raw_out:
            out = HashingWriter(raw_out)
            steps = _merge_pcap(paths, out) if fmt == "pcap" else _merge_pcapng(paths, out)
            for n in steps:
                done += n
                if done - last >= PROGRESS_EVERY:
                    last = done
                    yield done, total
        os.replace(tmp, output)
    except BaseException:  # error or cancel: don't leave a half-written file
        if os.path.exists(tmp):
            os.remove(tmp)
        raise

    verified = None
    if verify and expected:
        if out.h.hexdigest() != expected:
            raise PcapError("SHA-256 mismatch: merged file differs from the original")
        verified = True

    yield total, total
    return {
        "folder": folder,
        "output": output,
        "chunks": len(paths),
        "size": os.path.getsize(output),
        "verified": verified,
    }


def merge(*args, **kwargs):
    return run(merge_steps(*args, **kwargs))


def _merge_pcap(paths, out):
    """Yields number of input bytes consumed."""
    first_hdr = None
    for p in paths:
        with open(p, "rb", buffering=BUF) as f:
            hdr, _, _ = read_pcap_header(f)
            if first_hdr is None:
                first_hdr = hdr
                out.write(hdr)
            elif hdr != first_hdr:
                raise PcapError(f"{os.path.basename(p)} has a different pcap header "
                                "(link type / snaplen / precision); cannot merge")
            yield len(hdr)
            while True:
                data = f.read(BUF)
                if not data:
                    break
                out.write(data)
                yield len(data)


def _merge_pcapng(paths, out):
    """Yields number of input bytes consumed (batched)."""
    cur_shb, cur_idbs = None, []
    for i, p in enumerate(paths):
        pending = 0
        with open(p, "rb", buffering=BUF) as f:
            blocks = iter_pcapng_blocks(f)
            if i > 0:
                # drop the prefix the splitter added: SHB + interfaces seen so far
                for want in [cur_shb] + cur_idbs:
                    got = next(blocks, (None, b""))[1]
                    if got != want:
                        raise PcapError(f"{os.path.basename(p)} does not continue the previous "
                                        "chunk (unexpected header blocks); was it reordered?")
                    pending += len(got)
            for btype, raw in blocks:
                if btype == SHB:
                    cur_shb, cur_idbs = raw, []
                elif btype == IDB:
                    cur_idbs.append(raw)
                out.write(raw)
                pending += len(raw)
                if pending >= BUF:
                    yield pending
                    pending = 0
        yield pending


# -------------------------------------------------------------------- cli --

def parse_size(text):
    mt = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgKMG]?)[bB]?\s*", text)
    if not mt:
        raise argparse.ArgumentTypeError(f"bad size {text!r} (examples: 50M, 512K, 1G, 1048576)")
    mult = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}[mt[2].lower()]
    n = int(float(mt[1]) * mult)
    if n <= 0:
        raise argparse.ArgumentTypeError("size must be positive")
    return n


def positive_int(text):
    n = int(text)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return n


def main(argv=None):
    logging.basicConfig(format="warning: %(message)s", level=logging.WARNING)
    ap = argparse.ArgumentParser(description="Split a pcap/pcapng into chunks, or merge a chunk folder back.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("split", help="split a capture into <name>_<id> chunks")
    sp.add_argument("input", help="pcap or pcapng file")
    sp.add_argument("-o", "--outdir", help="output folder (default: <name>_chunks next to the input)")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("-s", "--size", type=parse_size, help="max chunk size, e.g. 50M (default 50M)")
    g.add_argument("-n", "--chunks", type=positive_int, help="number of roughly equal chunks")
    g.add_argument("-p", "--packets", type=positive_int, help="packets per chunk")
    sp.add_argument("-f", "--force", action="store_true", help="replace chunks already in the folder")

    mp = sub.add_parser("merge", help="merge a chunk folder back into one capture")
    mp.add_argument("folder", help="folder produced by split")
    mp.add_argument("-o", "--output", help="output file (default: <folder>/<original name>)")
    mp.add_argument("-f", "--force", action="store_true", help="overwrite the output file")
    mp.add_argument("--no-verify", action="store_true", help="skip the SHA-256 check")

    a = ap.parse_args(argv)
    try:
        if a.cmd == "split":
            r = split(a.input, a.outdir, a.size, a.packets, a.chunks, a.force)
            print(f"split {r['input']} ({r['format']}, {r['size']:,} bytes, {r['packets']:,} packets) "
                  f"into {r['chunks']} chunks in {r['outdir']}")
        else:
            r = merge(a.folder, a.output, a.force, not a.no_verify)
            print(f"merged {r['chunks']} chunks into {r['output']} ({r['size']:,} bytes)")
            if r["verified"]:
                print("verified: SHA-256 matches the original file")
    except (PcapError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
