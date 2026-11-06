"""Pure-stdlib byte builders for PcapChunk test fixtures.

Everything here produces or inspects raw capture bytes.  It never imports the
engine: tests use these builders to create deterministic inputs and inspect
chunk outputs independently.

Layout of this module:

* constants and tiny helpers (``write``, ``gzip_bytes``, ``sha256``)
* classic pcap builders (both byte orders, usec/nsec, Kuznetzov, any linktype)
* pcapng block builders (SHB/IDB/EPB/SPB/NRB/unknown, options, padding)
* packet layer builders (Ethernet/IPv4/IPv6/TCP/UDP/ICMP) for flow tests
* tolerant parsers used by tests to inspect chunk files
"""

import gzip
import hashlib
import ipaddress
import os
import struct

# Fixed epoch: 2020-09-13T13:00:00Z.  Divisible by 60 and 3600 so epoch-aligned
# rotation buckets are trivial to predict.
BASE_S = 1_600_002_000
BASE_NS = BASE_S * 1_000_000_000

# ---------------------------------------------------------------- constants --

SHB = 0x0A0D0D0A
SHB_BYTES = b"\x0a\x0d\x0d\x0a"
IDB = 0x00000001
SPB = 0x00000003
NRB = 0x00000004
EPB = 0x00000006
OLD_PACKET = 0x00000002
BOM_LE = b"\x4d\x3c\x2b\x1a"
BOM_BE = b"\x1a\x2b\x3c\x4d"

PCAP_MAGIC_USEC = 0xA1B2C3D4
PCAP_MAGIC_NSEC = 0xA1B23C4D
PCAP_MAGIC_KUZ = 0xA1B2CD34

PCAP_GLOBAL_HDR_LEN = 24

_PCAP_SPECS = {
    b"\xd4\xc3\xb2\xa1": ("<", "usec", 16),  # LE usec
    b"\xa1\xb2\xc3\xd4": (">", "usec", 16),  # BE usec
    b"\x4d\x3c\xb2\xa1": ("<", "nsec", 16),  # LE nsec
    b"\xa1\xb2\x3c\x4d": (">", "nsec", 16),  # BE nsec
    b"\x34\xcd\xb2\xa1": ("<", "usec", 24),  # Kuznetzov LE
    b"\xa1\xb2\xcd\x34": (">", "usec", 24),  # Kuznetzov BE
}

# --------------------------------------------------------------- io helpers --

def write(path, data):
    """Write *data* (bytes) to *path* and return the path."""
    with open(path, "wb") as f:
        f.write(data)
    return path


def read(path):
    with open(path, "rb") as f:
        return f.read()


def gzip_bytes(data, mtime=0):
    """Deterministic gzip wrapper (fixed mtime)."""
    return gzip.compress(data, 9, mtime=mtime)


def gzip_read(data):
    return gzip.decompress(data)


def sha256(data):
    if isinstance(data, str):
        data = read(data)
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def list_files(root):
    """All regular files below *root* as relative paths, sorted."""
    if not os.path.isdir(root):
        return []
    out = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            out.append(os.path.relpath(os.path.join(dirpath, name), root))
    return sorted(out)


def payload(size, seed=0):
    """Deterministic, mildly compressible bytes."""
    if size <= 0:
        return b""
    raw = bytes((seed + i) % 251 for i in range(size))
    return raw


def packet_stream(n, payload_size=24, start_ns=BASE_NS, step_ns=1_000_000,
                  kind="tcp"):
    """List of (ts_ns, packet_bytes) with decodable Ethernet/IPv4 packages."""
    out = []
    for i in range(n):
        sport = 10000 + i
        if kind == "tcp":
            data = eth_ipv4_tcp("10.0.0.1", "10.0.0.2", sport, 80,
                                payload(payload_size, i))
        elif kind == "udp":
            data = eth_ipv4_udp("10.0.0.3", "10.0.0.4", sport, 53,
                                payload(payload_size, i))
        elif kind == "icmp":
            data = eth_ipv4_icmp("10.0.0.5", "10.0.0.6",
                                 payload(payload_size, i))
        else:
            data = payload(payload_size, i)
        out.append((start_ns + i * step_ns, data))
    return out


# ------------------------------------------------------------- classic pcap --

def pcap_global_header(endian="<", precision="usec", linktype=1, snaplen=65535,
                       kuznetzov=False, version=(2, 4), thiszone=0,
                       sigfigs=0):
    if kuznetzov:
        magic = PCAP_MAGIC_KUZ
    elif precision == "nsec":
        magic = PCAP_MAGIC_NSEC
    else:
        magic = PCAP_MAGIC_USEC
    return struct.pack(endian + "IHHIIII", magic, version[0], version[1],
                       thiszone & 0xFFFFFFFF, sigfigs, snaplen, linktype)


def pcap_record(ts_ns, data=b"", endian="<", precision="usec",
                kuznetzov=False, declared_len=None, orig_len=None):
    """One classic-pcap record.  ``declared_len`` can lie about the length."""
    sec = ts_ns // 1_000_000_000
    frac = ts_ns % 1_000_000_000
    sub = frac if precision == "nsec" else frac // 1000
    incl = len(data) if declared_len is None else declared_len
    orig = incl if orig_len is None else orig_len
    hdr = struct.pack(endian + "IIII", sec & 0xFFFFFFFF, sub & 0xFFFFFFFF,
                      incl & 0xFFFFFFFF, orig & 0xFFFFFFFF)
    if kuznetzov:
        # 8 extra bytes of metadata (content is opaque to the engine).
        hdr += struct.pack(endian + "IHBB", 0, 0, 0, 0)
    return hdr + data


def pcap_bytes(packets, endian="<", precision="usec", linktype=1,
               snaplen=65535, kuznetzov=False, header=None, tail=b"",
               version=(2, 4)):
    """Build a classic pcap file from ``[(ts_ns, data), ...]``."""
    if header is None:
        header = pcap_global_header(endian=endian, precision=precision,
                                    linktype=linktype, snaplen=snaplen,
                                    kuznetzov=kuznetzov, version=version)
    out = [header]
    for item in packets:
        if len(item) == 3:
            ts_ns, data, extra = item
            out.append(pcap_record(ts_ns, data, endian=endian,
                                   precision=precision, kuznetzov=kuznetzov,
                                   **extra))
        else:
            ts_ns, data = item
            out.append(pcap_record(ts_ns, data, endian=endian,
                                   precision=precision, kuznetzov=kuznetzov))
    out.append(tail)
    return b"".join(out)


# ---------------------------------------------------------------- pcapng ----

def _pad4(data):
    return data + b"\x00" * (-len(data) % 4)


def pcapng_block(block_type, body, endian="<", declared_len=None):
    body = _pad4(body)
    total = 12 + len(body)
    wire_total = total if declared_len is None else declared_len
    return (struct.pack(endian + "II", block_type, wire_total) + body
            + struct.pack(endian + "I", wire_total))


def pcapng_option(code, value, endian="<"):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return struct.pack(endian + "HH", code, len(value)) + _pad4(value)


def pcapng_options(pairs, endian="<"):
    """Encode option pairs, terminated with opt_endofopt."""
    return b"".join(pcapng_option(c, v, endian) for c, v in pairs) + \
        struct.pack(endian + "HH", 0, 0)


def section_header(endian="<", options=(), section_len=-1, version=(1, 0)):
    bom = BOM_LE if endian == "<" else BOM_BE
    body = bom + struct.pack(endian + "HHq", version[0], version[1],
                             section_len)
    if options:
        body += pcapng_options(options, endian)
    return pcapng_block(SHB, body, endian)


def interface_description(linktype=1, snaplen=65535, endian="<", tsresol=6,
                          name=None, options=(), with_end=True):
    body = struct.pack(endian + "HHI", linktype, 0, snaplen)
    opts = []
    if name is not None:
        opts.append((2, name))
    if tsresol is not None:
        opts.append((9, bytes([tsresol])))
    opts.extend(options)
    if with_end and opts:
        body += pcapng_options(opts, endian)
    return pcapng_block(IDB, body, endian)


def _ts_to_units(ts_ns, tsresol):
    """Convert ns to timestamp units for an if_tsresol value."""
    if tsresol & 0x80:
        return ts_ns * (1 << (tsresol & 0x7F)) // 1_000_000_000
    return ts_ns * (10 ** tsresol) // 1_000_000_000


def enhanced_packet(iface, ts_ns, data, endian="<", tsresol=6,
                    orig_len=None, options=()):
    units = _ts_to_units(ts_ns, tsresol)
    hi = (units >> 32) & 0xFFFFFFFF
    lo = units & 0xFFFFFFFF
    orig = len(data) if orig_len is None else orig_len
    body = struct.pack(endian + "IIIII", iface, hi, lo, len(data), orig)
    body += _pad4(data)
    if options:
        body += pcapng_options(options, endian)
    return pcapng_block(EPB, body, endian)


def simple_packet(data, endian="<", orig_len=None):
    orig = len(data) if orig_len is None else orig_len
    return pcapng_block(SPB, struct.pack(endian + "I", orig) + _pad4(data),
                        endian)


def nrb_record(record_type, value, endian="<"):
    return struct.pack(endian + "HH", record_type, len(value)) + _pad4(value)


def name_resolution_block(records, endian="<"):
    body = b"".join(nrb_record(t, v, endian) for t, v in records)
    body += struct.pack(endian + "HH", 0, 0)
    return pcapng_block(NRB, body, endian)


def unknown_block(block_type=0x00000BAD, body=b"opaque!", endian="<"):
    return pcapng_block(block_type, body, endian)


def pcapng_section(*blocks, endian="<", options=()):
    """A section: SHB followed by *blocks*."""
    return section_header(endian=endian, options=options) + b"".join(blocks)


def default_pcapng(packets, endian="<", linktype=1, snaplen=65535,
                   tsresol=6, name=None, options=None):
    """One section, one interface, EPB per packet: [(ts_ns, data), ...]."""
    blocks = [interface_description(linktype=linktype, snaplen=snaplen,
                                    endian=endian, tsresol=tsresol,
                                    name=name)]
    for ts_ns, data in packets:
        blocks.append(enhanced_packet(0, ts_ns, data, endian=endian,
                                      tsresol=tsresol))
    if options:
        blocks.append(options)
    return pcapng_section(*blocks, endian=endian)


# ---------------------------------------------------------- packet layers ---
# The fields the engine needs to decode (addresses, ports, protocol, lengths)
# are correct; checksums are left at zero because decoding does not verify them.

def _mac(last):
    return b"\x02\x00\x00\x00\x00" + bytes([last])


def ethernet(payload, ethertype=0x0800, dst=2, src=1, vlan=None):
    if vlan is None:
        return _mac(dst) + _mac(src) + struct.pack(">H", ethertype) + payload
    return (_mac(dst) + _mac(src) + struct.pack(">H", 0x8100)
            + struct.pack(">HH", vlan, ethertype) + payload)


def ipv4(src="10.0.0.1", dst="10.0.0.2", proto=6, payload=b"", ttl=64,
         ident=1):
    src_b = ipaddress.IPv4Address(src).packed
    dst_b = ipaddress.IPv4Address(dst).packed
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ident, 0, ttl, proto,
                      0, src_b, dst_b)
    return hdr + payload


def ipv6(src="2001:db8::1", dst="2001:db8::2", next_header=6, payload=b"",
         hop_limit=64):
    src_b = ipaddress.IPv6Address(src).packed
    dst_b = ipaddress.IPv6Address(dst).packed
    return struct.pack(">IHBB16s16s", 0x60000000, len(payload), next_header,
                       hop_limit, src_b, dst_b) + payload


def tcp(sport, dport, payload=b"", flags=0x18, seq=0):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags,
                       65535, 0, 0) + payload


def udp(sport, dport, payload=b""):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(payload=b"\x08\x00\x00\x00"):
    return payload


def eth_ipv4_tcp(src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=1234, dport=80,
                 data=b"", vlan=None):
    return ethernet(ipv4(src_ip, dst_ip, 6, tcp(sport, dport, data)),
                    vlan=vlan)


def eth_ipv4_udp(src_ip="10.0.0.3", dst_ip="10.0.0.4", sport=5353, dport=53,
                 data=b"", vlan=None):
    return ethernet(ipv4(src_ip, dst_ip, 17, udp(sport, dport, data)),
                    vlan=vlan)


def eth_ipv4_icmp(src_ip="10.0.0.5", dst_ip="10.0.0.6", data=b""):
    return ethernet(ipv4(src_ip, dst_ip, 1, icmp(data)))


def null_ipv4_tcp(src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=1234, dport=80,
                  data=b""):
    # BSD loopback header: address family in host byte order (LE on x86).
    return struct.pack("<I", 2) + ipv4(src_ip, dst_ip, 6,
                                       tcp(sport, dport, data))


def raw_ipv4_tcp(src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=1234, dport=80,
                 data=b""):
    return ipv4(src_ip, dst_ip, 6, tcp(sport, dport, data))


# ------------------------------------------------------------------ parsers --
# Tolerant parsers: enough to check framing / timestamps / payloads of fixtures
# and of chunk files produced by the engine.  They never raise.

def detect_magic(data):
    if data[:4] in _PCAP_SPECS:
        return "pcap"
    if data[:4] == SHB_BYTES:
        return "pcapng"
    return None


def parse_pcap(data):
    endian, precision, rec_len = _PCAP_SPECS[data[:4]]
    magic, vmaj, vmin, thiszone, sigfigs, snaplen, linktype = struct.unpack(
        endian + "IHHIIII", data[:PCAP_GLOBAL_HDR_LEN])
    records = []
    packets = []
    pos = PCAP_GLOBAL_HDR_LEN
    truncated = False
    tail = b""
    while pos < len(data):
        if pos + rec_len > len(data):
            truncated = True
            tail = data[pos:]
            break
        sec, frac, incl, orig = struct.unpack_from(endian + "IIII", data, pos)
        raw_hdr = data[pos:pos + rec_len]
        data_start = pos + rec_len
        avail = max(0, len(data) - data_start)
        take = min(incl, avail)
        if take < incl:
            truncated = True
        payload_b = data[data_start:data_start + take]
        ts_ns = sec * 1_000_000_000 + (frac if precision == "nsec"
                                       else frac * 1000)
        records.append(raw_hdr + payload_b)
        packets.append({
            "ts_ns": ts_ns, "caplen": incl, "orig_len": orig,
            "data": payload_b, "endian": endian, "precision": precision,
            "truncated": take < incl,
        })
        pos = data_start + take
        if take < incl:
            break
    return {
        "format": "pcap", "endian": endian, "precision": precision,
        "linktype": linktype, "snaplen": snaplen, "version": (vmaj, vmin),
        "records": records, "packets": packets, "truncated": truncated,
        "tail": tail,
    }


def _parse_options(body, endian):
    opts = {}
    pos = 0
    while pos + 4 <= len(body):
        code, length = struct.unpack_from(endian + "HH", body, pos)
        pos += 4
        value = body[pos:pos + length]
        pos += length + (-length % 4)
        if code == 0:
            break
        opts.setdefault(code, []).append(value)
    return opts


def iter_pcapng_blocks(data):
    """Yield dicts for each block; truncated tails are marked, never raised."""
    endian = None
    pos = 0
    out = []
    while pos < len(data):
        if len(data) - pos < 12:
            out.append({"type": None, "body": data[pos:], "raw": data[pos:],
                        "truncated": True})
            break
        if data[pos:pos + 4] == SHB_BYTES:
            bom = data[pos + 8:pos + 12]
            if bom == BOM_LE:
                endian = "<"
            elif bom == BOM_BE:
                endian = ">"
            else:
                out.append({"type": None, "body": data[pos:],
                            "raw": data[pos:], "truncated": True})
                break
            btype = SHB
        else:
            if endian is None:
                out.append({"type": None, "body": data[pos:],
                            "raw": data[pos:], "truncated": True})
                break
            btype = struct.unpack_from(endian + "I", data, pos)[0]
        blen = struct.unpack_from(endian + "I", data, pos + 4)[0]
        if blen < 12 or blen % 4 or pos + blen > len(data):
            out.append({"type": btype, "body": data[pos + 8:],
                        "raw": data[pos:], "truncated": True,
                        "declared_len": blen})
            break
        out.append({"type": btype, "body": data[pos + 8:pos + blen - 4],
                    "raw": data[pos:pos + blen], "truncated": False,
                    "endian": endian})
        pos += blen
    return out


def parse_pcapng(data):
    sections = []
    packets = []
    blocks = iter_pcapng_blocks(data)
    endian = None
    for blk in blocks:
        btype = blk["type"]
        body = blk["body"]
        if btype == SHB and not blk["truncated"]:
            bom = body[0:4]
            endian = "<" if bom == BOM_LE else ">" if bom == BOM_BE else endian
            vmaj, vmin = struct.unpack_from(endian + "HH", body, 4)
            sections.append({"endian": endian, "version": (vmaj, vmin),
                             "interfaces": [], "blocks": []})
            blocks_list = sections[-1]["blocks"]
        else:
            blocks_list = sections[-1]["blocks"] if sections else []
        blocks_list.append(blk)
        if btype == IDB and not blk["truncated"]:
            linktype, _res, snaplen = struct.unpack_from(endian + "HHI", body,
                                                         0)
            opts = _parse_options(body[8:], endian)
            tsresol = opts.get(9, [b"\x06"])[0][0]
            name = None
            if 2 in opts:
                try:
                    name = opts[2][0].decode("utf-8", "replace")
                except Exception:
                    name = None
            sections[-1]["interfaces"].append({
                "linktype": linktype, "snaplen": snaplen,
                "name": name, "tsresol": tsresol, "packets": 0,
            })
        elif btype == EPB and not blk["truncated"] and sections:
            iface, hi, lo, caplen, orig = struct.unpack_from(
                endian + "IIIII", body, 0)
            pkt = body[20:20 + caplen]
            ifaces = sections[-1]["interfaces"]
            tsresol = ifaces[iface]["tsresol"] if iface < len(ifaces) else 6
            units = (hi << 32) | lo
            if tsresol & 0x80:
                ts_ns = units * 1_000_000_000 // (1 << (tsresol & 0x7F))
            else:
                ts_ns = units * 1_000_000_000 // (10 ** tsresol)
            packets.append({"iface": iface, "ts_ns": ts_ns,
                            "caplen": caplen, "orig_len": orig,
                            "data": pkt, "type": "epb",
                            "section": len(sections) - 1})
            if iface < len(ifaces):
                ifaces[iface]["packets"] += 1
        elif btype == SPB and not blk["truncated"] and sections:
            orig = struct.unpack_from(endian + "I", body, 0)[0]
            pkt = body[4:4 + orig]
            packets.append({"iface": 0, "ts_ns": None, "caplen": orig,
                            "orig_len": orig, "data": pkt, "type": "spb",
                            "section": len(sections) - 1})
            if sections[-1]["interfaces"]:
                sections[-1]["interfaces"][0]["packets"] += 1
    return {"format": "pcapng", "sections": sections,
            "blocks": [blk for sec in sections for blk in sec["blocks"]],
            "packets": packets, "truncated": any(sec["blocks"]
                                                and sec["blocks"][-1]["truncated"]
                                                for sec in sections)}


def parse_capture(data):
    kind = detect_magic(data)
    if kind == "pcap":
        return parse_pcap(data)
    if kind == "pcapng":
        return parse_pcapng(data)
    raise ValueError("not a pcap/pcapng fixture")


def packet_ts_list(data):
    return [p["ts_ns"] for p in parse_capture(data)["packets"]]


def packet_payloads(data):
    return [p["data"] for p in parse_capture(data)["packets"]]


def packet_count(data):
    return len(parse_capture(data)["packets"])


def utc_stamp(ts_ns):
    import datetime
    dt = datetime.datetime.fromtimestamp(ts_ns // 1_000_000_000,
                                         datetime.timezone.utc)
    return dt.strftime("%Y%m%dT%H%M%S")


def _selftest():  # pragma: no cover - manual fixture sanity check
    packets = packet_stream(5)
    for endian in ("<", ">"):
        for precision in ("usec", "nsec"):
            data = pcap_bytes(packets, endian=endian, precision=precision)
            parsed = parse_pcap(data)
            assert len(parsed["packets"]) == 5, (endian, precision)
            assert parsed["precision"] == precision
            assert parsed["packets"][2]["ts_ns"] == packets[2][0]
    for endian in ("<", ">"):
        data = default_pcapng(packets, endian=endian)
        parsed = parse_pcapng(data)
        assert len(parsed["packets"]) == 5, endian
        assert parsed["packets"][3]["ts_ns"] == packets[3][0]
    data = pcapng_section(
        interface_description(linktype=1, name="eth0", tsresol=9,
                              endian=">"),
        enhanced_packet(0, BASE_NS, b"abc", endian=">", tsresol=9),
        name_resolution_block([(1, b"\x0a\x00\x00\x01")], endian=">"),
        simple_packet(b"xyz", endian=">"),
        unknown_block(0xBAD, b"junk", endian=">"),
        endian=">")
    parsed = parse_pcapng(data)
    assert len(parsed["packets"]) == 2
    print("fixtures selftest OK")


if __name__ == "__main__":  # pragma: no cover
    _selftest()
