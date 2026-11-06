"""Inspection: detect_format, open_capture, describe, info, iso_ts."""

import os
import unittest

from support import TempDirTest, BASE_NS

import fixtures as fx
import pcapchunk

SEC = 1_000_000_000


class DetectFormatTest(TempDirTest):
    def test_detect_classic_variants(self):
        packets = fx.packet_stream(3)
        variants = [
            fx.pcap_bytes(packets, endian="<", precision="usec"),
            fx.pcap_bytes(packets, endian=">", precision="usec"),
            fx.pcap_bytes(packets, endian="<", precision="nsec"),
            fx.pcap_bytes(packets, endian=">", precision="nsec"),
            fx.pcap_bytes(packets, endian="<", kuznetzov=True),
            fx.pcap_bytes(packets, endian=">", kuznetzov=True),
        ]
        for i, data in enumerate(variants):
            with self.subTest(i=i):
                path = self.write("cap_%d.pcap" % i, data)
                self.assertEqual(pcapchunk.detect_format(path), "pcap")

    def test_detect_pcapng(self):
        packets = fx.packet_stream(3)
        for endian in ("<", ">"):
            path = self.write("cap_%s.pcapng" % ("le" if endian == "<" else
                                                 "be"),
                              fx.default_pcapng(packets, endian=endian))
            self.assertEqual(pcapchunk.detect_format(path), "pcapng")

    def test_detect_through_gzip(self):
        raw = fx.pcap_bytes(fx.packet_stream(3))
        path = self.write("cap.pcap.gz", fx.gzip_bytes(raw))
        self.assertEqual(pcapchunk.detect_format(path), "pcap")
        pathng = self.write("cap.pcapng.gz",
                            fx.gzip_bytes(fx.default_pcapng(
                                fx.packet_stream(3))))
        self.assertEqual(pcapchunk.detect_format(pathng), "pcapng")

    def test_detect_unknown_raises(self):
        path = self.write("notes.bin", b"this is not a capture")
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.detect_format(path)
        empty = self.write("empty.bin", b"")
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.detect_format(empty)


class OpenCaptureTest(TempDirTest):
    def test_open_plain_pcap(self):
        packets = fx.packet_stream(4)
        data = fx.pcap_bytes(packets)
        path = self.write("cap.pcap", data)
        f, fmt, compressed, logical_size = pcapchunk.open_capture(path)
        try:
            self.assertEqual(f.read(), data)
        finally:
            f.close()
        self.assertEqual(fmt, "pcap")
        self.assertIsNone(compressed)
        self.assertEqual(logical_size, len(data))

    def test_open_gzip_pcap(self):
        packets = fx.packet_stream(4)
        raw = fx.pcap_bytes(packets)
        gz = fx.gzip_bytes(raw)
        path = self.write("cap.pcap.gz", gz)
        f, fmt, compressed, logical_size = pcapchunk.open_capture(path)
        try:
            self.assertEqual(f.read(), raw)
        finally:
            f.close()
        self.assertEqual(fmt, "pcap")
        self.assertEqual(compressed, "gzip")
        self.assertIn(logical_size, (None, len(raw)))

    def test_open_pcapng(self):
        raw = fx.default_pcapng(fx.packet_stream(3))
        path = self.write("cap.pcapng", raw)
        f, fmt, compressed, logical_size = pcapchunk.open_capture(path)
        try:
            self.assertEqual(f.read(), raw)
        finally:
            f.close()
        self.assertEqual(fmt, "pcapng")
        self.assertIsNone(compressed)
        self.assertEqual(logical_size, len(raw))


class DescribeTest(TempDirTest):
    def test_describe_pcap_le_usec(self):
        packets = fx.packet_stream(3)
        path = self.make_pcap(packets, linktype=1, snaplen=65535)
        result = pcapchunk.describe(path)
        self.assertEqual(result["path"], path)
        self.assertEqual(result["format"], "pcap")
        self.assertIsNone(result["compressed"])
        self.assertEqual(result["size"], os.path.getsize(path))
        self.assertEqual(result["logical_size"], os.path.getsize(path))
        self.assertEqual(result["precision"], "usec")
        self.assertEqual(result["linktype"], 1)
        self.assertEqual(result["snaplen"], 65535)
        # interfaces is documented for pcapng; a pcap may expose a synthetic
        # interface, but if it does it must describe the same header.
        ifaces = result.get("interfaces") or []
        for iface in ifaces:
            self.assertEqual(iface["linktype"], 1)
            self.assertEqual(iface["snaplen"], 65535)

    def test_describe_pcap_nsec_and_be(self):
        packets = fx.packet_stream(3)
        path = self.make_pcap(packets, endian=">", precision="nsec",
                              linktype=101, snaplen=262144)
        result = pcapchunk.describe(path)
        self.assertEqual(result["precision"], "nsec")
        self.assertEqual(result["linktype"], 101)
        self.assertEqual(result["snaplen"], 262144)

    def test_describe_pcapng_interfaces(self):
        data = (fx.pcapng_section(
                    fx.interface_description(linktype=1, snaplen=65535,
                                             name="eth0", tsresol=6),
                    fx.enhanced_packet(0, BASE_NS, fx.eth_ipv4_tcp(data=b"a")),
                    endian="<")
                + fx.pcapng_section(
                    fx.interface_description(linktype=101, snaplen=65535,
                                             name="raw0", tsresol=9,
                                             endian=">"),
                    fx.enhanced_packet(0, BASE_NS + 1, fx.raw_ipv4_tcp(
                        data=b"b"), endian=">", tsresol=9),
                    endian=">"))
        path = self.write("multi.pcapng", data)
        result = pcapchunk.describe(path)
        self.assertEqual(result["format"], "pcapng")
        self.assertIsNone(result["precision"])
        ifaces = result["interfaces"]
        self.assertEqual(len(ifaces), 2)
        # `linktype`/`snaplen` are documented for pcap only; if the engine
        # also fills them for pcapng they must mirror the first interface.
        if result["linktype"] is not None:
            self.assertEqual(result["linktype"], ifaces[0]["linktype"])
        if result["snaplen"] is not None:
            self.assertEqual(result["snaplen"], ifaces[0]["snaplen"])
        for iface in ifaces:
            for key in ("id", "linktype", "snaplen", "name", "tsresol"):
                self.assertIn(key, iface)
        self.assertEqual(ifaces[0]["linktype"], 1)
        self.assertEqual(ifaces[0]["name"], "eth0")
        self.assertEqual(ifaces[0]["tsresol"], 6)
        self.assertEqual(ifaces[1]["linktype"], 101)
        self.assertEqual(ifaces[1]["name"], "raw0")
        self.assertEqual(ifaces[1]["tsresol"], 9)

    def test_describe_gzip(self):
        raw = fx.pcap_bytes(fx.packet_stream(3))
        gz = fx.gzip_bytes(raw)
        path = self.write("cap.pcap.gz", gz)
        result = pcapchunk.describe(path)
        self.assertEqual(result["format"], "pcap")
        self.assertEqual(result["compressed"], "gzip")
        self.assertEqual(result["size"], len(gz))
        self.assertIn(result["logical_size"], (None, len(raw)))
        self.assertEqual(result["precision"], "usec")
        self.assertEqual(result["linktype"], 1)


class InfoTest(TempDirTest):
    def _capture(self, n=5):
        packets = [(BASE_NS + i * SEC, fx.eth_ipv4_tcp(data=bytes([i])))
                   for i in range(n)]
        return self.make_pcap(packets), packets

    def test_info_basic_fields(self):
        src, packets = self._capture()
        result = pcapchunk.info(src)
        self.assertEqual(result["path"], src)
        self.assertEqual(result["format"], "pcap")
        self.assertIsNone(result["compressed"])
        self.assertEqual(result["size"], os.path.getsize(src))
        self.assertEqual(result["logical_size"], os.path.getsize(src))
        self.assertEqual(result["packets"], len(packets))
        self.assertEqual(result["bytes"], sum(len(p) for _ts, p in packets))
        self.assertEqual(result["first_ts_ns"], packets[0][0])
        self.assertEqual(result["last_ts_ns"], packets[-1][0])
        self.assertAlmostEqual(result["duration_s"],
                               (packets[-1][0] - packets[0][0]) / 1e9,
                               places=6)
        self.assertEqual(result.get("top") or [], [])

    def test_info_steps_generator(self):
        src, packets = self._capture(n=200)
        gen = pcapchunk.info_steps(src)
        yields = []
        result = None
        while True:
            try:
                yields.append(next(gen))
            except StopIteration as stop:
                result = stop.value
                break
        self.assertTrue(yields)
        size = os.path.getsize(src)
        for done, total in yields:
            self.assertIsInstance(done, int)
            self.assertIsInstance(total, int)
            self.assertEqual(total, size)
            self.assertLessEqual(0, done)
            self.assertLessEqual(done, total)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["packets"], len(packets))

    def test_info_pcapng_per_interface_packets(self):
        data = fx.pcapng_section(
            fx.interface_description(linktype=1, name="eth0"),
            fx.enhanced_packet(0, BASE_NS, fx.eth_ipv4_tcp(data=b"a")),
            fx.enhanced_packet(0, BASE_NS + 1, fx.eth_ipv4_tcp(data=b"b")),
            fx.interface_description(linktype=101, name="raw0"),
            fx.enhanced_packet(1, BASE_NS + 2, fx.raw_ipv4_tcp(data=b"c")),
            fx.enhanced_packet(1, BASE_NS + 3, fx.raw_ipv4_tcp(data=b"d")),
            fx.enhanced_packet(1, BASE_NS + 4, fx.raw_ipv4_tcp(data=b"e")),
        )
        src = self.write("ifaces.pcapng", data)
        result = pcapchunk.info(src)
        self.assertEqual(result["packets"], 5)
        by_name = {i["name"]: i["packets"] for i in result["interfaces"]}
        self.assertEqual(by_name, {"eth0": 2, "raw0": 3})
        self.assertEqual(len(result["interfaces"]), 2)

    def test_info_top_flows(self):
        packets = [
            (BASE_NS + 0 * SEC,
             fx.eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1234, 80, b"a")),
            (BASE_NS + 1 * SEC,
             fx.eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1234, 80, b"b")),
            (BASE_NS + 2 * SEC,
             fx.eth_ipv4_udp("10.0.0.3", "10.0.0.4", 5353, 53, b"c")),
        ]
        src = self.make_pcap(packets)
        result = pcapchunk.info(src, top=5)
        self.assertIn("top", result)
        self.assertTrue(result["top"])
        for entry in result["top"]:
            self.assertIsInstance(entry["flow"], str)
            self.assertTrue(entry["flow"])
            self.assertIsInstance(entry["packets"], int)
            self.assertIsInstance(entry["bytes"], int)
        self.assertLessEqual(sum(e["packets"] for e in result["top"]),
                             result["packets"])
        self.assertEqual(len(result["top"]), 2)

    def test_info_gzip_source(self):
        packets = [(BASE_NS + i * SEC, fx.eth_ipv4_tcp(data=bytes([i])))
                   for i in range(4)]
        raw = fx.pcap_bytes(packets)
        src = self.write("cap.pcap.gz", fx.gzip_bytes(raw))
        result = pcapchunk.info(src)
        self.assertEqual(result["format"], "pcap")
        self.assertEqual(result["compressed"], "gzip")
        self.assertEqual(result["packets"], 4)
        self.assertEqual(result["first_ts_ns"], packets[0][0])
        self.assertEqual(result["last_ts_ns"], packets[-1][0])

    def test_info_empty_capture(self):
        src = self.make_pcap([], name="empty.pcap")
        result = pcapchunk.info(src)
        self.assertEqual(result["packets"], 0)
        self.assertIsNone(result["first_ts_ns"])
        self.assertIsNone(result["last_ts_ns"])
        self.assertIsNone(result["duration_s"])


class IsoTsTest(unittest.TestCase):
    def test_iso_ts_utc_microseconds(self):
        self.assertEqual(pcapchunk.iso_ts(BASE_NS),
                         "2020-09-13T13:00:00.000000Z")
        self.assertEqual(pcapchunk.iso_ts(BASE_NS + 123_456_789),
                         "2020-09-13T13:00:00.123456Z")
        self.assertEqual(pcapchunk.iso_ts(BASE_NS + SEC),
                         "2020-09-13T13:00:01.000000Z")
        self.assertEqual(pcapchunk.iso_ts(BASE_NS + 1_000_000),
                         "2020-09-13T13:00:00.001000Z")

    def test_iso_ts_none(self):
        self.assertEqual(pcapchunk.iso_ts(None), "")


if __name__ == "__main__":
    unittest.main()
