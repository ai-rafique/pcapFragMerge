"""Robustness: hostile inputs, truncated tails, salvage mode."""

import os
import unittest

from support import TempDirTest, BASE_NS

import fixtures as fx
import pcapchunk

SEC = 1_000_000_000


class BadInputTest(TempDirTest):
    def _assert_rejected_by_inspection(self, path):
        for name, fn in (
                ("describe", pcapchunk.describe),
                ("info", pcapchunk.info),
                ("open_capture", pcapchunk.open_capture),
        ):
            with self.subTest(fn=name):
                with self.assertRaises(pcapchunk.PcapError):
                    fn(path)

    def test_empty_file(self):
        path = self.write("empty.pcap", b"")
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.detect_format(path)
        self._assert_rejected_by_inspection(path)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(path, outdir=self.path("out"))

    def test_garbage_file(self):
        path = self.write("garbage.pcap", b"NOT A CAPTURE" * 100)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.detect_format(path)
        self._assert_rejected_by_inspection(path)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(path, outdir=self.path("out"))

    def test_gzip_of_garbage(self):
        path = self.write("garbage.pcap.gz",
                          fx.gzip_bytes(b"still not a capture"))
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.detect_format(path)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.describe(path)

    def test_truncated_gzip_stream(self):
        raw = fx.pcap_bytes(fx.packet_stream(5))
        gz = fx.gzip_bytes(raw)[:20]
        path = self.write("broken.pcap.gz", gz)
        # Magic sniffing may succeed (the header bytes decompress fine); any
        # full read must fail with a PcapError or an OSError (contract §10).
        try:
            pcapchunk.detect_format(path)
        except (pcapchunk.PcapError, OSError):
            pass
        for fn in (pcapchunk.describe, pcapchunk.info):
            with self.assertRaises((pcapchunk.PcapError, OSError)):
                fn(path)

    def test_truncated_pcap_global_header(self):
        path = self.write("short.pcap", fx.pcap_global_header()[:10])
        for fn in (pcapchunk.describe, pcapchunk.info):
            with self.assertRaises(pcapchunk.PcapError):
                fn(path)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(path, outdir=self.path("short_out"))

    def test_corrupt_pcapng_block_length(self):
        import struct
        data = (fx.section_header(endian="<")
                + fx.interface_description(endian="<")
                + struct.pack("<II", fx.EPB, 7) + b"\x00\x00\x00")
        path = self.write("corrupt.pcapng", data)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(path, outdir=self.path("out"))
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.info(path)

    def test_pcapng_invalid_byte_order_magic(self):
        data = bytearray(fx.section_header(endian="<"))
        data[8:12] = b"\x00\x00\x00\x00"
        path = self.write("bad_bom.pcapng", bytes(data))
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(path, outdir=self.path("out"))


class TruncatedTailTest(TempDirTest):
    def _roundtrip_bytes(self, src, data, **split_kw):
        summary = self.split(src, **split_kw)
        out = self.path("merged_truncated" +
                        os.path.splitext(src)[1])
        pcapchunk.merge(summary["outdir"], output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))

    def test_truncated_pcap_record_preserved(self):
        data = fx.pcap_bytes(fx.packet_stream(6, payload_size=100))
        data = data[:-20]
        src = self.write("truncated.pcap", data)
        self._roundtrip_bytes(src, data, packets=2)

    def test_truncated_pcapng_block_preserved(self):
        data = fx.default_pcapng(fx.packet_stream(5, payload_size=100))
        data = data[:-6]
        src = self.write("truncated.pcapng", data)
        self._roundtrip_bytes(src, data, packets=2)

    def test_truncated_pcapng_mid_block_preserved(self):
        data = fx.default_pcapng(fx.packet_stream(5, payload_size=73))
        # Cut in the middle of the last EPB's payload.
        data = data[:len(data) - 40]
        src = self.write("midcut.pcapng", data)
        self._roundtrip_bytes(src, data, packets=2)

    def test_pcap_ends_inside_record_header(self):
        data = fx.pcap_bytes(fx.packet_stream(4, payload_size=50))
        data = data[:-41]  # leaves a partial 16-byte record header
        src = self.write("header_cut.pcap", data)
        self._roundtrip_bytes(src, data, packets=2)


class SalvageTest(TempDirTest):
    def test_merge_without_salvage_rejects_truncated_chunk(self):
        src = self.make_pcap(fx.packet_stream(9), name="cap.pcap")
        summary = self.split(src, packets=3)
        folder = summary["outdir"]
        names = self.chunk_names(folder)
        last = os.path.join(folder, names[-1])
        data = fx.read(last)
        fx.write(last, data[:-12])
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.merge(folder, output=self.path("noselect.pcap"))

    def test_merge_salvage_tolerates_truncated_final_chunk(self):
        src = self.make_pcap(fx.packet_stream(9), name="cap.pcap")
        summary = self.split(src, packets=3)
        folder = summary["outdir"]
        names = self.chunk_names(folder)
        last = os.path.join(folder, names[-1])
        data = fx.read(last)
        fx.write(last, data[:-12])
        out = self.path("salvaged.pcap")
        result = pcapchunk.merge(folder, output=out, salvage=True)
        self.assertTrue(os.path.isfile(out))
        self.assertGreater(result["size"], 0)

    def test_merge_corrupted_chunk_rejected(self):
        src = self.make_pcap(fx.packet_stream(9), name="cap.pcap")
        summary = self.split(src, packets=3)
        folder = summary["outdir"]
        first = os.path.join(folder, self.chunk_names(folder)[0])
        data = bytearray(fx.read(first))
        data[-1] ^= 0xFF
        fx.write(first, bytes(data))
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.merge(folder, output=self.path("corrupt_merge.pcap"))

    def test_split_salvage_kwarg_accepted(self):
        data = fx.pcap_bytes(fx.packet_stream(6))
        src = self.write("trunc.pcap", data[:-10])
        summary = self.split(src, packets=2, salvage=True)
        self.assertGreaterEqual(summary["chunks"], 1)

    def test_split_max_record_guards_huge_claim(self):
        data = (fx.pcap_global_header()
                + fx.pcap_record(BASE_NS, b"", declared_len=0xFFFFFFF0))
        src = self.write("huge.pcap", data)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(src, outdir=self.path("out"), max_record=1 << 20)


class ZeroLengthPacketTest(TempDirTest):
    def test_zero_length_records_are_counted_and_roundtrip(self):
        packets = [(BASE_NS + i * SEC, b"") for i in range(3)]
        src = self.make_pcap(packets)
        info = pcapchunk.info(src)
        self.assertEqual(info["packets"], 3)
        self.assertEqual(info["bytes"], 0)
        summary = self.split(src, packets=1)
        self.assertEqual(summary["packets"], 3)
        out = self.path("zero_merged.pcap")
        pcapchunk.merge(summary["outdir"], output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))

    def test_eth_packet_with_empty_payload_filtered_out(self):
        packets = [(BASE_NS, fx.eth_ipv4_tcp(data=b""))]
        src = self.make_pcap(packets)
        out = self.path("empty_payload.pcap")
        result = pcapchunk.trim(src, out, filter_spec={"port": 80})
        self.assertEqual(result["packets"], 1)


if __name__ == "__main__":
    unittest.main()
