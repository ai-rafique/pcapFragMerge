"""Split/merge: every rotation mode, both formats, compression, naming,
dry-run, resume, cancellation, and manifest compatibility."""

import datetime
import os
import unittest

import support
from support import TempDirTest, BASE_NS

import fixtures as fx
import pcapchunk

UTC = datetime.timezone.utc


def ts_at(h, m, s, ns=0):
    dt = datetime.datetime(2020, 9, 13, h, m, s, ns // 1000, tzinfo=UTC)
    return int(dt.timestamp()) * 1_000_000_000 + ns % 1000


def zstd_available():
    try:
        from compression import zstd  # noqa: F401
    except ImportError:
        return False
    return True


class ConstantsTest(unittest.TestCase):
    def test_module_constants(self):
        self.assertEqual(pcapchunk.__version__, "2.0.0")
        self.assertEqual(pcapchunk.APP_NAME, "PcapChunk")
        self.assertEqual(pcapchunk.MANIFEST, "manifest.json")
        self.assertEqual(pcapchunk.SUMS, "SHA256SUMS")
        self.assertEqual(pcapchunk.INCOMPLETE, ".pcapchunk-incomplete")
        self.assertEqual(pcapchunk.STAGING, ".pcapchunk-staging")
        self.assertEqual(pcapchunk.BUF, 1 << 20)
        self.assertEqual(pcapchunk.PROGRESS_EVERY, 1 << 20)
        self.assertTrue(issubclass(pcapchunk.PcapError, Exception))
        presets = dict(pcapchunk.PRESETS)
        self.assertEqual(presets["email"], 20 << 20)
        self.assertEqual(presets["upload"], 100 << 20)
        self.assertEqual(presets["fat32"], (4 << 30) - 1)
        self.assertEqual(presets["telegram"], 1900 << 20)
        self.assertEqual(presets["dvd"], 4_700_000_000)
        for value in presets.values():
            self.assertIsInstance(value, int)

    def test_filter_keys(self):
        self.assertEqual(tuple(pcapchunk.FILTER_KEYS),
                         ("host", "src", "dst", "port", "sport", "dport",
                          "proto"))


class SplitSummaryTest(TempDirTest):
    def _packets(self, n=10, payload_size=200):
        return fx.packet_stream(n, payload_size=payload_size)

    def test_split_returns_documented_summary(self):
        packets = self._packets()
        src = self.make_pcap(packets)
        outdir = self.path("out")
        summary = pcapchunk.split(src, outdir=outdir, size=1000)
        self.assertEqual(summary["input"], src)
        self.assertEqual(summary["outdir"], outdir)
        self.assertEqual(summary["format"], "pcap")
        self.assertEqual(summary["size"], os.path.getsize(src))
        self.assertEqual(summary["sha256"], fx.sha256_file(src))
        self.assertIsInstance(summary["chunks"], int)
        self.assertGreater(summary["chunks"], 1)
        self.assertEqual(summary["packets"], len(packets))
        chunks = pcapchunk.discover_chunks(outdir).chunks
        self.assertEqual(summary["bytes"], sum(c["bytes"] for c in chunks))
        self.assertIs(summary["dry_run"], False)
        self.assertIsNone(summary["plan"])
        self.assertIsNone(summary["index_csv"])

    def test_split_steps_generator_contract(self):
        src = self.make_pcap(self._packets(n=40, payload_size=1000))
        gen = self.split_steps(src, size=65536)
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
        dones = [d for d, _t in yields]
        self.assertEqual(dones, sorted(dones))
        self.assertIsInstance(result, dict)
        self.assertEqual(result["chunks"], len(self.chunk_names(
            result["outdir"])))

    def test_pcapng_summary_and_roundtrip(self):
        packets = self._packets()
        src = self.make_pcapng(packets)
        summary, result, folder = self.assert_roundtrip(src, size=1000)
        self.assertEqual(summary["format"], "pcapng")
        self.assertEqual(summary["packets"], len(packets))
        self.assertEqual(result["chunks"], summary["chunks"])
        self.assertGreaterEqual(result["chunks"], 1)


class RotationModesTest(TempDirTest):
    def _packets_at(self, offsets_s, payload_size=32):
        return [(BASE_NS + int(round(off * 1e9)),
                 fx.eth_ipv4_tcp(data=fx.payload(payload_size, i)))
                for i, off in enumerate(offsets_s)]

    def _merge_equal(self, src, summary):
        ext = os.path.splitext(src)[1]
        out = self.path("merged_mode" + ext)
        result = pcapchunk.merge(summary["outdir"], output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))
        return result

    def _chunk_counts(self, folder):
        return [c["packets"] for c in self.manifest(folder)["chunks"]]

    def test_size_mode_rotation(self):
        packets = fx.packet_stream(10, payload_size=200)
        src = self.make_pcap(packets)
        summary = self.split(src, size=1000)
        self.assertGreater(summary["chunks"], 1)
        self.assertEqual(sum(self._chunk_counts(summary["outdir"])),
                         len(packets))
        manifest = self.manifest(summary["outdir"])
        self.assertEqual(manifest["mode"]["kind"], "size")
        self.assertEqual(manifest["mode"]["value"], 1000)
        self.assertEqual(manifest["naming"], "index")
        self.assertIsNone(manifest["compression"])
        self.assert_valid_chunks(summary["outdir"], fmt="pcap")
        self._merge_equal(src, summary)

    def test_size_mode_oversized_single_packet(self):
        packets = [(BASE_NS, fx.eth_ipv4_tcp(data=b"x" * 4000)),
                   (BASE_NS + 1_000_000, fx.eth_ipv4_tcp(data=b"y" * 40))]
        src = self.make_pcap(packets)
        summary = self.split(src, size=512)
        self.assertGreaterEqual(summary["chunks"], 2)
        self._merge_equal(src, summary)

    def test_packets_mode_exact_count(self):
        packets = fx.packet_stream(12)
        src = self.make_pcap(packets)
        summary = self.split(src, packets=4)
        self.assertEqual(summary["chunks"], 3)
        self.assertEqual(self._chunk_counts(summary["outdir"]), [4, 4, 4])
        self._merge_equal(src, summary)

    def test_chunks_mode_exact_count(self):
        packets = fx.packet_stream(10)
        src = self.make_pcap(packets)
        summary = self.split(src, chunks=3)
        self.assertEqual(summary["chunks"], 3)
        self.assertEqual(sum(self._chunk_counts(summary["outdir"])),
                         len(packets))
        self._merge_equal(src, summary)

    def test_every_mode_epoch_aligned(self):
        packets = self._packets_at([0, 5, 10, 15, 20, 25])
        src = self.make_pcap(packets)
        summary = self.split(src, every=10)
        self.assertEqual(summary["chunks"], 3)
        self.assertEqual(self._chunk_counts(summary["outdir"]), [2, 2, 2])
        chunks = self.manifest(summary["outdir"])["chunks"]
        self.assertEqual(chunks[0]["first_ts_ns"], BASE_NS)
        self.assertEqual(chunks[0]["last_ts_ns"], BASE_NS + 5_000_000_000)
        self._merge_equal(src, summary)

    def test_gap_mode_rotation(self):
        packets = self._packets_at([0, 1, 2, 7, 8, 14])
        src = self.make_pcap(packets)
        summary = self.split(src, gap=5)
        self.assertEqual(self._chunk_counts(summary["outdir"]), [3, 2, 1])
        self._merge_equal(src, summary)

    def test_pcapng_rotation_modes_roundtrip(self):
        packets = [(BASE_NS + i * 1_000_000_000,
                    fx.eth_ipv4_tcp(data=bytes([i]))) for i in range(6)]
        cases = [
            ("packets", dict(packets=2)),
            ("every", dict(every=2)),
            ("gap", dict(gap=0.5)),
            ("split_at", dict(split_at=["13:00:02"])),
        ]
        for label, kw in cases:
            with self.subTest(mode=label):
                src = self.make_pcapng(packets, name="cap_%s.pcapng" % label)
                summary = self.split(src, outdir=self.path("ng_" + label),
                                     **kw)
                self.assertGreaterEqual(summary["chunks"], 2)
                merged = self.path("ng_%s_merged.pcapng" % label)
                pcapchunk.merge(summary["outdir"], output=merged)
                self.assertEqual(fx.sha256_file(src),
                                 fx.sha256_file(merged))

    def test_split_at_mode_utc(self):
        packets = [
            (ts_at(1, 59, 59), fx.eth_ipv4_tcp(data=b"a")),
            (ts_at(2, 0, 1), fx.eth_ipv4_tcp(data=b"b")),
            (ts_at(14, 30, 14), fx.eth_ipv4_tcp(data=b"c")),
            (ts_at(14, 30, 16), fx.eth_ipv4_tcp(data=b"d")),
        ]
        src = self.make_pcap(packets)
        summary = self.split(src, split_at=["02:00", "14:30:15"])
        self.assertEqual(self._chunk_counts(summary["outdir"]), [1, 2, 1])
        self._merge_equal(src, summary)

    def test_target_preset(self):
        packets = fx.packet_stream(4)
        src = self.make_pcap(packets)
        summary = self.split(src, target="email")
        self.assertEqual(summary["chunks"], 1)
        self._merge_equal(src, summary)

    def test_default_mode_is_50m(self):
        packets = fx.packet_stream(4)
        src = self.make_pcap(packets)
        summary = self.split(src)
        self.assertEqual(summary["chunks"], 1)
        self._merge_equal(src, summary)

    def test_index_csv_written(self):
        src = self.make_pcap(fx.packet_stream(9))
        csv = self.path("index.csv")
        summary = self.split(src, packets=3, index_csv=csv)
        self.assertEqual(summary["index_csv"], csv)
        self.assertTrue(os.path.isfile(csv))
        with open(csv, "r", encoding="utf-8") as f:
            rows = [ln for ln in f.read().splitlines() if ln.strip()]
        self.assertGreaterEqual(len(rows), summary["chunks"])

    def test_dry_run_creates_nothing(self):
        packets = fx.packet_stream(10)
        src = self.make_pcap(packets)
        outdir = self.path("dry_out")
        summary = pcapchunk.split(src, outdir=outdir, size=1000,
                                  dry_run=True)
        self.assertIs(summary["dry_run"], True)
        self.assertIsInstance(summary["plan"], list)
        self.assertTrue(summary["plan"])
        self.assertEqual(summary["chunks"], len(summary["plan"]))
        for entry in summary["plan"]:
            self.assertIn("file", entry)
            self.assertIn("bytes", entry)
            self.assertIn("packets", entry)
        if os.path.isdir(outdir):
            self.assertEqual(os.listdir(outdir), [])
        self.assertFalse(os.path.exists(
            os.path.join(outdir, pcapchunk.MANIFEST)))
        self.assertFalse(os.path.exists(
            os.path.join(outdir, pcapchunk.STAGING)))

    def test_mode_is_mutually_exclusive(self):
        src = self.make_pcap(fx.packet_stream(4))
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(src, outdir=self.path("bad"), size=1000,
                            packets=2)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(src, outdir=self.path("bad2"), target="email",
                            size=1000)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(src, outdir=self.path("bad3"), target="no-such")


class RoundTripVariantsTest(TempDirTest):
    def test_roundtrip_classic_variants(self):
        packets = fx.packet_stream(7)
        variants = {
            "le_usec": dict(endian="<", precision="usec"),
            "be_usec": dict(endian=">", precision="usec"),
            "le_nsec": dict(endian="<", precision="nsec"),
            "be_nsec": dict(endian=">", precision="nsec"),
            "kuz_le": dict(endian="<", kuznetzov=True),
            "kuz_be": dict(endian=">", kuznetzov=True),
            "lt_101": dict(linktype=101),
            "lt_228": dict(linktype=228),
        }
        for label, kw in variants.items():
            with self.subTest(label=label):
                src = self.write("cap_%s.pcap" % label,
                                 fx.pcap_bytes(packets, **kw))
                summary, _result, _folder = self.assert_roundtrip(
                    src, outdir=self.path("out_" + label), packets=3)
                self.assertEqual(summary["format"], "pcap")
                self.assert_valid_chunks(summary["outdir"], fmt="pcap")

    def test_roundtrip_pcapng_variants(self):
        packets = fx.packet_stream(7)
        cases = {
            "le": fx.default_pcapng(packets, endian="<"),
            "be": fx.default_pcapng(packets, endian=">"),
            "nsec": fx.default_pcapng(packets, tsresol=9),
        }
        for label, data in cases.items():
            with self.subTest(label=label):
                src = self.write("cap_%s.pcapng" % label, data)
                summary, _result, _folder = self.assert_roundtrip(
                    src, outdir=self.path("out_" + label), packets=3)
                self.assertEqual(summary["format"], "pcapng")
                self.assert_valid_chunks(summary["outdir"], fmt="pcapng")

    def test_roundtrip_multiple_sections(self):
        packets = fx.packet_stream(5)
        data = (fx.pcapng_section(
                    fx.interface_description(linktype=1, name="eth0",
                                             tsresol=6),
                    *[fx.enhanced_packet(0, ts, p) for ts, p in packets[:3]],
                    endian="<")
                + fx.pcapng_section(
                    fx.interface_description(linktype=101, name="raw0",
                                             tsresol=9, endian=">"),
                    *[fx.enhanced_packet(0, ts, fx.raw_ipv4_tcp(data=b"z"),
                                         endian=">", tsresol=9)
                      for ts, _p in packets[3:]],
                    endian=">"))
        src = self.write("multi_section.pcapng", data)
        summary, _result, _folder = self.assert_roundtrip(
            src, outdir=self.path("out_ms"), packets=2)
        self.assertGreaterEqual(summary["chunks"], 2)

    def test_roundtrip_midfile_interface(self):
        data = fx.pcapng_section(
            fx.interface_description(linktype=1, name="eth0"),
            fx.enhanced_packet(0, BASE_NS, fx.eth_ipv4_tcp(data=b"a")),
            fx.interface_description(linktype=101, name="raw0"),
            fx.enhanced_packet(1, BASE_NS + 1_000_000,
                               fx.raw_ipv4_tcp(data=b"b")),
            fx.enhanced_packet(0, BASE_NS + 2_000_000,
                               fx.eth_ipv4_udp(data=b"c")),
        )
        src = self.write("midfile.pcapng", data)
        self.assert_roundtrip(src, outdir=self.path("out_mid"), packets=1)

    def test_roundtrip_rich_pcapng_blocks(self):
        data = (fx.section_header(endian="<")
                + fx.interface_description(linktype=1, name="eth0")
                + fx.enhanced_packet(0, BASE_NS, fx.eth_ipv4_tcp(data=b"a"))
                + fx.name_resolution_block([(1, b"\x0a\x00\x00\x01")])
                + fx.unknown_block(0x00000BAD, b"opaque payload")
                + fx.simple_packet(b"simple packet data")
                + fx.enhanced_packet(0, BASE_NS + 1_000_000,
                                     fx.eth_ipv4_udp(data=b"b")))
        src = self.write("rich.pcapng", data)
        self.assert_roundtrip(src, outdir=self.path("out_rich"), packets=1)
        parsed = fx.parse_pcapng(self.read(src))
        self.assertEqual(len(parsed["packets"]), 3)

    def test_roundtrip_pcapng_padding_variety(self):
        data = fx.pcapng_section(
            fx.interface_description(linktype=1, name="eth0", tsresol=9,
                                     options=[(3, b"desc"), (4, b"12345"),
                                              (5, b"7")]),
            fx.enhanced_packet(0, BASE_NS, b"\x01", tsresol=9,
                               options=[(1, b"one byte option")]),
            fx.simple_packet(b"abc"),
            fx.unknown_block(0x00000BAD, b"x" * 5),
            fx.enhanced_packet(0, BASE_NS + 3, b"\x01\x02\x03",
                               tsresol=9),
        )
        src = self.write("padding.pcapng", data)
        self.assert_roundtrip(src, outdir=self.path("out_padding"),
                              packets=1)
        parsed = fx.parse_pcapng(self.read(src))
        self.assertEqual(len(parsed["packets"]), 3)
        self.assertEqual(parsed["sections"][0]["interfaces"][0]["name"],
                         "eth0")

    def test_roundtrip_compressed_pcapng(self):
        src = self.make_pcapng(fx.packet_stream(8, payload_size=64))
        summary = self.split(src, outdir=self.path("out_ng_gz"), packets=3,
                             compress="gzip")
        names = pcapchunk.discover_chunks(summary["outdir"]).names
        self.assertTrue(all(n.endswith(".pcapng.gz") for n in names), names)
        out = self.path("merged_ng_gz.pcapng")
        pcapchunk.merge(summary["outdir"], output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))

    def test_roundtrip_empty_capture(self):
        cases = {
            "empty.pcap": fx.pcap_bytes([]),
            "empty.pcapng": fx.pcapng_section(
                fx.interface_description(linktype=1)),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                src = self.write(name, data)
                self.assert_roundtrip(src, outdir=self.path("out_" + name))
                self.assert_valid_chunks(self.path("out_" + name))

    def test_roundtrip_zero_length_packets(self):
        packets = [(BASE_NS, b""), (BASE_NS + 1_000_000,
                                    fx.eth_ipv4_tcp(data=b"")),
                   (BASE_NS + 2_000_000, b"")]
        for fmt in ("pcap", "pcapng"):
            with self.subTest(fmt=fmt):
                src = self.make_capture(fmt=fmt, packets=packets)
                self.assert_roundtrip(src, outdir=self.path("out_zero_" + fmt),
                                      packets=1)
                parsed = fx.parse_capture(self.read(src))
                self.assertEqual(len(parsed["packets"]), 3)


class NamingTest(TempDirTest):
    def test_index_names(self):
        packets = fx.packet_stream(6)
        src = self.make_pcap(packets)
        summary = self.split(src, packets=2)
        names = self.chunk_names(summary["outdir"])
        self.assertEqual(names, ["cap_0001.pcap", "cap_0002.pcap",
                                 "cap_0003.pcap"])

    def test_time_names_use_utc_packet_range(self):
        packets = [(BASE_NS, fx.eth_ipv4_tcp(data=b"a")),
                   (BASE_NS + 1_000_000_000, fx.eth_ipv4_tcp(data=b"b")),
                   (BASE_NS + 2_000_000_000, fx.eth_ipv4_tcp(data=b"c")),
                   (BASE_NS + 3_000_000_000, fx.eth_ipv4_tcp(data=b"d"))]
        src = self.make_pcap(packets)
        summary = self.split(src, packets=2, name_style="time")
        manifest = self.manifest(summary["outdir"])
        self.assertEqual(manifest["naming"], "time")
        self.assertEqual(len(manifest["chunks"]), 2)
        for i, chunk in enumerate(manifest["chunks"], 1):
            expected = "cap_%s-%s_%04d.pcap" % (
                fx.utc_stamp(chunk["first_ts_ns"]),
                fx.utc_stamp(chunk["last_ts_ns"]), i)
            self.assertEqual(chunk["file"], expected)
        self.assertEqual(self.chunk_names(summary["outdir"]),
                         [c["file"] for c in manifest["chunks"]])
        # 2020-09-13T13:00:00Z .. 13:00:03Z
        self.assertEqual(manifest["chunks"][0]["file"],
                         "cap_20200913T130000-20200913T130001_0001.pcap")
        self.assertEqual(manifest["chunks"][1]["file"],
                         "cap_20200913T130002-20200913T130003_0002.pcap")

    def test_source_extension_is_kept(self):
        packets = fx.packet_stream(4)
        src = self.make_capture(fmt="pcapng", packets=packets)
        summary = self.split(src, packets=2)
        self.assertTrue(all(n.endswith(".pcapng")
                            for n in self.chunk_names(summary["outdir"])))

    def test_pcapng_time_names(self):
        packets = fx.packet_stream(4)
        src = self.make_capture(fmt="pcapng", packets=packets)
        summary = self.split(src, packets=2, name_style="time")
        manifest = self.manifest(summary["outdir"])
        self.assertEqual(manifest["naming"], "time")
        for chunk in manifest["chunks"]:
            self.assertRegex(chunk["file"],
                             r"^cap_\d{8}T\d{6}-\d{8}T\d{6}_\d{4}"
                             r"\.pcapng$")


class CompressionTest(TempDirTest):
    def test_gzip_chunks_roundtrip(self):
        packets = fx.packet_stream(10, payload_size=100)
        src = self.make_pcap(packets)
        summary = self.split(src, packets=3, compress="gzip")
        manifest = self.manifest(summary["outdir"])
        self.assertEqual(manifest["compression"], "gzip")
        names = self.chunk_names(summary["outdir"])
        self.assertTrue(names)
        for name in names:
            self.assertTrue(name.endswith(".pcap.gz"), name)
            raw = fx.gzip_read(self.read(os.path.join(summary["outdir"],
                                                      name)))
            self.assertEqual(fx.detect_magic(raw), "pcap")
        for chunk in manifest["chunks"]:
            on_disk = os.path.getsize(os.path.join(summary["outdir"],
                                                   chunk["file"]))
            self.assertEqual(chunk["bytes"], on_disk)
            raw = fx.gzip_read(self.read(os.path.join(summary["outdir"],
                                                      chunk["file"])))
            self.assertEqual(chunk["raw_bytes"], len(raw))
        out = self.path("merged_gz.pcap")
        pcapchunk.merge(summary["outdir"], output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))

    def test_zstd_chunks_conditional(self):
        packets = fx.packet_stream(8, payload_size=100)
        src = self.make_pcap(packets)
        if not zstd_available():
            with self.assertRaises(pcapchunk.PcapError):
                self.split(src, outdir=self.path("zstd_no"), packets=2,
                           compress="zstd")
            return
        from compression import zstd
        summary = self.split(src, outdir=self.path("zstd_yes"), packets=2,
                             compress="zstd")
        names = self.chunk_names(summary["outdir"])
        self.assertTrue(names)
        for name in names:
            self.assertTrue(name.endswith(".pcap.zst"), name)
            raw = zstd.decompress(self.read(os.path.join(summary["outdir"],
                                                         name)))
            self.assertEqual(fx.detect_magic(raw), "pcap")
        out = self.path("merged_zstd.pcap")
        pcapchunk.merge(summary["outdir"], output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))

    def test_invalid_compression_rejected(self):
        src = self.make_pcap(fx.packet_stream(4))
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(src, outdir=self.path("bad"), compress="brotli")


class ProgressAndCancelTest(TempDirTest):
    def _big_capture(self):
        packets = fx.packet_stream(400, payload_size=8000)
        return self.make_pcap(packets, name="big.pcap")

    def test_staging_visible_during_split(self):
        src = self._big_capture()
        outdir = self.path("marker_out")
        gen = pcapchunk.split_steps(src, outdir=outdir, packets=37)
        saw_staging = False
        try:
            for _ in range(50):
                try:
                    next(gen)
                except StopIteration:
                    break
                staging = os.path.join(outdir, pcapchunk.STAGING)
                if os.path.isdir(staging):
                    saw_staging = True
                    break
        finally:
            gen.close()
        self.assertTrue(saw_staging,
                        "staging folder never appeared during a split")

    def test_stale_incomplete_marker_cleaned_by_successful_split(self):
        src = self.make_pcap(fx.packet_stream(8))
        outdir = self.subdir("stale_out")
        fx.write(os.path.join(outdir, pcapchunk.INCOMPLETE), b"crashed\n")
        fx.write(os.path.join(outdir, "notes.txt"), b"keep")
        summary = self.split(src, outdir=outdir, packets=3)
        self.assertEqual(summary["chunks"], 3)
        self.assertFalse(os.path.exists(os.path.join(outdir,
                                                    pcapchunk.INCOMPLETE)))
        self.assertEqual(fx.read(os.path.join(outdir, "notes.txt")), b"keep")

    def test_successful_split_clears_marker(self):
        src = self.make_pcap(fx.packet_stream(8))
        summary = self.split(src, packets=3)
        outdir = summary["outdir"]
        self.assertFalse(os.path.exists(os.path.join(outdir,
                                                    pcapchunk.INCOMPLETE)))
        self.assertFalse(os.path.exists(os.path.join(outdir,
                                                    pcapchunk.STAGING)))
        self.assertEqual(self.manifest(outdir)["status"], "complete")

    def test_cancel_leaves_no_partial_output(self):
        src = self._big_capture()
        outdir = self.path("cancel_out")
        gen = pcapchunk.split_steps(src, outdir=outdir, packets=37)
        next(gen)
        try:
            for _ in range(3):
                next(gen)
        except StopIteration:
            pass
        gen.close()
        self.assertFalse(os.path.exists(os.path.join(outdir,
                                                    pcapchunk.STAGING)))
        self.assertFalse(os.path.exists(os.path.join(outdir,
                                                    pcapchunk.MANIFEST)))
        left = fx.list_files(outdir) if os.path.isdir(outdir) else []
        for name in left:
            self.assertFalse(name.endswith(".pcap"), name)
            self.assertFalse(name.endswith(".part"), name)

    def test_cancel_keeps_previous_set(self):
        first = self.make_pcap(fx.packet_stream(6), name="first.pcap")
        outdir = self.path("prev_out")
        self.split(first, outdir=outdir, packets=2)
        before = {n: fx.sha256_file(os.path.join(outdir, n))
                  for n in self.chunk_names(outdir)}
        before_manifest = fx.sha256_file(os.path.join(outdir,
                                                      pcapchunk.MANIFEST))
        # Same source stem, new (bigger) content in the same file.
        fx.write(first, fx.pcap_bytes(fx.packet_stream(
            400, payload_size=8000)))
        gen = pcapchunk.split_steps(first, outdir=outdir, packets=37,
                                    force=True)
        next(gen)
        gen.close()
        for name, digest in before.items():
            self.assertEqual(fx.sha256_file(os.path.join(outdir, name)),
                             digest)
        self.assertEqual(fx.sha256_file(os.path.join(outdir,
                                                     pcapchunk.MANIFEST)),
                         before_manifest)
        self.assertTrue(pcapchunk.verify(outdir)["ok"])

    def test_cancel_with_resume_keeps_staging(self):
        # Contract update: resume=True keeps staging so the job can continue.
        src = self._big_capture()
        outdir = self.path("resume_cancel_out")
        gen = pcapchunk.split_steps(src, outdir=outdir, packets=37,
                                    resume=True)
        next(gen)
        try:
            next(gen)
        except StopIteration:
            pass
        gen.close()
        self.assertTrue(os.path.isdir(os.path.join(outdir,
                                                   pcapchunk.STAGING)))
        summary = self.split(src, outdir=outdir, packets=37, resume=True)
        self.assertGreaterEqual(summary["chunks"], 2)
        out = self.path("merged_resume_cancel.pcap")
        pcapchunk.merge(outdir, output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))

    def test_resume_without_staging_does_normal_split(self):
        packets = fx.packet_stream(10)
        src = self.make_pcap(packets)
        summary = self.split(src, packets=3, resume=True)
        self.assertEqual(summary["chunks"], 4)
        out = self.path("merged_resume.pcap")
        pcapchunk.merge(summary["outdir"], output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))

    def test_resume_ignores_unusable_staging(self):
        packets = fx.packet_stream(8)
        src = self.make_pcap(packets)
        outdir = self.path("resume_junk")
        os.makedirs(os.path.join(outdir, pcapchunk.STAGING))
        fx.write(os.path.join(outdir, pcapchunk.STAGING, "junk.bin"), b"junk")
        summary = self.split(src, outdir=outdir, packets=3, resume=True)
        self.assertEqual(summary["chunks"], 3)
        out = self.path("merged_resume_junk.pcap")
        pcapchunk.merge(outdir, output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))


class ManifestCompatTest(TempDirTest):
    def _split_set(self, n=9, packets_per_chunk=3):
        packets = fx.packet_stream(n)
        src = self.make_pcap(packets)
        summary = self.split(src, packets=packets_per_chunk)
        return src, summary

    def test_schema2_manifest_fields(self):
        src, summary = self._split_set()
        m = self.manifest(summary["outdir"])
        self.assertEqual(m["schema"], 2)
        self.assertEqual(m["tool"], "PcapChunk")
        self.assertEqual(m["version"], "2.0.0")
        self.assertIsInstance(m["created"], str)
        self.assertEqual(m["status"], "complete")
        self.assertEqual(m["source"], "cap.pcap")
        self.assertEqual(m["format"], "pcap")
        self.assertIsNone(m["compressed"])
        self.assertEqual(m["size"], os.path.getsize(src))
        self.assertEqual(m["hash"], "sha256")
        self.assertEqual(m["sha256"], fx.sha256_file(src))
        self.assertIn("kind", m["mode"])
        self.assertEqual(m["naming"], "index")
        self.assertIsNone(m["compression"])
        cap = m["capture"]
        self.assertEqual(cap["linktype"], 1)
        self.assertEqual(cap["snaplen"], 65535)
        self.assertEqual(cap["precision"], "usec")
        self.assertEqual(cap["packets"], 9)
        self.assertEqual(cap["first_ts_ns"], BASE_NS)
        self.assertEqual(cap["last_ts_ns"], BASE_NS + 8_000_000)
        self.assertEqual(len(m["chunks"]), 3)
        offset = 0
        for i, chunk in enumerate(m["chunks"], 1):
            self.assertEqual(chunk["index"], i)
            self.assertEqual(chunk["file"], "cap_%04d.pcap" % i)
            self.assertEqual(chunk["packets"], 3)
            self.assertEqual(chunk["offset"], offset)
            self.assertIn("bytes", chunk)
            self.assertIn("raw_bytes", chunk)
            self.assertEqual(len(chunk["sha256"]), 64)
            self.assertEqual(chunk["first_packet"], 3 * (i - 1))
            self.assertEqual(chunk["last_packet"], 3 * i - 1)
            offset += chunk["bytes"]

    def test_sha256sums_file(self):
        src, summary = self._split_set()
        folder = summary["outdir"]
        path = os.path.join(folder, pcapchunk.SUMS)
        self.assertTrue(os.path.isfile(path))
        with open(path, "r", encoding="utf-8", newline="") as f:
            raw = f.read()
        self.assertNotIn("\r\n", raw)
        lines = [ln for ln in raw.split("\n") if ln]
        entries = []
        for line in lines:
            digest, name = line.split("  ", 1)
            self.assertEqual(len(digest), 64)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            entries.append((name, digest))
        names = [name for name, _d in entries]
        self.assertEqual(names, sorted(names))
        self.assertIn(pcapchunk.MANIFEST, names)
        for chunk in self.manifest(folder)["chunks"]:
            self.assertIn(chunk["file"], names)
        for name, digest in entries:
            self.assertEqual(fx.sha256_file(os.path.join(folder, name)),
                             digest)

    def test_merge_manifest_less(self):
        src, summary = self._split_set()
        folder = summary["outdir"]
        os.remove(os.path.join(folder, pcapchunk.MANIFEST))
        sums = os.path.join(folder, pcapchunk.SUMS)
        if os.path.exists(sums):
            os.remove(sums)
        out = self.path("merged_manifestless.pcap")
        result = pcapchunk.merge(folder, output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))
        self.assertIsNone(result["schema"])
        self.assertTrue(result["complete"])
        self.assertIsNone(result["verified"])
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["chunks"], 3)

    def test_merge_v1_manifest(self):
        src, summary = self._split_set()
        folder = summary["outdir"]
        chunks = self.manifest(folder)["chunks"]
        v1 = {
            "source": "cap.pcap",
            "format": "pcap",
            "size": os.path.getsize(src),
            "sha256": fx.sha256_file(src),
            "chunks": [{"file": c["file"], "bytes": c["bytes"],
                        "packets": c["packets"]} for c in chunks],
        }
        self.write_manifest(folder, v1)
        out = self.path("merged_v1.pcap")
        result = pcapchunk.merge(folder, output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))
        self.assertEqual(result["schema"], 1)
        self.assertTrue(result["verified"])
        self.assertTrue(result["complete"])

    def test_merge_allow_missing(self):
        src, summary = self._split_set()
        folder = summary["outdir"]
        missing = self.manifest(folder)["chunks"][1]["file"]
        os.remove(os.path.join(folder, missing))
        out = self.path("merged_missing.pcap")
        result = pcapchunk.merge(folder, output=out, allow_missing=True)
        self.assertFalse(result["complete"])
        self.assertIn(missing, result["missing"])
        self.assertIn(result["verified"], (False, None))
        self.assertEqual(result["chunks"], 2)
        self.assertTrue(os.path.isfile(out))
        out2 = self.path("merged_missing_strict.pcap")
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.merge(folder, output=out2)

    def test_merge_force_overwrite(self):
        src, summary = self._split_set()
        out = self.path("merged_twice.pcap")
        pcapchunk.merge(summary["outdir"], output=out)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.merge(summary["outdir"], output=out)
        result = pcapchunk.merge(summary["outdir"], output=out, force=True)
        self.assertTrue(result["verified"])
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))

    def test_merge_no_verify(self):
        src, summary = self._split_set()
        out = self.path("merged_noverify.pcap")
        result = pcapchunk.merge(summary["outdir"], output=out, verify=False)
        self.assertIsNone(result["verified"])
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))

    def test_merge_steps_generator(self):
        src, summary = self._split_set()
        out = self.path("merged_steps.pcap")
        gen = pcapchunk.merge_steps(summary["outdir"], output=out)
        yields = list(gen)
        self.assertTrue(yields)
        for done, total in yields:
            self.assertIsInstance(done, int)
            self.assertIsInstance(total, int)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))


class DiscoverTest(TempDirTest):
    def test_discover_schema2_chunk_set(self):
        src = self.make_pcap(fx.packet_stream(6))
        summary = self.split(src, packets=2)
        cs = pcapchunk.discover_chunks(summary["outdir"])
        self.assertIsInstance(cs, tuple)  # ChunkSet is a NamedTuple
        self.assertEqual(cs.folder, summary["outdir"])
        self.assertEqual(cs.names, ["cap_0001.pcap", "cap_0002.pcap",
                                    "cap_0003.pcap"])
        self.assertEqual(cs.merged_name, "cap.pcap")
        self.assertEqual(cs.sha256, fx.sha256_file(src))
        self.assertEqual(cs.manifest["schema"], 2)
        self.assertEqual(len(cs.chunks), 3)
        for chunk in cs.chunks:
            self.assertIn("file", chunk)
            self.assertIn("bytes", chunk)
            self.assertIn("packets", chunk)

    def test_discover_manifestless(self):
        src = self.make_pcap(fx.packet_stream(6))
        summary = self.split(src, packets=2)
        folder = summary["outdir"]
        os.remove(os.path.join(folder, pcapchunk.MANIFEST))
        cs = pcapchunk.discover_chunks(folder)
        self.assertIsNone(cs.manifest)
        self.assertIsNone(cs.sha256)
        self.assertEqual(len(cs.names), 3)
        self.assertEqual(cs.merged_name, "cap.pcap")

    def test_discover_missing_chunk_visible_to_verify(self):
        # A chunk file listed in the manifest but absent from disk must be
        # surfaced by verify()/merge(), not silently dropped.
        src = self.make_pcap(fx.packet_stream(6))
        summary = self.split(src, packets=2)
        os.remove(os.path.join(summary["outdir"], "cap_0002.pcap"))
        result = pcapchunk.verify(summary["outdir"])
        self.assertFalse(result["ok"])
        self.assertIn("cap_0002.pcap", result["missing"])
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.merge(summary["outdir"], output=self.path("x.pcap"))

    def test_discover_empty_folder_raises(self):
        empty = self.subdir("nothing_here")
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.discover_chunks(empty)

    def test_default_outdir(self):
        src = self.make_pcap(fx.packet_stream(2))
        expected = os.path.join(os.path.dirname(os.path.abspath(src)),
                                "cap_chunks")
        self.assertEqual(pcapchunk.default_outdir(src), expected)

    def test_default_merge_output(self):
        src = self.make_pcap(fx.packet_stream(6))
        summary = self.split(src, packets=2)
        self.assertEqual(pcapchunk.default_merge_output(summary["outdir"]),
                         os.path.join(summary["outdir"], "cap.pcap"))

    def test_existing_chunk_files(self):
        src = self.make_pcap(fx.packet_stream(6))
        summary = self.split(src, packets=2)
        folder = summary["outdir"]
        fx.write(os.path.join(folder, "notes.txt"), b"keep me")
        fx.write(os.path.join(folder, "other_0001.pcap"), b"unrelated")
        found = pcapchunk.existing_chunk_files(folder)
        for name in ("cap_0001.pcap", "cap_0002.pcap", "cap_0003.pcap"):
            self.assertIn(name, found)
        self.assertNotIn("notes.txt", found)
        own = set(pcapchunk.existing_chunk_files(folder, stem="cap",
                                                 ext=".pcap"))
        self.assertTrue({"cap_0001.pcap", "cap_0002.pcap",
                         "cap_0003.pcap"} <= own)
        # A file for a different split's stem is not "this split's own".
        other = pcapchunk.existing_chunk_files(folder, stem="nomatch",
                                              ext=".pcap")
        self.assertNotIn("other_0001.pcap", other)
        self.assertNotIn("notes.txt", other)

    def test_chunk_matches_name_style(self):
        self.assertTrue(pcapchunk.chunk_matches_name_style("cap_0001.pcap"))
        self.assertTrue(pcapchunk.chunk_matches_name_style(
            "cap_20200913T130000-20200913T130002_0001.pcap"))
        self.assertTrue(pcapchunk.chunk_matches_name_style(
            "cap_0001.pcap.gz"))
        self.assertFalse(pcapchunk.chunk_matches_name_style("cap.pcap"))
        self.assertFalse(pcapchunk.chunk_matches_name_style("notes.txt"))
        self.assertFalse(pcapchunk.chunk_matches_name_style(
            "cap_20200913T130000-20200913T130002_0001"))


if __name__ == "__main__":
    unittest.main()
