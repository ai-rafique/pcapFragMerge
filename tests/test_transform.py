"""Transformations: trim, convert, combine, demux, filtering."""

import os
import unittest

from support import TempDirTest, BASE_NS

import fixtures as fx
import pcapchunk

SEC = 1_000_000_000


def flows_packets():
    return [
        (BASE_NS + 0 * SEC,
         fx.eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1234, 80, b"a")),
        (BASE_NS + 1 * SEC,
         fx.eth_ipv4_tcp("10.0.0.2", "10.0.0.1", 80, 1234, b"b")),
        (BASE_NS + 2 * SEC,
         fx.eth_ipv4_tcp("10.0.0.7", "10.0.0.8", 2222, 443, b"c")),
        (BASE_NS + 3 * SEC,
         fx.eth_ipv4_udp("10.0.0.3", "10.0.0.4", 5353, 53, b"d")),
        (BASE_NS + 4 * SEC,
         fx.eth_ipv4_icmp("10.0.0.5", "10.0.0.6", b"e")),
    ]


def no_part_files(root):
    return [n for n in fx.list_files(root) if n.endswith(".part")]


class TrimTest(TempDirTest):
    def _capture(self, n=6):
        packets = [(BASE_NS + i * SEC, fx.eth_ipv4_tcp(data=bytes([i])))
                   for i in range(n)]
        return self.make_pcap(packets), packets

    def test_trim_by_time_range(self):
        src, _packets = self._capture()
        out = self.path("trimmed.pcap")
        result = pcapchunk.trim(src, out, from_ts=BASE_NS // SEC + 1,
                                to_ts=BASE_NS // SEC + 3)
        self.assertEqual(result["input"], src)
        self.assertEqual(result["output"], out)
        self.assertEqual(result["format"], "pcap")
        self.assertEqual(result["packets"], 2)
        self.assertIsInstance(result["filtered"], bool)
        self.assertEqual(result["size"], os.path.getsize(out))
        self.assertEqual(self.read_ts(out),
                         [BASE_NS + SEC, BASE_NS + 2 * SEC])
        self.assertEqual(no_part_files(self.dir), [])

    def test_trim_iso_time_strings(self):
        src, _packets = self._capture()
        out = self.path("trimmed_iso.pcap")
        result = pcapchunk.trim(
            src, out,
            from_ts="2020-09-13T13:00:01+00:00",
            to_ts="2020-09-13T13:00:03Z")
        self.assertEqual(result["packets"], 2)
        self.assertEqual(self.read_ts(out),
                         [BASE_NS + SEC, BASE_NS + 2 * SEC])

    def test_trim_first_and_last(self):
        src, _packets = self._capture()
        out_first = self.path("first2.pcap")
        r1 = pcapchunk.trim(src, out_first, first=2)
        self.assertEqual(r1["packets"], 2)
        self.assertEqual(self.read_ts(out_first),
                         [BASE_NS, BASE_NS + SEC])
        out_last = self.path("last2.pcap")
        r2 = pcapchunk.trim(src, out_last, last=2)
        self.assertEqual(r2["packets"], 2)
        self.assertEqual(self.read_ts(out_last),
                         [BASE_NS + 4 * SEC, BASE_NS + 5 * SEC])

    def test_trim_filter_counts(self):
        src = self.make_pcap(flows_packets())
        cases = [
            ({"host": "10.0.0.2"}, 2),
            ({"src": "10.0.0.1"}, 1),
            ({"dst": "10.0.0.8"}, 1),
            ({"port": 80}, 2),
            ({"sport": 1234}, 1),
            ({"dport": 53}, 1),
            ({"proto": "tcp"}, 3),
            ({"proto": "udp"}, 1),
            ({"proto": 1}, 1),
            ({"proto": "tcp", "port": 80}, 2),
            ({"host": ["10.0.0.2", "10.0.0.5"]}, 3),
        ]
        for i, (filt, expected) in enumerate(cases):
            with self.subTest(filt=filt):
                out = self.path("filtered_%d.pcap" % i)
                result = pcapchunk.trim(src, out, filter_spec=filt)
                self.assertEqual(result["packets"], expected, filt)
                self.assertIs(result["filtered"], True)
                self.assertEqual(fx.packet_count(self.read(out)), expected)

    def test_filter_never_matches_undecodable(self):
        packets = [(BASE_NS + i * SEC, b"\xde\xad\xbe\xef" + bytes([i]))
                   for i in range(3)]
        src = self.make_pcap(packets, linktype=147)
        out = self.path("undecodable.pcap")
        result = pcapchunk.trim(src, out, filter_spec={"host": "10.0.0.1"})
        self.assertEqual(result["packets"], 0)
        self.assertIs(result["filtered"], True)

    def test_trim_output_format_and_precision(self):
        src, _packets = self._capture()
        out_ng = self.path("trimmed.pcapng")
        pcapchunk.trim(src, out_ng, out_format="pcapng")
        self.assertEqual(fx.detect_magic(self.read(out_ng)), "pcapng")
        out_nsec = self.path("trimmed_nsec.pcap")
        pcapchunk.trim(src, out_nsec, precision="nsec")
        parsed = fx.parse_pcap(self.read(out_nsec))
        self.assertEqual(parsed["precision"], "nsec")
        self.assertEqual(pcapchunk.describe(out_nsec)["precision"], "nsec")

    def test_trim_replaces_existing_output(self):
        src, _packets = self._capture()
        out = self.path("trimmed.pcap")
        fx.write(out, b"stale output")
        pcapchunk.trim(src, out, first=3)
        self.assertEqual(fx.packet_count(self.read(out)), 3)
        self.assertEqual(no_part_files(self.dir), [])

    def test_trim_salvage_kwarg_accepted(self):
        src, _packets = self._capture()
        out = self.path("trimmed_salvage.pcap")
        result = pcapchunk.trim(src, out, salvage=True)
        self.assertEqual(result["packets"], 6)

    def test_trim_cancel_is_safe_at_yield_points(self):
        packets = fx.packet_stream(300, payload_size=8000)
        src = self.make_pcap(packets, name="big.pcap")
        out = self.path("cancelled.pcap")
        gen = pcapchunk.trim_steps(src, out)
        yielded = False
        try:
            next(gen)
            yielded = True
        except StopIteration:
            pass
        gen.close()
        self.assertTrue(yielded)
        self.assertEqual(no_part_files(self.dir), [])
        # Whatever was produced must be complete, never a partial file.
        if os.path.exists(out):
            self.assertEqual(fx.packet_count(self.read(out)), len(packets))


class ConvertTest(TempDirTest):
    def test_convert_pcap_to_pcapng(self):
        packets = flows_packets()
        src = self.make_pcap(packets)
        out = self.path("converted.pcapng")
        result = pcapchunk.convert(src, out, out_format="pcapng")
        self.assertEqual(result["format"], "pcapng")
        self.assertEqual(result["packets"], len(packets))
        self.assertEqual(fx.detect_magic(self.read(out)), "pcapng")
        info = pcapchunk.describe(out)
        self.assertEqual(len(info["interfaces"]), 1)
        self.assertEqual(info["interfaces"][0]["linktype"], 1)
        self.assertEqual([p["data"] for p in self.read_packets(out)],
                         [p for _ts, p in packets])
        self.assertEqual(self.read_ts(out), [ts for ts, _p in packets])

    def test_convert_pcapng_to_pcap(self):
        packets = flows_packets()
        src = self.make_pcapng(packets)
        out = self.path("converted.pcap")
        result = pcapchunk.convert(src, out, out_format="pcap")
        self.assertEqual(result["format"], "pcap")
        self.assertEqual(fx.detect_magic(self.read(out)), "pcap")
        parsed = fx.parse_pcap(self.read(out))
        self.assertEqual(parsed["precision"], "usec")
        self.assertEqual(len(parsed["packets"]), len(packets))

    def test_convert_pcapng_to_pcap_nsec(self):
        packets = [(BASE_NS + i * 123_456_789, fx.eth_ipv4_tcp(data=b"x"))
                   for i in range(4)]
        src = self.make_pcapng(packets, tsresol=9)
        out = self.path("converted_nsec.pcap")
        pcapchunk.convert(src, out, out_format="pcap", precision="nsec")
        parsed = fx.parse_pcap(self.read(out))
        self.assertEqual(parsed["precision"], "nsec")
        self.assertEqual([p["ts_ns"] for p in parsed["packets"]],
                         [ts for ts, _p in packets])

    def test_convert_pcap_nsec_to_pcapng_keeps_resolution(self):
        packets = [(BASE_NS + i, fx.eth_ipv4_tcp(data=b"x"))
                   for i in range(3)]
        src = self.make_pcap(packets, precision="nsec")
        out = self.path("converted_nsec.pcapng")
        pcapchunk.convert(src, out, out_format="pcapng")
        info = pcapchunk.describe(out)
        self.assertEqual(info["interfaces"][0]["tsresol"], 9)
        self.assertEqual(pcapchunk.info(out)["first_ts_ns"], packets[0][0])
        self.assertEqual(self.read_ts(out), [ts for ts, _p in packets])

    def test_convert_mixed_linktypes_to_pcap_raises(self):
        data = (fx.section_header(endian="<")
                + fx.interface_description(linktype=1, endian="<")
                + fx.enhanced_packet(0, BASE_NS, fx.eth_ipv4_tcp(data=b"a"),
                                     endian="<")
                + fx.interface_description(linktype=101, endian="<")
                + fx.enhanced_packet(1, BASE_NS + 1, fx.raw_ipv4_tcp(data=b"b"),
                                     endian="<"))
        src = self.write("mixed.pcapng", data)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.convert(src, self.path("out.pcap"), out_format="pcap")

    def test_convert_salvage_kwarg_accepted(self):
        src = self.make_pcap(fx.packet_stream(4))
        out = self.path("converted_salvage.pcapng")
        result = pcapchunk.convert(src, out, salvage=True)
        self.assertEqual(result["packets"], 4)

    def test_convert_cancel_is_safe_at_yield_points(self):
        src = self.make_pcap(fx.packet_stream(300, payload_size=8000),
                             name="big.pcap")
        out = self.path("cancel_convert.pcapng")
        gen = pcapchunk.convert_steps(src, out)
        yielded = False
        try:
            next(gen)
            yielded = True
        except StopIteration:
            pass
        gen.close()
        self.assertTrue(yielded)
        self.assertEqual(no_part_files(self.dir), [])
        if os.path.exists(out):
            self.assertEqual(fx.packet_count(self.read(out)), 300)


class CombineTest(TempDirTest):
    def _two(self):
        a = self.make_pcap([(BASE_NS, fx.eth_ipv4_tcp(data=b"a")),
                            (BASE_NS + 2 * SEC, fx.eth_ipv4_tcp(data=b"c"))],
                           name="a.pcap")
        b = self.make_pcap([(BASE_NS + SEC, fx.eth_ipv4_tcp(data=b"b")),
                            (BASE_NS + 3 * SEC, fx.eth_ipv4_tcp(data=b"d"))],
                           name="b.pcap")
        return a, b

    def test_combine_default_pcap(self):
        a, b = self._two()
        out = self.path("combined.pcap")
        result = pcapchunk.combine([a, b], out)
        self.assertEqual(result["format"], "pcap")
        self.assertEqual(result["inputs"], [a, b])
        self.assertEqual(result["packets"], 4)
        self.assertEqual(fx.detect_magic(self.read(out)), "pcap")
        self.assertEqual(self.read_ts(out),
                         [BASE_NS, BASE_NS + 2 * SEC, BASE_NS + SEC,
                          BASE_NS + 3 * SEC])
        self.assertEqual(no_part_files(self.dir), [])

    def test_combine_sort(self):
        a, b = self._two()
        out = self.path("sorted.pcap")
        result = pcapchunk.combine([a, b], out, sort=True)
        self.assertEqual(result["packets"], 4)
        self.assertEqual(self.read_ts(out),
                         [BASE_NS + i * SEC for i in range(4)])

    def test_combine_sort_rejects_non_monotonic_input(self):
        bad = self.make_pcap([(BASE_NS, fx.eth_ipv4_tcp(data=b"a")),
                              (BASE_NS + 5 * SEC, fx.eth_ipv4_tcp(data=b"b")),
                              (BASE_NS + 2 * SEC, fx.eth_ipv4_tcp(data=b"c"))],
                             name="bad.pcap")
        good = self.make_pcap([(BASE_NS + SEC, fx.eth_ipv4_tcp(data=b"d"))],
                              name="good.pcap")
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.combine([bad, good], self.path("sorted.pcap"),
                              sort=True)

    def test_combine_adjacent_dedupe(self):
        shared = fx.eth_ipv4_tcp(data=b"shared")
        a = self.make_pcap([(BASE_NS, fx.eth_ipv4_tcp(data=b"a")),
                            (BASE_NS + SEC, shared)], name="a.pcap")
        b = self.make_pcap([(BASE_NS + SEC, shared),
                            (BASE_NS + 2 * SEC, fx.eth_ipv4_tcp(data=b"b"))],
                           name="b.pcap")
        out = self.path("deduped.pcap")
        result = pcapchunk.combine([a, b], out, dedupe=True)
        self.assertEqual(result["packets"], 3)
        self.assertEqual(self.read_payloads(out).count(shared), 1)

    def test_combine_sorted_dedupe_cross_capture(self):
        shared = fx.eth_ipv4_tcp(data=b"shared")
        a = self.make_pcap([(BASE_NS, shared),
                            (BASE_NS + 2 * SEC, fx.eth_ipv4_tcp(data=b"a"))],
                           name="a.pcap")
        b = self.make_pcap([(BASE_NS, shared),
                            (BASE_NS + SEC, fx.eth_ipv4_tcp(data=b"b"))],
                           name="b.pcap")
        out = self.path("deduped_sorted.pcap")
        result = pcapchunk.combine([a, b], out, sort=True, dedupe=True)
        self.assertEqual(result["packets"], 3)
        self.assertEqual(self.read_ts(out), [BASE_NS, BASE_NS + SEC,
                                             BASE_NS + 2 * SEC])

    def test_combine_mixed_linktypes_uses_pcapng(self):
        eth = self.make_pcap([(BASE_NS, fx.eth_ipv4_tcp(data=b"a"))],
                             name="eth.pcap")
        raw = self.make_pcap([(BASE_NS + SEC, fx.raw_ipv4_tcp(data=b"b"))],
                             name="raw.pcap", linktype=101)
        out = self.path("mixed_combined.pcapng")
        result = pcapchunk.combine([eth, raw], out)
        self.assertEqual(result["format"], "pcapng")
        self.assertEqual(result["packets"], 2)
        info = pcapchunk.describe(out)
        self.assertEqual(len(info["interfaces"]), 2)
        self.assertEqual(sorted(i["linktype"] for i in info["interfaces"]),
                         [1, 101])

    def test_combine_out_format_override(self):
        a, b = self._two()
        out = self.path("forced.pcapng")
        result = pcapchunk.combine([a, b], out, out_format="pcapng")
        self.assertEqual(result["format"], "pcapng")
        self.assertEqual(fx.detect_magic(self.read(out)), "pcapng")


class DemuxTest(TempDirTest):
    def test_demux_flows_and_csv(self):
        packets = [
            (BASE_NS + 0 * SEC,
             fx.eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1234, 80, b"a")),
            (BASE_NS + 1 * SEC,
             fx.eth_ipv4_tcp("10.0.0.2", "10.0.0.1", 80, 1234, b"b")),
            (BASE_NS + 2 * SEC,
             fx.eth_ipv4_tcp("10.0.0.7", "10.0.0.8", 2222, 443, b"c")),
            (BASE_NS + 3 * SEC,
             fx.eth_ipv4_udp("10.0.0.3", "10.0.0.4", 5353, 53, b"d")),
        ]
        src = self.make_pcap(packets)
        outdir = self.path("flows")
        result = pcapchunk.demux(src, outdir)
        self.assertEqual(result["input"], src)
        self.assertEqual(result["outdir"], outdir)
        self.assertEqual(result["flows"], 3)
        self.assertEqual(result["packets"], 4)
        self.assertEqual(result["bytes"], sum(len(p) for _ts, p in packets))
        self.assertTrue(os.path.isfile(result["csv"]))
        self.assertEqual(os.path.dirname(os.path.abspath(result["csv"])),
                         os.path.abspath(outdir))
        files = [n for n in fx.list_files(outdir) if n.endswith(".pcap")]
        self.assertEqual(len(files), 3)
        self.assertEqual(sum(fx.packet_count(self.read(
            os.path.join(outdir, n))) for n in files), 4)
        with open(result["csv"], "r", encoding="utf-8") as f:
            rows = [ln for ln in f.read().splitlines() if ln.strip()]
        self.assertGreaterEqual(len(rows), 3)
        self.assertEqual(no_part_files(self.dir), [])

    def test_demux_undecodable_goes_to_other(self):
        packets = [(BASE_NS + i * SEC, b"\xde\xad\xbe\xef" + bytes([i]))
                   for i in range(3)]
        src = self.make_pcap(packets, linktype=147)
        outdir = self.path("flows_other")
        result = pcapchunk.demux(src, outdir)
        other = os.path.join(outdir, "flow_0000_other.pcap")
        self.assertTrue(os.path.isfile(other))
        self.assertEqual(fx.packet_count(self.read(other)), 3)
        self.assertEqual(result["packets"], 3)

    def test_demux_filter(self):
        packets = flows_packets()
        src = self.make_pcap(packets)
        outdir = self.path("flows_filtered")
        result = pcapchunk.demux(src, outdir, filter_spec={"proto": "tcp"})
        self.assertEqual(result["packets"], 3)
        files = [n for n in fx.list_files(outdir) if n.endswith(".pcap")]
        total = sum(fx.packet_count(self.read(os.path.join(outdir, n)))
                    for n in files)
        self.assertEqual(total, 3)

    def test_demux_salvage_kwarg_accepted(self):
        src = self.make_pcap(flows_packets())
        outdir = self.path("flows_salvage")
        result = pcapchunk.demux(src, outdir, salvage=True)
        self.assertEqual(result["packets"], 5)


if __name__ == "__main__":
    unittest.main()
