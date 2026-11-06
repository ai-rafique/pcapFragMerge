"""Safety: user files, promotion of a new set over an old one, markers,
space checks and bounded reads of hostile length fields."""

import collections
import os
import shutil
import struct
import time
import unittest
from unittest import mock

from support import TempDirTest, BASE_NS

import fixtures as fx
import pcapchunk

_Usage = collections.namedtuple("usage", "total used free")


def fake_usage(free):
    return _Usage(total=free + 1, used=1, free=free)


def big_capture(testcase, name="big.pcap", n=400, payload_size=8000):
    return testcase.make_pcap(fx.packet_stream(n, payload_size=payload_size),
                              name=name)


class UserFilesTest(TempDirTest):
    def test_unrelated_files_survive_force_split(self):
        src = self.make_pcap(fx.packet_stream(6), name="cap.pcap")
        outdir = self.path("out")
        first = self.split(src, outdir=outdir, packets=2)
        self.assertGreaterEqual(first["chunks"], 1)
        fx.write(os.path.join(outdir, "notes.txt"), b"user notes\n")
        fx.write(os.path.join(outdir, "keep.bin"), b"\x00\x01\x02")
        os.makedirs(os.path.join(outdir, "archive"), exist_ok=True)
        fx.write(os.path.join(outdir, "archive", "x.dat"), b"nested")
        before = {
            "notes.txt": fx.read(os.path.join(outdir, "notes.txt")),
            "keep.bin": fx.read(os.path.join(outdir, "keep.bin")),
            os.path.join("archive", "x.dat"): fx.read(
                os.path.join(outdir, "archive", "x.dat")),
        }
        # Replace the source content, then force a re-split into the same folder.
        new_packets = fx.packet_stream(9)
        fx.write(src, fx.pcap_bytes(new_packets))
        summary = self.split(src, outdir=outdir, packets=3, force=True)
        for rel, data in before.items():
            self.assertEqual(fx.read(os.path.join(outdir, rel)), data,
                             "unrelated file %r was modified" % rel)
        self.assertEqual(summary["packets"], 9)
        out = self.path("merged_force.pcap")
        pcapchunk.merge(outdir, output=out)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(out))

    def test_force_required_when_chunk_set_exists(self):
        src = self.make_pcap(fx.packet_stream(6), name="cap.pcap")
        self.split(src, outdir=self.path("out"), packets=2)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(src, outdir=self.path("out"), packets=2)

    def test_failed_force_split_preserves_old_set(self):
        src = self.make_pcap(fx.packet_stream(9), name="cap.pcap")
        outdir = self.path("out")
        self.split(src, outdir=outdir, packets=3)
        before_names = self.chunk_names(outdir)
        before_hashes = {n: fx.sha256_file(os.path.join(outdir, n))
                         for n in before_names}
        before_manifest = fx.sha256_file(os.path.join(outdir,
                                                      pcapchunk.MANIFEST))
        # Corrupt the source with a pcapng file whose block length is invalid;
        # detect_format succeeds but the split must fail mid-flight.
        bad = (fx.section_header(endian="<")
               + fx.interface_description(endian="<")
               + struct.pack("<II", fx.EPB, 7) + b"\x00\x00\x00")
        fx.write(src, bad)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(src, outdir=outdir, packets=2, force=True)
        self.assertEqual(self.chunk_names(outdir), before_names)
        for name, digest in before_hashes.items():
            self.assertEqual(fx.sha256_file(os.path.join(outdir, name)),
                             digest)
        self.assertEqual(fx.sha256_file(os.path.join(outdir,
                                                     pcapchunk.MANIFEST)),
                         before_manifest)
        result = pcapchunk.verify(outdir)
        self.assertTrue(result["ok"], result["problems"])


class MarkerTest(TempDirTest):
    def test_failed_split_leaves_no_marker_or_staging(self):
        bad = (fx.section_header(endian="<")
               + fx.interface_description(endian="<")
               + struct.pack("<II", fx.EPB, 7) + b"\x00\x00\x00")
        src = self.write("bad.pcapng", bad)
        outdir = self.path("out")
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(src, outdir=outdir)
        self.assertFalse(os.path.exists(os.path.join(outdir,
                                                    pcapchunk.INCOMPLETE)))
        self.assertFalse(os.path.exists(os.path.join(outdir,
                                                    pcapchunk.STAGING)))
        self.assertFalse(os.path.exists(os.path.join(outdir,
                                                    pcapchunk.MANIFEST)))

    def test_marker_removed_after_successful_promotion(self):
        src = self.make_pcap(fx.packet_stream(8))
        outdir = self.subdir("out")
        marker = os.path.join(outdir, pcapchunk.INCOMPLETE)
        fx.write(marker, b"stale marker from a crashed run\n")
        gen = pcapchunk.split_steps(src, outdir=outdir, packets=2)
        while True:
            try:
                next(gen)
            except StopIteration:
                break
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(self.manifest(outdir)["status"], "complete")


class LockTest(TempDirTest):
    def test_concurrent_split_into_same_folder_is_rejected(self):
        src = self.make_pcap(fx.packet_stream(40, payload_size=2000),
                             name="cap.pcap")
        outdir = self.path("locked_out")
        gen = pcapchunk.split_steps(src, outdir=outdir, packets=5)
        next(gen)
        try:
            with self.assertRaises(pcapchunk.PcapError):
                pcapchunk.split(src, outdir=outdir, packets=5, force=True)
        finally:
            gen.close()
        # The lock is released, so a fresh split now succeeds.
        summary = pcapchunk.split(src, outdir=outdir, packets=5)
        self.assertGreaterEqual(summary["chunks"], 1)
        self.assertEqual([n for n in fx.list_files(outdir)
                          if "lock" in os.path.basename(n).lower()], [])

    def test_dry_run_takes_no_lock(self):
        src = self.make_pcap(fx.packet_stream(6), name="cap.pcap")
        summary = pcapchunk.split(src, outdir=self.path("dry"),
                                  packets=2, dry_run=True)
        self.assertIs(summary["dry_run"], True)
        self.assertFalse(os.path.isdir(self.path("dry")))


class SpaceCheckTest(TempDirTest):
    def test_insufficient_space_raises(self):
        src = self.make_pcap(fx.packet_stream(20, payload_size=500),
                             name="cap.pcap")
        with mock.patch.object(shutil, "disk_usage",
                               return_value=fake_usage(0)):
            with self.assertRaises(pcapchunk.PcapError):
                pcapchunk.split(src, outdir=self.path("out"))

    def test_space_check_can_be_disabled(self):
        src = self.make_pcap(fx.packet_stream(20, payload_size=500),
                             name="cap.pcap")
        with mock.patch.object(shutil, "disk_usage",
                               return_value=fake_usage(0)):
            summary = pcapchunk.split(src, outdir=self.path("out"),
                                      space_check=False)
        self.assertEqual(summary["packets"], 20)

    def test_enough_space_passes(self):
        src = self.make_pcap(fx.packet_stream(5), name="cap.pcap")
        with mock.patch.object(shutil, "disk_usage",
                               return_value=fake_usage(1 << 40)):
            summary = pcapchunk.split(src, outdir=self.path("out"), packets=2)
        self.assertGreaterEqual(summary["chunks"], 1)


class HostileLengthsTest(TempDirTest):
    def test_huge_pcap_record_length_is_bounded(self):
        data = (fx.pcap_global_header()
                + fx.pcap_record(BASE_NS, b"", declared_len=0xFFFFFFF0))
        src = self.write("huge.pcap", data)
        outdir = self.path("out")
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(src, outdir=outdir, max_record=1 << 20)
        self.assertFalse(os.path.exists(os.path.join(outdir,
                                                    pcapchunk.MANIFEST)))

    def test_huge_pcapng_caplen_is_bounded(self):
        body = struct.pack("<IIIII", 0, 0, 0, 0xFFFFFFF0, 0xFFFFFFF0)
        data = (fx.section_header(endian="<")
                + fx.interface_description(endian="<")
                + fx.pcapng_block(fx.EPB, body, endian="<"))
        src = self.write("huge_cap.pcapng", data)
        outdir = self.path("out")
        started = time.monotonic()
        try:
            summary = pcapchunk.split(src, outdir=outdir)
        except pcapchunk.PcapError:
            summary = None
        elapsed = time.monotonic() - started
        # Either a clean error, or the bogus record is tolerated without
        # allocating/reading the claimed 4 GiB payload.
        self.assertLess(elapsed, 10.0, "split spent too long on a bogus length")
        if summary is not None:
            written = sum(os.path.getsize(os.path.join(outdir, n))
                          for n in fx.list_files(outdir))
            self.assertLess(written, 1 << 20)
        started = time.monotonic()
        try:
            info = pcapchunk.info(src)
        except pcapchunk.PcapError:
            info = None
        self.assertLess(time.monotonic() - started, 10.0)
        if info is not None:
            self.assertLessEqual(info["bytes"], len(data))

    def test_huge_pcapng_block_length_is_rejected(self):
        header = struct.pack("<II", fx.EPB, 0xFFFFFFF0)
        data = (fx.section_header(endian="<")
                + fx.interface_description(endian="<")
                + header + b"\x00" * 8)
        src = self.write("huge_block.pcapng", data)
        with self.assertRaises(pcapchunk.PcapError):
            pcapchunk.split(src, outdir=self.path("out2"))


class CancelMergeTest(TempDirTest):
    def test_cancelled_merge_leaves_no_part_file(self):
        src = big_capture(self)
        summary = self.split(src, packets=127)
        out = self.path("merged_cancel.pcap")
        gen = pcapchunk.merge_steps(summary["outdir"], output=out)
        next(gen)
        gen.close()
        self.assertFalse(os.path.exists(out))
        leftovers = [n for n in fx.list_files(self.dir) if n.endswith(".part")]
        self.assertEqual(leftovers, [])

    def test_cancelled_merge_preserves_existing_output(self):
        src = self.make_pcap(fx.packet_stream(9), name="cap.pcap")
        summary = self.split(src, packets=3)
        out = self.path("existing.pcap")
        fx.write(out, b"old output bytes")
        gen = pcapchunk.merge_steps(summary["outdir"], output=out,
                                    force=True)
        next(gen)
        gen.close()
        self.assertEqual(fx.read(out), b"old output bytes")


if __name__ == "__main__":
    unittest.main()
