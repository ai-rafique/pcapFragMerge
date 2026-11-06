"""CLI: --version, --json success/error shapes, help, subprocess end-to-end."""

import os
import re
import unittest

from support import TempDirTest, run_module

import fixtures as fx
import pcapchunk


class VersionAndHelpTest(TempDirTest):
    def test_version_flag(self):
        proc = self.run_cli("--version")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("2.0.0", proc.stdout)

    def test_version_flag_before_or_after_prog(self):
        proc = run_module("--version", cwd=self.dir)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("2.0.0", proc.stdout)

    def test_help_lists_commands(self):
        proc = self.run_cli("--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        text = proc.stdout
        for command in ("split", "merge", "verify", "info", "trim",
                        "convert", "combine", "demux"):
            self.assertIn(command, text)

    def test_subcommand_help(self):
        proc = self.run_cli("split", "--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        text = proc.stdout
        for token in ("--compress", "--name-style", "--resume",
                      "--dry-run"):
            self.assertIn(token, text)
        proc = self.run_cli("trim", "--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for token in ("--host", "--port", "--proto"):
            self.assertIn(token, proc.stdout)


class JsonTest(TempDirTest):
    def test_json_split_success_shape(self):
        src = self.make_pcap(fx.packet_stream(12))
        outdir = self.path("json_out")
        proc = self.run_cli("--json", "split", src, "-o", outdir,
                            "-s", "1K")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        obj = self.json_stdout(proc)
        self.assertIs(obj["ok"], True)
        self.assertIn("chunks", obj)
        self.assertIn("outdir", obj)
        self.assertEqual(obj["outdir"], outdir)
        self.assertGreater(obj["chunks"], 1)
        self.assertNotIn("progress", proc.stdout)

    def test_json_error_shape(self):
        missing = self.path("does_not_exist.pcap")
        proc = self.run_cli("--json", "split", missing,
                            "-o", self.path("nope"))
        self.assertEqual(proc.returncode, 1, proc.stderr)
        obj = self.json_stdout(proc)
        self.assertIs(obj["ok"], False)
        self.assertIn("error", obj)
        self.assertIsInstance(obj["error"], str)
        self.assertTrue(obj["error"])

    def test_json_info_success(self):
        src = self.make_pcap(fx.packet_stream(5))
        proc = self.run_cli("--json", "info", src)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        obj = self.json_stdout(proc)
        self.assertIs(obj["ok"], True)
        self.assertEqual(obj["packets"], 5)
        self.assertEqual(obj["format"], "pcap")

    def test_json_verify_good(self):
        src = self.make_pcap(fx.packet_stream(6))
        summary = self.split(src, packets=2)
        proc = self.run_cli("--json", "verify", summary["outdir"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        obj = self.json_stdout(proc)
        self.assertIs(obj["ok"], True)
        self.assertIn("chunks", obj)


class EndToEndTest(TempDirTest):
    def test_split_then_merge_subprocess(self):
        packets = fx.packet_stream(25, payload_size=100)
        src = self.make_pcap(packets)
        outdir = self.path("e2e_chunks")
        proc = self.run_cli("split", src, "-o", outdir, "-p", "10")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.isdir(outdir))
        folders = pcapchunk.discover_chunks(outdir)
        self.assertEqual(len(folders.names), 3)
        output = self.path("restored.pcap")
        proc = self.run_cli("merge", outdir, "-o", output)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(fx.sha256_file(src), fx.sha256_file(output))

    def test_split_default_mode_subprocess(self):
        src = self.make_pcap(fx.packet_stream(8))
        outdir = self.path("default_chunks")
        proc = self.run_cli("split", src, "-o", outdir)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(pcapchunk.discover_chunks(outdir).names), 1)

    def test_every_and_gap_modes_subprocess(self):
        packets = [(fx.BASE_NS + i * 10_000_000_000,
                    fx.eth_ipv4_tcp(data=bytes([i]))) for i in range(4)]
        src = self.make_pcap(packets)
        proc = self.run_cli("split", src, "-o", self.path("every"),
                            "--every", "10s")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc = self.run_cli("split", src, "-o", self.path("gap"),
                            "--gap", "5s")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc = self.run_cli("split", src, "-o", self.path("split_at"),
                            "--split-at", "13:00:10,13:00:20")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_verify_exit_code_two_subprocess(self):
        src = self.make_pcap(fx.packet_stream(6))
        summary = self.split(src, packets=2)
        folder = summary["outdir"]
        path = os.path.join(folder, pcapchunk.discover_chunks(folder).names[0])
        data = bytearray(fx.read(path))
        data[-1] ^= 0xFF
        fx.write(path, bytes(data))
        proc = self.run_cli("verify", folder)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn(os.path.basename(path), proc.stdout + proc.stderr)

    def test_merge_allow_missing_subprocess(self):
        src = self.make_pcap(fx.packet_stream(9))
        summary = self.split(src, packets=3)
        folder = summary["outdir"]
        names = pcapchunk.discover_chunks(folder).names
        os.remove(os.path.join(folder, names[1]))
        output = self.path("partial.pcap")
        proc = self.run_cli("merge", folder, "-o", output, "--allow-missing")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.isfile(output))

    def test_transform_commands_subprocess(self):
        src = self.make_pcap(fx.packet_stream(10, payload_size=64))
        trimmed = self.path("trimmed_cli.pcap")
        proc = self.run_cli("trim", src, "-o", trimmed, "--first", "3")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(fx.packet_count(fx.read(trimmed)), 3)

        converted = self.path("converted_cli.pcapng")
        proc = self.run_cli("convert", src, "-o", converted,
                            "--format", "pcapng")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(fx.detect_magic(fx.read(converted)), "pcapng")

        second = self.make_pcap(fx.packet_stream(4), name="second.pcap")
        combined = self.path("combined_cli.pcap")
        proc = self.run_cli("combine", src, second, "-o", combined, "--sort")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(fx.packet_count(fx.read(combined)), 14)

        demuxed = self.path("demux_cli")
        proc = self.run_cli("demux", src, "-o", demuxed)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.isdir(demuxed))

    def test_quiet_and_verbose_flags(self):
        src = self.make_pcap(fx.packet_stream(6))
        proc = self.run_cli("-q", "split", src, "-o", self.path("q_out"),
                            "-p", "3")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc = self.run_cli("-v", "split", src, "-o", self.path("v_out"),
                            "-p", "3")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_json_dry_run_plan(self):
        src = self.make_pcap(fx.packet_stream(9))
        outdir = self.path("dry_json")
        proc = self.run_cli("--json", "split", src, "-o", outdir,
                            "-p", "3", "--dry-run")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        obj = self.json_stdout(proc)
        self.assertIs(obj["ok"], True)
        self.assertIs(obj["dry_run"], True)
        self.assertIsInstance(obj["plan"], list)
        self.assertEqual(len(obj["plan"]), 3)
        self.assertFalse(os.path.exists(outdir))

    def test_split_option_flags_subprocess(self):
        src = self.make_pcap(fx.packet_stream(10, payload_size=100))
        gzdir = self.path("gz_out")
        proc = self.run_cli("split", src, "-o", gzdir, "-p", "3",
                            "--compress", "gzip")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        names = pcapchunk.discover_chunks(gzdir).names
        self.assertTrue(names)
        self.assertTrue(all(n.endswith(".pcap.gz") for n in names), names)

        timedir = self.path("time_out")
        proc = self.run_cli("split", src, "-o", timedir, "-p", "2",
                            "--name-style", "time")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        block = pcapchunk.discover_chunks(timedir)
        self.assertTrue(all(
            re.match(r"^cap_\d{8}T\d{6}-\d{8}T\d{6}_\d{4}\.pcap$", n)
            for n in block.names), block.names)
        self.assertEqual(block.manifest["naming"], "time")

        csv = self.path("index.csv")
        proc = self.run_cli("split", src, "-o", self.path("csv_out"),
                            "-p", "3", "--index", csv, "--no-space-check")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.isfile(csv))
        with open(csv, "r", encoding="utf-8") as f:
            self.assertGreaterEqual(len(f.read().splitlines()), 3)

    def test_force_and_salvage_flags(self):
        src = self.make_pcap(fx.packet_stream(6))
        outdir = self.path("force_out")
        proc = self.run_cli("split", src, "-o", outdir, "-p", "2")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc = self.run_cli("split", src, "-o", outdir, "-p", "2")
        self.assertEqual(proc.returncode, 1, "existing set must need --force")
        proc = self.run_cli("split", src, "-o", outdir, "-p", "2", "--force")
        self.assertEqual(proc.returncode, 0, proc.stderr)

        truncated = self.write("truncated.pcap",
                               fx.pcap_bytes(fx.packet_stream(4))[:-12])
        proc = self.run_cli("split", truncated,
                            "-o", self.path("salvage_out"), "-p", "2",
                            "--salvage")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_json_transform_summaries(self):
        src = self.make_pcap(fx.packet_stream(10, payload_size=64))
        trimmed = self.path("json_trim.pcap")
        proc = self.run_cli("--json", "trim", src, "-o", trimmed,
                            "--first", "3")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        obj = self.json_stdout(proc)
        self.assertIs(obj["ok"], True)
        self.assertEqual(obj["packets"], 3)

        converted = self.path("json_convert.pcapng")
        proc = self.run_cli("--json", "convert", src, "-o", converted,
                            "--format", "pcapng")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIs(self.json_stdout(proc)["ok"], True)

        second = self.make_pcap(fx.packet_stream(4), name="second.pcap")
        combined = self.path("json_combine.pcap")
        proc = self.run_cli("--json", "combine", src, second, "-o", combined,
                            "--sort")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        obj = self.json_stdout(proc)
        self.assertIs(obj["ok"], True)
        self.assertEqual(obj["packets"], 14)

        demuxed = self.path("json_demux")
        proc = self.run_cli("--json", "demux", src, "-o", demuxed)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIs(self.json_stdout(proc)["ok"], True)

        outdir = self.path("json_merge_chunks")
        self.split(src, outdir=outdir, packets=4)
        merged = self.path("json_merge.pcap")
        proc = self.run_cli("--json", "merge", outdir, "-o", merged)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        obj = self.json_stdout(proc)
        self.assertIs(obj["ok"], True)
        self.assertIs(obj["verified"], True)

    def test_json_info_top_and_deep_verify(self):
        src = self.make_pcap(fx.packet_stream(8))
        proc = self.run_cli("--json", "info", src, "--top", "2")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        obj = self.json_stdout(proc)
        self.assertIs(obj["ok"], True)
        self.assertIn("top", obj)
        outdir = self.path("deep_chunks")
        self.split(src, outdir=outdir, packets=2)
        proc = self.run_cli("--json", "verify", outdir, "--deep")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIs(self.json_stdout(proc)["ok"], True)


if __name__ == "__main__":
    unittest.main()
