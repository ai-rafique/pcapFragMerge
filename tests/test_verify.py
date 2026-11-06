"""Verify: good sets, corruption, missing chunks, deep checks, schema 1 and
the CLI exit code 2 contract."""

import os
import unittest

from support import TempDirTest

import fixtures as fx
import pcapchunk


class VerifyTest(TempDirTest):
    def _set(self, n=9, packets_per_chunk=3, name="cap.pcap"):
        packets = fx.packet_stream(n)
        src = self.make_pcap(packets, name=name)
        summary = self.split(src, packets=packets_per_chunk)
        return src, summary["outdir"]

    def test_good_set_schema2(self):
        src, folder = self._set()
        result = pcapchunk.verify(folder)
        self.assertEqual(result["folder"], folder)
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(result["schema"], 2)
        self.assertTrue(result["manifest"])
        self.assertEqual(result["problems"], [])
        self.assertEqual(result["missing"], [])
        self.assertFalse(result["incomplete"])
        self.assertEqual(len(result["chunks"]), 3)
        for chunk in result["chunks"]:
            self.assertTrue(chunk["ok"], chunk["problems"])
            self.assertEqual(chunk["bytes"], chunk["expected_bytes"])
            self.assertEqual(chunk["packets"], chunk["expected_packets"])
            self.assertEqual(chunk["sha256"], chunk["expected_sha256"])
            self.assertEqual(chunk["problems"], [])
            self.assertEqual(chunk["first_ts_ns"] % 1_000_000, 0)
        self.assertEqual(result["chunks"][0]["file"], "cap_0001.pcap")

    def test_corrupted_chunk_is_reported_with_file_name(self):
        src, folder = self._set()
        target = "cap_0002.pcap"
        path = os.path.join(folder, target)
        data = bytearray(fx.read(path))
        data[-1] ^= 0xFF
        fx.write(path, bytes(data))
        result = pcapchunk.verify(folder)
        self.assertFalse(result["ok"])
        self.assertTrue(result["problems"])
        named = False
        for chunk in result["chunks"]:
            if chunk["file"] == target:
                self.assertFalse(chunk["ok"])
                self.assertTrue(chunk["problems"])
            text = " ".join(chunk["problems"])
            if target in text:
                named = True
        text = " ".join(result["problems"])
        if target in text:
            named = True
        self.assertTrue(named,
                        "verify did not name the corrupted file: %r"
                        % result["problems"])
        self.assertIn(target, " ".join(result["problems"])
                      + " ".join(" ".join(c["problems"])
                                 for c in result["chunks"]))

    def test_missing_chunk(self):
        src, folder = self._set()
        os.remove(os.path.join(folder, "cap_0002.pcap"))
        result = pcapchunk.verify(folder)
        self.assertFalse(result["ok"])
        self.assertEqual(result["missing"], ["cap_0002.pcap"])
        self.assertTrue(result["problems"])

    def test_verify_is_read_only(self):
        src, folder = self._set()
        before = {name: fx.sha256_file(os.path.join(folder, name))
                  for name in fx.list_files(folder)}
        pcapchunk.verify(folder)
        pcapchunk.verify(folder, deep=True)
        after = {name: fx.sha256_file(os.path.join(folder, name))
                 for name in fx.list_files(folder)}
        self.assertEqual(before, after)

    def test_verify_steps_yields_ints(self):
        src, folder = self._set()
        gen = pcapchunk.verify_steps(folder)
        yields = []
        result = None
        while True:
            try:
                yields.append(next(gen))
            except StopIteration as stop:
                result = stop.value
                break
        self.assertTrue(yields)
        expected_total = sum(
            os.path.getsize(os.path.join(folder, n)) for n in
            self.chunk_names(folder))
        for done, total in yields:
            self.assertIsInstance(done, int)
            self.assertIsInstance(total, int)
            self.assertEqual(total, expected_total)
            self.assertLessEqual(0, done)
            self.assertLessEqual(done, total)
        self.assertIsInstance(result, dict)
        self.assertTrue(result["ok"])

    def test_incomplete_marker_reported(self):
        src, folder = self._set()
        fx.write(os.path.join(folder, pcapchunk.INCOMPLETE), b"")
        result = pcapchunk.verify(folder)
        self.assertTrue(result["incomplete"])

    def test_manifest_less_set(self):
        src, folder = self._set()
        os.remove(os.path.join(folder, pcapchunk.MANIFEST))
        sums = os.path.join(folder, pcapchunk.SUMS)
        if os.path.exists(sums):
            os.remove(sums)
        result = pcapchunk.verify(folder)
        self.assertIsNone(result["schema"])
        self.assertFalse(result["manifest"])
        # Contract note: without a manifest the set cannot be proven complete.
        self.assertFalse(result["ok"])
        self.assertIn("warnings", result)
        self.assertEqual(len(result["chunks"]), 3)


class VerifyDeepTest(TempDirTest):
    def _set(self):
        packets = fx.packet_stream(9)
        src = self.make_pcap(packets)
        summary = self.split(src, packets=3)
        return src, summary["outdir"]

    def test_deep_verify_good_set(self):
        src, folder = self._set()
        result = pcapchunk.verify(folder, deep=True)
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(result["schema"], 2)

    def test_deep_detects_packet_count_mismatch(self):
        src, folder = self._set()
        manifest = self.manifest(folder)
        manifest["chunks"][1]["packets"] += 1
        self.write_manifest(folder, manifest)
        deep = pcapchunk.verify(folder, deep=True)
        self.assertFalse(deep["ok"])
        self.assertTrue(deep["problems"])

    def test_shallow_trusts_manifest_counts(self):
        # The contract reserves packet-count checks for deep verification.
        src, folder = self._set()
        manifest = self.manifest(folder)
        manifest["chunks"][1]["packets"] += 1
        self.write_manifest(folder, manifest)
        shallow = pcapchunk.verify(folder)
        self.assertTrue(shallow["ok"], shallow["problems"])

    def test_deep_detects_timestamp_range_mismatch(self):
        src, folder = self._set()
        manifest = self.manifest(folder)
        manifest["chunks"][1]["last_ts_ns"] += 999_999_999
        self.write_manifest(folder, manifest)
        result = pcapchunk.verify(folder, deep=True)
        self.assertFalse(result["ok"])
        self.assertTrue(result["problems"])

    def test_deep_manifest_less_set(self):
        src, folder = self._set()
        os.remove(os.path.join(folder, pcapchunk.MANIFEST))
        sums = os.path.join(folder, pcapchunk.SUMS)
        if os.path.exists(sums):
            os.remove(sums)
        result = pcapchunk.verify(folder, deep=True)
        self.assertIsNone(result["schema"])
        self.assertFalse(result["manifest"])
        self.assertFalse(result["ok"])
        self.assertIn("warnings", result)


class SchemaOneTest(TempDirTest):
    def _v1_set(self):
        packets = fx.packet_stream(9)
        src = self.make_pcap(packets, name="cap.pcap")
        summary = self.split(src, packets=3)
        folder = summary["outdir"]
        manifest = self.manifest(folder)
        v1 = {
            "source": "cap.pcap",
            "format": "pcap",
            "size": os.path.getsize(src),
            "sha256": fx.sha256_file(src),
            "chunks": [{"file": c["file"], "bytes": c["bytes"],
                        "packets": c["packets"]}
                       for c in manifest["chunks"]],
        }
        self.write_manifest(folder, v1)
        return src, folder

    def test_verify_schema1(self):
        src, folder = self._v1_set()
        result = pcapchunk.verify(folder)
        self.assertEqual(result["schema"], 1)
        self.assertTrue(result["manifest"])
        self.assertTrue(result["ok"], result["problems"])
        for chunk in result["chunks"]:
            self.assertTrue(chunk["ok"])
            self.assertEqual(chunk["bytes"], chunk["expected_bytes"])
            self.assertEqual(chunk["packets"], chunk["expected_packets"])
            self.assertIsNone(chunk["expected_sha256"])

    def test_deep_verify_schema1(self):
        src, folder = self._v1_set()
        result = pcapchunk.verify(folder, deep=True)
        self.assertEqual(result["schema"], 1)
        self.assertTrue(result["ok"], result["problems"])


class VerifyCliExitCodeTest(TempDirTest):
    def test_cli_verify_exit_codes(self):
        packets = fx.packet_stream(9)
        src = self.make_pcap(packets)
        summary = self.split(src, packets=3)
        folder = summary["outdir"]
        rc, out, err = self.run_main("verify", folder)
        self.assertEqual(rc, 0, out + err)
        path = os.path.join(folder, "cap_0002.pcap")
        data = bytearray(fx.read(path))
        data[-1] ^= 0xFF
        fx.write(path, bytes(data))
        rc, out, err = self.run_main("verify", folder)
        self.assertEqual(rc, 2, out + err)
        self.assertIn("cap_0002.pcap", out + err)

    def test_cli_verify_json_exit_code_2(self):
        src = self.make_pcap(fx.packet_stream(9))
        summary = self.split(src, packets=3)
        folder = summary["outdir"]
        proc = self.run_cli("verify", folder)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        path = os.path.join(folder, "cap_0001.pcap")
        data = bytearray(fx.read(path))
        data[-1] ^= 0xFF
        fx.write(path, bytes(data))
        proc = self.run_cli("--json", "verify", folder)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        obj = self.json_stdout(proc)
        self.assertIs(obj["ok"], False)
        self.assertTrue(obj["problems"])


if __name__ == "__main__":
    unittest.main()
