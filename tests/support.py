"""Shared unittest harness for the PcapChunk v2 test suite.

Deliberately small: temp-dir management, capture-file helpers, a CLI runner and
a few assertion conveniences.  Only the public engine API documented in
``docs/API_V2.md`` is touched here.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for _p in (HERE, ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import fixtures as fx  # noqa: E402
import pcapchunk  # noqa: E402

BASE_S = fx.BASE_S
BASE_NS = fx.BASE_NS
SCRIPT = os.path.join(ROOT, "pcapchunk.py")

# Some restricted sandboxes (including the one this suite is developed under)
# deny writing inside the owner-only temp directory that tempfile.mkdtemp
# creates.  Prefer a real tempfile.mkdtemp (the norm), but fall back to an
# inherited-ACL directory under the platform temp root when that is the case.
_USE_MKDTEMP = None


def _is_writable(directory):
    probe = os.path.join(directory, ".pcapchunk-write-probe")
    try:
        with open(probe, "wb") as f:
            f.write(b"x")
        os.remove(probe)
        return True
    except OSError:
        return False


def make_temp_dir(prefix="pcapchunk-test-"):
    """Create a unique directory outside the repository, cleanup by caller."""
    global _USE_MKDTEMP
    base = tempfile.gettempdir()
    if _USE_MKDTEMP is not False:
        try:
            directory = tempfile.mkdtemp(prefix=prefix, dir=base)
        except OSError:
            directory = None
        if directory is not None:
            if _is_writable(directory):
                _USE_MKDTEMP = True
                return directory
            _USE_MKDTEMP = False
            shutil.rmtree(directory, ignore_errors=True)
    for _ in range(100):
        directory = os.path.join(base, prefix + uuid.uuid4().hex[:12])
        try:
            os.makedirs(directory)
            return directory
        except FileExistsError:
            continue
    raise RuntimeError("could not create a temporary directory under %r"
                       % base)


def run_cli(*args, cwd=None, timeout=180):
    """Run the real CLI in a subprocess; returns CompletedProcess (text)."""
    return subprocess.run(
        [sys.executable, SCRIPT] + [str(a) for a in args],
        cwd=cwd, capture_output=True, text=True, timeout=timeout,
        env=_clean_env(),
    )


def run_module(*args, cwd=None, timeout=180):
    """Run ``python -m pcapchunk`` in a subprocess."""
    env = _clean_env()
    env["PYTHONPATH"] = ROOT
    return subprocess.run(
        [sys.executable, "-m", "pcapchunk"] + [str(a) for a in args],
        cwd=cwd, capture_output=True, text=True, timeout=timeout,
        env=env,
    )


def _clean_env():
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return env


def list_files(root):
    """All regular files below *root* as relative POSIX-ish paths."""
    out = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            out.append(os.path.relpath(full, root))
    return sorted(out)


class TempDirTest(unittest.TestCase):
    """TestCase with a throw-away directory outside the repository."""

    def setUp(self):
        self.dir = make_temp_dir()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    # -- paths ---------------------------------------------------------
    def path(self, *parts):
        return os.path.join(self.dir, *parts)

    def subdir(self, name):
        p = self.path(name)
        os.makedirs(p, exist_ok=True)
        return p

    def write(self, name, data):
        p = self.path(name)
        parent = os.path.dirname(p)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        return fx.write(p, data)

    def read(self, path):
        return fx.read(path)

    def read_packets(self, path):
        return fx.parse_capture(self.read(path))["packets"]

    def read_ts(self, path):
        return [p["ts_ns"] for p in self.read_packets(path)]

    def read_payloads(self, path):
        return [p["data"] for p in self.read_packets(path)]

    # -- capture builders ---------------------------------------------
    def make_pcap(self, packets=None, name="cap.pcap", n=12, **kw):
        if packets is None:
            packets = fx.packet_stream(n)
        return self.write(name, fx.pcap_bytes(list(packets), **kw))

    def make_pcapng(self, packets=None, name="cap.pcapng", n=12, **kw):
        if packets is None:
            packets = fx.packet_stream(n)
        return self.write(name, fx.default_pcapng(list(packets), **kw))

    def make_capture(self, fmt="pcap", packets=None, name=None, **kw):
        if name is None:
            name = "cap.pcap" if fmt == "pcap" else "cap.pcapng"
        if fmt == "pcap":
            return self.make_pcap(packets=packets, name=name, **kw)
        return self.make_pcapng(packets=packets, name=name, **kw)

    # -- engine helpers ------------------------------------------------
    def split(self, path, outdir=None, **kw):
        outdir = outdir if outdir is not None else self.path("chunks")
        return pcapchunk.split(path, outdir=outdir, **kw)

    def split_steps(self, path, outdir=None, **kw):
        outdir = outdir if outdir is not None else self.path("chunks")
        return pcapchunk.split_steps(path, outdir=outdir, **kw)

    def merge(self, folder, output=None, **kw):
        output = output if output is not None else self.path("merged.out")
        return pcapchunk.merge(folder, output=output, **kw)

    def manifest(self, folder):
        with open(os.path.join(folder, pcapchunk.MANIFEST), "r",
                  encoding="utf-8") as f:
            return json.load(f)

    def write_manifest(self, folder, manifest):
        with open(os.path.join(folder, pcapchunk.MANIFEST), "w",
                  encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

    def chunk_names(self, folder):
        return pcapchunk.discover_chunks(folder).names

    def assert_roundtrip(self, src_path, outdir=None, merge_output=None,
                         **split_kw):
        """Split *src_path*, merge the set, and require byte equality."""
        summary = self.split(src_path, outdir=outdir, **split_kw)
        folder = summary["outdir"]
        ext = os.path.splitext(src_path)[1] or ".pcap"
        if merge_output is None:
            merge_output = self.path(
                "merged_roundtrip_" + uuid.uuid4().hex[:8] + ext)
        result = self.merge(folder, output=merge_output)
        self.assertEqual(
            fx.sha256_file(src_path), fx.sha256_file(merge_output),
            "merged output is not byte-identical to the source")
        return summary, result, folder

    def assert_valid_chunks(self, folder, fmt=None, compressed=None):
        """Every listed chunk opens standalone (after decompression)."""
        cs = pcapchunk.discover_chunks(folder)
        for name in cs.names:
            p = os.path.join(folder, name)
            data = fx.read(p)
            if compressed == "gzip" or name.endswith(".gz"):
                data = fx.gzip_read(data)
            elif compressed == "zstd" or name.endswith(".zst"):
                from compression import zstd  # noqa: F401
                data = zstd.decompress(data)
            actual = fx.detect_magic(data)
            if fmt is not None:
                self.assertEqual(actual, fmt, "chunk %s is not %s" % (name, fmt))
            self.assertFalse(fx.parse_capture(data)["truncated"],
                             "chunk %s has a truncated tail" % name)

    # -- CLI -----------------------------------------------------------
    def run_cli(self, *args, cwd=None, timeout=180):
        return run_cli(*args, cwd=cwd or self.dir, timeout=timeout)

    def run_main(self, *args):
        """Call pcapchunk.main(argv) in-process, capturing stdout/stderr."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = pcapchunk.main(list(args))
            except SystemExit as exc:  # --help / --version
                rc = exc.code if isinstance(exc.code, int) else 1
        return rc, out.getvalue(), err.getvalue()

    def json_stdout(self, proc):
        text = proc.stdout.strip()
        self.assertTrue(text, "expected one JSON object on stdout, got %r"
                        % proc.stdout)
        return json.loads(text)
