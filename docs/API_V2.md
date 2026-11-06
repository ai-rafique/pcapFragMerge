# PcapChunk v2 — frozen internal API contract

This document is the single source of truth for the v2 public API. The engine
(`pcapchunk.py`) implements it, the GUI (`pcapchunk_gui.py`) and the test suite
(`tests/`) consume it. Do not change a signature here without the Lead updating
this file and notifying everyone.

Python target: **3.8+**, standard library only at runtime. No threads in the
engine or the GUI. All long operations are generators that yield progress and
return a summary dict.

---

## 1. Module-level names

```python
__version__          # "2.0.0"
APP_NAME             # "PcapChunk"
MANIFEST             # "manifest.json"
SUMS                 # "SHA256SUMS"
INCOMPLETE           # ".pcapchunk-incomplete"  (marker while a set is not final)
STAGING              # ".pcapchunk-staging"      (staging folder name, inside outdir)
BUF                  # 1 MiB
PROGRESS_EVERY       # 1 MiB
PRESETS              # {"email": 20<<20, "upload": 100<<20, "fat32": (4<<30)-1,
                     #  "telegram": 1900<<20, "dvd": 4_700_000_000}
class PcapError(Exception)
```

`PcapError` is the only error type the GUI should special-case; `OSError` is
also possible and must be handled too.

---

## 2. Paths, formats, inspection

```python
detect_format(path) -> "pcap" | "pcapng"
```
Sniffs magic bytes, transparently through gzip. Raises `PcapError` for
unknown/corrupt headers. Never opens more than a few KiB.

```python
open_capture(path) -> (fileobj, format_str, compressed_str_or_None, logical_size_or_None)
```
Caller closes the file object. For gzip sources the returned stream is
decompressed and `logical_size` is `None` unless reliably known (4 GiB modulo
issue => treat as unknown). `compressed` is `"gzip"` or `None`.

```python
describe(path) -> dict
```
Header-only (no packet payload scan; pcapng blocks other than SHB/IDB are
seeked over, so every interface in every section is reported). `interfaces` is
empty for pcap. Keys:

```
{
  "path": str, "format": "pcap"|"pcapng", "compressed": None|"gzip",
  "size": int,                 # bytes on disk
  "logical_size": int|None,
  "precision": "usec"|"nsec"|None,     # pcap only
  "linktype": int|None, "snaplen": int|None,   # pcap only
  "interfaces": [ {"id": int, "linktype": int, "snaplen": int,
                   "name": str|None, "tsresol": int, "section": int} ],
}
```

```python
info_steps(path, top=0) -> generator
info(path, top=0) -> dict
```
Full scan. Yields `(done, total)` where `total` is the on-disk size (or the
logical size when known; `0` when unknown). Return value:

```
{
  "path", "format", "compressed", "size", "logical_size",
  "packets": int, "bytes": int,                       # sum of caplen
  "first_ts_ns": int|None, "last_ts_ns": int|None, "duration_s": float|None,
  "interfaces": [ {"id","linktype","snaplen","name","tsresol","packets"} ],
  "top": [ {"flow": str, "packets": int, "bytes": int} ],   # when top>0
}
```

Timestamp helper (GUI tables):
```python
iso_ts(ns) -> str   # "2026-11-06T12:00:00.123456Z" or "" for None; always UTC
```

---

## 3. Chunk sets and manifests

```python
class ChunkSet(NamedTuple):
    folder: str
    manifest: dict | None      # raw manifest (schema 1 or 2), or None
    names: list[str]           # ordered chunk file names
    merged_name: str           # suggested output name
    sha256: str | None         # expected final hash (manifest only)
    chunks: list[dict]         # per-chunk dicts: file, bytes, packets,
                               # sha256?, first_ts_ns?, last_ts_ns?,
                               # first_packet?, last_packet?
```
```python
discover_chunks(folder) -> ChunkSet                 # raises PcapError
default_outdir(path) -> str
default_merge_output(folder) -> str
existing_chunk_files(folder, stem=None, ext=None) -> list[str]
    # files a new split would replace: manifest-listed chunks plus files
    # matching this split's own <stem>_<id><ext> / <stem>_<time>_<id><ext>
    # names. When stem is None, return every manifest/pattern chunk in folder.
chunk_matches_name_style(name) -> bool               # for tests/GUI
```

Manifest schema 2 (written by v2):

```json
{
  "schema": 2, "tool": "PcapChunk", "version": "2.0.0",
  "created": "2026-11-06T12:00:00Z",
  "status": "complete" | "incomplete",
  "source": "capture.pcap",
  "format": "pcap",
  "compressed": null,
  "size": 123456,
  "hash": "sha256",
  "sha256": "…",
  "mode": {"kind": "size", "value": 52428800},
  "naming": "index",
  "compression": null,
  "capture": {
    "linktype": 1, "snaplen": 65535, "precision": "usec",
    "interfaces": [{"id":0,"linktype":1,"snaplen":65535,"name":"eth0","tsresol":6}],
    "packets": 1234, "first_ts_ns": 0, "last_ts_ns": 0
  },
  "chunks": [
    {"index": 1, "file": "cap_0001.pcap", "bytes": 52428824,
     "raw_bytes": 52428824, "packets": 300, "sha256": "…",
     "first_ts_ns": 0, "last_ts_ns": 1, "first_packet": 0, "last_packet": 299,
     "offset": 0}
  ]
}
```
`bytes` is the on-disk size, `raw_bytes` the uncompressed size. `offset` is the
cumulative on-disk size of the preceding chunk files (0 for the first chunk);
`first_ts_ns`/`last_ts_ns` are the chunk's minimum and maximum packet
timestamps. `mode` always has `kind`, plus a `value` key (for `split_at` it is
a sorted list of seconds-of-day). Schema 1 manifests (v1:
`source, format, size, sha256, chunks[{file,bytes,packets}]`) are read but never
written.

`SHA256SUMS` is written next to the manifest in `sha256sum` format
(`<hex>  <filename>\n`, LF, chunk files and `manifest.json` included, sorted by
file name). Only written when the hash algorithm is sha256.

---

## 4. Split

```python
split_steps(path, outdir=None, size=None, packets=None, chunks=None, *,
            every=None, gap=None, split_at=None, local_time=False,
            target=None, force=False, resume=False, compress=None,
            name_style="index", hash_name="sha256", index_csv=None,
            dry_run=False, salvage=False, space_check=True,
            max_record=None) -> generator
split(...) -> dict
```
- Exactly one of `size` (bytes), `packets`, `chunks`, `every` (seconds),
  `gap` (seconds), `split_at` (list like `["02:00", "14:30:15"]`), or
  `target` (key of `PRESETS`) may be given. None => `size=50<<20`.
- `compress`: `None | "gzip" | "zstd"` (zstd only when `compression.zstd`
  exists; otherwise `PcapError`). Applies to chunks, not the manifest.
- `name_style`: `"index"` => `stem_0001.ext`; `"time"` =>
  `stem_YYYYMMDDTHHMMSS-YYYYMMDDTHHMMSS_0001.ext` (UTC, first/last packet of
  the chunk). The `.ext` keeps the source extension and appends `.gz`/`.zst`
  when compressing.
- Rotation modes:
  - `size`: rotate before a packet that would exceed `size` uncompressed
    bytes including the per-chunk header prefix; a single packet larger than
    the limit still gets a chunk of its own.
  - `packets`: exact count per chunk.
  - `chunks`: exactly `chunks` chunks, byte-proportional boundaries.
  - `every`: epoch-aligned buckets (a 1 h period starts chunks at :00).
  - `gap`: rotate when the gap since the previous packet is >= `gap`.
  - `split_at`: rotate when the timestamp crosses one of the daily wall-clock
    times, UTC unless `local_time=True`.
- `dry_run=True` scans and returns the plan; no files, no staging, no lock.
- `resume=True`: reuse `.pcapchunk-staging` from an interrupted run of the same
  source, after verifying the already-written chunk hashes. Ignored when no
  usable staging state exists. With `resume=True` a cancelled or failed run
  keeps its staging folder (a journal is written on every closed chunk) so the
  next `--resume` continues; without `resume` staging is always removed.
- `force=True` allows replacing an existing chunk set in `outdir`.
- Writes into `outdir/.pcapchunk-staging/`, promotes on success, leaves
  `.pcapchunk-incomplete` in `outdir` until promotion completes. Cancellation
  (`gen.close()`) never touches the previous set.
- Per-chunk `first_ts_ns`/`last_ts_ns` are the minimum and maximum packet
  timestamps in that chunk.
- `space_check=True` raises `PcapError` when free space is clearly insufficient.

Yields `(done, total)`; `total` is `0` when the logical size is unknown
(gzip). Return summary:

```
{"input": str, "outdir": str, "format": str, "size": int,
 "sha256": str|None, "chunks": int, "packets": int, "bytes": int,
 "dry_run": bool, "plan": [ ...chunk dicts... ] | None,
 "index_csv": str|None}
```

---

## 5. Merge

```python
merge_steps(folder, output=None, force=False, verify=True,
            allow_missing=False, salvage=False) -> generator
merge(...) -> dict
```
- Verifies each chunk's recorded hash while reading it (schema 2), and the
  final whole-file hash at the end. `verify=False` skips both.
- `.part` output, atomic replace, cleanup on cancel.
- `allow_missing=True`: merge the chunks that exist, in numeric order; the
  result is explicitly reported as incomplete and is never hash-verified.
- `salvage=True`: tolerate a truncated final chunk/record.
- Accepts v1 manifests and manifest-less chunk folders.

Return:
```
{"folder","output","chunks","size","verified": bool|None,
 "complete": bool, "missing": [str], "schema": int|None}
```

---

## 6. Verify

```python
verify_steps(folder, deep=False) -> generator
verify(folder, deep=False) -> dict
```
Yields `(done, total)` over chunk bytes. Never modifies anything. Return:
```
{"folder", "ok": bool, "schema": int|None, "manifest": bool,
 "problems": [str], "chunks": [
   {"file", "ok", "bytes", "expected_bytes", "packets", "expected_packets",
    "sha256", "expected_sha256", "first_ts_ns", "last_ts_ns",
    "problems": [str]}],
 "missing": [str], "incomplete": bool, "warnings": [str]}
```
`deep=True` additionally parses each chunk to EOF, checks framing, packet
counts and timestamp ranges against the manifest. `ok` is false when
`manifest.json` is absent (nothing can be verified), when a chunk is missing or
corrupt, or when the set is marked incomplete. `warnings` carries non-fatal
notes such as a schema-1 manifest without per-chunk hashes.

---

## 7. Transformations

All accept `salvage=False`, write `.part` then replace, and support
cancellation. `filter_spec` (see §8) selects packets; `None` means all.

```python
trim_steps(path, output, *, from_ts=None, to_ts=None, first=None, last=None,
           filter_spec=None, out_format=None, precision=None,
           salvage=False) -> generator
trim(...) -> dict
```
`from_ts`/`to_ts` are epoch seconds (float/int, inclusive from, exclusive to)
or ISO-8601 strings. `first`/`last` are packet counts. `out_format` defaults to
the input format; `precision` (`"usec"|"nsec"`) only affects pcap output.

```python
convert_steps(path, output, *, out_format="pcapng", precision=None,
              filter_spec=None, salvage=False) -> generator
convert(...) -> dict
```
pcap -> pcapng: one interface. pcapng -> pcap: requires all interfaces to share
one link type (else `PcapError`). Multi-interface timestamp resolution is
preserved for pcapng output; pcap output uses `precision` (default usec).

```python
combine_steps(paths, output, *, sort=False, dedupe=False, out_format=None,
              salvage=False) -> generator
combine(...) -> dict
```
- `sort=True`: k-way merge assuming each input is time-ordered; a
  non-monotonic input raises `PcapError`.
- `dedupe=True`: drop a packet identical (timestamp, captured bytes) to the
  previously emitted one. With `sort=True` this removes cross-capture
  duplicates; without sorting it only removes adjacent duplicates.
- Default output: pcap when every input is pcap with a byte-identical global
  header, otherwise pcapng (one output interface per distinct source
  interface).

```python
demux_steps(path, outdir, *, max_flows=500, filter_spec=None,
            salvage=False) -> generator
demux(...) -> dict
```
One file per bidirectional flow plus `flows.csv`:
`flow_0001.<ext>`, `flow_0000_other.<ext>` for undecodable packets. The output
format matches the input; pcap output requires a single link type, otherwise
use a pcapng input. Return `{"input","outdir","flows","packets","bytes","csv"}`.

Transform summaries: `{"input"|"inputs", "output","format","packets","bytes",
"size","filtered": bool}`.

---

## 8. Filtering and flow decoding

```python
FILTER_KEYS = ("host", "src", "dst", "port", "sport", "dport", "proto")
```
`filter_spec` is a dict with any of those keys; values are a scalar or a list
of scalars. `host`/`src`/`dst` are IP strings; `port`/`sport`/`dport` are ints;
`proto` is `"tcp"`, `"udp"`, `"icmp"`, `"ip"`, or a numeric protocol. Keys are
ANDed, lists inside a key are ORed. Packets that cannot be decoded never match.

Supported link types for decoding: 1 (Ethernet, with VLAN tags), 0 (NULL),
101/12 (raw IP), 113 (Linux SLL), 228 (IPv4), 229 (IPv6). Others are
"undecodable" (no filter match, demuxed into the `other` file).

---

## 9. CLI

```
pcapchunk [--version] [-v|--verbose] [-q|--quiet] [--json] <command> ...

split INPUT [-o DIR] (-s/--size SIZE | -n/--chunks N | -p/--packets N
      | --every DUR | --gap DUR | --split-at TIMES | --target PRESET)
      [--compress {none,gzip,zstd}] [--name-style {index,time}] [--resume]
      [--force] [--dry-run] [--index CSV] [--salvage] [--no-space-check]
      [--local-time]
merge FOLDER [-o FILE] [--force] [--no-verify] [--allow-missing] [--salvage]
verify FOLDER [--deep]
info PATH [--top N]
trim INPUT -o OUTPUT [--from TS] [--to TS] [--first N] [--last N]
      [--host H] [--src H] [--dst H] [--port P] [--sport P] [--dport P]
      [--proto P] [--format {pcap,pcapng}] [--precision {usec,nsec}] [--salvage]
convert INPUT -o OUTPUT [--format {pcap,pcapng}] [--precision ...] [filters]
combine INPUT... -o OUTPUT [--sort] [--dedupe] [--format ...] [--salvage]
demux INPUT -o DIR [--max-flows N] [filters] [--salvage]
```
- `SIZE` accepts `50M`, `512K`, `1G`, plain bytes. `DUR` accepts `30s`, `10m`,
  `2h`, plain seconds. `TIMES` is comma-separated `HH:MM[:SS]`. `TS` accepts
  ISO-8601 or epoch seconds.
- `split` defaults to `-s 50M` when no mode is given.
- Exit codes: `0` success, `1` error, `2` verify found problems.
- `--json` prints exactly one JSON object on stdout (summaries get
  `"ok": true`; errors `{"ok": false, "error": str}`). Warnings always go to
  stderr. Progress is never printed in `--json` mode.
- `--verbose` shows progress on stderr for CLI jobs; `--quiet` suppresses
  warnings.

---

## 10. GUI-facing guarantees

- Every `*_steps` generator yields `(done, total)` with `int` values; `total`
  can be `0` when unknown.
- `gen.close()` is safe at any yield point and leaves no partial output.
- The only state shared between GUI jobs and the engine is the filesystem.
- Nothing in the engine touches Tk; nothing in the GUI parses capture bytes.
- All user-facing errors are `PcapError` or `OSError` with complete messages.
