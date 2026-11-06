# PcapChunk

Split a packet capture into smaller chunks that each open on their own, verify
them later, and merge the pieces back into a file that is byte-for-byte
identical to the original.

PcapChunk is a single-file Python engine plus a Tkinter desktop app. It reads
classic libpcap (`.pcap`, both byte orders, microsecond and nanosecond
timestamps, plus the Kuznetzov variant) and pcapng (multiple sections and
interfaces) with the Python standard library only — no third-party runtime
dependencies, no threads, no network access.

---

## Why

Big captures are awkward to handle. They are slow to open in Wireshark, too
large for email or upload limits, and hard to archive or hand over. PcapChunk
cuts a capture into smaller files at packet boundaries. Every chunk carries the
headers it needs, so each one is a valid capture on its own.

- **Chunks are standalone.** Each chunk restates the pcap global header, or the
  pcapng section header and interface definitions it depends on. Open any chunk
  directly in Wireshark or tcpdump.
- **Merge is byte-identical.** Repeated headers are stripped again on merge, so
  the result equals the original capture exactly.
- **Integrity is built in.** v2 records a SHA-256 for every chunk and for the
  whole capture, plus a `SHA256SUMS` file, and verifies them on merge. v1 only
  had the whole-capture hash.
- **Safe by design.** Splitting writes into a staging folder and only promotes
  the new chunk set when it is complete. A cancelled or failed split never
  destroys a previous chunk set or unrelated files in the output folder.
- **No third-party runtime dependencies.** One less supply-chain surface for a
  tool that handles possibly sensitive packet data.

---

## Requirements

| What | Needs |
|---|---|
| Command line (`split`, `merge`, `verify`, `info`, `trim`, `convert`, `combine`, `demux`) | Python 3.8 or newer. Standard library only. |
| Desktop GUI | Python 3.8+, Tkinter (ships with the python.org installers; on Debian/Ubuntu install `python3-tk`) |
| Drag and drop *inside* the GUI window | Optional `tkinterdnd2` package; without it use the Browse buttons |
| zstd-compressed chunks (`--compress zstd`) | Python 3.14+ (stdlib `compression.zstd`); gzip always works |
| Building `PcapChunk.exe` | PyInstaller |

No network access is used at runtime, and the tool never transmits capture
data anywhere.

---

## Install and run

### From a checkout, no install

```bash
python -m pcapchunk --version        # engine + CLI
python -m pcapchunk split capture.pcap
python pcapchunk_gui.py              # GUI
```

### Installed as a package

```bash
python -m pip install .              # installs both console scripts
pcapchunk --version
pcapchunk split capture.pcap
pcapchunk-gui
```

Or install in editable mode with the development extra (PyInstaller):

```bash
python -m pip install -e ".[dev]"
```

### Packaged executable

Build the `dist/PcapChunk/` folder (see
[Building a portable executable](#building-a-portable-executable)) and run
`PcapChunk.exe` inside it, or run it from a terminal. The executable is the GUI,
windowed (no console). The command line lives in `pcapchunk.py`; run it with
Python, or build your own console executable from it if needed.

---

## Command line

```
pcapchunk [--version] [-v|--verbose] [-q|--quiet] [--json] <command> ...
```

### Global options

| Option | Meaning |
|---|---|
| `--version` | Print the version (`2.0.0`) and exit. |
| `-v`, `--verbose` | Show progress on stderr for CLI jobs. |
| `-q`, `--quiet` | Suppress warnings. |
| `--json` | Print exactly one JSON object on stdout. Progress is never printed in this mode; warnings still go to stderr. |

---

### `split`

Split a capture into chunks.

```
pcapchunk split INPUT [-o DIR] (-s SIZE | -n N | -p N | --every DUR | --gap DUR
      | --split-at TIMES | --target PRESET)
      [--compress {none,gzip,zstd}] [--name-style {index,time}] [--resume]
      [--force] [--dry-run] [--index CSV] [--salvage] [--no-space-check]
      [--local-time]
```

Exactly one rotation mode must be given. With no mode, `split` behaves like
`-s 50M`.

Output defaults to `<capture>_chunks/` next to the input. Chunk names default to
`<stem>_0001.<ext>`, `<stem>_0002.<ext>`, … following the source order.

| Mode | Flag | Example | Behaviour |
|---|---|---|---|
| Size | `-s`, `--size` | `-s 50M` | Rotate before a packet would push the chunk past the size (uncompressed, including the per-chunk header). A single packet larger than the limit still gets a chunk of its own. |
| Packets | `-p`, `--packets` | `-p 100000` | Exactly N packets per chunk (the last chunk may be shorter). |
| Chunks | `-n`, `--chunks` | `-n 8` | Exactly N chunks with byte-proportional boundaries. |
| Time period | `--every` | `--every 1h` | Epoch-aligned buckets: a one-hour period starts chunks at `:00`. Good for "one file per hour of capture". |
| Session gap | `--gap` | `--gap 30s` | Start a new chunk when the gap since the previous packet is at least the given duration. Good for separating sessions or bursts. |
| Wall clock | `--split-at` | `--split-at 02:00,14:30:15` | Start a new chunk whenever a packet crosses one of these daily times. Times are UTC by default; add `--local-time` to interpret them in the machine's local timezone. |
| Preset | `--target` | `--target email` | Shortcut for a well-known size limit (see [presets](#presets)). |

#### Presets

| Name | Size |
|---|---|
| `email` | 20 MiB |
| `upload` | 100 MiB |
| `fat32` | 4 GiB − 1 byte (largest file a FAT32 volume accepts) |
| `telegram` | 1900 MiB |
| `dvd` | 4,700,000,000 bytes |

#### Compression

`--compress gzip` or `--compress zstd` compresses the **chunk files**, not the
manifest. The default is `--compress none` (uncompressed chunks). Chunk names
get the matching suffix: `capture_0001.pcap.gz`, `capture_0002.pcap.zst`, and
so on. gzip is always available; zstd requires Python 3.14+ (stdlib
`compression.zstd`) and otherwise fails with an error. Every gzip/zstd chunk is
still a standalone capture once decompressed, and the manifest records both the
on-disk size (`bytes`) and the uncompressed size (`raw_bytes`).

#### Naming styles

| Style | Flag | Chunk names |
|---|---|---|
| Index (default) | `--name-style index` | `capture_0001.pcap` |
| Time | `--name-style time` | `capture_20261106T120000-20261106T130000_0001.pcap` (UTC timestamps of the chunk's first and last packet, plus the numeric index) |

With compression, the capture extension is kept and `.gz` or `.zst` is
appended.

#### Dry run

`--dry-run` scans the capture and reports the split plan without writing
anything: no chunks, no manifest, no staging folder, no lock. The summary is
returned as usual (or printed as JSON with `--json`), with the plan included
and `"dry_run": true`.

#### Resume

`--resume` reuses `.pcapchunk-staging/` left behind by an interrupted run of the
same source, after verifying the hashes of the chunks already written. If no
usable staging state exists (completed run, different source, damaged staging),
the flag is simply ignored and the split starts from scratch. See
[Resume semantics](#resume-semantics).

#### Replacing an existing chunk set

If the output folder already contains chunk files, `split` refuses to proceed
unless you pass `--force`. `--force` replaces the chunk set that belongs to
this split; unrelated files in the folder are left alone. The old set is not
deleted before the new set has been promoted, so an interrupted `--force` split
does not lose the previous chunks.

#### Other options

| Option | Meaning |
|---|---|
| `--index CSV` | Also write a CSV index of the split plan (header plus one row per chunk: index, file, sizes, packets, timestamps, packet range, SHA-256). |
| `--local-time` | Interpret `--split-at` times in the machine's local timezone instead of UTC. |
| `--salvage` | Tolerate a truncated final packet/block instead of failing. |
| `--no-space-check` | Skip the free-space pre-check (for unusual filesystems or network shares). |

#### Split examples

```bash
# 50 MiB chunks (default), into ./capture_chunks/
pcapchunk split capture.pcap

# 100 MiB chunks into a chosen folder
pcapchunk split capture.pcap -s 100M -o D:\captures\chunks

# Eight roughly equal pieces, and a CSV plan
pcapchunk split capture.pcap -n 8 --index capture_chunks.csv

# One file per hour, gzip-compressed, named by time range
pcapchunk split long_run.pcap --every 1h --compress gzip --name-style time

# New chunk after 30 s of silence
pcapchunk split session.pcap --gap 30s

# Rotate at 02:00 and 14:30 UTC every day
pcapchunk split week.pcap --split-at 02:00,14:30

# Rotate at 02:00 local time every day
pcapchunk split week.pcap --split-at 02:00 --local-time

# Fit under a mail limit, then inspect the plan without writing anything
pcapchunk split capture.pcap --target email --dry-run

# Continue an interrupted split
pcapchunk split capture.pcap -s 50M --resume
```

---

### `merge`

Merge a chunk folder back into one capture.

```
pcapchunk merge FOLDER [-o FILE] [--force] [--no-verify] [--allow-missing] [--salvage]
```

- Output defaults to `<folder>/<original name>` (from the manifest, or from the
  chunk names when there is no manifest).
- Each chunk's recorded SHA-256 is verified while it is read, and the final
  whole-file SHA-256 is checked against the manifest at the end (schema 2). v1
  manifests only provide the whole-file hash, so that is what gets checked.
- The merged file is written as `<output>.part` and atomically renamed on
  success. Cancelling or failing removes the partial file.
- `--no-verify` skips both the per-chunk and final hash checks.
- `--allow-missing` merges the chunks that do exist, in numeric order, and
  reports the result as incomplete. Such an output is never hash-verified.
- `--salvage` tolerates a truncated final chunk/record.
- `--force` overwrites an existing output file.

```bash
pcapchunk merge capture_chunks
pcapchunk merge capture_chunks -o restored.pcap
pcapchunk merge damaged_set --allow-missing --force
```

---

### `verify`

Check a chunk folder without modifying anything.

```
pcapchunk verify FOLDER [--deep]
```

The default check confirms that every manifest-listed chunk is present, then
checks each chunk's size, packet count, and SHA-256 against the manifest.

`--deep` additionally parses every chunk to end-of-file: record/block framing,
packet counts, and timestamp ranges are compared with the manifest. Use it when
you suspect a chunk was truncated or edited rather than simply corrupted.

Output lists per-chunk results plus a list of problems and missing files.
`verify` never writes, deletes, or renames anything.

Exit codes: `0` clean, `2` problems found, `1` error (e.g. folder unreadable).
That makes it usable in scripts and CI:

```bash
pcapchunk verify capture_chunks || echo "chunk set is damaged"
```

See [Verify workflow](#verify-workflow) for the recommended full procedure.

---

### `info`

Header and statistics for one capture, with no splitting.

```
pcapchunk info PATH [--top N]
```

Prints the format, compression, on-disk and logical size, precision, link type,
snaplen, interfaces, packet count, byte count, first/last timestamp, duration,
and — with `--top N` — the N busiest flows. pcapng captures list each interface
(link type, snaplen, name, timestamp resolution, packet count).

```bash
pcapchunk info capture.pcap
pcapchunk info big.pcapng --top 10
```

The scan reports progress on stderr when `-v` is used, and can be cancelled
with Ctrl+C.

---

### `trim`

Copy a slice of a capture to a new file.

```
pcapchunk trim INPUT -o OUTPUT [--from TS] [--to TS] [--first N] [--last N]
      [--host H] [--src H] [--dst H] [--port P] [--sport P] [--dport P]
      [--proto P] [--format {pcap,pcapng}] [--precision {usec,nsec}] [--salvage]
```

- `--from` is inclusive, `--to` is exclusive. Both accept ISO-8601 strings or
  epoch seconds (for example `2026-11-06T12:00:00Z` or `1793966400.0`).
- `--first N` / `--last N` take packet counts instead of times.
- `--format` sets the output format (default: same as the input);
  `--precision usec|nsec` sets the pcap timestamp precision.
- Filter flags (see [Filters](#filters)) keep only matching packets.
- The output is written as `.part` and renamed on success; cancel leaves
  nothing behind.

```bash
pcapchunk trim capture.pcap -o noon.pcap --from 2026-11-06T12:00:00Z --to 2026-11-06T13:00:00Z
pcapchunk trim capture.pcap -o first10k.pcap --first 10000
pcapchunk trim capture.pcap -o web.pcap --host 10.0.0.5 --port 443 --format pcapng
```

---

### `convert`

Convert between pcap and pcapng.

```
pcapchunk convert INPUT -o OUTPUT [--format {pcap,pcapng}] [--precision ...] [filters]
```

Defaults to pcapng output. pcap → pcapng creates a single interface. pcapng →
pcap is only possible when every interface in the input shares one link type;
otherwise the tool stops with an error (convert to pcapng, or demux, instead).
Multi-interface timestamp resolution is preserved in pcapng output; pcap output
uses `--precision` (default `usec`).

```bash
pcapchunk convert capture.pcap -o capture.pcapng
pcapchunk convert capture.pcapng -o capture.pcap --format pcap --precision nsec
pcapchunk convert capture.pcap -o dns.pcapng --proto udp --port 53
```

---

### `combine`

Combine several captures into one file.

```
pcapchunk combine INPUT... -o OUTPUT [--sort] [--dedupe] [--format ...] [--salvage]
```

- `--sort` performs a k-way merge, assuming each input is already ordered by
  time. A non-monotonic input is an error.
- `--dedupe` drops a packet identical (same timestamp and captured bytes) to
  the previously emitted one. With `--sort` that removes duplicates across
  captures; without it, only adjacent duplicates inside the stream are
  removed.
- Output defaults to pcap when every input is pcap with a byte-identical global
  header, otherwise pcapng (one output interface per distinct source
  interface).

```bash
pcapchunk combine day1.pcap day2.pcap day3.pcap -o week.pcapng --sort --dedupe
pcapchunk combine tap0.pcap tap1.pcap -o both.pcapng
```

`combine` has no packet-filter flags of its own; run `trim` or `convert` first
if you need to select packets before combining.

---

### `demux`

Split a capture into one file per bidirectional flow.

```
pcapchunk demux INPUT -o DIR [--max-flows N] [filters] [--salvage]
```

Writes `flow_0001.<ext>`, `flow_0002.<ext>`, … for each flow, plus
`flow_0000_other.<ext>` for packets that cannot be decoded, and a `flows.csv`
index. `--max-flows` (default 500) caps the number of per-flow files.

```bash
pcapchunk demux capture.pcap -o flows/
pcapchunk demux capture.pcap -o flows/ --max-flows 2000 --proto tcp
```

---

### Filters

`trim`, `convert`, and `demux` accept the same packet filter flags:

| Flag | Value |
|---|---|
| `--host H` | Either endpoint IP address |
| `--src H`, `--dst H` | Source / destination IP address |
| `--port P` | Either endpoint port |
| `--sport P`, `--dport P` | Source / destination port |
| `--proto P` | `tcp`, `udp`, `icmp`, `ip`, or a numeric protocol |

Every value may be a comma-separated list, for example
`--src 10.0.0.5,10.0.0.6` or `--port 80,443`. Different flags are ANDed;
values inside one flag are ORed. Packets that cannot be decoded (unsupported
link type, non-IP, fragment beyond the first) never match a filter.

Supported link types for decoding: Ethernet (1, including VLAN tags), NULL (0),
raw IP (101 and 12), Linux SLL (113), IPv4 (228), IPv6 (229). Other link types
are copied through unchanged when no filter is active, and land in the `other`
file on demux.

```bash
pcapchunk trim capture.pcap -o https.pcap --host 10.0.0.5 --proto tcp --port 443
pcapchunk demux capture.pcap -o flows/ --src 10.0.0.5 --sport 53
```

---

### Sizes, durations, timestamps

| Kind | Accepted forms |
|---|---|
| Size (`-s`, `--target` uses presets) | `50M`, `512K`, `1G`, `1.5G`, or plain bytes (`1048576`); 1024-based |
| Duration (`--every`, `--gap`) | `30s`, `10m`, `2h`, `1d`, or plain seconds (`90`); `ms` also accepted |
| Split times (`--split-at`) | Comma-separated `HH:MM` or `HH:MM:SS`; UTC unless `--local-time` |
| Timestamps (`--from`, `--to`) | ISO-8601 (`2026-11-06T12:00:00Z`) or epoch seconds (`1793966400`) |

---

### Exit codes and `--json`

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error (bad input, corrupt capture, I/O failure, unsupported option) |
| `2` | `verify` found problems |

`--json` prints exactly one JSON object on stdout per invocation. Successful
summaries carry `"ok": true`; failures are `{"ok": false, "error": "..."}`.
`verify` is the exception: its JSON object is the full verification report with
an `"ok"` boolean, and the exit code is `0` or `2` accordingly. Warnings always
go to stderr, and progress is never printed in JSON mode, so the stdout stream
can be piped straight into `jq` or a script.

```bash
pcapchunk --json verify capture_chunks
pcapchunk --json split capture.pcap -s 100M | jq .chunks
```

---

## What a chunk folder looks like

```
capture_chunks/
├── capture_0001.pcap
├── capture_0002.pcap
├── capture_0003.pcap
├── ...
├── manifest.json              # schema 2: source, capture info, chunk list + hashes
├── SHA256SUMS                 # sha256sum format checksums for the chunks + manifest
├── .pcapchunk-incomplete      # present only while the set is not final
└── .pcapchunk-staging/        # only during an active or interrupted split
```

The dot-files are working state, not part of the finished set: `.pcapchunk-staging/`
holds chunks until a split succeeds and is promoted; `.pcapchunk-incomplete`
marks a folder whose set is not final. A `.pcapchunk.lock` file (also temporary)
prevents two jobs from writing the same folder at the same time.

Chunk order is the order listed in `manifest.json` (or the numeric file-name
order for sets without a manifest).

### `manifest.json` (schema 2)

```json
{
  "schema": 2,
  "tool": "PcapChunk",
  "version": "2.0.0",
  "created": "2026-11-06T12:00:00Z",
  "status": "complete",
  "source": "capture.pcap",
  "format": "pcap",
  "compressed": null,
  "size": 104857600,
  "hash": "sha256",
  "sha256": "0b6f...e4c1",
  "digest": "0b6f...e4c1",
  "mode": {"kind": "size", "value": 52428800},
  "naming": "index",
  "compression": null,
  "capture": {
    "linktype": 1,
    "snaplen": 65535,
    "precision": "usec",
    "interfaces": [
      {"id": 0, "linktype": 1, "snaplen": 65535, "name": "eth0",
       "tsresol": 6, "section": 1}
    ],
    "packets": 123456,
    "first_ts_ns": 1793966400000000000,
    "last_ts_ns": 1793969999000000000
  },
  "chunks": [
    {
      "index": 1,
      "file": "capture_0001.pcap",
      "bytes": 52428824,
      "raw_bytes": 52428824,
      "packets": 61000,
      "sha256": "9f2c...77aa",
      "offset": 0,
      "first_packet": 0,
      "first_ts_ns": 1793966400000000000,
      "last_ts_ns": 1793967800000000000,
      "last_packet": 60999,
      "compressed": null
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `schema` | `2` for v2 chunk sets; v1 sets have `1` and are read but never written by v2. |
| `status` | `complete` for a finished set. A value of `incomplete` means the set is not final. |
| `source`, `format`, `compressed`, `size` | Original file name, capture format, source compression (`null` or `gzip`), source size in bytes. |
| `hash`, `sha256`, `digest` | Hash algorithm name (`sha256`), the whole-capture SHA-256 (`null` when the algorithm is not SHA-256), and `digest` — always the hex digest for the recorded algorithm. |
| `mode` | Rotation mode and its parameter, for example `{"kind": "size", "value": 52428800}`. |
| `naming` | Chunk name style, `index` or `time`. |
| `compression` | Chunk compression: `null`, `gzip`, or `zstd`. |
| `capture` | Header/statistics of the source: link type, snaplen, timestamp precision, pcapng interfaces (with their `section` number), packet count, first/last timestamp in ns. |
| `chunks[].bytes` / `raw_bytes` | On-disk chunk size / uncompressed size (they differ when chunks are compressed). |
| `chunks[].sha256` | SHA-256 of the chunk's uncompressed capture bytes (what `merge`/`verify` check). `SHA256SUMS` instead lists on-disk hashes, so `sha256sum -c` works on compressed chunks too. |
| `chunks[].compressed` | Compression applied to this chunk file (`null`, `gzip`, or `zstd`). |
| `chunks[].first_ts_ns`, `last_ts_ns` | Minimum/maximum packet timestamps in the chunk, in nanoseconds. |
| `chunks[].first_packet`, `last_packet` | Global packet index range covered by the chunk. |
| `chunks[].offset` | Cumulative on-disk size of the preceding chunk files (`0` for the first chunk) — where this chunk starts if the chunk files are concatenated. |

Timestamps in the manifest are integer nanoseconds; `created` is ISO-8601 UTC.

### `SHA256SUMS`

Written next to the manifest in standard `sha256sum` format
(`<hex>  <filename>`, LF endings), covering every chunk file plus
`manifest.json`, sorted by file name. It is only written when the hash
algorithm is sha256.

```text
9f2c...77aa  capture_0001.pcap
41d0...1183  capture_0002.pcap
0b6f...e4c1  manifest.json
```

Check it with the tools you already have:

```bash
cd capture_chunks && sha256sum -c SHA256SUMS         # Linux / macOS
certutil -hashfile capture_0001.pcap SHA256          # Windows, one file at a time
```

`SHA256SUMS` detects accidental corruption, not malicious tampering: it is not
signed, so anyone who can rewrite the chunks can rewrite the checksums too.

### Chunk overhead

Every chunk repeats its share of capture headers. For classic pcap that is the
24-byte global header per chunk. For pcapng it is the section header block plus
the interface description blocks a chunk depends on — typically tens to a few
hundred bytes per chunk, depending on how many interfaces exist.

Manifest and checksum files add roughly a few hundred bytes per chunk. For
example, a 4 GiB capture split into 50 MiB chunks yields about 82 chunks, so the
total overhead is on the order of tens of kilobytes — a fraction of one percent.
Overhead only becomes noticeable when you ask for tiny chunks relative to the
capture, or when a single packet is larger than the size limit (that packet
still gets a chunk of its own, which can exceed the requested size).

The merged result contains none of this overhead and is byte-for-byte identical
to the original capture.

---

## Verify workflow

A complete round-trip check of a chunk set:

```bash
# 1. Structural check: files present, sizes, packet counts, per-chunk hashes.
pcapchunk verify capture_chunks

# 2. Deep check: parse every chunk to EOF and compare framing, counts, timestamps.
pcapchunk verify capture_chunks --deep

# 3. Optional, independent of PcapChunk (from inside the chunk folder):
cd capture_chunks && sha256sum -c SHA256SUMS && cd ..

# 4. Merge and let the final whole-capture hash be checked against the manifest.
pcapchunk merge capture_chunks -o restored.pcap

# 5. Compare with the original if you still have it.
sha256sum restored.pcap capture.pcap
```

`verify` exit code `2` means one or more problems were found; the output names
the affected chunk files. Common causes: a chunk was truncated while copying,
one was edited, or a chunk from another capture set was mixed in. Restoring the
missing or damaged chunk from a backup is usually easier than re-splitting, but
re-splitting the original and running `verify` again is always safe.

`verify` is read-only. Feel free to run it on sets of unknown provenance before
merging them.

---

## Resume semantics

Splitting is crash-safe:

1. The split writes new chunks into `outdir/.pcapchunk-staging/`.
2. On success, the staged chunks are promoted into `outdir` and the
   `.pcapchunk-incomplete` marker is removed once promotion completes.
3. On cancellation or error, the staging folder is removed and the previously
   existing chunk set is untouched.

If the process is killed mid-split, the staging folder and the
`.pcapchunk-incomplete` marker remain. Re-running the same command with
`--resume` checks the hashes of the chunks already in staging and continues
from the first missing packet. Without `--resume`, the leftover staging folder
is ignored/cleaned and the split starts over.

Caveats:

- `--resume` only helps for the same source file and the same split settings;
  a different source or mode means the staging state is not reusable and the
  flag is ignored.
- Do not edit, move, or "fix" files inside `.pcapchunk-staging/` yourself.
- Resuming a split that already completed has nothing to do (the staging folder
  is gone); the flag is harmless.

---

## GUI

`pcapchunk-gui` (or the packaged `PcapChunk.exe`) is a Tkinter desktop app with
the same engine underneath. Jobs run in short slices from the Tk event loop —
no threads — so the window stays responsive and **Cancel** stops a job cleanly
(leaving no partial output).

| Tab | What it does |
|---|---|
| **Split** | One input or a batch queue of captures; output folder; modes: size, chunks, packets, every, gap, split-at; presets; gzip/zstd compression; index/time naming; resume; dry-run plan preview; index CSV; force confirmation. |
| **Merge** | Chunk folder, output file, verify on/off, allow-missing for damaged sets. |
| **Verify** | Chunk folder, optional deep check, a table of chunks (index, file, size, packets, time range, hash ok/fail) and an overall verdict. |
| **Tools** | `info`/statistics for a capture with progress, convert pcap ↔ pcapng, trim by time/first/last and simple host/port/proto filters. |

Shared features:

- **Chunk table** with *Open chunk*, *Open in Wireshark* (auto-detected or a
  configured path), and *Open folder*.
- **Drag and drop**: dropping files or folders into the window works when the
  optional `tkinterdnd2` package is installed
  (`python -m pip install tkinterdnd2`). Without it the GUI works normally but
  you select files with the Browse buttons.
- **Settings** (window geometry, theme, last folders, last mode, Wireshark
  path) are remembered per user, and recent files are listed in a menu.
- **Theme** switch (system / clam / dark), DPI handling, keyboard shortcuts,
  and an About dialog showing the engine version.

The GUI uses `assets/icon.ico` when it is present. If you build your own
executable, make sure the `assets` folder ships with it (the bundled
`PcapChunk.spec` does this).

You can pass a capture or a chunk folder on the command line
(`pcapchunk-gui capture.pcap`, or `python pcapchunk_gui.py capture_chunks`), and
dropping a file or folder onto `PcapChunk.exe` does the same: the matching tab
opens with it loaded.

---

## Compatibility with v1 chunk folders

v2 reads everything v1 produced:

- **v1 manifests (schema 1)** are read but never written. Fields:
  `source`, `format`, `size`, `sha256`, `chunks[{file, bytes, packets}]`.
- **Manifest-less chunk folders** still merge: files are recognized by the
  `<name>_<id>.<ext>` pattern, ordered numerically, and a gap in the numbering
  is an error.
- v1 sets have no per-chunk SHA-256, so `verify` can only check what the
  manifest records (presence, size, packet counts). The whole-capture hash in a
  v1 manifest is still verified on merge.
- v1 chunks merge to the same byte-identical output; merging an old set with v2
  is safe and does not rewrite the folder.

If you plan to keep using an old set, run `pcapchunk verify old_chunks` first
and keep the original capture until you have confirmed the merge.

---

## Sensitive captures

Packet captures routinely contain credentials, session cookies, personal data,
medical or financial records, and internal addresses. A chunk set is **more**
files with the same secret payloads, not fewer:

- Treat every chunk, the staging folder, and any `.part` leftovers as sensitive
  as the original capture.
- Delete a chunk set securely when it is no longer needed, including
  `.pcapchunk-staging/` and `.pcapchunk-incomplete`; keep only what you need.
- Prefer encrypted disks/archives for storage and transfer. The tool works
  entirely offline and never uploads anything, but any file you send elsewhere
  is out of its control.
- The manifest and `SHA256SUMS` reveal file names, sizes, packet counts, and
  hashes — metadata that can itself be sensitive. Review them before sharing.
- Do not commit captures or chunk folders to version control. The bundled
  `.gitignore` ignores `*.pcap`, `*.pcapng`, `*.cap`, `*.part`, and `*_chunks/`,
  but that is a convenience, not a security control.

---

## Building a portable executable

Build on the operating system you want to run it on; PyInstaller does not cross-
compile. `PcapChunk.spec` produces a **one-directory, windowed** build and uses
`assets/icon.ico` when present.

### One-directory build (the spec, recommended)

```bash
python -m pip install -e ".[dev]"     # installs PyInstaller
pyinstaller PcapChunk.spec
```

Output: `dist/PcapChunk/` (Windows: `dist/PcapChunk/PcapChunk.exe`; Linux and
macOS: `dist/PcapChunk/PcapChunk`). Ship the whole folder — zip it if you need a
single download. No console window; errors appear in dialogs/log panels.

A one-directory build starts faster, is less likely to be flagged by antivirus,
and needs **no temporary extraction directory**. That matters on locked-down
machines: the one-file bootloader unpacks itself into `%TEMP%` at launch and
fails with `could not create temp directory` when `%TEMP%` is read-only, denied
by policy, or sandboxed. If you hit that message with an older one-file build,
use this directory build instead.

### One-file build (optional, portable single .exe)

Only use this when you specifically need one file and the target machine has a
normal writable `%TEMP%`:

```bash
pyinstaller --onefile --windowed --name PcapChunk --icon assets/icon.ico --add-data "assets/icon.ico;assets" pcapchunk_gui.py
```

Linux / macOS: use `:` instead of `;` in `--add-data`, and drop `--icon` if the
file is not an `.ico`. Output: `dist/PcapChunk.exe` (or `dist/PcapChunk`). It
unpacks to `%TEMP%` on every launch, so it is slower to start and may be blocked
by antivirus or restrictive temp policies.

### Build notes

- No code signing is configured. Windows SmartScreen and some antivirus products
  may warn about unsigned binaries; see
  [Troubleshooting](#troubleshooting).
- `--windowed` only matters on Windows and macOS; the Linux build has no
  console regardless.
- If you include the optional drag-and-drop support, install `tkinterdnd2` in
  the build environment before running PyInstaller so the package is detected.
- UPX compression is enabled in the spec (`upx=True`) when UPX is available.

---

## Troubleshooting

### gzip-compressed input

v2 reads gzip-compressed captures transparently for `split`, `info`, and the
other read paths — you do **not** need to `gunzip` first. Progress totals may
show `0` (indeterminate) because the uncompressed size of a gzip stream is often
unknown; that is expected. If a tool tells you to decompress the file first,
you are looking at a v1 build or error message; upgrade to v2.

To produce gzip-compressed *chunks*, use `--compress gzip` (see
[Compression](#compression)).

### Truncated captures

A capture cut off mid-record (crash, full disk, killed `tcpdump`) can stop a
normal pass with an error about a truncated packet. Add `--salvage` to keep the
captured bytes of the final incomplete record/block instead of failing. Salvage
is supported by `split`, `merge`, `trim`, `convert`, `combine`, and `demux`.
Salvaged output is not byte-identical to what a complete capture would have
produced, so verify the result and keep the original.

### Antivirus flags the executable

PyInstaller one-file executables unpack themselves at launch, which looks
suspicious to some scanners and triggers false positives. Options:

- build the one-directory variant instead (see
  [One-directory build](#one-directory-build));
- add an allowlist exception for the build output;
- build locally from source you control, so you can verify what went into it.

There is no code signing; if you distribute binaries, sign them with your own
certificate.

### `... already contains chunk files ... use --force to replace them`

The output folder holds chunks (of this capture or another). Pick a different
folder, or pass `--force` to replace the chunk set. `--force` only replaces
chunks belonging to the split; unrelated files are preserved.

### `zstd` is unavailable

zstd-compressed chunks need Python 3.14 or newer (stdlib `compression.zstd`).
Use `--compress gzip` on older interpreters.

### SHA-256 mismatch when merging

A chunk is damaged or the folder mixes chunks from different sets. Run
`pcapchunk verify FOLDER` to see which file fails (add `--deep` for a full
parse), restore the bad chunk from a backup, or re-split the original capture.
As a last resort `--no-verify` merges without integrity checking; the output is
then of unknown correctness.

### The GUI does not start / `No module named tkinter`

Tkinter is missing. Use the python.org installer on Windows/macOS; on
Debian/Ubuntu install `python3-tk` (`sudo apt install python3-tk`). The CLI
works without Tkinter.

### Drag and drop does not work inside the window

That feature needs the optional `tkinterdnd2` package
(`python -m pip install tkinterdnd2`). Without it the GUI is fully functional;
use the Browse buttons instead. Dropping a capture or chunk folder onto
`PcapChunk.exe` still opens it in the right tab.

### Disk full during a split

The split pre-checks free space and stops early when the target is clearly too
small, leaving the previous set intact. If the check is too conservative for a
network share, `--no-space-check` skips it. Remove a stale
`.pcapchunk-staging/` folder to reclaim space from an interrupted run.

---

## Development

```bash
# Standard-library test suite (no third-party test dependencies)
python -m unittest discover -s tests -v

# Byte-compile check used by CI
python -m py_compile pcapchunk.py pcapchunk_gui.py
```

CI runs on Linux, Windows, and macOS with Python 3.9, 3.12, and 3.13
(`.github/workflows/ci.yml`). Tagging a release `v*` additionally builds a
PyInstaller artifact.
