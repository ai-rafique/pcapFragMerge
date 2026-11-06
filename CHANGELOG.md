# Changelog

All notable changes to PcapChunk are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

v1 had no changelog; the 2.0.0 entry below summarises the whole v2 effort
relative to the v1 scripts.

## 2.0.0 - 2026-11-06

PcapChunk v2 turns the v1 split/merge pair into a complete, verifiable chunking
tool: manifest schema 2 with per-chunk hashes, a `verify` command, crash-safe
staging, compressed chunks, time/session-based splitting, capture
transformations, and a rewritten GUI.

### Added

- **`verify` command** (`verify FOLDER [--deep]`): read-only structural check of
  a chunk set (presence, byte sizes, packet counts, per-chunk SHA-256), with
  `--deep` parsing every chunk to EOF to check framing, packet counts, and
  timestamp ranges. Exit code `2` when problems are found, so it can gate CI
  and scripts.
- **Manifest schema 2**: per-chunk SHA-256, on-disk and uncompressed sizes
  (`bytes` / `raw_bytes`), first/last timestamps, packet ranges, byte offsets,
  plus capture metadata (link type, snaplen, precision, interfaces, totals) and
  split settings (`mode`, `naming`, `compression`, `status`).
- **`SHA256SUMS`** in `sha256sum` format next to the manifest, covering every
  chunk file and `manifest.json`, so sets can be checked with standard tools.
- **Crash-safe splitting**: new chunks are written into
  `.pcapchunk-staging/` and promoted only on success; an
  `.pcapchunk-incomplete` marker stays in the output folder until the set is
  final; cancellation removes staging and leaves the previous set untouched; a
  `.pcapchunk.lock` file prevents two jobs from writing the same folder
  concurrently.
- **Resume**: `split --resume` reuses staging from an interrupted run of the
  same source after verifying the hashes of chunks already written; unusable
  staging is ignored.
- **Compressed chunks**: `--compress gzip|zstd` (zstd when the stdlib
  `compression.zstd` module exists), with `.gz`/`.zst` chunk names, on-disk and
  raw sizes recorded in the manifest.
- **New split modes** in addition to size/packets/chunks:
  - `--every DUR` — epoch-aligned time buckets (e.g. one file per hour);
  - `--gap DUR` — new chunk after a silence of at least the given duration;
  - `--split-at TIMES` — rotate when a packet crosses daily wall-clock times;
  - `--target PRESET` — `email`, `upload`, `fat32`, `telegram`, `dvd`.
- **Chunk name styles**: `--name-style index` (default) and `--name-style time`
  (UTC first/last packet timestamps in the file name).
- **`--dry-run`**: scan and report the split plan without writing chunks,
  staging, or a lock.
- **`--index CSV`**: write a CSV index of the split plan.
- **`--no-space-check`**: skip the free-space pre-check for unusual filesystems
  and network shares.
- **New commands**: `info` (header + statistics, with `--top N` flow table),
  `trim` (time/first/last/filter slices), `convert` (pcap ↔ pcapng),
  `combine` (with `--sort` and `--dedupe`), and `demux` (one file per
  bidirectional flow plus `flows.csv`).
- **Packet filters** for trim/convert/combine/demux: `--host`, `--src`, `--dst`,
  `--port`, `--sport`, `--dport`, `--proto`, with decoding for Ethernet
  (including VLAN), NULL, raw IP, Linux SLL, IPv4, and IPv6 link types.
- **CLI polish**: `--version`, `--json` (one machine-readable object on stdout;
  warnings on stderr), `--verbose` progress, `--quiet`, human-friendly
  `SIZE`/`DUR`/`TIMES`/`TS` parsing, and documented exit codes (`0` success,
  `1` error, `2` verify problems).
- **`--salvage`** for truncated captures across split, merge, trim, convert,
  combine, and demux.
- **Packaging and tooling**: `pyproject.toml` with the `pcapchunk` and
  `pcapchunk-gui` console scripts and an optional `dev` extra for PyInstaller;
  updated `PcapChunk.spec` (one-file windowed build, icon, UPX); multi-size
  `assets/icon.ico` + `assets/icon.png`; GitHub Actions CI (Ubuntu/Windows/
  macOS × Python 3.9/3.12/3.13) and a tag-triggered PyInstaller build artifact.
- **GUI rewrite**: tabs for Split (with batch queue, all split modes, presets,
  compression, naming, resume, dry-run preview, index CSV), Merge, Verify
  (chunk table with hash status), and Tools (info, convert, trim with filters);
  chunk table actions (open chunk / open in Wireshark / open folder); persistent
  settings and recent files; theme switch (system/clam/dark); DPI handling;
  keyboard shortcuts; About dialog showing the engine version. Still
  threadless (Tk `after` slices, cancel via `gen.close()`).
- **Optional in-window drag and drop** via `tkinterdnd2`, with a graceful
  fallback when the package is absent.
- **v2 unittest suite** (`tests/`) covering split/merge round-trips in every
  mode, manifests, hashes, verify, transformations, CLI, and malformed inputs.

### Changed

- CLI restructured into subcommands: `split`, `merge`, `verify`, `info`,
  `trim`, `convert`, `combine`, `demux`; global options come before the
  command. `split` with no mode still defaults to 50 MiB chunks.
- `merge` now verifies each chunk's recorded hash while reading (schema 2) and
  the final whole-file hash at the end; writes `OUTPUT.part` and atomically
  replaces the output; `--no-verify` skips both checks.
- `merge --allow-missing` merges the chunks that exist, reports the result as
  incomplete, and never hash-verifies it.
- Merging accepts v1 manifests (schema 1), v2 manifests, and manifest-less
  `<name>_<id>.<ext>` folders; v2 only ever writes schema 2.
- Chunk metadata and integrity data live entirely in `manifest.json` and
  `SHA256SUMS`; chunk files themselves stay valid standalone captures.
- Long operations remain generators that yield `(done, total)` and can be
  cancelled with `gen.close()` without leaving partial output; the GUI uses the
  same API as the CLI.
- Python 3.8+ and standard library only at runtime, with no runtime
  dependencies; PyInstaller and tkinterdnd2 are optional.

### Fixed

- **v1 data loss when re-splitting into a folder:** v1 deleted every existing
  chunk-pattern file in the output folder *before* writing the new chunks. An
  interrupted or failed split could therefore leave the folder without the
  previous chunk set. v2 stages the new set first and replaces the old one only
  after the new set is complete; the old set is never removed early.
- **v1 deleted files it did not own:** the old cleanup matched any
  `<name>_<digits>.<ext>` file (and any `manifest.json`) in the folder,
  including chunks of another capture or unrelated user files that happened to
  match. v2 only replaces manifest-listed chunks and files matching the current
  split's own naming, and leaves unrelated files alone.
- **v1 could not tell you which chunk was bad:** a corrupted chunk made merge
  fail on the final whole-file hash with no indication of the culprit. v2
  records per-chunk hashes and `verify` names the damaged or missing file.
- **v1 refused gzip-compressed captures** ("decompress it first"); v2 reads
  gzip sources transparently, with progress totals reported as unknown when the
  logical size cannot be determined.
- **v1 split left fragments/partial files behind on error or cancellation;**
  v2 removes staging on cancel and never promotes a partial set.
- **Merge output is atomic:** `.part` plus replace, so a failed merge never
  leaves a half-written file under the final output name.
- **Bounds checks on corrupt record/block lengths:** malformed or hostile
  captures that claim huge record sizes are rejected instead of triggering huge
  allocations.
- GUI jobs no longer leave partial output on Cancel; the rewritten tabs use the
  v2 `*_steps` generators consistently, so split, merge, verify, and tools all
  report progress and support cancellation.
- Corrected chunk-set discovery for v1 folders: numerical gap detection, mixed
  multiple-capture folders rejected with a clear message, and stable ordering
  from the manifest.

### Security

- **Integrity verification is now per chunk**, not only per merged file: any
  corrupted, truncated, swapped, or missing chunk is detected and named before
  it can silently end up in a merged capture.
- **Safe replacement semantics** remove the data-loss risk of re-splitting:
  a failed split cannot destroy a previously good chunk set, and `--force` only
  replaces the chunks the new split owns.
- **Verification works without the original capture** (checksums in the
  manifest/`SHA256SUMS`), and `verify` is strictly read-only, so sets of unknown
  provenance can be checked before use.
- **Hostile-input hardening**: inflated record/block lengths in corrupt captures
  are rejected with bounded reads rather than trusting declared sizes, and
  salvage mode only tolerates a truncated tail instead of disabling framing
  checks everywhere.
- **No third-party runtime dependencies**: the CLI and GUI need only the Python
  standard library (tkinterdnd2 is optional), keeping the supply-chain surface
  small for a tool that handles sensitive packet data.
- **Secrets guidance** documented: chunk sets multiply copies of sensitive
  payloads; `manifest.json` and `SHA256SUMS` reveal file names, sizes, and
  hashes. The README documents handling, deletion, and offline-only operation.
  `.gitignore` covers captures, chunk folders, staging, incomplete markers,
  lock files, and common tool artifacts to reduce accidental commits.
