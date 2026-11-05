# PcapFragMerge

Split a large packet capture into smaller pieces, and put the pieces back together later.

## Why

Big captures are awkward to handle. They're slow to open in Wireshark, too large for email or upload limits, and hard to share or archive. PcapChunk cuts a capture into smaller files that each open on their own. When you need the whole capture again, it merges the folder back into one file that is byte-for-byte identical to the original.

- Works with `.pcap` and `.pcapng`, including pcapng files with several interfaces or sections.
- Chunks are cut only between packets, and each one carries the headers it needs, so every chunk is a valid capture.
- Merging checks the result against the original's SHA-256, recorded at split time.
- Pure Python standard library: no third-party packages, no threads.

## Files

| File | What it is |
|---|---|
| `pcapchunk.py` | The engine, also usable from the command line |
| `pcapchunk_gui.py` | Desktop app (Tkinter) |

Keep both in the same folder.

## Using the app

Run `python pcapchunk_gui.py`, or the built `PcapChunk.exe`.

- **Split tab:** choose a capture, choose the output folder (defaults to `<name>_chunks` next to the capture), then split by max size in MB, number of chunks, or packets per chunk.
- **Merge tab:** choose the chunk folder. The merged file defaults to `<folder>/<original name>`.

Cancel stops the job and removes any partial output. You can also drop a capture or a chunk folder onto the `.exe` to open it in the right tab.

## Command line

```bash
python pcapchunk.py split capture.pcap -s 50M    # chunks of at most 50 MB (default)
python pcapchunk.py split capture.pcap -n 8      # 8 roughly equal chunks
python pcapchunk.py split capture.pcap -p 100000 # 100,000 packets per chunk
python pcapchunk.py split capture.pcap -o out/   # choose the output folder

python pcapchunk.py merge capture_chunks         # -> capture_chunks/capture.pcap
python pcapchunk.py merge capture_chunks -o restored.pcap
```

Add `-f` to overwrite existing output, or `--no-verify` to skip the checksum on merge.

## What a chunk folder looks like

```
capture_chunks/
├── capture_0001.pcap
├── capture_0002.pcap
├── ...
└── manifest.json      # original name, size, SHA-256, chunk list
```

Merging works without `manifest.json` too: chunks are ordered by their number, and a missing chunk is reported as an error. Without the manifest there is no checksum to verify against. Keep one capture's chunks per folder.

## Building a portable executable

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name PcapChunk pcapchunk_gui.py
```

The result is `dist/PcapChunk.exe` on Windows, or `dist/PcapChunk` on Linux and macOS. Build on the operating system you want to run it on. If antivirus flags the one-file build, use `--onedir` instead.

## Requirements

Python 3.8 or newer. The GUI needs Tkinter, which ships with the python.org installers; on Debian or Ubuntu, install `python3-tk`.
