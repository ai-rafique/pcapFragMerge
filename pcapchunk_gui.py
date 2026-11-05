#!/usr/bin/env python3
"""
pcapchunk_gui.py - Tkinter front end for pcapchunk.py.

Standard library only. No threads: long jobs are generators from pcapchunk
that are advanced in short time slices from Tk's event loop (root.after),
so the window stays responsive and Cancel works.

Run:    python pcapchunk_gui.py [capture.pcap | chunk_folder]
Build:  pyinstaller --onefile --windowed --name PcapChunk pcapchunk_gui.py
"""

import logging
import os
import sys
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import pcapchunk as core

APP_TITLE = "PcapChunk"
SLICE_SECONDS = 0.04  # how long each event-loop tick works before redrawing
CAPTURE_TYPES = [("Capture files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")]


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


class TextLogHandler(logging.Handler):
    """Sends pcapchunk warnings to the log box."""

    def __init__(self, app):
        super().__init__(logging.WARNING)
        self.app = app

    def emit(self, record):
        self.app.log(f"Warning: {record.getMessage()}")


class App(ttk.Frame):
    def __init__(self, root):
        super().__init__(root, padding=12)
        self.root = root
        self.job = None
        self.job_name = ""
        self.job_started = 0.0
        self.on_job_done = None
        self.busy_widgets = []

        root.title(APP_TITLE)
        root.minsize(620, 520)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self.nb = ttk.Notebook(self)
        self.nb.grid(row=0, column=0, sticky="nsew")
        self.nb.add(self._build_split_tab(), text="  Split  ")
        self.nb.add(self._build_merge_tab(), text="  Merge  ")
        self.busy_widgets.append(self.nb)

        self._build_progress().grid(row=1, column=0, sticky="ew", pady=(12, 8))
        self._build_log().grid(row=2, column=0, sticky="nsew")

        logging.getLogger("pcapchunk").addHandler(TextLogHandler(self))
        self.log("Ready. Pick a capture to split, or a chunk folder to merge.")

    # ------------------------------------------------------------- layout --

    def _row(self, parent, row, label, var, browse, width=48):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        entry = ttk.Entry(parent, textvariable=var, width=width)
        entry.grid(row=row, column=1, sticky="ew", padx=8, pady=4)
        btn = ttk.Button(parent, text="Browse…", command=browse)
        btn.grid(row=row, column=2, pady=4)
        self.busy_widgets += [entry, btn]
        return entry

    def _build_split_tab(self):
        tab = ttk.Frame(self.nb, padding=12)
        tab.columnconfigure(1, weight=1)

        self.s_input = tk.StringVar()
        self.s_outdir = tk.StringVar()
        self._row(tab, 0, "Capture file", self.s_input, self.browse_split_input)
        self._row(tab, 1, "Output folder", self.s_outdir, self.browse_split_outdir)
        self.s_info = ttk.Label(tab, text="", foreground="gray")
        self.s_info.grid(row=2, column=1, sticky="w", padx=8)

        box = ttk.LabelFrame(tab, text="Split by", padding=10)
        box.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(10, 4))
        self.s_mode = tk.StringVar(value="size")
        self.s_size = tk.StringVar(value="50")
        self.s_chunks = tk.StringVar(value="8")
        self.s_packets = tk.StringVar(value="100000")
        modes = [
            ("size", "Max chunk size", self.s_size, "MB"),
            ("chunks", "Number of chunks", self.s_chunks, "equal-sized chunks"),
            ("packets", "Packets per chunk", self.s_packets, "packets"),
        ]
        self.s_mode_entries = {}
        for r, (key, text, var, unit) in enumerate(modes):
            rb = ttk.Radiobutton(box, text=text, value=key, variable=self.s_mode,
                                 command=self._sync_split_mode)
            rb.grid(row=r, column=0, sticky="w", pady=2)
            e = ttk.Spinbox(box, textvariable=var, from_=1, to=10**9, width=12)
            e.grid(row=r, column=1, sticky="w", padx=8)
            ttk.Label(box, text=unit, foreground="gray").grid(row=r, column=2, sticky="w")
            self.s_mode_entries[key] = e
            self.busy_widgets.append(rb)
        self._sync_split_mode()

        self.s_button = ttk.Button(tab, text="Split", command=self.start_split)
        self.s_button.grid(row=4, column=0, columnspan=3, sticky="e", pady=(10, 0))
        self.busy_widgets.append(self.s_button)
        return tab

    def _build_merge_tab(self):
        tab = ttk.Frame(self.nb, padding=12)
        tab.columnconfigure(1, weight=1)

        self.m_folder = tk.StringVar()
        self.m_output = tk.StringVar()
        self._row(tab, 0, "Chunk folder", self.m_folder, self.browse_merge_folder)
        self._row(tab, 1, "Merged file", self.m_output, self.browse_merge_output)
        self.m_info = ttk.Label(tab, text="", foreground="gray")
        self.m_info.grid(row=2, column=1, sticky="w", padx=8)

        self.m_verify = tk.BooleanVar(value=True)
        cb = ttk.Checkbutton(tab, text="Verify against the original's SHA-256 (when manifest.json is present)",
                             variable=self.m_verify)
        cb.grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 4))
        self.busy_widgets.append(cb)

        self.m_button = ttk.Button(tab, text="Merge", command=self.start_merge)
        self.m_button.grid(row=4, column=0, columnspan=3, sticky="e", pady=(10, 0))
        self.busy_widgets.append(self.m_button)
        return tab

    def _build_progress(self):
        f = ttk.Frame(self)
        f.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(f, mode="determinate", maximum=1000)
        self.progress.grid(row=0, column=0, sticky="ew")
        self.cancel_btn = ttk.Button(f, text="Cancel", command=self.cancel, state="disabled")
        self.cancel_btn.grid(row=0, column=1, padx=(8, 0))
        self.status = ttk.Label(f, text="Idle", foreground="gray")
        self.status.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))
        return f

    def _build_log(self):
        f = ttk.Frame(self)
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        self.logbox = tk.Text(f, height=8, wrap="word", state="disabled", relief="flat",
                              borderwidth=1, highlightthickness=1)
        sb = ttk.Scrollbar(f, orient="vertical", command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=sb.set)
        self.logbox.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        return f

    def log(self, msg):
        self.logbox.configure(state="normal")
        self.logbox.insert("end", time.strftime("%H:%M:%S  ") + msg + "\n")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    def _sync_split_mode(self):
        for key, e in self.s_mode_entries.items():
            e.configure(state="normal" if key == self.s_mode.get() and not self.job else "disabled")

    # ------------------------------------------------------------ browse --

    def browse_split_input(self):
        p = filedialog.askopenfilename(title="Choose a capture to split", filetypes=CAPTURE_TYPES)
        if p:
            self.set_split_input(p)

    def set_split_input(self, p):
        self.s_input.set(os.path.normpath(p))
        self.s_outdir.set(os.path.normpath(core.default_outdir(p)))
        try:
            fmt = core.detect_format(p)
            self.s_info.configure(text=f"{fmt}, {human(os.path.getsize(p))}")
        except (core.PcapError, OSError) as e:
            self.s_info.configure(text=str(e))

    def browse_split_outdir(self):
        p = filedialog.askdirectory(title="Choose where to save the chunks", mustexist=False)
        if p:
            self.s_outdir.set(os.path.normpath(p))

    def browse_merge_folder(self):
        p = filedialog.askdirectory(title="Choose the folder with the chunks", mustexist=True)
        if p:
            self.set_merge_folder(p)

    def set_merge_folder(self, p):
        p = os.path.normpath(p)
        self.m_folder.set(p)
        try:
            names, merged, sha = core.discover_chunks(p)
            size = sum(os.path.getsize(os.path.join(p, n)) for n in names)
            self.m_output.set(os.path.join(p, merged))
            extra = "manifest found" if sha else "no manifest, ordered by chunk number"
            self.m_info.configure(text=f"{len(names)} chunks, {human(size)} ({extra})")
        except (core.PcapError, OSError, ValueError, KeyError) as e:
            self.m_output.set("")
            self.m_info.configure(text=str(e))

    def browse_merge_output(self):
        cur = self.m_output.get()
        p = filedialog.asksaveasfilename(
            title="Save merged capture as",
            initialdir=os.path.dirname(cur) or None,
            initialfile=os.path.basename(cur) or None,
            defaultextension=os.path.splitext(cur)[1] or ".pcap",
            filetypes=CAPTURE_TYPES,
            confirmoverwrite=False,  # asked when Merge is pressed
        )
        if p:
            self.m_output.set(os.path.normpath(p))

    # -------------------------------------------------------------- jobs --

    def start_split(self):
        path, outdir = self.s_input.get().strip(), self.s_outdir.get().strip()
        if not os.path.isfile(path):
            return messagebox.showerror(APP_TITLE, "Choose a capture file to split.")
        outdir = outdir or core.default_outdir(path)

        mode = self.s_mode.get()
        raw = {"size": self.s_size, "chunks": self.s_chunks, "packets": self.s_packets}[mode].get()
        try:
            value = float(raw) if mode == "size" else int(raw)
            if value <= 0:
                raise ValueError
        except ValueError:
            return messagebox.showerror(APP_TITLE, f"Enter a positive number for “{mode}”.")
        kwargs = {"size": int(value * (1 << 20))} if mode == "size" else {mode: value}

        force = False
        existing = core.existing_chunk_files(outdir)
        if existing:
            if not messagebox.askyesno(APP_TITLE, f"{outdir}\nalready has {len(existing)} chunk file(s).\n\n"
                                                   "Delete them and split again?", icon="warning"):
                return
            force = True

        try:
            gen = core.split_steps(path, outdir, force=force, **kwargs)
        except Exception as e:
            return messagebox.showerror(APP_TITLE, str(e))
        self.log(f"Splitting {os.path.basename(path)} …")

        def done(r):
            self.log(f"Done: {r['packets']:,} packets in {r['chunks']} chunks → {r['outdir']}")
            if messagebox.askyesno(APP_TITLE, f"Split into {r['chunks']} chunks.\n\nOpen the folder?"):
                open_path(r["outdir"])

        self.run_job("Splitting", gen, done)

    def start_merge(self):
        folder, output = self.m_folder.get().strip(), self.m_output.get().strip()
        if not os.path.isdir(folder):
            return messagebox.showerror(APP_TITLE, "Choose the folder that holds the chunks.")
        try:
            output = output or core.default_merge_output(folder)
        except core.PcapError as e:
            return messagebox.showerror(APP_TITLE, str(e))

        force = False
        if os.path.exists(output):
            if not messagebox.askyesno(APP_TITLE, f"{output}\nalready exists. Overwrite it?", icon="warning"):
                return
            force = True

        gen = core.merge_steps(folder, output, force=force, verify=self.m_verify.get())
        self.log(f"Merging {folder} …")

        def done(r):
            note = ("SHA-256 matches the original." if r["verified"]
                    else "Not verified (no manifest or verification off).")
            self.log(f"Done: {r['chunks']} chunks → {r['output']} ({human(r['size'])}). {note}")
            if messagebox.askyesno(APP_TITLE, f"Merged {r['chunks']} chunks.\n{note}\n\nOpen the folder?"):
                open_path(os.path.dirname(r["output"]))

        self.run_job("Merging", gen, done)

    def run_job(self, name, gen, on_done):
        self.job, self.job_name, self.on_job_done = gen, name, on_done
        self.job_started = time.perf_counter()
        self.set_busy(True)
        self.progress["value"] = 0
        self.status.configure(text=f"{name}…")
        self.after(1, self.pump)

    def pump(self):
        """Advance the current job for one short time slice, then yield to Tk."""
        if self.job is None:
            return
        progress = None
        deadline = time.perf_counter() + SLICE_SECONDS
        try:
            while time.perf_counter() < deadline:
                progress = next(self.job)
        except StopIteration as fin:
            on_done = self.on_job_done
            self.finish_job(f"{self.job_name} finished in {time.perf_counter() - self.job_started:.1f} s")
            self.progress["value"] = 1000
            on_done(fin.value)
            return
        except Exception as e:  # PcapError, OSError, anything unexpected
            self.finish_job(f"{self.job_name} failed")
            self.log(f"Error: {e}")
            messagebox.showerror(APP_TITLE, str(e))
            return
        if progress:
            done, total = progress
            self.progress["value"] = 1000 * done / total if total else 0
            elapsed = time.perf_counter() - self.job_started
            rate = done / elapsed if elapsed > 0 else 0
            eta = f", about {(total - done) / rate:.0f} s left" if rate and done < total else ""
            self.status.configure(text=f"{self.job_name}: {human(done)} of {human(total)}"
                                       f"  ({human(rate)}/s{eta})")
        self.after(1, self.pump)

    def cancel(self):
        if self.job is not None:
            self.job.close()  # generator cleanup removes partial output
            self.finish_job(f"{self.job_name} cancelled")
            self.progress["value"] = 0
            self.log(f"{self.job_name} cancelled; partial output removed.")

    def finish_job(self, status):
        self.job = None
        self.on_job_done = None
        self.set_busy(False)
        self.status.configure(text=status)

    def set_busy(self, busy):
        for w in self.busy_widgets:
            if isinstance(w, ttk.Notebook):
                for t in w.tabs():
                    w.tab(t, state="disabled" if busy and t != w.select() else "normal")
            else:
                w.configure(state="disabled" if busy else "normal")
        self._sync_split_mode()
        self.cancel_btn.configure(state="normal" if busy else "disabled")
        self.root.configure(cursor="watch" if busy else "")

    def on_close(self):
        if self.job is not None:
            if not messagebox.askyesno(APP_TITLE, f"{self.job_name} is still running. Cancel it and quit?"):
                return
            self.cancel()
        self.root.destroy()


def open_path(path):
    """Open a folder in the system file browser."""
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # noqa: S606 (Windows only)
        elif sys.platform == "darwin":
            os.spawnlp(os.P_NOWAIT, "open", "open", path)
        else:
            os.spawnlp(os.P_NOWAIT, "xdg-open", "xdg-open", path)
    except OSError:
        pass


def main():
    if sys.platform.startswith("win"):
        try:  # crisp text on high-DPI Windows displays
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    root = tk.Tk()
    style = ttk.Style(root)
    if "vista" not in style.theme_names() and "clam" in style.theme_names():
        style.theme_use("clam")
    app = App(root)

    # Dropping a file or folder onto the .exe (or passing it on the command line)
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if os.path.isdir(target):
            app.nb.select(1)
            app.set_merge_folder(target)
        elif os.path.isfile(target):
            app.set_split_input(target)

    root.mainloop()


if __name__ == "__main__":
    main()
