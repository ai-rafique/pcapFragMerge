#!/usr/bin/env python3
"""
pcapchunk_gui.py - Tkinter front end for pcapchunk.py (v2 API).

Standard library only.  No threads: every long operation is one of the
generator functions from pcapchunk (``*_steps``) advanced in short slices from
Tk's event loop (``root.after``), so the window stays responsive and Cancel
works by closing the generator.

The GUI only calls the frozen API documented in docs/API_V2.md.

Run:    python pcapchunk_gui.py [capture.pcap ... | chunk_folder]
Build:  pyinstaller --onefile --windowed --name PcapChunk pcapchunk_gui.py
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import tkinter as tk
import traceback
from tkinter import filedialog, messagebox, ttk

import pcapchunk as core

try:  # optional dependency: drag & drop support
    from tkinterdnd2 import DND_FILES, TkinterDnD

    DND_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    DND_FILES = None
    TkinterDnD = None
    DND_AVAILABLE = False


APP_TITLE = "PcapChunk"
SLICE_SECONDS = 0.04           # how long each event-loop tick works before redrawing
MAX_LOG_LINES = 4000
MAX_PLAN_ROWS = 500            # dry-run preview cap, keeps the UI responsive
TITLE_VERSION = "unknown"

CAPTURE_TYPES = [
    ("Capture files", "*.pcap *.pcapng *.cap *.pcap.gz *.pcapng.gz *.gz *.zst"),
    ("All files", "*.*"),
]
SPLIT_MODES = ("size", "chunks", "packets", "every", "gap", "split_at")

# Fallbacks used only while the engine module is being (re)written; the real
# values always come from pcapchunk.PRESETS / pcapchunk.FILTER_KEYS.
DEFAULT_PRESETS = {
    "email": 20 << 20,
    "upload": 100 << 20,
    "fat32": (4 << 30) - 1,
    "telegram": 1900 << 20,
    "dvd": 4_700_000_000,
}
DEFAULT_FILTER_KEYS = ("host", "src", "dst", "port", "sport", "dport", "proto")
FILTER_LABELS = {
    "host": "Host",
    "src": "Source IP",
    "dst": "Dest IP",
    "port": "Port",
    "sport": "Src port",
    "dport": "Dst port",
    "proto": "Protocol",
}

DEFAULTS = {
    "geometry": "",
    "theme": "system",
    "last_input_dir": "",
    "last_output_dir": "",
    "last_mode": "size",
    "wireshark_path": "",
    "recent": [],
    "split": {
        "preset": "custom",
        "compress": "none",
        "naming": "index",
        "resume": False,
        "force": False,
        "size": "50",
        "chunks": "8",
        "packets": "100000",
        "every": "1h",
        "gap": "5m",
        "split_at": "00:00",
        "index_csv": "",
    },
}

_GEOMETRY_RE = re.compile(r"^\d+x\d+([+-]\d+[+-]\d+)?$")
_SIZE_RE = re.compile(r"^\s*(\d+(?:[.,]\d+)?)\s*([kKmMgG]?)\s*[bB]?\s*$")
_DURATION_RE = re.compile(r"^\s*(\d+(?:[.,]\d+)?)\s*([sSmMhH]?)\s*$")
_SPLIT_TIME_RE = re.compile(r"^(\d{1,2}):(\d{2})(?::(\d{2}))?$")
_POSITION_RE = re.compile(r"^(\d+)x(\d+)([+-]\d+)([+-]\d+)$")


# ------------------------------------------------------------------ helpers --


def human(n):
    """Human readable byte count; tolerant of None/garbage."""
    if n is None:
        return "?"
    try:
        value = float(n)
    except (TypeError, ValueError):
        return "?"
    if value < 0:
        return "?"
    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            if unit == "B":
                return "%.0f B" % value
            return "%.1f %s" % (value, unit)
        value /= 1024.0
    return "?"


def num(n):
    """Thousands-separated integer, or '' for None."""
    if n is None:
        return ""
    try:
        return "{:,}".format(int(n))
    except (TypeError, ValueError):
        return str(n)


def human_seconds(value):
    if value is None:
        return "?"
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return "?"
    if seconds < 0:
        return "?"
    if seconds < 1:
        return "%.0f ms" % (seconds * 1000.0)
    if seconds < 90:
        return "%.2f s" % seconds
    if seconds < 5400:
        return "%.1f min" % (seconds / 60.0)
    return "%.2f h" % (seconds / 3600.0)


def iso_ts(ns):
    """UTC ISO timestamp via core.iso_ts, safe for None and bad values."""
    if ns is None or ns == "":
        return ""
    formatter = getattr(core, "iso_ts", None)
    if formatter is None:  # transitional engine build
        return ""
    try:
        return formatter(ns)
    except Exception:
        return ""


def parse_chunk_size(text):
    """Chunk size in MB.  A bare number is MB; ``50M`` / ``512K`` / ``1G`` also work."""
    match = _SIZE_RE.match(text or "")
    if not match:
        raise ValueError("Invalid chunk size %r. Use MB (e.g. 50) or 50M / 512K / 1G." % (text,))
    value = float(match.group(1).replace(",", "."))
    unit = (match.group(2) or "").lower()
    scale = {"": 1 << 20, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}[unit]
    size = int(value * scale)
    if size <= 0:
        raise ValueError("Chunk size must be greater than zero.")
    return size


def parse_duration(text):
    """Duration in whole seconds; ``30`` = 30 s, ``30s``, ``10m``, ``2h``."""
    match = _DURATION_RE.match(text or "")
    if not match:
        raise ValueError("Invalid duration %r. Use 30s, 10m, 2h or plain seconds." % (text,))
    value = float(match.group(1).replace(",", "."))
    unit = (match.group(2) or "s").lower()
    seconds = value * {"s": 1, "m": 60, "h": 3600}[unit]
    if seconds <= 0:
        raise ValueError("Duration must be greater than zero.")
    return max(1, int(round(seconds)))


def parse_positive_int(text, what="Value"):
    raw = (text or "").strip().replace(",", "")
    try:
        value = int(raw)
    except ValueError:
        raise ValueError("%s must be a whole number." % what)
    if value <= 0:
        raise ValueError("%s must be greater than zero." % what)
    return value


def parse_nonnegative_int(text, what="Value"):
    raw = (text or "").strip().replace(",", "")
    try:
        value = int(raw)
    except ValueError:
        raise ValueError("%s must be a whole number (0 or more)." % what)
    if value < 0:
        raise ValueError("%s cannot be negative." % what)
    return value


def parse_split_times(text):
    """Comma separated HH:MM[:SS] list, matching core.split_steps(split_at=...)."""
    parts = [part.strip() for part in (text or "").split(",") if part.strip()]
    if not parts:
        raise ValueError("Enter at least one HH:MM time, e.g. 02:00, 14:30.")
    for part in parts:
        match = _SPLIT_TIME_RE.match(part)
        if not match:
            raise ValueError("Invalid split-at time %r; use HH:MM or HH:MM:SS." % part)
        hour = int(match.group(1))
        minute = int(match.group(2))
        second = int(match.group(3) or 0)
        if hour > 23 or minute > 59 or second > 59:
            raise ValueError("Split-at time %r is out of range." % part)
    return parts


def check_timestamp(text, what):
    """Validate an ISO-8601 string or epoch seconds; empty -> None."""
    value = (text or "").strip()
    if not value:
        return None
    try:
        float(value)
        return value
    except ValueError:
        pass
    try:
        from datetime import datetime

        datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        raise ValueError(
            "%s must be ISO-8601 (e.g. 2026-11-06T12:00:00Z) or epoch seconds." % what
        )
    return value


def resource_path(relative):
    """Resolve a bundled resource, honoring PyInstaller's sys._MEIPASS."""
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative)


def settings_dir():
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming"
        )
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
            os.path.expanduser("~"), ".config"
        )
    return os.path.join(base, APP_TITLE)


def settings_path():
    return os.path.join(settings_dir(), "settings.json")


def _defaults():
    return json.loads(json.dumps(DEFAULTS))


def _merge_known(target, source):
    for key, default in list(target.items()):
        if key not in source:
            continue
        value = source[key]
        if isinstance(default, dict) and isinstance(value, dict):
            _merge_known(default, value)
        elif isinstance(default, list):
            if isinstance(value, list):
                target[key] = [item for item in value if isinstance(item, str)][:10]
        elif isinstance(default, bool):
            if isinstance(value, bool):
                target[key] = value
        elif isinstance(value, str):
            target[key] = value
    return target


def load_settings():
    """Read per-user settings; any problem falls back to defaults."""
    settings = _defaults()
    try:
        with open(settings_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError, TypeError):
        return settings
    if not isinstance(data, dict):
        return settings
    _merge_known(settings, data)
    if settings.get("theme") not in ("system", "clam", "dark"):
        settings["theme"] = "system"
    if settings.get("last_mode") not in SPLIT_MODES:
        settings["last_mode"] = "size"
    if not _GEOMETRY_RE.match(settings.get("geometry") or ""):
        settings["geometry"] = ""
    recent = []
    for item in settings.get("recent") or []:
        if isinstance(item, str) and item and item not in recent:
            recent.append(item)
    settings["recent"] = recent[:10]
    if not isinstance(settings.get("split"), dict):
        settings["split"] = _defaults()["split"]
    return settings


def save_settings(settings):
    """Write settings atomically; returns False instead of raising."""
    path = settings_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        temp = path + ".tmp"
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump(settings, handle, indent=2, sort_keys=True)
        os.replace(temp, path)
        return True
    except OSError:
        return False


def open_path(path):
    """Open a file or folder with the OS default handler.  Raises OSError."""
    if sys.platform.startswith("win"):
        os.startfile(path)  # noqa: S606 - Windows only
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def _clamped_geometry(saved, width, height, screen_w, screen_h):
    match = _POSITION_RE.match(saved or "")
    if not match:
        return None
    saved_w = max(int(match.group(1)), 800)
    saved_h = max(int(match.group(2)), 500)
    saved_w = min(saved_w, max(800, screen_w - 20))
    saved_h = min(saved_h, max(500, screen_h - 40))
    x = int(match.group(3))
    y = int(match.group(4))
    if x < -100 or x > screen_w - 120:
        x = 20
    if y < -40 or y > screen_h - 120:
        y = 20
    return "%dx%d+%d+%d" % (saved_w, saved_h, x, y)


# ------------------------------------------------------------------ logging --


class TextLogHandler(logging.Handler):
    """Forward pcapchunk warnings into the GUI log box."""

    def __init__(self, app):
        super().__init__(logging.WARNING)
        self.app = app

    def emit(self, record):
        try:
            message = record.getMessage()
        except Exception:
            message = "?"
        try:
            self.app.log("Warning: " + message)
        except Exception:
            pass


# ------------------------------------------------------------------ filters --


class FilterPanel(ttk.LabelFrame):
    """host/src/dst/port/sport/dport/proto entries -> a filter_spec dict."""

    def __init__(self, parent, app):
        super().__init__(parent, text="Filters", padding=8)
        self.app = app
        self.keys = tuple(getattr(core, "FILTER_KEYS", DEFAULT_FILTER_KEYS) or DEFAULT_FILTER_KEYS)
        hints = {
            "host": "e.g. 10.0.0.5",
            "port": "e.g. 443",
            "proto": "tcp, udp, icmp, ip, 6",
        }
        self.vars = {}
        for index, key in enumerate(self.keys):
            row, column = divmod(index, 2)
            cell = ttk.Frame(self)
            cell.grid(row=row, column=column, sticky="ew", padx=(0, 12), pady=2)
            cell.columnconfigure(1, weight=1)
            ttk.Label(cell, text=FILTER_LABELS.get(key, key.title())).grid(
                row=0, column=0, sticky="w"
            )
            variable = tk.StringVar()
            self.vars[key] = variable
            entry = ttk.Entry(cell, textvariable=variable, width=18)
            entry.grid(row=0, column=1, sticky="ew", padx=(6, 0))
            app._track_busy(entry)
            hint = hints.get(key)
            if hint:
                ttk.Label(cell, text=hint, foreground="gray").grid(
                    row=0, column=2, sticky="w", padx=(6, 0)
                )
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        clear = ttk.Button(self, text="Clear filters", command=self.clear)
        clear.grid(row=(len(self.keys) + 1) // 2, column=0, sticky="w", pady=(6, 0))
        app._track_busy(clear)

    def clear(self):
        for variable in self.vars.values():
            variable.set("")

    def spec(self):
        """Return a filter_spec dict (or None); comma separated values -> lists."""
        result = {}
        for key, variable in self.vars.items():
            raw = variable.get().strip()
            if not raw:
                continue
            parts = [part.strip() for part in raw.split(",") if part.strip()]
            if not parts:
                continue
            if key in ("port", "sport", "dport"):
                values = []
                for part in parts:
                    try:
                        values.append(int(part))
                    except ValueError:
                        raise ValueError(
                            "%s needs whole numbers, not %r." % (FILTER_LABELS.get(key, key), part)
                        )
                result[key] = values[0] if len(values) == 1 else values
            elif key == "proto":
                values = []
                for part in parts:
                    token = part.strip()
                    if token.lstrip("+-").isdigit():
                        values.append(int(token))
                    else:
                        values.append(token.lower())
                result[key] = values[0] if len(values) == 1 else values
            else:
                result[key] = parts[0] if len(parts) == 1 else parts
        return result or None


# ---------------------------------------------------------------- main app --


class App(ttk.Frame):
    """The whole window: notebook with tabs, progress bar, log and job pump."""

    def __init__(self, root):
        super().__init__(root, padding=10)
        self.root = root
        self.settings = load_settings()
        self.recent = list(self.settings.get("recent") or [])
        self.presets = dict(getattr(core, "PRESETS", None) or DEFAULT_PRESETS)
        self._preset_by_label = {}
        for key in self.presets:
            self._preset_by_label["%s (%s)" % (key, human(self.presets[key]))] = key
        self._busy_widgets = []          # list of (widget, idle state)
        self._busy = False
        self.job = None
        self.job_name = ""
        self._job_spec = None
        self._jobs = []
        self._jobs_total = 0
        self._jobs_index = 0
        self._jobs_ok = 0
        self._failures = []
        self._batch_title = ""
        self._batch_final = None
        self._cancelling = False
        self._indeterminate = False
        self._job_started = 0.0
        self._last_split_outdir = ""
        self._last_verify_ok = None
        self._last_verify_problems = 0
        self._dark = False
        self._colored_labels = {}
        self._tagged_trees = []
        self._text_widgets = []
        self._recent_menu = None

        title = APP_TITLE
        version = getattr(core, "__version__", "")
        if version:
            title = "%s %s" % (APP_TITLE, version)
        root.title(title)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=4)
        self.rowconfigure(2, weight=1)

        self._set_window_geometry()
        self._load_icon()
        self._build_notebook()
        self._build_progress().grid(row=1, column=0, sticky="ew", pady=(8, 4))
        self._build_log().grid(row=2, column=0, sticky="nsew")
        self._build_menu()
        self._restore_state()
        self.apply_theme(self.settings.get("theme", "system"))
        self._bind_shortcuts()
        logging.getLogger("pcapchunk").addHandler(TextLogHandler(self))
        self._setup_dnd()
        self.log(
            "Ready. PcapChunk %s — add captures to the Split list or pick a chunk folder to merge/verify."
            % (version or "?")
        )

    # ------------------------------------------------------------ window --

    def _set_window_geometry(self):
        try:
            screen_w = self.root.winfo_screenwidth()
            screen_h = self.root.winfo_screenheight()
        except tk.TclError:
            screen_w, screen_h = 1280, 800
        min_w, min_h = 1000, 700
        width = min(max(1200, min_w), max(min_w, screen_w - 80))
        height = min(max(860, min_h), max(min_h, screen_h - 100))
        restored = _clamped_geometry(
            self.settings.get("geometry") or "", width, height, screen_w, screen_h
        )
        self.root.geometry(restored or "%dx%d" % (width, height))
        self.root.minsize(min_w, min_h)

    def _load_icon(self):
        icon = resource_path(os.path.join("assets", "icon.ico"))
        if not os.path.isfile(icon):
            return
        try:
            self.root.iconbitmap(icon)
        except (tk.TclError, OSError):
            pass

    def _build_notebook(self):
        self.nb = ttk.Notebook(self)
        self.nb.grid(row=0, column=0, sticky="nsew")
        self.split_tab = self._build_split_tab()
        self.merge_tab = self._build_merge_tab()
        self.verify_tab = self._build_verify_tab()
        self.tools_tab = self._build_tools_tab()
        self.nb.add(self.split_tab, text="  Split  ")
        self.nb.add(self.merge_tab, text="  Merge  ")
        self.nb.add(self.verify_tab, text="  Verify  ")
        self.nb.add(self.tools_tab, text="  Tools  ")
        self._track_busy(self.nb)

    def _track_busy(self, *widgets, **kwargs):
        idle_state = kwargs.get("idle_state", "normal")
        for widget in widgets:
            self._busy_widgets.append((widget, idle_state))

    def _row(self, parent, row, label, variable, buttons=(), width=40):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        entry = ttk.Entry(parent, textvariable=variable, width=width)
        entry.grid(row=row, column=1, sticky="ew", padx=(8, 8), pady=3)
        self._track_busy(entry)
        column = 2
        for text, command in buttons:
            button = ttk.Button(parent, text=text, command=command)
            button.grid(row=row, column=column, sticky="w", padx=(0, 4), pady=3)
            self._track_busy(button)
            column += 1
        return entry

    # ------------------------------------------------------------ menus ----

    def _build_menu(self):
        self.theme_var = tk.StringVar(value=self.settings.get("theme", "system"))
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(
            label="Add capture(s)…", accelerator="Ctrl+O", command=self.browse_split_input
        )
        file_menu.add_command(
            label="Choose merge folder…", accelerator="Ctrl+M", command=self.browse_merge_folder
        )
        self.recent_menu = tk.Menu(file_menu, tearoff=False)
        file_menu.add_cascade(label="Recent", menu=self.recent_menu)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        settings_menu = tk.Menu(menubar, tearoff=False)
        settings_menu.add_command(label="Set Wireshark path…", command=self.choose_wireshark)
        settings_menu.add_command(label="Clear Wireshark path", command=self.clear_wireshark)
        settings_menu.add_separator()
        settings_menu.add_command(label="Open settings folder", command=self.open_settings_folder)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        theme_menu = tk.Menu(menubar, tearoff=False)
        for value, label in (("system", "System"), ("clam", "Clam"), ("dark", "Dark")):
            theme_menu.add_radiobutton(
                label=label,
                value=value,
                variable=self.theme_var,
                command=self._on_theme_selected,
            )
        menubar.add_cascade(label="Theme", menu=theme_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="Keyboard shortcuts", command=self.show_shortcuts)
        help_menu.add_command(label="About PcapChunk", accelerator="F1", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.configure(menu=menubar)
        self._rebuild_recent_menu()

    def _rebuild_recent_menu(self):
        if self._recent_menu is None:
            return
        self._recent_menu.delete(0, "end")
        if not self.recent:
            self._recent_menu.add_command(label="(no recent files)", state="disabled")
            return
        for index, path in enumerate(self.recent, 1):
            base = os.path.basename(path.rstrip("\\/")) or path
            parent = os.path.dirname(path.rstrip("\\/"))
            label = "%d. %s" % (index, base)
            if parent:
                label += "   (%s)" % parent
            self._recent_menu.add_command(
                label=label, command=lambda value=path: self._open_recent(value)
            )

    def _add_recent(self, path):
        try:
            path = os.path.normpath(path)
        except (TypeError, ValueError):
            return
        if not path:
            return
        if path in self.recent:
            self.recent.remove(path)
        self.recent.insert(0, path)
        del self.recent[10:]
        self._rebuild_recent_menu()

    def _open_recent(self, path):
        if self._busy:
            return
        if os.path.isdir(path):
            self.nb.select(self.merge_tab)
            self.set_merge_folder(path)
        elif os.path.isfile(path):
            self.nb.select(self.split_tab)
            self._add_split_paths([path], replace=True)
        else:
            self.log("Recent item no longer exists: %s" % path)

    def open_arguments(self, args):
        """Handle files/folders passed on the command line (or dropped on the .exe)."""
        if self._busy:
            return
        files = []
        folders = []
        for arg in args:
            try:
                path = os.path.normpath(os.path.abspath(os.path.expanduser(str(arg))))
            except (TypeError, ValueError):
                continue
            if os.path.isdir(path):
                folders.append(path)
            elif os.path.isfile(path):
                files.append(path)
        if files:
            self.nb.select(self.split_tab)
            self._add_split_paths(files)
            self.log("Loaded %d capture(s) from the command line." % len(files))
        if folders:
            self.nb.select(self.merge_tab)
            self.set_merge_folder(folders[0])
            for extra in folders[1:]:
                self._add_recent(extra)
            self.log("Loaded merge folder from the command line: %s" % folders[0])

    # --------------------------------------------------------- progress ----

    def _build_progress(self):
        frame = ttk.Frame(self)
        frame.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(frame, mode="determinate", maximum=1000)
        self.progress.grid(row=0, column=0, sticky="ew")
        self.cancel_btn = ttk.Button(
            frame, text="Cancel", command=self.cancel, state="disabled"
        )
        self.cancel_btn.grid(row=0, column=1, padx=(8, 0))
        self.status = ttk.Label(frame, text="Idle", foreground="gray")
        self.status.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))
        return frame

    def _build_log(self):
        frame = ttk.Frame(self)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self.logbox = tk.Text(
            frame,
            height=6,
            wrap="word",
            state="disabled",
            relief="flat",
            borderwidth=1,
            highlightthickness=1,
        )
        self._text_widgets.append(self.logbox)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=scroll.set)
        self.logbox.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        return frame

    def log(self, message):
        if not hasattr(self, "logbox"):
            return
        try:
            self.logbox.configure(state="normal")
            self.logbox.insert(
                "end", time.strftime("%H:%M:%S") + "  " + str(message) + "\n"
            )
            line_count = int(self.logbox.index("end-1c").split(".")[0])
            if line_count > MAX_LOG_LINES:
                self.logbox.delete("1.0", "%d.0" % (line_count - MAX_LOG_LINES + 1))
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
        except tk.TclError:
            pass

    def _set_text(self, widget, text):
        try:
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", text)
            widget.configure(state="disabled")
        except tk.TclError:
            pass

    # ------------------------------------------------------------ split ----

    def _build_split_tab(self):
        tab = ttk.Frame(self.nb, padding=10)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(1, weight=2)
        tab.rowconfigure(7, weight=3)

        self.s_input = tk.StringVar()
        self.s_outdir = tk.StringVar()
        self._row(
            tab,
            0,
            "Capture file",
            self.s_input,
            [("Browse…", self.browse_split_input), ("Add files…", self.add_split_files)],
        )

        tree_frame = ttk.Frame(tab)
        tree_frame.grid(row=1, column=0, columnspan=4, sticky="nsew", pady=(6, 0))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        self.s_batch = ttk.Treeview(
            tree_frame,
            columns=("name", "size", "folder"),
            show="headings",
            selectmode="extended",
            height=3,
        )
        for column, text, width, stretch in (
            ("name", "Capture", 280, False),
            ("size", "Size", 90, False),
            ("folder", "Folder", 480, True),
        ):
            self.s_batch.heading(column, text=text)
            self.s_batch.column(column, width=width, stretch=stretch)
        self.s_batch.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.s_batch.yview)
        self.s_batch.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")

        batch_actions = ttk.Frame(tab)
        batch_actions.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        for text, command in (
            ("Add files…", self.add_split_files),
            ("Remove selected", self.remove_split_selected),
            ("Clear list", self.clear_split_batch),
        ):
            button = ttk.Button(batch_actions, text=text, command=command)
            button.pack(side="left", padx=(0, 6))
            self._track_busy(button)
        self.s_info = ttk.Label(batch_actions, text="No captures yet.", foreground="gray")
        self.s_info.pack(side="right")

        self._row(
            tab, 3, "Output folder", self.s_outdir, [("Browse…", self.browse_split_outdir)]
        )
        ttk.Label(
            tab,
            text="Leave empty to create <name>_chunks next to each capture.",
            foreground="gray",
        ).grid(row=4, column=1, sticky="w", padx=(8, 0))

        options = ttk.Frame(tab)
        options.grid(row=5, column=0, columnspan=4, sticky="nsew", pady=(8, 0))
        options.columnconfigure(0, weight=1, uniform="split")
        options.columnconfigure(1, weight=1, uniform="split")
        mode_box = self._build_split_modes(options)
        mode_box.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        option_box = self._build_split_options(options)
        option_box.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        action_row = ttk.Frame(tab)
        action_row.grid(row=6, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self.s_preview_btn = ttk.Button(
            action_row, text="Preview plan (dry run)", command=self.preview_split
        )
        self.s_preview_btn.pack(side="left")
        self.s_split_btn = ttk.Button(action_row, text="Split", command=self.start_split)
        self.s_split_btn.pack(side="right")
        self._track_busy(self.s_preview_btn, self.s_split_btn)

        plan_frame = ttk.LabelFrame(tab, text="Plan preview (dry run)", padding=4)
        plan_frame.grid(row=7, column=0, columnspan=4, sticky="nsew", pady=(8, 0))
        plan_frame.columnconfigure(0, weight=1)
        plan_frame.rowconfigure(0, weight=1)
        self.plan_tree = ttk.Treeview(
            plan_frame,
            columns=("source", "index", "file", "bytes", "packets", "first", "last"),
            show="headings",
            height=3,
        )
        for column, text, width, stretch in (
            ("source", "Source", 150, False),
            ("index", "#", 45, False),
            ("file", "Chunk file", 220, True),
            ("bytes", "Bytes", 100, False),
            ("packets", "Packets", 90, False),
            ("first", "First packet (UTC)", 155, False),
            ("last", "Last packet (UTC)", 155, False),
        ):
            self.plan_tree.heading(column, text=text)
            self.plan_tree.column(column, width=width, stretch=stretch)
        self.plan_tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(plan_frame, orient="vertical", command=self.plan_tree.yview)
        self.plan_tree.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")
        return tab

    def _build_split_modes(self, parent):
        box = ttk.LabelFrame(parent, text="Split by", padding=8)
        self.s_mode = tk.StringVar(value="size")
        self.s_size = tk.StringVar(value="50")
        self.s_chunks = tk.StringVar(value="8")
        self.s_packets = tk.StringVar(value="100000")
        self.s_every = tk.StringVar(value="1h")
        self.s_gap = tk.StringVar(value="5m")
        self.s_split_at = tk.StringVar(value="00:00")
        self.s_mode_widgets = {}
        modes = [
            ("size", "Max size", "MB", self.s_size),
            ("chunks", "Chunks", "", self.s_chunks),
            ("packets", "Packets/chunk", "", self.s_packets),
            ("every", "Every", "1h, 30m", self.s_every),
            ("gap", "Gap", "5m, 30s", self.s_gap),
            ("split_at", "Split at", "HH:MM", self.s_split_at),
        ]
        for index, (key, text, hint, variable) in enumerate(modes):
            cell = ttk.Frame(box)
            cell.grid(row=index // 2, column=index % 2, sticky="w", padx=(0, 10), pady=2)
            radio = ttk.Radiobutton(
                cell,
                text=text,
                value=key,
                variable=self.s_mode,
                command=self._sync_split_mode,
            )
            radio.grid(row=0, column=0, sticky="w")
            entry = ttk.Entry(cell, textvariable=variable, width=12)
            entry.grid(row=0, column=1, sticky="w", padx=(4, 0))
            self._track_busy(radio, entry)
            self.s_mode_widgets[key] = (radio, entry)
            if hint:
                ttk.Label(cell, text=hint, foreground="gray").grid(
                    row=0, column=2, sticky="w", padx=(4, 0)
                )
        ttk.Label(
            box, text="Pick a mode, or choose a preset on the right.", foreground="gray"
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))
        return box

    def _build_split_options(self, parent):
        box = ttk.LabelFrame(parent, text="Options", padding=8)
        box.columnconfigure(1, weight=1)

        self.s_preset = tk.StringVar(value="custom")
        self.s_compress = tk.StringVar(value="none")
        self.s_naming = tk.StringVar(value="index")
        self.s_resume = tk.BooleanVar(value=False)
        self.s_force = tk.BooleanVar(value=False)
        self.s_index_csv = tk.StringVar()

        ttk.Label(box, text="Preset").grid(row=0, column=0, sticky="w", pady=2)
        preset_values = ["custom"] + list(self._preset_by_label)
        self.preset_combo = ttk.Combobox(
            box,
            textvariable=self.s_preset,
            values=preset_values,
            state="readonly",
            width=22,
        )
        self.preset_combo.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=2)
        self.preset_combo.bind("<<ComboboxSelected>>", self._on_preset_changed)
        self._track_busy(self.preset_combo, idle_state="readonly")

        ttk.Label(box, text="Compression").grid(row=1, column=0, sticky="w", pady=2)
        compress_combo = ttk.Combobox(
            box,
            textvariable=self.s_compress,
            values=["none", "gzip", "zstd"],
            state="readonly",
            width=12,
        )
        compress_combo.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=2)
        self._track_busy(compress_combo, idle_state="readonly")

        ttk.Label(box, text="Chunk names").grid(row=2, column=0, sticky="w", pady=2)
        naming_combo = ttk.Combobox(
            box,
            textvariable=self.s_naming,
            values=["index", "time"],
            state="readonly",
            width=12,
        )
        naming_combo.grid(row=2, column=1, sticky="w", padx=(8, 0), pady=2)
        self._track_busy(naming_combo, idle_state="readonly")

        ttk.Label(box, text="Index CSV").grid(row=3, column=0, sticky="w", pady=2)
        csv_frame = ttk.Frame(box)
        csv_frame.grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=2)
        csv_frame.columnconfigure(0, weight=1)
        csv_entry = ttk.Entry(csv_frame, textvariable=self.s_index_csv)
        csv_entry.grid(row=0, column=0, sticky="ew")
        csv_button = ttk.Button(csv_frame, text="…", width=3, command=self.browse_index_csv)
        csv_button.grid(row=0, column=1, padx=(4, 0))
        self._track_busy(csv_entry, csv_button)

        checks = ttk.Frame(box)
        checks.grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 0))
        resume_check = ttk.Checkbutton(
            checks, text="Resume interrupted run", variable=self.s_resume
        )
        resume_check.pack(side="left")
        force_check = ttk.Checkbutton(
            checks, text="Force replace existing chunks", variable=self.s_force
        )
        force_check.pack(side="left", padx=(12, 0))
        self._track_busy(resume_check, force_check)
        return box

    def _sync_split_mode(self, _event=None):
        if not hasattr(self, "s_mode_widgets"):
            return
        preset = self._selected_preset()
        mode = self.s_mode.get() if hasattr(self, "s_mode") else "size"
        for key, (radio, entry) in self.s_mode_widgets.items():
            radio_state = "normal" if (preset == "custom" and not self._busy) else "disabled"
            active = bool(preset == "custom" and mode == key and not self._busy)
            try:
                radio.configure(state=radio_state)
                entry.configure(state="normal" if active else "disabled")
            except tk.TclError:
                pass

    def _selected_preset(self):
        if not hasattr(self, "s_preset"):
            return "custom"
        return self._preset_by_label.get(self.s_preset.get(), "custom")

    def _on_preset_changed(self, _event=None):
        key = self._selected_preset()
        if key != "custom":
            size = self.presets.get(key)
            if size:
                self.s_size.set(("%.2f" % (size / float(1 << 20))).rstrip("0").rstrip("."))
                self.log("Preset %r selected: chunks up to %s." % (key, human(size)))
        self._sync_split_mode()

    def _refresh_split_info(self):
        rows = self.s_batch.get_children()
        total = 0
        for item in rows:
            try:
                total += os.path.getsize(item)
            except OSError:
                pass
        if rows:
            text = "%d capture(s), %s total" % (len(rows), human(total))
        else:
            text = "No captures yet — use Add files… or drop files here."
        try:
            self.s_info.configure(text=text)
        except tk.TclError:
            pass

    def _add_split_paths(self, paths, replace=False):
        normalized = []
        for path in paths:
            try:
                path = os.path.normpath(os.path.abspath(os.path.expanduser(str(path))))
            except (TypeError, ValueError):
                continue
            if os.path.isfile(path) and path not in normalized:
                normalized.append(path)
        if replace:
            self.clear_split_batch(quiet=True)
        added = 0
        for path in normalized:
            if path in self.s_batch.get_children():
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                size = None
            self.s_batch.insert(
                "",
                "end",
                iid=path,
                values=(os.path.basename(path), human(size), os.path.dirname(path)),
            )
            added += 1
        if normalized:
            self.s_input.set(normalized[0])
            self.settings["last_input_dir"] = os.path.dirname(normalized[0])
            if not self.s_outdir.get().strip():
                try:
                    self.s_outdir.set(os.path.normpath(core.default_outdir(normalized[0])))
                except (core.PcapError, OSError):
                    pass
            for path in normalized:
                self._add_recent(path)
        self._refresh_split_info()
        if added:
            self.log("Added %d capture(s) to the split list." % added)
        ignored = len(paths) - len(normalized)
        if ignored > 0:
            self.log("Ignored %d item(s) that are not files." % ignored)

    def clear_split_batch(self, quiet=False):
        try:
            items = self.s_batch.get_children()
            if items:
                self.s_batch.delete(*items)
        except tk.TclError:
            pass
        if not quiet:
            self.log("Cleared the split list.")
        self._refresh_split_info()

    def remove_split_selected(self):
        if self._busy:
            return
        try:
            selected = self.s_batch.selection()
            if selected:
                self.s_batch.delete(*selected)
        except tk.TclError:
            pass
        self._refresh_split_info()

    def browse_split_input(self):
        if self._busy:
            return
        paths = filedialog.askopenfilenames(
            title="Add capture files to split",
            initialdir=self._dialog_dir("last_input_dir"),
            filetypes=CAPTURE_TYPES,
        )
        if paths:
            self._add_split_paths(list(paths), replace=True)

    def add_split_files(self):
        if self._busy:
            return
        paths = filedialog.askopenfilenames(
            title="Add capture files to split",
            initialdir=self._dialog_dir("last_input_dir"),
            filetypes=CAPTURE_TYPES,
        )
        if paths:
            self._add_split_paths(list(paths))

    def browse_split_outdir(self):
        if self._busy:
            return
        folder = filedialog.askdirectory(
            title="Choose where to write the chunks",
            mustexist=False,
            initialdir=self._dialog_dir("last_output_dir"),
        )
        if folder:
            folder = os.path.normpath(folder)
            self.s_outdir.set(folder)
            self.settings["last_output_dir"] = folder

    def browse_index_csv(self):
        if self._busy:
            return
        filename = filedialog.asksaveasfilename(
            title="Index CSV path",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialdir=self._dialog_dir("last_output_dir"),
        )
        if filename:
            filename = os.path.normpath(filename)
            self.s_index_csv.set(filename)
            self.settings["last_output_dir"] = os.path.dirname(filename)

    def _split_input_paths(self):
        paths = list(self.s_batch.get_children())
        entry = self.s_input.get().strip()
        if entry:
            try:
                entry = os.path.normpath(os.path.abspath(os.path.expanduser(entry)))
            except (TypeError, ValueError):
                entry = ""
            if entry and entry not in paths:
                paths.insert(0, entry)
        return paths

    def _split_kwargs(self):
        kwargs = {}
        preset = self._selected_preset()
        if preset != "custom":
            kwargs["target"] = preset
        else:
            mode = self.s_mode.get()
            if mode == "size":
                kwargs["size"] = parse_chunk_size(self.s_size.get())
            elif mode == "chunks":
                kwargs["chunks"] = parse_positive_int(self.s_chunks.get(), "Number of chunks")
            elif mode == "packets":
                kwargs["packets"] = parse_positive_int(
                    self.s_packets.get(), "Packets per chunk"
                )
            elif mode == "every":
                kwargs["every"] = parse_duration(self.s_every.get())
            elif mode == "gap":
                kwargs["gap"] = parse_duration(self.s_gap.get())
            elif mode == "split_at":
                kwargs["split_at"] = parse_split_times(self.s_split_at.get())
        compression = self.s_compress.get()
        kwargs["compress"] = None if compression in ("", "none") else compression
        naming = self.s_naming.get()
        kwargs["name_style"] = naming if naming in ("index", "time") else "index"
        kwargs["resume"] = bool(self.s_resume.get())
        return kwargs

    def _default_outdir(self, path):
        try:
            return os.path.normpath(core.default_outdir(path))
        except (core.PcapError, OSError):
            stem = os.path.splitext(os.path.basename(path))[0]
            return os.path.join(os.path.dirname(path), stem + "_chunks")

    def _per_file_csv(self, csv_path, path, count):
        if not csv_path:
            return None
        if count <= 1:
            return csv_path
        stem = os.path.splitext(os.path.basename(path))[0]
        base, extension = os.path.splitext(csv_path)
        return "%s_%s%s" % (base, stem, extension or ".csv")

    def preview_split(self):
        self.start_split(dry_run=True)

    def start_split(self, dry_run=False):
        if self._busy:
            return
        try:
            paths = self._split_input_paths()
            if not paths:
                raise ValueError("Add at least one capture file to split.")
            missing = [path for path in paths if not os.path.isfile(path)]
            if missing:
                raise ValueError("File not found:\n" + "\n".join(missing[:5]))
            outdir = self.s_outdir.get().strip()
            if outdir:
                outdir = os.path.normpath(os.path.abspath(os.path.expanduser(outdir)))
            kwargs = self._split_kwargs()
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        if outdir:
            try:
                os.makedirs(outdir, exist_ok=True)
            except OSError as exc:
                messagebox.showerror(
                    APP_TITLE, "Cannot create the output folder:\n%s\n\n%s" % (outdir, exc)
                )
                return

        force = bool(self.s_force.get())
        targets = [(path, outdir or self._default_outdir(path)) for path in paths]
        existing = []
        for _path, folder in targets:
            try:
                files = core.existing_chunk_files(folder)
            except (core.PcapError, OSError):
                files = []
            if files:
                existing.append((folder, len(files)))
        if existing:
            detail = "\n".join(
                "  %s: %d chunk file(s)" % (folder, count) for folder, count in existing[:6]
            )
            if len(existing) > 6:
                detail += "\n  … and %d more" % (len(existing) - 6)
            answer = messagebox.askyesno(
                APP_TITLE,
                "The output folder already contains chunk files:\n\n%s\n\nReplace them?"
                % detail,
                icon="warning",
            )
            if not answer:
                return
            force = True

        seen = {}
        collisions = []
        for path, folder in targets:
            key = (
                os.path.splitext(os.path.basename(path))[0].lower(),
                os.path.normcase(os.path.abspath(folder)),
            )
            if key in seen:
                collisions.append(os.path.basename(path))
            else:
                seen[key] = path
        if collisions:
            answer = messagebox.askyesno(
                APP_TITLE,
                "These captures share a base name and write to the same output folder, "
                "so their chunk files would collide:\n\n  %s\n\nContinue anyway?"
                % ", ".join(collisions[:10]),
                icon="warning",
            )
            if not answer:
                return

        csv_path = None
        csv_text = self.s_index_csv.get().strip()
        if csv_text:
            csv_path = os.path.normpath(os.path.abspath(os.path.expanduser(csv_text)))

        if dry_run:
            self._clear_tree(self.plan_tree)
        jobs = []
        for path in paths:
            folder = outdir or self._default_outdir(path)
            csv_for = self._per_file_csv(csv_path, path, len(paths))
            label = "%s %s" % ("Preview" if dry_run else "Split", os.path.basename(path))

            def make(path=path, folder=folder, csv_for=csv_for):
                call_kwargs = dict(kwargs)
                call_kwargs["index_csv"] = csv_for
                return core.split_steps(
                    path, folder, force=force, dry_run=dry_run, **call_kwargs
                )

            def done(result, source=os.path.basename(path), dry=dry_run, used=folder):
                self._on_split_done(result, source, dry, used)

            jobs.append({"label": label, "make": make, "done": done})

        title = "Preview plan" if dry_run else "Split"
        final = lambda cancelled, ok, failures, all_paths=paths, dry=dry_run: (
            self._split_finished(cancelled, ok, failures, all_paths, dry)
        )
        self._run_jobs(title, jobs, final)

    def _on_split_done(self, result, source, dry_run, outdir_used):
        result = result or {}
        if dry_run:
            plan = result.get("plan") or []
            shown = 0
            for index, chunk in enumerate(plan, 1):
                if shown >= MAX_PLAN_ROWS:
                    break
                if not isinstance(chunk, dict):
                    continue
                self.plan_tree.insert(
                    "",
                    "end",
                    values=(
                        source,
                        chunk.get("index", index),
                        chunk.get("file", ""),
                        num(chunk.get("bytes")),
                        num(chunk.get("packets")),
                        iso_ts(chunk.get("first_ts_ns")),
                        iso_ts(chunk.get("last_ts_ns")),
                    ),
                )
                shown += 1
            if len(plan) > shown:
                self.log(
                    "Plan for %s: showing the first %d of %d chunks (table capped)."
                    % (source, shown, len(plan))
                )
            self.log(
                "Plan %s: %d chunk(s), %s packets, %s input — nothing written."
                % (source, len(plan), num(result.get("packets")), human(result.get("size")))
            )
            return
        self._last_split_outdir = result.get("outdir") or outdir_used
        if self._last_split_outdir:
            self.settings["last_output_dir"] = self._last_split_outdir
        self.log(
            "Done %s: %s chunk(s), %s packets, %s input → %s"
            % (
                source,
                num(result.get("chunks")),
                num(result.get("packets")),
                human(result.get("size")),
                result.get("outdir") or outdir_used,
            )
        )
        if result.get("index_csv"):
            self.log("Index CSV written to %s" % result.get("index_csv"))

    def _split_finished(self, cancelled, ok, failures, paths, dry_run):
        if cancelled:
            return
        if dry_run:
            self.log("Preview finished for %d of %d capture(s)." % (ok, len(paths)))
            return
        self.log("Split finished: %d of %d capture(s) succeeded." % (ok, len(paths)))
        if ok == 1 and len(paths) == 1 and not failures and self._last_split_outdir:
            if messagebox.askyesno(
                APP_TITLE, "Split complete.\n\nOpen the output folder?", icon="question"
            ):
                self.open_path_safe(self._last_split_outdir)

    # ------------------------------------------------------------ merge ----

    def _build_merge_tab(self):
        tab = ttk.Frame(self.nb, padding=10)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(3, weight=1)
        self.m_folder = tk.StringVar()
        self.m_output = tk.StringVar()
        self._row(
            tab, 0, "Chunk folder", self.m_folder, [("Browse…", self.browse_merge_folder)]
        )
        self._row(
            tab, 1, "Merged file", self.m_output, [("Browse…", self.browse_merge_output)]
        )
        self.m_info = ttk.Label(
            tab, text="Choose the folder produced by a split.", foreground="gray"
        )
        self.m_info.grid(row=2, column=0, columnspan=4, sticky="w", pady=(2, 6))
        self._colored_labels[self.m_info] = "muted"

        frame = ttk.Frame(tab)
        frame.grid(row=3, column=0, columnspan=4, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        columns = ("index", "file", "bytes", "packets", "first", "last")
        self.merge_tree = ttk.Treeview(
            frame, columns=columns, show="headings", selectmode="browse", height=7
        )
        for column, text, width, stretch in (
            ("index", "#", 45, False),
            ("file", "Chunk file", 280, True),
            ("bytes", "Bytes", 100, False),
            ("packets", "Packets", 90, False),
            ("first", "First packet (UTC)", 155, False),
            ("last", "Last packet (UTC)", 155, False),
        ):
            self.merge_tree.heading(column, text=text)
            self.merge_tree.column(column, width=width, stretch=stretch)
        self.merge_tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.merge_tree.yview)
        self.merge_tree.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")
        self._tagged_trees.append(self.merge_tree)
        self.merge_tree.bind(
            "<Double-1>",
            lambda event, tree=self.merge_tree, var=self.m_folder: self._open_chunk_from_tree(
                event, tree, var
            ),
        )

        actions = ttk.Frame(tab)
        actions.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        open_chunk = ttk.Button(
            actions,
            text="Open chunk",
            command=lambda: self.open_selected_chunk(self.merge_tree, self.m_folder),
        )
        open_folder = ttk.Button(
            actions, text="Open folder", command=lambda: self.open_folder(self.m_folder)
        )
        open_wireshark = ttk.Button(
            actions,
            text="Open in Wireshark",
            command=lambda: self.open_selected_in_wireshark(self.merge_tree, self.m_folder),
        )
        for button in (open_chunk, open_folder, open_wireshark):
            button.pack(side="left", padx=(0, 6))
            self._track_busy(button)
        ttk.Label(
            actions, text="Double-click a chunk to open it.", foreground="gray"
        ).pack(side="right")

        options = ttk.Frame(tab)
        options.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self.m_verify = tk.BooleanVar(value=True)
        self.m_allow_missing = tk.BooleanVar(value=False)
        verify_check = ttk.Checkbutton(
            options, text="Verify hashes while merging", variable=self.m_verify
        )
        verify_check.pack(side="left")
        missing_check = ttk.Checkbutton(
            options, text="Allow missing chunks", variable=self.m_allow_missing
        )
        missing_check.pack(side="left", padx=(16, 0))
        self._track_busy(verify_check, missing_check)

        button_row = ttk.Frame(tab)
        button_row.grid(row=6, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self.m_merge_btn = ttk.Button(button_row, text="Merge", command=self.start_merge)
        self.m_merge_btn.pack(side="right")
        self._track_busy(self.m_merge_btn)
        return tab

    def browse_merge_folder(self):
        if self._busy:
            return
        folder = filedialog.askdirectory(
            title="Choose the folder with the chunks",
            mustexist=True,
            initialdir=self._dialog_dir("last_input_dir"),
        )
        if folder:
            self.set_merge_folder(folder)

    def set_merge_folder(self, folder):
        if self._busy:
            return
        folder = os.path.normpath(os.path.abspath(os.path.expanduser(str(folder))))
        self.m_folder.set(folder)
        parent = os.path.dirname(folder)
        if os.path.isdir(parent):
            self.settings["last_input_dir"] = parent
        self._load_merge_folder(folder)

    def _load_merge_folder(self, folder):
        try:
            chunk_set = core.discover_chunks(folder)
        except (core.PcapError, OSError) as exc:
            self._clear_tree(self.merge_tree)
            self.m_output.set("")
            self._set_label(self.m_info, str(exc), "bad")
            self.log("Merge folder: %s" % exc)
            return
        except Exception as exc:  # engine bug: never take the GUI down
            self._clear_tree(self.merge_tree)
            self.m_output.set("")
            self._set_label(self.m_info, "Could not read the folder: %s" % exc, "bad")
            self.log("Merge folder: %s" % exc)
            return
        self._populate_merge(folder, chunk_set)

    def _populate_merge(self, folder, chunk_set):
        self._clear_tree(self.merge_tree)
        manifest = getattr(chunk_set, "manifest", None) or {}
        chunks = getattr(chunk_set, "chunks", None) or []
        names = getattr(chunk_set, "names", None) or []
        merged_name = getattr(chunk_set, "merged_name", "") or ""
        sha256 = getattr(chunk_set, "sha256", None)
        total = 0
        shown = 0
        if chunks:
            for index, chunk in enumerate(chunks, 1):
                if not isinstance(chunk, dict):
                    chunk = {}
                name = chunk.get("file") or ""
                if not name and index - 1 < len(names):
                    name = names[index - 1]
                size = chunk.get("bytes")
                if size is None:
                    try:
                        size = os.path.getsize(os.path.join(folder, name))
                    except OSError:
                        size = None
                if size:
                    total += size
                self.merge_tree.insert(
                    "",
                    "end",
                    values=(
                        chunk.get("index", index),
                        name,
                        num(size),
                        num(chunk.get("packets")),
                        iso_ts(chunk.get("first_ts_ns")),
                        iso_ts(chunk.get("last_ts_ns")),
                    ),
                )
                shown += 1
        else:
            for index, name in enumerate(names, 1):
                try:
                    size = os.path.getsize(os.path.join(folder, name))
                except OSError:
                    size = None
                if size:
                    total += size
                self.merge_tree.insert(
                    "", "end", values=(index, name, num(size), "", "", "")
                )
                shown += 1
        if merged_name:
            self.m_output.set(os.path.join(folder, merged_name))
        bits = ["%d chunk(s)" % shown, human(total)]
        schema = manifest.get("schema") if isinstance(manifest, dict) else None
        if schema:
            bits.append("manifest schema %s" % schema)
        else:
            bits.append("no manifest — ordered by chunk number")
        if sha256:
            bits.append("original SHA-256 available")
        incomplete = (
            isinstance(manifest, dict) and manifest.get("status") == "incomplete"
        )
        if incomplete:
            bits.append("INCOMPLETE set")
        self._set_label(self.m_info, ", ".join(bits), "warn" if incomplete else "muted")

    def browse_merge_output(self):
        if self._busy:
            return
        current = self.m_output.get().strip()
        initial_dir = (
            os.path.dirname(current)
            if current and os.path.isdir(os.path.dirname(current))
            else self._dialog_dir("last_output_dir")
        )
        filename = filedialog.asksaveasfilename(
            title="Save merged capture as",
            initialdir=initial_dir,
            initialfile=os.path.basename(current) if current else None,
            defaultextension=os.path.splitext(current)[1] or ".pcap",
            filetypes=CAPTURE_TYPES,
            confirmoverwrite=False,
        )
        if filename:
            filename = os.path.normpath(filename)
            self.m_output.set(filename)
            self.settings["last_output_dir"] = os.path.dirname(filename)

    def start_merge(self):
        if self._busy:
            return
        try:
            folder = self.m_folder.get().strip()
            if not folder:
                raise ValueError("Choose the folder with the chunks.")
            folder = os.path.normpath(os.path.abspath(os.path.expanduser(folder)))
            if not os.path.isdir(folder):
                raise ValueError("Folder not found:\n%s" % folder)
            output = self.m_output.get().strip()
            if not output:
                try:
                    output = core.default_merge_output(folder)
                except (core.PcapError, OSError) as exc:
                    raise ValueError(str(exc))
            output = os.path.normpath(os.path.abspath(os.path.expanduser(output)))
            parent = os.path.dirname(output)
            if not os.path.isdir(parent):
                raise ValueError("Output folder does not exist:\n%s" % parent)
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        force = False
        if os.path.exists(output):
            if not messagebox.askyesno(
                APP_TITLE,
                "%s\nalready exists. Overwrite it?" % output,
                icon="warning",
            ):
                return
            force = True
        verify = bool(self.m_verify.get())
        allow_missing = bool(self.m_allow_missing.get())
        self.settings["last_output_dir"] = os.path.dirname(output)
        self._set_label(self.m_info, "Merging…", "muted")
        generator = lambda: core.merge_steps(
            folder, output, force=force, verify=verify, allow_missing=allow_missing
        )
        self._run_jobs(
            "Merge",
            [{"label": "Merge chunks", "make": generator, "done": self._show_merge_result}],
        )

    def _show_merge_result(self, result):
        result = result or {}
        verified = result.get("verified")
        complete = result.get("complete", True)
        missing = result.get("missing") or []
        output = result.get("output") or ""
        if verified is True:
            note = "SHA-256 matches the original."
        elif verified is False:
            note = "Verification did not match."
        else:
            note = "Not hash-verified (no expected hash, or verification was off)."
        bits = ["%s chunk(s)" % num(result.get("chunks")), human(result.get("size"))]
        bits.append("complete" if complete else "INCOMPLETE")
        if missing:
            bits.append("%d missing" % len(missing))
        self._set_label(
            self.m_info,
            ", ".join(bits),
            "ok" if complete and not missing else "warn",
        )
        self.log(
            "Done: merged %s chunk(s) → %s (%s). %s"
            % (num(result.get("chunks")), output, human(result.get("size")), note)
        )
        for name in missing:
            self.log("Missing chunk: %s" % name)
        if not complete:
            messagebox.showwarning(
                APP_TITLE,
                "The merged file is INCOMPLETE%s\n\nIt was not hash-verified."
                % (
                    (":\n" + "\n".join(str(name) for name in missing[:8]))
                    if missing
                    else "."
                ),
            )
            return
        if messagebox.askyesno(
            APP_TITLE,
            "Merged %s chunk(s) into:\n%s\n\n%s\n\nOpen the folder?"
            % (num(result.get("chunks")), output, note),
            icon="question",
        ):
            self.open_path_safe(os.path.dirname(output))

    # ----------------------------------------------------------- verify ----

    def _build_verify_tab(self):
        tab = ttk.Frame(self.nb, padding=10)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(3, weight=1)
        self.v_folder = tk.StringVar()
        self._row(
            tab, 0, "Chunk folder", self.v_folder, [("Browse…", self.browse_verify_folder)]
        )

        controls = ttk.Frame(tab)
        controls.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        self.v_deep = tk.BooleanVar(value=False)
        deep_check = ttk.Checkbutton(
            controls,
            text="Deep verify (parse each chunk, compare packet counts and timestamps)",
            variable=self.v_deep,
        )
        deep_check.pack(side="left")
        self.v_verify_btn = ttk.Button(controls, text="Verify", command=self.start_verify)
        self.v_verify_btn.pack(side="right")
        self._track_busy(deep_check, self.v_verify_btn)

        self.v_info = ttk.Label(
            tab, text="Choose a chunk folder and press Verify.", foreground="gray"
        )
        self.v_info.grid(row=2, column=0, columnspan=4, sticky="w", pady=(4, 6))
        self._colored_labels[self.v_info] = "muted"

        frame = ttk.Frame(tab)
        frame.grid(row=3, column=0, columnspan=4, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        columns = ("index", "file", "bytes", "packets", "first", "last", "hash", "problems")
        self.verify_tree = ttk.Treeview(
            frame, columns=columns, show="headings", selectmode="browse", height=8
        )
        for column, text, width, stretch in (
            ("index", "#", 42, False),
            ("file", "Chunk file", 230, True),
            ("bytes", "Bytes", 120, False),
            ("packets", "Packets", 85, False),
            ("first", "First packet (UTC)", 155, False),
            ("last", "Last packet (UTC)", 155, False),
            ("hash", "Hash", 60, False),
            ("problems", "Problems", 260, True),
        ):
            self.verify_tree.heading(column, text=text)
            self.verify_tree.column(column, width=width, stretch=stretch)
        self.verify_tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.verify_tree.yview)
        self.verify_tree.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")
        self._tagged_trees.append(self.verify_tree)
        self.verify_tree.bind(
            "<Double-1>",
            lambda event, tree=self.verify_tree, var=self.v_folder: self._open_chunk_from_tree(
                event, tree, var
            ),
        )

        actions = ttk.Frame(tab)
        actions.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        open_chunk = ttk.Button(
            actions,
            text="Open chunk",
            command=lambda: self.open_selected_chunk(self.verify_tree, self.v_folder),
        )
        open_folder = ttk.Button(
            actions, text="Open folder", command=lambda: self.open_folder(self.v_folder)
        )
        open_wireshark = ttk.Button(
            actions,
            text="Open in Wireshark",
            command=lambda: self.open_selected_in_wireshark(self.verify_tree, self.v_folder),
        )
        for button in (open_chunk, open_folder, open_wireshark):
            button.pack(side="left", padx=(0, 6))
            self._track_busy(button)
        ttk.Label(
            actions, text="Bad rows are highlighted.", foreground="gray"
        ).pack(side="right")
        return tab

    def browse_verify_folder(self):
        if self._busy:
            return
        folder = filedialog.askdirectory(
            title="Choose the folder with the chunks",
            mustexist=True,
            initialdir=self._dialog_dir("last_input_dir"),
        )
        if folder:
            folder = os.path.normpath(folder)
            self.v_folder.set(folder)
            parent = os.path.dirname(folder)
            if os.path.isdir(parent):
                self.settings["last_input_dir"] = parent
            self._clear_tree(self.verify_tree)
            self._set_label(
                self.v_info, "Folder selected. Press Verify to check it.", "muted"
            )

    def start_verify(self):
        if self._busy:
            return
        folder = self.v_folder.get().strip()
        try:
            if not folder:
                raise ValueError("Choose the folder with the chunks.")
            folder = os.path.normpath(os.path.abspath(os.path.expanduser(folder)))
            if not os.path.isdir(folder):
                raise ValueError("Folder not found:\n%s" % folder)
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        deep = bool(self.v_deep.get())
        self._clear_tree(self.verify_tree)
        self._last_verify_ok = None
        self._last_verify_problems = 0
        self._set_label(self.v_info, "Verifying…", "muted")
        generator = lambda: core.verify_steps(folder, deep=deep)
        final = lambda cancelled, ok, failures: self._after_verify(cancelled, failures)
        self._run_jobs(
            "Verify",
            [{"label": "Verify chunks", "make": generator, "done": self._show_verify_result}],
            final,
        )

    def _after_verify(self, cancelled, failures):
        if cancelled or failures or self._last_verify_ok is None:
            return
        if self._last_verify_ok:
            self.status.configure(text="Verify finished: OK")
        else:
            self.status.configure(
                text="Verify finished: %d problem(s)" % self._last_verify_problems
            )

    def _show_verify_result(self, result):
        result = result or {}
        self._clear_tree(self.verify_tree)
        chunks = result.get("chunks") or []
        problems = result.get("problems") or []
        missing = result.get("missing") or []
        for index, chunk in enumerate(chunks, 1):
            if not isinstance(chunk, dict):
                chunk = {}
            name = chunk.get("file") or ""
            got_bytes = chunk.get("bytes")
            expected_bytes = chunk.get("expected_bytes")
            size_text = num(got_bytes)
            if (
                expected_bytes is not None
                and got_bytes is not None
                and int(got_bytes) != int(expected_bytes)
            ):
                size_text = "%s (expected %s)" % (num(got_bytes), num(expected_bytes))
            got_hash = chunk.get("sha256")
            expected_hash = chunk.get("expected_sha256")
            if expected_hash:
                hash_text = "OK" if got_hash == expected_hash else "FAIL"
            else:
                hash_text = "skip"
            chunk_problems = chunk.get("problems") or []
            ok = chunk.get("ok", not chunk_problems)
            tags = () if ok else ("bad",)
            self.verify_tree.insert(
                "",
                "end",
                values=(
                    index,
                    name,
                    size_text,
                    num(chunk.get("packets")),
                    iso_ts(chunk.get("first_ts_ns")),
                    iso_ts(chunk.get("last_ts_ns")),
                    hash_text,
                    "; ".join(str(problem) for problem in chunk_problems),
                ),
                tags=tags,
            )
        for name in missing:
            self.verify_tree.insert(
                "",
                "end",
                values=("", name, "MISSING", "", "", "", "—", "chunk file is missing"),
                tags=("bad",),
            )
        warnings = result.get("warnings") or []
        for warning in warnings[:20]:
            self.log("Verify warning: %s" % warning)
        if len(warnings) > 20:
            self.log("Verify: … and %d more warning(s)" % (len(warnings) - 20))
        extras = []
        if result.get("manifest"):
            extras.append("manifest schema %s" % result.get("schema"))
        else:
            extras.append("no manifest")
        if result.get("incomplete"):
            extras.append("set marked incomplete")
        if missing:
            extras.append("%d missing" % len(missing))
        if warnings:
            extras.append("%d warning(s)" % len(warnings))
        if result.get("ok"):
            text = "OK — %d chunk(s) verified, no problems (%s)." % (
                len(chunks),
                ", ".join(extras),
            )
            self._set_label(self.v_info, text, "ok")
            self.log("Verify: OK — %d chunk(s), no problems." % len(chunks))
        else:
            detail = "; ".join(str(problem) for problem in problems[:4])
            if len(problems) > 4:
                detail += " …"
            text = "PROBLEMS — %d issue(s) (%s)" % (len(problems), ", ".join(extras))
            if detail:
                text += ": " + detail
            self._set_label(self.v_info, text, "bad")
            self.log("Verify: PROBLEMS in %s" % result.get("folder", "folder"))
            for problem in problems[:20]:
                self.log("  %s" % problem)
            if len(problems) > 20:
                self.log("  … and %d more problem(s)" % (len(problems) - 20))
            for name in missing:
                self.log("  missing chunk: %s" % name)
        self._last_verify_ok = bool(result.get("ok"))
        self._last_verify_problems = len(problems)

    # ------------------------------------------------------------ tools ----

    def _build_tools_tab(self):
        tab = ttk.Frame(self.nb, padding=8)
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        self.tools_nb = ttk.Notebook(tab)
        self.tools_nb.grid(row=0, column=0, sticky="nsew")
        self.info_tab_widget = self._build_info_tab(self.tools_nb)
        self.convert_tab_widget = self._build_convert_tab(self.tools_nb)
        self.trim_tab_widget = self._build_trim_tab(self.tools_nb)
        self.tools_nb.add(self.info_tab_widget, text="  Info  ")
        self.tools_nb.add(self.convert_tab_widget, text="  Convert  ")
        self.tools_nb.add(self.trim_tab_widget, text="  Trim  ")
        self._track_busy(self.tools_nb)
        return tab

    def _build_info_tab(self, notebook):
        tab = ttk.Frame(notebook, padding=8)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(2, weight=1)
        self.i_input = tk.StringVar()
        self._row(
            tab, 0, "Capture file", self.i_input, [("Browse…", self.browse_info_input)]
        )
        controls = ttk.Frame(tab)
        controls.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        ttk.Label(controls, text="Top conversations").pack(side="left")
        self.i_top = tk.StringVar(value="10")
        top_spin = ttk.Spinbox(controls, from_=0, to=100000, textvariable=self.i_top, width=8)
        top_spin.pack(side="left", padx=(6, 0))
        ttk.Label(controls, text="(0 = none)", foreground="gray").pack(
            side="left", padx=(6, 0)
        )
        self.i_scan_btn = ttk.Button(controls, text="Scan", command=self.start_info)
        self.i_scan_btn.pack(side="right")
        self._track_busy(top_spin, self.i_scan_btn)

        paned = ttk.PanedWindow(tab, orient="horizontal")
        paned.grid(row=2, column=0, columnspan=4, sticky="nsew", pady=(8, 0))

        text_frame = ttk.Frame(paned)
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        self.info_text = tk.Text(
            text_frame,
            wrap="word",
            height=12,
            state="disabled",
            relief="flat",
            borderwidth=1,
            highlightthickness=1,
        )
        self._text_widgets.append(self.info_text)
        text_scroll = ttk.Scrollbar(
            text_frame, orient="vertical", command=self.info_text.yview
        )
        self.info_text.configure(yscrollcommand=text_scroll.set)
        self.info_text.grid(row=0, column=0, sticky="nsew")
        text_scroll.grid(row=0, column=1, sticky="ns")
        paned.add(text_frame, weight=3)

        flows_frame = ttk.Frame(paned)
        flows_frame.columnconfigure(0, weight=1)
        flows_frame.rowconfigure(0, weight=1)
        self.info_flows = ttk.Treeview(
            flows_frame,
            columns=("rank", "flow", "packets", "bytes"),
            show="headings",
            height=8,
        )
        for column, text, width, stretch in (
            ("rank", "#", 40, False),
            ("flow", "Conversation", 320, True),
            ("packets", "Packets", 80, False),
            ("bytes", "Bytes", 90, False),
        ):
            self.info_flows.heading(column, text=text)
            self.info_flows.column(column, width=width, stretch=stretch)
        self.info_flows.grid(row=0, column=0, sticky="nsew")
        flows_scroll = ttk.Scrollbar(
            flows_frame, orient="vertical", command=self.info_flows.yview
        )
        self.info_flows.configure(yscrollcommand=flows_scroll.set)
        flows_scroll.grid(row=0, column=1, sticky="ns")
        paned.add(flows_frame, weight=2)
        return tab

    def browse_info_input(self):
        if self._busy:
            return
        path = filedialog.askopenfilename(
            title="Choose a capture to inspect",
            initialdir=self._dialog_dir("last_input_dir"),
            filetypes=CAPTURE_TYPES,
        )
        if path:
            path = os.path.normpath(path)
            self.i_input.set(path)
            self.settings["last_input_dir"] = os.path.dirname(path)
            self._add_recent(path)

    def start_info(self):
        if self._busy:
            return
        path = self.i_input.get().strip()
        try:
            if not path:
                raise ValueError("Choose a capture file to inspect.")
            path = os.path.normpath(os.path.abspath(os.path.expanduser(path)))
            if not os.path.isfile(path):
                raise ValueError("File not found:\n%s" % path)
            top = parse_nonnegative_int(self.i_top.get(), "Top conversations")
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self._remember_capture_dir(path)
        self._set_text(self.info_text, "Scanning…")
        self._clear_tree(self.info_flows)
        generator = lambda: core.info_steps(path, top=top)
        self._run_jobs(
            "Info",
            [{"label": "Info %s" % os.path.basename(path), "make": generator,
              "done": self._show_info_result}],
        )

    def _show_info_result(self, result):
        result = result or {}
        lines = []
        lines.append("File:           %s" % (result.get("path") or ""))
        output_format = result.get("format") or "?"
        compressed = result.get("compressed")
        if compressed:
            output_format += " (%s-compressed)" % compressed
        lines.append("Format:         %s" % output_format)
        lines.append(
            "Size on disk:   %s (%s bytes)" % (human(result.get("size")), num(result.get("size")))
        )
        logical = result.get("logical_size")
        if logical is not None and logical != result.get("size"):
            lines.append(
                "Logical size:   %s (%s bytes)" % (human(logical), num(logical))
            )
        lines.append("Packets:        %s" % num(result.get("packets")))
        lines.append(
            "Captured bytes: %s (%s bytes)"
            % (human(result.get("bytes")), num(result.get("bytes")))
        )
        first = iso_ts(result.get("first_ts_ns"))
        last = iso_ts(result.get("last_ts_ns"))
        lines.append("First packet:   %s" % (first or "—"))
        lines.append("Last packet:    %s" % (last or "—"))
        duration = result.get("duration_s")
        if duration is not None:
            lines.append("Duration:       %s" % human_seconds(duration))
        interfaces = result.get("interfaces") or []
        if interfaces:
            lines.append("")
            lines.append("Interfaces:")
            for interface in interfaces:
                if not isinstance(interface, dict):
                    continue
                lines.append(
                    "  #%s  linktype %s  snaplen %s  tsresol %s  name %s  packets %s"
                    % (
                        interface.get("id", "?"),
                        interface.get("linktype", "?"),
                        interface.get("snaplen", "?"),
                        interface.get("tsresol", "?"),
                        interface.get("name") or "(unnamed)",
                        num(interface.get("packets")),
                    )
                )
        top_rows = result.get("top") or []
        if top_rows:
            lines.append("")
            lines.append("Top conversations: %d" % len(top_rows))
        self._set_text(self.info_text, "\n".join(lines))
        self._clear_tree(self.info_flows)
        for rank, item in enumerate(top_rows, 1):
            if not isinstance(item, dict):
                continue
            self.info_flows.insert(
                "",
                "end",
                values=(
                    rank,
                    item.get("flow", ""),
                    num(item.get("packets")),
                    human(item.get("bytes")),
                ),
            )
        self.log(
            "Info: %s packets, %s captured, duration %s (%s)."
            % (
                num(result.get("packets")),
                human(result.get("bytes")),
                human_seconds(result.get("duration_s")),
                os.path.basename(result.get("path") or ""),
            )
        )

    def _build_convert_tab(self, notebook):
        tab = ttk.Frame(notebook, padding=8)
        tab.columnconfigure(1, weight=1)
        self.c_input = tk.StringVar()
        self.c_output = tk.StringVar()
        self._row(
            tab, 0, "Input capture", self.c_input, [("Browse…", self.browse_convert_input)]
        )
        self._row(
            tab, 1, "Output file", self.c_output, [("Browse…", self.browse_convert_output)]
        )
        controls = ttk.Frame(tab)
        controls.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        ttk.Label(controls, text="Output format").pack(side="left")
        self.c_format = tk.StringVar(value="pcapng")
        format_combo = ttk.Combobox(
            controls,
            textvariable=self.c_format,
            values=["pcap", "pcapng"],
            state="readonly",
            width=10,
        )
        format_combo.pack(side="left", padx=(6, 16))
        ttk.Label(controls, text="Precision").pack(side="left")
        self.c_precision = tk.StringVar(value="default")
        precision_combo = ttk.Combobox(
            controls,
            textvariable=self.c_precision,
            values=["default", "usec", "nsec"],
            state="readonly",
            width=10,
        )
        precision_combo.pack(side="left", padx=(6, 0))
        self.c_run_btn = ttk.Button(controls, text="Convert", command=self.start_convert)
        self.c_run_btn.pack(side="right")
        self._track_busy(format_combo, precision_combo, idle_state="readonly")
        self._track_busy(self.c_run_btn)
        self.c_filters = FilterPanel(tab, self)
        self.c_filters.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(10, 0))
        ttk.Label(
            tab, text="Precision only affects pcap output.", foreground="gray"
        ).grid(row=4, column=0, columnspan=4, sticky="w", pady=(6, 0))
        return tab

    def browse_convert_input(self):
        if self._busy:
            return
        path = filedialog.askopenfilename(
            title="Choose a capture to convert",
            initialdir=self._dialog_dir("last_input_dir"),
            filetypes=CAPTURE_TYPES,
        )
        if path:
            path = os.path.normpath(path)
            self.c_input.set(path)
            self.settings["last_input_dir"] = os.path.dirname(path)
            if not self.c_output.get().strip():
                self.c_output.set(
                    self._suggest_output(path, "_converted", "." + self.c_format.get())
                )
            self._add_recent(path)

    def browse_convert_output(self):
        if self._busy:
            return
        current = self.c_output.get().strip()
        initial_dir = (
            os.path.dirname(current)
            if current and os.path.isdir(os.path.dirname(current))
            else self._dialog_dir("last_output_dir")
        )
        filename = filedialog.asksaveasfilename(
            title="Save converted capture as",
            initialdir=initial_dir,
            initialfile=os.path.basename(current) if current else None,
            defaultextension="." + self.c_format.get(),
            filetypes=CAPTURE_TYPES,
        )
        if filename:
            filename = os.path.normpath(filename)
            self.c_output.set(filename)
            self.settings["last_output_dir"] = os.path.dirname(filename)

    def start_convert(self):
        if self._busy:
            return
        try:
            path = self.c_input.get().strip()
            output = self.c_output.get().strip()
            if not path:
                raise ValueError("Choose a capture file to convert.")
            path = os.path.normpath(os.path.abspath(os.path.expanduser(path)))
            if not os.path.isfile(path):
                raise ValueError("File not found:\n%s" % path)
            if not output:
                raise ValueError("Choose an output file.")
            output = os.path.normpath(os.path.abspath(os.path.expanduser(output)))
            parent = os.path.dirname(output)
            if not os.path.isdir(parent):
                raise ValueError("Output folder does not exist:\n%s" % parent)
            output_format = self.c_format.get()
            if output_format not in ("pcap", "pcapng"):
                raise ValueError("Choose pcap or pcapng as the output format.")
            precision = self.c_precision.get()
            if precision not in ("usec", "nsec"):
                precision = None
            filter_spec = self.c_filters.spec()
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        if os.path.exists(output):
            if not messagebox.askyesno(
                APP_TITLE, "%s\nalready exists. Overwrite it?" % output, icon="warning"
            ):
                return
        self.settings["last_output_dir"] = os.path.dirname(output)
        self._remember_capture_dir(path)
        generator = lambda: core.convert_steps(
            path,
            output,
            out_format=output_format,
            precision=precision,
            filter_spec=filter_spec,
        )
        self._run_jobs(
            "Convert",
            [{"label": "Convert %s" % os.path.basename(path), "make": generator,
              "done": self._show_convert_result}],
        )

    def _show_convert_result(self, result):
        result = result or {}
        note = " — filtered" if result.get("filtered") else ""
        self.log(
            "Converted %s packets (%s) → %s [%s, %s]%s"
            % (
                num(result.get("packets")),
                human(result.get("bytes")),
                result.get("output"),
                result.get("format"),
                human(result.get("size")),
                note,
            )
        )

    def _build_trim_tab(self, notebook):
        tab = ttk.Frame(notebook, padding=8)
        tab.columnconfigure(1, weight=1)
        self.t_input = tk.StringVar()
        self.t_output = tk.StringVar()
        self._row(
            tab, 0, "Input capture", self.t_input, [("Browse…", self.browse_trim_input)]
        )
        self._row(
            tab, 1, "Output file", self.t_output, [("Browse…", self.browse_trim_output)]
        )

        times = ttk.Frame(tab)
        times.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        times.columnconfigure(1, weight=1)
        times.columnconfigure(3, weight=1)
        ttk.Label(times, text="From (ISO)").grid(row=0, column=0, sticky="w")
        self.t_from = tk.StringVar()
        from_entry = ttk.Entry(times, textvariable=self.t_from)
        from_entry.grid(row=0, column=1, sticky="ew", padx=(6, 12))
        ttk.Label(times, text="To (ISO)").grid(row=0, column=2, sticky="w")
        self.t_to = tk.StringVar()
        to_entry = ttk.Entry(times, textvariable=self.t_to)
        to_entry.grid(row=0, column=3, sticky="ew", padx=(6, 0))
        self._track_busy(from_entry, to_entry)

        counts = ttk.Frame(tab)
        counts.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        ttk.Label(counts, text="First N packets").pack(side="left")
        self.t_first = tk.StringVar()
        first_spin = ttk.Spinbox(
            counts, from_=0, to=10 ** 12, textvariable=self.t_first, width=12
        )
        first_spin.pack(side="left", padx=(6, 16))
        ttk.Label(counts, text="Last N packets").pack(side="left")
        self.t_last = tk.StringVar()
        last_spin = ttk.Spinbox(
            counts, from_=0, to=10 ** 12, textvariable=self.t_last, width=12
        )
        last_spin.pack(side="left", padx=(6, 0))
        ttk.Label(counts, text="(empty = ignore)", foreground="gray").pack(
            side="left", padx=(8, 0)
        )
        self._track_busy(first_spin, last_spin)

        controls = ttk.Frame(tab)
        controls.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        ttk.Label(controls, text="Output format").pack(side="left")
        self.t_format = tk.StringVar(value="keep")
        format_combo = ttk.Combobox(
            controls,
            textvariable=self.t_format,
            values=["keep", "pcap", "pcapng"],
            state="readonly",
            width=10,
        )
        format_combo.pack(side="left", padx=(6, 16))
        ttk.Label(controls, text="Precision").pack(side="left")
        self.t_precision = tk.StringVar(value="default")
        precision_combo = ttk.Combobox(
            controls,
            textvariable=self.t_precision,
            values=["default", "usec", "nsec"],
            state="readonly",
            width=10,
        )
        precision_combo.pack(side="left", padx=(6, 0))
        self.t_run_btn = ttk.Button(controls, text="Trim", command=self.start_trim)
        self.t_run_btn.pack(side="right")
        self._track_busy(format_combo, precision_combo, idle_state="readonly")
        self._track_busy(self.t_run_btn)

        self.t_filters = FilterPanel(tab, self)
        self.t_filters.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(10, 0))
        ttk.Label(
            tab,
            text="Leave times and counts empty to keep everything; filters still apply.",
            foreground="gray",
        ).grid(row=6, column=0, columnspan=4, sticky="w", pady=(6, 0))
        return tab

    def _suggest_output(self, input_path, tag, extension):
        stem = os.path.splitext(os.path.basename(input_path))[0]
        return os.path.join(os.path.dirname(input_path), "%s%s%s" % (stem, tag, extension))

    def browse_trim_input(self):
        if self._busy:
            return
        path = filedialog.askopenfilename(
            title="Choose a capture to trim",
            initialdir=self._dialog_dir("last_input_dir"),
            filetypes=CAPTURE_TYPES,
        )
        if path:
            path = os.path.normpath(path)
            self.t_input.set(path)
            self.settings["last_input_dir"] = os.path.dirname(path)
            if not self.t_output.get().strip():
                extension = os.path.splitext(path)[1] or ".pcap"
                self.t_output.set(self._suggest_output(path, "_trimmed", extension))
            self._add_recent(path)

    def browse_trim_output(self):
        if self._busy:
            return
        current = self.t_output.get().strip()
        initial_dir = (
            os.path.dirname(current)
            if current and os.path.isdir(os.path.dirname(current))
            else self._dialog_dir("last_output_dir")
        )
        filename = filedialog.asksaveasfilename(
            title="Save trimmed capture as",
            initialdir=initial_dir,
            initialfile=os.path.basename(current) if current else None,
            defaultextension=os.path.splitext(current)[1] or ".pcap",
            filetypes=CAPTURE_TYPES,
        )
        if filename:
            filename = os.path.normpath(filename)
            self.t_output.set(filename)
            self.settings["last_output_dir"] = os.path.dirname(filename)

    def start_trim(self):
        if self._busy:
            return
        try:
            path = self.t_input.get().strip()
            output = self.t_output.get().strip()
            if not path:
                raise ValueError("Choose a capture file to trim.")
            path = os.path.normpath(os.path.abspath(os.path.expanduser(path)))
            if not os.path.isfile(path):
                raise ValueError("File not found:\n%s" % path)
            if not output:
                raise ValueError("Choose an output file.")
            output = os.path.normpath(os.path.abspath(os.path.expanduser(output)))
            parent = os.path.dirname(output)
            if not os.path.isdir(parent):
                raise ValueError("Output folder does not exist:\n%s" % parent)
            from_ts = check_timestamp(self.t_from.get(), "From time")
            to_ts = check_timestamp(self.t_to.get(), "To time")
            first = (
                parse_positive_int(self.t_first.get(), "First N packets")
                if self.t_first.get().strip()
                else None
            )
            last = (
                parse_positive_int(self.t_last.get(), "Last N packets")
                if self.t_last.get().strip()
                else None
            )
            output_format = self.t_format.get()
            if output_format not in ("pcap", "pcapng"):
                output_format = None
            precision = self.t_precision.get()
            if precision not in ("usec", "nsec"):
                precision = None
            filter_spec = self.t_filters.spec()
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        if os.path.exists(output):
            if not messagebox.askyesno(
                APP_TITLE, "%s\nalready exists. Overwrite it?" % output, icon="warning"
            ):
                return
        self.settings["last_output_dir"] = os.path.dirname(output)
        self._remember_capture_dir(path)
        generator = lambda: core.trim_steps(
            path,
            output,
            from_ts=from_ts,
            to_ts=to_ts,
            first=first,
            last=last,
            filter_spec=filter_spec,
            out_format=output_format,
            precision=precision,
        )
        self._run_jobs(
            "Trim",
            [{"label": "Trim %s" % os.path.basename(path), "make": generator,
              "done": self._show_trim_result}],
        )

    def _show_trim_result(self, result):
        result = result or {}
        note = " — filtered" if result.get("filtered") else ""
        self.log(
            "Trimmed to %s packets (%s) → %s [%s, %s]%s"
            % (
                num(result.get("packets")),
                human(result.get("bytes")),
                result.get("output"),
                result.get("format"),
                human(result.get("size")),
                note,
            )
        )

    # ------------------------------------------------------ chunk actions --

    def _clear_tree(self, tree):
        try:
            children = tree.get_children()
            if children:
                tree.delete(*children)
        except tk.TclError:
            pass

    def _selected_chunk(self, tree, folder_variable):
        folder = folder_variable.get().strip()
        if not folder:
            messagebox.showinfo(APP_TITLE, "Choose a chunk folder first.")
            return ""
        folder = os.path.normpath(os.path.abspath(os.path.expanduser(folder)))
        selected = tree.selection()
        if not selected:
            messagebox.showinfo(APP_TITLE, "Select a chunk row in the table first.")
            return ""
        try:
            name = tree.set(selected[0], "file")
        except tk.TclError:
            name = ""
        if not name:
            messagebox.showinfo(APP_TITLE, "Select a chunk row in the table first.")
            return ""
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            messagebox.showerror(APP_TITLE, "Chunk file not found:\n%s" % path)
            return ""
        return path

    def open_selected_chunk(self, tree, folder_variable):
        path = self._selected_chunk(tree, folder_variable)
        if path:
            self.open_path_safe(path)

    def open_folder(self, folder_variable):
        folder = folder_variable.get().strip()
        if not folder:
            messagebox.showinfo(APP_TITLE, "Choose a folder first.")
            return
        folder = os.path.normpath(os.path.abspath(os.path.expanduser(folder)))
        if not os.path.isdir(folder):
            messagebox.showerror(APP_TITLE, "Folder not found:\n%s" % folder)
            return
        self.open_path_safe(folder)

    def open_selected_in_wireshark(self, tree, folder_variable):
        path = self._selected_chunk(tree, folder_variable)
        if not path:
            return
        executable = self._wireshark_executable()
        if not executable:
            return
        if os.path.basename(executable).lower().startswith("dumpcap"):
            messagebox.showwarning(
                APP_TITLE,
                "Only dumpcap was found at:\n%s\n\nIt cannot display capture files. "
                "Set Wireshark.exe in Settings → Set Wireshark path…" % executable,
            )
            return
        try:
            subprocess.Popen([executable, path])
        except OSError as exc:
            messagebox.showerror(
                APP_TITLE, "Could not start Wireshark:\n%s\n\n%s" % (executable, exc)
            )

    def _open_chunk_from_tree(self, event, tree, folder_variable):
        try:
            row = tree.identify_row(event.y)
        except tk.TclError:
            row = ""
        if not row:
            return
        try:
            tree.selection_set(row)
            tree.focus(row)
        except tk.TclError:
            pass
        self.open_selected_chunk(tree, folder_variable)

    def _find_wireshark(self):
        configured = (self.settings.get("wireshark_path") or "").strip()
        if configured and os.path.isfile(configured):
            return configured
        candidates = []
        for env_name in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
            base = os.environ.get(env_name)
            if base:
                candidates.append(os.path.join(base, "Wireshark", "Wireshark.exe"))
                candidates.append(os.path.join(base, "Wireshark", "dumpcap.exe"))
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            candidates.append(
                os.path.join(local_app_data, "Programs", "Wireshark", "Wireshark.exe")
            )
        for exe_name in ("wireshark", "dumpcap"):
            found = shutil.which(exe_name)
            if found:
                candidates.append(found)
        for candidate in candidates:
            if candidate and os.path.isfile(candidate):
                return candidate
        return ""

    def _wireshark_executable(self):
        executable = self._find_wireshark()
        if executable:
            return executable
        self.log("Wireshark was not found automatically; please locate it.")
        chosen = filedialog.askopenfilename(
            title="Locate Wireshark.exe",
            filetypes=[
                ("Wireshark executable", "wireshark.exe"),
                ("Executables", "*.exe"),
                ("All files", "*.*"),
            ],
        )
        if not chosen:
            return ""
        chosen = os.path.normpath(chosen)
        self.settings["wireshark_path"] = chosen
        self.log("Wireshark path set to %s" % chosen)
        return chosen

    def choose_wireshark(self):
        if self._busy:
            return
        current = self.settings.get("wireshark_path") or self._find_wireshark()
        initial_dir = os.path.dirname(current) if current else None
        chosen = filedialog.askopenfilename(
            title="Locate Wireshark",
            initialdir=initial_dir,
            filetypes=[
                ("Wireshark executable", "wireshark.exe"),
                ("Executables", "*.exe"),
                ("All files", "*.*"),
            ],
        )
        if chosen:
            chosen = os.path.normpath(chosen)
            self.settings["wireshark_path"] = chosen
            self.log("Wireshark path set to %s" % chosen)

    def clear_wireshark(self):
        self.settings["wireshark_path"] = ""
        self.log("Wireshark path cleared; auto-detection will be used.")

    def open_settings_folder(self):
        folder = settings_dir()
        try:
            os.makedirs(folder, exist_ok=True)
            open_path(folder)
        except OSError as exc:
            messagebox.showerror(
                APP_TITLE, "Could not open the settings folder:\n%s\n\n%s" % (folder, exc)
            )

    def open_path_safe(self, path):
        if not path:
            return
        try:
            open_path(path)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, "Could not open:\n%s\n\n%s" % (path, exc))

    # -------------------------------------------------------- job engine --

    def _run_jobs(self, title, jobs, final=None):
        if self._busy or not jobs:
            return
        self._busy = True
        self._batch_title = title
        self._jobs = list(jobs)
        self._jobs_total = len(self._jobs)
        self._jobs_index = 0
        self._jobs_ok = 0
        self._failures = []
        self._batch_final = final
        self._cancelling = False
        self.job = None
        self._job_spec = None
        self._job_started = time.perf_counter()
        self._set_busy_ui(True)
        self._reset_progress()
        self._advance_jobs()

    def _advance_jobs(self):
        self.job = None
        self._job_spec = None
        while self._jobs:
            spec = self._jobs.pop(0)
            self._jobs_index += 1
            self._job_spec = spec
            self.job_name = spec.get("label") or self._batch_title
            self._job_started = time.perf_counter()
            self._reset_progress()
            if self._jobs_total > 1:
                prefix = "[%d/%d] " % (self._jobs_index, self._jobs_total)
            else:
                prefix = ""
            self.status.configure(text="%s%s…" % (prefix, self.job_name))
            try:
                self.job = spec["make"]()
            except (core.PcapError, OSError) as exc:
                self._record_failure(exc)
                continue
            except Exception as exc:
                self._record_failure(exc)
                continue
            self.after(1, self.pump)
            return
        self._finish_jobs()

    def pump(self):
        """Advance the current job for one short slice, then yield to Tk."""
        if self.job is None:
            return
        progress = None
        deadline = time.perf_counter() + SLICE_SECONDS
        try:
            while time.perf_counter() < deadline:
                progress = next(self.job)
        except StopIteration as finished:
            result = finished.value
            self.job = None
            spec = self._job_spec or {}
            self._jobs_ok += 1
            handler = spec.get("done")
            if handler is not None:
                try:
                    handler(result)
                except Exception as exc:  # display bug must not kill the app
                    self.log("Warning: could not display the result: %s" % exc)
            self._advance_jobs()
            return
        except Exception as exc:
            self.job = None
            self._record_failure(exc)
            self._advance_jobs()
            return
        if progress:
            self._show_progress(progress)
        self.after(1, self.pump)

    def _record_failure(self, exc):
        name = self.job_name or self._batch_title
        if isinstance(exc, (core.PcapError, OSError)):
            message = str(exc) or exc.__class__.__name__
        else:
            message = "%s: %s" % (exc.__class__.__name__, exc)
            try:
                self.log(traceback.format_exc().rstrip())
            except Exception:
                pass
        self._failures.append((name, message))
        self.log("%s failed: %s" % (name, message))

    def _reset_progress(self):
        try:
            if self._indeterminate:
                self.progress.stop()
                self._indeterminate = False
            self.progress.configure(mode="determinate")
            self.progress["value"] = 0
        except tk.TclError:
            pass

    def _show_progress(self, progress):
        try:
            done, total = progress
            done = int(done)
            total = int(total)
        except (TypeError, ValueError):
            return
        prefix = "[%d/%d] " % (self._jobs_index, self._jobs_total) if self._jobs_total > 1 else ""
        if total > 0:
            if self._indeterminate:
                try:
                    self.progress.stop()
                    self.progress.configure(mode="determinate")
                except tk.TclError:
                    pass
                self._indeterminate = False
            value = max(0.0, min(1000.0, 1000.0 * done / total))
            try:
                self.progress["value"] = value
            except tk.TclError:
                pass
            elapsed = max(time.perf_counter() - self._job_started, 1e-6)
            rate = done / elapsed
            if rate > 0 and done < total:
                eta_text = ", %s left" % human_seconds((total - done) / rate)
            else:
                eta_text = ""
            self.status.configure(
                text="%s%s: %s / %s (%s/s%s)"
                % (prefix, self.job_name, human(done), human(total), human(rate), eta_text)
            )
        else:
            if not self._indeterminate:
                try:
                    self.progress.configure(mode="indeterminate")
                    self.progress.start(40)
                except tk.TclError:
                    pass
                self._indeterminate = True
            self.status.configure(
                text="%s%s: %s processed (total unknown)"
                % (prefix, self.job_name, human(done))
            )

    def cancel(self):
        if not self._busy:
            return
        self._cancelling = True
        job = self.job
        self.job = None
        if job is not None:
            try:
                job.close()  # generator cleanup removes partial output
            except Exception as exc:
                self.log("Warning: cleanup reported %s" % exc)
        self._jobs = []
        self._finish_jobs()

    def _finish_jobs(self):
        cancelled = self._cancelling
        failures = list(self._failures)
        ok = self._jobs_ok
        total = self._jobs_total
        final = self._batch_final
        title = self._batch_title
        self._jobs = []
        self.job = None
        self._job_spec = None
        self._batch_final = None
        self._cancelling = False
        self._set_busy_ui(False)
        try:
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self.progress["value"] = 0
        except tk.TclError:
            pass
        self._indeterminate = False
        if cancelled:
            self.status.configure(text="%s cancelled" % title)
            self.log("%s cancelled; incomplete output cleaned up." % title)
        elif failures:
            self.status.configure(text="%s finished with %d error(s)" % (title, len(failures)))
        else:
            self.status.configure(text="%s finished" % title)
        if final is not None:
            try:
                final(cancelled, ok, failures)
            except Exception as exc:
                self.log("Warning: could not finish up: %s" % exc)
        if failures and not cancelled:
            lines = ["%s: %s" % (name, message) for name, message in failures[:8]]
            if len(failures) > 8:
                lines.append("… and %d more (see the log)" % (len(failures) - 8))
            if total == 1:
                body = "Could not complete:\n\n" + "\n\n".join(lines)
            else:
                body = "%d of %d step(s) failed:\n\n%s" % (
                    len(failures),
                    total,
                    "\n\n".join(lines),
                )
            messagebox.showerror(APP_TITLE, body)

    def _set_busy_ui(self, busy):
        self._busy = busy
        for widget, idle_state in self._busy_widgets:
            try:
                if isinstance(widget, ttk.Notebook):
                    for tab_id in widget.tabs():
                        widget.tab(
                            tab_id,
                            state="disabled"
                            if busy and tab_id != widget.select()
                            else "normal",
                        )
                else:
                    widget.configure(state="disabled" if busy else idle_state)
            except tk.TclError:
                pass
        self._sync_split_mode()
        try:
            self.cancel_btn.configure(state="normal" if busy else "disabled")
            self.root.configure(cursor="watch" if busy else "")
        except tk.TclError:
            pass

    # ---------------------------------------------------------- theming ----

    def _on_theme_selected(self):
        self.apply_theme(self.theme_var.get())

    def _use_theme(self, style, name):
        current = style.theme_use()
        if current == name:
            # theme_use() with the same name does not reset custom styles;
            # bounce through another theme to restore the theme's defaults.
            for other in ("default", "clam", "alt"):
                if other != name and other in style.theme_names():
                    try:
                        style.theme_use(other)
                        break
                    except tk.TclError:
                        continue
        style.theme_use(name)

    def apply_theme(self, name=None):
        if name is None:
            name = self.theme_var.get() if hasattr(self, "theme_var") else "system"
        if name not in ("system", "clam", "dark"):
            name = "system"
        style = ttk.Style(self.root)
        self._dark = name == "dark"
        try:
            if name == "dark":
                self._use_theme(style, "clam")
                self._configure_dark(style)
            elif name == "clam":
                self._use_theme(style, "clam")
                self._configure_light(style)
            else:
                chosen = None
                for candidate in ("vista", "winnative", "aqua", "default"):
                    if candidate in style.theme_names():
                        chosen = candidate
                        break
                if chosen is None:
                    chosen = "clam"
                self._use_theme(style, chosen)
                self._configure_light(style)
        except tk.TclError:
            pass
        if hasattr(self, "theme_var"):
            self.theme_var.set(name)
        self.settings["theme"] = name
        for text_widget in self._text_widgets:
            self._style_text_widget(text_widget)
        for tree in self._tagged_trees:
            self._style_tree_tags(tree)
        for label, kind in list(self._colored_labels.items()):
            try:
                if label.winfo_exists():
                    self._paint_label(label, kind)
            except tk.TclError:
                pass

    def _configure_light(self, style):
        for option, value in (
            ("*TCombobox*Listbox.background", "white"),
            ("*TCombobox*Listbox.foreground", "black"),
            ("*TCombobox*Listbox.selectBackground", "#bcd6f5"),
            ("*TCombobox*Listbox.selectForeground", "black"),
        ):
            try:
                self.root.option_add(option, value)
            except tk.TclError:
                pass

    def _configure_dark(self, style):
        background = "#232629"
        panel = "#2b2f33"
        field = "#1b1d20"
        foreground = "#e6e6e6"
        muted = "#9da4ae"
        border = "#3c4043"
        button = "#2f3439"
        hover = "#3a4046"
        accent = "#3a7bd5"
        selected = "#35507a"

        style.configure(
            ".",
            background=background,
            foreground=foreground,
            fieldbackground=field,
            bordercolor=border,
            lightcolor=panel,
            darkcolor=border,
        )
        style.configure("TFrame", background=background)
        style.configure("TLabel", background=background, foreground=foreground)
        style.configure("TLabelframe", background=background, bordercolor=border)
        style.configure("TLabelframe.Label", background=background, foreground=muted)
        style.configure("TButton", background=button, foreground=foreground, bordercolor=border)
        style.map(
            "TButton",
            background=[("active", hover), ("disabled", panel)],
            foreground=[("disabled", muted)],
        )
        style.configure(
            "TEntry",
            fieldbackground=field,
            foreground=foreground,
            insertcolor=foreground,
            bordercolor=border,
            lightcolor=field,
            darkcolor=field,
        )
        style.map(
            "TEntry",
            fieldbackground=[("disabled", panel)],
            foreground=[("disabled", muted)],
        )
        style.configure(
            "TSpinbox",
            fieldbackground=field,
            foreground=foreground,
            arrowcolor=foreground,
            bordercolor=border,
        )
        style.map(
            "TSpinbox",
            fieldbackground=[("disabled", panel)],
            foreground=[("disabled", muted)],
        )
        style.configure(
            "TCombobox",
            fieldbackground=field,
            background=button,
            foreground=foreground,
            arrowcolor=foreground,
            bordercolor=border,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", field), ("disabled", panel)],
            foreground=[("disabled", muted)],
        )
        style.configure("TCheckbutton", background=background, foreground=foreground)
        style.map("TCheckbutton", background=[("active", background)])
        style.configure("TRadiobutton", background=background, foreground=foreground)
        style.map("TRadiobutton", background=[("active", background)])
        style.configure(
            "Treeview",
            background=field,
            fieldbackground=field,
            foreground=foreground,
            bordercolor=border,
            lightcolor=field,
            darkcolor=field,
        )
        style.map(
            "Treeview",
            background=[("selected", selected)],
            foreground=[("selected", "#ffffff")],
        )
        style.configure(
            "Treeview.Heading", background=panel, foreground=foreground, bordercolor=border
        )
        style.map("Treeview.Heading", background=[("active", hover)])
        style.configure("TNotebook", background=background, bordercolor=border)
        style.configure(
            "TNotebook.Tab", background=panel, foreground=muted, bordercolor=border
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", background)],
            foreground=[("selected", foreground)],
        )
        style.configure(
            "TProgressbar", background=accent, troughcolor=field, bordercolor=border
        )
        style.configure(
            "TScrollbar",
            background=button,
            troughcolor=background,
            arrowcolor=foreground,
            bordercolor=border,
        )
        style.map("TScrollbar", background=[("active", hover)])
        style.configure("TSeparator", background=border)
        for option, value in (
            ("*TCombobox*Listbox.background", field),
            ("*TCombobox*Listbox.foreground", foreground),
            ("*TCombobox*Listbox.selectBackground", selected),
            ("*TCombobox*Listbox.selectForeground", "#ffffff"),
        ):
            try:
                self.root.option_add(option, value)
            except tk.TclError:
                pass

    def _style_text_widget(self, widget):
        dark = self._dark
        background = "#1b1d20" if dark else "white"
        foreground = "#e6e6e6" if dark else "#1f2328"
        select_background = "#35507a" if dark else "#bcd6f5"
        select_foreground = "#ffffff" if dark else "#000000"
        border = "#3c4043" if dark else "#c8c8c8"
        try:
            widget.configure(
                background=background,
                foreground=foreground,
                insertbackground=foreground,
                selectbackground=select_background,
                selectforeground=select_foreground,
                highlightbackground=border,
                highlightcolor=border,
            )
        except tk.TclError:
            pass

    def _style_tree_tags(self, tree):
        dark = self._dark
        try:
            tree.tag_configure(
                "bad",
                background="#5a1f24" if dark else "#ffd9dc",
                foreground="#ffb3ba" if dark else "#7a0010",
            )
            tree.tag_configure(
                "warn",
                background="#4d3b12" if dark else "#fff3cd",
                foreground="#f0d27a" if dark else "#6b4e00",
            )
            tree.tag_configure(
                "ok",
                background="#1d3a26" if dark else "#d7f2de",
                foreground="#8fe0a2" if dark else "#135c2b",
            )
        except tk.TclError:
            pass

    def _paint_label(self, label, kind):
        palette = {
            "ok": ("#135c2b", "#8fe0a2"),
            "bad": ("#a4131f", "#ff8a92"),
            "warn": ("#7a5200", "#e8c56a"),
            "muted": ("#666666", "#9da4ae"),
        }
        light, dark = palette.get(kind, palette["muted"])
        try:
            label.configure(foreground=dark if self._dark else light)
        except tk.TclError:
            pass

    def _set_label(self, label, text, kind="muted"):
        try:
            label.configure(text=text)
        except tk.TclError:
            return
        self._colored_labels[label] = kind
        self._paint_label(label, kind)

    # ------------------------------------------------------ recent/dirs ----

    def _dialog_dir(self, key):
        for candidate in (self.settings.get(key), os.path.expanduser("~")):
            if candidate and os.path.isdir(candidate):
                return candidate
        return None

    def _remember_capture_dir(self, path):
        folder = os.path.dirname(os.path.abspath(path))
        if os.path.isdir(folder):
            self.settings["last_input_dir"] = folder

    # --------------------------------------------------------- settings ----

    def _restore_state(self):
        split = self.settings.get("split") or {}
        mode = self.settings.get("last_mode") or "size"
        if mode not in SPLIT_MODES:
            mode = "size"
        self.s_mode.set(mode)
        self.s_size.set(str(split.get("size") or "50"))
        self.s_chunks.set(str(split.get("chunks") or "8"))
        self.s_packets.set(str(split.get("packets") or "100000"))
        self.s_every.set(str(split.get("every") or "1h"))
        self.s_gap.set(str(split.get("gap") or "5m"))
        self.s_split_at.set(str(split.get("split_at") or "00:00"))
        index_csv = split.get("index_csv")
        if isinstance(index_csv, str):
            self.s_index_csv.set(index_csv)
        preset = split.get("preset") or "custom"
        label = "custom"
        for candidate_label, candidate_key in self._preset_by_label.items():
            if candidate_key == preset:
                label = candidate_label
                break
        self.s_preset.set(label)
        compression = split.get("compress") or "none"
        if compression not in ("none", "gzip", "zstd"):
            compression = "none"
        self.s_compress.set(compression)
        naming = split.get("naming") or "index"
        if naming not in ("index", "time"):
            naming = "index"
        self.s_naming.set(naming)
        self.s_resume.set(bool(split.get("resume")))
        self.s_force.set(bool(split.get("force")))
        self._sync_split_mode()

    def _collect_settings(self):
        settings = self.settings
        try:
            settings["geometry"] = self.root.geometry()
        except tk.TclError:
            pass
        if hasattr(self, "theme_var"):
            settings["theme"] = self.theme_var.get()
        if hasattr(self, "s_mode"):
            settings["last_mode"] = self.s_mode.get()
        split = settings.setdefault("split", _defaults()["split"])
        split.update(
            {
                "preset": self._selected_preset(),
                "compress": self.s_compress.get(),
                "naming": self.s_naming.get(),
                "resume": bool(self.s_resume.get()),
                "force": bool(self.s_force.get()),
                "size": self.s_size.get(),
                "chunks": self.s_chunks.get(),
                "packets": self.s_packets.get(),
                "every": self.s_every.get(),
                "gap": self.s_gap.get(),
                "split_at": self.s_split_at.get(),
                "index_csv": self.s_index_csv.get(),
            }
        )
        settings["recent"] = list(self.recent[:10])
        return settings

    # ----------------------------------------------------- drag and drop ----

    def _setup_dnd(self):
        if not DND_AVAILABLE:
            self.log(
                "Drag & drop is unavailable (tkinterdnd2 is not installed). "
                "You can still drop files onto PcapChunk.exe or use File → Add capture(s)…"
            )
            return
        registered = False
        try:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind("<<Drop>>", self._on_drop)
            registered = True
        except Exception:
            pass
        try:
            self.s_batch.drop_target_register(DND_FILES)
            self.s_batch.dnd_bind("<<Drop>>", self._on_drop)
            registered = True
        except Exception:
            pass
        if registered:
            self.log("Drag & drop enabled: drop captures or a chunk folder onto the window.")

    def _on_drop(self, event):
        self._handle_drop(getattr(event, "data", ""))
        return getattr(event, "action", "copy")

    def _drop_items(self, data):
        """Turn tkinterdnd2 drop data into a list of candidate paths."""
        if isinstance(data, (list, tuple)):
            return [str(item) for item in data]
        raw = str(data or "").strip()
        if not raw:
            return []
        try:
            items = [str(item) for item in self.root.tk.splitlist(raw)]
        except Exception:
            items = []
        if items and any(os.path.exists(str(item).strip().strip('"')) for item in items):
            return items
        braced = re.findall(r"\{([^{}]+)\}", raw)
        if braced:
            return braced
        return [raw]

    def _handle_drop(self, data):
        if self._busy:
            return
        items = self._drop_items(data)
        paths = []
        for item in items:
            path = str(item).strip().strip('"')
            if path.startswith("{") and path.endswith("}"):
                path = path[1:-1]
            if path.startswith("file://"):
                path = path[7:]
            try:
                path = os.path.normpath(path)
            except (TypeError, ValueError):
                continue
            if os.path.exists(path) and path not in paths:
                paths.append(path)
        files = [path for path in paths if os.path.isfile(path)]
        folders = [path for path in paths if os.path.isdir(path)]
        if files:
            self.nb.select(self.split_tab)
            self._add_split_paths(files)
            self.log("Added %d dropped file(s) to the Split list." % len(files))
        if folders:
            if len(folders) == 1 and not files:
                self.nb.select(self.merge_tab)
                self.set_merge_folder(folders[0])
                self.log("Dropped folder read as a merge folder: %s" % folders[0])
            else:
                for folder in folders:
                    self.log(
                        "Ignored dropped folder (use the Merge tab for chunk folders): %s"
                        % folder
                    )
        if not paths:
            self.log("Drop ignored: nothing usable was dropped.")

    # -------------------------------------------------------- shortcuts ----

    def _bind_shortcuts(self):
        def shortcut(callback):
            def handler(_event):
                self._run_shortcut(callback)
                return "break"

            return handler

        self.root.bind_all("<Control-o>", shortcut(self.browse_split_input))
        self.root.bind_all("<Control-O>", shortcut(self.browse_split_input))
        self.root.bind_all("<Control-m>", shortcut(self.browse_merge_folder))
        self.root.bind_all("<Control-M>", shortcut(self.browse_merge_folder))
        self.root.bind_all("<Control-r>", shortcut(self.run_current_tab))
        self.root.bind_all("<Control-R>", shortcut(self.run_current_tab))
        self.root.bind_all("<Escape>", lambda _event: self.cancel())
        self.root.bind_all("<F1>", shortcut(self.show_about))

    def _run_shortcut(self, callback):
        if self._busy:
            return
        try:
            callback()
        except Exception as exc:
            messagebox.showerror(APP_TITLE, "Shortcut failed:\n\n%s" % exc)

    def run_current_tab(self):
        if self._busy:
            return
        current = self.nb.select()
        if current == str(self.split_tab):
            self.start_split()
        elif current == str(self.merge_tab):
            self.start_merge()
        elif current == str(self.verify_tab):
            self.start_verify()
        else:
            selected = self.tools_nb.select()
            if selected == str(self.info_tab_widget):
                self.start_info()
            elif selected == str(self.convert_tab_widget):
                self.start_convert()
            else:
                self.start_trim()

    # ------------------------------------------------------ about/close ----

    def show_about(self):
        if self._busy:
            return
        version = getattr(core, "__version__", "unknown")
        text = (
            "%s %s\n\n"
            "Split one or more captures into portable chunks, merge them back,\n"
            "verify an existing chunk set, and inspect/convert/trim captures.\n\n"
            "No threads and no third-party runtime dependencies: every long job\n"
            "is advanced in slices from the Tk event loop and can be cancelled.\n\n"
            "Python %s · Tk %s\n"
            "Settings: %s\n\n"
            "Keyboard shortcuts\n"
            "  Ctrl+O  Add capture(s) to the Split list\n"
            "  Ctrl+M  Choose a folder to merge/verify\n"
            "  Ctrl+R  Run the current tab\n"
            "  Esc     Cancel the running job\n"
            "  F1      About"
            % (
                APP_TITLE,
                version,
                sys.version.split()[0],
                tk.TkVersion,
                settings_path(),
            )
        )
        messagebox.showinfo("About %s" % APP_TITLE, text)

    def show_shortcuts(self):
        if self._busy:
            return
        messagebox.showinfo(
            "Keyboard shortcuts",
            "Ctrl+O — add capture(s) to the Split list\n"
            "Ctrl+M — choose a folder to merge/verify\n"
            "Ctrl+R — run the active tab\n"
            "Esc — cancel the running job\n"
            "F1 — About",
        )

    def on_close(self):
        if self._busy:
            if not messagebox.askyesno(
                APP_TITLE,
                "%s is still running. Cancel it and quit?" % (self._batch_title or "A job"),
            ):
                return
            self.cancel()
        try:
            self._collect_settings()
        except Exception:
            pass
        saved = save_settings(self.settings)
        if not saved:
            try:
                messagebox.showwarning(
                    APP_TITLE,
                    "Could not save settings to:\n%s" % settings_path(),
                )
            except tk.TclError:
                pass
        try:
            self.root.destroy()
        except tk.TclError:
            pass


# ------------------------------------------------------------------- main --


def enable_dpi_awareness():
    """Best-effort per-monitor/system DPI awareness on Windows."""
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def _apply_dpi_scaling(root):
    if not sys.platform.startswith("win"):
        return
    try:
        dpi = root.winfo_fpixels("1i")
        if dpi and dpi > 0:
            root.tk.call("tk", "scaling", dpi / 72.0)
    except tk.TclError:
        pass


def _create_root():
    if DND_AVAILABLE and TkinterDnD is not None:
        try:
            return TkinterDnD.Tk()
        except Exception:
            pass
    return tk.Tk()


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    enable_dpi_awareness()
    root = _create_root()
    _apply_dpi_scaling(root)
    try:
        app = App(root)
    except Exception:
        traceback.print_exc()
        try:
            root.withdraw()
            messagebox.showerror(
                APP_TITLE, "PcapChunk could not start:\n\n%s" % traceback.format_exc()
            )
        except Exception:
            pass
        try:
            root.destroy()
        except Exception:
            pass
        return 1
    if argv:
        try:
            app.open_arguments(argv)
        except Exception as exc:
            app.log("Could not open the command-line arguments: %s" % exc)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())

