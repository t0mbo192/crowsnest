#!/usr/bin/env python3
"""
Connection Viewer -- the netwatch desktop app.

Reads a Wireshark capture (.pcapng / .pcap) and shows, in plain language, the
connections your computer made and received:

    * every site / host, split into OUTBOUND (you connected out) and INBOUND
      (something connected to you),
    * a short description of what each host is,
    * a live filter box, direction filter, and dark / light themes,
    * an "Export" button to save a simple text printout.

Analysis lives in netwatch_core, so it is shared with the terminal front end and
stays importable on a headless machine. Captures are read with the `tshark`
program that ships with Wireshark, so Wireshark must be installed -- but Python
does NOT need to be, once this is built into an .exe with PyInstaller.

Build a standalone .exe:
    pyinstaller --onefile --windowed --name ConnectionViewer connection_viewer.py
"""

from __future__ import annotations

import glob
import json
import os
import queue
import sys
import threading
import webbrowser

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox

import updater
from netwatch_version import __version__
from netwatch_core import (
    DROP_DIR, analyze, describe, fill_names, human_bytes, is_private,
    make_text, resolve_many,
)


# ----------------------------------------------------------------------------
# Theme
#
# Built on ttk's "clam" theme because it is the only stock theme that honours
# colour configuration on every platform -- the Windows default ("vista")
# silently ignores most of it. No third-party theme packages, so this still
# runs on a bare Raspberry Pi and bundles cleanly with PyInstaller.
# ----------------------------------------------------------------------------
PALETTES = {
    "dark": {
        "bg":        "#15171c",   # window background
        "surface":   "#1e2128",   # cards, table, inputs
        "surface2":  "#252932",   # table stripe / hover
        "border":    "#2f343f",
        "text":      "#e7eaf0",
        "muted":     "#8b93a3",
        "accent":    "#5b9cff",   # outbound / primary
        "accent_fg": "#ffffff",
        "inbound":   "#ff9d5c",   # inbound stands out on a monitoring screen
        "good":      "#4ec9a5",
        "heading":   "#232730",
    },
    "light": {
        "bg":        "#f4f6f9",
        "surface":   "#ffffff",
        "surface2":  "#f7f9fc",
        "border":    "#dfe4ec",
        "text":      "#1b1f28",
        "muted":     "#69717f",
        "accent":    "#2f6fed",
        "accent_fg": "#ffffff",
        "inbound":   "#c2570f",
        "good":      "#12855f",
        "heading":   "#eef1f6",
    },
}

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".netwatch.json")


def load_prefs() -> dict:
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_prefs(prefs: dict) -> None:
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(prefs, f)
    except OSError:
        pass


def pick_font(candidates: list[str], fallback: str) -> str:
    try:
        available = set(tkfont.families())
    except tk.TclError:
        return fallback
    for name in candidates:
        if name in available:
            return name
    return fallback


def dark_titlebar(root: tk.Tk, enabled: bool) -> None:
    """Match the Windows title bar to the theme. No-op elsewhere."""
    if os.name != "nt":
        return
    try:
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(1 if enabled else 0)
        # 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (19 on older Windows 10 builds)
        for attr in (20, 19):
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, attr, ctypes.byref(value), ctypes.sizeof(value))
    except Exception:
        pass


def apply_theme(root: tk.Tk, style: ttk.Style, mode: str) -> dict:
    """Paint every widget style for the chosen mode; returns the palette."""
    c = PALETTES[mode]
    ui = pick_font(["Segoe UI", "Inter", "DejaVu Sans", "Helvetica"], "TkDefaultFont")
    mono = pick_font(["Cascadia Mono", "Consolas", "DejaVu Sans Mono"], "TkFixedFont")

    style.theme_use("clam")
    root.configure(bg=c["bg"])

    style.configure(".", background=c["bg"], foreground=c["text"],
                    fieldbackground=c["surface"], borderwidth=0, font=(ui, 10))
    style.configure("TFrame", background=c["bg"])
    style.configure("Card.TFrame", background=c["surface"])
    style.configure("TLabel", background=c["bg"], foreground=c["text"])
    style.configure("Card.TLabel", background=c["surface"], foreground=c["text"])
    style.configure("Title.TLabel", font=(ui, 15, "bold"), foreground=c["text"])
    style.configure("Muted.TLabel", foreground=c["muted"], font=(ui, 9))
    style.configure("CardMuted.TLabel", background=c["surface"],
                    foreground=c["muted"], font=(ui, 8))
    style.configure("Stat.TLabel", background=c["surface"], foreground=c["text"],
                    font=(ui, 17, "bold"))
    style.configure("StatAccent.TLabel", background=c["surface"],
                    foreground=c["accent"], font=(ui, 17, "bold"))
    style.configure("StatIn.TLabel", background=c["surface"],
                    foreground=c["inbound"], font=(ui, 17, "bold"))

    # Buttons -- flat, with a visible hover state.
    style.configure("TButton", background=c["surface2"], foreground=c["text"],
                    borderwidth=0, focuscolor=c["surface2"], padding=(12, 7),
                    font=(ui, 9))
    style.map("TButton",
              background=[("pressed", c["border"]), ("active", c["border"])])
    style.configure("Accent.TButton", background=c["accent"],
                    foreground=c["accent_fg"], padding=(14, 7), font=(ui, 9, "bold"))
    style.map("Accent.TButton", background=[("pressed", c["accent"]),
                                            ("active", c["accent"])])

    style.configure("TEntry", fieldbackground=c["surface"], foreground=c["text"],
                    insertcolor=c["text"], borderwidth=1, padding=6)
    style.map("TEntry", bordercolor=[("focus", c["accent"])])
    style.configure("TCheckbutton", background=c["bg"], foreground=c["muted"],
                    focuscolor=c["bg"], font=(ui, 9),
                    indicatorbackground=c["surface"],
                    indicatorforeground=c["accent_fg"],
                    indicatormargin=(0, 0, 6, 0), borderwidth=0)
    style.map("TCheckbutton", foreground=[("active", c["text"])],
              indicatorbackground=[("selected", c["accent"]),
                                   ("active", c["surface2"])])

    # Segmented direction control (radiobuttons drawn as toggle buttons).
    style.configure("Toolbutton", background=c["surface2"], foreground=c["muted"],
                    borderwidth=0, padding=(14, 6), font=(ui, 9))
    style.map("Toolbutton",
              background=[("selected", c["accent"]), ("active", c["border"])],
              foreground=[("selected", c["accent_fg"]), ("active", c["text"])])

    # Table.
    style.configure("Treeview", background=c["surface"], fieldbackground=c["surface"],
                    foreground=c["text"], borderwidth=0, rowheight=30, font=(ui, 10))
    style.map("Treeview", background=[("selected", c["accent"])],
              foreground=[("selected", c["accent_fg"])])
    style.configure("Treeview.Heading", background=c["heading"],
                    foreground=c["muted"], relief="flat", borderwidth=0,
                    padding=(10, 9), font=(ui, 9, "bold"))
    style.map("Treeview.Heading", background=[("active", c["border"])])

    style.configure("Vertical.TScrollbar", background=c["surface2"],
                    troughcolor=c["bg"], borderwidth=0, arrowcolor=c["muted"])
    style.map("Vertical.TScrollbar", background=[("active", c["border"])])
    style.configure("TProgressbar", background=c["accent"], troughcolor=c["bg"],
                    borderwidth=0)

    dark_titlebar(root, mode == "dark")
    return {"c": c, "ui": ui, "mono": mono}


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------
COLUMNS = [
    ("dir",     "Direction", 110, False),
    ("site",    "Site / host", 300, True),
    ("desc",    "What it is", 260, True),
    ("ip",      "IP address", 150, False),
    ("packets", "Packets", 90, False),
    ("bytes",   "Data", 100, False),
]
NUMERIC_COLS = {"packets", "bytes"}


class App:
    def __init__(self, root: tk.Tk, initial: str | None = None):
        self.root = root
        self.capture = None
        self.meta: dict = {}
        self.all_rows: list[dict] = []
        self.q: queue.Queue = queue.Queue()
        self.update_q: queue.Queue = queue.Queue()   # update check, own channel
        self._busy = False
        self._sort_col = "bytes"
        self._sort_desc = True
        self._update = None

        self.prefs = load_prefs()
        self.mode = self.prefs.get("theme", "dark")
        self.style = ttk.Style(root)
        self.theme = apply_theme(root, self.style, self.mode)

        root.title(f"netwatch {__version__} — Connection Viewer")
        root.geometry("1180x740")
        root.minsize(900, 520)

        self._build_header()
        self._build_stats()
        self._build_controls()
        self._build_table()
        self._build_statusbar()
        # Wired up only once every widget exists -- setting the placeholder text
        # above would otherwise fire refresh() before the table is built.
        self.filter_var.trace_add("write", lambda *_: self.refresh())

        self._start_update_check()
        if initial:
            self.load(initial)

    # ------------------------------------------------------------------ build
    def _build_header(self):
        bar = ttk.Frame(self.root, padding=(18, 16, 18, 10))
        bar.pack(fill="x")
        left = ttk.Frame(bar)
        left.pack(side="left")
        ttk.Label(left, text="netwatch", style="Title.TLabel").pack(anchor="w")
        self.info = ttk.Label(left, text="No capture loaded", style="Muted.TLabel")
        self.info.pack(anchor="w", pady=(2, 0))

        right = ttk.Frame(bar)
        right.pack(side="right")
        self.theme_btn = ttk.Button(right, text=self._theme_label(),
                                    command=self.toggle_theme, width=10)
        self.theme_btn.pack(side="right")
        ttk.Button(right, text="Export", command=self.export
                   ).pack(side="right", padx=(0, 8))
        ttk.Button(right, text="Open Capture", style="Accent.TButton",
                   command=self.choose).pack(side="right", padx=(0, 8))
        # Stays hidden unless a newer version is actually found.
        self.update_btn = ttk.Button(right, text="", command=self._show_update)


    def _build_stats(self):
        wrap = ttk.Frame(self.root, padding=(18, 0, 18, 12))
        wrap.pack(fill="x")
        self.stat_vars = {}
        specs = [("total", "CONNECTIONS", "Stat.TLabel"),
                 ("out", "OUTBOUND", "StatAccent.TLabel"),
                 ("inb", "INBOUND", "StatIn.TLabel"),
                 ("data", "DATA", "Stat.TLabel")]
        for i, (key, label, vstyle) in enumerate(specs):
            card = ttk.Frame(wrap, style="Card.TFrame", padding=(16, 12))
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 10, 0))
            wrap.columnconfigure(i, weight=1)
            var = tk.StringVar(value="—")
            ttk.Label(card, textvariable=var, style=vstyle).pack(anchor="w")
            ttk.Label(card, text=label, style="CardMuted.TLabel").pack(anchor="w")
            self.stat_vars[key] = var

    def _build_controls(self):
        bar = ttk.Frame(self.root, padding=(18, 0, 18, 10))
        bar.pack(fill="x")

        self.filter_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self.filter_var, width=34)
        entry.pack(side="left")
        self._placeholder(entry, "Filter by site, description or IP…")

        seg = ttk.Frame(bar)
        seg.pack(side="left", padx=(12, 0))
        self.dir_var = tk.StringVar(value="all")
        for value, text in (("all", "All"), ("outbound", "Outbound"),
                            ("inbound", "Inbound")):
            ttk.Radiobutton(seg, text=text, value=value, variable=self.dir_var,
                            style="Toolbutton", command=self.refresh
                            ).pack(side="left", padx=(0, 2))

        self.resolve_var = tk.BooleanVar(value=self.prefs.get("resolve", True))
        ttk.Checkbutton(bar, text="Look up host names", variable=self.resolve_var
                        ).pack(side="left", padx=(14, 0))

        self.count_label = ttk.Label(bar, text="", style="Muted.TLabel")
        self.count_label.pack(side="right")

    def _placeholder(self, entry: ttk.Entry, text: str):
        """Grey hint text that clears on focus."""
        c = self.theme["c"]
        entry.insert(0, text)
        entry.configure(foreground=c["muted"])
        self._ph_active = True

        def on_focus_in(_):
            if self._ph_active:
                entry.delete(0, "end")
                entry.configure(foreground=c["text"])
                self._ph_active = False

        def on_focus_out(_):
            if not entry.get():
                self._ph_active = True
                entry.configure(foreground=c["muted"])
                entry.insert(0, text)

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)
        self._filter_entry = entry
        self._filter_placeholder = text

    def _build_table(self):
        frame = ttk.Frame(self.root, padding=(18, 0, 18, 0))
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frame, columns=[c[0] for c in COLUMNS],
                                 show="headings", selectmode="browse")
        for key, title, width, stretch in COLUMNS:
            anchor = "e" if key in NUMERIC_COLS else "w"
            self.tree.heading(key, text=title, anchor=anchor,
                              command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, stretch=stretch, anchor=anchor)
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._tag_rows()

    def _tag_rows(self):
        c = self.theme["c"]
        self.tree.tag_configure("odd", background=c["surface"])
        self.tree.tag_configure("even", background=c["surface2"])
        self.tree.tag_configure("in", foreground=c["inbound"])
        self.tree.tag_configure("out", foreground=c["text"])

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, padding=(18, 8, 18, 12))
        bar.pack(fill="x", side="bottom")
        self.status = ttk.Label(bar, text="Open a capture to begin.",
                                style="Muted.TLabel")
        self.status.pack(side="left")
        # Packed only while working -- an idle indeterminate bar still paints a
        # stray chunk, which reads as "something is running" when nothing is.
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=170)

    # ----------------------------------------------------------------- updates
    def _start_update_check(self):
        """Ask in the background whether a newer netwatch exists.

        Purely advisory -- nothing is downloaded, and a failed check is silent
        apart from the status bar. Runs off the main thread so a slow network
        can never stall the window.
        """
        def worker():
            try:
                self.update_q.put(updater.check(__version__))
            except Exception:
                self.update_q.put({"status": "unknown"})

        threading.Thread(target=worker, daemon=True).start()
        self.root.after(400, self._poll_update)

    def _poll_update(self):
        try:
            result = self.update_q.get_nowait()
        except queue.Empty:
            self.root.after(400, self._poll_update)
            return
        self._update = result
        if result.get("status") != "update":
            return
        if result.get("how") == "git":
            n = result.get("behind", 0)
            label = f"● Update: {n} commit{'' if n == 1 else 's'}"
        else:
            label = f"● Update: v{result.get('version')}"
        self.update_btn.config(text=label, style="Accent.TButton")
        self.update_btn.pack(side="right", padx=(0, 8))

    def _show_update(self):
        """Explain how to take the update -- we never apply it silently."""
        r = self._update or {}
        if r.get("how") == "git":
            n = r.get("behind", 0)
            body = (f"{n} new commit{'' if n == 1 else 's'} available.\n\n"
                    f"Latest: {r.get('detail', '')}\n\n"
                    f"Update with:\n    git pull\n\n"
                    f"Then restart netwatch.")
            messagebox.showinfo("Update available", body)
            return
        version = r.get("version", "")
        if messagebox.askyesno(
                "Update available",
                f"netwatch v{version} is available "
                f"(you have {__version__}).\n\n"
                f"Open the download page in your browser?"):
            webbrowser.open(r.get("url") or updater.RELEASES_PAGE)

    # ------------------------------------------------------------------ theme
    def _theme_label(self) -> str:
        return "Light mode" if self.mode == "dark" else "Dark mode"

    def toggle_theme(self):
        self.mode = "light" if self.mode == "dark" else "dark"
        self.theme = apply_theme(self.root, self.style, self.mode)
        self.theme_btn.config(text=self._theme_label())
        self._tag_rows()
        c = self.theme["c"]
        if getattr(self, "_ph_active", False):
            self._filter_entry.configure(foreground=c["muted"])
        else:
            self._filter_entry.configure(foreground=c["text"])
        self.refresh()
        self.prefs["theme"] = self.mode
        save_prefs(self.prefs)

    # ---------------------------------------------------------------- actions
    def choose(self):
        path = filedialog.askopenfilename(
            title="Open capture",
            filetypes=[("Captures", "*.pcapng *.pcap *.cap"), ("All files", "*.*")])
        if path:
            self.load(path)

    def load(self, path: str):
        """Kick off analysis on a background thread so the window stays live."""
        if not os.path.isfile(path):
            messagebox.showerror("Open capture", f"No such file:\n{path}")
            return
        if self._busy:
            return
        self.capture = path
        self.prefs["resolve"] = bool(self.resolve_var.get())
        save_prefs(self.prefs)
        self._set_busy(True, f"Reading {os.path.basename(path)} …")
        threading.Thread(target=self._parse_worker, args=(path,),
                         daemon=True).start()
        self.root.after(80, self._poll)

    # Workers run off the main thread and only ever hand results to the queue --
    # every widget and row update happens back in _poll on the main thread.
    def _parse_worker(self, path: str):
        try:
            self.q.put(("parsed", analyze(path, resolve=False)))
        except Exception as e:
            self.q.put(("error", str(e) or e.__class__.__name__))

    def _names_worker(self, ips: list[str]):
        try:
            self.q.put(("names", resolve_many(ips)))
        except Exception:
            self.q.put(("names", {}))

    def _poll(self):
        try:
            msg = self.q.get_nowait()
        except queue.Empty:
            self.root.after(80, self._poll)
            return

        kind = msg[0]
        if kind == "error":
            self._set_busy(False)
            messagebox.showerror("Analysis failed", msg[1])
            return

        if kind == "parsed":
            self.meta = msg[1]
            self.all_rows = self.meta["rows"]
            self.info.config(
                text=f"{os.path.basename(self.capture)}   ·   "
                     f"this machine {self.meta['my_ip'] or '?'}   ·   "
                     f"{self.meta['packets']} packets")
            self.refresh()   # table is usable now; names arrive next
            unresolved = [r["ip"] for r in self.all_rows if not r["name"]]
            if unresolved and self.resolve_var.get():
                self.status.config(
                    text=f"Looking up {len(unresolved)} host name(s) …")
                threading.Thread(target=self._names_worker, args=(unresolved,),
                                 daemon=True).start()
                self.root.after(80, self._poll)
            else:
                self._set_busy(False)
            return

        if kind == "names":
            names = msg[1]
            found = 0
            for r in self.all_rows:
                name = names.get(r["ip"], "")
                if name and not r["name"]:
                    r["name"] = r["site"] = name
                    r["description"] = describe(name, r["local"], r["ip"])
                    found += 1
            if found:
                self.refresh()
            self._set_busy(False)

    def _set_busy(self, busy: bool, text: str | None = None):
        self._busy = busy
        if text:
            self.status.config(text=text)
        if busy:
            self.progress.pack(side="right")
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()
            self.status.config(
                text=f"{len(self.all_rows)} connections" if self.all_rows
                else "Open a capture to begin.")

    # --------------------------------------------------------------- display
    def _filter_text(self) -> str:
        if getattr(self, "_ph_active", False):
            return ""
        return self.filter_var.get().strip().lower()

    def _visible_rows(self) -> list[dict]:
        text = self._filter_text()
        want = self.dir_var.get()
        rows = []
        for r in self.all_rows:
            if want != "all" and r["direction"] != want:
                continue
            if text and text not in (
                    f"{r['site']} {r['description']} {r['ip']}").lower():
                continue
            rows.append(r)
        # Sorting works on the underlying values, not the formatted strings.
        keys = {"dir": lambda r: r["direction"], "site": lambda r: r["site"].lower(),
                "desc": lambda r: r["description"].lower(),
                "ip": lambda r: r["ip"], "packets": lambda r: r["packets"],
                "bytes": lambda r: r["bytes"]}
        rows.sort(key=keys[self._sort_col], reverse=self._sort_desc)
        return rows

    def sort_by(self, col: str):
        if self._sort_col == col:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_col = col
            self._sort_desc = col in NUMERIC_COLS
        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        rows = self._visible_rows()
        for i, r in enumerate(rows):
            outbound = r["direction"] == "outbound"
            self.tree.insert(
                "", "end",
                values=("↑  Outbound" if outbound else "↓  Inbound",
                        r["site"], r["description"], r["ip"],
                        f"{r['packets']:,}", human_bytes(r["bytes"])),
                tags=("out" if outbound else "in",
                      "odd" if i % 2 else "even"))

        for key, title, _w, _s in COLUMNS:
            arrow = ""
            if key == self._sort_col:
                arrow = "  ▼" if self._sort_desc else "  ▲"
            self.tree.heading(key, text=title + arrow)

        n_out = sum(1 for r in rows if r["direction"] == "outbound")
        n_in = len(rows) - n_out
        total_bytes = sum(r["bytes"] for r in self.all_rows)
        self.stat_vars["total"].set(str(len(self.all_rows)))
        self.stat_vars["out"].set(
            str(sum(1 for r in self.all_rows if r["direction"] == "outbound")))
        self.stat_vars["inb"].set(
            str(sum(1 for r in self.all_rows if r["direction"] == "inbound")))
        self.stat_vars["data"].set(human_bytes(total_bytes) if total_bytes else "—")
        self.count_label.config(
            text=f"showing {len(rows)} of {len(self.all_rows)}"
                 f"   ·   {n_out} out, {n_in} in")

    def export(self):
        if not self.all_rows:
            messagebox.showinfo("Export", "Open a capture first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save printout", defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(make_text(self.capture, self.meta, self._visible_rows()))
        except OSError as e:
            messagebox.showerror("Export", f"Couldn't write file:\n{e}")
            return
        messagebox.showinfo("Export", f"Saved printout to:\n{path}")


def _newest(folder: str):
    files = glob.glob(os.path.join(folder, "*.pcapng")) + \
        glob.glob(os.path.join(folder, "*.pcap"))
    return max(files, key=os.path.getmtime) if files else None


def main():
    initial = None
    if len(sys.argv) > 1 and sys.argv[1].strip() and os.path.isfile(sys.argv[1]):
        initial = sys.argv[1]
    else:
        try:
            os.makedirs(DROP_DIR, exist_ok=True)
            initial = _newest(DROP_DIR)
        except OSError:
            pass
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.25)
    except tk.TclError:
        pass
    App(root, initial)
    root.mainloop()


if __name__ == "__main__":
    for _n in ("stdout", "stderr"):
        if getattr(sys, _n) is None:
            setattr(sys, _n, open(os.devnull, "w"))
    main()
