#!/usr/bin/env python3
"""
analyze_gui.py -- point-and-click front end for analyze_capture.py.

Launch it (or drag a .pcapng onto the launcher) and it opens a window showing
the hosts and remote endpoints your computer connected to, in sortable tables,
flagged against an optional allowlist. Uses only the Python standard library
(Tkinter) plus the tshark that ships with Wireshark -- nothing to install.

Heavy work (tshark, reverse DNS, GeoIP) runs on a background thread so the
window stays responsive. Choosing an allowlist or toggling "Flagged only" just
re-filters the already-parsed data instantly -- no re-read of the capture.
"""

from __future__ import annotations

import os
import queue
import sys
import threading

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox

# Under pythonw.exe there is no console, so sys.stdout / sys.stderr are None and
# any print() inside the imported module would raise. Neutralise that first.
for _name in ("stdout", "stderr"):
    if getattr(sys, _name) is None:
        setattr(sys, _name, open(os.devnull, "w"))

import analyze_capture as ac  # noqa: E402  (must follow the stdout guard above)


def run_pipeline(path: str, do_rdns: bool, do_geoip: bool):
    """The heavy part: dissect + optional reverse-DNS + optional GeoIP.

    Returns (report, geo). Reverse-DNS names are cached into report.ip_to_name
    so the UI and any CSV export don't repeat the lookups. Safe off-thread.
    """
    tshark = ac.find_tshark()
    report = ac.parse(ac.run_tshark(tshark, path))
    if do_rdns:
        for ip in list(report.endpoints):
            if ip not in report.ip_to_name:
                name = ac.reverse_dns(ip)
                if name:
                    report.ip_to_name[ip] = name
    geo = ac.geolocate(list(report.endpoints)) if do_geoip else {}
    return report, geo


class App:
    def __init__(self, root: tk.Tk, initial_file: str | None = None) -> None:
        self.root = root
        self.report = None            # parsed capture (ac.Report) or None
        self.geo: dict[str, str] = {}
        self.allow_hosts: set[str] = set()
        self.allow_ips: set[str] = set()
        self.current_path: str | None = None
        self.q: queue.Queue = queue.Queue()
        self._ep_sort: dict[str, bool] = {}

        root.title("Capture Analyzer")
        root.geometry("1040x700")
        root.minsize(820, 480)

        self._build_toolbar()
        self._build_summary()
        self._build_tables()
        self._build_statusbar()

        if initial_file:
            self.start_analysis(initial_file)

    # ---------------------------------------------------------------- UI build
    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(8, 8))
        bar.pack(fill="x")

        ttk.Button(bar, text="Open Capture…", command=self.choose_file).pack(side="left")
        ttk.Button(bar, text="Re-run", command=self.rerun).pack(side="left", padx=(6, 0))

        self.rdns_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Reverse DNS", variable=self.rdns_var
                        ).pack(side="left", padx=(14, 0))
        self.geoip_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="GeoIP (uses ip-api.com)", variable=self.geoip_var
                        ).pack(side="left", padx=(8, 0))

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=12)

        ttk.Button(bar, text="Allowlist…", command=self.choose_allowlist).pack(side="left")
        ttk.Button(bar, text="Clear", command=self.clear_allowlist).pack(side="left", padx=(4, 0))
        self.allow_label = ttk.Label(bar, text="(no allowlist)", foreground="#666")
        self.allow_label.pack(side="left", padx=(6, 0))
        self.flagged_var = tk.BooleanVar(value=False)
        self.flagged_chk = ttk.Checkbutton(bar, text="Flagged only",
                                           variable=self.flagged_var,
                                           command=self.populate, state="disabled")
        self.flagged_chk.pack(side="left", padx=(10, 0))

        ttk.Button(bar, text="Export CSV…", command=self.export_csv).pack(side="right")

    def _build_summary(self) -> None:
        self.summary = ttk.Label(
            self.root, padding=(10, 2),
            text="Open a .pcapng capture to begin. "
                 "(Encrypted traffic reveals which hosts were contacted, not page content.)")
        self.summary.pack(fill="x")

    def _build_tables(self) -> None:
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=8, pady=4)

        # --- Websites / hosts, grouped by root domain (a tree) ---------------
        f1 = ttk.Frame(nb)
        nb.add(f1, text="Websites / Hosts")
        self.web = ttk.Treeview(f1, columns=("hits", "via", "status"),
                                show="tree headings")
        self.web.heading("#0", text="Host  (grouped by root domain)")
        self.web.heading("hits", text="Hits")
        self.web.heading("via", text="Seen via")
        self.web.heading("status", text="Status")
        self.web.column("#0", width=360, minwidth=200)
        self.web.column("hits", width=60, anchor="e", stretch=False)
        self.web.column("via", width=230, stretch=False)
        self.web.column("status", width=110, anchor="w", stretch=False)
        sb1 = ttk.Scrollbar(f1, orient="vertical", command=self.web.yview)
        self.web.configure(yscrollcommand=sb1.set)
        self.web.pack(side="left", fill="both", expand=True)
        sb1.pack(side="right", fill="y")

        # --- IP endpoints, flat + sortable by column -------------------------
        f2 = ttk.Frame(nb)
        nb.add(f2, text="IP Endpoints")
        cols = ("packets", "bytes", "ip", "host", "location", "status")
        titles = {"packets": "Packets", "bytes": "Bytes", "ip": "IP address",
                  "host": "Host", "location": "Location", "status": "Status"}
        widths = {"packets": 70, "bytes": 90, "ip": 150, "host": 240,
                  "location": 240, "status": 110}
        self.numeric_cols = {"packets", "bytes"}
        self.ep = ttk.Treeview(f2, columns=cols, show="headings")
        for c in cols:
            self.ep.heading(c, text=titles[c],
                            command=lambda c=c: self.sort_endpoints(c))
            self.ep.column(c, width=widths[c],
                           anchor="e" if c in self.numeric_cols else "w",
                           stretch=(c in ("host", "location")))
        sb2 = ttk.Scrollbar(f2, orient="vertical", command=self.ep.yview)
        self.ep.configure(yscrollcommand=sb2.set)
        self.ep.pack(side="left", fill="both", expand=True)
        sb2.pack(side="right", fill="y")

        # Row styling: red = flagged, amber = unknown; bold = group header.
        bold = tkfont.nametofont("TkDefaultFont").copy()
        bold.configure(weight="bold")
        for tv in (self.web, self.ep):
            tv.tag_configure("flagged", foreground="#c0392b")
            tv.tag_configure("unknown", foreground="#b9770e")
        self.web.tag_configure("group", font=bold)

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", side="bottom")
        self.status = ttk.Label(bar, text="Ready", anchor="w", padding=(8, 3))
        self.status.pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=170)
        self.progress.pack(side="right", padx=8, pady=3)

    # ----------------------------------------------------------- actions
    def choose_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open capture",
            filetypes=[("Captures", "*.pcapng *.pcap *.cap"), ("All files", "*.*")])
        if path:
            self.start_analysis(path)

    def rerun(self) -> None:
        if self.current_path:
            self.start_analysis(self.current_path)
        else:
            self.choose_file()

    def choose_allowlist(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose allowlist",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            self.allow_hosts, self.allow_ips = ac.load_allowlist(path)
        except OSError as e:
            messagebox.showerror("Allowlist", f"Couldn't read file:\n{e}")
            return
        self.allow_label.config(
            text=f"{os.path.basename(path)}  "
                 f"({len(self.allow_hosts)} domains, {len(self.allow_ips)} IPs)",
            foreground="")
        self.flagged_chk.config(state="normal")
        self.populate()

    def clear_allowlist(self) -> None:
        self.allow_hosts, self.allow_ips = set(), set()
        self.allow_label.config(text="(no allowlist)", foreground="#666")
        self.flagged_var.set(False)
        self.flagged_chk.config(state="disabled")
        self.populate()

    def export_csv(self) -> None:
        if not self.report:
            messagebox.showinfo("Export CSV", "Nothing to export yet -- open a capture first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save CSV report", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        has_allow = bool(self.allow_hosts or self.allow_ips)
        try:
            ac.write_csv(path, self.report, False, self.geo, self.allow_hosts,
                         self.allow_ips, has_allow, self.flagged_var.get())
        except OSError as e:
            messagebox.showerror("Export CSV", f"Couldn't write file:\n{e}")
            return
        messagebox.showinfo("Export CSV", f"Saved report to:\n{path}")

    # ------------------------------------------------- background analysis
    def start_analysis(self, path: str) -> None:
        if not os.path.isfile(path):
            messagebox.showerror("Open capture", f"No such file:\n{path}")
            return
        self.current_path = path
        opts = (self.rdns_var.get(), self.geoip_var.get())
        self.set_busy(True, f"Analyzing {os.path.basename(path)} …")
        threading.Thread(target=self._worker, args=(path, opts), daemon=True).start()
        self.root.after(100, self._poll)

    def _worker(self, path: str, opts: tuple[bool, bool]) -> None:
        try:
            report, geo = run_pipeline(path, opts[0], opts[1])
            self.q.put(("ok", report, geo))
        except (Exception, SystemExit) as e:  # tshark/find_tshark may sys.exit
            self.q.put(("error", str(e) or e.__class__.__name__))

    def _poll(self) -> None:
        try:
            msg = self.q.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll)
            return
        self.set_busy(False)
        if msg[0] == "error":
            messagebox.showerror("Analysis failed", msg[1])
            return
        _, self.report, self.geo = msg
        self.populate()

    # -------------------------------------------------------- rendering
    def populate(self) -> None:
        """(Re)draw both tables from the current report + allowlist + filter."""
        if not self.report:
            return
        r = self.report
        flagged_only = self.flagged_var.get()
        has_allow = bool(self.allow_hosts or self.allow_ips)

        # Websites tree ----------------------------------------------------
        self.web.delete(*self.web.get_children())
        groups = ac.group_by_root(r)
        flagged_hosts = 0
        for root, g in sorted(groups.items(), key=lambda kv: (-kv[1]["count"], kv[0])):
            subs = sorted(g["subs"].items(), key=lambda kv: (-kv[1], kv[0]))
            not_ok = {h for h, _ in subs
                      if has_allow and not ac.host_allowed(h, self.allow_hosts)}
            flagged_hosts += len(not_ok)
            if flagged_only and not not_ok:
                continue
            gstatus = "" if not has_allow else (
                "OK" if not not_ok else f"FLAGGED ({len(not_ok)})")
            gtags = ("group",) + (("flagged",) if not_ok else ())
            parent = self.web.insert("", "end", text=root, open=bool(not_ok),
                                     values=(g["count"], "", gstatus), tags=gtags)
            for h, c in subs:
                if flagged_only and h not in not_ok:
                    continue
                flagged = h in not_ok
                via = ", ".join(sorted(r.host_source[h]))
                st = "" if not has_allow else ("FLAGGED" if flagged else "allowed")
                self.web.insert(parent, "end", text=h, values=(c, via, st),
                                tags=(("flagged",) if flagged else ()))

        # Endpoints table --------------------------------------------------
        self.ep.delete(*self.ep.get_children())
        flagged_eps = 0
        for ip, ep in sorted(r.endpoints.items(), key=lambda kv: -kv[1]["bytes"]):
            host = ac.label_ip(ip, r, False)
            status = ac.endpoint_status(ip, host, self.allow_hosts,
                                        self.allow_ips) if has_allow else "ok"
            if status == "flagged":
                flagged_eps += 1
            if flagged_only and status == "ok":
                continue
            tag = {"flagged": "flagged", "unknown": "unknown"}.get(status, "")
            stlabel = {"flagged": "NOT ALLOWED", "unknown": "unknown",
                       "ok": "allowed" if has_allow else ""}[status]
            self.ep.insert("", "end",
                           values=(ep["packets"], f"{ep['bytes']:,}", ip, host,
                                   self.geo.get(ip, ""), stlabel),
                           tags=((tag,) if tag else ()))

        # Summary line -----------------------------------------------------
        parts = [os.path.basename(self.current_path or ""),
                 f"{len(r.hosts)} hosts in {len(groups)} root domains",
                 f"{len(r.endpoints)} endpoints"]
        if has_allow:
            parts.append(f"⚠ {flagged_hosts} flagged hosts, "
                         f"{flagged_eps} flagged endpoints")
        self.summary.config(text="      |      ".join(parts))

    def sort_endpoints(self, col: str) -> None:
        numeric = col in self.numeric_cols
        rows = [(self.ep.set(k, col), k) for k in self.ep.get_children("")]
        if numeric:
            key = lambda v: float(v[0].replace(",", "") or 0)  # noqa: E731
        else:
            key = lambda v: v[0].lower()                       # noqa: E731
        reverse = self._ep_sort.get(col, not numeric)  # numeric: big->small first
        rows.sort(key=key, reverse=reverse)
        for i, (_, k) in enumerate(rows):
            self.ep.move(k, "", i)
        self._ep_sort[col] = not reverse

    def set_busy(self, busy: bool, text: str | None = None) -> None:
        if text:
            self.status.config(text=text)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()
            self.status.config(text="Ready")


def main() -> None:
    initial = sys.argv[1] if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]) else None
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.25)  # crisper on high-DPI displays
    except tk.TclError:
        pass
    App(root, initial)
    root.mainloop()


if __name__ == "__main__":
    main()
