#!/usr/bin/env python3
r"""AIQuick Security — an Aura (QuickOpen design system) GUI over ``aqsec``.

A single Aura window with four sections in the sidebar: **Scan** (on-demand),
**Schedule**, **Definitions** and **About**.  Every operation calls the tested
core library (never re-implements the logic) and long work runs on a background
thread so the UI stays responsive; results are marshalled back with
``self.after`` and shown in the Aura status bar.

The app is a **tray app**: it starts with an icon on the right of the taskbar,
closing the window hides it back to the tray, and a scan is one click away from
the tray menu.  Full quit is the tray's "Exit" (or the File menu).

House-style guarantees:
  * Importing this module does nothing.  Only :func:`main` builds a root window,
    and it degrades gracefully (prints a message, returns 0) with no display or
    with customtkinter missing.
  * Frozen-exe safe: bundled assets are resolved via ``sys._MEIPASS`` / the exe
    directory when ``sys.frozen`` is set -- never ``__file__``.
  * Privacy: definitions update only on the explicit button; nothing is phoned
    home, nothing auto-updates.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import os
import sys
import threading
from datetime import datetime

# NOTE: tkinter/customtkinter are imported lazily inside main()/build_app so
# that merely importing this module (packaging, headless CI) never fails.

APP_NAME = "AIQuick Security"
APP_VERSION = "1.0.0"
WINDOW_TITLE = "AIQuick Security — by QuickOpen (quickopen.ai)"
ACCENT = "#0891b2"      # UI-accent registry: aiquick-security -> #0891b2

VIEWS = [
    ("scan", "Scan", "◎"),
    ("schedule", "Schedule", "◷"),
    ("defs", "Definitions", "⛊"),
    ("about", "About", "ⓘ"),
]

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_FREQS = ["manual", "hourly", "daily", "weekly"]
_WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
             "Saturday", "Sunday"]


# ---------------------------------------------------------------------------
# Asset / frozen handling
# ---------------------------------------------------------------------------
def asset_path(name):
    """Locate a bundled asset from source OR a PyInstaller one-file build."""
    roots = []
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(meipass)
        roots.append(os.path.dirname(os.path.abspath(sys.executable)))
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        roots += [here, os.path.dirname(here), os.getcwd()]
    for root in roots:
        candidate = os.path.join(root, name)
        if os.path.exists(candidate):
            return candidate
    return None


def open_in_file_manager(path):
    """Best-effort 'reveal in file manager', guarded on every platform."""
    try:
        folder = path if os.path.isdir(path) else os.path.dirname(
            os.path.abspath(path))
        if hasattr(os, "startfile"):
            os.startfile(folder)              # noqa: S606 - intended
        elif sys.platform == "darwin":
            import subprocess
            subprocess.Popen(["open", folder])
        else:
            import subprocess
            subprocess.Popen(["xdg-open", folder])
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# The app (built lazily; tkinter/customtkinter imported only inside build_app)
# ---------------------------------------------------------------------------
def build_app():
    """Construct and return the App class bound to live GUI imports."""
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    import customtkinter as ctk

    from . import aura, guiconfig, tray
    from .errors import AQSecError
    from . import engine as _engine
    from . import defs as _defs
    from .schedule import ScheduleConfig, next_run_after
    from .engine import default_scan_roots, engine_status, scan_paths
    from .rules import default_rules

    class App(aura.AuraApp):
        def __init__(self):
            super().__init__(
                title=WINDOW_TITLE, app_name=APP_NAME, accent=ACCENT,
                theme=guiconfig.get_theme(),
                icon_png=asset_path("aiquick-security.png"), version=APP_VERSION,
                tagline="offline malware scanner",
                on_theme_change=guiconfig.set_theme,
                size=(1080, 720), min_size=(940, 620))

            self._busy = False
            self._img_refs_gui = []
            self._stop_event = threading.Event()
            self._results = []
            self._tray = None

            self._set_icon()
            self._build_menu()

            self.progress = aura.ProgressBar(self.statusbar.actions,
                                             mode="indeterminate", width=140)

            for vid, label, glyph in VIEWS:
                self.add_section(vid, label, glyph,
                                 getattr(self, "_build_" + vid))
            self.show("scan")
            self.set_status("Ready")
            self.protocol("WM_DELETE_WINDOW", self._on_close)
            self._start_tray()
            self._sched_after = None
            self._schedule_tick()   # periodic due-check while running

        # ---- assets / icon
        def _set_icon(self):
            try:
                ico = asset_path("aiquick-security.ico")
                if ico and os.name == "nt":
                    self.iconbitmap(ico)
                    return
            except Exception:
                pass
            try:
                png = asset_path("aiquick-security.png")
                if png:
                    img = tk.PhotoImage(file=png)
                    self._img_refs_gui.append(img)
                    self.iconphoto(True, img)
            except Exception:
                pass

        def _build_menu(self):
            bar = tk.Menu(self)
            filem = tk.Menu(bar, tearoff=0)
            filem.add_command(label="Hide to tray", command=self._hide_to_tray)
            filem.add_separator()
            filem.add_command(label="Exit", command=self._real_quit)
            bar.add_cascade(label="File", menu=filem)
            viewm = tk.Menu(bar, tearoff=0)
            viewm.add_command(
                label="Toggle dark mode",
                command=lambda: self.set_theme(
                    "light" if self.theme == "dark" else "dark"))
            bar.add_cascade(label="View", menu=viewm)
            helpm = tk.Menu(bar, tearoff=0)
            helpm.add_command(label="About", command=lambda: self.show("about"))
            bar.add_cascade(label="Help", menu=helpm)
            try:
                self.config(menu=bar)
            except Exception:
                pass

        # ---- background operation runner
        def _bg(self, work, on_ok, button=None, busy="Working…"):
            if self._busy:
                self.set_error("Please wait — an operation is already running.")
                return
            self._busy = True
            if button is not None:
                try:
                    button.state(["disabled"])
                except Exception:
                    pass
            self.set_status(busy, kind="working")
            try:
                self.progress.pack(side="left", padx=(8, 4), pady=6)
                self.progress.start()
            except Exception:
                pass

            def run():
                try:
                    res, err = work(), None
                except AQSecError as ex:
                    res, err = None, str(ex)
                except Exception as ex:
                    res, err = None, f"Unexpected error: {ex}"
                self.after(0, lambda: finish(res, err))

            def finish(res, err):
                self._busy = False
                try:
                    self.progress.stop()
                    self.progress.pack_forget()
                except Exception:
                    pass
                if button is not None:
                    try:
                        button.state(["!disabled"])
                    except Exception:
                        pass
                if err is not None:
                    self.set_error(err)
                    return
                try:
                    on_ok(res)
                except Exception as ex:
                    self.set_error(f"Post-processing error: {ex}")

            threading.Thread(target=run, daemon=True).start()

        # ===============================================================
        # Scan section
        # ===============================================================
        def _build_scan(self, frame):
            aura.Caption(
                frame,
                "Scan a folder (or your whole account) for malware. The built-in "
                "rules always run; ClamAV is added when it is installed.",
                wraplength=820, justify="left").pack(anchor="w", pady=(0, 10))

            top = aura.Card(frame, title="What to scan", padding=12)
            top.pack(fill="x")
            row = ctk.CTkFrame(top.body, fg_color="transparent")
            row.pack(fill="x")
            self._scan_entry = aura.AuraEntry(
                row, placeholder="Choose a folder to scan…")
            self._scan_entry.pack(side="left", fill="x", expand=True)
            aura.AuraButton(row, "Browse…", kind="secondary",
                            command=self._browse_scan).pack(side="left",
                                                            padx=(8, 0))
            opts = ctk.CTkFrame(top.body, fg_color="transparent")
            opts.pack(fill="x", pady=(10, 0))
            self._use_roots = tk.BooleanVar(value=True)
            ctk.CTkCheckBox(opts, text="Use OS default scan roots",
                            variable=self._use_roots, font=aura.font(),
                            command=self._sync_scan_target).pack(side="left")
            self._use_clam = tk.BooleanVar(value=guiconfig.get_use_clamav())
            ctk.CTkCheckBox(opts, text="Use ClamAV engine when available",
                            variable=self._use_clam, font=aura.font(),
                            command=lambda: guiconfig.set_use_clamav(
                                self._use_clam.get())).pack(side="left", padx=16)
            self._roots_caption = aura.Caption(top.body, "")
            self._roots_caption.pack(anchor="w", pady=(8, 0))
            self._sync_scan_target()

            actions = ctk.CTkFrame(frame, fg_color="transparent")
            actions.pack(fill="x", pady=12)
            self._scan_btn = aura.AuraButton(actions, "Start scan", kind="primary",
                                             command=self._start_scan)
            self._scan_btn.pack(side="left")
            self._stop_btn = aura.AuraButton(actions, "Stop", kind="secondary",
                                             command=self._stop_scan)
            self._stop_btn.pack(side="left", padx=10)
            try:
                self._stop_btn.state(["disabled"])
            except Exception:
                pass
            self._scan_count = aura.Caption(actions, "")
            self._scan_count.pack(side="left", padx=12)

            table = ctk.CTkFrame(frame, fg_color="transparent")
            table.pack(fill="both", expand=True)
            cols = ("severity", "signature", "engine", "path")
            self._tree = ttk.Treeview(table, columns=cols, show="headings",
                                      selectmode="browse")
            for cid, text, w, anchor in (
                    ("severity", "Severity", 90, "w"),
                    ("signature", "Detection", 240, "w"),
                    ("engine", "Engine", 90, "w"),
                    ("path", "File", 520, "w")):
                self._tree.heading(cid, text=aura.spaced(text), anchor="w")
                self._tree.column(cid, width=w, anchor=anchor)
            sb = ttk.Scrollbar(table, orient="vertical",
                               command=self._tree.yview)
            self._tree.configure(yscrollcommand=sb.set)
            sb.pack(side="right", fill="y")
            self._tree.pack(side="left", fill="both", expand=True)
            self._tree.bind("<Double-1>", self._reveal_selected)

        def _browse_scan(self):
            initial = self._scan_entry.get().strip() or os.path.expanduser("~")
            chosen = filedialog.askdirectory(initialdir=initial, mustexist=True)
            if chosen:
                self._use_roots.set(False)
                self._scan_entry.delete(0, "end")
                self._scan_entry.insert(0, chosen)
                self._sync_scan_target()

        def _sync_scan_target(self):
            use_roots = self._use_roots.get()
            try:
                self._scan_entry.configure(
                    state="disabled" if use_roots else "normal")
            except Exception:
                pass
            if use_roots:
                roots = default_scan_roots()
                self._roots_caption.configure(
                    text="Will scan: " + (", ".join(roots) if roots
                                          else "(no default roots on this system)"))
            else:
                self._roots_caption.configure(
                    text="Will scan the folder above.")

        def _scan_targets(self):
            if self._use_roots.get():
                return default_scan_roots()
            p = self._scan_entry.get().strip()
            return [p] if p else []

        def _quick_scan_from_tray(self):
            """Tray 'Quick scan': scan default roots and surface the window."""
            self._show_window()
            self.show("scan")
            self._use_roots.set(True)
            self._sync_scan_target()
            self._start_scan()

        def _start_scan(self):
            paths = self._scan_targets()
            if not paths:
                self.set_error("Choose a folder to scan, or tick "
                               "“Use OS default scan roots”.")
                return
            for t in self._tree.get_children():
                self._tree.delete(t)
            self._results = []
            self._stop_event.clear()
            use_clam = self._use_clam.get()
            try:
                self._stop_btn.state(["!disabled"])
            except Exception:
                pass

            def progress(n, path):
                self.after(0, lambda: self._scan_count.configure(
                    text=f"{n} files scanned…"))

            def work():
                return scan_paths(
                    paths, rules=default_rules(), use_clamav=use_clam,
                    progress=progress,
                    should_stop=lambda: self._stop_event.is_set())

            self._bg(work, self._scan_done, button=self._scan_btn,
                     busy="Scanning…")

        def _stop_scan(self):
            self._stop_event.set()
            self.set_status("Stopping…", kind="working")

        def _scan_done(self, res):
            try:
                self._stop_btn.state(["disabled"])
            except Exception:
                pass
            self._results = list(res.findings)
            for f in sorted(res.findings,
                            key=lambda x: _SEV_ORDER.get(x.severity, 9)):
                self._tree.insert("", "end", values=(
                    f.severity.upper(), f.signature, f.engine, f.path))
            self._scan_count.configure(
                text=f"{res.files_scanned} files scanned")
            engine_txt = "ClamAV + built-in" if res.clam_used else "built-in rules"
            if res.findings:
                n = len(res.findings)
                self.set_error(
                    f"{n} detection(s) in {res.files_scanned} files "
                    f"({engine_txt}). Review the list above.")
                if self._tray:
                    self._tray.notify(
                        "AIQuick Security",
                        f"{n} threat(s) found in your last scan.")
            else:
                self.set_success(
                    f"No threats found — {res.files_scanned} files scanned "
                    f"in {res.duration:.1f}s ({engine_txt}).")

        def _reveal_selected(self, _e=None):
            sel = self._tree.selection()
            if not sel:
                return
            vals = self._tree.item(sel[0], "values")
            if len(vals) >= 4:
                open_in_file_manager(vals[3])

        # ===============================================================
        # Schedule section
        # ===============================================================
        def _build_schedule(self, frame):
            aura.Caption(
                frame,
                "Run a scan automatically on a schedule. Scans only run while "
                "AIQuick Security is open in the tray — nothing is added to the "
                "system scheduler, and nothing runs behind your back.",
                wraplength=820, justify="left").pack(anchor="w", pady=(0, 10))

            sched = guiconfig.get_schedule()
            card = aura.Card(frame, title="Scheduled scan", padding=14)
            card.pack(fill="x")

            self._sched_enabled = tk.BooleanVar(value=sched.enabled)
            aura.Switch(card.body, text="Enable scheduled scan",
                        variable=self._sched_enabled).pack(anchor="w")

            grid = ctk.CTkFrame(card.body, fg_color="transparent")
            grid.pack(fill="x", pady=(12, 0))
            ctk.CTkLabel(grid, text="Frequency:", font=aura.font()).grid(
                row=0, column=0, sticky="w", padx=(0, 8), pady=4)
            self._sched_freq = aura.AuraOption(
                grid, values=_FREQS, command=lambda _v: self._sched_refresh())
            self._sched_freq.set(sched.frequency)
            self._sched_freq.grid(row=0, column=1, sticky="w", pady=4)

            ctk.CTkLabel(grid, text="At time:", font=aura.font()).grid(
                row=1, column=0, sticky="w", padx=(0, 8), pady=4)
            timerow = ctk.CTkFrame(grid, fg_color="transparent")
            timerow.grid(row=1, column=1, sticky="w", pady=4)
            self._sched_hour = ttk.Spinbox(timerow, from_=0, to=23, width=4)
            self._sched_hour.set(sched.hour)
            self._sched_hour.pack(side="left")
            ctk.CTkLabel(timerow, text=":", font=aura.font()).pack(side="left",
                                                                   padx=3)
            self._sched_min = ttk.Spinbox(timerow, from_=0, to=59, width=4)
            self._sched_min.set(sched.minute)
            self._sched_min.pack(side="left")

            ctk.CTkLabel(grid, text="Weekday:", font=aura.font()).grid(
                row=2, column=0, sticky="w", padx=(0, 8), pady=4)
            self._sched_weekday = aura.AuraOption(grid, values=_WEEKDAYS)
            self._sched_weekday.set(_WEEKDAYS[sched.weekday])
            self._sched_weekday.grid(row=2, column=1, sticky="w", pady=4)

            aura.AuraButton(card.body, "Save schedule", kind="primary",
                            command=self._save_schedule).pack(anchor="w",
                                                              pady=(14, 0))
            self._sched_next = aura.Caption(card.body, "")
            self._sched_next.pack(anchor="w", pady=(10, 0))
            self._sched_refresh()

        def _sched_refresh(self):
            freq = self._sched_freq.get()
            try:
                state = "readonly" if freq == "weekly" else "disabled"
                self._sched_weekday.configure(
                    state="normal" if freq == "weekly" else "disabled")
            except Exception:
                pass
            self._update_next_run()

        def _read_schedule(self):
            try:
                hour = int(self._sched_hour.get())
                minute = int(self._sched_min.get())
            except Exception:
                hour, minute = 3, 0
            weekday = _WEEKDAYS.index(self._sched_weekday.get()) \
                if self._sched_weekday.get() in _WEEKDAYS else 0
            return ScheduleConfig(
                enabled=self._sched_enabled.get(),
                frequency=self._sched_freq.get(), hour=hour, minute=minute,
                weekday=weekday,
                roots=None,
                last_run=guiconfig.get_schedule().last_run)

        def _save_schedule(self):
            try:
                cfg = self._read_schedule().validate()
            except AQSecError as ex:
                self.set_error(str(ex))
                return
            guiconfig.set_schedule(cfg)
            self.set_success("Schedule saved.")
            self._update_next_run()

        def _update_next_run(self):
            try:
                cfg = self._read_schedule()
                nxt = next_run_after(cfg, datetime.now())
            except Exception:
                nxt = None
            if not getattr(self, "_sched_next", None):
                return
            if nxt:
                self._sched_next.configure(
                    text="Next run: " + nxt.strftime("%a %d %b %Y, %H:%M"))
            else:
                self._sched_next.configure(
                    text="No automatic runs (manual / disabled).")

        def _schedule_tick(self):
            """Check every minute whether a scheduled scan is due."""
            try:
                from .schedule import is_due
                cfg = guiconfig.get_schedule()
                if not self._busy and is_due(cfg, datetime.now()):
                    now_iso = datetime.now().isoformat(timespec="seconds")
                    guiconfig.record_scheduled_run(now_iso)
                    self._run_scheduled_scan(cfg)
            except Exception:
                pass
            try:
                self._sched_after = self.after(60_000, self._schedule_tick)
            except Exception:
                pass

        def _run_scheduled_scan(self, cfg):
            paths = cfg.roots or default_scan_roots()
            if not paths:
                return
            self.show("scan")
            self._use_roots.set(not bool(cfg.roots))
            self._sync_scan_target()
            if not cfg.roots:
                pass
            else:
                self._scan_entry.configure(state="normal")
                self._scan_entry.delete(0, "end")
                self._scan_entry.insert(0, cfg.roots[0])
            self._start_scan()

        # ===============================================================
        # Definitions section
        # ===============================================================
        def _build_defs(self, frame):
            aura.Caption(
                frame,
                "Virus definitions and rules update ONLY when you click Update — "
                "never automatically, and nothing is ever sent from your "
                "computer. No telemetry.",
                wraplength=820, justify="left").pack(anchor="w", pady=(0, 10))

            self._defs_card = aura.Card(frame, title="Engine status", padding=14)
            self._defs_card.pack(fill="x")
            self._defs_body = ctk.CTkFrame(self._defs_card.body,
                                           fg_color="transparent")
            self._defs_body.pack(fill="x")

            actions = ctk.CTkFrame(frame, fg_color="transparent")
            actions.pack(fill="x", pady=12)
            self._defs_btn = aura.AuraButton(
                actions, "Update definitions now", kind="primary",
                command=self._update_defs)
            self._defs_btn.pack(side="left")
            aura.AuraButton(actions, "Refresh status", kind="secondary",
                            command=self._refresh_defs).pack(side="left", padx=10)

            note = aura.Card(frame, title="How updates work", padding=14)
            note.pack(fill="x")
            aura.Caption(
                note.body,
                "• The built-in rules ship with the app and change only when you "
                "install a new version.\n"
                "• The ClamAV engine (optional) is updated by running "
                "freshclam once, here, on demand.\n"
                "• There is no background updater and no network access unless "
                "you press Update.",
                wraplength=800, justify="left").pack(anchor="w")
            self._refresh_defs()

        def _refresh_defs(self):
            for w in self._defs_body.winfo_children():
                w.destroy()
            st = engine_status(probe_version=True)
            info = _defs.definitions_info(status=st)

            def line(text, strong=False):
                aura.SectionLabel(self._defs_body, text).pack(anchor="w") \
                    if strong else aura.Caption(self._defs_body, text).pack(
                        anchor="w")

            if st.clam_installed:
                line(f"ClamAV engine: installed"
                     + (f"  ({st.version})" if st.version else ""), strong=True)
            else:
                line("ClamAV engine: not installed — scans use the built-in "
                     "rules only.", strong=True)
                aura.Caption(
                    self._defs_body,
                    "Install ClamAV to add the full engine; everything else "
                    "keeps working without it.").pack(anchor="w")
            if info.present:
                line(f"Definitions: {len(info.files or [])} file(s), updated "
                     f"{_defs.age_string(info.newest_mtime)}")
            else:
                line("Definitions: none found on disk.")
            line(f"Built-in rules: {len(default_rules())} active.")
            try:
                self._defs_btn.configure(
                    text="Update definitions now" if st.freshclam
                    else "Update definitions (ClamAV not installed)")
            except Exception:
                pass

        def _update_defs(self):
            def work():
                return _defs.update_definitions()

            def done(res):
                if res.ok:
                    self.set_success(res.message)
                elif not res.ran:
                    self.set_status(res.message, kind="idle")
                else:
                    self.set_error(res.message)
                self._refresh_defs()

            self._bg(work, done, button=self._defs_btn, busy="Updating…")

        # ===============================================================
        # About section
        # ===============================================================
        def _build_about(self, frame):
            card = aura.Card(frame, title=f"{APP_NAME} {APP_VERSION}", padding=16)
            card.pack(fill="x")
            aura.Caption(
                card.body,
                "A privacy-respecting, offline malware scanner. ClamAV-backed "
                "when installed, with its own built-in signature rules so it "
                "always works. On-demand and scheduled scans, from a tray icon "
                "on the right of your taskbar.\n\n"
                "Privacy by design: definitions update only when you ask, "
                "nothing auto-updates, and no telemetry ever leaves your "
                "computer.\n\n"
                "100% AI-built, open source (Apache-2.0). Published on QuickOpen "
                "— quickopen.ai.",
                wraplength=800, justify="left").pack(anchor="w")

            opts = aura.Card(frame, title="Preferences", padding=14)
            opts.pack(fill="x", pady=(12, 0))
            self._pref_tray = tk.BooleanVar(
                value=guiconfig.load().get("start_in_tray", True))

            def _save_pref():
                cfg = guiconfig.load()
                cfg["start_in_tray"] = self._pref_tray.get()
                guiconfig.save(cfg)

            ctk.CTkCheckBox(
                opts.body, text="Closing the window hides to the tray "
                "(instead of quitting)", variable=self._pref_tray,
                font=aura.font(), command=_save_pref).pack(anchor="w")

        # ---- tray + lifecycle
        def _start_tray(self):
            def _q(fn):
                return lambda: self.after(0, fn)
            cbs = tray.TrayCallbacks(
                on_open=_q(self._show_window),
                on_scan=_q(self._quick_scan_from_tray),
                on_update=_q(lambda: (self.show("defs"), self._update_defs())),
                on_exit=_q(self._real_quit))
            try:
                self._tray = tray.start_tray(
                    APP_NAME, cbs, icon_path=asset_path("aiquick-security.ico"),
                    tooltip=f"{APP_NAME} — offline malware scanner")
            except Exception:
                self._tray = None

        def _show_window(self):
            try:
                self.deiconify()
                self.lift()
                self.focus_force()
            except Exception:
                pass

        def _hide_to_tray(self):
            if self._tray is not None:
                try:
                    self.withdraw()
                    return
                except Exception:
                    pass
            self._real_quit()

        def _on_close(self):
            # Closing hides to tray when a tray icon exists and the pref is set.
            start_in_tray = guiconfig.load().get("start_in_tray", True)
            if self._tray is not None and start_in_tray:
                self._hide_to_tray()
            else:
                self._real_quit()

        def _real_quit(self):
            try:
                if getattr(self, "_sched_after", None):
                    self.after_cancel(self._sched_after)
            except Exception:
                pass
            if self._tray is not None:
                try:
                    self._tray.stop()
                except Exception:
                    pass
            try:
                self.destroy()
            except Exception:
                pass

    return App


def main():
    """Entry point: build the root window and run.  Degrades on headless hosts."""
    try:
        import tkinter as tk
    except Exception as exc:
        print(f"{APP_NAME}: a graphical environment with tkinter is required "
              f"to run the GUI ({exc}).")
        return 0

    try:
        App = build_app()
        app = App()
    except ImportError as exc:
        print(f"{APP_NAME}: the GUI needs the 'customtkinter' package "
              f"({exc}). Install it with:  pip install customtkinter")
        return 0
    except tk.TclError as exc:
        print(f"{APP_NAME}: no graphical display available — cannot start the "
              f"GUI here ({exc}). This app is intended for the Windows desktop.")
        return 0
    except Exception as exc:
        print(f"{APP_NAME}: could not start the GUI ({exc}).")
        return 1

    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
