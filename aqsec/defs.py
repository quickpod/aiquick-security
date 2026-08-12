r"""Virus-definitions updater — explicit user action only, never automatic.

This is the *only* code path that reaches the network, and it runs **only when
the user asks** (the CLI ``update-defs`` command or the GUI "Update now"
button).  There is no background timer, no auto-update, and no telemetry --
which is exactly what the OS product rules demand (no dial-back, no
auto-update).

When ClamAV's ``freshclam`` is installed we run it once, synchronously, and
report the result.  When it is not installed we say so plainly (the built-in
rules keep working regardless).  The built-in rules ship with the app and are
"updated" only by installing a new app version -- again, an explicit action.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Callable, List, Optional

from .errors import AQSecError
from . import engine
from .engine import EngineStatus


@dataclass
class DefsInfo:
    """What we know about the on-disk virus definitions."""

    db_dir: Optional[str] = None
    present: bool = False
    files: Optional[List[dict]] = None   # [{name, bytes, mtime}]
    newest_mtime: Optional[float] = None

    def as_dict(self):
        return {"db_dir": self.db_dir, "present": self.present,
                "files": self.files or [], "newest_mtime": self.newest_mtime}


@dataclass
class UpdateResult:
    """Outcome of an explicit definitions update."""

    ran: bool                 # did freshclam actually run?
    ok: bool                  # did it succeed?
    message: str              # human-readable summary
    output: str = ""          # trimmed freshclam output

    def as_dict(self):
        return {"ran": self.ran, "ok": self.ok, "message": self.message,
                "output": self.output}


def definitions_info(status: Optional[EngineStatus] = None) -> DefsInfo:
    """Report the local ClamAV definition files (filesystem only, no network)."""
    st = status or engine.engine_status()
    info = DefsInfo(db_dir=st.db_dir, present=st.db_present)
    if not st.db_dir or not os.path.isdir(st.db_dir):
        return info
    files, newest = [], None
    try:
        for name in sorted(os.listdir(st.db_dir)):
            if not name.endswith((".cvd", ".cld")):
                continue
            fp = os.path.join(st.db_dir, name)
            try:
                stt = os.stat(fp)
            except OSError:
                continue
            files.append({"name": name, "bytes": stt.st_size,
                          "mtime": stt.st_mtime})
            newest = stt.st_mtime if newest is None else max(newest, stt.st_mtime)
    except OSError:
        pass
    info.files = files
    info.newest_mtime = newest
    return info


def update_definitions(status: Optional[EngineStatus] = None,
                       progress: Optional[Callable[[str], None]] = None
                       ) -> UpdateResult:
    """Update ClamAV definitions **now** by running ``freshclam`` once.

    This is deliberately a one-shot, foreground, user-initiated operation.  It
    is never called on a timer.  If ``freshclam`` is missing it returns a
    ``ran=False`` result explaining that ClamAV is not installed -- it does not
    try to fetch or install anything itself.
    """
    st = status or engine.engine_status()
    if not st.freshclam:
        return UpdateResult(
            ran=False, ok=False,
            message="ClamAV's updater (freshclam) is not installed, so there "
                    "are no external definitions to refresh. The built-in "
                    "rules are always active. Install ClamAV to enable engine "
                    "definitions.")
    if progress:
        try:
            progress("Running freshclam…")
        except Exception:
            pass
    rc, out, err = engine._execute([st.freshclam], timeout=1800)
    text = (out or "") + (("\n" + err) if err else "")
    text = text.strip()
    # freshclam exit codes: 0 = updated, 1 = already up to date (no error).
    if rc in (0, 1):
        already = rc == 1 or "up to date" in text.lower() or "up-to-date" in text.lower()
        msg = ("Definitions are already up to date." if already
               else "Virus definitions updated successfully.")
        return UpdateResult(ran=True, ok=True, message=msg, output=text[-4000:])
    return UpdateResult(ran=True, ok=False,
                        message=f"freshclam reported an error (exit {rc}).",
                        output=text[-4000:])


def age_string(newest_mtime: Optional[float], now: Optional[float] = None) -> str:
    """A short 'updated N days ago' style string for a definitions timestamp."""
    if not newest_mtime:
        return "unknown"
    now = now if now is not None else time.time()
    secs = max(0, int(now - newest_mtime))
    if secs < 3600:
        return f"{secs // 60} min ago"
    if secs < 86400:
        return f"{secs // 3600} h ago"
    return f"{secs // 86400} d ago"
