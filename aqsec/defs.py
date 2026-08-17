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
    low = text.lower()
    # freshclam exit codes: 0 = updated, 1 = already up to date (no error).
    if rc in (0, 1):
        already = rc == 1 or "up to date" in low or "up-to-date" in low
        msg = ("Definitions are already up to date." if already
               else "Virus definitions updated successfully.")
        return UpdateResult(ran=True, ok=True, message=msg, output=text[-4000:])
    # Where a freshclam *service* is installed -- systemd on most Linux
    # distros, launchd on macOS, the ClamAV service on Windows -- it holds an
    # exclusive lock on the log and database, so our one-shot run bails out
    # before reaching the network.  That is the healthy configuration rather
    # than a failure, but only if the service is genuinely keeping the
    # definitions current, so confirm that on disk before saying so.
    if _is_lock_contention(low) and _definitions_are_fresh(st):
        return UpdateResult(
            ran=False, ok=True,
            message="Definitions are kept up to date automatically by the "
                    "ClamAV updater service, so there is nothing to do here.",
            output=text[-4000:])
    return UpdateResult(ran=True, ok=False,
                        message=f"freshclam reported an error (exit {rc}).",
                        output=text[-4000:])


#: A service that is doing its job refreshes the databases well inside this
#: window (freshclam's default is hourly).  Anything older means the lock is
#: masking a real problem, so we report the error rather than reassure.
FRESH_WITHIN_SECONDS = 7 * 24 * 3600


def _definitions_are_fresh(status: Optional[EngineStatus] = None,
                           now: Optional[float] = None) -> bool:
    """True when on-disk definitions exist and were refreshed recently."""
    info = definitions_info(status)
    if not info.present or not info.newest_mtime:
        return False
    now = now if now is not None else time.time()
    return (now - info.newest_mtime) <= FRESH_WITHIN_SECONDS


def _is_lock_contention(lowered_output: str) -> bool:
    """True when freshclam bailed out because another instance holds the lock.

    These markers come from libfreshclam itself and are the same English text
    on Linux, macOS and Windows.  The trailing part of the real message is
    ``strerror()`` output, which the OS translates, so it is deliberately not
    matched on -- and because a lock can also fail for real reasons (bad
    permissions, read-only filesystem), callers pair this with a freshness
    check rather than trusting the text alone.
    """
    return any(marker in lowered_output for marker in (
        "failed to lock",
        "locked by another process",
        "problem with internal logger",
    ))


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
