r"""Scheduled-scan logic — pure, testable, and entirely local.

A schedule is just a small config object; there is **no** OS-level cron/Task
Scheduler entry and nothing runs in the background when the app is closed.
While AIQuick Security is running (in the tray), the app checks
:func:`is_due` on a timer and, when a scan comes due, runs it and records
``last_run``.  This keeps the behaviour transparent and privacy-respecting: no
hidden persistence, no auto-update, no network.

The date maths lives here as pure functions so it can be unit-tested with fixed
``datetime`` values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional

from .errors import AQSecError

FREQUENCIES = ("manual", "hourly", "daily", "weekly")
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


@dataclass
class ScheduleConfig:
    """A scheduled-scan definition.

    Attributes:
      enabled:   run on the schedule at all.
      frequency: one of :data:`FREQUENCIES`.
      hour/minute: local time-of-day for daily/weekly runs (0-23 / 0-59).
      weekday:   0=Mon .. 6=Sun, for weekly runs.
      roots:     paths to scan, or None to use the OS default scan roots.
      last_run:  ISO-8601 timestamp of the last completed scheduled run.
    """

    enabled: bool = False
    frequency: str = "daily"
    hour: int = 3
    minute: int = 0
    weekday: int = 0
    roots: Optional[List[str]] = None
    last_run: Optional[str] = None

    def validate(self) -> "ScheduleConfig":
        if self.frequency not in FREQUENCIES:
            raise AQSecError(f"Unknown frequency {self.frequency!r}. "
                             f"Choose one of {', '.join(FREQUENCIES)}.")
        if not (0 <= self.hour <= 23):
            raise AQSecError("Hour must be between 0 and 23.")
        if not (0 <= self.minute <= 59):
            raise AQSecError("Minute must be between 0 and 59.")
        if not (0 <= self.weekday <= 6):
            raise AQSecError("Weekday must be 0 (Mon) .. 6 (Sun).")
        return self

    def as_dict(self):
        return {"enabled": self.enabled, "frequency": self.frequency,
                "hour": self.hour, "minute": self.minute,
                "weekday": self.weekday, "roots": self.roots,
                "last_run": self.last_run}

    @classmethod
    def from_dict(cls, d):
        d = d or {}
        return cls(
            enabled=bool(d.get("enabled", False)),
            frequency=d.get("frequency", "daily"),
            hour=int(d.get("hour", 3)),
            minute=int(d.get("minute", 0)),
            weekday=int(d.get("weekday", 0)),
            roots=list(d["roots"]) if d.get("roots") else None,
            last_run=d.get("last_run"),
        )


def _parse_iso(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def next_run_after(cfg: ScheduleConfig, after: datetime) -> Optional[datetime]:
    """Return the next scheduled run strictly after *after* (naive local time).

    ``manual`` schedules have no next run (returns None).  Pure function.
    """
    cfg.validate()
    if not cfg.enabled or cfg.frequency == "manual":
        return None
    if cfg.frequency == "hourly":
        nxt = after.replace(minute=cfg.minute, second=0, microsecond=0)
        if nxt <= after:
            nxt += timedelta(hours=1)
        return nxt
    if cfg.frequency == "daily":
        nxt = after.replace(hour=cfg.hour, minute=cfg.minute, second=0,
                            microsecond=0)
        if nxt <= after:
            nxt += timedelta(days=1)
        return nxt
    if cfg.frequency == "weekly":
        nxt = after.replace(hour=cfg.hour, minute=cfg.minute, second=0,
                            microsecond=0)
        days_ahead = (cfg.weekday - nxt.weekday()) % 7
        nxt += timedelta(days=days_ahead)
        if nxt <= after:
            nxt += timedelta(days=7)
        return nxt
    return None


def is_due(cfg: ScheduleConfig, now: datetime) -> bool:
    """True if a scheduled scan should run at *now* given ``cfg.last_run``.

    A scan is due when the most recent scheduled fire-time at or before *now*
    is later than the last recorded run (so a missed run while the app was
    closed fires once on next launch, not repeatedly).  Pure function.
    """
    cfg.validate()
    if not cfg.enabled or cfg.frequency == "manual":
        return False
    last = _parse_iso(cfg.last_run)
    # The previous fire-time is the next-run computed from a moment far enough
    # back; simplest correct form: find the next run after (now - period) and
    # see if it is <= now.
    period = {"hourly": timedelta(hours=1), "daily": timedelta(days=1),
              "weekly": timedelta(days=7)}[cfg.frequency]
    prev_fire = next_run_after(cfg, now - period)
    if prev_fire is None or prev_fire > now:
        return False
    if last is None:
        return True
    return prev_fire > last
