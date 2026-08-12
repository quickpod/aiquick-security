r"""JSON-backed settings for AIQuick Security (theme, schedule, preferences).

Stores only local preferences and never raises -- a corrupt or unreadable
config must never stop the app from starting.  Nothing here is uploaded; the
file lives under the user's profile.

On Windows the base dir is ``%LOCALAPPDATA%\AIQuickSecurity``; elsewhere it
falls back to ``~/.aiquick-security``.  Setting ``AQSEC_HOME`` overrides both
(used by the test-suite to keep everything inside a tmp tree).
"""

from __future__ import annotations

import json
import os
from typing import Optional

from .schedule import ScheduleConfig

APP_DIRNAME = "AIQuickSecurity"
CONFIG_NAME = "config.json"
VALID_THEMES = ("light", "dark")


def config_dir() -> str:
    override = os.environ.get("AQSEC_HOME")
    if override:
        return override
    local = os.environ.get("LOCALAPPDATA")
    if local and os.name == "nt":
        return os.path.join(local, APP_DIRNAME)
    return os.path.join(os.path.expanduser("~"), ".aiquick-security")


def config_path() -> str:
    return os.path.join(config_dir(), CONFIG_NAME)


def rules_path() -> str:
    """Location of the optional user rules file (loaded only on request)."""
    return os.path.join(config_dir(), "rules.json")


def _defaults() -> dict:
    return {"theme": "dark", "use_clamav": True, "schedule": {},
            "start_in_tray": True}


def load() -> dict:
    """Return the settings dict, always with valid keys."""
    cfg = _defaults()
    try:
        with open(config_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            if data.get("theme") in VALID_THEMES:
                cfg["theme"] = data["theme"]
            if isinstance(data.get("use_clamav"), bool):
                cfg["use_clamav"] = data["use_clamav"]
            if isinstance(data.get("start_in_tray"), bool):
                cfg["start_in_tray"] = data["start_in_tray"]
            if isinstance(data.get("schedule"), dict):
                cfg["schedule"] = data["schedule"]
    except Exception:
        pass  # missing/corrupt -> defaults; never fatal
    return cfg


def save(cfg: dict) -> None:
    """Persist *cfg* (best-effort; failures are swallowed)."""
    try:
        os.makedirs(config_dir(), exist_ok=True)
        clean = _defaults()
        if cfg.get("theme") in VALID_THEMES:
            clean["theme"] = cfg["theme"]
        if isinstance(cfg.get("use_clamav"), bool):
            clean["use_clamav"] = cfg["use_clamav"]
        if isinstance(cfg.get("start_in_tray"), bool):
            clean["start_in_tray"] = cfg["start_in_tray"]
        if isinstance(cfg.get("schedule"), dict):
            clean["schedule"] = cfg["schedule"]
        tmp = config_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(clean, fh, indent=2)
        os.replace(tmp, config_path())
    except Exception:
        pass


# ---- typed helpers ---------------------------------------------------------
def get_theme() -> str:
    return load().get("theme", "dark")


def set_theme(theme: str) -> None:
    if theme not in VALID_THEMES:
        return
    cfg = load()
    cfg["theme"] = theme
    save(cfg)


def get_use_clamav() -> bool:
    return bool(load().get("use_clamav", True))


def set_use_clamav(value: bool) -> None:
    cfg = load()
    cfg["use_clamav"] = bool(value)
    save(cfg)


def get_schedule() -> ScheduleConfig:
    return ScheduleConfig.from_dict(load().get("schedule") or {})


def set_schedule(sched: ScheduleConfig) -> None:
    cfg = load()
    cfg["schedule"] = sched.as_dict()
    save(cfg)


def record_scheduled_run(when_iso: str) -> None:
    """Persist the timestamp of a completed scheduled run."""
    cfg = load()
    sched = cfg.get("schedule") or {}
    sched["last_run"] = when_iso
    cfg["schedule"] = sched
    save(cfg)
