r"""aqsec -- AIQuick Security: a privacy-respecting, offline malware scanner.

Two cooperating engines:

* **Built-in rules** (:mod:`aqsec.rules`) -- pure, offline, always active; ships
  the EICAR test signature, a hash denylist and a handful of high-signal
  heuristics.
* **ClamAV** (:mod:`aqsec.engine`) -- used when ``clamscan``/``clamdscan`` is
  installed; the app degrades gracefully to the built-in rules with a clear
  "engine not installed" state when it is not.

Public API::

    from aqsec import scan_paths, engine_status, default_scan_roots
    st = engine_status()                 # what's installed
    res = scan_paths(default_scan_roots())   # OS-aware on-demand scan
    for f in res.findings:
        print(f.path, f.signature, f.engine)

Definitions update only on the explicit :func:`update_definitions` call (the
CLI ``update-defs`` / the GUI button) -- never automatically, never phoning
home.  Every function raises :class:`AQSecError` (and only that) on failure.
100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

from .errors import AQSecError
from .rules import (
    Match,
    Rule,
    default_rules,
    eicar_bytes,
    load_user_rules,
    scan_data,
    scan_file,
    sha256_file,
)
from .engine import (
    EngineStatus,
    ScanFinding,
    ScanResult,
    clam_scan,
    clamav_available,
    default_scan_roots,
    engine_status,
    iter_files,
    parse_clamscan_output,
    scan_paths,
)
from .defs import (
    DefsInfo,
    UpdateResult,
    age_string,
    definitions_info,
    update_definitions,
)
from .schedule import ScheduleConfig, is_due, next_run_after

__version__ = "1.0.6"

__all__ = [
    "AQSecError",
    "Rule",
    "Match",
    "default_rules",
    "eicar_bytes",
    "load_user_rules",
    "scan_data",
    "scan_file",
    "sha256_file",
    "EngineStatus",
    "ScanFinding",
    "ScanResult",
    "engine_status",
    "clamav_available",
    "clam_scan",
    "default_scan_roots",
    "iter_files",
    "parse_clamscan_output",
    "scan_paths",
    "DefsInfo",
    "UpdateResult",
    "definitions_info",
    "update_definitions",
    "age_string",
    "ScheduleConfig",
    "next_run_after",
    "is_due",
    "__version__",
]
