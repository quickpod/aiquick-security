r"""The scanner engine: ClamAV detection, OS-aware scan roots, and the scan loop.

Two engines cooperate:

* **Built-in rules** (:mod:`aqsec.rules`) always run -- pure, offline, no deps.
* **ClamAV**, *if installed*, runs too: we shell out to ``clamscan`` (or the
  faster ``clamdscan`` when a daemon is up).  If neither is present the engine
  simply reports ``clam_installed = False`` and the app degrades gracefully to
  the built-in rules with a clear "engine not installed" state -- it never
  crashes and never tries to install anything.

Scan roots are **OS-aware** (requirement A8): on Linux we scan ``$HOME``,
``/tmp`` and ``/opt``; on Windows the fixed drive letters plus ``%TEMP%``; on
macOS ``$HOME`` and ``/tmp`` -- always detected at runtime, never hardcoded to
one platform.

The single :func:`_execute` function is the only place we shell out; tests
monkeypatch it so the whole engine is exercised with no ClamAV, no root and no
network.  Everything raises :class:`AQSecError` (and only that) on failure.
"""

from __future__ import annotations

import os
import shutil
import string
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple

from .errors import AQSecError
from . import rules as _rules
from .rules import Match, Rule

# Skip files larger than this in the built-in pass (still counted, not read).
DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
# Directory names we never descend into (noise / pseudo filesystems).
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".cache",
              "proc", "sys", "dev", "run", ".Trash", "$RECYCLE.BIN",
              "System Volume Information"}


# --------------------------------------------------------------------------- #
# Engine availability
# --------------------------------------------------------------------------- #
@dataclass
class EngineStatus:
    """A snapshot of which scanning engines are available."""

    clamscan: Optional[str] = None       # path to clamscan, or None
    clamdscan: Optional[str] = None      # path to clamdscan, or None
    freshclam: Optional[str] = None      # path to freshclam, or None
    version: Optional[str] = None        # clamav version string, if probed
    db_dir: Optional[str] = None         # virus-definitions directory, if found
    db_present: bool = False             # any .cvd/.cld present in db_dir?

    @property
    def clam_installed(self) -> bool:
        return bool(self.clamscan or self.clamdscan)

    def as_dict(self):
        return {"clam_installed": self.clam_installed, "clamscan": self.clamscan,
                "clamdscan": self.clamdscan, "freshclam": self.freshclam,
                "version": self.version, "db_dir": self.db_dir,
                "db_present": self.db_present}


def _which(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    # Common install locations that may not be on PATH for a windowed app.
    cands = []
    if os.name == "nt":
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        cands = [os.path.join(pf, "ClamAV", name + ".exe")]
    else:
        cands = [f"/usr/bin/{name}", f"/usr/local/bin/{name}", f"/opt/clamav/bin/{name}"]
    for c in cands:
        if os.path.exists(c):
            return c
    return None


def _find_db_dir() -> Tuple[Optional[str], bool]:
    """Locate the ClamAV virus-definitions directory and whether it has data."""
    cands = []
    if os.name == "nt":
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        cands = [os.path.join(pf, "ClamAV", "database")]
    else:
        cands = ["/var/lib/clamav", "/usr/local/share/clamav", "/opt/clamav/share/clamav"]
    for d in cands:
        try:
            if os.path.isdir(d):
                has = any(f.endswith((".cvd", ".cld")) for f in os.listdir(d))
                return d, has
        except OSError:
            continue
    return None, False


def engine_status(probe_version: bool = False) -> EngineStatus:
    """Detect the available engines.

    Filesystem-only by default (fast, safe on every platform).  With
    *probe_version* it additionally runs ``clamscan --version`` through
    :func:`_execute` to fill in the version string.
    """
    st = EngineStatus(clamscan=_which("clamscan"), clamdscan=_which("clamdscan"),
                      freshclam=_which("freshclam"))
    st.db_dir, st.db_present = _find_db_dir()
    if probe_version and st.clamscan:
        try:
            rc, out, err = _execute([st.clamscan, "--version"], timeout=20)
            line = (out or err or "").strip().splitlines()
            st.version = line[0].strip() if line else None
        except AQSecError:
            st.version = None
    return st


def clamav_available() -> bool:
    """True if a ClamAV command-line scanner is installed."""
    return engine_status().clam_installed


# --------------------------------------------------------------------------- #
# OS-aware scan roots (requirement A8)
# --------------------------------------------------------------------------- #
def default_scan_roots() -> List[str]:
    """Return sensible default scan roots for *this* operating system.

    Only existing directories are returned, deduplicated, order preserved.
    """
    home = os.path.expanduser("~")
    if os.name == "nt":
        cands = _windows_drives()
        for env in ("TEMP", "TMP"):
            v = os.environ.get(env)
            if v:
                cands.append(v)
        cands.append(home)
    elif sys.platform == "darwin":
        cands = [home, "/tmp", os.path.join(home, "Downloads")]
    else:  # linux / other posix
        cands = [home, "/tmp", "/opt"]
    seen, out = set(), []
    for c in cands:
        if not c:
            continue
        norm = os.path.normpath(c)
        if norm in seen:
            continue
        seen.add(norm)
        if os.path.isdir(norm):
            out.append(norm)
    return out


def _windows_drives() -> List[str]:
    """Fixed drive roots present on a Windows box, e.g. ``["C:\\", "D:\\"]``."""
    drives = []
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        if os.path.exists(root):
            drives.append(root)
    return drives


# --------------------------------------------------------------------------- #
# File walking
# --------------------------------------------------------------------------- #
def iter_files(paths: Sequence[str], skip_hidden: bool = True,
               follow_symlinks: bool = False):
    """Yield regular files under *paths* (files themselves are yielded as-is).

    Skips :data:`_SKIP_DIRS`, and hidden dot-entries when *skip_hidden*.  Never
    follows symlinked directories unless *follow_symlinks*.  I/O errors on a
    single entry are swallowed so one bad directory can't abort the walk.
    """
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        if not os.path.isdir(p):
            continue
        for root, dirs, files in os.walk(p, followlinks=follow_symlinks):
            dirs[:] = [d for d in dirs
                       if d not in _SKIP_DIRS
                       and not (skip_hidden and d.startswith("."))]
            for name in files:
                if skip_hidden and name.startswith("."):
                    # dotfiles can still be malicious, but skip .-prefixed by
                    # default to keep a full-home scan tractable; EICAR/tests
                    # use normal names.
                    pass
                fp = os.path.join(root, name)
                try:
                    if os.path.islink(fp) and not follow_symlinks:
                        continue
                    if not os.path.isfile(fp):
                        continue
                except OSError:
                    continue
                yield fp


# --------------------------------------------------------------------------- #
# Findings + results
# --------------------------------------------------------------------------- #
@dataclass
class ScanFinding:
    """One infected/suspicious file reported by a scan."""

    path: str
    signature: str
    engine: str          # "builtin" | "clamav"
    severity: str = "medium"
    description: str = ""

    def as_dict(self):
        return {"path": self.path, "signature": self.signature,
                "engine": self.engine, "severity": self.severity,
                "description": self.description}


@dataclass
class ScanResult:
    """The outcome of a scan run."""

    roots: List[str] = field(default_factory=list)
    files_scanned: int = 0
    findings: List[ScanFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    clam_used: bool = False
    started: float = 0.0
    finished: float = 0.0
    stopped: bool = False

    @property
    def duration(self) -> float:
        return max(0.0, (self.finished or time.time()) - (self.started or 0.0))

    @property
    def clean(self) -> bool:
        return not self.findings

    def as_dict(self):
        return {"roots": self.roots, "files_scanned": self.files_scanned,
                "findings": [f.as_dict() for f in self.findings],
                "errors": self.errors, "clam_used": self.clam_used,
                "duration": round(self.duration, 3), "stopped": self.stopped,
                "clean": self.clean}


# --------------------------------------------------------------------------- #
# Subprocess boundary (the single seam tests monkeypatch)
# --------------------------------------------------------------------------- #
def _execute(argv: List[str], timeout: int = 3600) -> Tuple[int, str, str]:
    """Run *argv* and return ``(returncode, stdout, stderr)``.

    The one and only place the engine shells out.  Tests replace this to feed
    canned ClamAV output without a real binary.
    """
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise AQSecError(f"Command not found: {argv[0]} ({exc}).")
    except subprocess.TimeoutExpired:
        raise AQSecError("Timed out waiting for the scanner to respond.")
    except Exception as exc:  # pragma: no cover - defensive
        raise AQSecError(f"Could not run scanner: {exc}.")
    return proc.returncode, proc.stdout or "", proc.stderr or ""


# --------------------------------------------------------------------------- #
# ClamAV integration
# --------------------------------------------------------------------------- #
def parse_clamscan_output(text: str) -> List[Tuple[str, str]]:
    """Parse ``clamscan``/``clamdscan`` output into ``[(path, signature), ...]``.

    Each infected line looks like ``/path/to/file: Signature.Name FOUND``.
    Summary and ``OK`` lines are ignored.  Pure -- no I/O.
    """
    out: List[Tuple[str, str]] = []
    if not text:
        return out
    for line in text.splitlines():
        line = line.rstrip()
        if not line.endswith("FOUND"):
            continue
        # rsplit so paths containing ':' still parse (drive letters, URLs).
        head, _, _found = line.rpartition(" FOUND")
        path, sep, sig = head.rpartition(": ")
        if not sep:
            continue
        out.append((path.strip(), sig.strip()))
    return out


def clam_scan(paths: Sequence[str], status: Optional[EngineStatus] = None
              ) -> List[ScanFinding]:
    """Run ClamAV over *paths* and return its findings (or [] if not installed).

    Prefers ``clamdscan`` (uses a running daemon, far faster) and falls back to
    ``clamscan``.  A non-zero exit is normal for ClamAV when it finds something
    (exit 1) -- only a genuine error (exit >= 2) raises.
    """
    st = status or engine_status()
    binary = st.clamdscan or st.clamscan
    if not binary:
        return []
    if st.clamdscan:
        argv = [binary, "--no-summary", "--infected", "--fdpass", *paths]
    else:
        argv = [binary, "--no-summary", "--infected", "--recursive", *paths]
    rc, out, err = _execute(argv)
    if rc >= 2:
        detail = (err or out).strip() or f"exit {rc}"
        raise AQSecError(f"ClamAV failed: {detail}")
    findings = []
    for path, sig in parse_clamscan_output(out):
        findings.append(ScanFinding(path=path, signature=sig, engine="clamav",
                                    severity="critical",
                                    description="Detected by the ClamAV engine."))
    return findings


# --------------------------------------------------------------------------- #
# The scan
# --------------------------------------------------------------------------- #
def scan_paths(paths: Sequence[str],
               rules: Optional[Sequence[Rule]] = None,
               use_clamav: bool = True,
               max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
               progress: Optional[Callable[[int, str], None]] = None,
               should_stop: Optional[Callable[[], bool]] = None,
               status: Optional[EngineStatus] = None) -> ScanResult:
    """Scan *paths* with the built-in rules and (if available) ClamAV.

    Args:
      paths:          files/directories to scan.  Empty -> raises.
      rules:          rule set (defaults to :func:`aqsec.rules.default_rules`).
      use_clamav:     also run ClamAV when installed.
      max_file_bytes: built-in pass skips reading files larger than this.
      progress:       optional ``callback(files_scanned, current_path)``.
      should_stop:    optional ``() -> bool`` checked between files to cancel.
      status:         a pre-computed :class:`EngineStatus` (else detected).

    Returns a :class:`ScanResult`.  Per-file read errors are collected in
    ``result.errors`` and do not abort the scan.
    """
    if not paths:
        raise AQSecError("No paths to scan. Pass a file or folder, or use the "
                         "default scan roots.")
    ruleset = list(rules) if rules is not None else _rules.default_rules()
    st = status or engine_status()
    result = ScanResult(roots=[os.path.normpath(p) for p in paths],
                        started=time.time())

    need_hash = any(r.kind == "sha256" for r in ruleset)
    seen = set()
    for fp in iter_files(paths):
        if should_stop and should_stop():
            result.stopped = True
            break
        if fp in seen:
            continue
        seen.add(fp)
        result.files_scanned += 1
        if progress:
            try:
                progress(result.files_scanned, fp)
            except Exception:
                pass
        try:
            size = os.path.getsize(fp)
        except OSError:
            size = 0
        if size > max_file_bytes and not need_hash:
            continue
        try:
            matches = _rules.scan_file(fp, ruleset, need_hash=need_hash)
        except AQSecError as exc:
            result.errors.append(str(exc))
            continue
        for m in matches:
            result.findings.append(ScanFinding(
                path=fp, signature=m.name, engine="builtin",
                severity=m.severity, description=m.description))

    # ClamAV pass (best-effort; a ClamAV error is recorded, not fatal).
    if use_clamav and st.clam_installed and not result.stopped:
        result.clam_used = True
        try:
            for f in clam_scan(paths, status=st):
                result.findings.append(f)
        except AQSecError as exc:
            result.errors.append(str(exc))

    result.finished = time.time()
    return result
