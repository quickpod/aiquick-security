r"""Built-in signature rules — AIQuick Security's own lightweight engine.

This is the part of the scanner that works with **no external engine at all**.
It ships a small, conservative set of well-known malware markers plus a
file-hash denylist, so a scan still catches obviously-bad files (starting with
the industry-standard EICAR test file) even when ClamAV is not installed.

Everything here is pure and offline: :func:`default_rules` returns the built-in
rule set, :func:`scan_data` matches a ``bytes`` buffer against a rule set, and
:func:`scan_file` reads a file (a bounded prefix for content rules, plus a
streaming SHA-256 for the hash denylist) and returns the matches.  No network,
no subprocess -- so it is trivial to unit-test and can never phone home.

Rule *kinds*:

* ``substr``  -- case-insensitive byte substring (text markers)
* ``regex``   -- regular expression matched against the latin-1 view of bytes
* ``sha256``  -- lowercase hex digest of the whole file

Users can extend the set from a local ``rules.json`` file (see
:func:`load_user_rules`); that file is read only when the user asks -- it is
never fetched from anywhere.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Sequence

from .errors import AQSecError

# Severity ordering (low -> critical) used for sorting / display.
SEVERITIES = ("low", "medium", "high", "critical")

# The EICAR standard anti-malware test string.  It is a harmless 68-byte file
# that every scanner is expected to detect.  We build it from fragments at
# runtime so this source file does not itself contain the literal signature
# (otherwise the scanner would flag its own program files).
_EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    + "$EICAR-STANDARD-"
    + "ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@dataclass(frozen=True)
class Rule:
    """One detection rule (see the module docstring for ``kind`` values)."""

    id: str
    name: str
    kind: str            # "substr" | "regex" | "sha256"
    pattern: str         # marker text / regex source / hex digest
    severity: str = "medium"
    description: str = ""


@dataclass(frozen=True)
class Match:
    """A single rule hit against some data or file."""

    rule_id: str
    name: str
    severity: str
    description: str

    def as_dict(self):
        return {"rule_id": self.rule_id, "name": self.name,
                "severity": self.severity, "description": self.description}


# --------------------------------------------------------------------------- #
# Built-in rule set
# --------------------------------------------------------------------------- #
# Deliberately small and conservative: high-signal, low-false-positive markers
# that are widely published as malicious.  This is a *complement* to ClamAV,
# never a replacement for it.
_BUILTIN: Sequence[Rule] = (
    Rule("eicar", "EICAR-Test-File", "substr", _EICAR, "critical",
         "The standard EICAR anti-malware test file. Harmless, but its "
         "presence means a scanner test (or a real one) planted it."),
    Rule("eicar-hash", "EICAR-Test-File (hash)", "sha256", EICAR_SHA256,
         "critical", "Exact SHA-256 of the EICAR test file."),
    Rule("php-webshell-eval", "Heuristic.PHP.EvalBase64", "regex",
         r"eval\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(", "high",
         "PHP that evaluates decoded/obfuscated input -- the classic web-shell "
         "pattern."),
    Rule("php-shell-exec", "Heuristic.PHP.RequestExec", "regex",
         r"(system|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST)",
         "high",
         "PHP passing a raw HTTP parameter straight to a shell -- remote "
         "command execution."),
    Rule("ps-hidden-enc", "Heuristic.PowerShell.HiddenEncoded", "regex",
         r"powershell(\.exe)?[^\n]{0,80}?-(?:e|en|enc|encodedcommand)\b",
         "medium",
         "A hidden/encoded PowerShell command line -- a common download-and-run "
         "cradle."),
    Rule("ransom-shadow-delete", "Heuristic.Ransom.ShadowDelete", "regex",
         r"vssadmin(\.exe)?\s+delete\s+shadows", "high",
         "Deletes Volume Shadow Copies to block recovery -- textbook "
         "ransomware behaviour."),
    Rule("bcdedit-recovery-off", "Heuristic.Ransom.DisableRecovery", "regex",
         r"bcdedit[^\n]{0,60}recoveryenabled\s+no", "high",
         "Disables Windows automatic recovery -- often paired with "
         "ransomware."),
)


def default_rules() -> List[Rule]:
    """Return a fresh list of the built-in rules."""
    return list(_BUILTIN)


def eicar_bytes() -> bytes:
    """The exact EICAR test-file bytes (handy for tests and self-checks)."""
    return _EICAR.encode("ascii")


# --------------------------------------------------------------------------- #
# User-supplied rules (explicit, local file only)
# --------------------------------------------------------------------------- #
def load_user_rules(path: str) -> List[Rule]:
    """Load extra rules from a local JSON file (a list of rule objects).

    Each entry needs ``id``, ``name``, ``kind`` and ``pattern``; ``severity``
    and ``description`` are optional.  Missing file -> empty list (not an
    error).  A malformed file raises :class:`AQSecError`.  Nothing is fetched
    from the network -- this reads the local path and only when a caller asks.
    """
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as exc:
        raise AQSecError(f"Could not read rules file {path!r}: {exc}")
    if not isinstance(raw, list):
        raise AQSecError("Rules file must contain a JSON list of rules.")
    out: List[Rule] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise AQSecError(f"Rule #{i} is not an object.")
        try:
            kind = item["kind"]
            if kind not in ("substr", "regex", "sha256"):
                raise AQSecError(f"Rule #{i}: unknown kind {kind!r}.")
            sev = item.get("severity", "medium")
            if sev not in SEVERITIES:
                sev = "medium"
            rule = Rule(str(item["id"]), str(item["name"]), kind,
                        str(item["pattern"]), sev, str(item.get("description", "")))
        except KeyError as exc:
            raise AQSecError(f"Rule #{i} is missing field {exc}.")
        if kind == "regex":
            _compile(rule)          # validate up front
        out.append(rule)
    return out


# --------------------------------------------------------------------------- #
# Matching (pure)
# --------------------------------------------------------------------------- #
_regex_cache: dict = {}


def _compile(rule: Rule):
    key = rule.pattern
    rx = _regex_cache.get(key)
    if rx is None:
        try:
            rx = re.compile(rule.pattern.encode("latin-1"), re.IGNORECASE)
        except re.error as exc:
            raise AQSecError(f"Bad regex in rule {rule.id!r}: {exc}")
        _regex_cache[key] = rx
    return rx


def scan_data(data: bytes, rules: Sequence[Rule],
              sha256: Optional[str] = None) -> List[Match]:
    """Match *data* against *rules* and return the hits.

    ``substr`` and ``regex`` rules run against *data* directly.  ``sha256``
    rules compare against *sha256* if given, else the digest of *data*.  Pure:
    no I/O, so tests just hand it bytes.
    """
    if data is None:
        data = b""
    matches: List[Match] = []
    digest = None
    for rule in rules:
        hit = False
        if rule.kind == "substr":
            hit = rule.pattern.encode("latin-1", "ignore").lower() in data.lower()
        elif rule.kind == "regex":
            hit = _compile(rule).search(data) is not None
        elif rule.kind == "sha256":
            if digest is None:
                digest = (sha256 or hashlib.sha256(data).hexdigest()).lower()
            hit = digest == rule.pattern.lower()
        if hit:
            matches.append(Match(rule.id, rule.name, rule.severity,
                                 rule.description))
    return matches


# Files bigger than this are hashed in full but only their first
# ``content_bytes`` are scanned for text/regex markers (which live near the top
# of scripts/macros); keeps a scan bounded on huge media files.
DEFAULT_CONTENT_BYTES = 4 * 1024 * 1024


def sha256_file(path: str, chunk: int = 1024 * 1024) -> str:
    """Streaming SHA-256 of *path* (raises :class:`AQSecError` on I/O error)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(chunk), b""):
                h.update(block)
    except OSError as exc:
        raise AQSecError(f"Could not read {path!r}: {exc}")
    return h.hexdigest()


def scan_file(path: str, rules: Sequence[Rule],
              content_bytes: int = DEFAULT_CONTENT_BYTES,
              need_hash: Optional[bool] = None) -> List[Match]:
    """Scan a single file with the built-in engine and return matches.

    Reads at most *content_bytes* for the text/regex rules and, when any
    ``sha256`` rule is present (or *need_hash* is forced True), a full streaming
    digest for the hash denylist.  Unreadable files raise :class:`AQSecError`
    so the caller can record them as errors and carry on.
    """
    if need_hash is None:
        need_hash = any(r.kind == "sha256" for r in rules)
    try:
        with open(path, "rb") as fh:
            head = fh.read(content_bytes)
    except OSError as exc:
        raise AQSecError(f"Could not read {path!r}: {exc}")
    digest = sha256_file(path) if need_hash else None
    return scan_data(head, rules, sha256=digest)
