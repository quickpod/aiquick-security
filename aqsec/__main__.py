r"""Command-line interface: ``python -m aqsec <command> ...``.

Commands::

    aqsec scan [PATH ...]      Scan files/folders (default: OS scan roots)
                               [--no-clamav] [--json] [--rules FILE]
    aqsec status               Show which engines/definitions are installed
    aqsec roots                Print the OS-aware default scan roots
    aqsec update-defs          Update ClamAV definitions NOW (explicit only)
    aqsec schedule             Show the scheduled-scan configuration

Everything is offline except ``update-defs``, which runs ``freshclam`` once and
only when you ask.  Exits 0 on success, 1 on an :class:`AQSecError` (with a
clean ``error: ...`` line, never a traceback), and 2 when a scan finds
something (so it composes in scripts / CI).
"""

from __future__ import annotations

import argparse
import json
import sys

from . import (
    AQSecError,
    default_rules,
    default_scan_roots,
    definitions_info,
    engine_status,
    load_user_rules,
    scan_paths,
    update_definitions,
    __version__,
)
from . import guiconfig
from .defs import age_string


# --------------------------------------------------------------------------- #
# rendering helpers
# --------------------------------------------------------------------------- #
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _print_status(st, defs):
    print(f"ClamAV engine: {'installed' if st.clam_installed else 'NOT installed'}")
    if st.clamscan:
        print(f"  clamscan : {st.clamscan}")
    if st.clamdscan:
        print(f"  clamdscan: {st.clamdscan}")
    if st.freshclam:
        print(f"  freshclam: {st.freshclam}")
    if st.version:
        print(f"  version  : {st.version}")
    if defs.present:
        print(f"Definitions: {len(defs.files or [])} file(s) in {defs.db_dir} "
              f"(updated {age_string(defs.newest_mtime)})")
    else:
        print("Definitions: none found "
              "(built-in rules are always active)")
    print(f"Built-in rules: {len(default_rules())} active")
    if not st.clam_installed:
        print("\nClamAV is not installed, so scans use the built-in rules only. "
              "Install ClamAV (clamscan) to add the full engine; the app keeps "
              "working either way.")


def _print_scan(res):
    if res.stopped:
        print("Scan stopped early.")
    print(f"Scanned {res.files_scanned} file(s) in {res.duration:.1f}s "
          f"({'ClamAV + built-in' if res.clam_used else 'built-in rules'}).")
    if res.findings:
        print(f"\n{len(res.findings)} detection(s):")
        for f in sorted(res.findings, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
            print(f"  [{f.severity.upper():8}] {f.signature}  ({f.engine})")
            print(f"             {f.path}")
    else:
        print("No threats found.")
    if res.errors:
        print(f"\n{len(res.errors)} file(s) could not be read "
              f"(e.g. permissions); first few:")
        for e in res.errors[:5]:
            print(f"  - {e}")


# --------------------------------------------------------------------------- #
# command handlers
# --------------------------------------------------------------------------- #
def cmd_scan(a):
    paths = a.paths or default_scan_roots()
    if not paths:
        raise AQSecError("No paths to scan and no default scan roots exist.")
    rules = default_rules()
    if a.rules:
        rules = rules + load_user_rules(a.rules)

    last = {"n": 0}

    def progress(n, path):
        if not a.json and (n - last["n"] >= 200 or n == 1):
            last["n"] = n
            sys.stderr.write(f"\r  scanning… {n} files")
            sys.stderr.flush()

    res = scan_paths(paths, rules=rules, use_clamav=not a.no_clamav,
                     progress=progress)
    if not a.json and last["n"]:
        sys.stderr.write("\r" + " " * 40 + "\r")
    if a.json:
        print(json.dumps(res.as_dict(), indent=2))
    else:
        _print_scan(res)
    return 2 if res.findings else 0


def cmd_status(a):
    st = engine_status(probe_version=True)
    defs = definitions_info(status=st)
    if a.json:
        out = st.as_dict()
        out["definitions"] = defs.as_dict()
        out["builtin_rules"] = len(default_rules())
        print(json.dumps(out, indent=2))
    else:
        _print_status(st, defs)
    return 0


def cmd_roots(a):
    roots = default_scan_roots()
    if a.json:
        print(json.dumps(roots, indent=2))
    else:
        if not roots:
            print("(no default scan roots exist on this system)")
        for r in roots:
            print(r)
    return 0


def cmd_update_defs(a):
    def progress(msg):
        if not a.json:
            print(msg)

    res = update_definitions(progress=progress)
    if a.json:
        print(json.dumps(res.as_dict(), indent=2))
    else:
        print(res.message)
    return 0 if res.ok or not res.ran else 1


def cmd_schedule(a):
    sched = guiconfig.get_schedule()
    if a.json:
        print(json.dumps(sched.as_dict(), indent=2))
        return 0
    if not sched.enabled or sched.frequency == "manual":
        print("Scheduled scan: disabled (manual scans only).")
        return 0
    when = f"{sched.hour:02d}:{sched.minute:02d}"
    detail = {"hourly": f"every hour at :{sched.minute:02d}",
              "daily": f"daily at {when}",
              "weekly": f"weekly on {('Mon','Tue','Wed','Thu','Fri','Sat','Sun')[sched.weekday]} at {when}"}
    print(f"Scheduled scan: {detail.get(sched.frequency, sched.frequency)}")
    print(f"Roots: {', '.join(sched.roots) if sched.roots else 'OS default roots'}")
    print(f"Last run: {sched.last_run or 'never'}")
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser():
    p = argparse.ArgumentParser(
        prog="aqsec",
        description="AIQuick Security — offline, privacy-respecting malware "
                    "scanner (ClamAV-backed + built-in rules).")
    p.add_argument("--version", action="version",
                   version=f"AIQuick Security {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan files/folders (default: OS scan roots)")
    s.add_argument("paths", nargs="*", help="files or folders (default: scan roots)")
    s.add_argument("--no-clamav", action="store_true",
                   help="use only the built-in rules, even if ClamAV is present")
    s.add_argument("--rules", metavar="FILE",
                   help="also load extra rules from a local JSON file")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("status", help="Show installed engines and definitions")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("roots", help="Print the OS-aware default scan roots")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_roots)

    s = sub.add_parser("update-defs",
                       help="Update ClamAV definitions now (explicit only)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_update_defs)

    s = sub.add_parser("schedule", help="Show the scheduled-scan configuration")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_schedule)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args) or 0
    except AQSecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
