# AIQuick Security

A fast, **offline**, **100% open-source** malware scanner for Windows. Nothing is uploaded anywhere. Built entirely by AI with human testing and guidance, and published on [QuickOpen](https://quickopen.ai/projects/aiquick-security).

> **100% AI-built and open source.** Apache-2.0.

## What it does

A privacy-respecting, offline malware scanner. It uses the open-source ClamAV engine when it is installed (clamscan/clamdscan) and always applies its own built-in signature rules, so it still catches known-bad files even with no engine present. Run an on-demand scan of a folder or your whole account, or set up a scheduled scan. Virus definitions and rules only ever update when you explicitly ask — nothing updates automatically and nothing is ever phoned home. No telemetry. Lives in the system tray so a scan is one click away.

## Install

Download **`AIQuickSecurity-Setup.exe`** from the [QuickOpen page](https://quickopen.ai/projects/aiquick-security) or the [GitHub release](https://github.com/quickpod/aiquick-security/releases/latest) and double-click it. It installs per-user, adds Desktop and Start Menu shortcuts, and can optionally trust the QuickOpen Root CA. Authenticode-signed by the QuickOpen Code Signing CA — verify at [quickopen.ai/trust](https://quickopen.ai/trust).

## Two engines, one scanner

- **Built-in rules** — always active, fully offline, no dependencies. Ships the
  industry-standard EICAR test signature, a file-hash denylist, and a handful of
  high-signal heuristics (PHP web-shells, ransomware shadow-copy deletion,
  hidden/encoded PowerShell, …).
- **ClamAV** *(optional)* — when `clamscan`/`clamdscan` is installed it runs too,
  adding the full open-source engine. If ClamAV is **not** installed the app says
  so plainly and keeps working on the built-in rules — it never tries to install
  anything itself.

Scans are **OS-aware**: on Linux the default roots are `$HOME`, `/tmp` and
`/opt`; on Windows the fixed drive letters plus `%TEMP%`; on macOS `$HOME`,
`/tmp` and `~/Downloads`.

## Privacy

Privacy is a product rule, not a setting:

- Virus definitions and rules update **only when you ask** (the *Update
  definitions* button, or `aqsec update-defs`). There is **no** background
  updater and **no** auto-update.
- **Nothing is phoned home. No telemetry.** The only code path that touches the
  network is the on-demand ClamAV `freshclam` update you trigger yourself.
- Settings live locally under `%LOCALAPPDATA%\AIQuickSecurity` (Windows) or
  `~/.aiquick-security` (elsewhere).

## Run from source

```sh
pip install -r requirements.txt
python aiquick_security_app.py          # GUI (starts in the tray)
python -m aqsec --help                  # CLI
```

### CLI

```sh
aqsec scan [PATH ...]      # scan a folder (default: OS scan roots)
                           #   --no-clamav   built-in rules only
                           #   --rules FILE  also load extra local rules (JSON)
                           #   --json        machine-readable output
aqsec status               # which engines / definitions are installed
aqsec roots                # the OS-aware default scan roots
aqsec update-defs          # update ClamAV definitions NOW (explicit only)
aqsec schedule             # show the scheduled-scan configuration
```

`aqsec scan` exits `0` when clean, `2` when it finds something (so it composes
in scripts and CI), and `1` on error.

## License

Apache-2.0 — see [LICENSE](LICENSE). A 100% AI-built project published on QuickOpen.
