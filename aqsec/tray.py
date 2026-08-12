r"""System-tray presence for AIQuick Security — the icon on the right of the
taskbar's notification area.

On Windows this is a dependency-free ctypes implementation: a hidden message
window plus a ``Shell_NotifyIcon`` entry, run on its own background thread with
its own Win32 message loop (the Tk GUI owns the main thread).  Right-click menu:
Open · Quick scan · Update definitions · Exit; double-click opens the window.
It re-adds itself if Explorer restarts.

Elsewhere it falls back to ``pystray`` **iff** it happens to be installed, and
otherwise to a harmless no-op stub -- so importing this module never fails and
the GUI still runs on a headless box.  Menu actions are plain callables; the
GUI passes callbacks that marshal back onto the Tk thread with ``after``.

Nothing here is created at import time; only :func:`start_tray` touches the
platform APIs.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class TrayCallbacks:
    """Callbacks wired to the tray menu (all optional, all safe to omit)."""

    on_open: Optional[Callable[[], None]] = None
    on_scan: Optional[Callable[[], None]] = None
    on_update: Optional[Callable[[], None]] = None
    on_exit: Optional[Callable[[], None]] = None


class _TrayHandle:
    """A running tray; ``stop()`` removes the icon and ends its message loop."""

    def __init__(self, impl):
        self._impl = impl

    def stop(self):
        try:
            self._impl.stop()
        except Exception:
            pass

    def notify(self, title, message):
        """Best-effort balloon/notification (no-op if unsupported)."""
        try:
            self._impl.notify(title, message)
        except Exception:
            pass


def start_tray(app_name: str, callbacks: TrayCallbacks,
               icon_path: Optional[str] = None,
               tooltip: Optional[str] = None) -> Optional[_TrayHandle]:
    """Start the tray icon on a background thread; return a handle or None.

    Returns None when no tray backend is available (e.g. headless Linux with no
    pystray) -- the caller treats that as "no tray" and simply keeps the window
    open.  Never raises.
    """
    import os
    tooltip = tooltip or app_name
    try:
        if os.name == "nt":
            impl = _WinTray(app_name, callbacks, icon_path, tooltip)
        else:
            impl = _PystrayTray(app_name, callbacks, icon_path, tooltip)
        impl.start()
        return _TrayHandle(impl)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Windows (ctypes, no dependencies)
# --------------------------------------------------------------------------- #
class _WinTray:  # pragma: no cover - exercised only on Windows
    """Pure-ctypes tray icon running its own message loop on a daemon thread."""

    def __init__(self, app_name, callbacks, icon_path, tooltip):
        import ctypes
        from ctypes import (POINTER, Structure, WINFUNCTYPE, c_int, c_long,
                            c_size_t, c_ssize_t, c_uint, c_ushort, c_void_p,
                            c_wchar, c_wchar_p)
        self.ctypes = ctypes
        self.app_name = app_name
        self.cb = callbacks
        self.icon_path = icon_path
        self.tooltip = tooltip
        self.hwnd = None
        self.nid = None
        self._thread = None
        self._wm_taskbar = 0

        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.shell32 = ctypes.WinDLL("shell32", use_last_error=True)

        self.WM_APP = 0x8000
        self.WM_TRAY = self.WM_APP + 1
        self.WM_DESTROY = 0x0002
        self.WM_CLOSE = 0x0010
        self.WM_LBUTTONDBLCLK = 0x0203
        self.WM_RBUTTONUP = 0x0205
        self.WM_CONTEXTMENU = 0x007B
        self.NIM_ADD, self.NIM_MODIFY, self.NIM_DELETE = 0, 1, 2
        self.NIF_MESSAGE, self.NIF_ICON, self.NIF_TIP, self.NIF_INFO = 0x01, 0x02, 0x04, 0x10
        self.MF_STRING, self.MF_SEPARATOR = 0x0000, 0x0800
        self.TPM_RIGHTBUTTON, self.TPM_RETURNCMD, self.TPM_NONOTIFY = 0x0002, 0x0100, 0x0080
        self.IDI_SHIELD = 32518
        self.ID_OPEN, self.ID_SCAN, self.ID_UPDATE, self.ID_EXIT = 1, 2, 3, 4

        self.WNDPROC = WINFUNCTYPE(c_ssize_t, c_void_p, c_uint, c_size_t, c_ssize_t)

        class GUID(Structure):
            _fields_ = [("b", ctypes.c_ubyte * 16)]

        class POINT(Structure):
            _fields_ = [("x", c_long), ("y", c_long)]

        class MSG(Structure):
            _fields_ = [("hwnd", c_void_p), ("message", c_uint),
                        ("wParam", c_size_t), ("lParam", c_ssize_t),
                        ("time", c_uint), ("pt", POINT)]

        class WNDCLASS(Structure):
            _fields_ = [("style", c_uint), ("lpfnWndProc", self.WNDPROC),
                        ("cbClsExtra", c_int), ("cbWndExtra", c_int),
                        ("hInstance", c_void_p), ("hIcon", c_void_p),
                        ("hCursor", c_void_p), ("hbrBackground", c_void_p),
                        ("lpszMenuName", c_wchar_p), ("lpszClassName", c_wchar_p)]

        class NOTIFYICONDATAW(Structure):
            _fields_ = [
                ("cbSize", c_uint), ("hWnd", c_void_p), ("uID", c_uint),
                ("uFlags", c_uint), ("uCallbackMessage", c_uint),
                ("hIcon", c_void_p), ("szTip", c_wchar * 128),
                ("dwState", c_uint), ("dwStateMask", c_uint),
                ("szInfo", c_wchar * 256), ("uVersion", c_uint),
                ("szInfoTitle", c_wchar * 64), ("dwInfoFlags", c_uint),
                ("guidItem", GUID), ("hBalloonIcon", c_void_p)]

        self.POINT, self.MSG, self.WNDCLASS = POINT, MSG, WNDCLASS
        self.NOTIFYICONDATAW = NOTIFYICONDATAW
        self._wndproc_ref = self.WNDPROC(self._on_message)  # keep alive (no GC)

    # -- lifecycle ----------------------------------------------------------
    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="aqsec-tray")
        self._thread.start()

    def stop(self):
        if self.hwnd:
            self.user32.PostMessageW(self.hwnd, self.WM_CLOSE, 0, 0)

    # -- icon ---------------------------------------------------------------
    def _load_icon(self):
        ctypes = self.ctypes
        IMAGE_ICON, LR_LOADFROMFILE, LR_DEFAULTSIZE = 1, 0x0010, 0x0040
        if self.icon_path:
            self.user32.LoadImageW.restype = ctypes.c_void_p
            self.user32.LoadImageW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                               ctypes.c_uint, ctypes.c_int,
                                               ctypes.c_int, ctypes.c_uint]
            h = self.user32.LoadImageW(None, self.icon_path, IMAGE_ICON, 0, 0,
                                       LR_LOADFROMFILE | LR_DEFAULTSIZE)
            if h:
                return h
        self.user32.LoadIconW.restype = ctypes.c_void_p
        self.user32.LoadIconW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        return self.user32.LoadIconW(None, ctypes.c_void_p(self.IDI_SHIELD))

    def _add_icon(self):
        ctypes = self.ctypes
        nid = self.NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(self.NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = self.NIF_MESSAGE | self.NIF_ICON | self.NIF_TIP
        nid.uCallbackMessage = self.WM_TRAY
        nid.hIcon = self._load_icon()
        nid.szTip = self.tooltip[:127]
        self.nid = nid
        return self.shell32.Shell_NotifyIconW(self.NIM_ADD, ctypes.byref(nid))

    def _remove_icon(self):
        if self.nid is not None:
            self.shell32.Shell_NotifyIconW(self.NIM_DELETE,
                                           self.ctypes.byref(self.nid))
            self.nid = None

    def notify(self, title, message):
        if self.nid is None:
            return
        ctypes = self.ctypes
        nid = self.nid
        nid.uFlags = self.NIF_INFO
        nid.szInfo = str(message)[:255]
        nid.szInfoTitle = str(title)[:63]
        nid.dwInfoFlags = 0x01  # NIIF_INFO
        self.shell32.Shell_NotifyIconW(self.NIM_MODIFY, ctypes.byref(nid))

    # -- menu ---------------------------------------------------------------
    def _show_menu(self):
        ctypes = self.ctypes
        hmenu = self.user32.CreatePopupMenu()
        self.user32.AppendMenuW(hmenu, self.MF_STRING, self.ID_OPEN,
                                f"Open {self.app_name}")
        self.user32.SetMenuDefaultItem(hmenu, self.ID_OPEN, 0)
        self.user32.AppendMenuW(hmenu, self.MF_SEPARATOR, 0, None)
        self.user32.AppendMenuW(hmenu, self.MF_STRING, self.ID_SCAN, "Quick scan")
        self.user32.AppendMenuW(hmenu, self.MF_STRING, self.ID_UPDATE,
                                "Update definitions")
        self.user32.AppendMenuW(hmenu, self.MF_SEPARATOR, 0, None)
        self.user32.AppendMenuW(hmenu, self.MF_STRING, self.ID_EXIT, "Exit")
        pt = self.POINT()
        self.user32.GetCursorPos(ctypes.byref(pt))
        self.user32.SetForegroundWindow(self.hwnd)
        cmd = self.user32.TrackPopupMenu(
            hmenu, self.TPM_RIGHTBUTTON | self.TPM_RETURNCMD | self.TPM_NONOTIFY,
            pt.x, pt.y, 0, self.hwnd, None)
        self.user32.DestroyMenu(hmenu)
        if cmd:
            self._invoke(cmd)

    def _invoke(self, cmd):
        mapping = {self.ID_OPEN: self.cb.on_open, self.ID_SCAN: self.cb.on_scan,
                   self.ID_UPDATE: self.cb.on_update, self.ID_EXIT: self.cb.on_exit}
        fn = mapping.get(cmd)
        if fn:
            try:
                fn()
            except Exception:
                pass
        if cmd == self.ID_EXIT:
            self.stop()

    # -- window proc / loop -------------------------------------------------
    def _on_message(self, hwnd, msg, wparam, lparam):
        if msg == self.WM_TRAY:
            if lparam == self.WM_LBUTTONDBLCLK and self.cb.on_open:
                try:
                    self.cb.on_open()
                except Exception:
                    pass
            elif lparam in (self.WM_RBUTTONUP, self.WM_CONTEXTMENU):
                self._show_menu()
            return 0
        if msg == self.WM_CLOSE:
            self.user32.DestroyWindow(hwnd)
            return 0
        if self._wm_taskbar and msg == self._wm_taskbar:
            self._add_icon()          # Explorer restarted
            return 0
        if msg == self.WM_DESTROY:
            self._remove_icon()
            self.user32.PostQuitMessage(0)
            return 0
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _run(self):
        ctypes = self.ctypes
        self.user32.DefWindowProcW.restype = ctypes.c_ssize_t
        self.user32.DefWindowProcW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                               ctypes.c_size_t, ctypes.c_ssize_t]
        self.user32.CreateWindowExW.restype = ctypes.c_void_p
        self.kernel32.GetModuleHandleW.restype = ctypes.c_void_p
        self.shell32.Shell_NotifyIconW.argtypes = [ctypes.c_uint,
                                                   ctypes.POINTER(self.NOTIFYICONDATAW)]
        hinst = self.kernel32.GetModuleHandleW(None)
        wc = self.WNDCLASS()
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinst
        wc.lpszClassName = "AIQuickSecurityTray"
        if not self.user32.RegisterClassW(ctypes.byref(wc)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.hwnd = self.user32.CreateWindowExW(
            0, "AIQuickSecurityTray", self.app_name, 0, 0, 0, 0, 0,
            None, None, hinst, None)
        if not self.hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        self._wm_taskbar = self.user32.RegisterWindowMessageW("TaskbarCreated")
        self._add_icon()
        msg = self.MSG()
        while True:
            r = self.user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if r <= 0:
                break
            self.user32.TranslateMessage(ctypes.byref(msg))
            self.user32.DispatchMessageW(ctypes.byref(msg))
        self._remove_icon()


# --------------------------------------------------------------------------- #
# Non-Windows fallback (pystray if present, else no-op)
# --------------------------------------------------------------------------- #
class _PystrayTray:
    """Optional pystray-backed tray; a harmless stub if pystray is missing."""

    def __init__(self, app_name, callbacks, icon_path, tooltip):
        self.app_name = app_name
        self.cb = callbacks
        self.icon_path = icon_path
        self.tooltip = tooltip
        self._icon = None
        try:
            import pystray  # noqa: F401
            from PIL import Image  # noqa: F401
            self._available = True
        except Exception:
            self._available = False

    def start(self):
        if not self._available:
            # No tray backend: signal "not started" to the caller.
            raise RuntimeError("no tray backend available")
        import pystray
        from PIL import Image
        image = None
        try:
            if self.icon_path:
                image = Image.open(self.icon_path)
        except Exception:
            image = None
        if image is None:
            image = Image.new("RGBA", (64, 64), (8, 145, 178, 255))

        def _wrap(fn):
            return (lambda icon, item: fn()) if fn else (lambda icon, item: None)

        menu = pystray.Menu(
            pystray.MenuItem(f"Open {self.app_name}", _wrap(self.cb.on_open),
                             default=True),
            pystray.MenuItem("Quick scan", _wrap(self.cb.on_scan)),
            pystray.MenuItem("Update definitions", _wrap(self.cb.on_update)),
            pystray.MenuItem("Exit", _wrap(self.cb.on_exit)),
        )
        self._icon = pystray.Icon("aiquick-security", image, self.tooltip, menu)
        threading.Thread(target=self._icon.run, daemon=True,
                         name="aqsec-tray").start()

    def stop(self):
        if self._icon is not None:
            try:
                self._icon.stop()
            except Exception:
                pass

    def notify(self, title, message):
        if self._icon is not None:
            try:
                self._icon.notify(str(message), str(title))
            except Exception:
                pass
