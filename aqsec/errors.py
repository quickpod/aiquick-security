"""Error types for aqsec (AIQuick Security)."""


class AQSecError(Exception):
    """Raised for any recoverable failure in an aqsec operation.

    Every public function raises this (and only this) on failure so callers
    -- the CLI, the GUI and the tray -- have a single exception to catch and
    can show a clean message instead of a raw traceback.
    """
