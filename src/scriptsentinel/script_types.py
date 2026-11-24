"""Executable JavaScript MIME essences from the WHATWG MIME Sniffing Standard."""

JAVASCRIPT_MIME_TYPES = frozenset(
    {
        "application/ecmascript",
        "application/javascript",
        "application/x-ecmascript",
        "application/x-javascript",
        "text/ecmascript",
        "text/javascript",
        "text/javascript1.0",
        "text/javascript1.1",
        "text/javascript1.2",
        "text/javascript1.3",
        "text/javascript1.4",
        "text/javascript1.5",
        "text/jscript",
        "text/livescript",
        "text/x-ecmascript",
        "text/x-javascript",
    }
)


def executable_script_type(value: str | None) -> bool:
    essence = (value or "").split(";", 1)[0].strip().lower()
    return essence in JAVASCRIPT_MIME_TYPES or essence in ("", "module")
