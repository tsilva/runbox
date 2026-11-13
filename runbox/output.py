"""Sanitize reviewed application logs before forwarding them to the operator."""

import re

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SESSION_URL = re.compile(r"(?:https?|postgres(?:ql)?)://[^\s/]+@", re.I)
JWT = re.compile(r"eyJ[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+")
SERVICE_KEY = re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9_-]+|\bsk-or-v1-[A-Za-z0-9_-]+")
CAPABILITY = re.compile(r"/objects/[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")
QUERY_SECRET = re.compile(
    r"([?&](?:__clerk\w*|(?:access_|refresh_)?token|nonce|code|state|api_key)=)[^&\s]+",
    re.I,
)


def safe_output(line, redactions=()):
    """Return text only; never retain an unsanitized log or redaction inventory."""
    line = ANSI.sub("", line)
    line = "".join(
        character for character in line if character in "\t\n\r" or ord(character) >= 32
    )
    for value in sorted(
        (item for item in redactions if isinstance(item, str) and item),
        key=len,
        reverse=True,
    ):
        line = line.replace(value, "[redacted]")
    line = SESSION_URL.sub("[redacted-session]@", line)
    line = re.sub(r"agv_[A-Za-z0-9_.%+-]+", "[redacted-session]", line)
    line = JWT.sub("[redacted-token]", line)
    line = SERVICE_KEY.sub("[redacted-key]", line)
    line = CAPABILITY.sub("/objects/[redacted-capability]", line)
    return QUERY_SECRET.sub(r"\1[redacted]", line)
