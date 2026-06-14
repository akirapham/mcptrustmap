"""Secret-reconnaissance vocabulary — candidate paths/keywords for the attacker.

Standard sensitive-file enumeration: a file-reading tool that does no path
confinement will happily serve any of these, and a content-search tool will
confirm a secret's presence by keyword. The attacker is handed this vocabulary in
its arsenal and told to enumerate it (and to *infer* siblings from the tool's own
hints, e.g. a "public" dir implies a "private" one). The values themselves carry no
honey marker — a hit is proven only when a `watch` secret or a honey marker shows
up in the response, so this just widens where the attacker looks, never what counts.
"""

from __future__ import annotations

# Common secret-bearing absolute paths + bare filenames worth trying against any
# file-read / path-traversal tool.
SECRET_PATHS: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.aws/credentials",
    "~/.netrc",
    "~/.git-credentials",
    ".env",
    ".env.local",
    "config.json",
    "config.yaml",
    "settings.py",
    "secrets.json",
    "credentials.json",
    "credentials.txt",
    "secrets.txt",
    "private/credentials.txt",
    "id_rsa",
    "server.key",
)

# Keywords that betray a secret's presence to a content-search / grep tool.
SECRET_KEYWORDS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "token",
    "credential",
    "private_key",
    "BEGIN RSA PRIVATE KEY",
    "aws_secret_access_key",
    "bearer",
)
