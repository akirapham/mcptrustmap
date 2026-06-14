"""Typed errors. Every boundary failure is one of these, never a bare exception."""

from __future__ import annotations


class MtmError(Exception):
    """Base class for all MCPTrustMap errors."""

    exit_code: int = 1


class InputError(MtmError):
    """Bad/missing input: unreadable path, malformed config/manifest, unknown transport."""

    exit_code = 2


class SchemaValidationError(MtmError):
    """A record or report failed JSON Schema validation (fail-closed)."""

    exit_code = 3


class RegistryError(MtmError):
    """A finding id / severity / OWASP id is unknown to the registry."""

    exit_code = 3


class LlmReplayMiss(MtmError):
    """`--llm-mode replay` received a request with no recorded cassette.

    Raised loudly so prompt/model drift fails CI instead of silently calling the network.
    """

    exit_code = 4


class NotImplementedYet(MtmError):
    """A CLI surface exists but its phase is not yet implemented."""

    exit_code = 6
