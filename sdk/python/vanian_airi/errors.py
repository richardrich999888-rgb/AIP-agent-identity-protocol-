"""Failure modes of the AIRI SDK. Every one is fatal by design."""

from __future__ import annotations


class AiriError(Exception):
    """Base class. The SDK raises; it never degrades silently."""


class IdentityUnavailable(AiriError):
    """The agent's signing key could not be loaded.

    This is deliberately fatal and deliberately *not* recoverable by
    generating a new key. A process that mints a replacement identity when it
    cannot read its own is a process that has silently become a different
    principal — every token issued to the old identity is now unverifiable,
    and the service reports itself healthy while doing it. Fail closed.
    """


class ContextUnavailable(AiriError):
    """No execution context is active where one is required.

    Ambiguous execution context is refused rather than guessed: an event
    attributed to the wrong execution is worse than no event.
    """


class ContextMalformed(AiriError):
    """A propagated context could not be parsed, or failed its integrity check."""


class CommitmentError(AiriError):
    """A value could not be committed to (unserialisable, or oversized)."""
