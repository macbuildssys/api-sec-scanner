"""Small text helpers shared by the report formats."""

from __future__ import annotations

_END = (".", "!", "?")

def sentence(text: str) -> str:
    """Make an evidence line read as a sentence: a capital letter first and a full stop at the end.
    Lines that start with a name, address or header (for example 'Cookie X', 'http://...',
    'X-Frame-Options: ...') keep their first letter as written."""
    text = " ".join(str(text).split())
    if not text:
        return text
    first = text.split(" ", 1)[0]
    if text[0].islower() and not any(c in first for c in ":/.-_@"):
        text = text[0].upper() + text[1:]
    if not text.endswith(_END):
        text += "."
    return text
