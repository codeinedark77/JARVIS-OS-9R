"""Tokenisation helpers shared by safety and policy (label / resource-id matching)."""
from __future__ import annotations

import re
from typing import List

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ALNUM = re.compile(r"[a-z0-9]+")


def tokens(*parts) -> List[str]:
    """Lower-case alnum tokens; splits camelCase, snake_case, punctuation."""
    out: List[str] = []
    for p in parts:
        if not p:
            continue
        out.extend(_ALNUM.findall(_CAMEL.sub(" ", str(p)).lower()))
    return out


def joined(*parts) -> str:
    """Space-padded token string so ' term ' substring tests are whole-word / whole-phrase."""
    return " " + " ".join(tokens(*parts)) + " "


def has_term(j: str, term: str) -> bool:
    return (" " + term + " ") in j
