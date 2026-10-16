"""UI-tree parsing + structural state hashing.

Goal: two screens that differ only in dynamic content (timestamps, counters, feed text, list length)
hash identically; screens that differ in structure/affordances hash differently.

  exact hash  : sha256 of a canonical tree string (text excluded, repeated siblings collapsed to X*)
  text fallback: when few interactive nodes carry a resource-id (Compose/Flutter-ish trees), labels of
                 interactive nodes (digits masked) join the hash, otherwise everything looks identical
  simhash     : 64-bit over node/bigram features (set-valued so list length is irrelevant) for near-dup lookup
"""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

NOISE_PKGS = frozenset({"com.android.systemui"})
EDIT_SUFFIXES = ("EditText", "AutoCompleteTextView", "SearchAutoComplete")

_BOUNDS = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")
_DIGITS = re.compile(r"\d+")
_WS = re.compile(r"\s+")


def short_cls(c: str) -> str:
    return c.rsplit(".", 1)[-1] if c else ""


def short_rid(r: str) -> str:
    if not r:
        return ""
    return r.split("/", 1)[1] if "/" in r else r


def norm_text(s: Optional[str], limit: int = 40) -> str:
    s = _WS.sub(" ", (s or "").strip().lower())
    return _DIGITS.sub("#", s)[:limit]


def _bounds(s: str) -> Tuple[int, int, int, int]:
    m = _BOUNDS.match(s or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))) if m else (0, 0, 0, 0)


@dataclass(frozen=True)
class UINode:
    idx: int
    path: str
    depth: int
    parent: int
    cls: str
    rid: str
    text: str
    desc: str
    pkg: str
    clickable: bool
    long_clickable: bool
    scrollable: bool
    checkable: bool
    enabled: bool
    password: bool
    editable: bool
    bounds: Tuple[int, int, int, int]

    @property
    def area(self) -> int:
        l, t, r, b = self.bounds
        return max(0, r - l) * max(0, b - t)

    @property
    def center(self) -> Tuple[int, int]:
        l, t, r, b = self.bounds
        return ((l + r) // 2, (t + b) // 2)

    @property
    def interactive(self) -> bool:
        return self.enabled and (self.clickable or self.long_clickable or self.scrollable
                                 or self.checkable or self.editable)

    def sig(self) -> str:
        return f"{short_cls(self.cls)}|{short_rid(self.rid)}|{norm_text(self.text or self.desc)}"


def parse_ui(xml_text: str, noise_pkgs: Iterable[str] = NOISE_PKGS) -> List[UINode]:
    """uiautomator-dump XML -> DFS-ordered nodes. Noise packages (status bar) are dropped with subtrees."""
    noise = frozenset(noise_pkgs)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:  # pragma: no cover - defensive
        raise ValueError(f"unparseable UI dump: {e}") from e
    nodes: List[UINode] = []

    def visit(el: ET.Element, depth: int, parent: int, path: str) -> None:
        a = el.attrib
        pkg = a.get("package", "")
        if pkg in noise:
            return
        cls = a.get("class", "")
        idx = len(nodes)
        nodes.append(UINode(
            idx=idx, path=path, depth=depth, parent=parent, cls=cls, rid=a.get("resource-id", ""),
            text=a.get("text", ""), desc=a.get("content-desc", ""), pkg=pkg,
            clickable=a.get("clickable") == "true", long_clickable=a.get("long-clickable") == "true",
            scrollable=a.get("scrollable") == "true", checkable=a.get("checkable") == "true",
            enabled=a.get("enabled", "true") == "true", password=a.get("password") == "true",
            editable=any(cls.endswith(s) for s in EDIT_SUFFIXES), bounds=_bounds(a.get("bounds", ""))))
        k = 0
        for child in el:
            if child.tag != "node":
                continue
            before = len(nodes)
            visit(child, depth + 1, idx, f"{path}/{k}")
            if len(nodes) > before:
                k += 1

    k = 0
    for child in root:
        if child.tag != "node":
            continue
        before = len(nodes)
        visit(child, 0, -1, str(k))
        if len(nodes) > before:
            k += 1
    return nodes


def simhash(features: Dict[str, int]) -> int:
    v = [0] * 64
    for f, w in features.items():
        h = int.from_bytes(hashlib.blake2b(f.encode("utf-8"), digest_size=8).digest(), "big")
        for b in range(64):
            v[b] += w if (h >> b) & 1 else -w
    out = 0
    for b in range(64):
        if v[b] > 0:
            out |= 1 << b
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


@dataclass
class ScreenAnalysis:
    hash: str
    simhash: int
    pkg: str
    nodes: List[UINode]
    children: Dict[int, List[int]]
    rid_coverage: float
    text_fallback: bool

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def simhash_hex(self) -> str:
        return f"{self.simhash:016x}"

    def subtree_text(self, idx: int, limit: int = 160) -> str:
        """Visible labels under a node (own text/desc first, then descendants, document order)."""
        out: List[str] = []
        size = 0
        stack = [idx]
        while stack and size < limit:
            n = self.nodes[stack.pop()]
            if not n.password:
                for s in (n.text, n.desc):
                    if s:
                        out.append(s)
                        size += len(s) + 1
            stack.extend(reversed(self.children.get(n.idx, [])))
        return " ".join(out)[:limit]


def _flags(n: UINode) -> str:
    return "".join(ch for ch, on in (("c", n.clickable), ("l", n.long_clickable), ("s", n.scrollable),
                                     ("k", n.checkable), ("e", n.editable), ("p", n.password),
                                     ("d", not n.enabled)) if on)


def _token(n: UINode, use_text: bool) -> str:
    t = f"{short_cls(n.cls)}|{short_rid(n.rid)}|{_flags(n)}"
    if use_text and n.interactive:
        lab = norm_text(n.text or n.desc)
        if lab:
            t += "|" + lab
    return t


def analyze(xml_text: str, noise_pkgs: Iterable[str] = NOISE_PKGS,
            text_fallback_threshold: float = 0.3) -> ScreenAnalysis:
    nodes = parse_ui(xml_text, noise_pkgs)
    children: Dict[int, List[int]] = {-1: []}
    for n in nodes:
        children.setdefault(n.idx, [])
        children.setdefault(n.parent, []).append(n.idx)

    inter = [n for n in nodes if n.interactive and n.area > 0]
    pool = inter if inter else [n for n in nodes if n.area > 0]
    rid_cov = (sum(1 for n in pool if n.rid) / len(pool)) if pool else 1.0
    use_text = rid_cov < text_fallback_threshold

    def canon(i: int) -> str:
        n = nodes[i]
        parts = [canon(c) for c in children[i] if nodes[c].area > 0 or nodes[c].scrollable]
        if n.scrollable:  # list-like: order-insensitive unique collapse
            seen: Dict[str, int] = {}
            for p in parts:
                seen[p] = seen.get(p, 0) + 1
            parts = [p + ("*" if c > 1 else "") for p, c in seen.items()]
        else:             # consecutive-duplicate collapse
            runs: List[List] = []
            for p in parts:
                if runs and runs[-1][0] == p:
                    runs[-1][1] += 1
                else:
                    runs.append([p, 1])
            parts = [p + ("*" if c > 1 else "") for p, c in runs]
        return "(" + _token(n, use_text) + ":" + ",".join(parts) + ")"

    roots = [c for c in children[-1] if nodes[c].area > 0 or nodes[c].scrollable]
    body = "".join(canon(r) for r in roots)

    # package of the dominant (largest) window node
    pkg = ""
    best = -1
    for n in nodes:
        if n.area > best:
            best, pkg = n.area, n.pkg
    h = hashlib.sha256((pkg + "|" + body).encode("utf-8")).hexdigest()[:16]

    feats: Dict[str, int] = {}
    for n in nodes:
        if n.area <= 0 and not n.scrollable:
            continue
        tok = _token(n, use_text)
        w = 2 if n.interactive else 1
        for f in (f"{n.depth}:{tok}",
                  f"{_token(nodes[n.parent], use_text) if n.parent >= 0 else '^'}>{tok}"):
            feats[f] = max(feats.get(f, 0), w)
    return ScreenAnalysis(hash=h, simhash=simhash(feats), pkg=pkg, nodes=nodes, children=children,
                          rid_coverage=rid_cov, text_fallback=use_text)


class ScreenIndex:
    """Assigns state ids. Every exact hash gets its own id; `new` is False for near-duplicates
    (same package, simhash within `near_threshold` bits of an existing state)."""

    def __init__(self, near_threshold: int = 3):
        self.near_threshold = near_threshold
        self.by_hash: Dict[str, int] = {}
        self.entries: List[Tuple[int, str]] = []  # (simhash, pkg)

    def observe(self, a: ScreenAnalysis) -> Tuple[int, bool, Optional[int]]:
        if a.hash in self.by_hash:
            return self.by_hash[a.hash], False, None
        best, bd = None, 65
        for i, (sh, pkg) in enumerate(self.entries):
            if pkg != a.pkg:
                continue
            d = hamming(sh, a.simhash)
            if d < bd:
                best, bd = i, d
        sid = len(self.entries)
        self.entries.append((a.simhash, a.pkg))
        self.by_hash[a.hash] = sid
        if best is not None and bd <= self.near_threshold:
            return sid, False, best
        return sid, True, None
