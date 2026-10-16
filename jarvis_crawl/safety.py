"""Action-tier permission model for the crawler.

  T0 observe        dump / wait
  T1 navigate       tap benign controls, scroll, back, (re)launch the app under test
  T2 input          type into fields -- sandbox identity values only
  T3 consequential  anything that spends, sends, publishes, deletes, shares, grants, creates accounts
  T4 forbidden      leaving the app under test, payment/identity fields, destructive system actions

Autonomous ceiling defaults to T2. T3 -> ESCALATE (autonomous runs treat it as skipped and queue it for
review). T4 -> DENY always. Matching is keyword/whole-word on resource-id + label + descendant labels
(English). False positives cost coverage, never safety; extend the term sets per app.
"""
from __future__ import annotations

import os
import random
import string
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional

from .schema import (T_CONSEQUENTIAL, T_FORBIDDEN, T_INPUT, T_NAVIGATE, T_OBSERVE, V_ALLOW, V_DENY,
                     V_ESCALATE, Action)
from .statehash import ScreenAnalysis, UINode, short_rid
from .textutil import has_term, joined

PERMISSION_PKGS = frozenset({"com.google.android.permissioncontroller", "com.android.permissioncontroller"})

T3_TERMS = frozenset({
    "buy", "purchase", "pay", "checkout", "order", "subscribe", "upgrade", "donate", "tip",
    "send", "post", "publish", "tweet", "submit", "share", "invite", "reply",
    "delete", "remove", "erase", "clear", "reset", "logout", "signout", "sign out", "log out",
    "transfer", "withdraw", "book", "reserve", "call", "dial", "confirm", "allow", "grant",
    "sign up", "signup", "create account", "register", "join now", "unlock", "install", "download",
})
T4_TERMS = frozenset({
    "uninstall", "factory reset", "wipe", "format", "delete account", "delete my account",
    "deactivate", "deactivate account", "close account", "emergency", "sos", "911", "112",
    "force stop", "erase all", "reset all", "disable",
})
BENIGN_TERMS = frozenset({
    "order history", "my orders", "orders", "track order", "payment methods", "saved posts", "my posts",
    "call history", "share settings", "download settings", "invite friends settings", "clear search",
})
SENSITIVE_FIELD_TERMS = frozenset({
    "card number", "credit card", "debit card", "cvv", "cvc", "security code", "expiry", "expiration",
    "iban", "ssn", "social security", "routing number", "account number", "pin", "otp",
    "verification code", "passport", "license number", "tax id",
})


@dataclass
class SafetyDecision:
    tier: int
    verdict: str
    reasons: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"tier": self.tier, "verdict": self.verdict, "reasons": list(self.reasons), "rules": list(self.rules)}


@dataclass
class SafetyConfig:
    allowed_packages: FrozenSet[str]
    permission_pkgs: FrozenSet[str] = PERMISSION_PKGS
    permission_mode: str = "deny"          # deny: allow-buttons are T3 | grant: allow-buttons are T2 (sandbox device)
    max_autonomous_tier: int = T_INPUT
    allow_leave_app: bool = False
    extra_t3: FrozenSet[str] = frozenset()
    extra_t4: FrozenSet[str] = frozenset()
    extra_benign: FrozenSet[str] = frozenset()
    max_text_inputs: int = 12
    max_actions: int = 500

    def to_dict(self) -> Dict:
        return {"allowed_packages": sorted(self.allowed_packages), "permission_pkgs": sorted(self.permission_pkgs),
                "permission_mode": self.permission_mode, "max_autonomous_tier": self.max_autonomous_tier,
                "allow_leave_app": self.allow_leave_app, "extra_t3": sorted(self.extra_t3),
                "extra_t4": sorted(self.extra_t4), "extra_benign": sorted(self.extra_benign),
                "max_text_inputs": self.max_text_inputs, "max_actions": self.max_actions}


class SafetyPolicy:
    def __init__(self, cfg: SafetyConfig):
        self.cfg = cfg
        t3 = set(T3_TERMS | cfg.extra_t3)
        if cfg.permission_mode == "grant":
            t3 -= {"allow", "grant"}
        self.t3 = frozenset(t3)
        self.t4 = frozenset(T4_TERMS | cfg.extra_t4)
        self.benign = frozenset(BENIGN_TERMS | cfg.extra_benign)

    def evaluate(self, action: Action, node: Optional[UINode], label: str, screen_pkg: str,
                 counters: Optional[Dict[str, int]] = None) -> SafetyDecision:
        cfg = self.cfg
        counters = counters or {}
        tier = T_NAVIGATE
        reasons: List[str] = []
        rules: List[str] = []

        def up(t: int, rule: str, reason: str) -> None:
            nonlocal tier
            tier = max(tier, t)
            rules.append(rule)
            reasons.append(reason)

        allowed, perm = cfg.allowed_packages, cfg.permission_pkgs
        screen_ok = screen_pkg in allowed or screen_pkg in perm
        kind = action.kind

        if kind == "wait":
            tier = T_OBSERVE
        elif kind == "back":
            pass
        elif kind == "launch":
            if action.pkg not in allowed:
                up(T_FORBIDDEN, "launch.foreign", f"launch:{action.pkg}")
        elif kind == "home":
            if not cfg.allow_leave_app:
                up(T_FORBIDDEN, "leave_app", "home")
        elif kind == "swipe":
            if not screen_ok:
                up(T_FORBIDDEN, "screen.foreign", f"screen:{screen_pkg}")
        elif kind in ("tap", "long_tap", "text"):
            if not screen_ok:
                up(T_FORBIDDEN, "screen.foreign", f"screen:{screen_pkg}")
            elif node is None:
                up(T_FORBIDDEN, "untargeted", "no_target_node")
            else:
                self._node_rules(kind, node, label, up)
        else:
            up(T_FORBIDDEN, "unknown_kind", f"kind:{kind}")

        if counters.get("actions", 0) >= cfg.max_actions:
            up(T_FORBIDDEN, "cap.actions", "cap:actions")
        if kind == "text" and counters.get("text_inputs", 0) >= cfg.max_text_inputs:
            up(T_FORBIDDEN, "cap.text_inputs", "cap:text_inputs")

        if tier >= T_FORBIDDEN:
            verdict = V_DENY
        elif tier > cfg.max_autonomous_tier:
            verdict = V_ESCALATE if tier == T_CONSEQUENTIAL else V_DENY
        else:
            verdict = V_ALLOW
        return SafetyDecision(tier, verdict, reasons, rules)

    def _node_rules(self, kind: str, node: UINode, label: str, up) -> None:
        cfg = self.cfg
        j = joined(node.rid, node.desc, node.text, label)
        if node.pkg in cfg.permission_pkgs:
            rid = short_rid(node.rid)
            if rid.startswith("permission_allow"):
                if cfg.permission_mode == "grant":
                    up(T_INPUT, "perm.allow.grant", "perm:allow(grant-mode)")
                else:
                    up(T_CONSEQUENTIAL, "perm.allow", "perm:allow")
            elif rid.startswith("permission_deny"):
                up(T_NAVIGATE, "perm.deny", "perm:deny")
            else:
                up(T_FORBIDDEN, "perm.unknown_target", f"perm_ui:{rid or node.cls}")
            return
        if node.pkg not in cfg.allowed_packages:
            up(T_FORBIDDEN, "node.foreign", f"node_pkg:{node.pkg}")
            return
        if kind == "text":
            hits = sorted(t for t in SENSITIVE_FIELD_TERMS if has_term(j, t))
            if hits:
                up(T_FORBIDDEN, "field.sensitive", "field:" + hits[0])
            else:
                up(T_INPUT, "input.sandbox", "text_input")
            return
        hits4 = sorted(t for t in self.t4 if has_term(j, t))
        if hits4:
            up(T_FORBIDDEN, "term.t4", "t4:" + hits4[0])
            return
        if any(has_term(j, b) for b in self.benign):
            return
        hits3 = sorted(t for t in self.t3 if has_term(j, t))
        if hits3:
            up(T_CONSEQUENTIAL, "term.t3", "t3:" + hits3[0])


class KillSwitch:
    """Checked before every action. Trips on: in-process trip(), file at `path`, env JARVIS_CRAWL_KILL."""

    def __init__(self, path: Optional[str] = None, env_var: str = "JARVIS_CRAWL_KILL"):
        self.path, self.env_var = path, env_var
        self._reason: Optional[str] = None

    def trip(self, reason: str = "manual") -> None:
        self._reason = reason

    def tripped(self) -> Optional[str]:
        if self._reason:
            return self._reason
        if self.path and os.path.exists(self.path):
            return f"file:{self.path}"
        if os.environ.get(self.env_var, "") not in ("", "0"):
            return "env"
        return None


class SandboxIdentity:
    """Deterministic throwaway identity. Never real data. .invalid is a reserved TLD (RFC 2606)."""

    FIRST = ("Alex", "Sam", "Jordan", "Riley", "Casey", "Morgan")
    LAST = ("Tester", "Probe", "Sandbox", "Crawler")

    def __init__(self, seed: int):
        r = random.Random(f"identity:{seed}")
        n = r.randrange(10 ** 6)
        self.first, self.last = r.choice(self.FIRST), r.choice(self.LAST)
        self.username = f"crawler{n:06d}"
        self.email = f"{self.username}@example.invalid"
        self.password = "Cr4wl-" + "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(10))
        self.phone = f"555010{r.randrange(10, 99)}"       # 555-01xx: reserved fictional range
        self.zip = "00000"

    def value_for(self, field_kind: str) -> str:
        return {"email": self.email, "password": self.password, "phone": self.phone, "name": f"{self.first} {self.last}",
                "first": self.first, "last": self.last, "username": self.username, "zip": self.zip,
                "search": "test"}.get(field_kind, "test")


def field_kind(node: UINode, label: str = "") -> str:
    j = joined(node.rid, node.desc, node.text, label)
    if node.password or has_term(j, "password") or has_term(j, "passcode"):
        return "password"
    for kind, terms in (("email", ("email", "mail")), ("phone", ("phone", "mobile", "tel")),
                        ("username", ("username", "user", "login")), ("first", ("first",)),
                        ("last", ("last", "surname")), ("name", ("name",)), ("zip", ("zip", "postal")),
                        ("search", ("search", "query"))):
        if any(has_term(j, t) for t in terms):
            return kind
    return "text"


_PERM_KINDS = (("location", "loc"), ("contacts", "contacts"), ("microphone", "mic"), ("record audio", "mic"),
               ("camera", "cam"), ("text messages", "sms"), ("sms", "sms"), ("calendar", "calendar"),
               ("call log", "calllog"), ("phone calls", "calllog"), ("notifications", "notif"),
               ("photos", "media"), ("files", "media"), ("nearby devices", "wifi"))


def permission_prompt_kind(an: ScreenAnalysis, permission_pkgs: FrozenSet[str] = PERMISSION_PKGS) -> Optional[str]:
    """Which resource a system permission dialog is asking for (None if this isn't one)."""
    for n in an.nodes:
        if n.pkg in permission_pkgs and short_rid(n.rid).endswith("permission_message"):
            t = (n.text or n.desc).lower()
            for needle, kind in _PERM_KINDS:
                if needle in t:
                    return kind
            return "other"
    return None
