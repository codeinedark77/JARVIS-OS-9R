"""Simulated Android app + device for tests, replay and offline development.

com.fake.shop: home feed (volatile text, variable-length list), product detail (Buy now / Share = T3),
cart (Checkout = T3), profile -> login form (sandbox typing) / sign up (T3), settings (location switch ->
system permission dialog; Delete account = T4), about -> privacy link (leaves the app), a periodic analytics
beacon (background), ad-pixel + advertising-id reads on first product view, and a planted privacy bug: after
the user DENIES location, the app keeps reading it from a third-party SDK stack.
Every injected event carries detail.cause = index of the device call that caused it (-1 = background), so
tests can score attribution accuracy against ground truth.
"""
from __future__ import annotations

import random
from collections import Counter
from typing import Dict, List, Optional, Tuple
from xml.sax.saxutils import quoteattr

from .device import Clock, Device, FakeClock
from .schema import Action, HookEvent

PKG = "com.fake.shop"
CHROME = "com.android.chrome"
LAUNCHER = "com.android.launcher3"
PERM = "com.google.android.permissioncontroller"
SDK_STACK = ["android.location.LocationManager.getLastKnownLocation", "com.adsdk.tracker.Collector.sample",
             "com.fake.shop.App.onResume"]

DANGEROUS_RIDS = {"btn_buy_now", "btn_share", "btn_checkout", "row_delete", "btn_signup",
                  "permission_allow_foreground_only_button"}


def _b(v: bool) -> str:
    return "true" if v else "false"


class _Builder:
    def __init__(self):
        self.hits: List[Tuple[Tuple[int, int, int, int], str, object]] = []

    def n(self, cls, bounds, kids=(), *, rid="", text="", desc="", pkg=PKG, clickable=False, scrollable=False,
          checkable=False, checked=False, enabled=True, password=False, meta=None) -> str:
        l, t, r, b = bounds
        full_rid = f"{pkg}:id/{rid}" if rid else ""
        editable = cls.endswith("EditText")
        attrs = [("index", "0"), ("text", text), ("resource-id", full_rid), ("class", cls), ("package", pkg),
                 ("content-desc", desc), ("checkable", _b(checkable)), ("checked", _b(checked)),
                 ("clickable", _b(clickable)), ("enabled", _b(enabled)), ("focusable", _b(clickable or editable)),
                 ("focused", "false"), ("scrollable", _b(scrollable)), ("long-clickable", "false"),
                 ("password", _b(password)), ("selected", "false"), ("bounds", f"[{l},{t}][{r},{b}]")]
        if clickable or editable:
            self.hits.append((bounds, rid, meta))
        return "<node " + " ".join(f"{k}={quoteattr(v)}" for k, v in attrs) + ">" + "".join(kids) + "</node>"

    def hit(self, x: int, y: int):
        best = None
        for bounds, rid, meta in self.hits:
            l, t, r, b = bounds
            if l <= x < r and t <= y < b:
                area = (r - l) * (b - t)
                if best is None or area < best[0]:
                    best = (area, rid, meta)
        return (best[1], best[2]) if best else (None, None)


class FakeDevice(Device):
    DUMP_COST_S = 0.4   # virtual cost of a uiautomator dump

    def __init__(self, clock: Optional[Clock] = None, seed: int = 0):
        self.clock = clock or FakeClock()
        self.rng = random.Random(f"fake:{seed}")
        self.fg = LAUNCHER
        self.screen = "launcher"
        self.stack: List[str] = []
        self.visits: Counter = Counter()
        self.typed: Dict[str, str] = {}
        self.loc_denied = False
        self.login_error = False
        self.page = 0
        self.seen_detail = False
        self.seq = -1                      # index of device call (launch/act) -> detail.cause
        self.queue: List[Tuple[float, HookEvent]] = []
        self.bg_next: Optional[float] = None
        self.tap_log: List[Tuple[str, str, Optional[str]]] = []
        self.act_log: List[Action] = []
        self.b = _Builder()

    # ---- Device API -------------------------------------------------------------------------------------
    def info(self) -> Dict:
        return {"kind": "fake", "pkg": PKG}

    def current_package(self) -> str:
        return self.fg

    def force_stop(self, pkg: str) -> None:
        if pkg == PKG:
            self.fg, self.screen, self.stack = LAUNCHER, "launcher", []
            self.queue.clear()
            self.bg_next = None
            self.loc_denied = False
            self.seen_detail = False
            self.typed.clear()
            self.login_error = False

    def launch(self, pkg: str) -> None:
        self.seq += 1
        if pkg != PKG:
            return
        self.fg, self.stack = PKG, []
        self.loc_denied = False
        self.seen_detail = False
        self.login_error = False
        self.bg_next = self.clock.now() + 2.0
        self._goto("home", push=False)
        self._emit("net.connect", "config.fakeshop.example:443", 0.2, 0.6, "Socket.connect")
        self._emit("net.url", "https://api.fakeshop.example/v1/config", 0.3, 0.9, "URL.openConnection")

    def act(self, a: Action) -> None:
        self.seq += 1
        self.act_log.append(a)
        if self.fg != PKG and self.fg != PERM:
            if a.kind == "back" and self.fg == CHROME:
                self.fg, self.screen = PKG, "about"
            return
        if a.kind == "tap":
            self._tap(a.x, a.y)
        elif a.kind == "text":
            self.b = _Builder()
            self._render()
            rid, _ = self.b.hit(a.x, a.y)
            if rid:
                self.typed[rid] = a.text or ""
        elif a.kind == "swipe":
            if self.screen == "home":
                self.page += 1
                self._emit("net.url", f"https://api.fakeshop.example/v1/feed?page={self.page}", 0.1, 0.5,
                           "URL.openConnection")
        elif a.kind == "back":
            self._back()

    def dump_ui(self) -> str:
        self.clock.sleep(self.DUMP_COST_S)
        return self._render()

    def drain_events(self) -> List[HookEvent]:
        now = self.clock.now()
        while self.bg_next is not None and self.bg_next <= now:
            self.queue.append((self.bg_next, HookEvent(t=self.bg_next, kind="net.connect",
                                                       target="analytics.fakeshop.example:443",
                                                       api="Socket.connect", pkg=PKG, detail={"cause": -1})))
            self.bg_next += 2.0
        ready = sorted((x for x in self.queue if x[0] <= now), key=lambda x: (x[0], x[1].kind, x[1].target))
        self.queue = [x for x in self.queue if x[0] > now]
        return [e for _, e in ready]

    # ---- internals ----------------------------------------------------------------------------------------
    def _emit(self, kind, target, lo, hi, api="", stack=None) -> None:
        lag = round(self.rng.uniform(lo, hi), 3)
        t = round(self.clock.now() + lag, 3)
        self.queue.append((t, HookEvent(t=t, kind=kind, target=target, api=api, pkg=PKG, tid=1,
                                        stack=list(stack or []), detail={"cause": self.seq})))

    def _goto(self, screen: str, push: bool = True) -> None:
        if push and self.screen not in ("launcher", screen):
            self.stack.append(self.screen)
        self.screen = screen
        self.visits[screen] += 1
        if screen == "home":
            self._emit("net.url", "https://api.fakeshop.example/v1/feed?page=0", 0.1, 0.6, "URL.openConnection")
            if self.loc_denied:  # planted bug: location read continues after the user said no
                self._emit("loc.read", "gps", 0.2, 0.7, "LocationManager.getLastKnownLocation", SDK_STACK)

    def _back(self) -> None:
        if self.fg == CHROME:
            self.fg, self.screen = PKG, "about"
            return
        if self.screen == "perm":
            self.loc_denied = True  # dismissing counts as deny
            self.screen = self.stack.pop() if self.stack else "settings"
            self.fg = PKG
            return
        if self.stack:
            self.screen = self.stack.pop()
            if self.screen == "home":
                self.visits["home"] += 1
        else:
            self.fg, self.screen = LAUNCHER, "launcher"

    def _tap(self, x: int, y: int) -> None:
        self.b = _Builder()
        self._render()
        rid, meta = self.b.hit(x, y)
        self.tap_log.append((self.fg, self.screen, rid))
        if rid is None:
            return
        h = getattr(self, "_on_" + rid, None)
        if h:
            h(meta)

    # handlers ---------------------------------------------------------------------------------------------
    def _on_btn_settings(self, m): self._goto("settings")
    def _on_tab_home(self, m): self.stack = []; self._goto("home", push=False)
    def _on_tab_cart(self, m):
        self.stack = []
        self._goto("cart", push=False)
        self._emit("net.url", "https://api.fakeshop.example/v1/cart", 0.1, 0.6, "URL.openConnection")
    def _on_tab_profile(self, m): self.stack = []; self._goto("profile", push=False)
    def _on_btn_back(self, m): self._back()

    def _on_item_row(self, pid):
        self.cur_pid = pid
        self._goto("detail")
        self._emit("net.url", f"https://api.fakeshop.example/v1/product/{pid}", 0.1, 0.5, "URL.openConnection")
        self._emit("net.url", f"https://ads.tracker.example/pixel?p={pid}", 0.2, 1.0, "URL.openConnection")
        if not self.seen_detail:
            self.seen_detail = True
            self._emit("ident.read", "advertising_id", 0.15, 0.6, "AdvertisingIdClient.getAdvertisingIdInfo",
                       ["com.adsdk.tracker.Ids.adid"])

    def _on_btn_add_cart(self, m): self._emit("net.url", "https://api.fakeshop.example/v1/cart/add", 0.1, 0.5, "URL.openConnection")
    def _on_btn_buy_now(self, m): self._goto("done")
    def _on_btn_share(self, m): self._goto("done")
    def _on_btn_checkout(self, m): self._goto("done")
    def _on_btn_login(self, m): self._goto("login")
    def _on_btn_signup(self, m): self._goto("done")
    def _on_row_delete(self, m): self._goto("done")

    def _on_btn_signin(self, m):
        self.login_error = True
        self._emit("net.connect", "auth.fakeshop.example:443", 0.1, 0.4, "Socket.connect")
        self._emit("net.url", "https://auth.fakeshop.example/oauth/token", 0.2, 0.8, "URL.openConnection")

    def _on_row_about(self, m): self._goto("about")

    def _on_row_location(self, m):
        self.fg = PERM
        self.stack.append("settings")
        self.screen = "perm"

    def _on_permission_allow_foreground_only_button(self, m):
        self.fg, self.screen = PKG, (self.stack.pop() if self.stack else "settings")
        self._emit("loc.read", "gps", 0.2, 0.6, "LocationManager.getLastKnownLocation",
                   ["com.fake.shop.LocationHelper.get"])

    def _on_permission_deny_button(self, m):
        self.loc_denied = True
        self.fg, self.screen = PKG, (self.stack.pop() if self.stack else "settings")

    def _on_link_privacy(self, m):
        self.fg = CHROME
        self.screen = "chrome"

    # rendering --------------------------------------------------------------------------------------------
    def _nav(self, b: _Builder) -> str:
        return b.n("android.widget.LinearLayout", (0, 2100, 1080, 2400), [
            b.n("android.widget.TextView", (0, 2100, 360, 2400), rid="tab_home", text="Home", clickable=True),
            b.n("android.widget.TextView", (360, 2100, 720, 2400), rid="tab_cart", text="Cart", clickable=True),
            b.n("android.widget.TextView", (720, 2100, 1080, 2400), rid="tab_profile", text="Profile", clickable=True),
        ], rid="bottom_nav")

    def _toolbar(self, b: _Builder, title: str, back=True, settings=False) -> str:
        kids = []
        if back:
            kids.append(b.n("android.widget.ImageButton", (0, 85, 160, 145), rid="btn_back", desc="Navigate up", clickable=True))
        kids.append(b.n("android.widget.TextView", (180, 85, 800, 145), rid="title", text=title))
        if settings:
            kids.append(b.n("android.widget.ImageButton", (900, 85, 1060, 145), rid="btn_settings", desc="Settings", clickable=True))
        return b.n("android.view.ViewGroup", (0, 80, 1080, 150), kids, rid="toolbar")

    def _btn(self, b: _Builder, rid: str, text: str, y: int) -> str:
        return b.n("android.widget.Button", (60, y, 1020, y + 120), rid=rid, text=text, clickable=True)

    def _render(self) -> str:
        b = _Builder()
        self.b = b
        pkg = self.fg
        s = self.screen
        if pkg == LAUNCHER:
            inner = b.n("android.widget.FrameLayout", (0, 0, 1080, 2400), [
                b.n("android.widget.TextView", (100, 300, 400, 400), text="Launcher")], pkg=LAUNCHER, rid="workspace")
        elif pkg == CHROME:
            inner = b.n("android.widget.FrameLayout", (0, 0, 1080, 2400), [
                b.n("android.widget.TextView", (40, 300, 1040, 400), text="Privacy policy page", pkg=CHROME)],
                pkg=CHROME, rid="content")
        elif s == "perm":
            inner = b.n("android.widget.FrameLayout", (0, 0, 1080, 2400), [
                b.n("android.widget.TextView", (80, 800, 1000, 1000), rid="permission_message",
                    text="Allow Shop to access this device's location?", pkg=PERM),
                b.n("android.widget.Button", (80, 1050, 1000, 1170), rid="permission_allow_foreground_only_button",
                    text="While using the app", clickable=True, pkg=PERM),
                b.n("android.widget.Button", (80, 1200, 1000, 1320), rid="permission_deny_button",
                    text="Don't allow", clickable=True, pkg=PERM)], pkg=PERM, rid="grant_dialog")
        else:
            body = self._screen_body(b, s)
            inner = b.n("android.widget.FrameLayout", (0, 0, 1080, 2400), body, rid="content")
        sysui = b.n("android.widget.FrameLayout", (0, 0, 1080, 80), [
            b.n("android.widget.TextView", (400, 10, 700, 70), text=f"12:{int(self.clock.now()) % 60:02d}",
                pkg="com.android.systemui")], pkg="com.android.systemui")
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><hierarchy rotation="0">'
                + sysui + inner + "</hierarchy>")

    def _screen_body(self, b: _Builder, s: str) -> List[str]:
        if s == "home":
            n_items = 3 + (self.visits["home"] % 4)
            rows = []
            for k in range(n_items):
                pid = self.page * 10 + k
                y = 230 + 200 * k
                rows.append(b.n("android.view.ViewGroup", (0, y, 1080, y + 200), [
                    b.n("android.widget.TextView", (40, y + 20, 800, y + 100), rid="item_title", text=f"Product {pid}"),
                    b.n("android.widget.TextView", (40, y + 100, 400, y + 180), rid="item_price", text=f"${pid}.99")],
                    rid="item_row", clickable=True, meta=pid))
            return [self._toolbar(b, "Shop", back=False, settings=True),
                    b.n("android.widget.TextView", (0, 150, 1080, 230), rid="updated",
                        text=f"Updated {int(self.clock.now()) % 60}s ago"),
                    b.n("androidx.recyclerview.widget.RecyclerView", (0, 230, 1080, 2100), rows, rid="list", scrollable=True),
                    self._nav(b)]
        if s == "detail":
            return [self._toolbar(b, f"Product {getattr(self, 'cur_pid', 0)}"),
                    b.n("android.widget.TextView", (60, 200, 1020, 380), rid="description", text="A fine product."),
                    self._btn(b, "btn_add_cart", "Add to cart", 400), self._btn(b, "btn_buy_now", "Buy now", 540),
                    self._btn(b, "btn_share", "Share", 680)]
        if s == "cart":
            return [self._toolbar(b, "Cart", back=False),
                    b.n("android.widget.TextView", (60, 250, 1020, 400), rid="empty", text="Your cart"),
                    self._btn(b, "btn_checkout", "Checkout", 900), self._nav(b)]
        if s == "profile":
            return [self._toolbar(b, "Profile", back=False), self._btn(b, "btn_login", "Log in", 300),
                    self._btn(b, "btn_signup", "Create account", 460), self._nav(b)]
        if s == "login":
            kids = [self._toolbar(b, "Log in"),
                    b.n("android.widget.EditText", (60, 250, 1020, 370), rid="field_email",
                        text=self.typed.get("field_email", "Email")),
                    b.n("android.widget.EditText", (60, 420, 1020, 540), rid="field_password",
                        text=self.typed.get("field_password", "Password"), password=True),
                    self._btn(b, "btn_signin", "Sign in", 600)]
            if self.login_error:
                kids.append(b.n("android.widget.TextView", (60, 760, 1020, 860), rid="error", text="Invalid credentials"))
            return kids
        if s == "settings":
            return [self._toolbar(b, "Settings"),
                    b.n("android.view.ViewGroup", (0, 200, 1080, 360), [
                        b.n("android.widget.TextView", (40, 220, 800, 340), text="Location sharing")],
                        rid="row_location", clickable=True, checkable=True),
                    b.n("android.view.ViewGroup", (0, 380, 1080, 540), [
                        b.n("android.widget.TextView", (40, 400, 800, 520), text="About")],
                        rid="row_about", clickable=True),
                    b.n("android.view.ViewGroup", (0, 560, 1080, 720), [
                        b.n("android.widget.TextView", (40, 580, 800, 700), text="Delete account")],
                        rid="row_delete", clickable=True)]
        if s == "about":
            return [self._toolbar(b, "About"),
                    b.n("android.widget.TextView", (60, 200, 1020, 300), rid="version", text="Version 1.0"),
                    b.n("android.widget.TextView", (60, 340, 1020, 440), rid="link_privacy", text="Privacy policy",
                        clickable=True)]
        if s == "done":
            return [self._toolbar(b, "Done"), b.n("android.widget.TextView", (60, 300, 1020, 400), rid="msg", text="Done")]
        return []
