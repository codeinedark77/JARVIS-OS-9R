"""JARVIS Autonomous App Exploration (Crawl) Subsystem.
Bridges directly to jarvis_crawl: drives applications, enforces zero-trust safety tiers,
captures Frida hook events, and emits replayable traces for Warden classification and Jarvis Loop training.
"""
from __future__ import annotations

from jarvis_crawl.runner import Runner, RunConfig
from jarvis_crawl.device import AdbDevice, RealClock, FakeClock, JsonlTailSource
from jarvis_crawl.fakeapp import FakeDevice
from jarvis_crawl.safety import KillSwitch, SafetyEngine, SafetyConfig, ActionVerdict, T_OBSERVE, T_NAVIGATE, T_INPUT, T_CONSEQUENTIAL, T_FORBIDDEN
from jarvis_crawl.schema import (
    Episode,
    Step,
    Action,
    HookEvent,
    AttributedEvent,
    read_episode,
    flatten_for_trace,
    safety_violations,
    validate_episode,
)
from jarvis_crawl.replay import verify_episode, Replayer
from jarvis_crawl.export import episode_features, episode_sequence, export_dataset
from jarvis_crawl.statehash import analyze, StateAnalysis, UINode

__all__ = [
    "Runner",
    "RunConfig",
    "AdbDevice",
    "RealClock",
    "FakeClock",
    "JsonlTailSource",
    "FakeDevice",
    "KillSwitch",
    "SafetyEngine",
    "SafetyConfig",
    "ActionVerdict",
    "T_OBSERVE",
    "T_NAVIGATE",
    "T_INPUT",
    "T_CONSEQUENTIAL",
    "T_FORBIDDEN",
    "Episode",
    "Step",
    "Action",
    "HookEvent",
    "AttributedEvent",
    "read_episode",
    "flatten_for_trace",
    "safety_violations",
    "validate_episode",
    "verify_episode",
    "Replayer",
    "episode_features",
    "episode_sequence",
    "export_dataset",
    "analyze",
    "StateAnalysis",
    "UINode",
]
