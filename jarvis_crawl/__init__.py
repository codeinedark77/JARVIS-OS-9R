"""jarvis_crawl: autonomous app-exploration engine.

Jarvis action layer drives an app, Frida hooks capture behaviour, every episode is a
replayable trace that feeds warden (labels) and jarvis_loop (training signal).
Pure stdlib; device backends shell out to adb, Frida runs host-side in frida/frida_host.py.
"""
__version__ = "0.1.0"
