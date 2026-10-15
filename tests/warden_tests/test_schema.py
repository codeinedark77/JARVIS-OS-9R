import json
from warden import schema


def test_normalize_defaults_fg_and_keeps_bytes():
    assert schema.normalize_event({"t": 5, "cat": "network", "api": "x"})["fg"] == 1
    assert schema.normalize_event({"t": 5, "cat": "traffic", "arg": "tls", "n": 10, "fg": 0})["n"] == 10


def test_normalize_rejects_missing_fields():
    assert schema.normalize_event({"cat": "network"}) is None
    assert schema.normalize_event({"t": 1}) is None


def test_dump_and_load_roundtrip(tmp_path):
    p = tmp_path / "s.session.jsonl"
    ev = [{"t": 2, "api": "a", "cat": "network", "arg": "h", "caller": "c", "fg": 1}, {"t": 1, "api": "b", "cat": "location", "arg": None, "caller": "?", "fg": 0}]
    schema.dump_session(p, {"package": "com.x"}, ev)
    s = schema.load_session(p)
    assert s.package == "com.x" and s.sid == "s"
    assert [e["t"] for e in s.events] == [1, 2]            # sorted on load


def test_load_session_skips_malformed_lines(tmp_path):
    p = tmp_path / "bad.session.jsonl"
    p.write_text('{"meta": {"package": "p"}}\nnot json\n{"t": 1, "cat": "network"}\n{}\n')
    s = schema.load_session(p)
    assert len(s.events) == 1


def test_iter_session_paths_excludes_reserved(tmp_path):
    (tmp_path / "a.session.jsonl").write_text('{"meta":{}}\n')
    (tmp_path / "labels.jsonl").write_text("{}\n")
    (tmp_path / "verdicts.jsonl").write_text("{}\n")
    paths = schema.iter_session_paths(tmp_path)
    assert [p.name for p in paths] == ["a.session.jsonl"]
