"""Verdict export: Cypher script for Neo4j (apply with cypher-shell) and a JSON webhook POST (n8n etc.)."""
import json, time, urllib.request


def q(s):
    s = "" if s is None else str(s)
    s = "".join(ch for ch in s if ch >= " " or ch == "\t")
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def to_cypher(verdicts):
    out = ["// warden export %s" % time.strftime("%Y-%m-%dT%H:%M:%S"),
           "CREATE CONSTRAINT warden_app IF NOT EXISTS FOR (a:App) REQUIRE a.package IS UNIQUE;",
           "CREATE CONSTRAINT warden_sdk IF NOT EXISTS FOR (s:SDK) REQUIRE s.name IS UNIQUE;",
           "CREATE CONSTRAINT warden_host IF NOT EXISTS FOR (h:Host) REQUIRE h.name IS UNIQUE;"]
    for v in verdicts:
        pk = v["package"] or v["sid"]
        evd = v.get("_evidence") or {}
        out.append("MERGE (a:App {package:%s}) SET a.verdict=%s, a.risk=%d, a.alert=%s, a.novel=%s, a.model=%s, a.last_session=%s;" % (q(pk), q(v["class"]), v["risk"], str(v["alert"]).lower(), str(v["novel"]).lower(), q(v["model_id"]), q(v["sid"])))
        for s in evd.get("sdks", []):
            out.append("MERGE (a:App {package:%s}) MERGE (s:SDK {name:%s}) SET s.kind=%s MERGE (a)-[r:EMBEDS]->(s) SET r.events=%d;" % (q(pk), q(s["name"]), q(s["kind"]), s["n"]))
        for h in evd.get("hosts", []):
            out.append("MERGE (a:App {package:%s}) MERGE (h:Host {name:%s}) SET h.tracker=%s, h.ip=%s MERGE (a)-[r:CONTACTS]->(h) SET r.events=%d;" % (q(pk), q(h["host"]), str(h["tracker"]).lower(), str(h["ip"]).lower(), h["n"]))
        for cat, n in (evd.get("counts") or {}).items():
            out.append("MERGE (a:App {package:%s}) MERGE (b:Behavior {name:%s}) MERGE (a)-[r:EXHIBITS]->(b) SET r.events=%d;" % (q(pk), q(cat), n))
        for i, r in enumerate(v.get("reasons") or []):
            out.append("MERGE (a:App {package:%s}) MERGE (f:Finding {key:%s}) SET f.text=%s MERGE (a)-[:HAS_FINDING]->(f);" % (q(pk), q("%s#%d" % (pk, i)), q(r)))
    return "\n".join(out) + "\n"


def post_webhook(url, verdict, token=None, timeout=15):
    body = {k: val for k, val in verdict.items() if not k.startswith("_")}
    body["hosts"] = [h["host"] for h in (verdict.get("_evidence") or {}).get("hosts", [])][:50]
    body["sdks"] = [s["name"] for s in (verdict.get("_evidence") or {}).get("sdks", [])][:50]
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **({"X-Warden-Token": token} if token else {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status
