"""Middleware test with a fake detector, so no model download is needed."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from waf.middleware import WAFMiddleware


class FakeDetector:
    def inspect(self, method, path, query, body):
        bad = "<script" in (query + body).lower() or "union select" in (query + body).lower()
        return {"blocked": bad, "label": "xss" if bad else "benign", "malicious_score": 0.99 if bad else 0.01}


def make_client():
    app = FastAPI()
    app.add_middleware(WAFMiddleware, detector=FakeDetector())

    @app.get("/s")
    def s(q: str = ""):
        return {"q": q}

    @app.post("/p")
    def p(d: dict):
        return d

    return TestClient(app)


def test_allows_benign_and_replays_body():
    c = make_client()
    assert c.get("/s", params={"q": "shoes"}).status_code == 200
    assert c.post("/p", json={"a": 1}).json() == {"a": 1}


def test_blocks_attack():
    c = make_client()
    assert c.get("/s", params={"q": "<script>alert(1)</script>"}).status_code == 403
