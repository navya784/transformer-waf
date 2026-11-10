"""Demo site protected by the transformer WAF.
Run: uvicorn demo_app:app --reload --port 8000"""
import logging

from fastapi import FastAPI

from waf.inference import WAFDetector
from waf.middleware import WAFMiddleware

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Protected demo app")
app.add_middleware(WAFMiddleware, detector=WAFDetector())


@app.get("/")
def index():
    return {"message": "hello from the protected app"}


@app.get("/search")
def search(q: str = ""):
    return {"query": q, "results": []}


@app.post("/login")
def login(data: dict):
    return {"ok": True, "user": data.get("username")}
