"""WAF dashboard + inspection API.
Run:  uvicorn waf.api:app --port 9000      then open http://127.0.0.1:9000
"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .inference import WAFDetector
from .preprocess import request_to_text

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="Transformer WAF")
app.mount("/static", StaticFiles(directory=STATIC), name="static")
detector = WAFDetector()


class InspectRequest(BaseModel):
    method: str = "GET"
    path: str = ""
    query: str = ""
    body: str = ""


@app.get("/")
def dashboard():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/inspect")
def inspect(req: InspectRequest):
    res = detector.inspect(req.method, req.path, req.query, req.body)
    res["model_input"] = request_to_text(req.method, req.path, req.query, req.body)
    return res