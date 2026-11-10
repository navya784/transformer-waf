"""Pure-ASGI WAF middleware (works with FastAPI/Starlette). Buffers the body, inspects it,
then either returns 403 or replays the body to the downstream app."""
import json
import logging
from urllib.parse import unquote

from starlette.concurrency import run_in_threadpool

log = logging.getLogger("waf")


class WAFMiddleware:
    def __init__(self, app, detector, max_body: int = 1_000_000, fail_open: bool = True):
        self.app = app
        self.detector = detector
        self.max_body = max_body
        self.fail_open = fail_open  # if the model errors: True = allow, False = block

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        body, more = b"", True
        while more:
            msg = await receive()
            if msg["type"] == "http.request":
                body += msg.get("body", b"")
                more = msg.get("more_body", False)
            else:  # client disconnected
                break

        try:
            res = await run_in_threadpool(
                self.detector.inspect,
                scope["method"],
                unquote(scope["path"]),
                scope.get("query_string", b"").decode("latin-1"),
                body[: self.max_body].decode("utf-8", errors="replace"),
            )
        except Exception:  # noqa: BLE001
            log.exception("WAF inference failed")
            res = {"blocked": not self.fail_open, "label": "error", "malicious_score": 0.0}

        if res["blocked"]:
            log.warning("BLOCKED %s %s -> %s (%.3f)", scope["method"], scope["path"],
                        res["label"], res["malicious_score"])
            payload = json.dumps({"error": "Request blocked by WAF", "category": res["label"],
                                  "score": round(res["malicious_score"], 4)}).encode()
            await send({"type": "http.response.start", "status": 403,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"content-length", str(len(payload)).encode())]})
            await send({"type": "http.response.body", "body": payload})
            return

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
