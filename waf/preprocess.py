"""Request normalisation: undo common obfuscation before the model sees the text."""
import html
import re
import urllib.parse

_SQL_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_WS = re.compile(r"\s+")


def normalize(text: str, max_rounds: int = 3) -> str:
    """Iteratively URL-decode + HTML-unescape (defeats double encoding),
    then strip null bytes / inline SQL comments and collapse whitespace."""
    cur = text or ""
    for _ in range(max_rounds):
        nxt = html.unescape(urllib.parse.unquote_plus(cur))
        if nxt == cur:
            break
        cur = nxt
    cur = cur.replace("\x00", "")
    cur = _SQL_COMMENT.sub(" ", cur)
    return _WS.sub(" ", cur).strip()


def request_to_text(method: str = "GET", path: str = "", query: str = "", body: str = "") -> str:
    """Flatten an HTTP request into one string. Used identically at train and inference time."""
    parts = [
        f"[METHOD] {method.upper()}",
        f"[PATH] {normalize(path)}",
        f"[QUERY] {normalize(query)}",
        f"[BODY] {normalize(body)}",
    ]
    return " ".join(parts)
