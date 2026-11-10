"""Harder, more varied dataset: multi-field JSON/form bodies, realistic benign text.
Run:  python -m waf.generate_dataset_v2 --n 20000
"""
import argparse
import json
import random
import urllib.parse

import pandas as pd
from sklearn.model_selection import train_test_split

from .config import CFG
from .generate_dataset import HARD_BENIGN, NAMES, PATHS, SQLI, WORDS, XSS, mutate
from .preprocess import request_to_text

EXTRA_SQLI = ["' OR ''='", "1' OR '1'='1' -- ", "x' UNION SELECT 1,2,3-- ", "') UNION SELECT NULL--",
              "1; SELECT pg_sleep(5)--", "' OR 1=1 LIMIT 1 --", "admin' #", "1 AND 1=1",
              "' AND 1=0 UNION SELECT user(),database()--", "\" OR \"\"=\"", "alice' OR 'x'='x"]
EXTRA_XSS = ["<ScRiPt>alert(1)</ScRiPt>", "<img/src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
             "\" onmouseover=\"alert(1)", "<a href=javascript:alert(1)>x</a>", "<body onpageshow=alert(1)>",
             "<script src=//evil.test/x.js></script>", "<b onmouseover=alert(1)>hi</b>",
             "<textarea autofocus onfocus=alert(1)>", "<iframe src=javascript:alert(1)></iframe>"]
POOL = WORDS + ["the", "a", "great", "how", "to", "what", "is", "best", "for", "please", "thanks", "order",
                "status", "help", "delivery", "my", "new", "review", "hello", "need", "with", "about", "can", "you", "ship"]
FIELDS = ["username", "password", "email", "name", "comment", "message", "title", "address", "q",
          "search", "id", "page", "token", "city", "note"]
EXTRA_PATHS = ["/login", "/register", "/api/v1/comments", "/api/v1/orders", "/checkout", "/feedback"]
DOMAINS = ["example.com", "mail.test", "company.org", "uni.edu"]


def password(rng):
    return rng.choice(WORDS).replace(" ", "") + str(rng.randint(0, 9999)) + rng.choice(["", "!", "@", "#", "$", "*"])


def benign_value(rng):
    r = rng.random()
    if r < 0.15: return rng.choice(WORDS)
    if r < 0.30: return rng.choice(NAMES)
    if r < 0.42: return f"{rng.choice(NAMES).replace(' ', '.').replace(chr(39), '')}@{rng.choice(DOMAINS)}"
    if r < 0.57: return password(rng)
    if r < 0.75: return " ".join(rng.choice(POOL) for _ in range(rng.randint(3, 10))) + rng.choice(["", ".", "!", "?"])
    if r < 0.88: return rng.choice(HARD_BENIGN)
    return str(rng.randint(1, 100000))


def encode_body(rng, fields):
    r = rng.random()
    if r < 0.45:
        return json.dumps(fields) if rng.random() < 0.5 else json.dumps(fields, separators=(",", ":"))
    if r < 0.9:
        return "&".join(f"{k}={urllib.parse.quote_plus(v) if rng.random() < 0.5 else v}" for k, v in fields.items())
    return json.dumps({"data": fields})


def make_request(rng, bad=None):
    path = rng.choice(PATHS + EXTRA_PATHS)
    method = rng.choice(["GET", "POST", "POST", "PUT"])
    keys = rng.sample(FIELDS, rng.randint(1, 3) if method == "GET" else rng.randint(1, 4))
    vals = {k: benign_value(rng) for k in keys}
    if bad is not None:
        vals[rng.choice(keys)] = bad
    if method == "GET":
        q = "&".join(f"{k}={urllib.parse.quote_plus(v) if rng.random() < 0.5 else v}" for k, v in vals.items())
        return method, path, q, ""
    return method, path, "", encode_body(rng, vals)


def attack(rng, bank):
    payload = mutate(rng.choice(bank), rng)
    return make_request(rng, rng.choice(["", "", rng.choice(WORDS) + " "]) + payload)


def make_rows(n, seed):
    rng = random.Random(seed)
    n_ben, n_sql = int(n * 0.5), int(n * 0.25)
    rows = [(request_to_text(*make_request(rng)), 0) for _ in range(n_ben)]
    rows += [(request_to_text(*attack(rng, SQLI + EXTRA_SQLI)), 1) for _ in range(n_sql)]
    rows += [(request_to_text(*attack(rng, XSS + EXTRA_XSS)), 2) for _ in range(n - n_ben - n_sql)]
    df = pd.DataFrame(rows, columns=["text", "label"]).drop_duplicates("text")
    df["label_name"] = df["label"].map(CFG.id2label)
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20000)
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