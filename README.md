# Transformer-WAF

A web application firewall that uses a fine-tuned transformer to classify incoming HTTP requests as `benign`, `sqli` (SQL injection) or `xss` (cross-site scripting), and blocks malicious ones with a `403`.

```
request -> normalise -> transformer classifier -> allow / block (403)
```

> **Status: research prototype.** It is trained and tested on a synthetic, templated dataset. The metrics below show that the pipeline works end to end, not how it would perform on real traffic. See [Limitations](#limitations).

## Features

- **Normalisation before classification:** repeated URL and HTML-entity decoding and SQL comment stripping, so encoded payloads like `%27%20OR%201%3D1` are seen in their real form.
- **Transformer classifier:** fine-tuned BERT-small (`google/bert_uncased_L-4_H-256_A-4`), small enough to train and run on CPU.
- **Drop-in ASGI middleware** that inspects query strings and bodies and returns `403` for attacks.
- **Standalone decision API** (`/inspect`) with a small web UI for trying payloads by hand.
- **Configurable block threshold** to trade off missed attacks against false positives.
- **Tests that run without downloading a model.**

## Project structure

```
transformer-waf/
├── waf/
│   ├── config.py               # paths, model name, labels, block threshold
│   ├── preprocess.py           # URL/HTML decode loops, comment stripping, request -> text
│   ├── generate_dataset.py     # first synthetic dataset
│   ├── generate_dataset_v2.py  # improved synthetic dataset -> data/{train,val,test}.csv
│   ├── dataset.py              # torch Dataset
│   ├── train.py                # fine-tuning loop (saves best model to models/)
│   ├── evaluate.py             # classification report, confusion matrix
│   ├── inference.py            # WAFDetector: load model, predict, inspect
│   ├── middleware.py           # ASGI middleware: inspect + block with 403
│   ├── api.py                  # standalone /inspect decision API + web UI
│   └── static/                 # UI (index.html, app.js, style.css)
├── demo_app.py                 # FastAPI app protected by the middleware
├── tests/                      # pytest suite
├── data/                       # generated datasets (not committed)
├── models/                     # trained weights (not committed)
├── requirements.txt
└── .vscode/launch.json         # run/debug configs
```

## Getting started

### 1. Install

```bash
python -m venv .venv
# Windows (PowerShell): .venv\Scripts\Activate.ps1
# macOS / Linux:        source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Test

```bash
pytest -q
```

### 3. Generate data, train, evaluate

```bash
python -m waf.generate_dataset_v2 --n 20000
python -m waf.train --epochs 2 --model google/bert_uncased_L-4_H-256_A-4 --lr 1e-4
python -m waf.evaluate
```

`data/` and `models/` are not committed to git. They are rebuilt by the commands above.

### 4. Run

Decision API and UI:

```bash
uvicorn waf.api:app --port 9000
```

Then open <http://127.0.0.1:9000>.

Demo app protected by the middleware:

```bash
uvicorn demo_app:app --port 8000
```

Try it:

```bash
curl "http://localhost:8000/search?q=running+shoes"                        # 200
curl "http://localhost:8000/search?q=%27+OR+1%3D1+--"                      # 403 (sqli)
curl "http://localhost:8000/search?q=%3Cscript%3Ealert(1)%3C/script%3E"    # 403 (xss)
```

## Results

Trained for 2 epochs on 13,977 samples, evaluated on a 2,996-sample test split from the same generator.

| Class  | Precision | Recall | F1     | Support |
|--------|-----------|--------|--------|---------|
| benign | 1.0000    | 1.0000 | 1.0000 | 1498    |
| sqli   | 1.0000    | 1.0000 | 1.0000 | 750     |
| xss    | 1.0000    | 1.0000 | 1.0000 | 748     |

A perfect score on templated data is a sign that the dataset is easy, **not** that the model is perfect. The training and test sets share the same attack templates, so the model can succeed by recognising the templates. Do not read this table as real-world accuracy.

## Limitations

- **Synthetic data only.** The model has not been evaluated on attacks written independently of the generator, such as heavily obfuscated payloads, or on real production traffic.
- **Two attack classes.** Path traversal, SSRF, command injection and others are not detected.
- **Request coverage.** Only the fields converted by `request_to_text` are inspected. Headers and cookies are not covered by default.
- **Not a substitute for secure coding.** Keep parameterised queries, output encoding and a Content Security Policy in the application itself. Treat this as one extra layer.
- **Evasion.** No adversarial testing has been done.

## Configuration

Settings are in `waf/config.py`. The main one is `block_threshold`. Lower values block more requests (higher attack recall, more false positives), and higher values block fewer.

## Roadmap

- Evaluate on a held-out set of hand-written and externally sourced payloads (for example CSIC 2010 or public payload lists), and compare against regex-rule and TF-IDF baselines.
- Split train and test by attack family or template so test attacks are never seen in training.
- Add header and cookie fields to `request_to_text`.
- Add more classes (path traversal, SSRF, command injection).
- Evasion and adversarial augmentation.
- ONNX export for faster CPU inference.
- Logging of blocked and borderline requests, with a review queue.

## Author

Navya Agrawal ([@navya784](https://github.com/navya784))
