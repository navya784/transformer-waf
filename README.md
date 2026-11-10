# Transformer-based WAF

End-to-end pipeline: **request -> normalise -> transformer classifier -> allow / block (403)**.
Classes: `benign`, `sqli`, `xss`.

## Structure
```
transformer-waf/
├── waf/
│   ├── config.py            # paths, model name, labels, block threshold
│   ├── preprocess.py        # URL/HTML decode loops, comment stripping, request -> text
│   ├── generate_dataset.py  # synthetic bootstrap dataset -> data/{train,val,test}.csv
│   ├── dataset.py           # torch Dataset
│   ├── train.py             # fine-tuning loop (saves best model to models/)
│   ├── evaluate.py          # report, confusion matrix, attack-detection / FPR
│   ├── inference.py         # WAFDetector (load model, predict, inspect)
│   ├── middleware.py        # ASGI middleware: inspect + block with 403
│   └── api.py               # standalone /inspect decision API
├── demo_app.py              # FastAPI app protected by the middleware
├── tests/                   # pytest (no model download needed)
├── data/  models/           # generated artifacts
└── .vscode/launch.json      # one-click run/debug configs
```

## Run it
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

pytest -q                                   # sanity tests
python -m waf.generate_dataset --n 12000    # 1. data
python -m waf.train --epochs 3              # 2. train  (add --model prajjwal1/bert-tiny for fast CPU runs)
python -m waf.evaluate                      # 3. evaluate
uvicorn demo_app:app --port 8000            # 4. serve protected app
```

Try it:
```bash
curl "http://localhost:8000/search?q=running+shoes"            # 200
curl "http://localhost:8000/search?q=%27+OR+1%3D1+--"          # 403 (sqli)
curl "http://localhost:8000/search?q=%3Cscript%3Ealert(1)%3C/script%3E"   # 403 (xss)
curl -X POST localhost:8000/login -H "Content-Type: application/json" -d '{"username":"admin'"'"'--","password":"x"}'
```

## Important caveats
- The synthetic dataset is templated, so metrics will look near-perfect. That is **not** real-world
  performance. Add real data (CSIC 2010, your own labelled logs, public payload lists) in the same
  `text,label,label_name` schema and retrain.
- Tune `block_threshold` in `waf/config.py`: lower catches more attacks, raises false positives.
- Treat the model as one layer. Keep parameterised queries, output encoding and CSP in the app itself.
- Ideas to extend: add header/cookie fields to `request_to_text`, more classes (path traversal, SSRF, command
  injection), ONNX export for speed, adversarial/evasion augmentation, drift monitoring and a
  human-review queue for borderline scores.
