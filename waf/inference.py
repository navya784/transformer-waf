"""Load the fine-tuned model and classify requests."""
from typing import Dict, List

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from .config import CFG
from .preprocess import request_to_text


class WAFDetector:
    def __init__(self, model_dir=CFG.model_dir, threshold: float = CFG.block_threshold, device=None):
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
        self.tok = AutoTokenizer.from_pretrained(model_dir)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir).to(self.device).eval()
        self.id2label = self.model.config.id2label
        self.threshold = threshold

    @torch.inference_mode()
    def predict(self, texts: List[str], max_len: int = CFG.max_len) -> List[Dict]:
        enc = self.tok(texts, truncation=True, max_length=max_len, padding=True,
                       return_tensors="pt").to(self.device)
        probs = torch.softmax(self.model(**enc).logits, dim=-1).cpu()
        out = []
        for p in probs:
            idx = int(p.argmax())
            malicious = float(1.0 - p[0])  # label 0 == benign
            out.append({
                "label": self.id2label[idx],
                "confidence": float(p[idx]),
                "malicious_score": malicious,
                "probs": {self.id2label[i]: float(v) for i, v in enumerate(p)},
                "blocked": malicious >= self.threshold,
            })
        return out

    def inspect(self, method: str = "GET", path: str = "", query: str = "", body: str = "") -> Dict:
        return self.predict([request_to_text(method, path, query, body)])[0]
