from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Config:
    data_dir: Path = ROOT / "data"
    model_dir: Path = ROOT / "models" / "waf-transformer"
    # Swap for "prajjwal1/bert-tiny" (fast on CPU) or "microsoft/deberta-v3-small" (stronger).
    model_name: str = "distilbert-base-uncased"
    max_len: int = 128
    labels: list = field(default_factory=lambda: ["benign", "sqli", "xss"])
    # Block when P(malicious) = 1 - P(benign) >= threshold. Lower = stricter.
    block_threshold: float = 0.5
    seed: int = 42

    @property
    def label2id(self):
        return {l: i for i, l in enumerate(self.labels)}

    @property
    def id2label(self):
        return {i: l for i, l in enumerate(self.labels)}


CFG = Config()
