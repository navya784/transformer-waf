"""Fine-tune a transformer for 3-class request classification (benign / sqli / xss)."""
import argparse
import random

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import f1_score
from torch.utils.data import DataLoader
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          DataCollatorWithPadding, get_linear_schedule_with_warmup)

from .config import CFG
from .dataset import WAFDataset


def set_seed(s):
    random.seed(s)
    np.random.seed(s)
    torch.manual_seed(s)
    torch.cuda.manual_seed_all(s)


@torch.inference_mode()
def run_eval(model, loader, device):
    model.eval()
    preds, gold = [], []
    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items()}
        logits = model(**{k: v for k, v in batch.items() if k != "labels"}).logits
        preds += logits.argmax(-1).tolist()
        gold += batch["labels"].tolist()
    return f1_score(gold, preds, average="macro"), float(np.mean(np.array(preds) == np.array(gold)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=CFG.model_name)
    ap.add_argument("--tokenizer", default=None)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--max-len", type=int, default=CFG.max_len)
    a = ap.parse_args()

    set_seed(CFG.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    tok = AutoTokenizer.from_pretrained(a.tokenizer or a.model)
    model = AutoModelForSequenceClassification.from_pretrained(
        a.model, num_labels=len(CFG.labels), id2label=CFG.id2label, label2id=CFG.label2id
    ).to(device)

    tr = pd.read_csv(CFG.data_dir / "train.csv")
    va = pd.read_csv(CFG.data_dir / "val.csv")
    collate = DataCollatorWithPadding(tok)
    tr_dl = DataLoader(WAFDataset(tr.text, tr.label, tok, a.max_len),
                       batch_size=a.batch_size, shuffle=True, collate_fn=collate)
    va_dl = DataLoader(WAFDataset(va.text, va.label, tok, a.max_len),
                       batch_size=a.batch_size * 2, collate_fn=collate)

    opt = torch.optim.AdamW(model.parameters(), lr=a.lr, weight_decay=0.01)
    total = len(tr_dl) * a.epochs
    sched = get_linear_schedule_with_warmup(opt, int(0.1 * total), total)

    best = -1.0
    for ep in range(1, a.epochs + 1):
        model.train()
        running = 0.0
        for step, batch in enumerate(tr_dl, 1):
            batch = {k: v.to(device) for k, v in batch.items()}
            loss = model(**batch).loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            running += loss.item()
            if step % 50 == 0:
                print(f"epoch {ep} step {step}/{len(tr_dl)} loss {running / step:.4f}")
        f1, acc = run_eval(model, va_dl, device)
        print(f"== epoch {ep}: val macro-F1 {f1:.4f}  acc {acc:.4f}")
        if f1 > best:
            best = f1
            CFG.model_dir.mkdir(parents=True, exist_ok=True)
            model.save_pretrained(CFG.model_dir)
            tok.save_pretrained(CFG.model_dir)
            print(f"   saved best model -> {CFG.model_dir}")


if __name__ == "__main__":
    main()
