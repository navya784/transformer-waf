import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from .config import CFG
from .inference import WAFDetector


def main():
    df = pd.read_csv(CFG.data_dir / "test.csv")
    det = WAFDetector()
    preds = []
    for i in range(0, len(df), 64):
        preds += [CFG.label2id[r["label"]] for r in det.predict(df.text[i:i + 64].tolist())]
    print(classification_report(df.label, preds, target_names=CFG.labels, digits=4))
    print("Confusion matrix (rows=true, cols=pred):")
    print(confusion_matrix(df.label, preds))

    # Block-level view: did we stop attacks without blocking benign traffic?
    blocked = [p != 0 for p in preds]
    attack = df.label != 0
    tpr = sum(b and a for b, a in zip(blocked, attack)) / max(attack.sum(), 1)
    fpr = sum(b and not a for b, a in zip(blocked, attack)) / max((~attack).sum(), 1)
    print(f"Attack detection rate: {tpr:.4f} | False-positive rate on benign: {fpr:.4f}")


if __name__ == "__main__":
    main()
