from torch.utils.data import Dataset


class WAFDataset(Dataset):
    """Tokenises once up front; padding is done per batch by DataCollatorWithPadding."""

    def __init__(self, texts, labels, tokenizer, max_len: int):
        self.enc = tokenizer(list(texts), truncation=True, max_length=max_len)
        self.labels = list(labels)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, i):
        item = {k: v[i] for k, v in self.enc.items()}
        item["labels"] = self.labels[i]
        return item
