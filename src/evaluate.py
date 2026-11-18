"""Benchmark: how well does text -> ATT&CK technique mapping actually work?

Ground truth (no manual labelling): MITRE's own STIX data contains ~17k `uses` relationships
such as "Group APT29 uses T1059.001: <free-text procedure example>". We treat that free text as
the INPUT and the technique ID as the CORRECT LABEL, then ask each method to rank all techniques
using only the technique *definitions* (name + description) - exactly what the mapper does.
This is the same task TRAM (CTID) solves with a fine-tuned model, so numbers are comparable in kind.

Methods: 'tfidf' (classic keyword baseline) and 'sbert' (your Sentence-BERT mapper).
Run:  python -m src.evaluate --method tfidf --n 1000
      python -m src.evaluate --method sbert --n 1000      (needs sentence-transformers + model download)
Caveat: procedure text and technique definitions both come from MITRE, so absolute numbers are
optimistic vs. messy real-world reports; use it to COMPARE methods, not as a production accuracy.
"""
import argparse
import json
import os
import random

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from src.data_loader import DATA_PATH, load_data
from src.textutils import clean_text

RESULTS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results", "benchmark.json")


def build_eval_set(n=1000, seed=42, min_chars=60):
    """Return up to `n` (text, technique_id) pairs sampled from STIX 'uses' relationships.

    How: map every attack-pattern's internal id -> T-number; keep `uses` relationships whose
    target is a (non-revoked) technique and whose description is long enough to be meaningful;
    strip citation markers; sample reproducibly with `seed`.
    """
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        objs = json.load(f)["objects"]
    tid = {}
    for o in objs:
        if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            for r in o.get("external_references", []):
                if r.get("source_name") == "mitre-attack":
                    tid[o["id"]] = r["external_id"]
    pairs = []
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "uses" and o.get("target_ref") in tid:
            text = clean_text(o.get("description", ""))
            if len(text) >= min_chars:
                pairs.append((text, tid[o["target_ref"]]))
    random.Random(seed).shuffle(pairs)
    return pairs[:n]


def rank_metrics(sim, labels, ids):
    """Compute top-1, top-5 accuracy and MRR from a (samples x techniques) similarity matrix.

    How: for each row, sort technique indices by similarity (desc); the rank of the true
    technique gives top-k hits and reciprocal rank (MRR = mean of 1/rank).
    """
    idx = {t: i for i, t in enumerate(ids)}
    top1 = top5 = rr = 0.0
    for row, lab in zip(sim, labels):
        order = np.argsort(-row)
        rank = int(np.where(order == idx[lab])[0][0]) + 1
        top1 += rank == 1
        top5 += rank <= 5
        rr += 1.0 / rank
    n = len(labels)
    return {"top1": round(100 * top1 / n, 2), "top5": round(100 * top5 / n, 2), "mrr": round(rr / n, 4), "n": n}


def evaluate(method="tfidf", n=1000, seed=42):
    """Run one method on the sampled eval set and return its metrics dict."""
    df = load_data()
    docs = (df["name"] + ": " + df["description"].apply(clean_text)).tolist()
    ids = df["id"].tolist()
    texts, labels = zip(*build_eval_set(n, seed))
    labels = [l for l in labels]
    keep = [i for i, l in enumerate(labels) if l in set(ids)]
    texts, labels = [texts[i] for i in keep], [labels[i] for i in keep]
    if method == "tfidf":
        vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
        d = vec.fit_transform(docs)
        sim = cosine_similarity(vec.transform(texts), d)
    elif method == "sbert":
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("all-MiniLM-L6-v2")
        sim = cosine_similarity(model.encode(list(texts)), model.encode(docs))
    else:
        raise ValueError("method must be 'tfidf' or 'sbert'")
    res = rank_metrics(sim, labels, ids)
    res["method"] = method
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--method", default="tfidf", choices=["tfidf", "sbert"])
    ap.add_argument("--n", type=int, default=1000)
    a = ap.parse_args()
    r = evaluate(a.method, a.n)
    print(r)
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    old = json.load(open(RESULTS_PATH)) if os.path.exists(RESULTS_PATH) else {}
    old[a.method] = r
    json.dump(old, open(RESULTS_PATH, "w"), indent=2)
