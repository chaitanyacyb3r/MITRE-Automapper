"""Small text/entropy helpers shared by several modules (kept dependency-free so tests run fast)."""
import math
import re
from collections import Counter


def clean_text(text):
    """Normalise threat text before embedding.

    What it does: strips HTML tags, ATT&CK citation markers, version numbers and CVE IDs.
    How: four regex substitutions. Masking versions/CVE IDs stops the model from matching on
    incidental tokens (e.g. "2.4.1") instead of on the described behaviour.
    Returns '' for non-string input so callers never crash on NaN/None.
    """
    if not isinstance(text, str):
        return ""
    text = re.sub(r"\(Citation: [^)]*\)", "", text)      # MITRE inline citations
    text = re.sub(r"<[^>]+>", "", text)                  # HTML tags
    text = re.sub(r"\bv?\d+(\.\d+)+\b", "[version]", text)  # 1.2.3 -> [version]
    text = re.sub(r"CVE-\d{4}-\d{4,7}", "CVE", text)     # CVE-2021-44228 -> CVE
    return text.strip()


def shannon_entropy(data):
    """Shannon entropy of a bytes-like object, in bits per byte (0.0 - 8.0).

    What it measures: how unpredictable the bytes are. H = -sum(p * log2 p) where p is each byte
    value's frequency. All-zero data -> 0; uniformly random (or well-encrypted/compressed) -> ~8.
    How: Counter() counts byte frequencies in one pass (C speed), then the formula is applied.
    """
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())
