# MITRE ATT&CK Automapper & SOC Assistant (prototype)

Maps threat text, CVEs and files to **MITRE ATT&CK** techniques, attaches MITRE mitigations,
watches a folder for ransomware-like behaviour, and exports results to **ATT&CK Navigator**.
Inspired by Branescu et al. (CVE -> ATT&CK tactics) and CTID's TRAM. Status: **learning prototype**.

## Features
| Module | What it does | How |
|---|---|---|
| `src/mapper.py` | text/CVE -> top-k techniques | Sentence-BERT (`all-MiniLM-L6-v2`) + cosine similarity against ATT&CK technique descriptions (zero-shot, not fine-tuned) |
| `src/data_loader.py` | loads ATT&CK (STIX 2.x JSON) + mitigations | follows `relationship_type == "mitigates"` links |
| `src/static_analyzer.py` | PE/file triage | hashes, Shannon entropy, strings, PE imports/sections, 12 ATT&CK-tagged signatures, injection-API triad |
| `src/agent_alerts.py` | **RansomGuard** | real `watchdog` events + measured entropy jump + ransomware extension + distinct-file volume in a sliding window; safe simulator for demos |
| `src/navigator.py` | export | ATT&CK Navigator layer JSON (download button in CVE tab) |
| `src/evaluate.py` | benchmark | text->technique ranking on ~17k MITRE `uses` procedure examples |
| `src/ml_classifier.py` | Random Forest | trained on **synthetic** data; model file is SHA-256 verified before unpickling (CWE-502) |

## Run
```bash
pip install -r requirements.txt
streamlit run app.py          # UI
pytest -q                     # 9 tests (entropy, detector, e2e RansomGuard, signature-ID validity...)
python -m src.agent_alerts    # RansomGuard demo in a temp folder
python -m src.evaluate --method tfidf --n 1000
python -m src.evaluate --method sbert --n 1000   # needs model download; writes results/benchmark.json
```

## Benchmark (n=1000 sampled MITRE procedure examples, seed 42)
| Method | Top-1 | Top-5 | MRR |
|---|---|---|---|
| TF-IDF baseline | 23.9% | 46.5% | 0.348 |
| Sentence-BERT (this tool) | *run the command above and paste your number* | | |

Both text sets come from MITRE, so treat numbers as a way to **compare methods**, not as production accuracy.

## Limitations (honest)
* Random Forest uses 100 synthetic rows; its accuracy is a pipeline check only. Next: EMBER / MalwareBazaar data.
* Signatures are substring matches (false positives/negatives); evasion via packing or dynamic API resolution defeats them. Next: YARA / Capa.
* RansomGuard samples the first 64 KB, runs in user space (watchdog), and was validated only against its own simulator, not real ransomware. Production EDR uses kernel telemetry (ETW/minifilter).
* Mapper is zero-shot; fine-tuning a security model (SecBERT) on labelled CVE->tactic data is the planned upgrade.
