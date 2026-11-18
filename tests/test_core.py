"""Automated tests. Run: pytest -q   (the SBERT-dependent mapper is not imported, so no model download)."""
import json, os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.textutils import shannon_entropy, clean_text
from src.static_analyzer import StaticAnalyzer
from src.agent_alerts import RansomDetector, RansomGuard, RansomSimulator
from src.navigator import build_layer
from src.evaluate import rank_metrics
from src.data_loader import DATA_PATH
import numpy as np


def test_entropy_bounds():
    """All-same bytes -> 0 bits; all 256 byte values equally often -> exactly 8 bits."""
    assert shannon_entropy(b"\x00" * 1000) == 0
    assert abs(shannon_entropy(bytes(range(256)) * 10) - 8.0) < 1e-9


def test_clean_text_masks_cve_version_citation():
    """Cleaner removes noise tokens the embedding model should not key on."""
    out = clean_text("Exploits CVE-2021-44228 in v2.14.1 (Citation: Foo 2021) <b>x</b>")
    assert "44228" not in out and "2.14" not in out and "Citation" not in out and "<b>" not in out


def test_every_signature_id_exists_in_mitre_data():
    """Guards against wrong technique IDs (the T1497-vs-T1622 bug this suite found)."""
    ids = set()
    for o in json.load(open(DATA_PATH, encoding="utf-8"))["objects"]:
        if o["type"] == "attack-pattern":
            ids |= {r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"}
    for key, sig in StaticAnalyzer().signatures.items():
        assert sig["id"] in ids, (key, sig["id"])


def test_static_analyzer_flags_ransomware_sample_and_passes_benign(tmp_path):
    """Synthetic sample with ransom strings scores high; plain text scores low."""
    bad = tmp_path / "bad.exe"; bad.write_bytes(b"MZ" + b"CryptEncrypt vssadmin delete shadows bitcoin ransom " + os.urandom(3000))
    good = tmp_path / "good.txt"; good.write_text("hello world " * 100)
    a = StaticAnalyzer()
    assert a.analyze_file(str(bad))["threat_score"] >= 7.5
    assert a.analyze_file(str(good))["classification"] == "Benign"


def test_detector_ignores_compressed_file_but_flags_entropy_jump():
    """False-positive control: a new .zip is fine; a .txt that jumps 4.0 -> 7.9 is suspicious."""
    d = RansomDetector()
    assert d.process("/x/a.zip", "Created", 7.99, now=1)["severity"] == "INFO"
    d.learn_baseline("/x/b.txt", 4.0)
    assert d.process("/x/b.txt", "Modified", 7.9, now=2)["severity"] == "WARNING"


def test_detector_critical_needs_volume_in_window():
    """5 distinct suspicious files in 5s -> CRITICAL; the same files spread over minutes -> never."""
    d = RansomDetector()
    sev = [d.process("/x/f%d.locked" % i, "Renamed", 7.9, now=i * 0.1)["severity"] for i in range(5)]
    assert sev[-1] == "CRITICAL"
    d2 = RansomDetector()
    assert all(d2.process("/x/f%d.locked" % i, "Renamed", 7.9, now=i * 60)["severity"] != "CRITICAL" for i in range(5))


def test_guard_end_to_end_on_real_files():
    """Real watchdog + real files: benign phase raises no CRITICAL, attack phase does."""
    d = tempfile.mkdtemp(prefix="rg_test_")
    sim = RansomSimulator(d, n_files=25, benign_seconds=1.5, delay=0.02)
    sim.create_victim_files()
    g = RansomGuard(d); alerts = []
    g.start_monitoring(alerts.append)
    sim.start(); sim.finished.wait(20); time.sleep(1); g.stop_monitoring(); sim.cleanup()
    crit = [a for a in alerts if a["severity"] == "CRITICAL"]
    assert crit, "attack phase should trigger CRITICAL"
    first_attack = min(i for i, a in enumerate(alerts) if a["severity"] != "INFO")
    assert all(a["severity"] == "INFO" for a in alerts[:first_attack])  # benign edits stayed quiet


def test_navigator_layer_dedupes_and_scales():
    """Duplicate technique keeps max score; severity (0-10) is rescaled to 0-100."""
    layer = build_layer([{"id": "T1486", "severity": 9.0}, {"id": "T1486", "severity": 4.0}, {"id": "T1059.001", "score": 70}])
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores == {"T1486": 90.0, "T1059.001": 70.0}


def test_rank_metrics_perfect_and_worst():
    """Sanity-check the benchmark maths on a tiny hand-made matrix."""
    sim = np.array([[0.9, 0.1], [0.2, 0.8]])
    assert rank_metrics(sim, ["A", "B"], ["A", "B"])["top1"] == 100.0
    assert rank_metrics(sim, ["B", "A"], ["A", "B"])["top1"] == 0.0
