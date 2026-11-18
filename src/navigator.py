"""Export results as an ATT&CK Navigator layer (the file format MITRE's own heat-map tool loads).

Why: analysts already use Navigator; a tool whose output can be dropped straight into it is
immediately usable in a real workflow (this is the interoperability idea behind STIX/ATT&CK).
"""
import json


def build_layer(techniques, name="MITRE Automapper result", description=""):
    """Build a Navigator layer (v4.5 JSON dict) from mapper/analyzer results.

    `techniques`: list of dicts with an "id" (e.g. "T1059.001") and optionally "score" (0-100)
    and "name"/"reason". How: one {techniqueID, score, comment} entry per technique; duplicate
    IDs keep the highest score; the gradient colours cells from light to red by score.
    """
    best = {}
    for t in techniques:
        tid = t.get("id")
        if not tid:
            continue
        score = float(t["score"]) if "score" in t else float(t.get("severity", 5)) * 10  # severity is 0-10, layer is 0-100
        if tid not in best or score > best[tid]["score"]:
            best[tid] = {"techniqueID": tid, "score": round(score, 2),
                         "comment": t.get("reason") or t.get("name", "")}
    return {
        "name": name, "description": description, "domain": "enterprise-attack",
        "versions": {"navigator": "5.1.0", "layer": "4.5"},
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": 100},
        "techniques": list(best.values()),
    }


def layer_to_json(layer):
    """Serialise a layer dict to a JSON string (for st.download_button or writing to disk)."""
    return json.dumps(layer, indent=2)
