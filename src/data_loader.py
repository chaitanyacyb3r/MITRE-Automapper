import requests
import json
import os
import pandas as pd

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "enterprise-attack.json")

def download_mitre_data():
    """Downloads the MITRE Enterprise ATT&CK JSON if it doesn't exist."""
    if not os.path.exists(os.path.dirname(DATA_PATH)):
        os.makedirs(os.path.dirname(DATA_PATH))

    if not os.path.exists(DATA_PATH):
        print(f"Downloading MITRE ATT&CK data from {MITRE_URL}...")
        response = requests.get(MITRE_URL)
        response.raise_for_status()
        with open(DATA_PATH, "w", encoding='utf-8') as f:
            f.write(response.text)
        print("Download complete.")
    else:
        print("MITRE ATT&CK data already exists.")

def load_data():
    """
    Parses the MITRE JSON and returns a DataFrame of Techniques with Mitigations.
    """
    if not os.path.exists(DATA_PATH):
        download_mitre_data()
    
    with open(DATA_PATH, "r", encoding='utf-8') as f:
        data = json.load(f)
    
    objects = data.get("objects", [])
    
    # 1. Map Mitigations (Course of Action) to Techniques (Relationships)
    # Relationship type: "mitigates" -> source_ref (Mitigation) mitigates target_ref (Technique)
    mitigation_map = {} # Technique ID -> List of Mitigation Names
    mitigations = {obj['id']: obj for obj in objects if obj['type'] == 'course-of-action'}
    
    for obj in objects:
        if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates':
            tech_id = obj.get('target_ref')
            mitigation_id = obj.get('source_ref')
            
            if tech_id and mitigation_id and mitigation_id in mitigations:
                mitigation_name = mitigations[mitigation_id].get('name')
                mitigation_desc = mitigations[mitigation_id].get('description')
                
                if tech_id not in mitigation_map:
                    mitigation_map[tech_id] = []
                mitigation_map[tech_id].append(f"**{mitigation_name}**: {mitigation_desc}")

    # 2. Parse Techniques
    techniques = []
    for obj in objects:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            # Internal ID used for relationships
            internal_id = obj.get('id')
            
            # Extract external ID (e.g., T1059)
            external_references = obj.get("external_references", [])
            mitre_id = next((ref["external_id"] for ref in external_references if ref.get("source_name") == "mitre-attack"), None)
            url = next((ref["url"] for ref in external_references if ref.get("source_name") == "mitre-attack"), "")
            
            # Extract Tactics
            kill_chain_phases = obj.get("kill_chain_phases", [])
            tactics = [phase["phase_name"] for phase in kill_chain_phases if phase.get("kill_chain_name") == "mitre-attack"]
            
            # Get Mitigations for this technique
            tech_mitigations = mitigation_map.get(internal_id, ["No specific mitigation listed in MITRE data."])
            
            if mitre_id:
                techniques.append({
                    "id": mitre_id,
                    "name": obj.get("name", "Unknown"),
                    "description": obj.get("description", ""),
                    "url": url,
                    "tactics": tactics,
                    "mitigations": tech_mitigations
                })
    
    return pd.DataFrame(techniques)

if __name__ == "__main__":
    download_mitre_data()
    df = load_data()
    print(f"Loaded {len(df)} techniques.")
    # Show sample mitigations
    sample = df[df['mitigations'].apply(len) > 1].iloc[0]
    print(f"Technique: {sample['name']}")
    print(f"Mitigations: {sample['mitigations'][:1]}")
