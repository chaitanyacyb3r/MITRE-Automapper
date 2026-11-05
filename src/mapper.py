import pandas as pd
import re
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from src.data_loader import load_data

class MitreMapper:
    def __init__(self):
        print("Loading MITRE Data...")
        self.techniques_df = load_data()
        
        print("Loading Transformer Model (all-MiniLM-L6-v2)...")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        
        self.technique_embeddings = None
        self._generate_knowledge_base()

    def _clean_text(self, text):
        if not isinstance(text, str):
            return ""
        text = re.sub(r'<[^>]+>', '', text)
        text = re.sub(r'\bv?\d+(\.\d+)+\b', '[version]', text)
        text = re.sub(r'CVE-\d{4}-\d{4,7}', 'CVE', text)
        return text.strip()

    def _generate_knowledge_base(self):
        self.techniques_df['clean_desc'] = self.techniques_df['name'] + ": " + self.techniques_df['description'].apply(self._clean_text)
        print("Encoding MITRE Knowledge Base...")
        self.technique_embeddings = self.model.encode(self.techniques_df['clean_desc'].tolist(), convert_to_tensor=True)
        if hasattr(self.technique_embeddings, 'cpu'):
             self.technique_embeddings = self.technique_embeddings.cpu().numpy()

    def map_text(self, input_text, top_k=5, threshold=0.15):
        clean_input = self._clean_text(input_text)
        input_vector = self.model.encode([clean_input])
        similarities = cosine_similarity(input_vector, self.technique_embeddings).flatten()
        top_indices = similarities.argsort()[-top_k:][::-1]
        
        results = []
        tactic_scores = {}

        for idx in top_indices:
            score = similarities[idx]
            if score >= threshold:
                technique = self.techniques_df.iloc[idx]
                results.append({
                    "id": technique['id'],
                    "name": technique['name'],
                    "score": round(score * 100, 2),
                    "description": technique['description'][:300] + "...",
                    "url": technique['url'],
                    "tactics": technique['tactics'],
                    "mitigations": technique['mitigations'] # Added Mitigations
                })
                
                for tactic in technique['tactics']:
                    tactic = tactic.replace('-', ' ').title()
                    if tactic not in tactic_scores:
                        tactic_scores[tactic] = []
                    tactic_scores[tactic].append(score)
        
        final_tactics = []
        for tactic, scores in tactic_scores.items():
            avg_score = np.mean(scores) * 100
            final_tactics.append({"name": tactic, "score": round(avg_score, 2)})
        
        final_tactics.sort(key=lambda x: x['score'], reverse=True)

        return results, final_tactics

if __name__ == "__main__":
    mapper = MitreMapper()
    test_text = "The attacker used PowerShell to execute a base64 encoded payload."
    techniques, tactics = mapper.map_text(test_text)
    print("Detected Tactics:", tactics)
