import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from src.static_analyzer import StaticAnalyzer

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "data", "training_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "data", "malware_model.pkl")

def generate_synthetic_dataset():
    """Generates 100 synthetic PE samples to train the Random Forest model."""
    os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
    np.random.seed(42)
    
    samples = []
    # 1. Benign files (approx 35%)
    for i in range(35):
        entropy = np.random.uniform(3.5, 5.5)
        file_size_kb = np.random.uniform(50, 2000)
        suspicious_apis = np.random.randint(0, 3)
        has_packing = 0
        has_powershell = np.random.choice([0, 1], p=[0.9, 0.1])
        has_cmd = np.random.choice([0, 1], p=[0.8, 0.2])
        has_crypto = 0
        samples.append([entropy, file_size_kb, suspicious_apis, has_packing, has_powershell, has_cmd, has_crypto, "Benign"])
        
    # 2. Ransomware files (approx 35%)
    for i in range(35):
        entropy = np.random.uniform(7.1, 7.95)
        file_size_kb = np.random.uniform(20, 500)
        suspicious_apis = np.random.randint(4, 15)
        has_packing = np.random.choice([0, 1], p=[0.3, 0.7])
        has_powershell = np.random.choice([0, 1], p=[0.4, 0.6])
        has_cmd = np.random.choice([0, 1], p=[0.3, 0.7])
        has_crypto = np.random.choice([0, 1], p=[0.05, 0.95]) # highly likely to have crypto
        samples.append([entropy, file_size_kb, suspicious_apis, has_packing, has_powershell, has_cmd, has_crypto, "Ransomware"])
        
    # 3. Trojan files (approx 30%)
    for i in range(30):
        entropy = np.random.uniform(5.8, 7.3)
        file_size_kb = np.random.uniform(100, 5000)
        suspicious_apis = np.random.randint(3, 10)
        has_packing = np.random.choice([0, 1], p=[0.6, 0.4])
        has_powershell = np.random.choice([0, 1], p=[0.2, 0.8])
        has_cmd = np.random.choice([0, 1], p=[0.2, 0.8])
        has_crypto = np.random.choice([0, 1], p=[0.7, 0.3])
        samples.append([entropy, file_size_kb, suspicious_apis, has_packing, has_powershell, has_cmd, has_crypto, "Trojan"])

    columns = [
        "entropy", "file_size_kb", "suspicious_apis_count",
        "has_packing", "has_powershell", "has_cmd", "has_crypto", "label"
    ]
    df = pd.DataFrame(samples, columns=columns)
    df.to_csv(DATASET_PATH, index=False)
    print(f"Generated synthetic training dataset with {len(df)} samples at {DATASET_PATH}")
    return df

class MalwareClassifier:
    def __init__(self):
        self.model = None
        self.feature_cols = [
            "entropy", "file_size_kb", "suspicious_apis_count",
            "has_packing", "has_powershell", "has_cmd", "has_crypto"
        ]
        
    def train(self, n_estimators=100):
        """Trains a Random Forest Classifier on the synthetic/loaded dataset."""
        if not os.path.exists(DATASET_PATH):
            df = generate_synthetic_dataset()
        else:
            df = pd.read_csv(DATASET_PATH)
            
        X = df[self.feature_cols]
        y = df["label"]
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
        
        self.model = RandomForestClassifier(n_estimators=n_estimators, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
        
        # Save model to disk
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)
            
        return {
            "accuracy": round(accuracy * 100, 2),
            "report": report,
            "y_test": y_test.tolist(),
            "y_pred": y_pred.tolist()
        }

    def load_model(self):
        """Loads the pre-trained model from disk."""
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
            return True
        return False

    def predict_file(self, file_path):
        """
        Runs static analysis on a file, extracts feature values,
        and predicts the malware family.
        """
        if not self.model:
            if not self.load_model():
                self.train()
                
        analyzer = StaticAnalyzer()
        res = analyzer.analyze_file(file_path)
        if not res:
            return None
            
        # Map static analyzer output to ML features
        entropy = res["entropy"]
        file_size_kb = res["file_size"] / 1024.0
        
        # Count APIs
        suspicious_apis_count = len(res["detected_apis"])
        
        # Flags
        has_packing = 1 if any(p["pattern"] == "packing" for p in res["suspicious_patterns"]) else 0
        has_powershell = 1 if any(p["pattern"] == "powershell" for p in res["suspicious_patterns"]) else 0
        has_cmd = 1 if any(p["pattern"] == "cmd.exe" for p in res["suspicious_patterns"]) else 0
        has_crypto = 1 if any(p["pattern"] in ["encrypt", "cryptencrypt", "bitcoin"] for p in res["suspicious_patterns"]) else 0
        
        features = pd.DataFrame([[
            entropy, file_size_kb, suspicious_apis_count,
            has_packing, has_powershell, has_cmd, has_crypto
        ]], columns=self.feature_cols)
        
        # Predict
        pred_label = self.model.predict(features)[0]
        probs = self.model.predict_proba(features)[0]
        classes = self.model.classes_
        
        prob_dict = {classes[i]: round(probs[i] * 100, 2) for i in range(len(classes))}
        confidence = prob_dict.get(pred_label, 0.0)
        
        return {
            "predicted_family": pred_label,
            "confidence": confidence,
            "probabilities": prob_dict,
            "static_details": res
        }

if __name__ == "__main__":
    clf = MalwareClassifier()
    print("Training model...")
    print(clf.train())
    print("Predicting current file...")
    print(clf.predict_file(__file__))
