import hashlib
import math
import re
import os

try:
    import pefile
except ImportError:
    pefile = None

class StaticAnalyzer:
    def __init__(self):
        # Maps patterns/APIs to MITRE ATT&CK techniques and severity
        self.signatures = {
            "powershell": {
                "id": "T1059.001",
                "name": "PowerShell Execution",
                "tactic": "Execution",
                "description": "Execution of commands or scripts using PowerShell.",
                "url": "https://attack.mitre.org/techniques/T1059/001/",
                "severity": 7.0,
                "pattern_desc": "PowerShell execution string found."
            },
            "cmd.exe": {
                "id": "T1059.003",
                "name": "Windows Command Shell",
                "tactic": "Execution",
                "description": "Execution of commands using cmd.exe.",
                "url": "https://attack.mitre.org/techniques/T1059/003/",
                "severity": 5.0,
                "pattern_desc": "Command shell invocation string found."
            },
            "mimikatz": {
                "id": "T1003",
                "name": "OS Credential Dumping",
                "tactic": "Credential Access",
                "description": "Dumping memory credentials using tools like Mimikatz.",
                "url": "https://attack.mitre.org/techniques/T1003/",
                "severity": 9.5,
                "pattern_desc": "Mimikatz credential dumping signature detected."
            },
            "encrypt": {
                "id": "T1486",
                "name": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": "Encryption of files to deny access to user data.",
                "url": "https://attack.mitre.org/techniques/T1486/",
                "severity": 9.0,
                "pattern_desc": "File encryption keywords or capability detected."
            },
            "cryptencrypt": {
                "id": "T1486",
                "name": "Data Encrypted for Impact (CryptEncrypt API)",
                "tactic": "Impact",
                "description": "Calling encryption APIs to encrypt local data.",
                "url": "https://attack.mitre.org/techniques/T1486/",
                "severity": 9.0,
                "pattern_desc": "CryptEncrypt API import detected."
            },
            "virtualallocex": {
                "id": "T1055",
                "name": "Process Injection",
                "tactic": "Defense Evasion / Privilege Escalation",
                "description": "Injecting code into another process space using VirtualAllocEx.",
                "url": "https://attack.mitre.org/techniques/T1055/",
                "severity": 8.0,
                "pattern_desc": "VirtualAllocEx API import detected (Process Injection)."
            },
            "isdebuggerpresent": {
                "id": "T1497",
                "name": "Sandbox Evasion",
                "tactic": "Defense Evasion",
                "description": "Checking for debugger presence to evade analysis.",
                "url": "https://attack.mitre.org/techniques/T1497/",
                "severity": 6.0,
                "pattern_desc": "IsDebuggerPresent API import detected (Anti-Debugging)."
            },
            "bitcoin": {
                "id": "T1486",
                "name": "Data Encrypted for Impact (Crypto Ransom)",
                "tactic": "Impact",
                "description": "References to cryptocurrency wallets or bitcoin addresses.",
                "url": "https://attack.mitre.org/techniques/T1486/",
                "severity": 4.0,
                "pattern_desc": "Cryptocurrency (Bitcoin) wallet/address reference found."
            },
            "ransom": {
                "id": "T1486",
                "name": "Data Encrypted for Impact (Ransom Demand)",
                "tactic": "Impact",
                "description": "Ransom notes or payment demand keywords.",
                "url": "https://attack.mitre.org/techniques/T1486/",
                "severity": 8.5,
                "pattern_desc": "Ransomware warning or demand keyword detected."
            },
            "shellexecute": {
                "id": "T1204",
                "name": "User Execution",
                "tactic": "Execution",
                "description": "Execution of payload or application via ShellExecute.",
                "url": "https://attack.mitre.org/techniques/T1204/",
                "severity": 5.0,
                "pattern_desc": "ShellExecute API import detected."
            },
            "debugger": {
                "id": "T1497",
                "name": "Sandbox Evasion (Debugger)",
                "tactic": "Defense Evasion",
                "description": "Generic debugger detection checks.",
                "url": "https://attack.mitre.org/techniques/T1497/",
                "severity": 6.0,
                "pattern_desc": "Debugger references or anti-analysis patterns."
            }
        }

    def calculate_entropy(self, data):
        """Calculates Shannon Entropy of binary data."""
        if not data:
            return 0.0
        entropy = 0
        length = len(data)
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 2)

    def analyze_file(self, file_path):
        """
        Parses a file (PE or otherwise), extracts hashes, entropy,
        sections, suspicious imports, and maps patterns to MITRE.
        """
        if not os.path.exists(file_path):
            return None

        # 1. Read file bytes
        with open(file_path, "rb") as f:
            data = f.read()

        file_size = len(data)
        entropy = self.calculate_entropy(data)
        md5_hash = hashlib.md5(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        # 2. Extract ASCII/Unicode strings (simple string scanner)
        ascii_strings = re.findall(b"[a-zA-Z0-9_/\\.\\-]{4,}", data)
        strings_found = [s.decode('utf-8', errors='ignore') for s in ascii_strings]
        strings_text = " ".join(strings_found).lower()

        suspicious_patterns = []
        mapped_techniques = {}
        detected_apis = []

        # Scan for string signatures
        for sig_key, sig_val in self.signatures.items():
            if sig_key in strings_text:
                suspicious_patterns.append({
                    "pattern": sig_key,
                    "description": sig_val["pattern_desc"],
                    "severity": sig_val["severity"]
                })
                tech_id = sig_val["id"]
                if tech_id not in mapped_techniques:
                    mapped_techniques[tech_id] = {
                        "id": tech_id,
                        "name": sig_val["name"],
                        "tactic": sig_val["tactic"],
                        "severity": sig_val["severity"],
                        "reason": sig_val["pattern_desc"],
                        "url": sig_val["url"]
                    }
                else:
                    # Keep the higher severity
                    if sig_val["severity"] > mapped_techniques[tech_id]["severity"]:
                        mapped_techniques[tech_id]["severity"] = sig_val["severity"]
                        mapped_techniques[tech_id]["reason"] = sig_val["pattern_desc"]

        # 3. PE parsing (if applicable)
        is_pe = False
        pe_sections = []
        packing_detected = False

        if pefile is not None:
            try:
                pe = pefile.PE(file_path)
                is_pe = True
                
                # Check sections
                for section in pe.sections:
                    sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    sec_entropy = self.calculate_entropy(section.get_data())
                    pe_sections.append({
                        "name": sec_name,
                        "virtual_size": hex(section.Misc_VirtualSize),
                        "raw_size": hex(section.SizeOfRawData),
                        "entropy": sec_entropy
                    })
                    # High section entropy is a sign of packing/encryption
                    if sec_entropy > 7.4:
                        packing_detected = True

                # Check imports
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                imp_name = imp.name.decode('utf-8', errors='ignore')
                                detected_apis.append(imp_name)
                                imp_name_lower = imp_name.lower()
                                if imp_name_lower in self.signatures:
                                    sig_val = self.signatures[imp_name_lower]
                                    tech_id = sig_val["id"]
                                    if tech_id not in mapped_techniques:
                                        mapped_techniques[tech_id] = {
                                            "id": tech_id,
                                            "name": sig_val["name"],
                                            "tactic": sig_val["tactic"],
                                            "severity": sig_val["severity"],
                                            "reason": f"Imported API '{imp_name}'",
                                            "url": sig_val["url"]
                                        }

            except Exception as e:
                # Not a valid PE or error parsing
                pass

        # If packing detected in sections, flag it
        if packing_detected:
            suspicious_patterns.append({
                "pattern": "packing",
                "description": "High section entropy suggests packed/encrypted binary.",
                "severity": 8.0
            })

        # Calculate dynamic Threat Score (0 to 10 scale)
        if mapped_techniques:
            # Base score on average severity of mapped techniques plus entropy penalty
            base_score = sum(t["severity"] for t in mapped_techniques.values()) / len(mapped_techniques)
            # Add entropy contribution if entropy is high
            entropy_penalty = max(0, (entropy - 5.0) * 0.6) # max +1.8
            threat_score = min(10.0, round(base_score + entropy_penalty, 1))
        else:
            # Fallback to entropy and size
            if entropy > 7.0:
                threat_score = 6.5
            elif entropy > 6.0:
                threat_score = 4.0
            else:
                threat_score = 1.0

        # Classify based on signature match and threat score
        classification = "Benign"
        if threat_score >= 7.5:
            classification = "Ransomware" if ("encrypt" in strings_text or "ransom" in strings_text) else "Trojan"
        elif threat_score >= 4.0:
            classification = "Suspicious"
            
        return {
            "file_name": os.path.basename(file_path),
            "file_size": file_size,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "entropy": entropy,
            "is_pe": is_pe,
            "pe_sections": pe_sections,
            "detected_apis": list(set(detected_apis))[:20], # limit list
            "suspicious_patterns": suspicious_patterns,
            "mapped_techniques": list(mapped_techniques.values()),
            "threat_score": threat_score,
            "classification": classification
        }

if __name__ == "__main__":
    analyzer = StaticAnalyzer()
    # Simple self test
    test_file = __file__
    print(analyzer.analyze_file(test_file))
