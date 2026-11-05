import os
import random
import shutil

def create_samples():
    # Create test_samples directory
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test_samples")
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Generate Benign Sample
    # We can copy notepad.exe from Windows system folder if it exists, otherwise write a simple dummy PE-like file
    benign_path = os.path.join(output_dir, "calc_benign.exe")
    system_calc = r"C:\Windows\System32\calc.exe"
    if os.path.exists(system_calc):
        try:
            shutil.copy(system_calc, benign_path)
            print(f"Created benign sample by copying system calculator to: {benign_path}")
        except Exception as e:
            write_dummy_pe(benign_path, is_malicious=False)
    else:
        write_dummy_pe(benign_path, is_malicious=False)
        
    # 2. Generate Malicious/Suspicious Sample
    malicious_path = os.path.join(output_dir, "ransomware_suspicious.exe")
    write_dummy_pe(malicious_path, is_malicious=True)
    print(f"Created mock malicious/suspicious sample at: {malicious_path}")

def write_dummy_pe(file_path, is_malicious=False):
    # Standard DOS MZ Header
    data = bytearray(b"MZ" + b"\x00" * 58 + b"\x00\x00\x00\x00")
    
    # PE Header marker
    data += b"PE\x00\x00"
    
    # Some mock binary padding
    data += bytearray(random.getrandbits(8) for _ in range(500))
    
    if is_malicious:
        # Inject malicious strings and API names to be picked up by the static analyzer signatures
        malicious_strings = [
            b"powershell -ExecutionPolicy Bypass -File payload.ps1",
            b"cmd.exe /c start /B malicious_runner.exe",
            b"mimikatz_credentials_dump",
            b"CryptEncrypt",
            b"VirtualAllocEx",
            b"IsDebuggerPresent",
            b"ShellExecute",
            b"bitcoin_wallet_address_1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            b"Your files have been encrypted! Send ransom payment to restore access."
        ]
        for s in malicious_strings:
            data += s + b"\x00"
            
        # Add high entropy random bytes to simulate encryption/packing
        data += bytearray(random.getrandbits(8) for _ in range(2000))
    else:
        # Safe/clean strings
        clean_strings = [
            b"This is a benign test application.",
            b"Copyright (C) Microsoft Corporation. All rights reserved.",
            b"InitializeComponent",
            b"System.Windows.Forms"
        ]
        for s in clean_strings:
            data += s + b"\x00"
            
        # Add low entropy padding (zeros and repeating sequences)
        data += bytearray([0] * 1000)
        data += bytearray([1, 2, 3, 4] * 250)

    with open(file_path, "wb") as f:
        f.write(data)

if __name__ == "__main__":
    create_samples()
