import hashlib
import yara
import os
import magic
from pathlib import Path
from core.database import save_scan_result  # Import save_scan_result function
from core.alert_system import send_alert

class AntiVirusScanner:
    def __init__(self):
        self.mime = magic.Magic(mime=True)
        self.yara_rules = self._load_yara_rules()
        self.malware_hashes = self._load_known_hashes()

    def _load_yara_rules(self):
        try:
            return yara.compile(filepaths={
                'ransomware': 'data/yara_rules/ransomware.yar',
                'exploits': 'data/yara_rules/exploits.yar',
                'macros': 'data/yara_rules/macros.yar'
            })
        except yara.Error as e:
            print(f"YARA Error: {str(e)}")
            return None

    def _load_known_hashes(self):
        hash_file = Path('data/known_hashes.txt')
        return set(hash_file.read_text().splitlines()) if hash_file.exists() else set()

    def scan_file(self, file_path):  # <- Method definition starts here
        # PROPER INDENTATION STARTS FROM THIS LINE
        print(f"\n🔍 Scanning: {os.path.basename(file_path)}")
        try:
            detections = []
            path = Path(file_path)

            # Hash check
            with path.open('rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                print(f"🔑 File hash: {file_hash}")
                if file_hash in self.malware_hashes:
                    detections.append("Known malware hash")
                    print(f"🚨 Known malware hash detected: {file_hash}")

            # YARA check
            if self.yara_rules:
                matches = self.yara_rules.match(str(path))
                if matches:
                    detections.extend([f"YARA: {m.rule}" for m in matches])
                    print(f"🚨 YARA rule match: {matches}")

            # File type check
            file_type = self.mime.from_file(str(path))
            print(f"📄 File type: {file_type}")
            if "executable" in file_type or "zip" in file_type:
                detections.append("Suspicious file type")
                print(f"🚨 Suspicious file type: {file_type}")

            # Save results
            status = "Malicious" if detections else "Clean"
            print(f"📊 Scan result: {status}")
            
            # Save scan results to database
            save_scan_result(
                file_path=str(path),
                file_hash=file_hash,
                status=status,
                details=" | ".join(detections)
            )            

            if status == "Malicious":
                send_alert(path.name, detections)

            return detections

        except Exception as e:
            print(f"🔴 Scan error: {str(e)}")
            return []
