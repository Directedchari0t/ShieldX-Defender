import math
import lief
import numpy as np

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0
    entropy = 0
    counter = bytearray([0]*256)
    for b in data:
        counter[b] += 1
    for count in counter:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def extract_features(file_path):
    """Extract security-relevant features from files"""
    features = {}
    
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            
        # Basic features
        features['size'] = len(data)
        features['entropy'] = calculate_entropy(data)
        
        # PE file features
        try:
            binary = lief.parse(file_path)
            if binary:
                features['imports_count'] = len(binary.imports)
                features['sections'] = len(binary.sections)
                features['has_certificate'] = int(binary.has_signature)
        except:
            pass
            
        # Suspicious strings
        lower_data = data.lower()
        features['contains_http'] = int(b'http://' in lower_data)
        features['contains_cmd'] = int(b'cmd.exe' in lower_data)
        
    except Exception as e:
        print(f"Feature extraction failed: {str(e)}")
        return None
        
    return features
