import json
import os

def load_rules(file_path: str = None) -> list:
    if file_path is None:
        file_path = os.path.join(os.path.dirname(__file__), 'rules.json')
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)
