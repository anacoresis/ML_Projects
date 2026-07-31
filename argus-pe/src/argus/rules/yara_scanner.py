import os
from typing import List, Dict, Any
import yara


class YaraScanner:
    """
    Compiles and executes YARA signature rules against target binaries.
    """

    def __init__(self, rules_dir: str = "config/yara_rules"):
        self.rules_dir = rules_dir
        self.rules = self._compile_rules()

    def _compile_rules(self) -> yara.Rules | None:
        """Compiles all .yar files found in the rules directory."""
        if not os.path.exists(self.rules_dir):
            return None

        filepaths = {}
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    key = f"namespace_{len(filepaths)}"
                    filepaths[key] = os.path.join(root, file)

        if not filepaths:
            return None

        try:
            return yara.compile(filepaths=filepaths)
        except yara.Error:
            return None

    def scan(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scans a file against compiled YARA rules and returns match metadata.
        """
        if not self.rules or not os.path.exists(file_path):
            return []

        try:
            matches = self.rules.match(file_path)
            results = []
            for match in matches:
                meta = match.meta if hasattr(match, 'meta') else {}
                results.append({
                    'rule_name': match.rule,
                    'severity': meta.get('severity', 'MEDIUM'),
                    'description': meta.get('description', 'YARA signature match')
                })
            return results
        except yara.Error:
            return []