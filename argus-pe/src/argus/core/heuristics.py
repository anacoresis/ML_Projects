from typing import Dict, Any, List


class HeuristicsEngine:
    """
    Evaluates static analysis output against security policies 
    to trigger rule-based threat alerts and risk flags.
    """

    def analyze(self, parser_output: Dict[str, Any], yara_matches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluates PE features, metadata, and YARA matches to generate risk findings.
        """
        findings: List[Dict[str, Any]] = []
        features = parser_output.get('features', {})
        metadata = parser_output.get('metadata', {})

        if not parser_output.get('is_valid_pe', False):
            return {
                'heuristic_risk_score': 0.0,
                'findings': [{'rule_id': 'INVALID_PE', 'severity': 'LOW', 'description': 'File is not a valid PE binary'}]
            }

        # Rule 1: W^X Section Violation
        if metadata.get('wx_section_count', 0) > 0:
            findings.append({
                'rule_id': 'WX_SECTION_VIOLATION',
                'severity': 'HIGH',
                'description': f"Detected {metadata['wx_section_count']} section(s) marked both Writable and Executable."
            })

        # Rule 2: Extreme Entropy (Packed / Encrypted)
        max_entropy = features.get('max_section_entropy', 0.0)
        if max_entropy >= 7.2:
            findings.append({
                'rule_id': 'HIGH_SECTION_ENTROPY',
                'severity': 'HIGH',
                'description': f"Max section entropy ({max_entropy:.2f}) indicates encrypted or packed code."
            })
        elif max_entropy >= 6.8:
            findings.append({
                'rule_id': 'ELEVATED_SECTION_ENTROPY',
                'severity': 'MEDIUM',
                'description': f"Max section entropy ({max_entropy:.2f}) is elevated above compiled baselines."
            })

        # Rule 3: Extreme Virtual to Raw Size Ratio (Memory Unpacking Stub)
        max_ratio = features.get('max_virtual_raw_ratio', 1.0)
        if max_ratio > 10.0:
            findings.append({
                'rule_id': 'EXTREME_VIRTUAL_RAW_RATIO',
                'severity': 'HIGH',
                'description': f"Max Virtual/Raw size ratio ({max_ratio:.1f}x) indicates memory unpacking stubs."
            })

        # Rule 4: TLS Callbacks (Pre-Entrypoint Execution Stubs)
        if metadata.get('tls_callback_count', 0) > 0:
            findings.append({
                'rule_id': 'TLS_CALLBACK_PRESENT',
                'severity': 'MEDIUM',
                'description': f"Detected {metadata['tls_callback_count']} Thread Local Storage (TLS) callback(s)."
            })

        # Rule 5: Suspicious Win32 API Concentration
        suspicious_ratio = features.get('suspicious_api_ratio', 0.0)
        if suspicious_ratio >= 0.15:
            findings.append({
                'rule_id': 'SUSPICIOUS_API_DENSITY',
                'severity': 'MEDIUM',
                'description': f"High concentration of suspicious Win32 APIs ({suspicious_ratio * 100:.1f}% of imports)."
            })

        # Rule 6: Append YARA Matches
        for match in yara_matches:
            findings.append({
                'rule_id': f"YARA_{match['rule_name'].upper()}",
                'severity': match['severity'],
                'description': f"YARA Rule Match: {match['description']}"
            })

        # Calculate Normalized Heuristic Score (0.0 to 100.0)
        weights = {'HIGH': 35.0, 'MEDIUM': 15.0, 'LOW': 5.0}
        score = sum(weights.get(f['severity'], 5.0) for f in findings)
        normalized_score = min(100.0, score)

        return {
            'heuristic_risk_score': round(normalized_score, 2),
            'findings': findings
        }