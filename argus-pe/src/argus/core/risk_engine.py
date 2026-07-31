from typing import Dict, Any, List


class RiskEngine:
    """
    Aggregates ML probability, Heuristics, and YARA rule findings
    into a single unified threat rating.
    """

    @staticmethod
    def evaluate(
        ml_probability: float,
        heuristic_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Blends probabilistic and deterministic risk scores into a unified threat score.
        """
        heuristic_score = heuristic_result.get('heuristic_risk_score', 0.0)
        findings = heuristic_result.get('findings', [])

        # Weighted calculation (50% ML, 50% Heuristics)
        combined_score = (ml_probability * 0.50) + (heuristic_score * 0.50)

        # Safety Override: Force HIGH risk if explicit critical findings exist
        has_high_severity_finding = any(f.get('severity') == 'HIGH' for f in findings)
        if has_high_severity_finding and combined_score < 75.0:
            combined_score = 75.0

        final_score = round(min(100.0, combined_score), 2)

        # Map threat level category
        if final_score >= 85.0:
            threat_level = 'CRITICAL'
        elif final_score >= 60.0:
            threat_level = 'HIGH'
        elif final_score >= 30.0:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'

        return {
            'unified_threat_score': final_score,
            'threat_level': threat_level,
            'ml_probability': ml_probability,
            'heuristic_score': heuristic_score,
            'total_findings_count': len(findings),
            'findings': findings
        }