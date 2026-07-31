import pytest
from argus.core.risk_engine import RiskEngine


def test_risk_engine_override():
    # If ML predicts 10% malware, but Heuristics finds a HIGH severity finding (W^X violation)
    ml_prob = 10.0
    heuristic_res = {
        'heuristic_risk_score': 35.0,
        'findings': [{'rule_id': 'WX_SECTION_VIOLATION', 'severity': 'HIGH', 'description': 'W^X violation'}]
    }

    result = RiskEngine.evaluate(ml_prob, heuristic_res)
    
    # Overriding rule must force unified threat score to at least 75.0 (HIGH)
    assert result['unified_threat_score'] >= 75.0
    assert result['threat_level'] in ['HIGH', 'CRITICAL']


def test_low_risk_binary():
    ml_prob = 5.0
    heuristic_res = {'heuristic_risk_score': 0.0, 'findings': []}
    
    result = RiskEngine.evaluate(ml_prob, heuristic_res)
    assert result['unified_threat_score'] < 30.0
    assert result['threat_level'] == 'LOW'