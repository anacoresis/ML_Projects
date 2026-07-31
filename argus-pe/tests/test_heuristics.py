import pytest
from argus.core.heuristics import HeuristicsEngine


def test_wx_violation_trigger():
    engine = HeuristicsEngine()
    parser_output = {
        'is_valid_pe': True,
        'features': {'max_section_entropy': 5.5, 'max_virtual_raw_ratio': 1.0},
        'metadata': {'wx_section_count': 1, 'tls_callback_count': 0}
    }
    result = engine.analyze(parser_output, [])
    assert result['heuristic_risk_score'] >= 35.0
    rule_ids = [f['rule_id'] for f in result['findings']]
    assert 'WX_SECTION_VIOLATION' in rule_ids


def test_yara_match_integration():
    engine = HeuristicsEngine()
    parser_output = {'is_valid_pe': True, 'features': {}, 'metadata': {}}
    yara_matches = [{'rule_name': 'UPX_Packer', 'severity': 'HIGH', 'description': 'UPX Detected'}]
    
    result = engine.analyze(parser_output, yara_matches)
    rule_ids = [f['rule_id'] for f in result['findings']]
    assert 'YARA_UPX_PACKER' in rule_ids