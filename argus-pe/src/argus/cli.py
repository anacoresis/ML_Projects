import argparse
import sys
import os
from argus.core.parser import PEParser
from argus.rules.yara_scanner import YaraScanner
from argus.core.heuristics import HeuristicsEngine
from argus.core.ml_engine import MLEngine
from argus.core.risk_engine import RiskEngine
from argus.utils.reporter import Reporter


def analyze_file(file_path: str, ml_engine: MLEngine, parser: PEParser, yara: YaraScanner, heuristics: HeuristicsEngine):
    """Executes full hybrid analysis pipeline on a single binary file."""
    parser_output = parser.parse(file_path)
    
    if not parser_output.get('is_valid_pe', False):
        return {
            'file_path': file_path,
            'is_valid_pe': False,
            'risk_assessment': {
                'unified_threat_score': 0.0,
                'threat_level': 'UNKNOWN',
                'findings': [{'rule_id': 'INVALID_PE', 'severity': 'LOW', 'description': 'File is corrupt or not a valid PE binary'}]
            }
        }

    features = parser_output['features']
    ml_prob, _ = ml_engine.predict(features)
    
    yara_matches = yara.scan(file_path)
    heuristic_res = heuristics.analyze(parser_output, yara_matches)
    
    risk_res = RiskEngine.evaluate(ml_prob, heuristic_res)

    return {
        'file_path': file_path,
        'is_valid_pe': True,
        'risk_assessment': risk_res,
        'features': features,
        'metadata': parser_output['metadata']
    }


def main():
    parser_arg = argparse.ArgumentParser(
        prog="argus",
        description="ARGUS - Automated PE Header Triage & Hybrid Threat Analysis Framework"
    )

    parser_arg.add_argument("target", help="Path to Windows PE binary (.exe / .dll) to inspect")
    parser_arg.add_argument("--format", choices=["terminal", "json", "html"], default="terminal", help="Output format (default: terminal)")
    parser_arg.add_argument("--output", "-o", help="File path to save JSON or HTML report")

    args = parser_arg.parse_args()

    if not os.path.exists(args.target):
        print(f"[ERROR] Target path not found: {args.target}")
        sys.exit(1)

    # Initialize Engine Components
    pe_parser = PEParser()
    yara_scanner = YaraScanner()
    heuristics_engine = HeuristicsEngine()
    ml_engine = MLEngine()

    # Execute Analysis
    result = analyze_file(args.target, ml_engine, pe_parser, yara_scanner, heuristics_engine)

    # Handle Reporting
    if args.format == "json":
        json_out = Reporter.to_json(result, args.output)
        if not args.output:
            print(json_out)
        else:
            print(f"[+] JSON report saved to: {args.output}")

    elif args.format == "html":
        if not args.output:
            args.output = f"argus_report_{os.path.basename(args.target)}.html"
        saved_path = Reporter.to_html(result, args.output)
        print(f"[+] HTML report saved to: {saved_path}")

    else:
        # Terminal Display
        risk = result['risk_assessment']
        feats = result.get('features', {})
        meta = result.get('metadata', {})

        print("\n" + "=" * 68)
        print(" ARGUS | AUTOMATED PE HEADER TRIAGE & THREAT ANALYSIS ENGINE")
        print("=" * 68)
        print(f" Target File  : {args.target}")
        print(f" Valid PE     : {result['is_valid_pe']}")
        print(f" Threat Level : [{risk['threat_level']}] (Score: {risk['unified_threat_score']}/100)")
        print(f" ML Prob      : {risk.get('ml_probability', 0.0)}% Malware Probability")
        print(f" Heuristic    : {risk.get('heuristic_score', 0.0)} Risk Points")
        print("-" * 68)

        print("\n Key PE Structural Features:")
        print(f"   - Max Section Entropy    : {feats.get('max_section_entropy', 0.0)}")
        print(f"   - Max Virt/Raw Ratio     : {feats.get('max_virtual_raw_ratio', 1.0)}x")
        print(f"   - W^X Violations         : {meta.get('wx_section_count', 0)}")
        print(f"   - TLS Callbacks          : {meta.get('tls_callback_count', 0)}")
        print(f"   - Suspicious API Imports : {feats.get('suspicious_import_count', 0)}")

        print("\n Policy Findings & Anomalies:")
        for f in risk.get('findings', []):
            print(f"   [{f.get('severity')}] {f.get('rule_id')} : {f.get('description')}")

        if not risk.get('findings'):
            print("   None (Clean static signature)")
        print("=" * 68 + "\n")


if __name__ == "__main__":
    main()