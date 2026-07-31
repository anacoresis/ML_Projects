import json
import os
from typing import Dict, Any


class Reporter:
    """
    Generates structured security assessment reports in JSON and HTML formats.
    """

    @staticmethod
    def to_json(analysis_data: Dict[str, Any], output_path: str = None) -> str:
        """Converts analysis dictionary into a formatted JSON string or writes to disk."""
        json_str = json.dumps(analysis_data, indent=4)
        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(json_str)
        return json_str

    @staticmethod
    def to_html(analysis_data: Dict[str, Any], output_path: str) -> str:
        """Generates a standalone HTML report with responsive threat styling."""
        file_path = analysis_data.get('file_path', 'Unknown Binary')
        risk_info = analysis_data.get('risk_assessment', {})
        threat_score = risk_info.get('unified_threat_score', 0.0)
        threat_level = risk_info.get('threat_level', 'LOW')
        ml_prob = risk_info.get('ml_probability', 0.0)
        heur_score = risk_info.get('heuristic_score', 0.0)
        findings = risk_info.get('findings', [])
        
        parser_feats = analysis_data.get('features', {})
        metadata = analysis_data.get('metadata', {})

        # Color palette based on threat level
        color_map = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#198754'
        }
        badge_color = color_map.get(threat_level, '#6c757d')

        findings_html = ""
        for f in findings:
            sev_color = color_map.get(f.get('severity'), '#6c757d')
            findings_html += f"""
            <div style="border-left: 4px solid {sev_color}; padding: 10px; margin-bottom: 10px; background: #2c2c2c; border-radius: 4px;">
                <span style="background: {sev_color}; color: #fff; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 12px;">{f.get('severity')}</span>
                <strong style="margin-left: 10px; color: #e0e0e0;">{f.get('rule_id')}</strong>
                <p style="margin: 5px 0 0 0; color: #b0b0b0;">{f.get('description')}</p>
            </div>
            """

        if not findings_html:
            findings_html = "<p style='color: #888;'>No suspicious structural anomalies or YARA matches detected.</p>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ARGUS Threat Analysis Report - {os.path.basename(file_path)}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #121212; color: #e0e0e0; margin: 0; padding: 20px; }}
        .container {{ max-width: 900px; margin: auto; background: #1e1e1e; padding: 25px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #333; padding-bottom: 15px; }}
        .title {{ font-size: 24px; font-weight: bold; color: #fff; }}
        .badge {{ background: {badge_color}; color: #fff; padding: 6px 14px; font-size: 16px; border-radius: 20px; font-weight: bold; }}
        .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }}
        .card {{ background: #252525; padding: 15px; border-radius: 6px; text-align: center; }}
        .card .value {{ font-size: 22px; font-weight: bold; color: #fff; margin-top: 5px; }}
        .card .label {{ font-size: 12px; color: #888; text-transform: uppercase; }}
        .section-title {{ font-size: 18px; margin-top: 25px; border-bottom: 1px solid #333; padding-bottom: 8px; color: #fff; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #333; font-size: 14px; }}
        th {{ color: #888; background: #252525; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="title">ARGUS Static Binary Analysis</div>
                <div style="color: #888; font-size: 13px; margin-top: 5px;">Target: {file_path}</div>
            </div>
            <div class="badge">{threat_level} ({threat_score} / 100)</div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="label">Unified Threat Score</div>
                <div class="value" style="color: {badge_color};">{threat_score}</div>
            </div>
            <div class="card">
                <div class="label">ML Malware Prob</div>
                <div class="value">{ml_prob}%</div>
            </div>
            <div class="card">
                <div class="label">Heuristic Risk Score</div>
                <div class="value">{heur_score}</div>
            </div>
        </div>

        <div class="section-title">Security Policy & Heuristic Findings</div>
        <div style="margin-top: 15px;">
            {findings_html}
        </div>

        <div class="section-title">Key PE Structural Attributes</div>
        <table>
            <tr><th>Attribute</th><th>Extracted Value</th></tr>
            <tr><td>Max Section Entropy</td><td>{parser_feats.get('max_section_entropy', 0.0)} bits/byte</td></tr>
            <tr><td>Max Virtual / Raw Ratio</td><td>{parser_feats.get('max_virtual_raw_ratio', 1.0)}x</td></tr>
            <tr><td>W^X Section Violations</td><td>{metadata.get('wx_section_count', 0)}</td></tr>
            <tr><td>TLS Callbacks Count</td><td>{metadata.get('tls_callback_count', 0)}</td></tr>
            <tr><td>Suspicious Win32 APIs Found</td><td>{len(metadata.get('suspicious_apis_found', []))}</td></tr>
        </table>
    </div>
</body>
</html>
"""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(html_content)

        return output_path