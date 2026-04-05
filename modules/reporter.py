"""
reporter.py - Report Generation Module

Generates JSON and HTML reports from scan findings.
HTML report includes vulnerability details, severity breakdown,
mutation details, response diffs, and remediation guidance.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from jinja2 import Template

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel API Scanner - {{ scan_info.target }}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0a0a0f;
            --surface: #14141f;
            --surface-accent: #1e1e2d;
            --primary: #00f2ff;
            --secondary: #7000ff;
            --text-main: #e0e0e0;
            --text-dim: #94a3b8;
            --critical: #ff2e2e;
            --high: #ff8c00;
            --medium: #ffd700;
            --low: #00a3ff;
            --border: rgba(255, 255, 255, 0.08);
            --glass: rgba(255, 255, 255, 0.03);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Outfit', sans-serif; 
            background: var(--bg); 
            color: var(--text-main); 
            line-height: 1.6;
            background-image: 
                radial-gradient(circle at 0% 0%, rgba(112, 0, 255, 0.05) 0%, transparent 50%),
                radial-gradient(circle at 100% 100%, rgba(0, 242, 255, 0.05) 0%, transparent 50%);
            min-height: 100vh;
            padding-bottom: 50px;
        }

        .container { max-width: 1100px; margin: 0 auto; padding: 40px 20px; }

        header { 
            text-align: left; 
            margin-bottom: 40px; 
            padding: 30px; 
            background: var(--surface); 
            border: 1px solid var(--border); 
            border-radius: 24px;
            position: relative;
            overflow: hidden;
        }
        header::after {
            content: ""; position: absolute; top: 0; right: 0; width: 4px; height: 100%;
            background: linear-gradient(to bottom, var(--primary), var(--secondary));
        }

        h1 { font-size: 2.5rem; font-weight: 700; letter-spacing: -0.02em; background: linear-gradient(90deg, #fff, #94a3b8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .timestamp { font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: var(--text-dim); margin-top: 8px; }

        .disclaimer { 
            background: rgba(255, 46, 46, 0.05); 
            border: 1px solid rgba(255, 46, 46, 0.2); 
            padding: 16px 24px; 
            border-radius: 16px; 
            margin-bottom: 30px; 
            color: #ffa4a4; 
            font-size: 0.85rem;
            display: flex; align-items: center; gap: 12px;
        }

        .grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 24px; margin-bottom: 40px; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 20px; padding: 24px; }

        .scan-stats { grid-column: span 12; }
        .summary-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; width: 100%; }
        
        .stat-item { 
            background: var(--surface-accent); 
            padding: 20px; 
            border-radius: 16px; 
            text-align: center;
            border-bottom: 3px solid transparent;
            transition: transform 0.2s;
        }
        .stat-item:hover { transform: translateY(-4px); }
        .stat-val { font-size: 2rem; font-weight: 700; font-family: 'JetBrains Mono'; display: block; }
        .stat-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-dim); }
        
        .stat-item.critical { border-color: var(--critical); }
        .stat-item.high { border-color: var(--high); }
        .stat-item.medium { border-color: var(--medium); }
        .stat-item.low { border-color: var(--low); }
        .stat-item.critical .stat-val { color: var(--critical); text-shadow: 0 0 15px rgba(255, 46, 46, 0.3); }
        .stat-item.high .stat-val { color: var(--high); }
        
        .info-panel { grid-column: span 12; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .info-item { display: flex; flex-direction: column; gap: 4px; }
        .info-label { font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); font-weight: 600; }
        .info-value { font-size: 1rem; color: #fff; font-family: 'JetBrains Mono'; }

        .finding { 
            background: var(--surface); 
            border: 1px solid var(--border); 
            border-radius: 24px; 
            padding: 30px; 
            margin-bottom: 24px; 
            position: relative;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .finding:hover { border-color: rgba(255, 255, 255, 0.2); box-shadow: 0 20px 40px rgba(0,0,0,0.4); }
        
        .finding-head { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
        .finding-title { font-size: 1.25rem; font-weight: 600; color: #fff; }
        
        .severity-badge { 
            padding: 6px 14px; border-radius: 10px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
        }
        .severity-badge.CRITICAL { background: rgba(255, 46, 46, 0.15); color: var(--critical); border: 1px solid var(--critical); }
        .severity-badge.HIGH { background: rgba(255, 140, 0, 0.15); color: var(--high); border: 1px solid var(--high); }
        .severity-badge.MEDIUM { background: rgba(255, 215, 0, 0.15); color: var(--medium); border: 1px solid var(--medium); }
        .severity-badge.LOW { background: rgba(0, 163, 255, 0.15); color: var(--low); border: 1px solid var(--low); }

        .finding-meta { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
        .meta-tag { background: var(--surface-accent); color: var(--text-dim); padding: 4px 12px; border-radius: 8px; font-size: 0.8rem; font-family: 'JetBrains Mono'; border: 1px solid var(--border); }
        .meta-tag b { color: #fff; font-weight: 500; }

        .finding-body { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
        @media (max-width: 768px) { .finding-body { grid-template-columns: 1fr; } }
        
        .section-label { font-size: 0.8rem; text-transform: uppercase; font-weight: 700; margin-bottom: 12px; color: var(--primary); display: flex; align-items: center; gap: 8px; }
        
        .desc-box p { font-size: 0.95rem; color: var(--text-main); margin-bottom: 12px; }
        .evidence-list { list-style: none; }
        .evidence-list li { font-size: 0.85rem; color: var(--text-dim); margin-bottom: 6px; padding-left: 20px; position: relative; }
        .evidence-list li::before { content: "→"; position: absolute; left: 0; color: var(--primary); }

        .code-box { background: #07070a; border: 1px solid var(--border); border-radius: 12px; padding: 16px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #8bc34a; max-height: 200px; overflow-y: auto; overflow-x: hidden; word-break: break-all; }
        
        .remediation { 
            margin-top: 24px; padding-top: 24px; border-top: 1px solid var(--border);
            display: flex; gap: 16px; align-items: flex-start;
        }
        .remediation-icon { background: rgba(0, 242, 255, 0.1); color: var(--primary); padding: 10px; border-radius: 12px; font-size: 1.2rem; }
        .remediation-text { font-size: 0.9rem; color: #a5d6a7; }

        .no-vulns { text-align: center; padding: 60px; background: var(--surface); border-radius: 32px; border: 1px dashed #4caf50; }
        .no-vulns h2 { font-size: 2rem; color: #4caf50; margin-bottom: 12px; }

        footer { text-align: center; margin-top: 60px; padding-top: 30px; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 0.8rem; }
        
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: var(--surface-accent); border-radius: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="info-label">Sentinel API Security Audit</div>
            <h1>Audit Report & Analysis</h1>
            <div class="timestamp">SCAN_ID: {{ scan_info.timestamp.replace(':','').replace('-','') }} | TARGET: {{ scan_info.target }}</div>
        </header>

        <div class="disclaimer">
            <span>🛡️</span>
            <div><strong>LEGAL DISCLAIMER:</strong> This report was generated by an automated security scanning tool. Use findings only on systems you are authorized to test. Unauthorized access is a criminal offense.</div>
        </div>

        <section class="grid">
            <div class="card scan-stats">
                <div class="summary-row">
                    <div class="stat-item"><span class="stat-val">{{ summary.total_vulnerabilities }}</span><span class="stat-label">Findings</span></div>
                    <div class="stat-item critical"><span class="stat-val">{{ summary.critical }}</span><span class="stat-label">Critical</span></div>
                    <div class="stat-item high"><span class="stat-val">{{ summary.high }}</span><span class="stat-label">High Risk</span></div>
                    <div class="stat-item medium"><span class="stat-val">{{ summary.medium }}</span><span class="stat-label">Medium</span></div>
                    <div class="stat-item low"><span class="stat-val">{{ summary.low }}</span><span class="stat-label">Low</span></div>
                </div>
            </div>

            <div class="card info-panel">
                <div class="info-item"><div class="info-label">Base URL</div><div class="info-value">{{ scan_info.target }}</div></div>
                <div class="info-item"><div class="info-label">Auth Layer</div><div class="info-value">{{ scan_info.token_type | upper }}</div></div>
                <div class="info-item"><div class="info-label">Baseline</div><div class="info-value">HTTP {{ scan_info.baseline_status }}</div></div>
                <div class="info-item"><div class="info-label">Coverage</div><div class="info-value">{{ scan_info.total_mutations }} Mutations</div></div>
            </div>
        </section>

        <h2 style="margin-bottom: 24px;">Audit Findings Detail</h2>

        {% if findings %}
            {% for finding in findings %}
            <div class="finding">
                <div class="finding-head">
                    <div>
                        <div class="finding-title">{{ finding.mutation_name }}</div>
                        <div style="font-size: 0.8rem; color: var(--text-dim); margin-top: 4px;">CATEGORY: {{ finding.category | upper }}</div>
                    </div>
                    <span class="severity-badge {{ finding.severity }}">{{ finding.severity }}</span>
                </div>

                <div class="finding-meta">
                    <div class="meta-tag">CONFIDENCE: <b>{{ "%.0f%%" | format(finding.confidence * 100) }}</b></div>
                    <div class="meta-tag">IMPACT: <b>{{ finding.response_status }} (BASELINE {{ finding.baseline_status }})</b></div>
                    <div class="meta-tag">LATENCY: <b>{{ "%.0f" | format(finding.response_time_ms) }}ms</b></div>
                    <div class="meta-tag">PAYLOAD: <b>{{ finding.response_size_bytes }}B</b></div>
                </div>

                <div class="finding-body">
                    <div class="desc-box">
                        <div class="section-label">Summary & Evidence</div>
                        <p>{{ finding.description }}</p>
                        <ul class="evidence-list">
                            {% for ev in finding.evidence %}
                            <li>{{ ev }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    <div class="code-panel">
                        <div class="section-label">Response Preview</div>
                        <div class="code-box">{% if finding.response_body_preview %}{{ finding.response_body_preview }}{% else %}[No Body Content]{% endif %}</div>
                    </div>
                </div>

                <div class="remediation">
                    <div class="remediation-icon">✦</div>
                    <div class="remediation-text">
                        <strong>Security Recommendation:</strong><br>
                        {{ remediation_map.get(finding.category, "Ensure proper signature validation and cryptographic hygiene on this endpoint.") }}
                    </div>
                </div>
            </div>
            {% endfor %}
        {% else %}
            <div class="no-vulns">
                <h2>No Vulnerabilities Found</h2>
                <p>The scanner analyzed {{ scan_info.total_mutations }} mutations and found no authentication bypass signals.</p>
            </div>
        {% endif %}

        <footer>
            <strong>SENTINEL API AUDIT SYSTEM v2.1.0</strong><br>
            Automated misconfiguration analysis for JWT, HMAC, and OAuth 2.0 implementations.<br>
            Generated at {{ scan_info.timestamp }}
        </footer>
    </div>
</body>
</html>"""

REMEDIATION_MAP = {
    "Algorithm Substitution": (
        "Explicitly whitelist allowed algorithms (e.g., only HS256 or RS256). "
        "Never accept 'none' algorithm. Use a vetted JWT library with strict algorithm "
        "enforcement. Avoid algorithm confusion by separating verification keys per algorithm."
    ),
    "Payload Tampering": (
        "Never trust client-provided claims for authorization decisions without server-side "
        "verification. Validate role/permission claims against a trusted database. "
        "Always verify the token signature before reading any claims."
    ),
    "Replay": (
        "Implement jti (JWT ID) claim with server-side nonce tracking. "
        "Use short expiry windows (15 min or less). Consider binding tokens to IP/device. "
        "Implement a token revocation list for sensitive operations."
    ),
    "Expiration Manipulation": (
        "Always validate exp claim server-side. Reject tokens without exp. "
        "Set reasonable maximum token lifetimes. Consider clock skew tolerance (±5 min max). "
        "Validate iat and nbf claims if present."
    ),
    "HMAC-Specific": (
        "Use strong, randomly-generated secrets of at least 256 bits. "
        "Rotate secrets regularly. Implement constant-time comparison to prevent timing attacks. "
        "Validate full signature length before comparison."
    ),
    "Signature Manipulation": (
        "Always validate signature before processing any token data. "
        "Reject tokens with empty, missing, or malformed signatures. "
        "Use up-to-date cryptographic libraries. Validate key ID (kid) header against "
        "a trusted key store; never load keys from user-supplied URLs."
    ),
}


class Reporter:
    """
    Generates JSON and HTML reports from scan findings.
    """

    def save_json(self, report_data: Dict[str, Any], path: str) -> None:
        """
        Save scan results as a JSON report.

        Args:
            report_data: Complete report data dictionary
            path: Output file path
        """
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)

    def save_html(self, report_data: Dict[str, Any], path: str) -> None:
        """
        Save scan results as a styled HTML report.

        Args:
            report_data: Complete report data dictionary
            path: Output HTML file path
        """
        template = Template(HTML_TEMPLATE)
        html = template.render(
            scan_info=report_data["scan_info"],
            findings=report_data["findings"],
            summary=report_data["summary"],
            remediation_map=REMEDIATION_MAP,
        )
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def print_summary_table(self, report_data: Dict[str, Any]) -> None:
        """Print a concise summary table to stdout."""
        from tabulate import tabulate
        findings = report_data.get("findings", [])
        if not findings:
            print("No vulnerabilities found.")
            return

        rows = [
            [
                f["mutation_name"][:40],
                f["category"][:20],
                f["severity"],
                f["response_status"],
                f"{f['confidence']:.0%}",
            ]
            for f in findings
        ]
        print(tabulate(
            rows,
            headers=["Mutation", "Category", "Severity", "HTTP", "Confidence"],
            tablefmt="rounded_outline"
        ))
