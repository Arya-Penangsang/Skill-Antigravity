import os
import json

class ReportGenerator:
    def __init__(self, static_data, dynamic_data, yara_rule, target_name):
        self.static = static_data
        self.dynamic = dynamic_data
        self.yara = yara_rule
        self.target_name = target_name
        self.score, self.verdict, self.color = self._compute_threat_score()

    def _compute_threat_score(self):
        score = 0
        
        # Check packed sections
        sections = self.static.get("sections", [])
        if any(s.get("is_packed") for s in sections):
            score += 25
            
        # Check capabilities
        caps = self.static.get("capabilities", {}).get("capabilities", [])
        for c in caps:
            if c.get("risk") == "High":
                score += 20
            elif c.get("risk") == "Medium":
                score += 10
                
        # Check IOCs
        iocs = self.static.get("iocs", {})
        if iocs.get("ips") or iocs.get("urls"):
            score += 15
        if iocs.get("suspicious_indicators"):
            score += 10

        # Check dynamic behaviors
        dyn = self.dynamic or {}
        if dyn.get("registry_modifications"):
            score += 30
        if dyn.get("dropped_files"):
            score += 15
        if len(dyn.get("spawned_processes", [])) > 1:
            score += 20

        score = min(100, score)

        if score >= 60:
            verdict = "MALICIOUS"
            color = "#FF3366" # Red
        elif score >= 30:
            verdict = "SUSPICIOUS"
            color = "#FFAA00" # Orange/Amber
        else:
            verdict = "CLEAN / BENIGN"
            color = "#00E676" # Green

        return score, verdict, color

    def generate_json(self, output_path):
        report = {
            "target": self.target_name,
            "threat_score": self.score,
            "verdict": self.verdict,
            "static_analysis": self.static,
            "dynamic_analysis": self.dynamic,
            "yara_rule": self.yara
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        return output_path

    def generate_html(self, output_path):
        hashes = self.static.get("hashes", {})
        pe_hdr = self.static.get("pe_header", {})
        sections = self.static.get("sections", [])
        caps = self.static.get("capabilities", {}).get("capabilities", [])
        iocs = self.static.get("iocs", {})
        dyn = self.dynamic or {}

        sections_html = ""
        for s in sections:
            packed_badge = '<span style="color:#FF3366;font-weight:bold;">[PACKED]</span>' if s['is_packed'] else '<span style="color:#00E676;">[NORMAL]</span>'
            sections_html += f"<tr><td>{s['name']}</td><td>{s['virtual_address']}</td><td>{s['virtual_size']}</td><td>{s['raw_size']}</td><td>{s['entropy']}</td><td>{packed_badge}</td></tr>"

        caps_html = ""
        for c in caps:
            risk_color = "#FF3366" if c['risk'] == "High" else "#FFAA00"
            apis_joined = ", ".join(f"<code>{a}</code>" for a in c['matched_apis'])
            caps_html += f"""
            <div style="background:#222; border-left: 4px solid {risk_color}; padding:10px; margin-bottom:10px; border-radius:4px;">
                <div style="display:flex; justify-content:space-between;">
                    <strong>{c['category']}</strong>
                    <span style="color:{risk_color}; font-weight:bold;">[{c['risk']} Risk] MITRE: {c['mitre']}</span>
                </div>
                <div style="margin-top:6px; font-size:13px; color:#bbb;">APIs: {apis_joined}</div>
            </div>
            """

        if not caps_html:
            caps_html = "<p style='color:#888;'>No suspicious API capabilities matched.</p>"

        iocs_html = ""
        if iocs.get("ips"):
            iocs_html += f"<h4>IP Addresses:</h4><ul>{''.join(f'<li>{ip}</li>' for ip in iocs['ips'])}</ul>"
        if iocs.get("urls"):
            iocs_html += f"<h4>URLs / Domains:</h4><ul>{''.join(f'<li>{u}</li>' for u in iocs['urls'])}</ul>"
        if not iocs_html:
            iocs_html = "<p style='color:#888;'>No external network IOCs found in binary.</p>"

        dyn_procs = "".join(f"<li>PID {p['pid']} - {p['name']}</li>" for p in dyn.get("spawned_processes", [])) or "None"
        dyn_files = "".join(f"<li>{f}</li>" for f in dyn.get("dropped_files", [])) or "None"
        dyn_reg = "".join(f"<li>{r.get('action')}: {r.get('key')}</li>" for r in dyn.get("registry_modifications", [])) or "None"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Antigravity Sandbox Report - {self.target_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #121212; color: #E0E0E0; margin: 0; padding: 20px; }}
        .container {{ max-width: 1000px; margin: auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; background: #1E1E1E; padding: 20px; border-radius: 8px; border: 1px solid #333; }}
        .score-box {{ text-align: center; border: 2px solid {self.color}; padding: 10px 24px; border-radius: 8px; }}
        .score {{ font-size: 38px; font-weight: bold; color: {self.color}; }}
        .verdict {{ font-size: 14px; font-weight: bold; color: {self.color}; letter-spacing: 1px; }}
        .card {{ background: #1E1E1E; border: 1px solid #333; border-radius: 8px; padding: 18px; margin-top: 20px; }}
        h2 {{ color: #00B0FF; margin-top: 0; font-size: 18px; border-bottom: 1px solid #333; padding-bottom: 8px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #282828; }}
        th {{ background: #252525; color: #888; }}
        code {{ background: #2A2A2A; color: #00E5FF; padding: 2px 6px; border-radius: 3px; font-family: Consolas, monospace; }}
        pre {{ background: #161616; padding: 14px; border-radius: 6px; overflow-x: auto; color: #A5D6A7; font-family: Consolas, monospace; border: 1px solid #2C2C2C; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1 style="margin:0; font-size:24px;">Antigravity Automated Malware Triage</h1>
            <p style="margin:5px 0 0 0; color:#888;">Target: <strong>{self.target_name}</strong> | Size: {hashes.get('file_size', 0)} bytes</p>
        </div>
        <div class="score-box">
            <div class="score">{self.score}/100</div>
            <div class="verdict">{self.verdict}</div>
        </div>
    </div>

    <div class="card">
        <h2>File Hashes & Metadata</h2>
        <table>
            <tr><th width="20%">MD5</th><td><code>{hashes.get('md5')}</code></td></tr>
            <tr><th>SHA-1</th><td><code>{hashes.get('sha1')}</code></td></tr>
            <tr><th>SHA-256</th><td><code>{hashes.get('sha256')}</code></td></tr>
            <tr><th>Import Hash (Imphash)</th><td><code>{hashes.get('imphash')}</code></td></tr>
            <tr><th>Target Architecture</th><td>{pe_hdr.get('machine', 'N/A')}</td></tr>
            <tr><th>Compile Timestamp</th><td>{pe_hdr.get('compile_timestamp', 'N/A')}</td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Section Entropy & Packing Analysis</h2>
        <table>
            <thead>
                <tr><th>Section Name</th><th>Virtual Address</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy (0-8)</th><th>Status</th></tr>
            </thead>
            <tbody>
                {sections_html}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Behavioral Capabilities (MITRE ATT&CK Mapping)</h2>
        {caps_html}
    </div>

    <div class="card">
        <h2>Dynamic Execution Summary ({dyn.get('execution_status', 'N/A')})</h2>
        <p><strong>Spawned Processes:</strong></p>
        <ul>{dyn_procs}</ul>
        <p><strong>Dropped / Modified Files:</strong></p>
        <ul>{dyn_files}</ul>
        <p><strong>Registry Modifications:</strong></p>
        <ul>{dyn_reg}</ul>
    </div>

    <div class="card">
        <h2>Extracted Network & String Indicators (IOCs)</h2>
        {iocs_html}
    </div>

    <div class="card">
        <h2>Auto-Generated YARA Detection Rule</h2>
        <pre>{self.yara}</pre>
    </div>
</div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path
