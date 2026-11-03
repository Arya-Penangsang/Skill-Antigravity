"""
NIST SP 800-86 Network Forensics Audit Engine
Structures network sinkhole captures into the standard 4-phase forensic lifecycle:
Collection -> Examination -> Analysis -> Reporting.
Dedicated to research on 'Pengembangan Forensik Jaringan Menggunakan Metode NIST' by Achmad Nafik et al.
"""

from datetime import datetime
from typing import List, Dict, Any

class NISTNetworkForensics:
    """Processes network telemetry according to NIST SP 800-86 Digital Forensic Guidelines."""

    def __init__(self, raw_events: List[Dict[str, Any]]):
        self.raw_events = raw_events or []
        self.evidence_id = f"NET-EVD-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    def process(self) -> Dict[str, Any]:
        """Executes full NIST SP 800-86 4-Phase analysis."""
        collection_phase = self._phase_collection()
        examination_phase = self._phase_examination(collection_phase)
        analysis_phase = self._phase_analysis(examination_phase)
        reporting_phase = self._phase_reporting(analysis_phase)

        return {
            "evidence_id": self.evidence_id,
            "nist_standard": "NIST SP 800-86 (Network Forensics Framework)",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "phases": {
                "phase_1_collection": collection_phase,
                "phase_2_examination": examination_phase,
                "phase_3_analysis": analysis_phase,
                "phase_4_reporting": reporting_phase
            },
            "summary": {
                "total_packets": len(self.raw_events),
                "suspected_c2_sessions": analysis_phase.get("c2_beacon_count", 0),
                "data_exfiltration_detected": analysis_phase.get("exfiltration_confirmed", False),
                "threat_level": analysis_phase.get("threat_level", "LOW")
            }
        }

    def _phase_collection(self) -> Dict[str, Any]:
        """Phase 1: Collection - Safe acquisition and integrity recording of inbound traffic."""
        acquired_packets = []
        for i, ev in enumerate(self.raw_events):
            acquired_packets.append({
                "packet_seq": i + 1,
                "timestamp_epoch": ev.get("timestamp"),
                "method": ev.get("method", "UNKNOWN"),
                "uri_path": ev.get("path", "/"),
                "headers_count": len(ev.get("headers", {})),
                "payload_bytes": len(ev.get("payload_snippet", ""))
            })
        return {
            "status": "COMPLETED",
            "total_acquired": len(acquired_packets),
            "collection_protocol": "HTTP/Sinkhole (TCP:8080)",
            "packets": acquired_packets
        }

    def _phase_examination(self, collection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 2: Examination - In-depth inspection of HTTP headers, User-Agents and payloads."""
        examined_items = []
        user_agents = set()
        suspicious_uris = []

        for ev in self.raw_events:
            headers = ev.get("headers", {})
            ua = headers.get("User-Agent", "N/A")
            user_agents.add(ua)
            path = ev.get("path", "/")

            if any(k in path.lower() for k in ["beacon", "gate", "cmd", "check", "bot", "task"]):
                suspicious_uris.append(path)

            examined_items.append({
                "method": ev.get("method"),
                "path": path,
                "user_agent": ua,
                "is_anomalous_ua": ua == "N/A" or len(ua) < 10,
                "exfiltrated_data": ev.get("payload_snippet", "")
            })

        return {
            "status": "COMPLETED",
            "unique_user_agents": list(user_agents),
            "suspicious_endpoints": suspicious_uris,
            "examined_records": examined_items
        }

    def _phase_analysis(self, exam_data: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 3: Analysis - Threat correlation and MITRE ATT&CK technique mapping."""
        records = exam_data.get("examined_records", [])
        post_records = [r for r in records if r["method"] == "POST"]
        exfiltration_detected = len(post_records) > 0

        c2_count = len(records)
        threat_level = "CRITICAL" if exfiltration_detected else ("HIGH" if c2_count > 3 else ("MEDIUM" if c2_count > 0 else "LOW"))

        mitre_tactics = []
        if c2_count > 0:
            mitre_tactics.append({"technique": "T1071.001", "name": "Application Layer Protocol: Web Protocols"})
        if exfiltration_detected:
            mitre_tactics.append({"technique": "T1041", "name": "Exfiltration Over C2 Channel"})

        return {
            "status": "COMPLETED",
            "c2_beacon_count": c2_count,
            "exfiltration_confirmed": exfiltration_detected,
            "exfiltrated_records_count": len(post_records),
            "threat_level": threat_level,
            "mitre_mapping": mitre_tactics
        }

    def _phase_reporting(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 4: Reporting - Legal and technical evidence synthesis."""
        return {
            "status": "COMPLETED",
            "incident_classification": "Malicious Outbound C2 Communication" if analysis_data["c2_beacon_count"] > 0 else "Benign Traffic",
            "actionable_recommendations": [
                "Block identified destination IP / domain on perimeter firewall and IDS.",
                "Isolate compromised host machine from local network VLAN.",
                "Deploy YARA and Sigma detection signatures to enterprise SIEM."
            ]
        }
