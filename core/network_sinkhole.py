"""
Network Sinkhole and C2 Simulator (ApateDNS & INetSim Technique)
Emulates C2 servers and captures malicious outbound DNS/HTTP requests safely.
Inspired by Syai Labs & Yohanes Syailendra, M.Kom network analysis workshops.
"""

import threading
import time
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import List, Dict, Any

class MockC2HTTPHandler(BaseHTTPRequestHandler):
    """Logs all inbound HTTP requests and responds with neutral 200 OK."""

    def log_message(self, format, *args):
        # Suppress default console logging
        pass

    def do_GET(self):
        self.server.captured_requests.append({
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers),
            "timestamp": time.time()
        })
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b""
        self.server.captured_requests.append({
            "method": "POST",
            "path": self.path,
            "headers": dict(self.headers),
            "payload_snippet": post_data[:256].decode(errors="ignore"),
            "timestamp": time.time()
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(b"\x00\x00\x00\x00")


class NetworkSinkhole:
    """Manages local simulated C2 services."""

    def __init__(self, http_port: int = 8080):
        self.http_port = http_port
        self.http_server = None
        self.http_thread = None
        self.captured_traffic: List[Dict[str, Any]] = []

    def start(self):
        """Starts the mock C2 listener in a background thread."""
        try:
            self.http_server = HTTPServer(("127.0.0.1", self.http_port), MockC2HTTPHandler)
            self.http_server.captured_requests = self.captured_traffic
            self.http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
            self.http_thread.start()
        except OSError:
            # Port might be in use
            pass

    def stop(self) -> List[Dict[str, Any]]:
        """Shuts down the sinkhole and returns all captured events."""
        if self.http_server:
            self.http_server.shutdown()
            self.http_server.server_close()
        return self.captured_traffic

    def get_summary(self) -> Dict[str, Any]:
        """Returns summarized network telemetry."""
        return {
            "total_beacons": len(self.captured_traffic),
            "captured_events": self.captured_traffic,
            "exfiltration_suspected": any(ev.get("method") == "POST" for ev in self.captured_traffic)
        }
