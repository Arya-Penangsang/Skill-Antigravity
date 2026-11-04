#!/usr/bin/env python3
"""
Infrastructure Red Teaming & CEH Triage Helper Script
Multi-threaded Port Scanner, Service Banner Grabber & Local Privilege Escalation Auditor.
"""

import sys
import os
import socket
import argparse
import subprocess
import concurrent.futures
from typing import List, Dict, Any

class InfraAuditor:

    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]

    @staticmethod
    def grab_banner(target: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
        """Attempts connection and grabs service banner."""
        banner = ""
        is_open = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((target, port))
                if res == 0:
                    is_open = True
                    try:
                        # Send basic probe
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n" if port in [80, 8080, 8443] else b"\r\n")
                        banner = s.recv(1024).decode(errors="ignore").strip()
                    except Exception:
                        pass
        except Exception:
            pass

        return {
            "port": port,
            "open": is_open,
            "banner": banner[:120] if banner else "N/A"
        }

    def scan_ports(self, target: str, ports: List[int], max_threads: int = 50) -> List[Dict[str, Any]]:
        """Multi-threaded TCP port scanner."""
        print(f"[*] Scanning {len(ports)} ports on target: {target}...")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {executor.submit(self.grab_banner, target, p): p for p in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                if res["open"]:
                    results.append(res)
                    print(f"    [+] Port {res['port']:<5} : OPEN | Banner: {res['banner']}")
        return sorted(results, key=lambda x: x["port"])

    @staticmethod
    def audit_local_privesc() -> Dict[str, Any]:
        """Audits current host environment for local privilege escalation vectors."""
        print("\n[*] Auditing Local Privilege Escalation (LPE) Vectors...")
        findings = []

        if sys.platform == "win32":
            # 1. Whoami /priv
            try:
                proc = subprocess.run(["whoami", "/priv"], capture_output=True, text=True, check=False)
                privs = proc.stdout
                critical_privs = [
                    "SeImpersonatePrivilege",
                    "SeAssignPrimaryTokenPrivilege",
                    "SeDebugPrivilege",
                    "SeBackupPrivilege",
                    "SeRestorePrivilege",
                    "SeTakeOwnershipPrivilege",
                    "SeLoadDriverPrivilege"
                ]
                for p in critical_privs:
                    if p.lower() in privs.lower():
                        findings.append({
                            "vector": "Dangerous Windows Token",
                            "severity": "CRITICAL",
                            "detail": f"Token {p} enabled! Vulnerable to Potato family / Token Impersonation LPE."
                        })
            except Exception as e:
                findings.append({"vector": "whoami check", "severity": "INFO", "detail": str(e)})

            # 2. Check AlwaysInstallElevated in Registry
            try:
                import winreg
                for root in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
                    try:
                        with winreg.OpenKey(root, r"Software\Policies\Microsoft\Windows\Installer") as k:
                            val, _ = winreg.QueryValueEx(k, "AlwaysInstallElevated")
                            if val == 1:
                                findings.append({
                                    "vector": "AlwaysInstallElevated",
                                    "severity": "HIGH",
                                    "detail": "AlwaysInstallElevated set to 1! Any MSI will execute as SYSTEM."
                                })
                    except FileNotFoundError:
                        pass
            except Exception:
                pass

        else:
            # POSIX / Linux SUID check
            try:
                proc = subprocess.run(
                    ["find", "/", "-perm", "-4000", "-type", "f"],
                    capture_output=True, text=True, timeout=10, check=False
                )
                dangerous_suid = ["nmap", "vim", "find", "bash", "cp", "awk", "nano", "less", "more"]
                for line in proc.stdout.splitlines():
                    base = os.path.basename(line.strip())
                    if base in dangerous_suid:
                        findings.append({
                            "vector": "Dangerous SUID Binary (GTFOBins)",
                            "severity": "CRITICAL",
                            "detail": f"SUID binary found: {line.strip()} (Direct root shell breakout)"
                        })
            except Exception:
                pass

        if findings:
            for f in findings:
                print(f"    [!] [{f['severity']}] {f['vector']}: {f['detail']}")
        else:
            print("    [+] No trivial LPE vectors identified on current user context.")

        return {"findings": findings}

    @staticmethod
    def smb_check(target: str) -> Dict[str, Any]:
        """Basic socket probe to verify SMB 445 responsiveness."""
        print(f"\n[*] Probing SMB Service on {target}:445...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3.0)
            res = s.connect_ex((target, 445))
            if res == 0:
                print(f"    [+] Port 445 is OPEN! Host is accepting SMB connections.")
                print(f"    [*] Recommendation: Run 'enum4linux -a {target}' or 'smbclient -N -L //{target}' to test Null Session.")
                return {"smb_open": True}
            else:
                print(f"    [-] Port 445 is CLOSED or filtered.")
                return {"smb_open": False}


def main():
    parser = argparse.ArgumentParser(description="CEH & Infrastructure Red Teaming Auditor")
    parser.add_argument("--scan", help="Target IP or hostname to scan")
    parser.add_argument("--ports", help="Comma-separated ports to scan (e.g., 21,22,80,445) or 'all'")
    parser.add_argument("--audit-privesc", action="store_true", help="Audit local system for Privilege Escalation vectors")
    parser.add_argument("--smb-check", help="Target IP to check for SMB port 445 availability")

    args = parser.parse_args()
    auditor = InfraAuditor()

    if not any([args.scan, args.audit_privesc, args.smb_check]):
        parser.print_help()
        sys.exit(1)

    if args.scan:
        if args.ports:
            if args.ports.lower() == "all":
                ports = list(range(1, 1025))
            else:
                ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
        else:
            ports = InfraAuditor.COMMON_PORTS
        auditor.scan_ports(args.scan, ports)

    if args.smb_check:
        auditor.smb_check(args.smb_check)

    if args.audit_privesc:
        auditor.audit_local_privesc()

if __name__ == "__main__":
    main()
