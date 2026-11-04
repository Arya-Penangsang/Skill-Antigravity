#!/usr/bin/env python3
"""
Digital Forensics & Incident Response (DFIR) Helper Script
USB Connection History Auditor, File Carving Engine & Sigma (YAML) Detection Rule Generator.
"""

import sys
import os
import argparse
import uuid
from datetime import datetime

class ForensicTriage:

    @staticmethod
    def audit_usb_history():
        """Audits USB and storage devices recorded in Windows Registry."""
        print("=" * 65)
        print("       WINDOWS USB & STORAGE FORENSIC AUDIT                     ")
        print("=" * 65)

        if sys.platform != "win32":
            print("[-] Registry inspection is only available on Windows host.")
            return

        import winreg
        targets = [
            (r"SYSTEM\CurrentControlSet\Enum\USBSTOR", "USB Mass Storage (USBSTOR)"),
            (r"SYSTEM\CurrentControlSet\Enum\USB", "USB Hubs & Peripherals (USB)"),
            (r"SYSTEM\CurrentControlSet\Enum\STORAGE\Volume", "Mounted Storage Volumes"),
        ]

        found_any = False
        for base_key, label in targets:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key, 0, winreg.KEY_READ) as key:
                    num_subkeys = winreg.QueryInfoKey(key)[0]
                    print(f"\n[+] {label}: Found {num_subkeys} entries:")
                    found_any = True

                    for i in range(min(15, num_subkeys)):
                        device_name = winreg.EnumKey(key, i)
                        device_path = f"{base_key}\\{device_name}"
                        friendly_name = "N/A"
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_path, 0, winreg.KEY_READ) as dev_key:
                                try:
                                    friendly_name, _ = winreg.QueryValueEx(dev_key, "DeviceDesc")
                                except FileNotFoundError:
                                    friendly_name, _ = winreg.QueryValueEx(dev_key, "FriendlyName")
                        except Exception:
                            pass
                        print(f"    - ID: {device_name}")
                        if friendly_name != "N/A":
                            print(f"      Desc: {friendly_name}")
            except Exception:
                pass

        if not found_any:
            print("[-] No accessible USB enumeration keys found or elevated privileges required.")

    @staticmethod
    def carve_files(image_path: str, outdir: str = "carved_output"):
        """Carves common file types (JPEG, PNG, PDF) from raw disk/dump images based on magic headers."""
        if not os.path.exists(image_path):
            print(f"[-] Image file not found: {image_path}")
            return

        os.makedirs(outdir, exist_ok=True)
        print(f"[*] Starting File Carving on: {image_path}")
        print(f"[*] Output Directory: {outdir}\n")

        signatures = [
            {"type": "jpg", "header": b"\xFF\xD8\xFF", "footer": b"\xFF\xD9", "max_size": 10 * 1024 * 1024},
            {"type": "png", "header": b"\x89PNG\r\n\x1a\n", "footer": b"\x49\x45\x4e\x44\xae\x42\x60\x82", "max_size": 15 * 1024 * 1024},
            {"type": "pdf", "header": b"%PDF-", "footer": b"%%EOF", "max_size": 30 * 1024 * 1024},
        ]

        carved_count = 0
        with open(image_path, "rb") as f:
            data = f.read()

        for sig in signatures:
            h_len = len(sig["header"])
            f_len = len(sig["footer"])
            start_idx = 0

            while True:
                idx = data.find(sig["header"], start_idx)
                if idx == -1:
                    break

                # Search for corresponding footer
                end_idx = data.find(sig["footer"], idx + h_len)
                if end_idx != -1 and (end_idx - idx) <= sig["max_size"]:
                    carved_bytes = data[idx : end_idx + f_len]
                    carved_count += 1
                    out_name = os.path.join(outdir, f"carved_{carved_count:04d}_{hex(idx)}.{sig['type']}")
                    with open(out_name, "wb") as out_f:
                        out_f.write(carved_bytes)
                    print(f"[+] Carved [{sig['type'].upper()}]: offset {hex(idx)} -> {len(carved_bytes)} bytes saved to {out_name}")
                    start_idx = end_idx + f_len
                else:
                    start_idx = idx + h_len

        print(f"\n[+] Carving complete. Extracted {carved_count} intact files.")

    @staticmethod
    def generate_sigma_rule(title: str, process_cmd: str, level: str = "high"):
        """Generates standard Sigma (YAML) detection rule."""
        rule_id = str(uuid.uuid4())
        date_str = datetime.utcnow().strftime("%Y-%m-%d")

        rule = f"""title: {title}
id: {rule_id}
status: experimental
description: Auto-generated Sigma detection rule for incident response & threat hunting
author: Nafik Digital Forensics Labs
date: {date_str}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '{process_cmd}'
    condition: selection
falsepositives:
    - Administrative maintenance or legitimate automated scripts
level: {level}
tags:
    - attack.execution
    - attack.t1059
"""
        print("=" * 65)
        print("                GENERATED SIGMA DETECTION RULE (YAML)           ")
        print("=" * 65)
        print(rule)
        return rule


def main():
    parser = argparse.ArgumentParser(description="Digital Forensics & Incident Response Triage Helper")
    parser.add_argument("--audit-usb", action="store_true", help="Audit USBSTOR connection history from Windows Registry")
    parser.add_argument("--carve", help="Path to raw disk / dump file to carve deleted files from")
    parser.add_argument("--outdir", default="carved_output", help="Output directory for carved files")
    parser.add_argument("--gen-sigma", action="store_true", help="Generate Sigma (YAML) detection rule")
    parser.add_argument("--title", default="Suspicious Execution Incident", help="Title for the Sigma rule")
    parser.add_argument("--process", default="powershell.exe -enc", help="Process command line to detect")
    parser.add_argument("--level", default="high", help="Severity level (low, medium, high, critical)")

    args = parser.parse_args()
    triage = ForensicTriage()

    if not any([args.audit_usb, args.carve, args.gen_sigma]):
        parser.print_help()
        sys.exit(1)

    if args.audit_usb:
        triage.audit_usb_history()

    if args.carve:
        triage.carve_files(args.carve, args.outdir)

    if args.gen_sigma:
        triage.generate_sigma_rule(args.title, args.process, args.level)

if __name__ == "__main__":
    main()
