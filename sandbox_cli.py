import os
import sys
import argparse
from core.static_analyzer import StaticAnalyzer
from core.dynamic_sandbox import DynamicSandbox
from core.report_generator import ReportGenerator
from core.packer_detector import PackerDetector
from core.registry_diff import RegistryDiffEngine
from core.network_sinkhole import NetworkSinkhole
from core.quarantine_vault import QuarantineVault
from core.network_forensics import NISTNetworkForensics
from core.file_integrity import FileIntegrityScanner

def main():
    parser = argparse.ArgumentParser(description="Antigravity Automated Malware Analysis Sandbox & DFIR Engine")
    parser.add_argument("target", nargs="?", help="Path to executable or file to analyze")
    parser.add_argument("--dynamic", action="store_true", help="Run in dynamic behavioral sandbox")
    parser.add_argument("--timeout", type=int, default=8, help="Timeout in seconds for dynamic sandbox execution")
    parser.add_argument("--reg-diff", action="store_true", help="Take pre- and post-registry snapshots to detect persistence")
    parser.add_argument("--sinkhole", action="store_true", help="Launch local simulated C2 DNS/HTTP sinkhole listener")
    parser.add_argument("--quarantine", action="store_true", help="Safely XOR-neutralize and move malicious binary to Quarantine Vault")
    parser.add_argument("--restore", help="Identifier (filename or SHA256) of a quarantined file to restore")
    parser.add_argument("--restore-dir", default="restored_samples", help="Destination directory for restored sample")
    parser.add_argument("--outdir", default="reports", help="Output directory for reports")

    args = parser.parse_args()
    vault = QuarantineVault(vault_dir="quarantine")

    # Handle --restore mode
    if args.restore:
        print("=" * 65)
        print("       ANTIGRAVITY QUARANTINE VAULT: RESTORE OPERATION          ")
        print("=" * 65)
        try:
            restored_path = vault.restore_sample(args.restore, args.restore_dir)
            print(f"[+] Successfully restored and de-XORed sample to: {restored_path}")
            sys.exit(0)
        except Exception as e:
            print(f"[-] Restore failed: {e}")
            sys.exit(1)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(args.target):
        print(f"[-] Target file not found: {args.target}")
        sys.exit(1)

    os.makedirs(args.outdir, exist_ok=True)
    target_name = os.path.basename(args.target)

    print("=" * 65)
    print(f"   ANTIGRAVITY AUTOMATED MALWARE SANDBOX & DFIR ENGINE   ")
    print("=" * 65)
    print(f"[*] Target Sample : {target_name}")
    print(f"[*] Full Path     : {args.target}")

    sample_data = None
    analyzed_name = target_name

    # Support in-memory zip analysis (avoids host AV interception)
    if args.target.lower().endswith(".zip"):
        import zipfile
        print("\n[*] Detected ZIP archive. Inspecting in-memory without disk extraction...")
        with zipfile.ZipFile(args.target, 'r') as zf:
            exes = [n for n in zf.namelist() if n.lower().endswith(('.exe', '.dll', '.bin'))]
            if exes:
                selected_sample = exes[0]
                print(f"[+] Found binary inside archive: {selected_sample}")
                sample_data = zf.read(selected_sample)
                analyzed_name = os.path.basename(selected_sample)
            else:
                print("[-] No executable binary found inside zip archive.")
                sys.exit(1)

    # 1. Static Triage
    print("\n[*] Phase 1: Running Static Deep Analysis...")
    if sample_data:
        analyzer = StaticAnalyzer(data=sample_data, sample_name=analyzed_name)
    else:
        analyzer = StaticAnalyzer(file_path=args.target)
    hashes = analyzer.get_hashes()
    pe_header = analyzer.analyze_pe_headers()
    sections = analyzer.analyze_sections()
    capabilities = analyzer.analyze_imports_and_capabilities()
    iocs = analyzer.extract_strings_and_iocs()
    packer_info = analyzer.detect_packers()
    yara_rule = analyzer.generate_yara_rule()

    print(f"[+] SHA-256 : {hashes['sha256']}")
    print(f"[+] Imphash : {hashes['imphash']}")
    print(f"[+] Machine : {pe_header.get('machine', 'Unknown')}")
    print(f"[+] Compiler: {packer_info['detected_compiler']}")
    print(f"[+] Packers : {', '.join(packer_info['detected_packers'])}")
    print(f"[+] Sections: {len(sections)} detected")

    packed_count = sum(1 for s in sections if s["is_packed"])
    if packed_count > 0 or packer_info["is_packed"]:
        print(f"[!] WARNING : Sample exhibits packed characteristics / high entropy sections!")

    print(f"[+] Capabilities Matched: {len(capabilities['capabilities'])} behavioral categories")
    for cap in capabilities['capabilities']:
        print(f"    - [{cap['risk']} Risk] {cap['category']} (MITRE {cap['mitre']})")

    # 2. Dynamic Sandbox & Observability
    dyn_results = None
    sinkhole_engine = None
    if args.sinkhole:
        print("\n[*] Starting Local C2 Network Sinkhole Listener (127.0.0.1:8080)...")
        sinkhole_engine = NetworkSinkhole(http_port=8080)
        sinkhole_engine.start()

    reg_diff_results = None
    reg_engine = None
    if args.reg_diff:
        print("\n[*] Taking Registry Pre-Execution Baseline Snapshot...")
        reg_engine = RegistryDiffEngine()
        reg_engine.take_pre_snapshot()

    fim_scanner = FileIntegrityScanner()
    if args.dynamic:
        fim_scanner.take_baseline()
        print(f"\n[*] Phase 2: Running Dynamic Behavioral Sandbox ({args.timeout}s timeout)...")
        sandbox = DynamicSandbox(args.target, timeout_seconds=args.timeout)
        dyn_results = sandbox.run_dynamic_analysis(dry_run=False)
        print(f"[+] Dynamic Sandbox Status: {dyn_results['execution_status']}")
        print(f"[+] Spawned Child Processes: {len(dyn_results['spawned_processes'])}")
        print(f"[+] Dropped/Modified Files : {len(dyn_results['dropped_files'])}")
        print(f"[+] Registry Run Changes   : {len(dyn_results['registry_modifications'])}")

        fim_results = fim_scanner.take_post_execution()
        if dyn_results and isinstance(dyn_results, dict):
            dyn_results["file_integrity_monitoring"] = fim_results
            if fim_results["dropper_behavior_confirmed"]:
                print(f"[!] WARNING: FIM detected {len(fim_results['high_risk_executable_drops'])} high-risk executable drops!")
    else:
        print("\n[*] Phase 2: Dynamic Execution skipped (use --dynamic to enable).")
        dyn_results = {"execution_status": "Skipped (Static triage only)"}

    if reg_engine:
        print("[*] Taking Registry Post-Execution Snapshot & Computing Diff...")
        reg_engine.take_post_snapshot()
        reg_diff_results = reg_engine.compute_diff()
        print(f"[+] Registry Changes Detected: {reg_diff_results['total_changes']}")
        if reg_diff_results["suspicious_persistence_detected"]:
            print(f"[!] WARNING: Suspicious Autorun Persistence Added ({len(reg_diff_results['added_entries'])} entries)!")
        if dyn_results and isinstance(dyn_results, dict):
            dyn_results["registry_differential"] = reg_diff_results

    if sinkhole_engine:
        sinkhole_telemetry = sinkhole_engine.stop()
        print(f"[+] Sinkhole Inbound Beacons Captured: {len(sinkhole_telemetry)}")
        # Process via NIST SP 800-86 Network Forensics
        nist_forensics = NISTNetworkForensics(sinkhole_telemetry).process()
        print(f"[+] NIST SP 800-86 Assessment : {nist_forensics['summary']['threat_level']} (Evidence ID: {nist_forensics['evidence_id']})")
        if dyn_results and isinstance(dyn_results, dict):
            dyn_results["nist_network_forensics"] = nist_forensics

    # 3. Report Generation
    print("\n[*] Phase 3: Generating Intelligence Reports & YARA Signature...")
    generator = ReportGenerator(
        static_data={
            "hashes": hashes,
            "pe_header": pe_header,
            "sections": sections,
            "capabilities": capabilities,
            "iocs": iocs,
            "packer_info": packer_info
        },
        dynamic_data=dyn_results,
        yara_rule=yara_rule,
        target_name=target_name
    )

    base_out = os.path.join(args.outdir, os.path.splitext(target_name)[0])
    json_path = base_out + "_report.json"
    html_path = base_out + "_report.html"
    yara_path = base_out + "_rule.yar"

    generator.generate_json(json_path)
    generator.generate_html(html_path)
    with open(yara_path, "w", encoding="utf-8") as yf:
        yf.write(yara_rule)

    print("\n" + "=" * 65)
    print(f"  VERDICT      : {generator.verdict}")
    print(f"  THREAT SCORE : {generator.score} / 100")
    print("=" * 65)
    print(f"[+] Interactive HTML Dashboard : {os.path.abspath(html_path)}")
    print(f"[+] Machine-readable JSON Log  : {os.path.abspath(json_path)}")
    print(f"[+] Generated YARA Detection   : {os.path.abspath(yara_path)}")
    print("=" * 65)

    # 4. Quarantine Vault Execution (if requested or if score >= 60)
    if args.quarantine:
        if os.path.exists(args.target):
            print("\n[*] Executing Safe Quarantine Vault Isolation...")
            q_res = vault.quarantine_sample(args.target, threat_info={"score": generator.score, "verdict": generator.verdict})
            print(f"[+] Binary neutralised with XOR stream mask (Key: 0x5A)")
            print(f"[+] Quarantined Vault Path: {q_res['quarantined_path']}")
            print(f"[+] Original sample safely disarmed.")

if __name__ == "__main__":
    main()
