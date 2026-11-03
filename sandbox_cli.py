import os
import sys
import argparse
from core.static_analyzer import StaticAnalyzer
from core.dynamic_sandbox import DynamicSandbox
from core.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="Antigravity Automated Malware Analysis Sandbox")
    parser.add_argument("target", help="Path to executable or file to analyze")
    parser.add_argument("--dynamic", action="store_true", help="Run in dynamic behavioral sandbox")
    parser.add_argument("--timeout", type=int, default=8, help="Timeout in seconds for dynamic sandbox execution")
    parser.add_argument("--outdir", default="reports", help="Output directory for reports")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"[-] Target file not found: {args.target}")
        sys.exit(1)

    os.makedirs(args.outdir, exist_ok=True)
    target_name = os.path.basename(args.target)

    print("=" * 65)
    print(f"   ANTIGRAVITY AUTOMATED MALWARE SANDBOX & TRIAGE ENGINE   ")
    print("=" * 65)
    print(f"[*] Target Sample : {target_name}")
    print(f"[*] Full Path     : {args.target}")

    # 1. Static Triage
    print("\n[*] Phase 1: Running Static Deep Analysis...")
    analyzer = StaticAnalyzer(args.target)
    hashes = analyzer.get_hashes()
    pe_header = analyzer.analyze_pe_headers()
    sections = analyzer.analyze_sections()
    capabilities = analyzer.analyze_imports_and_capabilities()
    iocs = analyzer.extract_strings_and_iocs()
    yara_rule = analyzer.generate_yara_rule()

    print(f"[+] SHA-256 : {hashes['sha256']}")
    print(f"[+] Imphash : {hashes['imphash']}")
    print(f"[+] Machine : {pe_header.get('machine', 'Unknown')}")
    print(f"[+] Sections: {len(sections)} detected")

    packed_count = sum(1 for s in sections if s["is_packed"])
    if packed_count > 0:
        print(f"[!] WARNING : {packed_count} sections detected with high entropy / packing!")

    print(f"[+] Capabilities Matched: {len(capabilities['capabilities'])} behavioral categories")
    for cap in capabilities['capabilities']:
        print(f"    - [{cap['risk']} Risk] {cap['category']} (MITRE {cap['mitre']})")

    # 2. Dynamic Sandbox
    dyn_results = None
    if args.dynamic:
        print(f"\n[*] Phase 2: Running Dynamic Behavioral Sandbox ({args.timeout}s timeout)...")
        sandbox = DynamicSandbox(args.target, timeout_seconds=args.timeout)
        dyn_results = sandbox.run_dynamic_analysis(dry_run=False)
        print(f"[+] Dynamic Sandbox Status: {dyn_results['execution_status']}")
        print(f"[+] Spawned Child Processes: {len(dyn_results['spawned_processes'])}")
        print(f"[+] Dropped/Modified Files : {len(dyn_results['dropped_files'])}")
        print(f"[+] Registry Run Changes   : {len(dyn_results['registry_modifications'])}")
    else:
        print("\n[*] Phase 2: Dynamic Execution skipped (use --dynamic to enable).")
        dyn_results = {"execution_status": "Skipped (Static triage only)"}

    # 3. Report Generation
    print("\n[*] Phase 3: Generating Intelligence Reports & YARA Signature...")
    generator = ReportGenerator(
        static_data={
            "hashes": hashes,
            "pe_header": pe_header,
            "sections": sections,
            "capabilities": capabilities,
            "iocs": iocs
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

if __name__ == "__main__":
    main()
