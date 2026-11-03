import os
import math
import hashlib
import re
from datetime import datetime
import pefile

class StaticAnalyzer:
    def __init__(self, file_path=None, data=None, sample_name=None):
        if data is not None:
            self.data = data
            self.file_name = sample_name or "in_memory_sample.bin"
            self.file_path = file_path or self.file_name
        elif file_path:
            self.file_path = file_path
            self.file_name = sample_name or os.path.basename(file_path)
            with open(file_path, "rb") as f:
                self.data = f.read()
        else:
            raise ValueError("Either file_path or data must be provided")

        self.pe = None
        try:
            self.pe = pefile.PE(data=self.data)
        except Exception:
            pass

    def get_hashes(self):
        return {
            "md5": hashlib.md5(self.data).hexdigest(),
            "sha1": hashlib.sha1(self.data).hexdigest(),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "imphash": self.pe.get_imphash() if self.pe else "N/A",
            "file_size": len(self.data)
        }

    @staticmethod
    def calculate_entropy(data):
        if not data:
            return 0.0
        entropy = 0
        length = len(data)
        occ = {}
        for byte in data:
            occ[byte] = occ.get(byte, 0) + 1
        for count in occ.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return round(entropy, 3)

    def analyze_sections(self):
        sections = []
        if not self.pe:
            return sections
        for s in self.pe.sections:
            name = s.Name.decode("latin1", errors="ignore").strip("\x00")
            entropy = self.calculate_entropy(s.get_data())
            is_packed = entropy > 7.0 or name.lower() in [".upx0", ".upx1", "upx0", "upx1", ".themida", ".mpress", ".aspack"]
            sections.append({
                "name": name,
                "virtual_address": hex(s.VirtualAddress),
                "virtual_size": hex(s.Misc_VirtualSize),
                "raw_size": s.SizeOfRawData,
                "entropy": entropy,
                "is_packed": is_packed
            })
        return sections

    def analyze_pe_headers(self):
        if not self.pe:
            return {}
        hdr = self.pe.FILE_HEADER
        opt = self.pe.OPTIONAL_HEADER
        
        machine_map = {
            0x14c: "i386 (32-bit x86)",
            0x8664: "AMD64 (64-bit x64)",
            0xaa64: "ARM64",
            0x1c0: "ARM"
        }
        machine = machine_map.get(hdr.Machine, hex(hdr.Machine))
        
        try:
            timestamp = datetime.utcfromtimestamp(hdr.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            timestamp = "Invalid/Corrupted"

        dll_char = opt.DllCharacteristics
        security_features = {
            "ASLR": bool(dll_char & 0x0040),
            "DEP/NX": bool(dll_char & 0x0100),
            "HighEntropyVA": bool(dll_char & 0x0020),
            "SafeSEH": bool(not (opt.DllCharacteristics & 0x0400))
        }

        return {
            "machine": machine,
            "compile_timestamp": timestamp,
            "subsystem": opt.Subsystem,
            "entry_point": hex(opt.AddressOfEntryPoint),
            "image_base": hex(opt.ImageBase),
            "security_features": security_features
        }

    def analyze_imports_and_capabilities(self):
        capabilities = []
        imports_dict = {}

        SIGNATURES = {
            "Process Injection": {
                "mitre": "T1055",
                "risk": "High",
                "apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "SetThreadContext", "NtMapViewOfSection"]
            },
            "Anti-Debugging / Evasion": {
                "mitre": "T1497 / T1622",
                "risk": "Medium",
                "apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "OutputDebugStringW", "NtQueryInformationProcess", "FindWindowA", "FindWindowW", "GetTickCount"]
            },
            "Persistence (Registry/Service)": {
                "mitre": "T1547 / T1543",
                "risk": "High",
                "apis": ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyA", "RegCreateKeyW", "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"]
            },
            "Keylogging / Input Capture": {
                "mitre": "T1056.001",
                "risk": "High",
                "apis": ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState", "RegisterHotKey"]
            },
            "Downloader / C2 Network": {
                "mitre": "T1071 / T1105",
                "risk": "High",
                "apis": ["InternetOpenA", "InternetOpenW", "InternetReadFile", "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpSendRequest", "WSAStartup", "socket", "connect"]
            },
            "Cryptographic Operations / Ransomware": {
                "mitre": "T1486",
                "risk": "Medium",
                "apis": ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CryptGenKey", "BCryptEncrypt"]
            },
            "Dynamic Execution / Shell Execution": {
                "mitre": "T1059",
                "risk": "Medium",
                "apis": ["ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW", "WinExec", "CreateProcessA", "CreateProcessW"]
            }
        }

        if self.pe and hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("latin1", errors="ignore").lower()
                imports_dict[dll_name] = []
                for imp in entry.imports:
                    if imp.name:
                        api = imp.name.decode("latin1", errors="ignore")
                        imports_dict[dll_name].append(api)

            # Check matches
            all_apis = set()
            for apis in imports_dict.values():
                all_apis.update(apis)

            for cap_name, info in SIGNATURES.items():
                matched = [api for api in info["apis"] if api in all_apis]
                if matched:
                    capabilities.append({
                        "category": cap_name,
                        "mitre": info["mitre"],
                        "risk": info["risk"],
                        "matched_apis": matched
                    })

        return {
            "total_dlls": len(imports_dict),
            "imports": imports_dict,
            "capabilities": capabilities
        }

    def extract_strings_and_iocs(self):
        strings = [s.decode('latin1', errors='ignore') for s in re.findall(b'[\x20-\x7E]{5,}', self.data)]
        
        # Regex for IOCs
        ipv4_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        url_pattern = re.compile(r'https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s"\']*)?')
        registry_pattern = re.compile(r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[a-zA-Z0-9_\\]+')
        
        ips = set()
        urls = set()
        reg_keys = set()
        suspicious_words = []

        keywords = ["powershell", "cmd.exe", "vssadmin", "bitcoin", "wallet", "ransom", "payload", "backdoor", "mimikatz", "inject"]

        for s in strings:
            # IPs (exclude localhost / zeroes)
            for ip in ipv4_pattern.findall(s):
                if not ip.startswith(("127.", "0.", "255.", "10.", "192.168.")):
                    ips.add(ip)
            # URLs
            for url in url_pattern.findall(s):
                urls.add(url)
            # Reg keys
            for rk in registry_pattern.findall(s):
                reg_keys.add(rk)
            # Keywords
            for kw in keywords:
                if kw in s.lower() and s not in suspicious_words:
                    suspicious_words.append(s[:80])

        return {
            "total_strings": len(strings),
            "ips": sorted(list(ips))[:10],
            "urls": sorted(list(urls))[:15],
            "registry_keys": sorted(list(reg_keys))[:10],
            "suspicious_indicators": suspicious_words[:15]
        }

    def generate_yara_rule(self, threat_name=None):
        hashes = self.get_hashes()
        threat_name = threat_name or "Malware_" + hashes["sha256"][:8]
        strings_iocs = self.extract_strings_and_iocs()

        selected_strings = []
        for i, url in enumerate(strings_iocs["urls"][:3]):
            selected_strings.append(f'        $s{i+1} = "{url}" ascii')
        for i, word in enumerate(strings_iocs["suspicious_indicators"][:4]):
            escaped = word.replace('"', '\\"')
            selected_strings.append(f'        $kw{i+1} = "{escaped}" ascii wide nocase')

        if not selected_strings:
            selected_strings.append('        $magic = { 4D 5A }')

        rule = f"""rule {threat_name}
{{
    meta:
        description = "Auto-generated rule by Antigravity Sandbox"
        author = "Antigravity Automated Triage"
        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        sample_sha256 = "{hashes['sha256']}"
        imphash = "{hashes['imphash']}"
    strings:
{chr(10).join(selected_strings)}
    condition:
        uint16(0) == 0x5A4D and (1 of ($s*) or 2 of ($kw*))
}}
"""
        return rule
